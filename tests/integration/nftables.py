#!/usr/bin/env python3
"""Запускать через unshare --mount --net от root."""
import functools
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import atexit

def run(*args, ok=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=40)
    if ok and result.returncode:
        raise AssertionError((args, result.stdout, result.stderr))
    return result

assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')
assert os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt')
binary = os.environ['RKN_TEST_BINARY']
run('mount', '--make-rprivate', '/')
with tempfile.TemporaryDirectory(prefix='rkn-nft-') as work:
    shutil.copytree('/etc', work+'/etc', symlinks=True, ignore=shutil.ignore_patterns('mtab'))
    run('mount', '--bind', work+'/etc', '/etc')
    for path in ('/opt', '/var/lib/rkn-guard'):
        Path(path).mkdir(exist_ok=True)
        run('mount', '-t', 'tmpfs', 'tmpfs', path)
    for path in ('/etc/rkn-guard-firewall.json', '/etc/ipset.conf', '/etc/rkn-guard/exceptions.json'):
        Path(path).unlink(missing_ok=True)
    fake = Path(work)/'bin'; fake.mkdir()
    for name, body in {'systemctl':'exit 0', 'ufw':'echo "Status: inactive"', 'firewall-cmd':'exit 1'}.items():
        p = fake/name; p.write_text('#!/bin/sh\n'+body+'\n'); p.chmod(0o755)
    os.environ['PATH'] = str(fake)+':'+os.environ['PATH']
    firewalld_root = os.environ.get('RKN_FIREWALLD_ROOT')
    mode = 'firewalld' if firewalld_root else 'nftables'
    if firewalld_root:
        root = Path(firewalld_root)
        run('mount', '-t', 'tmpfs', 'tmpfs', '/run')
        Path('/run/dbus').mkdir()
        os.environ['PYTHONPATH'] = str(root/'usr/lib/python3/dist-packages')
        bus = subprocess.Popen(['dbus-daemon','--session','--nofork','--print-address'],stdout=subprocess.PIPE,text=True)
        atexit.register(bus.terminate)
        os.environ['DBUS_SYSTEM_BUS_ADDRESS'] = bus.stdout.readline().strip()
        shutil.copytree(root/'etc/firewalld','/etc/firewalld',dirs_exist_ok=True)
        (fake/'firewall-cmd').unlink()
        (fake/'firewall-cmd').symlink_to(root/'usr/bin/firewall-cmd')
        logfile = open(work+'/firewalld.log','w+')
        daemon = subprocess.Popen(['/usr/bin/python3',str(root/'usr/sbin/firewalld'),'--nofork','--nopid','--log-target=console','--default-config',str(root/'usr/lib/firewalld')],stdout=logfile,stderr=logfile)
        atexit.register(daemon.terminate)
        for _ in range(100):
            if run('firewall-cmd','--state',ok=False).returncode == 0: break
            if daemon.poll() is not None: break
            time.sleep(.1)
        else: raise AssertionError('firewalld start timeout')
        if daemon.poll() is not None:
            logfile.seek(0); raise AssertionError(logfile.read())
    run('ip','link','set','lo','up')
    for ip in ('192.0.2.10/32','192.0.2.11/32','2001:db8::10/128'):
        run('ip','addr','add',ip,'dev','lo')
    web = Path(work)/'web'; web.mkdir()
    (web/'list').write_text('192.0.2.0/24\n2001:db8::/64\n')
    server = http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(http.server.SimpleHTTPRequestHandler,directory=str(web)))
    threading.Thread(target=server.serve_forever,daemon=True).start()
    url = f'http://127.0.0.1:{server.server_port}/list'
    assert run(binary,'firewall-select','auto').stdout.strip() == mode
    assert run(binary,'firewall-select','invalid',ok=False).returncode != 0
    if not firewalld_root:
        run('ipset','create','unrelated','hash:net')
        assert run(binary,'firewall-select','auto').stdout.strip() == 'iptables'
        run('ipset','destroy','unrelated')
        (fake/'ufw').write_text('#!/bin/sh\necho "Status: active"\n')
        assert run(binary,'firewall-select','auto').stdout.strip() == 'iptables'
        assert run(binary,'firewall-select','nftables',ok=False).returncode != 0
        (fake/'ufw').write_text('#!/bin/sh\necho "Status: inactive"\n')
    run('nft','add','table','inet','user_keep')
    (fake/'systemctl').write_text('#!/bin/sh\nexit 1\n')
    assert run(binary,'full','--urls',url,'--firewall',mode,ok=False).returncode != 0
    assert not Path('/etc/rkn-guard-firewall.json').exists()
    assert 'rkn_guard' not in run('nft','list','tables').stdout
    (fake/'systemctl').write_text('#!/bin/sh\nexit 0\n')
    run(binary,'full','--urls',url,'--firewall','auto')
    assert json.loads(Path('/etc/rkn-guard-firewall.json').read_text())['backend']==mode
    assert run(binary,'firewall-select','auto').stdout.strip()==mode
    state_path = '/etc/rkn-guard-firewall.json'
    valid_state = Path(state_path).read_bytes()
    Path(state_path).write_text('{broken')
    assert run(binary,'update','--urls',url,ok=False).returncode != 0
    assert run(binary,'firewall-select','auto',ok=False).returncode != 0
    Path(state_path).write_bytes(valid_state)
    if firewalld_root:
        run('firewall-cmd','--reload')
        assert 'rkn_guard' in run('nft','list','tables').stdout
    def connects(ip, port):
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        with socket.socket(family) as listener, socket.socket(family) as client:
            listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listener.bind((ip,port)); listener.listen()
            client.settimeout(.25)
            try: client.connect((ip,port)); return True
            except (TimeoutError,ConnectionRefusedError): return False
    assert not connects('192.0.2.10',23456)
    assert not connects('2001:db8::10',23456)
    run(binary,'exceptions','add','192.0.2.10','tcp','23456')
    assert connects('192.0.2.10',23456)
    assert not connects('192.0.2.10',23457)
    run('nft','add','chain','inet','user_keep','input','{ type filter hook input priority 20; policy accept; }')
    run('nft','add','rule','inet','user_keep','input','tcp','dport','23456','drop')
    assert not connects('192.0.2.10',23456), 'exception bypasses user firewall'
    run('nft','flush','chain','inet','user_keep','input')
    run(binary,'manual-ips','add','198.51.100.1')
    assert run(binary,'manual-ips','add','198.51.100.1',ok=False).returncode != 0
    assert run(binary,'manual-ips','add','not-an-ip',ok=False).returncode != 0
    assert run(binary,'exceptions','add','192.0.2.10','tcp','23456',ok=False).returncode != 0
    assert run(binary,'exceptions','add','192.0.2.10','tcp','99999',ok=False).returncode != 0
    assert '198.51.100.1' in run('nft','list','set','inet','rkn_guard','blocked4').stdout
    run(binary,'update','--urls',url)
    rules_before = run('nft','-j','list','chain','inet','rkn_guard','input').stdout
    run(binary,'update','--urls',url)
    assert json.loads(run('nft','-j','list','chain','inet','rkn_guard','input').stdout) == json.loads(rules_before), 'update changed rules/counters'
    assert '198.51.100.1' in run('nft','list','set','inet','rkn_guard','blocked4').stdout
    assert connects('192.0.2.10',23456)
    run(binary,'manual-ips','delete','198.51.100.1')
    run(binary,'exceptions','delete','192.0.2.10','tcp','23456')
    assert not connects('192.0.2.10',23456)
    # Ошибка сохранения должна вернуть прежний набор.
    before = run('nft','list','set','inet','rkn_guard','blocked4').stdout
    state_path = '/etc/rkn-guard-firewall.json'
    saved = Path(state_path).read_bytes()
    run('mount','--bind',state_path,state_path)
    (web/'list').write_text('203.0.113.0/24\n')
    assert run(binary,'update','--urls',url,ok=False).returncode != 0
    assert run('nft','list','set','inet','rkn_guard','blocked4').stdout == before
    assert Path(state_path).read_bytes() == saved
    run('umount',state_path)
    before = run('nft','list','set','inet','rkn_guard','blocked4').stdout
    (web/'list').write_text('invalid\n')
    assert run(binary,'update','--urls',url,ok=False).returncode != 0
    assert run('nft','list','set','inet','rkn_guard','blocked4').stdout == before
    run('nft','delete','table','inet','rkn_guard')
    run(binary,'firewall-restore')
    assert not connects('192.0.2.10',23456)
    if not firewalld_root:
        (web/'list').write_text('192.0.2.0/24\n2001:db8::/64\n')
        (fake/'ufw').unlink()
        run('ufw','allow','22/tcp')
        real_nft = shutil.which('nft')
        (fake/'nft').write_text('#!/bin/sh\nif [ "$1" = delete ]; then exit 66; fi\nexec '+real_nft+' "$@"\n')
        (fake/'nft').chmod(0o755)
        assert run(binary,'full','--urls',url,'--firewall','iptables',ok=False).returncode != 0
        assert json.loads(Path(state_path).read_text())['cleanup_nft']
        assert 'rkn_guard' in run('nft','list','tables').stdout
        (fake/'nft').unlink()
        run(binary,'full','--urls',url,'--firewall','iptables')
        assert json.loads(Path(state_path).read_text())['backend'] == 'iptables'
        assert 'rkn_guard' not in run('nft','list','tables').stdout
        run('ipset','test','SCANNERS-BLOCK-V4','192.0.2.10')
        # Старому режиму не нужен рабочий nft.
        (fake/'nft').write_text('#!/bin/sh\necho called > '+work+'/nft-called\nexit 77\n')
        (fake/'nft').chmod(0o755)
        run(binary,'full','--urls',url,'--firewall','auto')
        assert not Path(work+'/nft-called').exists()
        (fake/'nft').unlink()
        # Старая установка без нового файла настроек.
        Path(state_path).unlink()
        assert run(binary,'firewall-select','auto').stdout.strip() == 'iptables'
        run(binary,'update','--urls',url)
        run('ufw','disable')
        run(binary,'full','--urls',url,'--firewall','nftables')
        assert run('iptables','-S','SCANNERS-BLOCK',ok=False).returncode != 0
        assert not connects('192.0.2.10',23456)
        assert 'user_keep' in run('nft','list','tables').stdout
    run(binary,'uninstall','--yes')
    assert 'rkn_guard' not in run('nft','list','tables').stdout
    assert 'user_keep' in run('nft','list','tables').stdout
    assert not Path('/etc/rkn-guard-firewall.json').exists()
    server.shutdown()
    if firewalld_root:
        daemon.terminate(); daemon.wait(timeout=10)
        bus.terminate(); bus.wait(timeout=10)
print(mode + ' integration: OK')
