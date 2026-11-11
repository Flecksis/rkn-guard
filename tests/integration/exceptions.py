#!/usr/bin/env python3
"""Запускать через unshare --mount --net от root. Файлы и сеть изолированы."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import http.server
import threading


def run(*args, ok=True):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
    if ok and result.returncode:
        raise AssertionError((args, result.stdout, result.stderr))
    return result


assert os.geteuid() == 0
assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'Нужно отдельное сетевое пространство'
assert os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt'), 'Нужно отдельное пространство монтирования'
binary = os.environ['RKN_TEST_BINARY']
run('mount', '--make-rprivate', '/')
with tempfile.TemporaryDirectory(prefix='rkn-exceptions-') as work:
    # Копия /etc нужна для настоящего ufw reload без изменения настроек хоста.
    shutil.copytree('/etc', work + '/etc', symlinks=True, ignore=shutil.ignore_patterns('mtab'))
    run('mount', '--bind', work + '/etc', '/etc')
    run('mount', '-t', 'tmpfs', 'tmpfs', '/opt')
    try:
        Path('/etc/rkn-guard/exceptions.json').unlink(missing_ok=True)
        run('ip', 'link', 'set', 'lo', 'up')
        for ip in ('192.0.2.10/32', '192.0.2.11/32', '192.0.2.20/32', '2001:db8::10/128', '2001:db8::11/128', '2001:db8::20/128'):
            run('ip', 'addr', 'add', ip, 'dev', 'lo')
        for family, network in (('inet','192.0.2.0/24'), ('inet6','2001:db8::/64')):
            name = 'SCANNERS-BLOCK-V4' if family == 'inet' else 'SCANNERS-BLOCK-V6'
            run('ipset','create',name,'hash:net','family',family)
            run('ipset','add',name,network)
        run('ufw','allow','22/tcp')
        run('ufw','--force','enable')
        for command in ('iptables','ip6tables'):
            run(command,'-N','SCANNERS-BLOCK')
            run(command,'-A','SCANNERS-BLOCK','-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','RETURN')
            name = 'SCANNERS-BLOCK-V4' if command == 'iptables' else 'SCANNERS-BLOCK-V6'
            run(command,'-A','SCANNERS-BLOCK','-m','set','--match-set',name,'src','-j','LOG')

        def change(action, ip, proto='tcp', port='443'):
            return run(binary,'exceptions',action,ip,proto,port)

        def traffic(ip, port=443, proto='tcp', allowed=True):
            family = socket.AF_INET6 if ':' in ip else socket.AF_INET
            dest = '2001:db8::20' if family == socket.AF_INET6 else '192.0.2.20'
            kind = socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM
            with socket.socket(family,kind) as server, socket.socket(family,kind) as client:
                server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                server.bind((dest,port)); server.settimeout(.3)
                client.bind((ip,0)); client.settimeout(.3)
                if proto == 'tcp':
                    server.listen()
                    try:
                        client.connect((dest,port)); conn,_ = server.accept(); conn.close(); received=True
                    except socket.timeout:
                        received=False
                else:
                    client.sendto(b'test',(dest,port))
                    try: server.recvfrom(32); received=True
                    except socket.timeout: received=False
                assert received == allowed, (ip,port,proto,received,allowed)

        for ip in ('192.0.2.10','2001:db8::10'):
            change('add',ip)
            change('add',ip,'udp','443')
        for proto in ('tcp','udp'):
            for ip,other in (('192.0.2.10','192.0.2.11'),('2001:db8::10','2001:db8::11')):
                traffic(ip,proto=proto)
                traffic(other,proto=proto,allowed=False)
                traffic(ip,444,proto,False)
        # RETURN обязан передать пакет следующему правилу UFW, даже если оно DROP.
        run('iptables','-I','ufw-before-input','2','-s','192.0.2.10','-p','tcp','--dport','443','-j','DROP')
        traffic('192.0.2.10',allowed=False)
        run('ufw','reload')
        traffic('192.0.2.10')
        # Обновление настоящей командой, источник работает только внутри тестовой сети.
        class Lists(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.end_headers()
                self.wfile.write(b'192.0.2.0/24\n2001:db8::/64\n')
            def log_message(self, *args): pass
        http = http.server.ThreadingHTTPServer(('127.0.0.1',0), Lists)
        threading.Thread(target=http.serve_forever,daemon=True).start()
        try:
            run(binary,'manual-ips','add','198.51.100.7')
            run(binary,'update','--urls',f'http://127.0.0.1:{http.server_port}/list')
            run('ipset','test','SCANNERS-BLOCK-V4','198.51.100.7')
            run(binary,'manual-ips','delete','198.51.100.7')
        finally:
            http.shutdown(); http.server_close()
        traffic('192.0.2.10'); traffic('192.0.2.11',allowed=False)
        # Ошибка reload должна вернуть прежние исключения и правила.
        snapshot = Path('/etc/rkn-guard/exceptions.json').read_bytes()
        wrapper = Path(work)/'bin'; wrapper.mkdir()
        flag = Path(work)/'failed'
        (wrapper/'ufw').write_text(f'#!/bin/sh\nif [ "$1" = reload ] && [ ! -f "{flag}" ]; then touch "{flag}"; exit 71; fi\nexec /usr/sbin/ufw "$@"\n')
        (wrapper/'ufw').chmod(0o755)
        old_path = os.environ['PATH']; os.environ['PATH'] = str(wrapper)+':'+old_path
        try:
            assert run(binary,'exceptions','delete','192.0.2.10','tcp','443',ok=False).returncode != 0
        finally: os.environ['PATH'] = old_path
        assert Path('/etc/rkn-guard/exceptions.json').read_bytes() == snapshot
        traffic('192.0.2.10')
        change('delete','192.0.2.10')
        traffic('192.0.2.10',allowed=False)
        traffic('192.0.2.10',proto='udp')
        change('add','192.0.2.10')
        # Обновление наборов через swap не затрагивает исключения.
        run('ipset','create','replacement','hash:net')
        run('ipset','add','replacement','192.0.2.0/24')
        run('ipset','swap','replacement','SCANNERS-BLOCK-V4')
        run('ipset','destroy','replacement')
        traffic('192.0.2.10')
        # Восстановление сохранённых правил после остановки и запуска firewall.
        run('ufw','--force','disable'); run('ufw','--force','enable')
        traffic('192.0.2.10'); traffic('2001:db8::10')
        result = run(binary,'manual-ips','delete','192.0.2.10',ok=False)
        assert result.returncode != 0 and 'Успешно разбанен' not in result.stdout
        run(binary,'manual-ips','add','192.0.2.10')
        (wrapper/'ipset').write_text('#!/bin/sh\nif [ "$1" = del ]; then exit 72; fi\nexec /usr/sbin/ipset "$@"\n')
        (wrapper/'ipset').chmod(0o755)
        os.environ['PATH'] = str(wrapper)+':'+old_path
        try:
            failed = run(binary,'manual-ips','delete','192.0.2.10',ok=False)
            assert failed.returncode != 0
            assert '192.0.2.10' in Path('/opt/rkn-guard-manual.list').read_text()
        finally: os.environ['PATH'] = old_path
        result = run(binary,'manual-ips','delete','192.0.2.10')
        assert 'остаётся' in result.stdout
        # Старую ручную запись тоже можно удалить, даже если её уже нет в ipset.
        Path('/opt/rkn-guard-manual.list').write_text('192.0.2.10\n')
        run(binary,'manual-ips','delete','192.0.2.10')
        assert not Path('/opt/rkn-guard-manual.list').read_text().strip()
        # Порядок загрузки сервера: сначала наборы, затем сохранённые правила UFW.
        run('ufw','--force','disable')
        for command in ('iptables','ip6tables'): run(command,'-F','SCANNERS-BLOCK')
        for name in ('SCANNERS-BLOCK-V4','SCANNERS-BLOCK-V6'): run('ipset','destroy',name)
        run('ipset','restore','-exist','-f','/etc/ipset.conf')
        run('ufw','--force','enable')
        traffic('192.0.2.10'); traffic('2001:db8::10')
        traffic('192.0.2.11',allowed=False)
        assert len(json.loads(Path('/etc/rkn-guard/exceptions.json').read_text())) == 4
        for command in ('iptables','ip6tables'):
            rules = run(command,'-S','SCANNERS-BLOCK').stdout
            assert rules.count('--comment rkn-exception') == 2
            assert rules.rindex('--comment rkn-exception') < rules.index('-j LOG') < rules.index('-j DROP')
        print('PASS: IPv4/IPv6, TCP/UDP, подсеть, другие порты, UFW DROP, удаление, swap, reload, restart, разбан')
    finally:
        run('umount','/opt',ok=False)
        run('umount','/etc',ok=False)
