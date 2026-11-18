#!/usr/bin/env python3
"""Disposable VM: install, reboot, verify and uninstall."""
import argparse
import json
from pathlib import Path
import subprocess
import time

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--image', required=True)
    p.add_argument('--work', required=True)
    p.add_argument('--binary', required=True)
    p.add_argument('--port', type=int, default=22240)
    p.add_argument('--rpm', action='store_true')
    p.add_argument('--reuse', action='store_true')
    a = p.parse_args()
    work = Path(a.work).resolve(); work.mkdir(parents=True, exist_ok=True)
    (work/'result.json').unlink(missing_ok=True)
    def run(args, **kw):
        return subprocess.run(args, check=True, text=True, **kw)
    key = work/'key'
    if not key.exists(): run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)])
    (work/'user-data').write_text('#cloud-config\ndisable_root: false\nssh_pwauth: false\nusers:\n  - name: root\n    ssh_authorized_keys:\n      - '+key.with_suffix('.pub').read_text().strip()+'\n')
    (work/'meta-data').write_text('instance-id: rkn-test\nlocal-hostname: rkn-test\n')
    run(['cloud-localds',str(work/'seed.img'),str(work/'user-data'),str(work/'meta-data')])
    disk = work/'disk.qcow2'
    if disk.exists() and not a.reuse: raise SystemExit('Use a fresh directory or --reuse')
    if not disk.exists():
        run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(Path(a.image).resolve()),str(disk),'12G'])
    ssh = ['ssh','-i',str(key),'-p',str(a.port),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile='+str(work/'known_hosts'),'-o','ConnectTimeout=5','-o','BatchMode=yes','root@127.0.0.1']
    log = open(work/'serial.log','w')
    vm = subprocess.Popen(['qemu-system-x86_64','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','1536','-drive',f'file={disk},if=virtio','-drive',f'file={work}/seed.img,format=raw,if=virtio','-nic',f'user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{a.port}-:22','-display','none','-serial','stdio','-monitor','none'],stdout=log,stderr=log)
    def remote(command, timeout=900):
        result = subprocess.run(ssh+[command], capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            with (work/'errors.log').open('a') as errors:
                errors.write(command+'\n'+result.stdout+result.stderr+'\n')
            result.check_returncode()
        return result.stdout
    def wait_boot(old=None):
        deadline = time.monotonic()+900
        while time.monotonic()<deadline:
            if vm.poll() is not None: raise RuntimeError('VM stopped; see serial.log')
            try:
                boot = remote('cat /proc/sys/kernel/random/boot_id',15).strip()
                if boot and boot != old: return boot
            except (subprocess.SubprocessError,OSError): pass
            time.sleep(5)
        raise TimeoutError('VM boot timeout')
    results = {}
    try:
        print('Waiting for VM boot',flush=True)
        wait_boot()
        remote('cloud-init status --wait',900)
        print('Installing dependencies',flush=True)
        packages = 'dnf install -y nftables python3 firewalld rsyslog logrotate' if a.rpm else 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y nftables python3 rsyslog logrotate'
        (work/'packages.log').write_text(remote(packages,1200))
        run(['scp','-O','-i',str(key),'-P',str(a.port),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile='+str(work/'known_hosts'),a.binary,'root@127.0.0.1:/usr/local/bin/rkn-guard'],capture_output=True)
        remote('chmod 755 /usr/local/bin/rkn-guard; mkdir -p /opt/rkn-test; printf "192.0.2.0/24\\n2001:db8::/64\\n" > /opt/rkn-test/list; systemctl enable --now rsyslog; systemd-run --unit=rkn-test-http python3 -m http.server 18080 --bind 127.0.0.1 --directory /opt/rkn-test')
        if a.rpm: remote('systemctl enable --now firewalld')
        print('Installing firewall',flush=True)
        if a.reuse:
            remote('rkn-guard uninstall --yes')
        (work/'install.log').write_text(remote('rkn-guard full --firewall auto --urls http://127.0.0.1:18080/list --enable-logging'))
        remote('rkn-guard manual-ips add 198.51.100.1; rkn-guard exceptions add 192.0.2.10 tcp 2222')
        old = remote('cat /proc/sys/kernel/random/boot_id').strip()
        results['os'] = remote('cat /etc/os-release')
        results['mode'] = remote('rkn-guard firewall-status')
        remote('systemctl is-enabled rkn-guard-firewall.service')
        print('Rebooting VM',flush=True)
        remote('systemctl reboot')
        results['boot_before'] = old
        results['boot_after'] = wait_boot(old)
        results['service'] = remote('systemctl is-active rkn-guard-firewall.service')
        rules = remote('nft list table inet rkn_guard')
        assert '192.0.2.0/24' in rules and '2001:db8::/64' in rules and '198.51.100.1' in rules
        assert 'tcp dport 2222 return' in rules
        if a.rpm:
            remote('firewall-cmd --reload')
            remote('nft list table inet rkn_guard')
        results['rules_after_reboot'] = rules
        results['journal'] = remote('journalctl -b -u rkn-guard-firewall.service --no-pager')
        remote('systemctl start antiscan-aggregate.service')
        results['collector'] = remote('systemctl show antiscan-aggregate.service --property=Result --value').strip()
        assert results['collector'] == 'success'
        remote('rkn-guard setup-logging')
        remote('logrotate --force /etc/logrotate.d/iptables-scanners')
        results['live_log'] = remote('timeout --signal=INT 2 rkn-guard logs v4; test $? -eq 124')
        assert 'LIVE' in results['live_log']
        assert 'rkn_probe_' not in remote('nft list tables')
        remote('rkn-guard uninstall --yes')
        assert 'rkn_guard' not in remote('nft list tables')
        results['result'] = 'PASS'
        (work/'result.json').write_text(json.dumps(results,ensure_ascii=False,indent=2))
        print('PASS: reboot, restored lists, manual IP, exception, uninstall',flush=True)
    except Exception as error:
        results.update(result='FAIL', error=str(error))
        (work/'result.json').write_text(json.dumps(results,ensure_ascii=False,indent=2))
        raise
    finally:
        vm.terminate()
        try: vm.wait(timeout=15)
        except subprocess.TimeoutExpired: vm.kill(); vm.wait()
        log.close()


if __name__ == '__main__':
    main()
