import importlib.util
from pathlib import Path
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'internal/service/aggregate_logs.py'
spec = importlib.util.spec_from_file_location('live', SOURCE)
live = importlib.util.module_from_spec(spec); spec.loader.exec_module(live)

class LiveLogsTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'linux' and os.environ.get('RKN_TEST_BINARY'), 'Нужен Linux-бинарник')
    def test_menu_returns_after_interrupt(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp)/'rkn-guard'
            binary.symlink_to(Path(os.environ['RKN_TEST_BINARY']).resolve())
            output = Path(tmp)/'output'
            env = dict(os.environ, PATH=tmp+os.pathsep+os.environ['PATH'],
                       MENU_SOURCE=str(SOURCE.parents[2]/'install.sh'))
            with output.open('w') as dest:
                proc = subprocess.Popen(['bash','-c','source "$MENU_SOURCE"; view_log /var/log/iptables-scanners-ipv4.log; echo RETURNED'],
                                        stdout=dest,stderr=subprocess.PIPE,env=env,start_new_session=True)
                try:
                    deadline = time.monotonic()+5
                    while 'LIVE' not in output.read_text() and time.monotonic()<deadline:
                        time.sleep(.1)
                    self.assertIn('LIVE', output.read_text())
                    os.killpg(proc.pid,signal.SIGINT)
                    _, errors = proc.communicate(timeout=5)
                    self.assertEqual(proc.returncode,0,errors)
                    self.assertIn('RETURNED',output.read_text())
                finally:
                    if proc.poll() is None: os.killpg(proc.pid,signal.SIGKILL); proc.wait()

    def test_parse_and_moscow_time(self):
        row = live.live_event('2026-11-15T12:00:00Z host kernel: ANTISCAN-v6: IN=eth0 SRC=2001:db8::1 PROTO=TCP DPT=443')
        self.assertEqual(row, ['15.11.2026 15:00:00','2001:db8::1','TCP','443','eth0'])
        self.assertIsNone(live.live_event('garbage'))
        self.assertIsNone(live.live_event('ANTISCAN-v4: SRC=not-an-ip'))

    @unittest.skipUnless(sys.platform == 'linux', 'Нужен GNU tail')
    def test_follow_rotate_and_interrupt(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp)/'iptables-scanners-ipv4.log'
            output = Path(tmp)/'output'
            def event(ip): return f'2026-11-15T12:00:00Z host kernel: ANTISCAN-v4: IN=eth0 SRC={ip} PROTO=UDP DPT=53\n'
            log.write_text(event('192.0.2.1'))
            with output.open('w') as dest:
                proc = subprocess.Popen([sys.executable,'-u',str(SOURCE),'--live',str(log)],stdout=dest,stderr=subprocess.PIPE,start_new_session=True)
                def wait_for(value):
                    until = time.monotonic()+8
                    while time.monotonic()<until:
                        if value in output.read_text(): return
                        time.sleep(.1)
                    self.fail('Нет строки '+value)
                try:
                    wait_for('192.0.2.1')
                    with log.open('a') as f: f.write(event('192.0.2.2'))
                    wait_for('192.0.2.2')
                    log.rename(log.with_suffix('.old'))
                    log.write_text(event('192.0.2.3'))
                    wait_for('192.0.2.3')
                    os.killpg(proc.pid,signal.SIGINT)
                    _, errors = proc.communicate(timeout=5)
                    self.assertEqual(proc.returncode,0,errors)
                    text = output.read_text()
                    self.assertIn('ВРЕМЯ (МСК)',text)
                    self.assertIn('└',text)
                    self.assertNotIn('\x1b',text)
                finally:
                    if proc.poll() is None: os.killpg(proc.pid,signal.SIGKILL); proc.wait()

if __name__ == '__main__': unittest.main()
