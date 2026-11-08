#!/usr/bin/env python3
"""Проверки отказов через бинарник, без вызовов настоящего firewall."""
import functools
import http.server
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest


@unittest.skipUnless(os.environ.get('RKN_TEST_BINARY') and hasattr(os, 'geteuid') and os.geteuid() == 0,
                     'Нужны Linux, root для lock и RKN_TEST_BINARY')
class SourceFailuresCLI(unittest.TestCase):
    def test_base_switches_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            args = [os.environ['RKN_TEST_BINARY'], 'sources', '--sources-file',
                    str(Path(directory) / 'sources.json'), '--base-url', 'https://example.org/one',
                    '--base-url', 'https://example.org/two']
            def run(*action):
                result = subprocess.run(args + list(action), capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                return result.stdout
            self.assertEqual(run('base-list').count('● Включён'), 2)
            run('base-disable', '1')
            output = run('base-list')
            self.assertIn('1. ● Отключён', output)
            self.assertIn('2. ● Включён', output)
            run('base-enable', '1')
            self.assertEqual(run('base-list').count('● Включён'), 2)

    def test_install_and_update_without_usable_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            web = root / 'web'
            web.mkdir()
            (web / 'bad').write_text('192.0.2.1/32\nbroken')
            (web / 'empty').write_text('# пустой список\n')
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0),
                functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(web)))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            fake = root / 'bin'
            fake.mkdir()
            for name in ('ipset', 'iptables', 'ip6tables', 'ufw', 'apt-get', 'systemctl'):
                path = fake / name
                path.write_text('#!/bin/sh\necho called >> "' + str(root / 'calls') + '"\nexit 99\n')
                path.chmod(0o755)
            for command in ('full', 'update'):
                for paths in ([], ['missing'], ['bad', 'empty', 'missing']):
                    with self.subTest(command=command, paths=paths):
                        args = [os.environ['RKN_TEST_BINARY'], command, '--managed-lists',
                                '--sources-file', str(root / 'sources.json')]
                        for path in paths:
                            args += ['-u', f'http://127.0.0.1:{server.server_port}/{path}']
                        result = subprocess.run(args, env=dict(os.environ, PATH=str(fake) + ':' + os.environ['PATH']),
                                                capture_output=True, text=True, timeout=15)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn('пригодного кэша нет', result.stdout + result.stderr)
                        self.assertFalse((root / 'calls').exists(), 'вызвана системная команда без данных')


if __name__ == '__main__':
    unittest.main(verbosity=2)
