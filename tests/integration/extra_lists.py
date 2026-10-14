#!/usr/bin/env python3
"""Проверки бинарника и таймера на одноразовом Linux-раннере; ipset заменён моделью."""
import functools
import http.server
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
ALLOWED = (os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_OS") == "Linux"
           and hasattr(os, "geteuid") and os.geteuid() == 0)


class QuietHTTP(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@unittest.skipUnless(ALLOWED, "Только одноразовый Linux-раннер GitHub с правами root")
class ExtraListsIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rkn-extra-integration-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.web = self.work / "web"
        self.web.mkdir()
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.config = self.work / "sources.json"
        self.model = self.work / "sets.json"
        self.calls = self.work / "calls"
        self.model.write_text(json.dumps({"foreign": ["198.18.0.0/15"]}))
        self.calls.touch()
        self.write_list("gov", "192.0.2.0/25")
        self.write_list("scan", "192.0.2.128/25")
        self.write_list("skipa", "2001:db8::/32")
        self.write_list("extra", "198.51.100.0/24\n2001:db8:1::/48")
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(QuietHTTP, directory=str(self.web)))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.persist = Path("/etc/ipset.conf")
        previous = self.persist.read_bytes() if self.persist.exists() else None

        def restore():
            if previous is None:
                self.persist.unlink(missing_ok=True)
            else:
                self.persist.write_bytes(previous)

        self.addCleanup(restore)
        (self.bin / "rkn-guard").symlink_to(os.environ["RKN_TEST_BINARY"])
        model_script = f'''#!/usr/bin/python3
import json, sys
from pathlib import Path
path=Path({str(self.model)!r})
calls=Path({str(self.calls)!r})
with calls.open('a') as f: f.write(' '.join(sys.argv[1:])+'\\n')
sets=json.loads(path.read_text())
action,name,*args=sys.argv[1:]
if action=='create':
    if name in sets: sys.exit(1)
    sets[name]=[]
elif action=='add':
    if Path({str(self.work / 'fail-add')!r}).exists(): sys.exit(77)
    sets[name].append(args[0])
elif action=='swap': sets[name],sets[args[0]]=sets[args[0]],sets[name]
elif action=='destroy': del sets[name]
elif action=='list': sys.exit(0 if name in sets else 1)
elif action=='save':
    print('create '+name+' hash:net')
    for subnet in sets[name]: print('add '+name+' '+subnet)
else: sys.exit(99)
path.write_text(json.dumps(sets))
'''
        (self.bin / "ipset").write_text(model_script)
        (self.bin / "ipset").chmod(0o755)
        for name in ("iptables", "ip6tables", "ufw"):
            path = self.bin / name
            path.write_text(f"#!/bin/sh\necho forbidden-{name} >> {shlex.quote(str(self.calls))}\nexit 99\n")
            path.chmod(0o755)
        self.runner = self.work / "manager.sh"
        self.runner.write_text(f'''#!/bin/bash
export PATH={shlex.quote(str(self.bin))}:"$PATH"
source {shlex.quote(str(ROOT / 'install.sh'))}
SOURCES_FILE={shlex.quote(str(self.config))}
LIST_GOV={self.url}/gov
LIST_SCAN={self.url}/scan
LIST_SKIPA={self.url}/skipa
sleep() {{ :; }}
case "$1" in
    update) update_lists ;;
    manual)
        read_cancellable_input() {{ builtin read -r "$@" || terminal_unavailable; }}
        manage_updates ;;
    menu)
        read_cancellable_input() {{ builtin read -r "$@" || terminal_unavailable; }}
        manage_extra_lists ;;
    *) source_command "$@" ;;
esac
''')
        self.runner.chmod(0o755)

    def write_list(self, name, text):
        (self.web / name).write_text(text + "\n")

    def run_manager(self, *args, status=0, data=None):
        result = subprocess.run(["bash", str(self.runner), *args], input=data, text=True,
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, status, result.stdout + result.stderr)
        self.assertNotIn("forbidden-", self.calls.read_text())
        return result.stdout + result.stderr

    def networks(self):
        sets = json.loads(self.model.read_text())
        self.assertEqual(sets["foreign"], ["198.18.0.0/15"])
        self.assertFalse(any(name.startswith("RKN-NEXT") for name in sets))
        return set(sets.get("SCANNERS-BLOCK-V4", []) + sets.get("SCANNERS-BLOCK-V6", []))

    def test_menu_manual_update_cache_errors_and_restart(self):
        self.run_manager("menu", data=f"1\n{self.url}/extra\n2\n1\n0\n")
        expected = {"192.0.2.0/25", "192.0.2.128/25", "2001:db8::/32", "198.51.100.0/24", "2001:db8:1::/48"}
        self.assertEqual(self.networks(), expected)
        self.assertIn("включён", self.run_manager("list"))
        self.write_list("gov", "203.0.113.0/24")
        self.write_list("extra", "198.51.100.9/32\nnot-cidr")
        output = self.run_manager("manual", data="1\n0\n")
        self.assertIn("последние корректные данные", output)
        expected.remove("192.0.2.0/25")
        expected.add("203.0.113.0/24")
        self.assertEqual(self.networks(), expected)
        self.assertNotIn("198.51.100.9/32", self.persist.read_text())
        (self.web / "extra").unlink()
        self.assertIn("последние корректные данные", self.run_manager("update", status=2))
        self.assertEqual(self.networks(), expected)
        self.run_manager("menu", data="3\n1\n0\n")
        expected -= {"198.51.100.0/24", "2001:db8:1::/48"}
        self.assertEqual(self.networks(), expected)
        self.run_manager("menu", data="4\n1\n0\n")
        self.assertEqual(json.loads(self.config.read_text())["extra"], [])
        self.assertEqual(self.networks(), expected)

    def test_shared_lock_and_failed_ipset_keep_previous_sets(self):
        import fcntl
        self.run_manager("update")
        before = self.model.read_bytes(), self.persist.read_bytes(), self.config.read_bytes()
        with open("/run/rkn-guard.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.run_manager("add", self.url + "/extra", status=1)
            self.run_manager("update", status=1)
        self.assertEqual(before, (self.model.read_bytes(), self.persist.read_bytes(), self.config.read_bytes()))
        self.write_list("gov", "203.0.113.0/24")
        (self.work / "fail-add").touch()
        self.run_manager("update", status=1)
        self.assertEqual(before[:2], (self.model.read_bytes(), self.persist.read_bytes()))
        (self.work / "fail-add").unlink()
        self.run_manager("update")
        self.assertIn("203.0.113.0/24", self.networks())

    def test_real_systemd_timer_uses_enabled_lists_and_reports_error(self):
        self.run_manager("add", self.url + "/extra")
        self.run_manager("enable", "1")
        self.run_manager("update")
        self.write_list("gov", "203.0.113.16/28")
        (self.web / "extra").unlink()
        unit = "rkn-extra-test-" + uuid.uuid4().hex

        def cleanup_unit():
            subprocess.run(["systemctl", "stop", unit + ".timer", unit + ".service"], capture_output=True)
            subprocess.run(["systemctl", "reset-failed", unit + ".service"], capture_output=True)

        self.addCleanup(cleanup_unit)
        result = subprocess.run(["systemd-run", "--unit=" + unit, "--on-active=1s",
                                 "--timer-property=AccuracySec=100ms", "/bin/bash", str(self.runner), "update"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            state = subprocess.run(["systemctl", "show", "--property=ActiveState", "--value", unit + ".service"],
                                   capture_output=True, text=True).stdout.strip()
            if state == "failed":
                break
            time.sleep(0.1)
        else:
            self.fail("таймер не завершил проверку ошибки")
        code = subprocess.check_output(["systemctl", "show", "--property=ExecMainStatus", "--value", unit + ".service"], text=True)
        self.assertEqual(code.strip(), "2")
        self.assertIn("203.0.113.16/28", self.networks())
        self.assertIn("198.51.100.0/24", self.networks())
        logs = subprocess.check_output(["journalctl", "-u", unit + ".service", "--no-pager"], text=True)
        self.assertIn("последние корректные данные", logs)

    @unittest.skipUnless(os.environ.get("RKN_TEST_PUBLIC_LISTS") == "yes", "Проверка внешних URL включается отдельно")
    def test_public_raw_lists_validate_without_applying(self):
        sources = [
            "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist-v4.txt",
            "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/skipa.list",
        ]
        public_config = self.work / "public-sources.json"
        for url in sources:
            result = subprocess.run([os.environ["RKN_TEST_BINARY"], "sources", "--sources-file", str(public_config), "add", url],
                                    capture_output=True, text=True, timeout=40)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        saved = json.loads(public_config.read_text())
        self.assertEqual(len(saved["extra"]), 2)
        for source in saved["extra"]:
            self.assertFalse(source["enabled"])
            self.assertGreater(len(saved["cache"][source["url"]]["networks"]), 0)
            print(source["url"], len(saved["cache"][source["url"]]["networks"]), "проверенных подсетей")
        self.assertEqual(self.calls.read_text(), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
