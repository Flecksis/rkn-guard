#!/usr/bin/env python3
"""Проверки регрессий ввода меню; все команды firewall заменены безопасными заглушками."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


BASH = os.environ.get("BASH", "bash")
SOURCE = Path(__file__).resolve().parents[1] / "install.sh"
MESSAGE = "Терминал недоступен, завершаю меню."
HARNESS = r'''
source "$MENU_SOURCE"
# Как в установленном скрипте: nounset включён, errexit выключен.
set +e
trap '' HUP
MANUAL_FILE="$TEST_DIR/manual.list"
SCHEDULE_CONFIG="$TEST_DIR/schedule.conf"
printf '192.0.2.1\n' > "$MANUAL_FILE"
choice=5 action=1 ip=192.0.2.99 input=192.0.2.99 confirm=y renders=0
# Принудительно останавливаем версии с зацикливанием, не дожидаясь таймаута.
clear() { (( ++renders <= 10 )) || exit 99; }
refresh_version_status() { :; }
sleep() { :; }
record() { printf '%s\n' "$*" >> "$TEST_DIR/actions"; }
ipset() { [[ "$1" == list ]] || record "ipset $*"; }
iptables() { :; }
rkn-guard() {
    record "rkn-guard $1"
    if [[ "$1" == update && "${LOSE_TTY:-0}" == 1 ]]; then
        command rm -- "$TEST_TTY"
    fi
    if [[ "$1" == update && "${WAIT_FOR_HANGUP:-0}" == 1 ]]; then
        while [[ ! -f "$TEST_DIR/resume" ]]; do command sleep 0.01; done
    fi
}
systemctl() { return 1; }
rm() { record "rm $*"; }
install_process() { record install; }
update_application() { record application-update; }
set_update_schedule() { record "schedule $*"; }
if [[ "${MOCK_INPUT:-0}" == 1 ]]; then
    exec 3< "$TEST_DIR/input"
    read() {
        # При сбое перенаправления переменная сохраняет прежнее значение. Проверяем
        # то же поведение при ошибке read, включая сохранённый ответ подтверждения.
        [[ "${FAIL_READ:-0}" == 1 ]] && return 1
        builtin read "$@" <&3
    }
fi
"$ENTRY"
'''


class MenuHarness(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rkn-menu-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = os.environ.copy()
        self.env.update(TEST_DIR=self.root.as_posix(), ENTRY="show_menu")
        (self.root / "actions").touch()

    def start(self, **kwargs):
        self.output = open(self.root / "output", "wb")
        self.addCleanup(self.output.close)
        self.proc = subprocess.Popen(
            [BASH, "--noprofile", "--norc", "-c", HARNESS],
            env=self.env, stdout=self.output, stderr=self.output, **kwargs
        )
        self.addCleanup(self.stop)

    def stop(self):
        if self.proc.poll() is None:
            if os.name == "nt":
                # Программа запуска Git Bash может оставить дочернюю оболочку работающей.
                subprocess.run(["taskkill", "/PID", str(self.proc.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                self.proc.kill()
            self.proc.wait(timeout=5)

    def finish(self, status, actions):
        try:
            actual_status = self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            output = (self.root / "output").read_text(encoding="utf-8", errors="replace")
            self.fail("Menu did not exit; possible repeated action or busy loop\n" + output[-6000:])
        output = (self.root / "output").read_text(encoding="utf-8", errors="replace")
        self.assertEqual(actual_status, status, output)
        self.assertEqual(output.count(MESSAGE), int(status == 1), output)
        self.assertEqual((self.root / "actions").read_text().splitlines(), actions)

    def mock_run(self, entry, data="", status=1, actions=(), **env):
        # Только в этой копии заменяем /dev/tty для проверки всех запросов на ОС
        # без псевдотерминалов. Проверки Linux ниже используют исходный скрипт.
        fixture = self.root / "menu.sh"
        fixture.write_text(
            SOURCE.read_text(encoding="utf-8").replace("/dev/tty", '"${TEST_TTY}"'),
            encoding="utf-8", newline="\n",
        )
        tty = self.root / "tty"
        tty.touch()
        (self.root / "input").write_text(data, encoding="utf-8", newline="\n")
        self.env.update(MENU_SOURCE=fixture.as_posix(), TEST_TTY=tty.as_posix(),
                        MOCK_INPUT="1", ENTRY=entry, **env)
        self.start(stdin=subprocess.DEVNULL)
        self.finish(status, list(actions))


class MenuTests(MenuHarness):
    def test_eof_at_each_prompt(self):
        cases = [
            ("show_menu", "", []),
            ("show_menu", "1\n", ["rkn-guard stats"]),
            ("show_menu", "5\n", []),
            ("show_menu", "5\n1\n", ["rkn-guard update"]),
            ("manage_updates", "", []),
            ("manage_updates", "2\n", []),
            ("manage_updates", "3\n", []),
            ("manage_test_ip", "", []),
            ("manage_test_ip", "1\n", []),
            ("manage_test_ip", "1\n192.0.2.2\n", ["ipset add SCANNERS-BLOCK-V4 192.0.2.2"]),
            ("manage_test_ip", "2\n", []),
            ("manage_test_ip", "2\n192.0.2.1\n", ["ipset del SCANNERS-BLOCK-V4 192.0.2.1"]),
            ("uninstall_process", "", []),
            ("offer_install_schedule", "", []),
        ]
        for entry, data, actions in cases:
            with self.subTest(entry=entry, data=data):
                (self.root / "actions").write_text("")
                self.mock_run(entry, data, actions=actions)

    def test_failed_read_does_not_use_stale_values(self):
        for entry in ("show_menu", "manage_test_ip", "manage_updates", "uninstall_process", "offer_install_schedule"):
            with self.subTest(entry=entry):
                self.mock_run(entry, FAIL_READ="1")

    def test_failed_open_does_not_repeat_update(self):
        self.mock_run("show_menu", "5\n1\n", actions=["rkn-guard update"], LOSE_TTY="1")

    def test_normal_navigation(self):
        self.mock_run("show_menu", "5\n1\n0\n4\n0\n8\nn\n0\n", status=0,
                      actions=["rkn-guard update"])


@unittest.skipUnless(sys.platform.startswith("linux"), "Requires Linux controlling PTYs")
class LinuxTerminalTests(MenuHarness):
    def original_source(self):
        self.env["MENU_SOURCE"] = SOURCE.as_posix()

    def wait_for(self, filename, text, count=1):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            output = (self.root / filename).read_text(encoding="utf-8", errors="replace")
            if output.count(text) >= count:
                return
            if self.proc.poll() is not None:
                break
            time.sleep(0.01)
        self.fail(f"Menu did not reach {text!r} ({count} times)\n{output[-6000:]}")

    def start_terminal(self):
        import fcntl
        import pty
        import termios

        self.original_source()
        master, slave = pty.openpty()

        def attach_terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.start(stdin=slave, preexec_fn=attach_terminal)
        os.close(slave)
        return master

    def test_start_without_controlling_terminal(self):
        self.original_source()
        self.start(stdin=subprocess.DEVNULL, start_new_session=True)
        self.finish(1, [])

    def test_real_terminal_eof(self):
        master = self.start_terminal()
        try:
            self.wait_for("output", "Ваш выбор:")
            os.write(master, b"\x04")
            self.finish(1, [])
        finally:
            os.close(master)

    def test_terminal_lost_after_update(self):
        self.env["WAIT_FOR_HANGUP"] = "1"
        master = self.start_terminal()
        try:
            self.wait_for("output", "Ваш выбор:")
            os.write(master, b"5\n1\n")
            self.wait_for("actions", "rkn-guard update")
        finally:
            os.close(master)
            (self.root / "resume").touch()
        self.finish(1, ["rkn-guard update"])

    def test_ctrl_c_still_cancels_ip_input(self):
        master = self.start_terminal()
        try:
            self.wait_for("output", "Ваш выбор:")
            os.write(master, b"4\n1\n")
            self.wait_for("output", "IP: ")
            os.write(master, b"\x03")
            self.wait_for("output", "Отмена.")
            self.wait_for("output", "Действие:", count=2)
            os.write(master, b"0\n")
            self.wait_for("output", "Ваш выбор:", count=2)
            os.write(master, b"0\n")
            self.finish(0, [])
        finally:
            os.close(master)

    def test_schedule_input_cancel_then_terminal_loss(self):
        master = self.start_terminal()
        try:
            self.wait_for("output", "Ваш выбор:")
            os.write(master, b"5\n2\n")
            self.wait_for("output", "Интервал в часах (1–168):")
            os.write(master, b"\x03")
            self.wait_for("output", "Обновления — выбор:", count=2)
        finally:
            os.close(master)
        self.finish(1, [])


if __name__ == "__main__":
    if not shutil.which(BASH):
        raise SystemExit(f"Bash not found: {BASH}")
    unittest.main(verbosity=2)
