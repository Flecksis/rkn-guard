#!/usr/bin/env python3
"""Проверки расписания, сохранения настроек и отката при сбоях без изменения системы."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

BASH = os.environ.get("BASH", "bash")
SOURCE = Path(__file__).resolve().parents[1] / "install.sh"
HARNESS = r'''
source "$TEST_DIR/menu.sh"
SCHEDULE_CONFIG="$TEST_DIR/schedule.conf"
SCHEDULE_UNIT_DIR="$TEST_DIR/units"
SCHEDULE_LOCK="$TEST_DIR/schedule.lock"
MANAGER_PATH="$TEST_DIR/menu.sh"
flock() {
    if [[ "${REAL_FLOCK:-0}" == 1 ]]; then command flock "$@";
    else [[ "${FLOCK_FAIL:-0}" != 1 ]]; fi
}
systemctl() {
    printf '%s\n' "$*" >> "$TEST_DIR/commands"
    if [[ "$1" == "${FAIL_COMMAND:-never}" && ! -e "$TEST_DIR/failed" ]]; then
        touch "$TEST_DIR/failed"
        return 1
    fi
    case "$1" in
        is-enabled) [[ -f "$TEST_DIR/enabled" ]] ;;
        is-active) [[ -f "$TEST_DIR/active" ]] ;;
        enable) touch "$TEST_DIR/enabled" ;;
        start) touch "$TEST_DIR/active" ;;
        disable) rm -f "$TEST_DIR/enabled" "$TEST_DIR/active" ;;
        daemon-reload) return 0 ;;
        *) printf 'Unexpected systemctl call: %s\n' "$*" >&2; return 99 ;;
    esac
}
'''


class ScheduleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rkn-schedule-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "units").mkdir()
        (self.root / "menu.sh").write_text(SOURCE.read_text(encoding="utf-8"),
                                          encoding="utf-8", newline="\n")
        self.env = dict(os.environ, TEST_DIR=self.root.as_posix())

    def run_shell(self, script, status=0, **env):
        result = subprocess.run([BASH, "--noprofile", "--norc", "-c", HARNESS + script],
                                env=dict(self.env, **env), capture_output=True,
                                timeout=15, encoding="utf-8", errors="replace")
        self.assertEqual(result.returncode, status, result.stdout + result.stderr)
        return result.stdout

    def snapshot(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes()
                for p in self.root.rglob("*") if p.is_file()
                and (p.parent.name == "units" or p.name in ("schedule.conf", "enabled", "active"))}

    def test_input_normalization(self):
        for mode, value, expected in [
            ("off", "", ""), ("interval", "001", "1"), ("interval", "168", "168"),
            ("msk", "06:00", "06:00"), ("local", "06:00", "06:00"),
            ("hours", "18, 6,06:00,00,23:59", "00:00,06:00,18:00,23:59"),
        ]:
            with self.subTest(mode=mode, value=value):
                output = self.run_shell('\nnormalize_schedule "$MODE" "$VALUE"', MODE=mode, VALUE=value)
                self.assertEqual(output, expected)

    def test_invalid_inputs_cannot_change_schedule(self):
        self.run_shell("\nset_update_schedule msk 06:00")
        before = self.snapshot()
        cases = [("interval", x) for x in ("", "0", "169", "-1", "1.5", "999999999999", "1;id", " 6")]
        cases += [("hours", x) for x in ("", " ", "24", "-1", "6:60", "6:1", "6,,12", ",6", "6,",
                                             "6\n12", "$(touch pwned)", "6 " * 150, ",".join(["6"] * 25))]
        cases += [("msk", "07:00"), ("local", "07:00"), ("off", "6"), ("unknown", "")]
        for mode, value in cases:
            with self.subTest(mode=mode, value=value):
                self.run_shell('\nset_update_schedule "$MODE" "$VALUE"', status=1, MODE=mode, VALUE=value)
                self.assertEqual(self.snapshot(), before)

    def test_all_modes_persist_switch_and_disable(self):
        for mode, value in (("interval", "7"), ("hours", "18,6,18"), ("msk", "06:00"), ("local", "06:00")):
            with self.subTest(mode=mode):
                self.run_shell('\nset_update_schedule "$MODE" "$VALUE"', MODE=mode, VALUE=value)
                timer = (self.root / "units/rkn-guard-update.timer").read_text()
                if mode == "interval":
                    self.assertIn("OnActiveSec=7h\nOnUnitActiveSec=7h", timer)
                    self.assertNotIn("OnCalendar", timer)
                else:
                    self.assertNotIn("OnActiveSec", timer)
                    if mode == "local":
                        self.assertIn("OnCalendar=*-*-* 06:00:00\n", timer)
                        self.assertNotIn("Europe/Moscow", timer)
                    else:
                        self.assertIn("OnCalendar=*-*-* 06:00:00 Europe/Moscow", timer)
                    self.assertEqual(timer.count("OnCalendar="), 2 if mode == "hours" else 1)
                    self.assertIn("Persistent=true", timer)
                self.assertEqual(len(list((self.root / "units").iterdir())), 2)
                output = self.run_shell("\nload_update_schedule; printf '%s:%s\\n' \"$SCHEDULE_MODE\" \"$SCHEDULE_VALUE\"; show_update_schedule")
                self.assertIn(mode + ":", output)
                self.assertIn("активно", output)
                before = self.snapshot()
                (self.root / "commands").write_text("")
                self.run_shell('\nset_update_schedule "$MODE" "$VALUE"', MODE=mode, VALUE=value)
                self.assertEqual(self.snapshot(), before)
                commands = (self.root / "commands").read_text()
                self.assertNotIn("disable", commands)
                self.assertNotIn("start ", commands)
        self.run_shell("\nset_update_schedule off ''")
        self.assertFalse((self.root / "active").exists())
        self.assertFalse((self.root / "enabled").exists())
        self.assertEqual((self.root / "schedule.conf").read_text(), "off=\n")
        self.assertIn("выключено", self.run_shell("\nshow_update_schedule"))
        self.assertNotIn("stop rkn-guard-update.service", (self.root / "commands").read_text())

    def test_systemctl_failures_restore_existing_schedule(self):
        self.run_shell("\nset_update_schedule interval 6")
        before = self.snapshot()
        for failure in ("disable", "daemon-reload", "enable", "start"):
            with self.subTest(failure=failure):
                (self.root / "failed").unlink(missing_ok=True)
                self.run_shell("\nset_update_schedule hours '6,18'", status=1, FAIL_COMMAND=failure)
                self.assertEqual(self.snapshot(), before)

    def test_first_install_failure_leaves_no_schedule(self):
        self.run_shell("\nset_update_schedule msk 06:00", status=1, FAIL_COMMAND="start")
        self.assertEqual(self.snapshot(), {})

    def install_prompt(self, answer, status=0, **env):
        (self.root / "input").write_text(answer, newline="\n")
        return self.run_shell(r'''
exec 3< "$TEST_DIR/input"
read_cancellable_input() { builtin read -r "$@" <&3 || terminal_unavailable; }
offer_install_schedule
''', status=status, **env)

    def test_install_yes_uppercase_repeated_and_invalid_input(self):
        for answer in ("y\n", "Y\n", "maybe\ny\n"):
            self.install_prompt(answer)
            self.assertEqual((self.root / "schedule.conf").read_text(), "local=06:00\n")
            timer = (self.root / "units/rkn-guard-update.timer").read_text()
            self.assertIn("OnCalendar=*-*-* 06:00:00\n", timer)
            self.assertNotIn("Europe/Moscow", timer)
            self.assertEqual(len(list((self.root / "units").iterdir())), 2)
        self.assertEqual((self.root / "commands").read_text().count("enable rkn-guard-update.timer"), 1)
        self.assertIn("локальное время сервера", self.run_shell("\nshow_update_schedule"))

    def test_install_decline_preserves_existing_settings(self):
        for answer in ("n\n", "N\n", "\n"):
            self.install_prompt(answer)
            self.assertEqual(self.snapshot(), {})
        self.run_shell("\nset_update_schedule interval 7")
        before = self.snapshot()
        self.install_prompt("n\n")
        self.assertEqual(self.snapshot(), before)

    def test_install_prompt_eof_and_schedule_failure(self):
        self.install_prompt("", status=1)
        self.assertEqual(self.snapshot(), {})
        self.install_prompt("y\n", status=1, FAIL_COMMAND="start")
        self.assertEqual(self.snapshot(), {})

    def test_full_installer_reaches_prompt_after_success(self):
        # Сохраняем порядок установки, заменяя пути к файлам и системные команды.
        # Пакеты, правила firewall и реальные сервисы не изменяются.
        menu = self.root / "menu.sh"
        text = menu.read_text(encoding="utf-8").replace("/var/log", '${TEST_DIR}/logs')
        menu.write_text(text, encoding="utf-8", newline="\n")
        (self.root / "input").write_text("Y\n", newline="\n")
        self.run_shell(r'''
exec 3< "$TEST_DIR/input"
MANUAL_FILE="$TEST_DIR/manual.list"
read_cancellable_input() { builtin read -r "$@" <&3 || terminal_unavailable; }
check_firewall_safety() { :; }
clear() { :; }
apt-get() { :; }
curl() { printf ':\n'; }
install_menu_command() { :; }
chown() { :; }
getent() { return 1; }
sleep() { :; }
eval "$(declare -f systemctl | sed '1s/systemctl/mock_systemctl/')"
systemctl() {
    case "$*" in
        *rsyslog*|*antiscan-aggregate*) return 0 ;;
        *) mock_systemctl "$@" ;;
    esac
}
rkn-guard() { printf '%s\n' "$*" >> "$TEST_DIR/installed"; }
install_process
''')
        self.assertIn("full -u https://", (self.root / "installed").read_text())
        self.assertEqual((self.root / "schedule.conf").read_text(), "local=06:00\n")

    def test_config_is_not_executed_and_status_reflects_stopped_timer(self):
        (self.root / "schedule.conf").write_text("hours=$(touch pwned)\n")
        self.assertIn("ошибка чтения", self.run_shell("\nshow_update_schedule"))
        (self.root / "schedule.conf").write_text("interval=6\nextra=value\n")
        self.run_shell("\nload_update_schedule", status=1)
        self.run_shell("\nset_update_schedule interval 6")
        (self.root / "active").unlink()
        self.assertIn("таймер не активен", self.run_shell("\nshow_update_schedule"))

    def test_settings_lock_rejects_competing_writer(self):
        self.run_shell("\nset_update_schedule interval 6", status=1, FLOCK_FAIL="1")
        self.assertEqual(self.snapshot(), {})

    def test_menu_routes_all_modes_and_manual_update(self):
        (self.root / "input").write_text("1\n2\n0\n2\n6\n3\n24\n3\n6,18\n4\n5\n0\n", newline="\n")
        output = self.run_shell(r'''
exec 3< "$TEST_DIR/input"
read_cancellable_input() { builtin read -r "$@" <&3 || terminal_unavailable; }
rkn-guard() { printf '%s\n' "$*" >> "$TEST_DIR/updates"; }
sleep() { :; }
manage_updates
''')
        self.assertEqual((self.root / "schedule.conf").read_text(), "off=\n")
        self.assertEqual(len((self.root / "updates").read_text().splitlines()), 1)
        self.assertIn("update -u https://", (self.root / "updates").read_text())
        self.assertIn("каждые 6 ч.", output)
        self.assertIn("06:00,18:00 (МСК)", output)
        self.assertIn("ежедневно в 06:00 (МСК)", output)
        self.assertEqual((self.root / "commands").read_text().count("enable rkn-guard-update.timer"), 3)

    def test_uninstall_removes_owned_schedule_only(self):
        self.run_shell("\nset_update_schedule msk 06:00")
        unrelated = self.root / "units/antiscan-aggregate.timer"
        unrelated.write_text("unrelated")
        self.run_shell("\nremove_update_schedule")
        self.assertEqual(self.snapshot(), {"units/antiscan-aggregate.timer": b"unrelated"})

    @unittest.skipUnless(sys.platform.startswith("linux"), "Requires Linux flock")
    def test_real_flock_rejects_competing_writer(self):
        import fcntl
        with open(self.root / "schedule.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.run_shell("\nset_update_schedule interval 6", status=1, REAL_FLOCK="1")
        self.run_shell("\nset_update_schedule interval 6", REAL_FLOCK="1")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Requires systemd-analyze")
    def test_systemd_parses_all_timer_modes_and_moscow_timezone(self):
        self.assertIsNotNone(shutil.which("systemd-analyze"))
        for mode, value in (("interval", "7"), ("hours", "0,06:00,18:30,23:59"), ("msk", "06:00"), ("local", "06:00")):
            self.run_shell('\nset_update_schedule "$MODE" "$VALUE"', MODE=mode, VALUE=value)
            result = subprocess.run(["systemd-analyze", "verify", "--man=no",
                                     str(self.root / "units/rkn-guard-update.timer"),
                                     str(self.root / "units/rkn-guard-update.service")],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = subprocess.run(["systemd-analyze", "calendar", "--base-time=2026-10-12 00:00:00 UTC",
                                 "*-*-* 06:00:00 Europe/Moscow"],
                                env=dict(os.environ, TZ="UTC"), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("2026-10-12 03:00:00 UTC", result.stdout)
        result = subprocess.run(["systemd-analyze", "calendar", "--base-time=2026-10-12 00:00:00 UTC",
                                 "*-*-* 06:00:00"],
                                env=dict(os.environ, TZ="UTC"), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("2026-10-12 06:00:00 UTC", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
