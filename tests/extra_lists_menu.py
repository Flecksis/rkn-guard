#!/usr/bin/env python3
"""Проверяем меню дополнительных списков без обращения к системным наборам."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

BASH = os.environ.get("BASH", "bash")
SOURCE = Path(__file__).resolve().parents[1] / "install.sh"
HARNESS = r'''
source "$TEST_DIR/menu.sh"
SOURCES_FILE="$TEST_DIR/sources.json"
exec 3< "$TEST_DIR/input"
read_cancellable_input() { builtin read -r "$@" <&3 || terminal_unavailable; }
sleep() { :; }
rkn-guard() {
    printf '%s\n' "$*" >> "$TEST_DIR/calls"
    case "$1" in
        sources) [[ "$*" != *"${REJECT_ACTION:-NEVER}"* ]] ;;
        update) return "${UPDATE_RESULT:-0}" ;;
        *) return 99 ;;
    esac
}
'''


class ExtraListsMenuTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rkn-extra-menu-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "menu.sh").write_text(SOURCE.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")

    def run_menu(self, data, script="manage_extra_lists", status=0, **env):
        (self.root / "input").write_text(data, encoding="utf-8", newline="\n")
        result = subprocess.run([BASH, "--noprofile", "--norc", "-c", HARNESS + script],
                                env=dict(os.environ, TEST_DIR=self.root.as_posix(), **env),
                                capture_output=True, encoding="utf-8", errors="replace", timeout=10)
        self.assertEqual(result.returncode, status, result.stdout + result.stderr)
        calls = (self.root / "calls").read_text().splitlines()
        return result.stdout + result.stderr, calls

    def test_add_enable_disable_remove_routes_and_warning(self):
        output, calls = self.run_menu("1\nhttps://example.org/list\n2\n1\n3\n1\n4\n1\n0\n")
        self.assertLess(output.index("Не рекомендуется"), output.index("1. Добавить"))
        self.assertIn("Основные списки сохраняются", output)
        for action in ("add https://example.org/list", "enable 1", "disable 1", "remove 1"):
            self.assertEqual(sum(line.endswith(action) for line in calls), 1)
        updates = [line for line in calls if line.startswith("update ")]
        self.assertEqual(len(updates), 3)
        for line in updates:
            self.assertIn("--managed-lists", line)
            self.assertIn("--sources-file", line)
            self.assertIn("public/skipa.list", line)
        for line in calls:
            if line.startswith("sources "):
                self.assertEqual(line.count("--base-url"), 3)
                self.assertIn("public/skipa.list", line)

    def test_invalid_numbers_and_failed_changes_do_not_update(self):
        _, calls = self.run_menu("2\n0\n3\n-1\n4\n$(touch bad)\n2\n1\n0\n", REJECT_ACTION="enable 1")
        self.assertFalse(any(line.startswith("update ") for line in calls))
        self.assertEqual(sum(line.endswith("enable 1") for line in calls), 1)

    def test_failed_add_and_eof(self):
        output, calls = self.run_menu("1\nhttps://example.org/fail\n0\n", REJECT_ACTION="add ")
        self.assertIn("Не удалось добавить", output)
        self.assertFalse(any(line.startswith("update ") for line in calls))

    def test_manual_and_timer_report_partial_failure(self):
        for code, message in ((0, "Готово"), (2, "Обновление завершено с ошибками"), (1, "Обновление не выполнено")):
            with self.subTest(code=code):
                output, _ = self.run_menu("", script="update_lists", status=code, UPDATE_RESULT=str(code))
                self.assertIn(message, output)

    def test_failure_after_setting_explains_retry(self):
        output, calls = self.run_menu("2\n1\n0\n", UPDATE_RESULT="1")
        self.assertIn("Настройки сохранены", output)
        self.assertEqual(sum(line.startswith("update ") for line in calls), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
