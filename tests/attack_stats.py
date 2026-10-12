#!/usr/bin/env python3
"""Проверки сбора CSV и логов во временных файлах без изменения firewall и сетевых запросов."""
import contextlib
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "internal/service/aggregate_logs.py"
spec = importlib.util.spec_from_file_location("attack_stats", SOURCE)
stats = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stats)
NOW = dt.datetime(2026, 10, 12, 12, tzinfo=dt.timezone.utc)


def event(ip="192.0.2.1", family="v4", stamp="2026-10-12T06:00:00+00:00"):
    return f"{stamp} server kernel: ANTISCAN-{family}: IN=eth0 SRC={ip} DST=192.0.2.200\n"


class StatisticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rkn-stats-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state.json"
        self.csv = self.root / "aggregate.csv"
        self.cache = self.root / "cache"
        self.v4 = self.root / "iptables-scanners-ipv4.log"
        self.v6 = self.root / "iptables-scanners-ipv6.log"

    def write(self, path, content):
        path.write_text(content, encoding="utf-8", newline="\n")

    def collect(self):
        return stats.collect(self.root, self.state, self.csv, self.cache, lookup=False, now=NOW)

    def display(self, rows):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            stats.display(rows)
        return output.getvalue()

    def test_csv_all_records_numeric_sort_and_duplicate_aggregation(self):
        data = "\ufeff" + "|".join(stats.HEADER) + "\r\n"
        for n in range(1, 31):
            data += f'v4|192.0.2.{n}|UNKNOWN|UNKNOWN|{n}|2026-10-12T04:00:00Z\r\n'
        data += '|'.join(stats.HEADER) + '\n'
        data += 'v4|192.0.2.1|AS123|"A | B"|100|2026-10-12T05:00:00Z\n'
        self.write(self.csv, data)
        rows, warnings = self.collect()
        self.assertEqual(warnings, [])
        self.assertEqual(len(rows), 30)
        self.assertEqual(rows['v4|192.0.2.1']['count'], 101)
        self.assertEqual(rows['v4|192.0.2.1']['name'], 'A | B')
        self.assertEqual([r['count'] for r in stats.sorted_rows(rows)], [101] + list(range(30, 1, -1)))
        output = self.display(rows)
        for n in range(1, 31):
            self.assertIn(f'192.0.2.{n} |', output)
        self.assertEqual(stats.read_csv(self.csv, NOW, []), rows)

    def test_headerless_first_record_and_invalid_rows(self):
        self.write(self.csv, 'v4|192.0.2.1|||2|old\n'
                   'broken\nv4|bad|AS1|name|2|old\nv4|192.0.2.2|AS1|name|-1|old\n'
                   'v6|2001:db8::1|AS1|name|9|old\n'
                   'v4|192.0.2.3|AS1|"unterminated|3|old\n')
        rows, warnings = self.collect()
        self.assertEqual(len(warnings), 4)
        self.assertEqual(rows['v4|192.0.2.1']['count'], 2)
        self.assertEqual(rows['v6|2001:db8::1']['count'], 9)
        self.assertIn('UNKNOWN', self.display(rows))

    def test_empty_missing_and_header_only_csv(self):
        for content in (None, '', '|'.join(stats.HEADER) + '\n'):
            with self.subTest(content=content):
                self.state.unlink(missing_ok=True)
                self.csv.unlink(missing_ok=True)
                if content is not None:
                    self.write(self.csv, content)
                rows, _ = self.collect()
                self.assertIn('Нет зарегистрированных атак', self.display(rows))
                self.write(self.v4, event())
                rows, _ = self.collect()
                self.assertEqual(rows['v4|192.0.2.1']['count'], 1)
                self.v4.unlink()

    def test_exact_ips_both_families_filtering_and_latest_time(self):
        self.write(self.v4, event('1.2.3.4') + event('1.2.3.40', stamp='2026-10-12T09:00:00Z')
                   + event('1.2.3.4', stamp='2026-10-12T08:00:00Z')
                   + event('1.2.3.4', stamp='2026-10-12T04:00:00Z')
                   + event('1.2.3.4').replace('ANTISCAN-v4:', 'OTHER:')
                   + event('invalid') + event('2001:db8::1'))
        self.write(self.v6, event('2001:0db8::1', 'v6') + event('2001:db8::1', 'v6')
                   + event('::ffff:192.0.2.1', 'v6', 'Oct 12 10:00:00'))
        rows, warnings = self.collect()
        self.assertEqual(len(warnings), 2)
        self.assertEqual(rows['v4|1.2.3.4']['count'], 3)
        self.assertEqual(rows['v4|1.2.3.4']['seen'], '2026-10-12T08:00:00+00:00')
        self.assertEqual(rows['v4|1.2.3.40']['count'], 1)
        self.assertEqual(rows['v6|2001:db8::1']['count'], 2)
        self.assertEqual(len(rows), 4)

    def test_incremental_partial_lines_and_logs_are_never_truncated(self):
        self.write(self.v4, event() + event().rstrip('\n'))
        original = self.v4.read_bytes()
        rows, _ = self.collect()
        self.assertEqual(rows['v4|192.0.2.1']['count'], 1)
        self.assertEqual(self.v4.read_bytes(), original)
        rows, _ = self.collect()
        self.assertEqual(rows['v4|192.0.2.1']['count'], 1)
        with self.v4.open('ab') as output:
            output.write(b'\n' + event().encode())
        rows, _ = self.collect()
        self.assertEqual(rows['v4|192.0.2.1']['count'], 3)
        self.assertEqual(self.collect()[0]['v4|192.0.2.1']['count'], 3)

    def test_rotation_and_truncation(self):
        self.write(self.v4.with_suffix('.log.2'), event() * 10)
        self.write(self.v4, event())
        self.collect()
        rotated = self.v4.with_suffix('.log.1')
        self.v4.rename(rotated)
        with rotated.open('a', newline='\n') as output:
            output.write(event())
        self.write(self.v4, event('192.0.2.2'))
        rows, _ = self.collect()
        self.assertEqual(rows['v4|192.0.2.1']['count'], 2)
        self.assertEqual(rows['v4|192.0.2.2']['count'], 1)
        # При том же inode и не меньшем размере смена начала файла обнаруживает copytruncate.
        self.write(self.v4, event('192.0.2.3') * 2)
        rows, _ = self.collect()
        self.assertEqual(rows['v4|192.0.2.3']['count'], 2)
        self.assertEqual(sum(r['count'] for r in rows.values()), 5)
        self.assertEqual(self.collect()[0], rows)

    def test_failure_before_commit_preserves_input_for_retry(self):
        self.write(self.v4, event())
        with patch.object(stats, 'atomic_write', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.collect()
        self.assertFalse(self.state.exists())
        self.assertEqual(self.v4.read_text(), event())
        self.assertEqual(self.collect()[0]['v4|192.0.2.1']['count'], 1)

    def test_csv_export_failure_retries_without_double_counting(self):
        self.write(self.v4, event())
        real_write = stats.atomic_write

        def failing_export(path, data, mode):
            if path == self.csv:
                raise OSError('disk full')
            real_write(path, data, mode)

        with patch.object(stats, 'atomic_write', side_effect=failing_export):
            with self.assertRaises(OSError):
                self.collect()
        self.assertTrue(self.state.exists())
        self.assertEqual(self.collect()[0]['v4|192.0.2.1']['count'], 1)

    def test_metadata_lookup_uses_exact_ip_and_is_optional(self):
        self.write(self.v4, event('1.2.3.4') + event('1.2.3.40'))
        self.write(self.cache, '1.2.3.40|AS40|Forty\n1x2x3x4|BAD|BAD\n')
        rows, _ = self.collect()
        self.assertEqual(rows['v4|1.2.3.4']['asn'], 'UNKNOWN')
        self.assertEqual(rows['v4|1.2.3.40']['asn'], 'AS40')
        with patch.object(stats.shutil, 'which', return_value='whois'), \
                patch.object(stats.subprocess, 'run', side_effect=subprocess.TimeoutExpired('whois', 2)):
            stats.enrich(rows, self.cache, True, NOW)
        self.assertEqual(rows['v4|1.2.3.4']['count'], 1)
        self.assertGreater(rows['v4|1.2.3.4']['lookup_after'], NOW.timestamp())

    def test_corrupt_state_does_not_overwrite_previous_files(self):
        self.write(self.state, '{broken')
        self.write(self.csv, 'previous')
        with self.assertRaises(ValueError):
            self.collect()
        self.assertEqual(self.state.read_text(), '{broken')
        self.assertEqual(self.csv.read_text(), 'previous')

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Requires Linux flock')
    def test_real_collector_cli_and_concurrent_display(self):
        import fcntl
        self.write(self.v4, event())
        command = [sys.executable, str(SOURCE), '--no-whois', '--display',
                   '--log-dir', str(self.root), '--state', str(self.state), '--csv', str(self.csv),
                   '--cache', str(self.cache), '--lock', str(self.root / 'lock')]
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('192.0.2.1', result.stdout)
        before = self.state.read_bytes()
        with (self.root / 'lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('уже идёт', result.stderr)
            self.assertIn('192.0.2.1', result.stdout)
            self.assertEqual(self.state.read_bytes(), before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
