#!/usr/bin/python3
"""Сбор новых событий без очистки логов; счётчики и позиции чтения сохраняются вместе."""
import argparse
import csv
import datetime as dt
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

HEADER = ["IP_TYPE", "IP_ADDRESS", "ASN", "NETNAME", "COUNT", "LAST_SEEN"]


def clean(value):
    return "".join(c for c in str(value) if c.isprintable()).strip()


def address(family, value):
    ip = ipaddress.ip_address(value)
    if family != "v" + str(ip.version):
        raise ValueError("IP family mismatch")
    return str(ip)


def timestamp(value, now):
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = dt.datetime.strptime(f"{now.year} {value}", "%Y %b %d %H:%M:%S")
            if parsed > now.replace(tzinfo=None) + dt.timedelta(days=1):
                parsed = parsed.replace(year=now.year - 1)
        except ValueError:
            return None
    # Время в формате RFC3164 указано в локальном часовом поясе сервера.
    return parsed.astimezone(dt.timezone.utc)


def add(rows, family, ip, count, seen, asn="UNKNOWN", name="UNKNOWN", now=None):
    ip = address(family, ip)
    key = family + "|" + ip
    row = rows.setdefault(key, dict(family=family, ip=ip, count=0, seen="",
                                    asn="UNKNOWN", name="UNKNOWN", lookup_after=0))
    row["count"] += count
    new_time, old_time = timestamp(seen, now), timestamp(row["seen"], now)
    if new_time and (not old_time or new_time > old_time):
        row["seen"] = new_time.isoformat()
    elif not row["seen"]:
        row["seen"] = clean(seen)
    for field, value in (("asn", asn), ("name", name)):
        if value and value != "UNKNOWN":
            row[field] = clean(value)


def read_csv(path, now, warnings):
    rows = {}
    try:
        source = path.open(encoding="utf-8-sig", errors="replace", newline="")
    except FileNotFoundError:
        return rows
    with source:
        for number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                fields = next(csv.reader([line], delimiter="|", strict=True))
                fields = [f.strip().lstrip("\ufeff") for f in fields]
                if fields == HEADER:
                    continue
                if len(fields) != 6 or not re.fullmatch(r"[0-9]+", fields[4]) or int(fields[4]) <= 0:
                    raise ValueError("invalid columns/count")
                add(rows, fields[0], fields[1], int(fields[4]), fields[5], fields[2], fields[3], now)
            except (ValueError, csv.Error):
                warnings.append(f"CSV: пропущена некорректная строка {number}")
    return rows


def atomic_write(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sorted_rows(rows):
    return sorted(rows.values(), key=lambda row: (-row["count"], row["family"],
                                                  int(ipaddress.ip_address(row["ip"]))))


def csv_text(rows):
    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter="|", lineterminator="\n")
    writer.writerow(HEADER)
    for row in sorted_rows(rows):
        writer.writerow([row[f] for f in ("family", "ip", "asn", "name", "count", "seen")])
    return output.getvalue()


def collect(log_dir, state_path, csv_path, cache_path, lookup=True, now=None):
    now = now or dt.datetime.now().astimezone()
    warnings = []
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if state.get("version") != 1 or not isinstance(state.get("rows"), dict) or not isinstance(state.get("cursors"), dict):
            raise ValueError("Некорректный файл состояния статистики")
    except FileNotFoundError:
        state = dict(version=1, rows=read_csv(csv_path, now, warnings), cursors={})
    rows, cursors = state["rows"], state["cursors"]
    visited = set()
    for family in ("v4", "v6"):
        current = log_dir / f"iptables-scanners-ip{family}.log"
        # Дочитываем отслеживаемый файл после переименования при ротации. Старые
        # архивы при переходе не перечитываем: их события уже могли попасть в CSV.
        paths = sorted(log_dir.glob(current.name + ".*")) + [current]
        for path in paths:
            if path.suffix == ".gz":
                continue
            try:
                source = path.open("rb")
            except FileNotFoundError:
                continue
            with source:
                stat = os.fstat(source.fileno())
                identity = f"{family}:{stat.st_dev}:{stat.st_ino}"
                if identity in visited or (path != current and identity not in cursors):
                    continue
                visited.add(identity)
                cursor = cursors.get(identity, dict(offset=0, prefix_size=0, prefix=""))
                old_prefix = source.read(cursor["prefix_size"])
                offset = cursor["offset"]
                if offset > stat.st_size or (cursor["prefix_size"] and hashlib.sha256(old_prefix).hexdigest() != cursor["prefix"]):
                    offset = 0
                source.seek(offset)
                while offset < stat.st_size:
                    raw = source.readline(stat.st_size - offset)
                    if not raw.endswith(b"\n"):
                        break  # Запись этой строки ещё может продолжаться.
                    offset += len(raw)
                    line = raw.decode("utf-8", errors="replace")
                    if f"ANTISCAN-{family}:" not in line:
                        continue
                    match = re.search(r"(?:^|\s)SRC=([^\s]+)(?=\s|$)", line)
                    if not match:
                        continue
                    fields = line.split()
                    seen = fields[0] if fields and timestamp(fields[0], now) else " ".join(fields[:3])
                    try:
                        add(rows, family, match[1], 1, seen, now=now)
                    except ValueError:
                        warnings.append(f"Лог: некорректный адрес {clean(match[1])}")
                source.seek(0)
                prefix = source.read(min(offset, 256))
                cursors[identity] = dict(offset=offset, prefix_size=len(prefix),
                                         prefix=hashlib.sha256(prefix).hexdigest(), last_seen=now.timestamp())
    # Сохраняем недавние позиции чтения на случай переименования во время обхода каталога.
    state["cursors"] = {k: v for k, v in cursors.items()
                        if k in visited or now.timestamp() - v.get("last_seen", 0) < 8 * 86400}
    enrich(rows, cache_path, lookup, now)
    # Основной файл состояния содержит и счётчики, и позиции чтения. При сбое
    # экспорта CSV повторный запуск восстановит его без повторного подсчёта событий.
    atomic_write(state_path, json.dumps(state, ensure_ascii=False), 0o600)
    atomic_write(csv_path, csv_text(rows), 0o640)
    return rows, warnings


def enrich(rows, cache_path, lookup, now):
    cache = {}
    try:
        for line in cache_path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split("|", 2)
            if len(parts) == 3:
                try:
                    cache[str(ipaddress.ip_address(parts[0]))] = parts[1:]
                except ValueError:
                    pass
    except OSError:
        pass  # Метаданные необязательны; недоступность старого кеша не мешает сбору.
    deadline = time.monotonic() + 2
    whois = shutil.which("whois") if lookup else None
    for row in rows.values():
        if row["ip"] in cache:
            asn, name = cache[row["ip"]]
            if asn != "UNKNOWN": row["asn"] = clean(asn)
            if name != "UNKNOWN": row["name"] = clean(name)
        if not whois or time.monotonic() >= deadline or row.get("lookup_after", 0) > now.timestamp():
            continue
        if row["asn"] != "UNKNOWN" and row["name"] != "UNKNOWN":
            continue
        row["lookup_after"] = now.timestamp() + 86400
        try:
            result = subprocess.run([whois, "-h", "whois.ripe.net", row["ip"]],
                                    capture_output=True, text=True, errors="replace",
                                    timeout=max(0.01, deadline - time.monotonic()))
            for field, pattern in (("asn", r"^origin:\s*(AS[0-9]+)\s*$"), ("name", r"^netname:\s*(.+)$")):
                match = re.search(pattern, result.stdout, re.MULTILINE | re.IGNORECASE)
                if match: row[field] = clean(match[1])
        except (OSError, subprocess.TimeoutExpired):
            pass  # Отсутствие метаданных не должно скрывать атаку или останавливать сбор.


def display(rows):
    if not rows:
        print("Нет зарегистрированных атак: подходящих записей в CSV и логах пока нет.")
        return
    print(f"АТАКИ: {len(rows)} адресов, по убыванию количества зарегистрированных событий")
    print("ТИП | IP | ASN | СЕТЬ | СОБЫТИЙ | ПОСЛЕДНЕЕ СОБЫТИЕ")
    for row in sorted_rows(rows):
        print(" | ".join(clean(row[f]) for f in ("family", "ip", "asn", "name", "count", "seen")))
    print("В журнал попадают только события, разрешённые лимитом логирования iptables.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--display", action="store_true")
    parser.add_argument("--no-whois", action="store_true")
    parser.add_argument("--log-dir", type=Path, default=Path("/var/log"))
    parser.add_argument("--state", type=Path, default=Path("/var/lib/rkn-guard/attack-stats.json"))
    parser.add_argument("--csv", type=Path, default=Path("/var/log/iptables-scanners-aggregate.csv"))
    parser.add_argument("--cache", type=Path, default=Path("/tmp/antiscan-whois-cache.txt"))
    parser.add_argument("--lock", type=Path, default=Path("/run/rkn-guard-stats.lock"))
    args = parser.parse_args()
    import fcntl
    try:
        with args.lock.open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if not args.display:
                    return 0
                print("Сбор статистики уже идёт; показан последний сохранённый CSV.", file=sys.stderr)
                rows = read_csv(args.csv, dt.datetime.now().astimezone(), [])
            else:
                rows, warnings = collect(args.log_dir, args.state, args.csv, args.cache, not args.no_whois)
                for warning in warnings:
                    print(warning, file=sys.stderr)
            if args.display:
                display(rows)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Не удалось прочитать или сохранить статистику: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
