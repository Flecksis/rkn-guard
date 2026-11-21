"""Привязка RKN1 и команды панели на сервере."""
import base64
import contextlib
import datetime
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

USER = "rkn-guard-user"
HOME = Path("/var/lib/rkn-guard-panel")
OWNER = HOME / "owner"
KEYS = HOME / ".ssh/authorized_keys"
SUDO = Path("/etc/sudoers.d/rkn-guard-panel")
BIN = "/usr/local/bin/rkn-guard"
MANAGER = "/opt/rkn-guard-manager.sh"
ACCOUNT_TAG = "rkn-guard-panel managed SSH account"


def run(*args):
    return subprocess.check_output(args, text=True).strip()


@contextlib.contextmanager
def locked():
    # Блокируем родительский каталог, чтобы блокировка пережила удаление привязки.
    fd = os.open(HOME.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def atomic(path, data, mode):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        tmp = Path(f.name)
        try:
            f.write(data.encode())
            f.flush()
            os.fchmod(f.fileno(), mode)
            tmp.replace(path)
        finally:
            tmp.unlink(missing_ok=True)


def account():
    try:
        return pwd.getpwnam(USER)
    except KeyError:
        return None


def check_owner():
    if HOME.is_symlink() or not OWNER.is_file() or OWNER.read_text() != ACCOUNT_TAG:
        raise ValueError("Каталог привязки не принадлежит rkn-guard-panel")
    user = account()
    if user and (user.pw_dir != str(HOME) or user.pw_gecos != ACCOUNT_TAG or user.pw_uid == 0):
        raise ValueError("Учётная запись принадлежит другой установке")


def revoke(disconnect=True):
    if not HOME.exists():
        return
    check_owner()
    KEYS.unlink(missing_ok=True)
    SUDO.unlink(missing_ok=True)
    user = account()
    if user:
        if disconnect:
            result = subprocess.run(["pkill", "-KILL", "-u", str(user.pw_uid)])
            if result.returncode not in (0, 1):
                raise ValueError("Не удалось завершить SSH-соединения панели")
        run("userdel", "--force", USER)
    shutil.rmtree(HOME)


def forced(mode, nonce, expires):
    return f"/usr/bin/sudo -n {BIN} panel rpc {mode} {nonce} {expires}"


def authorize(mode, key, expires):
    nonce = secrets.token_hex(24)
    options = "restrict"
    if expires:
        utc = datetime.datetime.fromtimestamp(expires, datetime.timezone.utc)
        options += ',expiry-time="' + utc.strftime("%Y%m%d%H%M%SZ") + '"'
    line = f'{options},command="{forced(mode, nonce, expires)}" {key}\n'
    atomic(KEYS, line, 0o644)


def issue(host, port):
    if not re.fullmatch(r"[A-Za-z0-9.:][A-Za-z0-9.:-]{0,252}", host) or not 0 < port < 65536:
        raise ValueError("Проверьте адрес и порт SSH")
    if HOME.exists() or account() or SUDO.exists():
        raise ValueError("Привязка или одноимённая учётная запись уже существует. Сначала отзовите старую привязку.")
    config = run("sshd", "-T").splitlines()
    # Берём ключ Ed25519 из конфигурации sshd.
    for line in config:
        if line.startswith("hostkey "):
            path = Path(line.split(" ", 1)[1] + ".pub")
            if path.is_file() and path.read_text().startswith("ssh-ed25519 "):
                host_key = " ".join(path.read_text().split()[:2])
                break
    else:
        raise ValueError("В sshd требуется ключ хоста Ed25519")
    with tempfile.TemporaryDirectory() as temp:
        key = Path(temp) / "bootstrap"
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
        sudoers = Path(temp) / "sudoers"
        sudoers.write_text(f"{USER} ALL=(root) NOPASSWD: {BIN} panel rpc *\n")
        run("visudo", "-cf", str(sudoers))
        HOME.mkdir(mode=0o755)
        OWNER.write_text(ACCOUNT_TAG)
        try:
            run("useradd", "--system", "--no-create-home", "--home-dir", str(HOME),
                "--shell", "/bin/sh", "--comment", ACCOUNT_TAG,
                "--password", "*", USER)
            KEYS.parent.mkdir(mode=0o755)
            # sshd читает authorized_keys от имени служебного пользователя.
            HOME.chmod(0o755)
            KEYS.parent.chmod(0o755)
            atomic(SUDO, sudoers.read_text(), 0o440)
            expires = int(time.time()) + 300
            authorize("enroll", " ".join(key.with_suffix(".pub").read_text().split()[:2]), expires)
            payload = dict(host=host, port=port, expires=expires, host_key=host_key,
                           bootstrap_key=key.read_text())
            return "RKN1." + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        except BaseException:
            revoke()
            raise


def public_key(value):
    if not isinstance(value, str):
        raise ValueError("Требуется открытый ключ Ed25519")
    match = re.fullmatch(r"ssh-ed25519 ([A-Za-z0-9+/]{68})", value)
    if not match:
        raise ValueError("Некорректный открытый ключ панели")
    wire = base64.b64decode(match[1], validate=True)
    if len(wire) != 51 or wire[:19] != bytes.fromhex("0000000b") + b"ssh-ed25519" + bytes.fromhex("00000020"):
        raise ValueError("Некорректный формат Ed25519")
    return value


def counters(backend):
    result = []
    if backend in ("nftables", "firewalld"):
        rules = json.loads(run("nft", "-j", "list", "chain", "inet", "rkn_guard", "input"))["nftables"]
        for family in ("4", "6"):
            for obj in rules:
                expr = obj.get("rule", {}).get("expr", [])
                if not any("drop" in e for e in expr):
                    continue
                if any(e.get("match", {}).get("right") == "@blocked" + family for e in expr):
                    counter = next(e["counter"] for e in expr if "counter" in e)
                    result.append(dict(family=family, packets=counter["packets"], bytes=counter["bytes"]))
    elif backend == "iptables":
        for family, tool in (("4", "iptables"), ("6", "ip6tables")):
            proc = subprocess.run([tool, "-w", "3", "-nvxL", "SCANNERS-BLOCK"], capture_output=True, text=True)
            if proc.returncode and family == "6" and "No chain" in proc.stderr:
                continue
            proc.check_returncode()
            drops = [line.split()[:2] for line in proc.stdout.splitlines()
                     if re.match(r"\s*\d+\s+\d+\s+DROP\s", line)]
            if drops:
                result.append(dict(family=family, packets=sum(int(a) for a, b in drops),
                                   bytes=sum(int(b) for a, b in drops)))
    if not result:
        raise ValueError("Не удалось прочитать счётчики цепочки rkn-guard")
    return result


def events(cursor):
    # У каждого журнала своя позиция чтения. Пути заданы на сервере.
    previous = json.loads(cursor) if cursor else {}
    positions, rows = {}, []
    for family in ("4", "6"):
        path = Path(f"/var/log/iptables-scanners-ipv{family}.log")
        if not path.is_file():
            continue
        with path.open("rb") as stream:
            info = os.fstat(stream.fileno())
            inode, offset = previous.get(family, [0, 0])
            if not isinstance(offset, int) or offset < 0:
                raise ValueError("Некорректная позиция журнала")
            if inode == info.st_ino and offset <= info.st_size:
                stream.seek(offset)
            elif family not in previous and info.st_size > 65536:
                stream.seek(-65536, 2)
                stream.readline(8192)
            for _ in range(100):
                raw = stream.readline(8192)
                if not raw:
                    break
                line = raw.decode(errors="replace").rstrip()
                fields = dict(re.findall(r"\b(SRC|PROTO|DPT)=([^\s]+)", line))
                if not fields.get("SRC") or not fields.get("PROTO"):
                    continue
                try:
                    ipaddress.ip_address(fields["SRC"])
                    port = int(fields["DPT"]) if "DPT" in fields else None
                    if port is not None and not 0 <= port <= 65535:
                        continue
                    try:
                        stamp = datetime.datetime.fromisoformat(line.split()[0].replace("Z", "+00:00"))
                    except ValueError:
                        now = datetime.datetime.now()
                        stamp = datetime.datetime.strptime(f"{now.year} {line[:15]}", "%Y %b %d %H:%M:%S")
                        if stamp > now + datetime.timedelta(days=1):
                            stamp = stamp.replace(year=now.year - 1)
                    rows.append(dict(time=int(stamp.timestamp()), source=fields["SRC"],
                                     protocol=fields["PROTO"], port=port, raw=line[:1500]))
                except (ValueError, OverflowError):
                    continue
            positions[family] = [info.st_ino, stream.tell()]
    return rows, json.dumps(positions)


def rpc(mode, nonce, expires, request):
    with locked():
        check_owner()
        expires = int(expires)
        if not re.fullmatch("[0-9a-f]{48}", nonce) or f'command="{forced(mode, nonce, expires)}"' not in KEYS.read_text():
            raise ValueError("Привязка отозвана или код уже использован")
        if mode == "enroll":
            if expires <= time.time():
                raise ValueError("Срок кода истёк")
            authorize("session", public_key(request.get("public_key")), 0)
            return {}
        op = request.get("op")
        if mode != "session":
            raise ValueError("Неизвестная команда")
        if op == "snapshot":
            backend = run(BIN, "firewall-status").splitlines()[0]
            rows, cursor = events(request.get("cursor", ""))
            return dict(version=run(BIN, "build-info").splitlines()[0], firewall=backend,
                        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                        cursor=cursor, events=rows, families=counters(backend))
        if op == "update":
            run(MANAGER, "panel-update")
        elif op == "uninstall" and request.get("confirm") is True:
            # Отзываем доступ под блокировкой до запуска удаления.
            revoke(disconnect=False)
            run(MANAGER, "panel-uninstall")
        else:
            raise ValueError("Неизвестная операция панели")
        return {}


def main(args):
    if os.geteuid() != 0:
        raise ValueError("Требуются права root")
    if len(args) == 4 and args[0] == "rpc":
        data = sys.stdin.buffer.readline(16385)
        if len(data) > 16384 or not data.endswith(b"\n"):
            raise ValueError("Некорректный запрос")
        print(json.dumps(dict(ok=True, data=rpc(*args[1:], json.loads(data)))))
    elif len(args) == 3 and args[0] == "issue":
        with locked():
            print(issue(args[1], int(args[2])))
    elif args == ["revoke"]:
        with locked():
            revoke()
    else:
        raise ValueError("Используйте panel issue АДРЕС ПОРТ или panel revoke")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as error:
        if sys.argv[1:2] == ["rpc"]:
            print(json.dumps(dict(ok=False, error=str(error))))
        else:
            sys.exit(str(error))
