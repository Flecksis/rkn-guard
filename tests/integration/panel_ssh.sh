#!/usr/bin/env bash
# Запускать в отдельных пространствах имён mount, net и PID с OpenSSH.
set -euo pipefail
[[ $EUID == 0 && $$ == 1 && -n ${RKN_TEST_BINARY:-} ]]
mount --make-rprivate /
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
cp -a /etc "$root/etc"
mount --bind "$root/etc" /etc
for path in /var/lib /var/log /run /opt /usr/local/bin; do
    mount -t tmpfs tmpfs "$path"
done
mkdir -p /run/sshd /run/lock
if [[ -n ${RKN_TEST_SSHD_PACKAGE:-} ]]; then
    dpkg-deb -x "$RKN_TEST_SSHD_PACKAGE" "$root/pkg"
    if [[ -n ${RKN_TEST_LIBWRAP_PACKAGE:-} ]]; then
        dpkg-deb -x "$RKN_TEST_LIBWRAP_PACKAGE" "$root/pkg"
        mount -t tmpfs tmpfs /usr/local/lib
        cp -L "$(find "$root/pkg" -name libwrap.so.0 -print -quit)" /usr/local/lib/libwrap.so.0
        ldconfig -X
    fi
    mount --bind "$root/pkg/usr/lib/openssh" /usr/lib/openssh
    ln -s "$root/pkg/usr/sbin/sshd" /usr/local/bin/sshd
fi
export PATH="/usr/local/bin:/usr/sbin:/usr/bin:/bin"
for user in sshd _sshd; do
    id "$user" >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin "$user"
done
ip link set lo up
ssh-keygen -q -t ed25519 -N '' -f "$root/host"
printf 'HostKey %s/host\nPort 2244\nListenAddress 127.0.0.1\nUsePAM no\nPasswordAuthentication no\n' "$root" > /etc/ssh/sshd_config
cp "$RKN_TEST_BINARY" /usr/local/bin/rkn-guard
"$(command -v sshd)" -E "$root/ssh.log"
trap 'cat "$root/ssh.log" >&2' ERR
rkn-guard panel issue 127.0.0.1 2244 > "$root/code"
python3 - "$root" <<'PY'
import base64, json, pathlib, sys
d = pathlib.Path(sys.argv[1])
code = (d/"code").read_text().strip()
assert code.startswith("RKN1.")
p = json.loads(base64.urlsafe_b64decode(code[5:] + "==="))
assert p["host"] == "127.0.0.1" and p["port"] == 2244
(d/"known").write_text("[127.0.0.1]:2244 " + p["host_key"] + "\n")
(d/"bootstrap").write_text(p["bootstrap_key"])
PY
chmod 600 "$root/bootstrap"
ssh-keygen -q -t ed25519 -N '' -f "$root/panel"
ssh=(ssh -o "UserKnownHostsFile=$root/known" -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o BatchMode=yes -p 2244)
target=rkn-guard-user@127.0.0.1
pub=$(cut -d' ' -f1-2 "$root/panel.pub")
printf '{"public_key":"%s"}\n' "$pub" > "$root/enroll"
"${ssh[@]}" -i "$root/bootstrap" "$target" 'panel enroll' < "$root/enroll" | python3 -c 'import json,sys; assert json.load(sys.stdin)["ok"]'
if "${ssh[@]}" -i "$root/bootstrap" "$target" 'panel enroll' < "$root/enroll"; then exit 1; fi
# Проверяем отказ на неизвестную команду после входа.
printf '{"op":"shell"}\n' | "${ssh[@]}" -M -S "$root/control" -o ControlPersist=60 -i "$root/panel" "$target" 'panel session' | python3 -c 'import json,sys; assert not json.load(sys.stdin)["ok"]'
mkdir -p /var/log
printf '%s\n' '2026-01-02T03:04:05+00:00 host kernel: ANTISCAN-v4: SRC=192.0.2.1 PROTO=TCP DPT=443' >/var/log/iptables-scanners-ipv4.log
printf '%s\n' 'v4|198.51.100.9|AS64500|Сеть теста|7|2025-01-02T03:04:05+00:00' >/var/log/iptables-scanners-aggregate.csv
{
    for _ in {1..210}; do echo пробел; done
    printf '%s\n' '2025-12-31T09:00:00+00:00 host kernel: ANTISCAN-v6: SRC=2001:db8::9 PROTO=UDP DPT=53'
} | gzip > /var/log/iptables-scanners-ipv6.log.2.gz
iptables -N SCANNERS-BLOCK
iptables -A SCANNERS-BLOCK -j DROP
ip6tables -N SCANNERS-BLOCK
ip6tables -A SCANNERS-BLOCK -j DROP
snap() { "${ssh[@]}" -S "$root/control" "$target" 'panel session'; }
install -m755 "$(dirname "$0")/../../install.sh" /opt/rkn-guard-manager.sh
echo '{"op":"manage","action":"base-list"}' | snap | python3 -c 'import json,sys; assert "https://" in json.load(sys.stdin)["data"]["message"]'
echo '{"op":"manage","action":"schedule-show"}' | snap | python3 -c 'import json,sys; assert "выключено" in json.load(sys.stdin)["data"]["message"]'
echo '{"op":"manage","action":"interval","value":"0"}' | snap | python3 -c 'import json,sys; assert not json.load(sys.stdin)["ok"]'
echo '{"op":"manage","action":"ban","value":"bad-ip"}' | snap | python3 -c 'import json,sys; assert not json.load(sys.stdin)["ok"]'
echo '{"op":"manage","action":"ban-list"}' | snap | python3 -c 'import json,sys; assert json.load(sys.stdin)["ok"]'
echo '{"op":"manage","action":"shell"}' | snap | python3 -c 'import json,sys; assert not json.load(sys.stdin)["ok"]'
echo '{"op":"snapshot","archive_cursor":""}' | snap > "$root/snap"
python3 - "$root/snap" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["ok"], s
assert {f["family"] for f in s["data"]["families"]} == {"4", "6"}
assert s["data"]["events"][0]["port"] == 443
source = s["data"]["attack_sources"][0]
assert source["ip"] == "198.51.100.9" and source["count"] == 7 and source["asn"] == "AS64500"
system = s["data"]["system"]
assert system["cores"] > 0 and system["cpu_total"] >= system["cpu_idle"]
assert 0 <= system["mem_used"] <= system["mem_total"]
assert 0 <= system["disk_used"] <= system["disk_total"]
assert "branch" in s["data"]["version_info"]
assert s["data"]["log_archive"]["cursor"]
PY
python3 -c 'import json,sys; print(json.dumps(dict(op="snapshot",archive_cursor=json.load(open(sys.argv[1]))["data"]["log_archive"]["cursor"])))' "$root/snap" | snap | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]["log_archive"]; assert d["cursor"] is None; assert any(e["source"]=="2001:db8::9" and e["port"]==53 for e in d["events"])'
python3 -c 'import json,sys; print(json.dumps(dict(op="snapshot",cursor=json.load(open(sys.argv[1]))["data"]["cursor"])))' "$root/snap" | snap | python3 -c 'import json,sys; assert json.load(sys.stdin)["data"]["events"] == []'
cat > /opt/rkn-guard-manager.sh <<'SH'
#!/bin/sh
test "$1" = panel-update || exit 2
echo RKN_STAGE:build
sleep 6
echo RKN_STAGE:install
SH
chmod 755 /opt/rkn-guard-manager.sh
echo '{"op":"update"}' | snap > "$root/update" 2> "$root/progress"
python3 -c 'import json,sys; assert json.load(sys.stdin)["ok"]' < "$root/update"
grep -qx 'RKN_STAGE:build' "$root/progress"
grep -qx 'RKN_STAGE:heartbeat' "$root/progress"
grep -qx 'RKN_STAGE:install' "$root/progress"
rkn-guard panel revoke
if "${ssh[@]}" -S "$root/control" "$target" 'panel session' <<< '{"op":"update"}' > "$root/revoked"; then
    python3 -c 'import json,sys; assert not json.load(sys.stdin)["ok"]' < "$root/revoked"
fi
rkn-guard panel revoke
! getent passwd rkn-guard-user
[[ ! -e /etc/sudoers.d/rkn-guard-panel && ! -e /var/lib/rkn-guard-panel ]]
# Удаляем программу с ещё не использованным кодом.
install -m755 "$(dirname "$0")/../../install.sh" /opt/rkn-guard-manager.sh
rkn-guard panel issue 127.0.0.1 2244 >/dev/null
/opt/rkn-guard-manager.sh panel-uninstall > "$root/uninstall.log" 2>&1 || { cat "$root/uninstall.log"; exit 1; }
if getent passwd rkn-guard-user; then exit 1; fi
[[ ! -e /etc/sudoers.d/rkn-guard-panel && ! -e /var/lib/rkn-guard-panel ]]
[[ ! -e /usr/local/bin/rkn-guard && ! -e /opt/rkn-guard-manager.sh ]]
echo 'Проверены привязка, мониторинг, повторный код, отзыв и удаление.'
