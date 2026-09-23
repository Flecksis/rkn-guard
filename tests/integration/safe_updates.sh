#!/usr/bin/env bash
# DESTRUCTIVE: disposable Linux container only; requires CAP_NET_ADMIN and UFW.
set -euo pipefail
[[ -f /.dockerenv && ${RKN_DISPOSABLE_TEST:-} == yes ]] || { echo 'Use a disposable container and RKN_DISPOSABLE_TEST=yes'; exit 1; }
work=$(mktemp -d)
trap 'kill "${server:-}" 2>/dev/null || true; rm -rf "$work"' EXIT
printf '192.0.2.1\n2001:db8::1\n' > "$work/list"
printf '192.0.2.2\n2001:db8::2\n' > "$work/next"
printf '<html>error</html>\n' > "$work/invalid"
: > "$work/empty"
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$work" > "$work/http.log" 2>&1 & server=$!
for i in $(seq 1 50); do curl -fsS http://127.0.0.1:18080/list >/dev/null 2>&1 && break; sleep .1; done
url=http://127.0.0.1:18080
fail() { if "$@" > "$work/failure.log" 2>&1; then cat "$work/failure.log"; echo 'Expected failure'; exit 1; fi; }
ipset create unrelated hash:net
ipset add unrelated 198.51.100.1
rkn-guard update -u "$url/list" > "$work/update.log" 2>&1
cp /etc/ipset.conf "$work/previous"
for source in "$url/missing" "$url/invalid" "$url/empty" http://127.0.0.1:9/unavailable; do
    fail rkn-guard update -u "$url/next" -u "$source"
    cmp /etc/ipset.conf "$work/previous"
    ipset test SCANNERS-BLOCK-V4 192.0.2.1
    ipset test SCANNERS-BLOCK-V6 2001:db8::1
done
echo 'PASS: unavailable, partial, invalid and empty sources preserve both families and file'
mkdir "$work/bin"
cat > "$work/bin/ipset" <<'EOF'
#!/bin/sh
if [ "${FAIL_ADD:-}" = yes ] && [ "$1" = add ]; then exit 77; fi
if [ "${FAIL_SWAP6:-}" = yes ] && [ "$1" = swap ] && [ "$3" = SCANNERS-BLOCK-V6 ]; then exit 78; fi
exec /usr/sbin/ipset "$@"
EOF
chmod +x "$work/bin/ipset"
fail env PATH="$work/bin:$PATH" FAIL_ADD=yes rkn-guard update -u "$url/next"
fail env PATH="$work/bin:$PATH" FAIL_SWAP6=yes rkn-guard update -u "$url/next"
cmp /etc/ipset.conf "$work/previous"
ipset test SCANNERS-BLOCK-V4 192.0.2.1
ipset test SCANNERS-BLOCK-V6 2001:db8::1
echo 'PASS: staging and second-family swap failures preserve old lists'
mv /etc/ipset.conf "$work/persisted"
mkdir /etc/ipset.conf
fail rkn-guard update -u "$url/next"
rmdir /etc/ipset.conf
mv "$work/persisted" /etc/ipset.conf
ipset test SCANNERS-BLOCK-V4 192.0.2.1
ipset test SCANNERS-BLOCK-V6 2001:db8::1
echo 'PASS: persistence failure rolls both families back'
flock /run/rkn-guard.lock sh -c "touch '$work/locked'; sleep 5" & locker=$!
while [[ ! -f "$work/locked" ]]; do sleep .1; done
fail rkn-guard update -u "$url/next"
wait "$locker"
echo 'PASS: overlapping update rejected'
rkn-guard update -u "$url/next" > "$work/update.log" 2>&1
ipset test SCANNERS-BLOCK-V4 192.0.2.2
ipset test SCANNERS-BLOCK-V6 2001:db8::2
ipset test unrelated 198.51.100.1
if ipset list -name | grep -q RKN-NEXT; then echo 'Leaked staging set'; exit 1; fi
echo 'PASS: successful update changes both families and keeps unrelated set'
ufw allow 22/tcp >/dev/null
ufw --force enable >/dev/null
rkn-guard full -u "$url/next" > "$work/full.log" 2>&1
ufw status | grep 'Status: active'
iptables -C ufw-before-input -j SCANNERS-BLOCK
ip6tables -C ufw6-before-input -j SCANNERS-BLOCK
cp /etc/ufw/before.rules "$work/before4"
cp /etc/ufw/before6.rules "$work/before6"
cat > "$work/bin/ufw" <<'EOF'
#!/bin/sh
echo "$*" >> /tmp/rkn-ufw-calls
if [ "$1" = reload ] && [ -f /tmp/rkn-fail-reload ]; then rm /tmp/rkn-fail-reload; exit 77; fi
if [ "$1" = --force ] && [ "$2" = enable ]; then exit 78; fi
exec /usr/sbin/ufw "$@"
EOF
chmod +x "$work/bin/ufw"
: > /tmp/rkn-ufw-calls
touch /tmp/rkn-fail-reload
fail env PATH="$work/bin:$PATH" rkn-guard full -u "$url/next" --enable-logging
cmp /etc/ufw/before.rules "$work/before4"
cmp /etc/ufw/before6.rules "$work/before6"
ufw status | grep 'Status: active'
if grep -q disable /tmp/rkn-ufw-calls; then echo 'Disabled active firewall'; exit 1; fi
iptables -C ufw-before-input -j SCANNERS-BLOCK
ip6tables -C ufw6-before-input -j SCANNERS-BLOCK
echo 'PASS: failed reload returns failure, restores files and keeps UFW active'
/usr/sbin/ufw --force disable >/dev/null
fail env PATH="$work/bin:$PATH" rkn-guard full -u "$url/next"
cmp /etc/ufw/before.rules "$work/before4"
cmp /etc/ufw/before6.rules "$work/before6"
echo 'PASS: failed initial enable returns failure and restores files'
echo 'All isolated regression checks passed (systemd/reboot not tested).'
