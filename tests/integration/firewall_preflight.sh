#!/usr/bin/env bash
# Интеграционный тест preflight-защиты rkn-guard (D5/D9/атомарность v4+v6).
#
# Запускается ВНУТРИ одноразового контейнера с systemd, ipset, iptables, ufw, sshd.
# Проверяет:
#   1. нет ipset  → exit 3, firewall байт-идентичен;
#   2. нет SSH    → exit 3, firewall байт-идентичен (обязательные порты не подтверждены);
#   3. нормальный путь → exit 0, цепочка есть и в IPv4, и в IPv6, UFW остаётся active.
#
# Использование: firewall_preflight.sh /usr/local/bin/rkn-guard
set -uo pipefail

BIN="${1:-/usr/local/bin/rkn-guard}"
WORK="${WORK:-/srv/rkn-preflight}"
LOG="$WORK/test.log"
FAILS=0

log() { printf '%s\n' "$*" | tee -a "$LOG"; }
pass() { log "PASS: $*"; }
fail() { log "FAIL: $*"; FAILS=$((FAILS + 1)); }

fingerprint() {
    {
        # Счётчики пакетов меняются от любого трафика — сравниваем только правила.
        iptables-save 2>/dev/null | grep -v '^#' | sed -E 's/[\[[0-9]+:[0-9]+\]]/[0:0]/g'
        echo '--- v6 ---'
        ip6tables-save 2>/dev/null | grep -v '^#' | sed -E 's/[\[[0-9]+:[0-9]+\]]/[0:0]/g'
        echo '--- ufw ---'
        ufw status verbose 2>/dev/null
        echo '--- policy ---'
        iptables -S INPUT 2>/dev/null | head -1
        ip6tables -S INPUT 2>/dev/null | head -1
    } | sha256sum | awk '{print $1}'
}

with_timeout() { timeout 180 "$@"; }

mkdir -p "$WORK"
: >"$LOG"
log "== rkn-guard preflight integration =="
log "binary: $BIN"
"$BIN" build-info >>"$LOG" 2>&1 || true

# ---- подготовка источника списков -------------------------------------------------
mkdir -p "$WORK/lists"
printf '203.0.113.0/24\n198.51.100.0/24\n' >"$WORK/lists/v4.txt"
printf '2001:db8:dead::/48\n' >"$WORK/lists/v6.txt"
LIST_URL="http://127.0.0.1:8099/v4.txt"
LIST_URL6="http://127.0.0.1:8099/v6.txt"
python3 -m http.server 8099 --bind 127.0.0.1 --directory "$WORK/lists" >"$WORK/http.log" 2>&1 &
HTTP_PID=$!
trap 'kill $HTTP_PID 2>/dev/null' EXIT
sleep 1

ARGS=(full --urls "$LIST_URL" --urls "$LIST_URL6")

wait_port() { # wait_port <port> <present|absent>
    local i
    for i in $(seq 1 20); do
        if ss -lnt "sport = :$1" | grep -q LISTEN; then
            [ "$2" = present ] && return 0
        else
            [ "$2" = absent ] && return 0
        fi
        sleep 0.5
    done
    return 1
}

# Стенд: слушатель на 22 (в образе нет sshd-юнита) и активный UFW,
# иначе FIX-1 справедливо откажет раньше D9.
pkill -f 'http.server 22' 2>/dev/null
sleep 0.5
python3 -m http.server 22 --bind 0.0.0.0 >"$WORK/ssh22.log" 2>&1 &
SSH_PID=$!
ufw allow 22/tcp >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1
ufw reload >/dev/null 2>&1
wait_port 22 present || { log "FATAL: слушатель 22 не поднялся — стенд не пригоден"; exit 1; }

# ---- 1. нет ipset: отказ без изменений -------------------------------------------
log ""
log "---- 1) установка без ipset ----"
BEFORE=$(fingerprint)
if [ -x /usr/sbin/ipset ]; then mv /usr/sbin/ipset /usr/sbin/ipset.hidden; IPSET_HIDDEN=1; else IPSET_HIDDEN=0; fi
with_timeout "$BIN" "${ARGS[@]}" >>"$LOG" 2>&1
rc=$?
AFTER=$(fingerprint)
if [ "$IPSET_HIDDEN" = 1 ]; then mv /usr/sbin/ipset.hidden /usr/sbin/ipset; fi
log "exit=$rc (ожидалось 3)"
[ "$rc" = 3 ] && pass "без ipset отказ с кодом 3" || fail "без ipset код $rc вместо 3"
[ "$BEFORE" = "$AFTER" ] && pass "firewall байт-идентичен после отказа (нет ipset)" || fail "firewall изменён при отказе (нет ipset)"
grep -q "ipset недоступен" "$LOG" && pass "в логе явная причина: ipset недоступен" || fail "в логе нет причины про ipset"

# ---- 2. нет SSH: обязательные порты не подтверждены ------------------------------
log ""
log "---- 2) установка при недоступном SSH ----"
BEFORE=$(fingerprint)
kill "$SSH_PID" 2>/dev/null; wait "$SSH_PID" 2>/dev/null; pkill -f 'http.server 22' 2>/dev/null
wait_port 22 absent || log "WARN: порт 22 всё ещё слушается"
with_timeout "$BIN" "${ARGS[@]}" --required-ports 22,2222,443,2443,2087 >>"$LOG" 2>&1
rc=$?
AFTER=$(fingerprint)
python3 -m http.server 22 --bind 0.0.0.0 >"$WORK/ssh22.log" 2>&1 &
SSH_PID=$!
wait_port 22 present || log "WARN: слушатель 22 не поднялся после теста"
log "exit=$rc (ожидалось 3)"
[ "$rc" = 3 ] && pass "без SSH отказ с кодом 3" || fail "без SSH код $rc вместо 3"
[ "$BEFORE" = "$AFTER" ] && pass "firewall байт-идентичен после отказа (нет SSH)" || fail "firewall изменён при отказе (нет SSH)"
grep -q "SSH-порта" "$LOG" && pass "в логе причина про SSH-порт" || fail "в логе нет причины про SSH"

# ---- 3. нормальный путь -----------------------------------------------------------
log ""
log "---- 3) нормальная установка (UFW active, оба семейства) ----"
with_timeout "$BIN" "${ARGS[@]}" >>"$LOG" 2>&1
rc=$?
log "exit=$rc (ожидалось 0)"
[ "$rc" = 0 ] && pass "нормальный путь завершён с кодом 0" || fail "нормальный путь код $rc"

v4=$(iptables -S SCANNERS-BLOCK 2>/dev/null | grep -c '^-A')
v6=$(ip6tables -S SCANNERS-BLOCK 2>/dev/null | grep -c '^-A')
log "правил в SCANNERS-BLOCK: v4=$v4 v6=$v6"
[ "$v4" -gt 0 ] && [ "$v6" -gt 0 ] && pass "оба набора созданы (v4 и v6 атомарно)" || fail "нет одного из наборов: v4=$v4 v6=$v6"
iptables -S ufw-before-input 2>/dev/null | grep -q -- '-j SCANNERS-BLOCK' && pass "v4 привязан к ufw-before-input" || fail "нет привязки v4"
ip6tables -S ufw6-before-input 2>/dev/null | grep -q -- '-j SCANNERS-BLOCK' && pass "v6 привязан к ufw6-before-input" || fail "нет привязки v6"
grep -q "Обязательные порты" "$LOG" && pass "обязательные порты явно залогированы" || fail "нет лога обязательных портов"
ufw status 2>/dev/null | grep -q "Status: active" && pass "UFW остался active" || fail "UFW не active после установки"

# ---- очистка ----------------------------------------------------------------------
log ""
log "---- 4) uninstall для чистоты стенда ----"
with_timeout "$BIN" uninstall --yes --remove-logs >>"$LOG" 2>&1
rc=$?
[ "$rc" = 0 ] && pass "uninstall завершён" || fail "uninstall код $rc"

log ""
if [ "$FAILS" -eq 0 ]; then
    log "RESULT: PASS (все проверки пройдены)"
    exit 0
fi
log "RESULT: FAIL ($FAILS проверок не прошли)"
exit 1
