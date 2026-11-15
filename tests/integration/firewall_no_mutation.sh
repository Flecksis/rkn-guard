#!/bin/bash
# tests/integration/firewall_no_mutation.sh
#
# Проверяет на живой системе (или в контейнере) три свойства:
#   (a) установка при выключенном UFW НЕ включает UFW и НЕ меняет политику INPUT;
#   (b) после uninstall состояние firewall равно снимку, снятому до установки;
#   (c) повторная установка идемпотентна (те же правила, те же файлы).
#
# Требования: root, iptables/ip6tables, ufw, ipset, systemd, curl.
# Переменные:
#   RKN_GUARD_BIN — путь к бинарнику (по умолчанию /usr/local/bin/rkn-guard)
#   LIST_URL      — URL списка подсетей (по умолчанию http://127.0.0.1:8899/list.txt)
#   KEEP_STATE    — при 1 не выключать UFW в конце (для ручного разбора)
set -u

BIN=${RKN_GUARD_BIN:-/usr/local/bin/rkn-guard}
LIST_URL=${LIST_URL:-http://127.0.0.1:8899/list.txt}
WORK=$(mktemp -d)
FAILED=0

pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; FAILED=$((FAILED + 1)); }
info() { printf '  .. %s\n' "$*"; }

cleanup() {
    if [ "${KEEP_STATE:-0}" != "1" ]; then
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { printf 'нужен root\n' >&2; exit 2; }
[ -x "$BIN" ] || { printf 'не найден бинарник %s\n' "$BIN" >&2; exit 2; }

# capture_state — канонизированное состояние firewall для сравнения.
capture_state() {
    local out=$1
    {
        echo "== ufw status"
        ufw status verbose 2>&1 | sed 's/[[:space:]]*$//'
        echo "== ufw.conf ENABLED"
        grep -E '^ENABLED' /etc/ufw/ufw.conf 2>&1
        echo "== default policies"
        grep -E '^DEFAULT_(INPUT|FORWARD|OUTPUT)_POLICY' /etc/default/ufw 2>&1
        echo "== iptables"
        # счётчики пакетов/байт не сравниваем
        iptables-save 2>&1 | grep -v '^#' | sed -E 's/\[[0-9]+:[0-9]+\]/[C]/g'
        echo "== ip6tables"
        ip6tables-save 2>&1 | grep -v '^#' | sed -E 's/\[[0-9]+:[0-9]+\]/[C]/g'
        echo "== ipset"
        ipset save 2>&1 | sort
        echo "== before.rules"
        sha256sum /etc/ufw/before.rules /etc/ufw/before6.rules /etc/ufw/user.rules /etc/ufw/user6.rules 2>&1
        echo "== units"
        for u in ufw.service antiscan-ipset-restore.service antiscan-move-rules.service rkn-guard-update.timer; do
            printf '%s=%s\n' "$u" "$(systemctl is-enabled "$u" 2>&1)"
        done
    } > "$out"
}

reset_host() {
    ufw --force reset >/dev/null 2>&1
    ufw --force disable >/dev/null 2>&1
    systemctl stop ufw >/dev/null 2>&1
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -t nat -F 2>/dev/null
    ip6tables -F 2>/dev/null
    ip6tables -X 2>/dev/null
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    ip6tables -P INPUT ACCEPT 2>/dev/null
    ip6tables -P FORWARD ACCEPT 2>/dev/null
    iptables -D INPUT -j SCANNERS-BLOCK 2>/dev/null
    ip6tables -D INPUT -j SCANNERS-BLOCK 2>/dev/null
    ipset destroy SCANNERS-BLOCK-V4 2>/dev/null
    ipset destroy SCANNERS-BLOCK-V6 2>/dev/null
    # чистим артефакты прошлых прогонов, чтобы baseline был действительно чистым
    for u in antiscan-ipset-restore.service antiscan-move-rules.service antiscan-aggregate.service \
             antiscan-aggregate.timer rkn-guard-update.service rkn-guard-update.timer; do
        systemctl disable "$u" >/dev/null 2>&1
        systemctl stop "$u" >/dev/null 2>&1
    done
    rm -f /etc/systemd/system/antiscan-* /etc/systemd/system/rkn-guard-*
    systemctl daemon-reload >/dev/null 2>&1
    rm -rf /var/lib/rkn-guard/snapshot
}

ufw_active() { ufw status 2>/dev/null | grep -q 'Status: active'; }

# enable_ufw_baseline — включает UFW и проверяет, что цепочки реально собраны.
# В контейнерах после ручных iptables -F ufw может считать себя включённым,
# оставляя INPUT без jump'ов; тогда пересобираем состояние.
enable_ufw_baseline() {
    ufw --force enable >/dev/null 2>&1
    if ! iptables -S INPUT 2>/dev/null | grep -q 'ufw-before-input'; then
        ufw --force disable >/dev/null 2>&1
        ufw --force enable >/dev/null 2>&1
    fi
    iptables -S INPUT 2>/dev/null | grep -q 'ufw-before-input'
}

printf '\n=== (a) установка при выключенном UFW не трогает firewall ===\n'
reset_host
capture_state "$WORK/state-a-before"

"$BIN" full --urls "$LIST_URL" >"$WORK/a-install.log" 2>&1
rc=$?

info "код возврата установки: $rc"
capture_state "$WORK/state-a-after"

[ "$rc" -ne 0 ] && pass "установка завершилась ненулевым кодом ($rc)" || fail "установка вернула 0 при выключенном UFW"
if grep -q 'FIREWALL НЕ ИЗМЕНЁН\|firewall не изменён\|ErrUFWInactive\|выключен' "$WORK/a-install.log"; then
    pass "причина отказа — выключенный UFW"
else
    fail "установка упала не из-за firewall: $(tail -2 "$WORK/a-install.log" | tr '\n' ' ')"
fi
if ufw_active; then fail "UFW был включён установкой"; else pass "UFW остался выключен"; fi
if diff -u "$WORK/state-a-before" "$WORK/state-a-after" >"$WORK/diff-a.txt"; then
    pass "состояние firewall не изменилось"
else
    fail "состояние firewall изменилось: см. $WORK/diff-a.txt"; sed -n '1,20p' "$WORK/diff-a.txt"
fi
if iptables -S INPUT 2>/dev/null | grep -q 'ufw-before-input'; then
    fail "в INPUT появились цепочки UFW"
else
    pass "цепочек UFW в INPUT нет"
fi
if iptables -S INPUT 2>/dev/null | grep -q 'SCANNERS-BLOCK'; then
    fail "установка прикрутила SCANNERS-BLOCK к INPUT, хотя правила ставить было некуда"
else
    pass "SCANNERS-BLOCK не прикручен к INPUT"
fi

printf '\n=== (a2) режим --observe-only ничего не меняет и завершается успешно ===\n'
ufw --force disable >/dev/null 2>&1
if "$BIN" full --observe-only --urls "$LIST_URL" >"$WORK/a2-observe.log" 2>&1; then
    capture_state "$WORK/state-a2-after"
    if diff -q "$WORK/state-a-before" "$WORK/state-a2-after" >/dev/null; then
        pass "observe-only: код 0, состояние не изменилось"
    else
        fail "observe-only изменил состояние firewall"
    fi
else
    fail "observe-only завершился ошибкой"
fi

printf '\n=== (b) uninstall возвращает состояние к снимку ===\n'
reset_host
# baseline: UFW включён, разрешён только SSH — типичный «уже настроенный» хост
ufw allow ssh >/dev/null 2>&1
enable_ufw_baseline || fail "не удалось собрать baseline UFW"
capture_state "$WORK/state-b-baseline"
if ! "$BIN" full --urls "$LIST_URL" >"$WORK/b-install.log" 2>&1; then
    fail "установка на активном UFW не удалась"
    tail -5 "$WORK/b-install.log"
else
    pass "установка на активном UFW завершилась успешно"
    capture_state "$WORK/state-b-installed"
    if grep -q 'SCANNERS-BLOCK' /etc/ufw/before.rules; then
        pass "правила rkn-guard записаны в before.rules"
    else
        fail "правил rkn-guard нет в before.rules"
    fi
    if "$BIN" uninstall --yes >"$WORK/b-uninstall.log" 2>&1; then
        pass "uninstall завершился успешно"
    else
        fail "uninstall вернул ошибку"
        tail -5 "$WORK/b-uninstall.log"
    fi
    capture_state "$WORK/state-b-after"
    if diff -u "$WORK/state-b-baseline" "$WORK/state-b-after" >"$WORK/diff-b.txt"; then
        pass "после uninstall состояние равно снимку baseline"
    else
        fail "uninstall не вернул baseline: см. $WORK/diff-b.txt"
        sed -n '1,30p' "$WORK/diff-b.txt"
    fi
fi

printf '\n=== (c) повторная установка идемпотентна ===\n'
reset_host
ufw allow ssh >/dev/null 2>&1
enable_ufw_baseline || fail "не удалось собрать baseline UFW"
if "$BIN" full --urls "$LIST_URL" >"$WORK/c-install1.log" 2>&1; then
    pass "первая установка"
else
    fail "первая установка не удалась"
fi
sha1=$(sha256sum /etc/ufw/before.rules | awk '{print $1}')
rules1=$(iptables -S ufw-before-input | sed -E 's/-c [0-9]+ [0-9]+//')
if "$BIN" full --urls "$LIST_URL" >"$WORK/c-install2.log" 2>&1; then
    pass "вторая установка завершилась успешно"
else
    fail "вторая установка не удалась"
fi
sha2=$(sha256sum /etc/ufw/before.rules | awk '{print $1}')
rules2=$(iptables -S ufw-before-input | sed -E 's/-c [0-9]+ [0-9]+//')
[ "$sha1" = "$sha2" ] && pass "before.rules не изменился при повторной установке" || fail "before.rules изменился: $sha1 -> $sha2"
[ "$rules1" = "$rules2" ] && pass "правила ufw-before-input не изменились" || fail "правила ufw-before-input изменились"
blocks=$(( $(grep -c 'SCANNERS-BLOCK chain - managed by antiscan' /etc/ufw/before.rules) + $(grep -c 'SCANNERS-BLOCK chain - managed by antiscan' /etc/ufw/before6.rules) ))
if [ "$blocks" -eq 2 ]; then
    pass "managed-блок ровно один в каждом файле (v4 + v6)"
else
    fail "managed-блоков $blocks вместо 2"
fi

printf '\n=== (d) rollback без снимка честно отказывается ===\n'
rm -rf /var/lib/rkn-guard/snapshot
if "$BIN" rollback --yes >"$WORK/d-rollback.log" 2>&1; then
    fail "rollback без снимка вернул 0"
else
    pass "rollback без снимка завершился ошибкой"
fi

printf '\n=== итог ===\n'
if [ "$FAILED" -eq 0 ]; then
    printf 'ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ\n'
    [ "${KEEP_STATE:-0}" = "1" ] && printf 'каталог с логами: %s\n' "$WORK"
    exit 0
fi
printf 'ПРОВАЛЕНО ПРОВЕРОК: %d (логи: %s)\n' "$FAILED" "$WORK"
exit 1
