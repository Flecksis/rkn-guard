#!/usr/bin/env bash
# Only for an ephemeral GitHub Linux runner. Never changes firewall or IP sets.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == Linux && $EUID == 0 ]] || {
    echo 'Run only as root on an ephemeral GitHub Linux runner.' >&2
    exit 1
}
source "$(dirname "$0")/../../install.sh"
work=$(mktemp -d /tmp/rkn-schedule-test.XXXXXX)
SCHEDULE_TIMER="rkn-schedule-test-$$.timer"
SCHEDULE_SERVICE="rkn-schedule-test-$$.service"
SCHEDULE_CONFIG="$work/schedule.conf"
SCHEDULE_LOCK="$work/schedule.lock"
MANAGER_PATH="$work/runner.sh"
cleanup() {
    systemctl disable --now "$SCHEDULE_TIMER" 2>/dev/null || true
    systemctl stop "$SCHEDULE_SERVICE" 2>/dev/null || true
    rm -f -- "$SCHEDULE_UNIT_DIR/$SCHEDULE_TIMER" "$SCHEDULE_UNIT_DIR/$SCHEDULE_SERVICE"
    systemctl daemon-reload
    rm -rf -- "$work"
}
trap cleanup EXIT
cat > "$MANAGER_PATH" <<EOF
#!/bin/bash
echo start >> "$work/actions"
while [[ ! -f "$work/resume" ]]; do sleep 0.05; done
echo done >> "$work/actions"
EOF
chmod 755 "$MANAGER_PATH"

for mode in interval hours msk; do
    case "$mode" in interval) value=7 ;; hours) value=06:00,18:30 ;; msk) value=06:00 ;; esac
    set_update_schedule "$mode" "$value"
    systemctl is-enabled --quiet "$SCHEDULE_TIMER"
    systemctl is-active --quiet "$SCHEDULE_TIMER"
    set_update_schedule "$mode" "$value"
    systemd-analyze verify "$SCHEDULE_UNIT_DIR/$SCHEDULE_TIMER" "$SCHEDULE_UNIT_DIR/$SCHEDULE_SERVICE"
done
set_update_schedule interval 7

# Repeated starts of the same oneshot service must not create another update.
systemctl start --no-block "$SCHEDULE_SERVICE"
for ((i=0; i<100; i++)); do
    [[ -s "$work/actions" ]] && break
    sleep 0.05
done
[[ -s "$work/actions" ]]
systemctl start --no-block "$SCHEDULE_SERVICE"
set_update_schedule off ''
! systemctl is-active --quiet "$SCHEDULE_TIMER"
! systemctl is-enabled --quiet "$SCHEDULE_TIMER"
[[ $(systemctl show --property=ActiveState --value "$SCHEDULE_SERVICE") == activating ]]
[[ $(grep -c '^start$' "$work/actions") == 1 ]]
touch "$work/resume"
for ((i=0; i<100; i++)); do
    [[ $(systemctl show --property=ActiveState --value "$SCHEDULE_SERVICE") == inactive ]] && break
    sleep 0.05
done
[[ $(grep -c '^done$' "$work/actions") == 1 ]]
remove_update_schedule
[[ ! -e "$SCHEDULE_CONFIG" && ! -e "$SCHEDULE_UNIT_DIR/$SCHEDULE_TIMER" ]]

# The compiled binary must reject a second operation before downloading or
# changing anything. This is the same command invoked by manual and timed updates.
if flock -n /run/rkn-guard.lock "$RKN_TEST_BINARY" update -u http://127.0.0.1:9/list > "$work/lock.log" 2>&1; then
    echo 'Concurrent update unexpectedly succeeded' >&2
    exit 1
fi
grep -q 'another rkn-guard operation is running' "$work/lock.log"
echo 'PASS: real systemd modes, repeated start, disable during update, cleanup and shared update lock'
