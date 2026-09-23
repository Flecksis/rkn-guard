#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_PATH="${RKN_GUARD_BIN:-${ROOT_DIR}/bin/rkn-guard}"
ANTISCANNER_URL="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list"
GOV_NETWORKS_URL="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list"
MANAGED_MARKER="# SCANNERS-BLOCK chain - managed by antiscan"

log() {
  printf '[integration] %s\n' "$*"
}

fail() {
  printf '[integration][ERROR] %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -x "${BIN_PATH}" ]]; then
    "${BIN_PATH}" uninstall --yes --remove-logs >/dev/null 2>&1 || true
  fi
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "Run this script as root"
  fi
}

require_linux() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    fail "This integration test must run on Linux"
  fi
}

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    fail "Required command not found: ${cmd}"
  fi
}

build_binary_if_needed() {
  if [[ -x "${BIN_PATH}" ]]; then
    return
  fi

  mkdir -p "$(dirname "${BIN_PATH}")"
  log "Building rkn-guard binary at ${BIN_PATH}"
  (cd "${ROOT_DIR}" && go build -o "${BIN_PATH}" ./cmd)
}

ensure_ufw_ssh_rule_if_needed() {
  if ! command -v ufw >/dev/null 2>&1; then
    return
  fi

  local ufw_status=""
  ufw_status="$(ufw status 2>/dev/null || true)"

  if grep -q "Status: active" <<<"${ufw_status}"; then
    return
  fi

  log "UFW detected and inactive; ensuring SSH rule exists for safe activation"
  ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp >/dev/null 2>&1 || true
}

assert_file_exists() {
  local path="$1"
  [[ -e "${path}" ]] || fail "Expected file does not exist: ${path}"
}

assert_file_not_exists() {
  local path="$1"
  [[ ! -e "${path}" ]] || fail "Expected file to be removed: ${path}"
}

chain_exists() {
  local cmd="$1"
  "${cmd}" -S SCANNERS-BLOCK >/dev/null 2>&1
}

chain_has_jump() {
  local cmd="$1"
  local chain="$2"

  if ! "${cmd}" -S "${chain}" >/dev/null 2>&1; then
    return 1
  fi

  "${cmd}" -S "${chain}" | grep -q -- "-j SCANNERS-BLOCK"
}

assert_chain_linked_v4() {
  if chain_has_jump iptables INPUT || chain_has_jump iptables ufw-before-input; then
    return
  fi
  fail "SCANNERS-BLOCK is not linked for IPv4"
}

assert_chain_linked_v6() {
  if chain_has_jump ip6tables INPUT || chain_has_jump ip6tables ufw6-before-input; then
    return
  fi
  fail "SCANNERS-BLOCK is not linked for IPv6"
}

assert_chain_unlinked_everywhere() {
  local cmd="$1"
  local first_chain="$2"
  local second_chain="$3"

  if chain_has_jump "${cmd}" "${first_chain}"; then
    fail "Found SCANNERS-BLOCK jump in ${cmd} ${first_chain}"
  fi

  if chain_has_jump "${cmd}" "${second_chain}"; then
    fail "Found SCANNERS-BLOCK jump in ${cmd} ${second_chain}"
  fi
}

assert_ipset_exists() {
  local set_name="$1"
  ipset list "${set_name}" >/dev/null 2>&1 || fail "Expected ipset to exist: ${set_name}"
}

assert_ipset_not_exists() {
  local set_name="$1"
  if ipset list "${set_name}" >/dev/null 2>&1; then
    fail "Expected ipset to be removed: ${set_name}"
  fi
}

assert_service_not_enabled() {
  local service_name="$1"
  local output=""

  output="$(systemctl is-enabled "${service_name}" 2>&1 || true)"
  output="$(echo "${output}" | tr -d '\r' | head -n1 | xargs)"
  if [[ "${output}" == "enabled" ]]; then
    fail "Service is still enabled: ${service_name}"
  fi
}

assert_marker_removed_if_file_exists() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    return
  fi

  if grep -q -- "${MANAGED_MARKER}" "${path}"; then
    fail "Managed UFW marker is still present in ${path}"
  fi
}

assert_no_scanners_block_in_saved_state() {
  if iptables-save | grep -q "SCANNERS-BLOCK"; then
    fail "SCANNERS-BLOCK still present in iptables-save output"
  fi

  if ip6tables-save | grep -q "SCANNERS-BLOCK"; then
    fail "SCANNERS-BLOCK still present in ip6tables-save output"
  fi
}

assert_no_scanner_logs() {
  shopt -s nullglob
  local logs=(/var/log/iptables-scanners-*)
  shopt -u nullglob

  if (( ${#logs[@]} > 0 )); then
    fail "Expected scanner log files to be removed, found: ${logs[*]}"
  fi
}

prepare_environment() {
  require_linux
  require_root
  require_cmd go
  require_cmd iptables
  require_cmd ip6tables
  require_cmd iptables-save
  require_cmd ip6tables-save
  require_cmd ipset
  require_cmd systemctl

  build_binary_if_needed
  ensure_ufw_ssh_rule_if_needed

  log "Cleaning any previous test state"
  "${BIN_PATH}" uninstall --yes --remove-logs >/dev/null 2>&1 || true
}

run_full_install() {
  log "Running full install"
  "${BIN_PATH}" full -u "${ANTISCANNER_URL}" -u "${GOV_NETWORKS_URL}" --enable-logging

  assert_ipset_exists SCANNERS-BLOCK-V4
  assert_ipset_exists SCANNERS-BLOCK-V6

  chain_exists iptables || fail "IPv4 chain SCANNERS-BLOCK was not created"
  chain_exists ip6tables || fail "IPv6 chain SCANNERS-BLOCK was not created"

  assert_chain_linked_v4
  assert_chain_linked_v6

  assert_file_exists /etc/ipset.conf
  assert_file_exists /etc/systemd/system/antiscan-ipset-restore.service

  # Ошибка настройки журналов не прерывает full. Даже в минимальном образе
  # без каталогов rsyslog должна оставаться возможность проверить удаление.
  if [[ -d /etc/rsyslog.d ]]; then
    if [[ -f /etc/rsyslog.d/10-iptables-scanners.conf ]]; then
      log "Logging artifacts detected: strict uninstall checks remain applicable"
    else
      log "Logging artifacts were not created on this host; continuing core flow checks"
    fi
  else
    log "Skipping strict logging artifact presence checks: /etc/rsyslog.d is absent"
  fi

  if command -v ufw >/dev/null 2>&1; then
    assert_file_exists /etc/systemd/system/antiscan-move-rules.service
  fi
}

run_uninstall_without_log_removal() {
  log "Running uninstall without --remove-logs"
  "${BIN_PATH}" uninstall --yes

  chain_exists iptables && fail "IPv4 chain SCANNERS-BLOCK still exists after uninstall"
  chain_exists ip6tables && fail "IPv6 chain SCANNERS-BLOCK still exists after uninstall"

  assert_chain_unlinked_everywhere iptables INPUT ufw-before-input
  assert_chain_unlinked_everywhere ip6tables INPUT ufw6-before-input

  assert_ipset_not_exists SCANNERS-BLOCK-V4
  assert_ipset_not_exists SCANNERS-BLOCK-V6

  assert_file_not_exists /etc/ipset.conf
  assert_file_not_exists /etc/systemd/system/antiscan-ipset-restore.service
  assert_file_not_exists /etc/systemd/system/antiscan-move-rules.service
  assert_file_not_exists /etc/systemd/system/antiscan-aggregate.service
  assert_file_not_exists /etc/systemd/system/antiscan-aggregate.timer
  assert_file_not_exists /etc/rsyslog.d/10-iptables-scanners.conf
  assert_file_not_exists /etc/logrotate.d/iptables-scanners
  assert_file_not_exists /usr/local/bin/antiscan-aggregate-logs.sh

  assert_service_not_enabled antiscan-aggregate.timer
  assert_service_not_enabled antiscan-aggregate.service
  assert_service_not_enabled antiscan-move-rules.service
  assert_service_not_enabled antiscan-ipset-restore.service

  assert_marker_removed_if_file_exists /etc/ufw/before.rules
  assert_marker_removed_if_file_exists /etc/ufw/before6.rules
  assert_no_scanners_block_in_saved_state
}

run_remove_logs_subscenario() {
  log "Re-running full install for --remove-logs scenario"
  "${BIN_PATH}" full -u "${ANTISCANNER_URL}" -u "${GOV_NETWORKS_URL}" --enable-logging

  touch /var/log/iptables-scanners-ipv4.log
  touch /var/log/iptables-scanners-ipv6.log
  touch /var/log/iptables-scanners-aggregate.csv

  log "Running uninstall with --remove-logs"
  "${BIN_PATH}" uninstall --yes --remove-logs

  assert_no_scanner_logs

  chain_exists iptables && fail "IPv4 chain SCANNERS-BLOCK still exists after uninstall --remove-logs"
  chain_exists ip6tables && fail "IPv6 chain SCANNERS-BLOCK still exists after uninstall --remove-logs"
  assert_ipset_not_exists SCANNERS-BLOCK-V4
  assert_ipset_not_exists SCANNERS-BLOCK-V6
}

main() {
  trap cleanup EXIT

  prepare_environment
  run_full_install
  run_uninstall_without_log_removal
  run_remove_logs_subscenario

  log "PASS: full -> uninstall integration flow succeeded"
}

main "$@"
