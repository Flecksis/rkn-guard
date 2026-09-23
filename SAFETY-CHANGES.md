# Safe list updates and UFW error handling

Fixes the failures reported in Flecksis/rkn-guard issues #1 and #2.

## Behavior

- All requested sources must download successfully and contain at least one valid IP/CIDR. Empty, malformed, oversized (>4 MiB) sources and unsupported `/0` or IPv4-mapped IPv6 entries fail before changing the live sets. Comments and individual IPs are supported; CIDRs are normalized and deduplicated. The existing capacity is 65,536 entries per family.
- Both replacement sets are filled before either live set is changed. Each family uses `ipset swap`; a later swap, snapshot or persistence error triggers rollback. If rollback itself fails, the old set is retained under the name included in the error for manual recovery.
- `/etc/ipset.conf` is replaced using a flushed temporary file and rename. It contains the two managed sets; unrelated live sets are not changed.
- `full`, `update` and `uninstall` share an exclusive `/run/rkn-guard.lock`. External firewall tools and the shell menu's manual IP additions do not participate in this lock.
- Active UFW is reloaded, never disabled as part of applying rules. Initial enable/reload/status failures propagate to the caller. Previous UFW before files are restored on failure, and a previously active firewall is reloaded with those files; rollback errors are reported too.
- The managed block is stored after filter chain declarations and before existing filter rules in both before files. Repeated reloads preserve first-position jumps. Other tables and rules are preserved. No new move-rules service is installed; old installations may still have the legacy service until uninstall.
- After applying UFW, both live jumps are verified in first position without deleting/reinserting rules. Verification failures trigger configuration rollback. Rollback verifies UFW is active; if this invocation successfully enabled UFW, later verification failures reload the restored files without disabling the firewall.
- The shell update menu reports a failed update instead of displaying success.

The staging, rollback and locking approach was informed by operational work on PAVLINK's antiscanner. Infrastructure-specific allowlists and prefix-size restrictions are intentionally not hardcoded into this general-purpose upstream patch.

## Validation

```sh
go test ./...
go vet ./...
go build -o /usr/local/bin/rkn-guard ./cmd
```

The integration script is **only for a disposable Linux container** with CAP_NET_ADMIN, Python 3, curl, ipset, iptables and UFW. It deliberately changes its firewall and injects failures. Never run it on a server host:

```sh
RKN_DISPOSABLE_TEST=yes bash tests/integration/safe_updates.sh
```

It checks partial/unavailable/invalid/empty sources, staging failure, second-family swap failure, persistence failure, overlapping updates, successful IPv4/IPv6 replacement, unrelated live set preservation, failed UFW reload with configuration rollback, and failed initial enable. Unit tests additionally check normalization, response limits and retention of the recovery set when rollback fails.

## Limits

IPv4 and IPv6 swaps are individually atomic, not one cross-family transaction. This handles returned errors; SIGKILL, power loss and arbitrary concurrent firewall edits are not transactionally recovered. An empty family in an otherwise valid list is supported. A syntactically valid but incomplete or malicious list still needs operator review.

`full` remains a multi-step installer, not a complete system transaction. Earlier successful steps (including ipset updates or chain/logging setup) are not all rolled back if a later UFW operation fails. Failure during initial UFW enable can partially change firewall state; it is reported, with files restored, but no automatic disable is issued. Existing optional systemd warnings remain. Container testing does not validate boot restoration, systemd ordering or protection from external probing.

The regular install script still downloads upstream releases. To test this branch, build its exact source; this document does not claim the published upstream release includes the fixes.
