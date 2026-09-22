package service

// SystemdTemplates contains all systemd unit file templates
const (
	// IpsetRestoreServiceTemplate is the systemd service for restoring ipset on boot
	IpsetRestoreServiceTemplate = `[Unit]
Description=Restore rkn-guard ipset configuration
Before=ufw.service
Before=netfilter-persistent.service
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ipset restore -exist -f /etc/ipset.conf
ExecStart=-/usr/sbin/iptables -N SCANNERS-BLOCK
ExecStart=-/usr/sbin/ip6tables -N SCANNERS-BLOCK

[Install]
WantedBy=multi-user.target
RequiredBy=netfilter-persistent.service
`

	// MoveRulesServiceTemplate is the systemd service for moving SCANNERS-BLOCK to position 1
	MoveRulesServiceTemplate = `[Unit]
Description=Move rkn-guard rules to position 1 in UFW chains
After=ufw.service
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sleep 2
ExecStart=-/usr/sbin/iptables -D ufw-before-input -j SCANNERS-BLOCK
ExecStart=/usr/sbin/iptables -I ufw-before-input 1 -j SCANNERS-BLOCK
ExecStart=-/usr/sbin/ip6tables -D ufw6-before-input -j SCANNERS-BLOCK
ExecStart=/usr/sbin/ip6tables -I ufw6-before-input 1 -j SCANNERS-BLOCK

[Install]
WantedBy=multi-user.target
`

	// AggregateLogsServiceTemplate is the systemd service for log aggregation
	AggregateLogsServiceTemplate = `[Unit]
Description=rkn-guard Log Aggregator
After=rsyslog.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/antiscan-aggregate-logs.sh
StandardOutput=journal
StandardError=journal
`

	// AggregateLogsTimerTemplate is the systemd timer for log aggregation
	AggregateLogsTimerTemplate = `[Unit]
Description=rkn-guard Log Aggregator Timer
Requires=antiscan-aggregate.service

[Timer]
OnBootSec=1min
OnUnitActiveSec=30sec
AccuracySec=5sec

[Install]
WantedBy=timers.target
`

	// AggregateLogsScriptTemplate is the bash script for log aggregation
	AggregateLogsScriptTemplate = `#!/bin/bash
# rkn-guard Log Aggregation Script
# Aggregates iptables logs into CSV format with ASN/netname lookup
#
# Output CSV format: IP_TYPE|IP_ADDRESS|ASN|NETNAME|COUNT|LAST_SEEN
# Example: v4|1.2.3.4|AS12345|EXAMPLE-NET|42|2026-01-26T12:34:56
#
# Features:
# - Whois lookup with caching (RIPE database with auto-referrals)
# - Atomic log rotation (grab -> clear -> process)
# - Merges with existing data and sorts by count

set -uo pipefail

# Configuration
IPV4_LOG="/var/log/iptables-scanners-ipv4.log"
IPV6_LOG="/var/log/iptables-scanners-ipv6.log"
OUTPUT_CSV="/var/log/iptables-scanners-aggregate.csv"
WHOIS_CACHE="/tmp/antiscan-whois-cache.txt"
TEMP_IPV4="/tmp/antiscan-ipv4-$$.tmp"
TEMP_IPV6="/tmp/antiscan-ipv6-$$.tmp"

# Create whois cache if doesn't exist, clean if older than 1 day
if [ -f "$WHOIS_CACHE" ]; then
    # Remove cache if older than 1 day
    find "$WHOIS_CACHE" -mtime +1 -delete 2>/dev/null || true
fi
touch "$WHOIS_CACHE"

# Grab content and immediately clear (atomic as possible)
if [ -f "$IPV4_LOG" ]; then
    cat "$IPV4_LOG" > "$TEMP_IPV4"
    > "$IPV4_LOG"
    chown syslog:adm "$IPV4_LOG" 2>/dev/null || true
    chmod 640 "$IPV4_LOG" 2>/dev/null || true
fi

if [ -f "$IPV6_LOG" ]; then
    cat "$IPV6_LOG" > "$TEMP_IPV6"
    > "$IPV6_LOG"
    chown syslog:adm "$IPV6_LOG" 2>/dev/null || true
    chmod 640 "$IPV6_LOG" 2>/dev/null || true
fi

# Function to get ASN and netname from IP with caching
get_ip_info() {
    local ip="$1"

    # Check cache first
    local cached=$(grep "^${ip}|" "$WHOIS_CACHE" 2>/dev/null | head -1)
    if [ -n "$cached" ]; then
        # Return cached result (format: IP|ASN|NETNAME)
        echo "$cached" | cut -d'|' -f2-
        return
    fi

    local asn=""
    local netname=""

    # Always use RIPE (most comprehensive database with auto-referrals)
    local whois_server="whois.ripe.net"

    # Try whois lookup with timeout
    local whois_output=$(timeout 3 whois -h "$whois_server" "$ip" 2>/dev/null || echo "")

    if [ -n "$whois_output" ]; then
        # Extract ASN from origin: line only
        asn=$(echo "$whois_output" | grep -iE "^origin:" | head -1 | awk '{print $2}' | sed 's/AS//gi' | tr -d '\r\n ')

        # Extract netname from netname: line only
        netname=$(echo "$whois_output" | grep -iE "^netname:" | head -1 | awk '{print $2}' | tr -d '\r\n')
    fi

    # Validate ASN is numeric
    if [ -n "$asn" ] && ! echo "$asn" | grep -qE '^[0-9]+$'; then
        asn=""
    fi

    # If empty, set defaults
    [ -z "$asn" ] && asn="UNKNOWN"
    [ -z "$netname" ] && netname="UNKNOWN"

    # Add AS prefix if missing
    if [ "$asn" != "UNKNOWN" ] && ! echo "$asn" | grep -q "^AS"; then
        asn="AS${asn}"
    fi

    # Save to cache
    echo "${ip}|${asn}|${netname}" >> "$WHOIS_CACHE"

    echo "${asn}|${netname}"
}

# Create CSV header if file doesn't exist
if [ ! -f "$OUTPUT_CSV" ]; then
    echo "IP_TYPE|IP_ADDRESS|ASN|NETNAME|COUNT|LAST_SEEN" > "$OUTPUT_CSV"
fi

# Process grabbed logs
TEMP_NEW="/tmp/antiscan-new-$$.tmp"
> "$TEMP_NEW"

if [ -f "$TEMP_IPV4" ] && [ -s "$TEMP_IPV4" ]; then
    grep 'ANTISCAN-v4:' "$TEMP_IPV4" | grep -oE 'SRC=[0-9.]+' | sed 's/SRC=//' | sort | uniq -c | while read cnt ip; do
        # Get timestamp for this IP (last occurrence)
        tm=$(grep "SRC=$ip" "$TEMP_IPV4" | tail -1 | awk '{print $1}')
        info=$(get_ip_info "$ip")
        echo "v4|${ip}|${info}|${cnt}|${tm}" >> "$TEMP_NEW"
    done
fi

if [ -f "$TEMP_IPV6" ] && [ -s "$TEMP_IPV6" ]; then
    grep 'ANTISCAN-v6:' "$TEMP_IPV6" | grep -oE 'SRC=[0-9a-fA-F:]+' | sed 's/SRC=//' | sort | uniq -c | while read cnt ip; do
        # Get timestamp for this IP (last occurrence)
        tm=$(grep "SRC=$ip" "$TEMP_IPV6" | tail -1 | awk '{print $1}')
        info=$(get_ip_info "$ip")
        echo "v6|${ip}|${info}|${cnt}|${tm}" >> "$TEMP_NEW"
    done
fi

# Merge with existing CSV if there's new data
if [ -s "$TEMP_NEW" ]; then
    {
        echo "IP_TYPE|IP_ADDRESS|ASN|NETNAME|COUNT|LAST_SEEN"
        cat "$OUTPUT_CSV" "$TEMP_NEW" | awk -F'|' '
        NR==1 { next }
        NF==6 {
            key = $1 "|" $2
            count[key] += $5
            time[key] = $6
            asn[key] = $3
            netname[key] = $4
        }
        END {
            for (k in count) {
                split(k, p, "|")
                print p[1] "|" p[2] "|" asn[k] "|" netname[k] "|" count[k] "|" time[k]
            }
        }' | sort -t'|' -k5 -nr
    } > "${OUTPUT_CSV}.new"

    mv "${OUTPUT_CSV}.new" "$OUTPUT_CSV"
fi

# Cleanup
rm -f "$TEMP_NEW" "$TEMP_IPV4" "$TEMP_IPV6"

exit 0
`

	// RsyslogConfigTemplate is the rsyslog configuration for iptables logging
	RsyslogConfigTemplate = `:msg, contains, "ANTISCAN-v4: " /var/log/iptables-scanners-ipv4.log
:msg, contains, "ANTISCAN-v6: " /var/log/iptables-scanners-ipv6.log
& stop
`

	// LogrotateConfigTemplate is the logrotate configuration
	LogrotateConfigTemplate = `/var/log/iptables-scanners-*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}

/var/log/iptables-scanners-aggregate.csv {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
`
)

// SystemdServicePaths contains paths to systemd service files
const (
	IpsetRestoreServicePath  = "/etc/systemd/system/antiscan-ipset-restore.service"
	MoveRulesServicePath     = "/etc/systemd/system/antiscan-move-rules.service"
	AggregateLogsServicePath = "/etc/systemd/system/antiscan-aggregate.service"
	AggregateLogsTimerPath   = "/etc/systemd/system/antiscan-aggregate.timer"
	AggregateLogsScriptPath  = "/usr/local/bin/antiscan-aggregate-logs.sh"
	RsyslogConfigPath        = "/etc/rsyslog.d/10-iptables-scanners.conf"
	LogrotateConfigPath      = "/etc/logrotate.d/iptables-scanners"
)

// UFWBeforeRulesTemplates contains templates for UFW before.rules
const (
	// UFWBeforeRulesHeader is the header for SCANNERS-BLOCK in UFW before.rules
	UFWBeforeRulesHeader = `
# SCANNERS-BLOCK chain - managed by antiscan
:SCANNERS-BLOCK - [0:0]
-A ufw-before-input -j SCANNERS-BLOCK
`

	// UFWBeforeRulesFooter is the footer for SCANNERS-BLOCK in UFW before.rules
	UFWBeforeRulesFooter = `# END SCANNERS-BLOCK
`

	// UFW6BeforeRulesHeader is the header for SCANNERS-BLOCK in UFW before6.rules
	UFW6BeforeRulesHeader = `
# SCANNERS-BLOCK chain - managed by antiscan
:SCANNERS-BLOCK - [0:0]
-A ufw6-before-input -j SCANNERS-BLOCK
`

	// UFW6BeforeRulesFooter is the footer for SCANNERS-BLOCK in UFW before6.rules
	UFW6BeforeRulesFooter = `# END SCANNERS-BLOCK
`
)

// IpsetConfigPaths contains paths for ipset configuration
const (
	IpsetConfigPath     = "/etc/ipset.conf"
	IpsetConfigPathAlt  = "/etc/iptables/ipsets"
	IptablesRulesV4Path = "/etc/iptables/rules.v4"
	IptablesRulesV6Path = "/etc/iptables/rules.v6"
	UFWBeforeRulesPath  = "/etc/ufw/before.rules"
	UFW6BeforeRulesPath = "/etc/ufw/before6.rules"
)

// LogPaths contains paths for log files
const (
	IPv4LogPath      = "/var/log/iptables-scanners-ipv4.log"
	IPv6LogPath      = "/var/log/iptables-scanners-ipv6.log"
	AggregateLogPath = "/var/log/iptables-scanners-aggregate.csv"
)
