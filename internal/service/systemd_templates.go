package service

// Шаблоны сервисов и таймеров systemd.
const (
	// IpsetRestoreServiceTemplate восстанавливает ipset при загрузке.
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

	// MoveRulesServiceTemplate — старый сервис перестановки SCANNERS-BLOCK на первое место.
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

	// AggregateLogsServiceTemplate запускает сбор статистики из журналов.
	AggregateLogsServiceTemplate = `[Unit]
Description=rkn-guard Log Aggregator
After=rsyslog.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/antiscan-aggregate-logs.sh
StandardOutput=journal
StandardError=journal
`

	// AggregateLogsTimerTemplate задаёт расписание сбора статистики.
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

	// AggregateLogsScriptTemplate собирает статистику из журналов.
	AggregateLogsScriptTemplate = `#!/bin/bash
# Сбор статистики rkn-guard.
# Преобразуем журналы iptables в CSV и добавляем ASN и имя сети.
#
# Поля CSV: IP_TYPE|IP_ADDRESS|ASN|NETNAME|COUNT|LAST_SEEN
# Пример: v4|1.2.3.4|AS12345|EXAMPLE-NET|42|2026-01-26T12:34:56
#
# Что делает скрипт:
# - Запрашивает whois через RIPE и кэширует результат.
# - Забирает журнал, очищает его и обрабатывает собранные строки.
# - Объединяет данные с сохранённой статистикой и сортирует по числу событий.

set -uo pipefail

# Настройки.
IPV4_LOG="/var/log/iptables-scanners-ipv4.log"
IPV6_LOG="/var/log/iptables-scanners-ipv6.log"
OUTPUT_CSV="/var/log/iptables-scanners-aggregate.csv"
WHOIS_CACHE="/tmp/antiscan-whois-cache.txt"
TEMP_IPV4="/tmp/antiscan-ipv4-$$.tmp"
TEMP_IPV6="/tmp/antiscan-ipv6-$$.tmp"

# Создаём кэш whois, если его нет; старый кэш очищаем раз в сутки.
if [ -f "$WHOIS_CACHE" ]; then
    # Удаляем кэш старше суток.
    find "$WHOIS_CACHE" -mtime +1 -delete 2>/dev/null || true
fi
touch "$WHOIS_CACHE"

# Забираем содержимое и сразу очищаем исходный журнал.
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

# Получаем ASN и имя сети для адреса, по возможности из кэша.
get_ip_info() {
    local ip="$1"

    # Сначала смотрим в кэше.
    local cached=$(grep "^${ip}|" "$WHOIS_CACHE" 2>/dev/null | head -1)
    if [ -n "$cached" ]; then
        # Возвращаем сохранённые данные в формате IP|ASN|NETNAME.
        echo "$cached" | cut -d'|' -f2-
        return
    fi

    local asn=""
    local netname=""

    # Запрашиваем RIPE, который может перенаправить запрос в нужную базу.
    local whois_server="whois.ripe.net"

    # Ограничиваем время ожидания ответа whois.
    local whois_output=$(timeout 3 whois -h "$whois_server" "$ip" 2>/dev/null || echo "")

    if [ -n "$whois_output" ]; then
        # Берём ASN только из строки origin:.
        asn=$(echo "$whois_output" | grep -iE "^origin:" | head -1 | awk '{print $2}' | sed 's/AS//gi' | tr -d '\r\n ')

        # Имя сети берём только из строки netname:.
        netname=$(echo "$whois_output" | grep -iE "^netname:" | head -1 | awk '{print $2}' | tr -d '\r\n')
    fi

    # Проверяем, что номер ASN состоит из цифр.
    if [ -n "$asn" ] && ! echo "$asn" | grep -qE '^[0-9]+$'; then
        asn=""
    fi

    # Для пустых полей подставляем значения по умолчанию.
    [ -z "$asn" ] && asn="UNKNOWN"
    [ -z "$netname" ] && netname="UNKNOWN"

    # При необходимости добавляем префикс AS.
    if [ "$asn" != "UNKNOWN" ] && ! echo "$asn" | grep -q "^AS"; then
        asn="AS${asn}"
    fi

    # Сохраняем результат в кэш.
    echo "${ip}|${asn}|${netname}" >> "$WHOIS_CACHE"

    echo "${asn}|${netname}"
}

# Если CSV ещё не существует, записываем заголовок.
if [ ! -f "$OUTPUT_CSV" ]; then
    echo "IP_TYPE|IP_ADDRESS|ASN|NETNAME|COUNT|LAST_SEEN" > "$OUTPUT_CSV"
fi

# Обрабатываем собранные строки журнала.
TEMP_NEW="/tmp/antiscan-new-$$.tmp"
> "$TEMP_NEW"

if [ -f "$TEMP_IPV4" ] && [ -s "$TEMP_IPV4" ]; then
    grep 'ANTISCAN-v4:' "$TEMP_IPV4" | grep -oE 'SRC=[0-9.]+' | sed 's/SRC=//' | sort | uniq -c | while read cnt ip; do
        # Находим время последнего события для этого IP.
        tm=$(grep "SRC=$ip" "$TEMP_IPV4" | tail -1 | awk '{print $1}')
        info=$(get_ip_info "$ip")
        echo "v4|${ip}|${info}|${cnt}|${tm}" >> "$TEMP_NEW"
    done
fi

if [ -f "$TEMP_IPV6" ] && [ -s "$TEMP_IPV6" ]; then
    grep 'ANTISCAN-v6:' "$TEMP_IPV6" | grep -oE 'SRC=[0-9a-fA-F:]+' | sed 's/SRC=//' | sort | uniq -c | while read cnt ip; do
        # Находим время последнего события для этого IP.
        tm=$(grep "SRC=$ip" "$TEMP_IPV6" | tail -1 | awk '{print $1}')
        info=$(get_ip_info "$ip")
        echo "v6|${ip}|${info}|${cnt}|${tm}" >> "$TEMP_NEW"
    done
fi

# Если появились данные, объединяем их с сохранённым CSV.
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

# Удаляем временные файлы.
rm -f "$TEMP_NEW" "$TEMP_IPV4" "$TEMP_IPV6"

exit 0
`

	// RsyslogConfigTemplate настраивает запись событий iptables.
	RsyslogConfigTemplate = `:msg, contains, "ANTISCAN-v4: " /var/log/iptables-scanners-ipv4.log
:msg, contains, "ANTISCAN-v6: " /var/log/iptables-scanners-ipv6.log
& stop
`

	// LogrotateConfigTemplate задаёт ротацию журналов.
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

// Пути к файлам сервисов systemd.
const (
	IpsetRestoreServicePath  = "/etc/systemd/system/antiscan-ipset-restore.service"
	MoveRulesServicePath     = "/etc/systemd/system/antiscan-move-rules.service"
	AggregateLogsServicePath = "/etc/systemd/system/antiscan-aggregate.service"
	AggregateLogsTimerPath   = "/etc/systemd/system/antiscan-aggregate.timer"
	AggregateLogsScriptPath  = "/usr/local/bin/antiscan-aggregate-logs.sh"
	RsyslogConfigPath        = "/etc/rsyslog.d/10-iptables-scanners.conf"
	LogrotateConfigPath      = "/etc/logrotate.d/iptables-scanners"
)

// Шаблоны блоков для before-файлов UFW.
const (
	// UFWBeforeRulesHeader открывает наш блок в before.rules.
	UFWBeforeRulesHeader = `
# SCANNERS-BLOCK chain - managed by antiscan
:SCANNERS-BLOCK - [0:0]
-A ufw-before-input -j SCANNERS-BLOCK
`

	// UFWBeforeRulesFooter закрывает наш блок в before.rules.
	UFWBeforeRulesFooter = `# END SCANNERS-BLOCK
`

	// UFW6BeforeRulesHeader открывает наш блок в before6.rules.
	UFW6BeforeRulesHeader = `
# SCANNERS-BLOCK chain - managed by antiscan
:SCANNERS-BLOCK - [0:0]
-A ufw6-before-input -j SCANNERS-BLOCK
`

	// UFW6BeforeRulesFooter закрывает наш блок в before6.rules.
	UFW6BeforeRulesFooter = `# END SCANNERS-BLOCK
`
)

// Пути к настройкам ipset.
const (
	IpsetConfigPath     = "/etc/ipset.conf"
	IpsetConfigPathAlt  = "/etc/iptables/ipsets"
	IptablesRulesV4Path = "/etc/iptables/rules.v4"
	IptablesRulesV6Path = "/etc/iptables/rules.v6"
	UFWBeforeRulesPath  = "/etc/ufw/before.rules"
	UFW6BeforeRulesPath = "/etc/ufw/before6.rules"
)

// Пути к журналам.
const (
	IPv4LogPath      = "/var/log/iptables-scanners-ipv4.log"
	IPv6LogPath      = "/var/log/iptables-scanners-ipv6.log"
	AggregateLogPath = "/var/log/iptables-scanners-aggregate.csv"
)
