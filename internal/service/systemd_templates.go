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
    create 0640 syslog adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
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
