#!/bin/bash
set -u

# --- ЦВЕТА ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

TG_URL="https://raw.githubusercontent.com/Flecksis/rkn-guard/master/app%20install.sh"
MANAGER_URL="https://raw.githubusercontent.com/Flecksis/rkn-guard/master/install.sh"
MANAGER_PATH="/opt/rkn-guard-manager.sh"
MENU_COMMAND="/usr/local/bin/rkn"
LIST_GOV="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list"
LIST_SCAN="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list"
LIST_SKIPA="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/skipa.list"
MANUAL_FILE="/opt/rkn-guard-manual.list"
RELEASE_API="https://api.github.com/repos/Flecksis/rkn-guard/releases/latest"
CURRENT_VERSION="не установлена"
CURRENT_BRANCH="неизвестна"
LATEST_VERSION=""
UPDATE_STATUS="ещё не проверено"
LAST_UPDATE_CHECK=-600
SCHEDULE_CONFIG="/etc/rkn-guard-update.conf"
SCHEDULE_UNIT_DIR="/etc/systemd/system"
SCHEDULE_LOCK="/run/rkn-guard-schedule.lock"
SCHEDULE_TIMER="rkn-guard-update.timer"
SCHEDULE_SERVICE="rkn-guard-update.service"

refresh_version_status() {
    local info old_version payload current latest newest
    CURRENT_VERSION="не установлена"
    CURRENT_BRANCH="неизвестна"
    if command -v rkn-guard >/dev/null 2>&1; then
        if info=$(rkn-guard build-info 2>/dev/null); then
            CURRENT_VERSION=$(printf '%s\n' "$info" | head -n 1)
            CURRENT_BRANCH=$(printf '%s\n' "$info" | sed -n '2p')
            [[ -z "$CURRENT_BRANCH" || "$CURRENT_BRANCH" == unknown ]] && CURRENT_BRANCH="неизвестна"
        else
            # Старые сборки ещё не знают команду build-info.
            old_version=$(rkn-guard --version 2>/dev/null) || old_version=""
            CURRENT_VERSION=${old_version##* }
            [[ -z "$CURRENT_VERSION" ]] && CURRENT_VERSION="неизвестна"
        fi
    fi
    # Не обращаемся к GitHub при каждом возврате в меню.
    if (( SECONDS - LAST_UPDATE_CHECK >= 600 )); then
        LAST_UPDATE_CHECK=$SECONDS
        LATEST_VERSION=""
        payload=""
        if command -v curl >/dev/null 2>&1; then
            payload=$(curl -fsSL --connect-timeout 3 --max-time 5 "$RELEASE_API" 2>/dev/null) || payload=""
        elif command -v wget >/dev/null 2>&1; then
            payload=$(wget -qO- --timeout=5 --tries=1 "$RELEASE_API" 2>/dev/null) || payload=""
        fi
        latest=$(printf '%s\n' "$payload" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
        # Показываем только номер версии, без управляющих символов из ответа.
        [[ "$latest" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]] && LATEST_VERSION=$latest
    fi
    if [[ -z "$LATEST_VERSION" ]]; then
        UPDATE_STATUS="не удалось проверить"
        return
    fi
    current=${CURRENT_VERSION#v}
    latest=${LATEST_VERSION#v}
    if [[ ! "$current" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        UPDATE_STATUS="последний стабильный релиз: $LATEST_VERSION; сборка не сравнивается"
    elif [[ "$current" == "$latest" ]]; then
        UPDATE_STATUS="установлена последняя версия ($LATEST_VERSION)"
    else
        newest=$(printf '%s\n%s\n' "$current" "$latest" | sort -V | tail -n 1)
        if [[ "$newest" == "$latest" ]]; then
            UPDATE_STATUS="доступно обновление: $LATEST_VERSION"
        else
            UPDATE_STATUS="сборка новее стабильного релиза $LATEST_VERSION"
        fi
    fi
}

check_root() {
    [[ $EUID -ne 0 ]] && { echo -e "${RED}Запуск только от root!${NC}"; exit 1; }
}

check_firewall_safety() {
    echo -e "${BLUE}[CHECK] Проверка конфигурации Firewall...${NC}"
    if command -v ufw >/dev/null; then
        UFW_STATUS=$(ufw status | grep "Status" | awk '{print $2}')
        UFW_RULES=$(ufw show added 2>/dev/null)
        if [[ "$UFW_STATUS" == "inactive" ]]; then
            if [[ "$UFW_RULES" != *"22"* ]] && [[ "$UFW_RULES" != *"SSH"* ]] && [[ "$UFW_RULES" != *"OpenSSH"* ]]; then
                echo -e "\n${RED}⛔ АВАРИЙНАЯ ОСТАНОВКА!${NC}"
                echo -e "${YELLOW}UFW выключен и нет правил SSH.${NC}"
                echo "Выполните: ufw allow ssh"
                exit 1
            fi
        fi
    else
        if ! dpkg -l | grep -q netfilter-persistent; then
            DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
            DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent
        fi
    fi
}

terminal_unavailable() {
    printf 'Терминал недоступен, завершаю меню.\n' >&2
    exit 1
}

read_cancellable_input() {
    local previous_int_trap
    previous_int_trap=$(trap -p INT)
    # Return from this function on Ctrl+C: continue in a read trap can leave
    # Bash waiting for input. EOF and terminal errors must still exit.
    trap 'trap - INT; eval "$previous_int_trap"; printf "\nОтмена.\n"; return 130' INT
    read -r "$@" < /dev/tty || terminal_unavailable
    trap - INT
    eval "$previous_int_trap"
}

uninstall_process() {
    echo -e "\n${RED}=== УДАЛЕНИЕ RKN-GUARD ===${NC}"
    trap 'echo -e "\nОтмена."; return' INT
    read -r -p "Вы уверены? (y/N): " confirm < /dev/tty || terminal_unavailable
    trap 'exit 0' INT

    [[ "$confirm" != "y" ]] && return

    remove_update_schedule || return 1

    # Используем встроенный uninstall rkn-guard (чистит UFW, ipset, iptables, systemd, rsyslog)
    if command -v rkn-guard >/dev/null 2>&1; then
        rkn-guard uninstall --yes || return 1
    else
        # Если бинарник уже удалён, убираем оставшиеся файлы и правила вручную.
        systemctl stop antiscan-aggregate.timer antiscan-aggregate.service 2>/dev/null
        systemctl disable antiscan-aggregate.timer antiscan-aggregate.service 2>/dev/null
        rm -f /usr/local/bin/rkn-guard /usr/local/bin/antiscan-aggregate-logs.sh
        rm -f /etc/systemd/system/antiscan-*
        rm -f /etc/rsyslog.d/10-iptables-scanners.conf /etc/logrotate.d/iptables-scanners

        iptables -D INPUT -j SCANNERS-BLOCK 2>/dev/null
        iptables -F SCANNERS-BLOCK 2>/dev/null
        iptables -X SCANNERS-BLOCK 2>/dev/null
        ipset flush SCANNERS-BLOCK-V4 2>/dev/null
        ipset destroy SCANNERS-BLOCK-V4 2>/dev/null
        ipset flush SCANNERS-BLOCK-V6 2>/dev/null
        ipset destroy SCANNERS-BLOCK-V6 2>/dev/null

        # Чистим UFW (причина бага: правила оставались в before.rules)
        sed -i '/SCANNERS-BLOCK/d' /etc/ufw/before.rules 2>/dev/null
        sed -i '/SCANNERS-BLOCK/d' /etc/ufw/before6.rules 2>/dev/null
        ufw reload 2>/dev/null
    fi

    # Удаляем команду меню и его сохранённый скрипт.
    rm -f "$MENU_COMMAND" "$MANAGER_PATH" "$MANUAL_FILE"

    systemctl restart rsyslog 2>/dev/null
    echo -e "${GREEN}✅ Удалено.${NC}"
    exit 0
}

# --- 🧪 УПРАВЛЕНИЕ IP ---
manage_test_ip() {
    # Создаем файл списка, если нет
    touch "$MANUAL_FILE"
    trap 'continue' INT

    while true; do
        clear
        echo -e "${YELLOW}=== 🧪 УПРАВЛЕНИЕ IP ===${NC}"
        echo -e " ${RED}1.${NC} ⛔ ЗАБАНИТЬ IP (Add)"
        echo -e " ${GREEN}2.${NC} ✅ РАЗБАНИТЬ IP (Select from list)"
        echo -e " ${CYAN}0.${NC} ↩️  Назад"
        echo ""
        echo -ne "${YELLOW}👉 Действие:${NC} "

        read_cancellable_input action || continue

        case $action in
            1)
                echo -e "\nВведите IP для БЛОКИРОВКИ ${YELLOW}(Ctrl+C = Отмена)${NC}:"
                read_cancellable_input -p "IP: " ip || continue
                [[ -z "$ip" ]] && continue

                OUTPUT=$(ipset add SCANNERS-BLOCK-V4 "$ip" 2>&1)
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}✅ IP $ip ЗАБЛОКИРОВАН!${NC}"
                    # Добавляем в файл, если его там еще нет
                    if ! grep -Fxq "$ip" "$MANUAL_FILE"; then
                        echo "$ip" >> "$MANUAL_FILE"
                    fi
                else
                    echo -e "${RED}❌ Ошибка:${NC} $OUTPUT"
                fi
                read_cancellable_input -p "[Enter]..." || continue
                ;;
            2)
                echo -e "\n${GREEN}=== СПИСОК РУЧНЫХ БАНОВ ===${NC}"
                if [ ! -s "$MANUAL_FILE" ]; then
                    echo "Список пуст."
                else
                    # Читаем файл в массив
                    mapfile -t MANUAL_IPS < "$MANUAL_FILE"
                    i=1
                    for ip in "${MANUAL_IPS[@]}"; do
                        echo -e "${CYAN}$i)${NC} $ip"
                        ((i++))
                    done
                fi

                echo -e "\nВведите ${CYAN}НОМЕР${NC} из списка или ${CYAN}IP${NC} вручную:"
                read_cancellable_input -p "Выбор: " input || continue
                [[ -z "$input" ]] && continue

                TARGET_IP=""

                # Проверяем, число это или IP
                if [[ "$input" =~ ^[0-9]+$ ]] && [ "$input" -le "${#MANUAL_IPS[@]}" ] && [ "$input" -gt 0 ]; then
                    # Это номер из списка (массив начинается с 0, ввод с 1)
                    INDEX=$((input-1))
                    TARGET_IP="${MANUAL_IPS[$INDEX]}"
                else
                    # Это вероятно IP
                    TARGET_IP="$input"
                fi

                echo -e "Разбаниваем: ${YELLOW}$TARGET_IP${NC}..."

                OUTPUT=$(ipset del SCANNERS-BLOCK-V4 "$TARGET_IP" 2>&1)
                # Удаляем из файла в любом случае
                sed -i "/^$TARGET_IP$/d" "$MANUAL_FILE"

                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}✅ Успешно разбанен!${NC}"
                else
                    echo -e "${RED}⚠️  Warning:${NC} $OUTPUT (Удален из списка)"
                fi
                read_cancellable_input -p "[Enter]..." || continue
                ;;
            0)
                trap 'exit 0' INT
                return
                ;;
            *) ;;
        esac
    done
}

update_lists() {
    echo -e "\n${CYAN}🔄 Обновление списков...${NC}"
    if ! rkn-guard update -u "$LIST_GOV" -u "$LIST_SCAN" -u "$LIST_SKIPA"; then
        echo -e "${RED}❌ Обновление не выполнено. Проверьте сообщения об ошибках.${NC}" >&2
        return 1
    fi
    echo -e "${GREEN}✅ Готово!${NC}"
    sleep 2
}

# Configuration is data, never shell code. All clock times use Europe/Moscow.
normalize_schedule() {
    local mode=$1 value=$2 item hour minute
    local -a times=()
    case "$mode" in
        off) [[ -z "$value" ]] ;;
        interval)
            [[ "$value" =~ ^[0-9]{1,3}$ ]] || return 1
            (( 10#$value >= 1 && 10#$value <= 168 )) || return 1
            printf '%d' "$((10#$value))"
            ;;
        msk) [[ "$value" == 06:00 ]] && printf '06:00' ;;
        hours)
            [[ ${#value} -le 256 && "$value" =~ ^[0-9:,[:blank:]]+$ ]] || return 1
            value=${value//[[:blank:]]/}
            [[ -n "$value" && "$value" != ,* && "$value" != *, && "$value" != *,,* ]] || return 1
            IFS=',' read -r -a times <<< "$value"
            (( ${#times[@]} <= 24 )) || return 1
            for item in "${times[@]}"; do
                [[ "$item" =~ ^([0-9]{1,2})(:([0-9]{2}))?$ ]] || return 1
                hour=${BASH_REMATCH[1]}
                minute=${BASH_REMATCH[3]:-00}
                (( 10#$hour <= 23 && 10#$minute <= 59 )) || return 1
            done
            for item in "${times[@]}"; do
                hour=${item%%:*}
                minute=00
                [[ "$item" == *:* ]] && minute=${item#*:}
                printf '%02d:%02d\n' "$((10#$hour))" "$((10#$minute))"
            done | LC_ALL=C sort -u | paste -sd, - | tr -d '\n'
            ;;
        *) return 1 ;;
    esac
}

load_update_schedule() {
    SCHEDULE_MODE=off SCHEDULE_VALUE=''
    local -a lines=()
    [[ -e "$SCHEDULE_CONFIG" ]] || return 0
    mapfile -t lines < "$SCHEDULE_CONFIG" || return 1
    [[ ${#lines[@]} == 1 && "${lines[0]}" == *=* ]] || return 1
    SCHEDULE_MODE=${lines[0]%%=*}
    SCHEDULE_VALUE=$(normalize_schedule "$SCHEDULE_MODE" "${lines[0]#*=}") || return 1
}

show_update_schedule() {
    if ! load_update_schedule; then
        printf 'Автообновление: ошибка чтения настроек; выберите расписание заново.\n'
        return
    fi
    printf 'Автообновление: '
    case "$SCHEDULE_MODE" in
        off) printf 'выключено' ;;
        interval) printf 'каждые %s ч.' "$SCHEDULE_VALUE" ;;
        hours) printf 'ежедневно в %s (МСК)' "$SCHEDULE_VALUE" ;;
        msk) printf 'ежедневно в 06:00 (МСК)' ;;
    esac
    if systemctl is-active --quiet "$SCHEDULE_TIMER" 2>/dev/null; then
        if [[ "$SCHEDULE_MODE" == off ]]; then
            printf ' — внимание: таймер всё ещё активен'
        elif systemctl is-enabled --quiet "$SCHEDULE_TIMER" 2>/dev/null; then
            printf ' — активно'
        else
            printf ' — активно только до перезагрузки'
        fi
    elif [[ "$SCHEDULE_MODE" != off ]]; then
        printf ' — таймер не активен'
    fi
    printf '\n'
}

write_update_units() {
    local mode=$1 value=$2 directory=$3 time
    local -a times=()
    cat > "$directory/$SCHEDULE_SERVICE" <<EOF || return 1
[Unit]
Description=rkn-guard subnet list update
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/bin/bash $MANAGER_PATH update
StandardInput=null
StandardOutput=journal
StandardError=journal
EOF
    {
        printf '[Unit]\nDescription=rkn-guard subnet update schedule\n\n[Timer]\n'
        if [[ "$mode" == interval ]]; then
            printf 'OnActiveSec=%sh\nOnUnitActiveSec=%sh\n' "$value" "$value"
        else
            IFS=',' read -r -a times <<< "$value"
            for time in "${times[@]}"; do
                printf 'OnCalendar=*-*-* %s:00 Europe/Moscow\n' "$time"
            done
            # Run once on boot if a calendar event was missed while offline.
            printf 'Persistent=true\n'
        fi
        printf 'AccuracySec=1s\nUnit=%s\n\n[Install]\nWantedBy=timers.target\n' "$SCHEDULE_SERVICE"
    } > "$directory/$SCHEDULE_TIMER"
}

restore_update_schedule() {
    local work=$1 enabled=$2 active=$3 file result=0
    if [[ -f "$SCHEDULE_UNIT_DIR/$SCHEDULE_TIMER" ]]; then
        systemctl disable --now "$SCHEDULE_TIMER" || result=1
    fi
    for file in "$SCHEDULE_SERVICE" "$SCHEDULE_TIMER"; do
        if [[ -f "$work/old/$file" ]]; then
            cp -p -- "$work/old/$file" "$SCHEDULE_UNIT_DIR/$file" || result=1
        else
            rm -f -- "$SCHEDULE_UNIT_DIR/$file" || result=1
        fi
    done
    if [[ -f "$work/old/config" ]]; then
        cp -p -- "$work/old/config" "$SCHEDULE_CONFIG" || result=1
    else
        rm -f -- "$SCHEDULE_CONFIG" || result=1
    fi
    systemctl daemon-reload || result=1
    if [[ "$enabled" == yes ]]; then systemctl enable "$SCHEDULE_TIMER" || result=1; fi
    if [[ "$active" == yes ]]; then systemctl start "$SCHEDULE_TIMER" || result=1; fi
    (( result == 0 )) || printf 'Не удалось полностью восстановить прежнее расписание. Проверьте systemctl status %s.\n' "$SCHEDULE_TIMER" >&2
    return "$result"
}

set_update_schedule() (
    local mode=$1 value=$2 work file enabled=no active=no pending=no schedule_fd
    value=$(normalize_schedule "$mode" "$value") || {
        printf 'Неверное расписание: интервал 1–168 ч.; до 24 значений 0–23 или ЧЧ:ММ через запятую.\n' >&2
        return 1
    }
    command -v flock >/dev/null && command -v systemctl >/dev/null || {
        printf 'Для автообновления нужны systemd и flock (util-linux).\n' >&2
        return 1
    }
    [[ "$mode" == off || -f "$MANAGER_PATH" ]] || {
        printf 'Сначала установите меню в %s.\n' "$MANAGER_PATH" >&2
        return 1
    }
    # This lock serializes settings only. rkn-guard itself owns the separate
    # /run/rkn-guard.lock for update/full/uninstall; do not lock it twice.
    exec {schedule_fd}> "$SCHEDULE_LOCK" || return 1
    flock -n "$schedule_fd" || { printf 'Расписание уже изменяется другим процессом.\n' >&2; return 1; }
    umask 077
    work=$(mktemp -d "$SCHEDULE_UNIT_DIR/.rkn-update.XXXXXX") || return 1
    trap '[[ "$pending" == no ]] || restore_update_schedule "$work" "$enabled" "$active"; rm -rf -- "$work"' EXIT
    trap 'exit 130' INT
    trap 'exit 1' TERM HUP
    mkdir "$work/old" || return 1
    for file in "$SCHEDULE_SERVICE" "$SCHEDULE_TIMER"; do
        if [[ -e "$SCHEDULE_UNIT_DIR/$file" ]]; then
            cp -p -- "$SCHEDULE_UNIT_DIR/$file" "$work/old/$file" || return 1
        fi
    done
    if [[ -e "$SCHEDULE_CONFIG" ]]; then cp -p -- "$SCHEDULE_CONFIG" "$work/old/config" || return 1; fi
    systemctl is-enabled --quiet "$SCHEDULE_TIMER" 2>/dev/null && enabled=yes
    systemctl is-active --quiet "$SCHEDULE_TIMER" 2>/dev/null && active=yes
    printf '%s=%s\n' "$mode" "$value" > "$work/config" || return 1
    if [[ "$mode" != off ]]; then
        write_update_units "$mode" "$value" "$work" || return 1
        # Reapplying the same setting must not postpone an interval timer.
        if [[ "$enabled" == yes && "$active" == yes ]] &&
            cmp -s "$work/config" "$SCHEDULE_CONFIG" &&
            cmp -s "$work/$SCHEDULE_TIMER" "$SCHEDULE_UNIT_DIR/$SCHEDULE_TIMER" &&
            cmp -s "$work/$SCHEDULE_SERVICE" "$SCHEDULE_UNIT_DIR/$SCHEDULE_SERVICE"; then
            printf 'Это расписание уже включено.\n'
            return 0
        fi
    fi
    pending=yes
    if [[ -f "$SCHEDULE_UNIT_DIR/$SCHEDULE_TIMER" || "$active" == yes || "$enabled" == yes ]]; then
        systemctl disable --now "$SCHEDULE_TIMER" || return 1
    fi
    # Stopping a timer does not interrupt an update already in progress.
    if [[ "$mode" != off ]]; then
        for file in "$SCHEDULE_SERVICE" "$SCHEDULE_TIMER"; do
            chmod 644 "$work/$file" && mv -f -- "$work/$file" "$SCHEDULE_UNIT_DIR/$file" || return 1
        done
        systemctl daemon-reload && systemctl enable "$SCHEDULE_TIMER" &&
            systemctl start "$SCHEDULE_TIMER" || return 1
    fi
    mv -f -- "$work/config" "$SCHEDULE_CONFIG" || return 1
    pending=no
    printf 'Расписание сохранено.\n'
)

remove_update_schedule() {
    [[ -e "$SCHEDULE_CONFIG" || -e "$SCHEDULE_UNIT_DIR/$SCHEDULE_TIMER" ]] || return 0
    set_update_schedule off '' || return 1
    rm -f -- "$SCHEDULE_CONFIG" "$SCHEDULE_UNIT_DIR/$SCHEDULE_TIMER" "$SCHEDULE_UNIT_DIR/$SCHEDULE_SERVICE" || return 1
    systemctl daemon-reload
}

manage_updates() {
    local action value
    while true; do
        printf '\n=== ОБНОВЛЕНИЕ ПОДСЕТЕЙ ===\n'
        show_update_schedule
        printf '%s\n' '1. Обновить сейчас' '2. Каждые N часов' \
            '3. В заданное время по списку (МСК)' '4. Ежедневно в 06:00 (МСК)' \
            '5. Отключить автообновление' '0. Назад'
        read_cancellable_input -p 'Обновления — выбор: ' action || continue
        case "$action" in
            1) update_lists ;;
            2)
                read_cancellable_input -p 'Интервал в часах (1–168): ' value || continue
                set_update_schedule interval "$value" || printf 'Не удалось применить расписание; подробности выше.\n' >&2
                ;;
            3)
                read_cancellable_input -p 'Время МСК через запятую (6,12,18 или 06:00,18:30): ' value || continue
                set_update_schedule hours "$value" || printf 'Не удалось применить расписание; подробности выше.\n' >&2
                ;;
            4) set_update_schedule msk 06:00 || printf 'Не удалось включить расписание.\n' >&2 ;;
            5) set_update_schedule off '' || printf 'Не удалось отключить расписание.\n' >&2 ;;
            0) return ;;
            *) printf 'Неверный пункт.\n' ;;
        esac
    done
}

install_menu_command() {
    local temp_manager="/tmp/rkn-guard-manager.sh"

    if command -v curl >/dev/null; then
        curl -fsSL "$MANAGER_URL" -o "$temp_manager"
    else
        wget -qO "$temp_manager" "$MANAGER_URL"
    fi

    install -m 755 "$temp_manager" "$MANAGER_PATH"
    rm -f "$temp_manager"
    printf '%s\n' '#!/usr/bin/env bash' "exec $MANAGER_PATH \"\$@\"" > "$MENU_COMMAND"
    chmod 755 "$MENU_COMMAND"
}

update_application() {
    echo -e "\n${CYAN}⬆️  Обновление rkn-guard и меню...${NC}"

    # Обновляем только бинарник и файлы меню. Не вызываем `full`, поэтому
    # цепочки iptables и их счётчики заблокированных атак не сбрасываются.
    if command -v curl >/dev/null; then
        curl -fsSL "$TG_URL" | bash
    else
        wget -qO- "$TG_URL" | bash
    fi

    install_menu_command
    echo -e "${GREEN}✅ rkn-guard и меню обновлены. Счётчики атак сохранены.${NC}"
    sleep 2
}

install_process() {
    trap 'exit 1' INT
    clear
    echo -e "${CYAN}🚀 УСТАНОВКА RKN-GUARD${NC}"
    check_firewall_safety

    echo -e "\n${BLUE}[INFO] Установка...${NC}"
    apt-get update
    apt-get install -y curl wget rsyslog ipset ufw grep sed coreutils whois util-linux tzdata
    systemctl enable --now rsyslog

    if command -v curl >/dev/null; then curl -fsSL "$TG_URL" | bash; else wget -qO- "$TG_URL" | bash; fi

    install_menu_command

    echo -e "\n${BLUE}[INFO] Настройка правил...${NC}"
    rkn-guard full -u "$LIST_GOV" -u "$LIST_SCAN" -u "$LIST_SKIPA" --enable-logging

    if [ $? -ne 0 ]; then
        echo -e "\n${RED}❌ ОШИБКА УСТАНОВКИ!${NC}"
        exit 1
    fi

    mkdir -p /var/log
    touch /var/log/iptables-scanners-{ipv4,ipv6}.log
    LOG_GROUP="syslog"; getent group adm >/dev/null && LOG_GROUP="adm"
    chown syslog:$LOG_GROUP /var/log/iptables-scanners-*.log
    chmod 640 /var/log/iptables-scanners-*.log

    # Создаем файл для ручных банов, если нет
    touch "$MANUAL_FILE"

    systemctl restart rsyslog
    systemctl restart antiscan-aggregate.service 2>/dev/null || true
    systemctl restart antiscan-aggregate.timer

    echo -e "\n${GREEN}✅ Установка завершена!${NC}"
    sleep 2
}

view_log() {
    local file=$1
    echo -e "\n${YELLOW}=== LIVE LOG (Ctrl+C для возврата) ===${NC}"
    trap ':' INT
    tail -f "$file"
    trap 'exit 0' INT
}

show_menu() {
    trap 'exit 0' INT
    while true; do
        clear
        refresh_version_status
        IPSET_CNT=$(ipset list SCANNERS-BLOCK-V4 2>/dev/null | grep "Number of entries" | awk '{print $4}')
        [[ -z "$IPSET_CNT" ]] && IPSET_CNT="0"
        PKTS_CNT=$(iptables -vnL SCANNERS-BLOCK 2>/dev/null | grep "LOG" | awk '{print $1}')
        [[ -z "$PKTS_CNT" ]] && PKTS_CNT="0"

        echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║               💜 RKN-GUARD MANAGER 💜                ║${NC}"
        echo -e "${CYAN}║                   💜 by X3D vpn 💜                   ║${NC}"
        echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
        printf "${CYAN}║${NC}  📊 Подсетей:       ${GREEN}%-33s${NC}${CYAN}║${NC}\n" "$IPSET_CNT"
        printf "${CYAN}║${NC}  🔥 Атак отбито:    ${RED}%-33s${NC}${CYAN}║${NC}\n" "$PKTS_CNT"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
        echo -e "  ${DIM}└─${NC} ${BOLD}${GREEN}◆ ${CURRENT_VERSION}${NC} ${DIM}·${NC} ${YELLOW}${CURRENT_BRANCH}${NC} ${DIM}· ${UPDATE_STATUS}${NC}"
        echo ""
        echo -e " ${GREEN}1.${NC} 📈 Топ атак (CSV)"
        echo -e " ${GREEN}2.${NC} 🕵 Логи IPv4 (Live)"
        echo -e " ${GREEN}3.${NC} 🕵 Логи IPv6 (Live)"
        echo -e " ${GREEN}4.${NC} 🧪 Управление IP (Ban/Unban)"
        echo -e " ${GREEN}5.${NC} 🔄 Обновление списков и расписание"
        echo -e " ${GREEN}6.${NC} ⬆️  Обновить rkn-guard"
        echo -e " ${GREEN}7.${NC} 🛠️  Переустановить (Reinstall)"
        echo -e " ${RED}8.${NC} 🗑️  Удалить (Uninstall)"
        echo -e " ${RED}0.${NC} ❌ Выход"
        echo ""

        echo -ne "${CYAN}👉 Ваш выбор:${NC} "
        read -r choice < /dev/tty || terminal_unavailable

        case $choice in
            1)
                echo -e "\n${GREEN}ТОП 20:${NC}"
                [ -f /var/log/iptables-scanners-aggregate.csv ] && tail -20 /var/log/iptables-scanners-aggregate.csv || echo "Нет данных"
                read -r -p $'\n[Enter] назад...' < /dev/tty || terminal_unavailable
                ;;
            2) view_log "/var/log/iptables-scanners-ipv4.log" ;;
            3) view_log "/var/log/iptables-scanners-ipv6.log" ;;
            4) manage_test_ip ;;
            5) manage_updates ;;
            6)
                update_application
                ;;
            7)
                rm -f /var/log/iptables-scanners-aggregate.csv
                install_process
                ;;
            8) uninstall_process ;;
            0) exit 0 ;;
            *) echo "Неверно"; sleep 1 ;;
        esac
    done
}

# When piped into bash, BASH_SOURCE[0] is unset even though we run directly.
if [[ "${BASH_SOURCE[0]:-$0}" != "$0" ]]; then
    return 0
fi
check_root
case "${1:-}" in
    install) install_process ;;
    monitor) show_menu ;;
    update) update_lists ;;
    uninstall) uninstall_process ;;
    *) show_menu ;;
esac
