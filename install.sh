#!/bin/bash
set -u

# --- ЦВЕТА ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

TG_URL="https://raw.githubusercontent.com/Flecksis/rkn-guard/master/app%20install.sh"
MANAGER_URL="https://raw.githubusercontent.com/Flecksis/rkn-guard/master/install.sh"
MANAGER_PATH="/opt/rkn-guard-manager.sh"
MENU_COMMAND="/usr/local/bin/rkn"
LIST_GOV="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list"
LIST_SCAN="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list"
LIST_SKIPA="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/skipa.list"
MANUAL_FILE="/opt/rkn-guard-manual.list"

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

uninstall_process() {
    echo -e "\n${RED}=== УДАЛЕНИЕ RKN-GUARD ===${NC}"
    trap 'echo -e "\nОтмена."; return' INT
    read -p "Вы уверены? (y/N): " confirm < /dev/tty
    trap 'exit 0' INT

    [[ "$confirm" != "y" ]] && return

    # Используем встроенный uninstall rkn-guard (чистит UFW, ipset, iptables, systemd, rsyslog)
    if command -v rkn-guard >/dev/null 2>&1; then
        rkn-guard uninstall --yes
    else
        # Fallback: ручная чистка (если бинарник уже удалён)
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

        read -r action < /dev/tty || continue

        case $action in
            1)
                echo -e "\nВведите IP для БЛОКИРОВКИ ${YELLOW}(Ctrl+C = Отмена)${NC}:"
                trap 'echo -e "\nОтмена."; sleep 1; continue' INT
                read -p "IP: " ip < /dev/tty
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
                read -p "[Enter]..." < /dev/tty
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
                trap 'echo -e "\nОтмена."; sleep 1; continue' INT
                read -p "Выбор: " input < /dev/tty
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
                read -p "[Enter]..." < /dev/tty
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
    apt-get install -y curl wget rsyslog ipset ufw grep sed coreutils whois
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
        echo ""
        echo -e " ${GREEN}1.${NC} 📈 Топ атак (CSV)"
        echo -e " ${GREEN}2.${NC} 🕵 Логи IPv4 (Live)"
        echo -e " ${GREEN}3.${NC} 🕵 Логи IPv6 (Live)"
        echo -e " ${GREEN}4.${NC} 🧪 Управление IP (Ban/Unban)"
        echo -e " ${GREEN}5.${NC} 🔄 Обновить списки (Update)"
        echo -e " ${GREEN}6.${NC} ⬆️  Обновить rkn-guard"
        echo -e " ${GREEN}7.${NC} 🛠️  Переустановить (Reinstall)"
        echo -e " ${RED}8.${NC} 🗑️  Удалить (Uninstall)"
        echo -e " ${RED}0.${NC} ❌ Выход"
        echo ""

        echo -ne "${CYAN}👉 Ваш выбор:${NC} "
        read -r choice < /dev/tty

        case $choice in
            1)
                echo -e "\n${GREEN}ТОП 20:${NC}"
                [ -f /var/log/iptables-scanners-aggregate.csv ] && tail -20 /var/log/iptables-scanners-aggregate.csv || echo "Нет данных"
                read -p $'\n[Enter] назад...' < /dev/tty
                ;;
            2) view_log "/var/log/iptables-scanners-ipv4.log" ;;
            3) view_log "/var/log/iptables-scanners-ipv6.log" ;;
            4) manage_test_ip ;;
            5) update_lists ;;
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

check_root
case "${1:-}" in
    install) install_process ;;
    monitor) show_menu ;;
    update) update_lists ;;
    uninstall) uninstall_process ;;
    *) show_menu ;;
esac
