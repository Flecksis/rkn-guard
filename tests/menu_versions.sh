#!/usr/bin/env bash
set -euo pipefail

# Загружаем функции меню без запуска интерфейса и команд firewall.
source "$(dirname "$0")/../install.sh"
mock_version=v1.2.0
mock_branch=dev
mock_tag=v1.3.0
mock_offline=false
mock_legacy=false
rkn-guard() {
    if [[ "$1" == build-info ]]; then
        [[ "$mock_legacy" == true ]] && return 1
        printf '%s\n%s\n' "$mock_version" "$mock_branch"
    else
        printf 'rkn-guard version %s\n' "$mock_version"
    fi
}
curl() {
    [[ "$mock_offline" == true ]] && return 1
    printf '{"tag_name":"%s"}\n' "$mock_tag"
}
check() {
    LAST_UPDATE_CHECK=-600
    refresh_version_status
    [[ "$UPDATE_STATUS" == "$1" ]] || { printf 'Ожидалось: %s\nПолучено: %s\n' "$1" "$UPDATE_STATUS"; exit 1; }
}
check 'доступно обновление: v1.3.0'
[[ "$CURRENT_BRANCH" == dev ]]
mock_version=v1.3.0
check 'установлена последняя версия (v1.3.0)'
mock_version=v1.10.0
check 'сборка новее стабильного релиза v1.3.0'
mock_version=dev
check 'последний стабильный релиз: v1.3.0; сборка не сравнивается'
mock_legacy=true
mock_version=v1.2.0
check 'доступно обновление: v1.3.0'
[[ "$CURRENT_BRANCH" == неизвестна ]]
mock_offline=true
# До истечения кэша повторный запрос не нужен.
refresh_version_status
[[ "$UPDATE_STATUS" == 'доступно обновление: v1.3.0' ]]
check 'не удалось проверить'
mock_offline=false
mock_tag='неверный ответ'
check 'не удалось проверить'
printf 'Проверки версии, ветки, обновлений и сетевых ошибок прошли.\n'
