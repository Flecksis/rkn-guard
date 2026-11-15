#!/usr/bin/env bash

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # Сбрасываем цвет.

# Константы
REPO="Flecksis/rkn-guard"
BINARY_NAME="rkn-guard"
INSTALL_DIR="/usr/local/bin"
# FIX-3: фиксированный релиз вместо releases/latest. Любой скачанный бинарник
# сверяется с checksums.txt из того же релиза; без совпадения sha256 установки нет.
PINNED_TAG="${RKN_GUARD_PINNED_TAG:-v2.4.0}"
DEV_MODE=false
TAG="${RKN_GUARD_TAG:-$PINNED_TAG}"

# Функция для вывода сообщений
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Проверка прав root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Необходимо запустить скрипт с правами root (sudo)"
        exit 1
    fi
}

# Определение архитектуры и ОС
detect_system() {
    local os=""
    local arch=""

    # Определение ОС
    case "$(uname -s)" in
        Linux*)
            os="linux"
            ;;
        *)
            log_error "Неподдерживаемая ОС: $(uname -s). Поддерживается только Linux"
            exit 1
            ;;
    esac

    # Определение архитектуры
    case "$(uname -m)" in
        x86_64|amd64)
            arch="amd64"
            ;;
        i386|i686)
            arch="386"
            ;;
        armv7l|armv6l)
            arch="arm"
            ;;
        aarch64|arm64)
            arch="arm64"
            ;;
        *)
            log_error "Неподдерживаемая архитектура: $(uname -m)"
            exit 1
            ;;
    esac

    echo "${os}-${arch}"
}

# Проверка sha256 скачанного бинарника по checksums.txt того же релиза.
verify_asset_sha256() {
    local file=$1 name=$2 tag=$3 sums expected actual
    sums=$(mktemp) || return 1
    if ! curl -fsSL "https://github.com/${REPO}/releases/download/${tag}/checksums.txt" -o "$sums" 2>/dev/null \
        && ! wget -qO "$sums" "https://github.com/${REPO}/releases/download/${tag}/checksums.txt" 2>/dev/null; then
        rm -f "$sums"
        log_error "Не удалось скачать checksums.txt для ${tag}: проверить целостность нечем, установка прервана"
        return 1
    fi
    expected=$(awk -v n="$name" '$2 == n {print $1}' "$sums" | head -n1)
    rm -f "$sums"
    if [ -z "$expected" ]; then
        log_error "В checksums.txt релиза ${tag} нет записи для ${name}: установка прервана"
        return 1
    fi
    actual=$(sha256sum "$file" | awk '{print $1}')
    if [ "$expected" != "$actual" ]; then
        log_error "sha256 не совпал для ${name}: ожидалось ${expected}, получено ${actual}"
        return 1
    fi
    log_info "sha256 подтверждён (${tag}): ${actual}"
    return 0
}

# Получение тега релиза для --dev (явный непроверенный ref, sha256 всё равно проверяется)
get_latest_release_tag() {
    local api_url="https://api.github.com/repos/${REPO}/releases"

    if [ "$DEV_MODE" = true ]; then
        log_info "Режим DEV: поиск последнего релиза (включая pre-release)..."
        api_url="${api_url}?per_page=1"
    else
        api_url="${api_url}/latest"
    fi

    local tag=""
    if command -v curl &> /dev/null; then
        tag=$(curl -fsSL "${api_url}" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/"tag_name": *"\(.*\)"/\1/')
    elif command -v wget &> /dev/null; then
        tag=$(wget -qO- "${api_url}" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/"tag_name": *"\(.*\)"/\1/')
    else
        log_error "Не найден curl или wget. Установите один из них"
        exit 1
    fi

    if [ -z "$tag" ]; then
        log_error "Не удалось определить версию релиза"
        exit 1
    fi

    echo "$tag"
}

# Скачивание бинарника
download_binary() {
    local platform=$1
    local temp_file
    temp_file=$(mktemp) || return 1
    local download_url=""

    local tag="$TAG"
    if [ "$DEV_MODE" = true ]; then
        tag=$(get_latest_release_tag) || { rm -f "$temp_file"; return 1; }
        log_warn "Режим DEV: тег ${tag} не закреплён, целостность проверяется по его checksums.txt"
    fi
    download_url="https://github.com/${REPO}/releases/download/${tag}/${BINARY_NAME}-${platform}"

    log_info "Скачивание ${BINARY_NAME} для ${platform}..."
    log_info "URL: ${download_url}"

    if command -v curl &> /dev/null; then
        if ! curl -fsSL "${download_url}" -o "${temp_file}"; then
            log_error "Ошибка при скачивании бинарника"
            rm -f "$temp_file"
            exit 1
        fi
    elif command -v wget &> /dev/null; then
        if ! wget -q "${download_url}" -O "${temp_file}"; then
            log_error "Ошибка при скачивании бинарника"
            rm -f "$temp_file"
            exit 1
        fi
    else
        log_error "Не найден curl или wget. Установите один из них"
        exit 1
    fi

    if ! verify_asset_sha256 "$temp_file" "${BINARY_NAME}-${platform}" "$tag"; then
        rm -f "$temp_file"
        exit 1
    fi

    echo "${temp_file}"
}

# Установка бинарника
install_binary() {
    local temp_file=$1
    local install_path="${INSTALL_DIR}/${BINARY_NAME}"

    log_info "Установка в ${install_path}..."

    # Создаём директорию если не существует
    mkdir -p "${INSTALL_DIR}"

    # Копируем файл
    local staged
    staged=$(mktemp "${install_path}.XXXXXX") || return 1
    if ! install -m 755 "${temp_file}" "$staged" || ! "$staged" --version >/dev/null; then
        rm -f "$staged" "$temp_file"
        log_error "Новый бинарник не прошёл проверку. Прежний файл сохранён."
        return 1
    fi
    if ! mv -f "$staged" "$install_path"; then
        rm -f "$staged" "$temp_file"
        return 1
    fi

    # Выдаём права на выполнение
    chmod +x "${install_path}"

    # Удаляем временный файл
    rm -f "${temp_file}"

    log_info "Бинарник установлен."
}

# Проверка установки
verify_installation() {
    if command -v ${BINARY_NAME} &> /dev/null; then
        local version=$(${BINARY_NAME} --version 2>&1 | head -n1)
        log_info "✓ ${BINARY_NAME} успешно установлен"
        log_info "Версия: ${version}"
        log_info "Путь: $(which ${BINARY_NAME})"
        return 0
    else
        log_error "Установка не удалась"
        return 1
    fi
}

# Вывод информации об использовании
show_usage() {
    log_info ""
    log_info "⚠️  ВАЖНО: Обязательно укажите URL с списками подсетей через параметр -u"
    echo "" >&2
    log_info "Публичные списки доступны здесь:"
    echo "  https://github.com/shadow-netlab/traffic-guard-lists/tree/main" >&2
    log_info "Для получения полной справки:"
    echo "" >&2
    echo "  ${BINARY_NAME} --help" >&2
    echo "" >&2
}

# Вывод справки
show_help() {
    echo "Использование: $0 [OPTIONS]" >&2
    echo "" >&2
    echo "Опции:" >&2
    echo "  --tag TAG   Установить конкретный релиз (по умолчанию ${PINNED_TAG}); sha256 обязателен"
    echo "  --dev       Установить последний релиз, включая pre-release (sha256 всё равно проверяется)" >&2
    echo "  --help      Показать эту справку" >&2
    echo "" >&2
    exit 0
}

# Парсинг аргументов
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dev)
                DEV_MODE=true
                shift
                ;;
            --tag)
                [ -n "${2:-}" ] || { log_error "--tag требует значение"; exit 1; }
                TAG="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                ;;
            *)
                log_error "Неизвестный параметр: $1"
                echo "Используйте --help для справки" >&2
                exit 1
                ;;
        esac
    done
}

# Главная функция
main() {
    # Парсинг аргументов
    parse_args "$@"

    log_info "=== Установка rkn-guard ==="
    if [ "$DEV_MODE" = true ]; then
        log_warn "Режим DEV: будет установлена последняя версия (включая pre-release)"
    fi
    echo "" >&2

    # Проверка прав
    check_root

    # Определение системы
    local platform
    platform=$(detect_system) || exit 1
    log_info "Определена система: ${platform}"

    # Скачивание
    local temp_file
    temp_file=$(download_binary "${platform}") || exit 1

    # Установка
    install_binary "${temp_file}"

    # Проверка
    if verify_installation; then
        echo "" >&2
        show_usage
        exit 0
    else
        exit 1
    fi
}

# Запуск
if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
    main "$@"
fi
