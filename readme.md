# rkn-guard

`rkn-guard` — утилита для блокировки подсетей сканеров с помощью `ipset` и `iptables`. Она загружает указанные списки сетей, применяет правила и сохраняет их после перезагрузки.

## Требования

- Linux с `systemd`;
- права `root` или `sudo`;
- доступ к GitHub для установки и к URL списков при активации.

## Установка

Основной установщик — [`install.sh`](./install.sh). Он устанавливает зависимости, скачивает бинарник `rkn`, применяет списки и открывает меню управления:

```bash
curl -fsSL https://raw.githubusercontent.com/Flecksis/rkn-guard/master/install.sh | sudo bash -s -- install
```

Если репозиторий уже скачан:

```bash
sudo bash install.sh install
```

Скрипт загрузки бинарника сохранён отдельно для совместимости и называется [`app install.sh`](./app%20install.sh):

```bash
curl -fsSL 'https://raw.githubusercontent.com/Flecksis/rkn-guard/master/app%20install.sh' | sudo bash
```

## Активация

Для включения защиты используйте команду `rkn` и укажите хотя бы один URL со списком подсетей:

```bash
sudo rkn full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  --enable-logging
```

Можно передать несколько списков:

```bash
sudo rkn full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list \
  --enable-logging
```

Внешние ссылки выше — источники списков; их названия сохранены в URL, чтобы загрузка продолжала работать.

## Управление

```bash
# Справка и версия
rkn --help
rkn --version

# Удалить правила и системные настройки
sudo rkn uninstall

# Удалить без подтверждения
sudo rkn uninstall --yes

# Удалить вместе с логами
sudo rkn uninstall --yes --remove-logs
```

После запуска основного установщика доступно меню мониторинга, обновления списков, ручной блокировки IP и удаления:

```bash
sudo bash install.sh
```

## Репозиторий и релизы

Исходный код, задачи и готовые бинарники: [github.com/Flecksis/rkn-guard](https://github.com/Flecksis/rkn-guard).
