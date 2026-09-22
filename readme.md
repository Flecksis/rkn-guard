# rkn-guard

`rkn-guard` блокирует подсети сканеров через `ipset` и `iptables`, сохраняет правила после перезагрузки и ведёт журналы подключений.

## Установка

Нужен Linux с `systemd` и права `root`/`sudo`. Установщик загрузит основной бинарник и установит команду меню `rkn`:

```bash
curl -fsSL https://raw.githubusercontent.com/Flecksis/rkn-guard/master/install.sh | sudo bash -s -- install
```

При запуске из клона репозитория:

```bash
sudo bash install.sh install
```

Для установки должен существовать опубликованный GitHub Release с файлами `rkn-guard-linux-*`.

## Меню

После установки просто выполните:

```bash
sudo rkn
```

Откроется интерактивное меню со статистикой, логами, ручной блокировкой IP, обновлением списков, переустановкой и удалением.

## Основная утилита

`rkn-guard` — основной бинарник. При необходимости его можно запускать напрямую:

```bash
sudo rkn-guard full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  --enable-logging

rkn-guard --help
sudo rkn-guard uninstall
```

Внешняя ссылка выше ведёт на источник списков и сохраняет своё исходное название в URL.

## Файлы установщиков

- `install.sh` — основной установщик и скрипт меню.
- `app install.sh` — отдельный загрузчик бинарника `rkn-guard`.

Репозиторий: [github.com/Flecksis/rkn-guard](https://github.com/Flecksis/rkn-guard).
