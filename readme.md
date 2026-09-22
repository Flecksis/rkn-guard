```markdown
# 🛡️ rkn-guard

**rkn-guard** — лёгкий инструмент для защиты Linux-серверов.  
Блокирует подсети сканеров через `ipset` + `iptables`, сохраняет правила после перезагрузки и ведёт журналы подключений.

---

## 🚀 Установка

Требования:
- Linux с **systemd**
- права `root` / `sudo`

### Быстрая установка
```bash
curl -fsSL https://raw.githubusercontent.com/Flecksis/rkn-guard/master/install.sh | sudo bash -s -- install
```

### Установка из клона репозитория
```bash
sudo bash install.sh install
```

> **Важно:** для установки должен существовать опубликованный GitHub Release с файлами `rkn-guard-linux-*`.

---

## 📋 Меню

После установки просто выполните:

```bash
sudo rkn
```

Откроется интерактивное меню:

- статистика
- логи
- ручная блокировка IP
- обновление списков
- переустановка
- удаление

### Особенности пунктов меню

| Пункт | Действие |
|-------|----------|
| **5. 🔄 Обновить списки** | Обновляет только ipset-наборы и **сохраняет** счётчик отбитых атак |
| **6. ⬆️ Обновить rkn-guard и меню** | Скачивает свежий бинарник и скрипт меню **без сброса** счётчиков |

---

## ⚙️ Основная утилита

`rkn-guard` — основной бинарник. Его можно запускать напрямую:

```bash
# Полный запуск с внешним списком и логированием
sudo rkn-guard full \
  -u https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list \
  --enable-logging

# Справка
rkn-guard --help

# Удаление
sudo rkn-guard uninstall
```

> Внешняя ссылка выше ведёт на источник списков и сохраняет своё исходное название в URL.

---

## 📁 Файлы установщиков

| Файл | Описание |
|------|----------|
| `install.sh` | Основной установщик и скрипт меню |
| `app install.sh` | Отдельный загрузчик бинарника `rkn-guard` |

---

## 📦 Репозиторий

[github.com/Flecksis/rkn-guard](https://github.com/Flecksis/rkn-guard)

---

## 📄 Лицензия

MIT License  
Copyright (c) 2026 rkn-guard
```
