# XKEEN VLESS Configurator

GUI-приложение для генерации конфигурационных файлов **Xray / Xkeen** из VLESS-ссылок.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-lightgrey)

## Возможности

- Импорт VLESS-ссылок и генерация трёх конфигурационных файлов:
  - `04_outbounds.json` — список прокси-серверов
  - `05_routing.json` — балансировщик с leastPing + принудительные правила
  - `06_observatory.json` — мониторинг доступности прокси
- Загрузка и редактирование существующих конфигов
- Принудительная маршрутизация (обход балансировщика) для отдельных доменов/IP
- Поддержка VLESS + Reality

## Скриншот

*(добавьте скриншот приложения в папку `assets/` и раскомментируйте строку ниже)*

<!-- ![screenshot](assets/screenshot.png) -->

## Установка и запуск

### Требования

- **Python 3.8+** (с модулем `tkinter`, входит в стандартную поставку CPython)

### Из исходников

```bash
git clone https://github.com/<ваш-username>/xkeen-vless-configurator.git
cd xkeen-vless-configurator
python xkeen_vless_configurator.py
```

### Windows EXE (без установки Python)

Скачайте готовый `.exe` из раздела [Releases](../../releases).

## Сборка EXE (Windows)

Для создания портативного `.exe` файла:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "XKEEN_VLESS_Configurator" xkeen_vless_configurator.py
```

Готовый файл будет в папке `dist/`.

## Использование

1. **Добавление прокси** — введите Tag (например, `proxy-de-1`) и VLESS URL, нажмите «Добавить».
2. **Загрузка существующих конфигов** — нажмите «Загрузить все файлы из папки» и выберите директорию с текущими конфигами. Приложение извлечёт прокси и правила.
3. **Принудительные правила** — выберите прокси, тип (domain/ip) и значение. Эти правила обходят балансировщик и направляют трафик напрямую через указанный прокси.
4. **Генерация** — нажмите «Сгенерировать все файлы» и выберите целевую папку (обычно `/opt/etc/xray/configs/`).
5. **Перезапуск** — после копирования файлов выполните: `xkeen -restart`.

## Структура генерируемых файлов

```
configs/
├── 04_outbounds.json    # VLESS-прокси + direct + block
├── 05_routing.json      # Правила маршрутизации
│   ├── block-правила (высший приоритет)
│   ├── принудительные правила
│   ├── правило балансировщика (leastPing)
│   └── прочие ручные правила
└── 06_observatory.json  # Мониторинг доступности прокси
```

## Лицензия

[MIT](LICENSE)
