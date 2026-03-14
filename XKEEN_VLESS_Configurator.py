#!/usr/bin/env python3
"""
XKEEN VLESS Configurator v4.0

GUI-приложение для генерации конфигурационных файлов Xray/Xkeen
из VLESS-ссылок. Поддерживает балансировку, принудительную маршрутизацию
и импорт существующих конфигов.

Требования: Python 3.8+, tkinter (входит в стандартную поставку CPython).
"""

from __future__ import annotations

import json
import os
import re
import sys
import tkinter as tk
from dataclasses import dataclass, field
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any
from urllib.parse import unquote

__version__ = "4.0.0"
__author__ = "Wolfhander"

# ──────────────────────────────────────────────
# Константы
# ──────────────────────────────────────────────

APP_TITLE = f"XKEEN VLESS Configurator v{__version__}"
APP_GEOMETRY = "960x780"

FILE_OUTBOUNDS = "04_outbounds.json"
FILE_ROUTING = "05_routing.json"
FILE_OBSERVATORY = "06_observatory.json"
FILE_POLICY = "06_policy.json"
FILE_POLICY_NEW = "10_policy.json"

STANDARD_TAGS = {"direct", "block"}
VALID_NETWORKS = {"tcp", "kcp", "ws", "http", "quic", "grpc"}

DEFAULT_PROBE_INTERVAL = "60s"
DEFAULT_PROBE_URL = "https://www.gstatic.com/generate_204"
DEFAULT_PORT = 443
DEFAULT_FLOW = "xtls-rprx-vision"
DEFAULT_FINGERPRINT = "chrome"


# ──────────────────────────────────────────────
# Утилиты
# ──────────────────────────────────────────────

def read_json_with_comments(filepath: str | Path) -> dict[str, Any]:
    """Читает JSON-файл, игнорируя строки-комментарии (// …)."""
    lines: list[str] = []
    with open(filepath, "r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped.startswith("//"):
                lines.append(line)
    return json.loads("".join(lines))


def write_json_with_header(filepath: str | Path, data: dict, header: str = "") -> None:
    """Записывает JSON с необязательным однострочным комментарием-заголовком."""
    with open(filepath, "w", encoding="utf-8") as fh:
        if header:
            fh.write(f"// {header}\n")
        json.dump(data, fh, indent=2, ensure_ascii=False)


# ──────────────────────────────────────────────
# Модель данных
# ──────────────────────────────────────────────

@dataclass
class VlessParams:
    """Результат разбора VLESS URL."""
    uuid: str
    host: str
    port: int = DEFAULT_PORT
    security: str = "reality"
    encryption: str = "none"
    pbk: str = ""
    fp: str = DEFAULT_FINGERPRINT
    flow: str = DEFAULT_FLOW
    sni: str = ""
    network: str = "tcp"


@dataclass
class ForcedRules:
    """Принудительные правила маршрутизации для одного прокси."""
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.domains) + len(self.ips)

    @property
    def is_empty(self) -> bool:
        return self.total == 0


# ──────────────────────────────────────────────
# Парсинг VLESS URL
# ──────────────────────────────────────────────

def parse_vless_url(url: str) -> VlessParams:
    """
    Разбирает VLESS URL вида:
        vless://UUID@HOST:PORT?security=…&pbk=…&fp=…&flow=…&sni=…&type=…#remark
    и возвращает VlessParams.
    """
    if not url.startswith("vless://"):
        raise ValueError("URL должен начинаться с vless://")

    body = url[8:]

    # Отрезаем фрагмент (#remark)
    body, _, _ = body.partition("#")

    # Отделяем query-string
    main_part, _, query_string = body.partition("?")

    # Парсим query параметры
    qp: dict[str, str] = {}
    if query_string:
        for token in query_string.split("&"):
            key, _, val = token.partition("=")
            qp[key] = unquote(val)

    # UUID @ host:port
    if "@" not in main_part:
        raise ValueError("Не найден разделитель '@' (UUID@host:port)")

    uuid, _, host_port = main_part.partition("@")

    host, _, port_str = host_port.rpartition(":")
    if not host:
        host = port_str
        port_str = ""

    # Чистим порт
    port_digits = re.sub(r"\D", "", port_str)
    port = int(port_digits) if port_digits else DEFAULT_PORT

    # network / type
    network = qp.get("type", "tcp").strip()
    if network not in VALID_NETWORKS:
        network = "tcp"

    return VlessParams(
        uuid=uuid.strip(),
        host=host.strip(),
        port=port,
        security=qp.get("security", "reality"),
        encryption=qp.get("encryption", "none"),
        pbk=qp.get("pbk", ""),
        fp=qp.get("fp", DEFAULT_FINGERPRINT),
        flow=qp.get("flow", DEFAULT_FLOW),
        sni=qp.get("sni", host).strip(),
        network=network,
    )


# ──────────────────────────────────────────────
# Генерация конфигов
# ──────────────────────────────────────────────

class ConfigGenerator:
    """Генерирует тройку JSON-конфигов Xray/Xkeen."""

    def __init__(
        self,
        entries: list[tuple[str, str]],
        forced_rules: dict[str, ForcedRules],
    ) -> None:
        self.entries = entries
        self.forced_rules = forced_rules

    @property
    def proxy_tags(self) -> list[str]:
        return [tag for tag, _ in self.entries]

    # ── outbounds ────────────────────────────

    def build_outbounds(self) -> dict:
        outbounds: list[dict] = []
        for tag, vless_url in self.entries:
            p = parse_vless_url(vless_url)
            outbound: dict[str, Any] = {
                "tag": tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": p.host,
                        "port": p.port,
                        "users": [{
                            "id": p.uuid,
                            "flow": p.flow,
                            "encryption": p.encryption,
                            "level": 0,
                        }],
                    }],
                },
                "streamSettings": {
                    "network": p.network,
                    "security": p.security,
                },
            }
            # Reality-настройки — только если security == reality
            if p.security == "reality":
                outbound["streamSettings"]["realitySettings"] = {
                    "publicKey": p.pbk,
                    "fingerprint": p.fp,
                    "serverName": p.sni,
                    "shortId": "",
                    "spiderX": "/",
                }
            outbounds.append(outbound)

        outbounds.append({"tag": "direct", "protocol": "freedom"})
        outbounds.append({
            "tag": "block",
            "protocol": "blackhole",
            "settings": {"response": {"type": "http"}},
        })
        return {"outbounds": outbounds}

    # ── routing ──────────────────────────────

    @staticmethod
    def _extract_existing_rules(routing_data: dict) -> list[dict]:
        """Извлекает «ручные» правила из существующего routing.json."""
        rules = routing_data.get("routing", {}).get("rules", [])
        manual: list[dict] = []
        for rule in rules:
            if "balancerTag" in rule:
                continue
            otag = rule.get("outboundTag")
            if otag == "block":
                manual.append(rule)
            elif otag == "direct":
                if rule.get("domain") or rule.get("ip"):
                    manual.append(rule)
            elif otag is None:
                manual.append(rule)
        return manual

    def _build_forced_rules(self) -> list[dict]:
        result: list[dict] = []
        for proxy, rules in self.forced_rules.items():
            if rules.is_empty:
                continue
            entry: dict[str, Any] = {
                "inboundTag": ["redirect", "tproxy"],
                "outboundTag": proxy,
                "type": "field",
            }
            if rules.domains:
                entry["domain"] = rules.domains
            if rules.ips:
                entry["ip"] = rules.ips
            result.append(entry)
        return result

    def build_routing(self, existing_routing: dict | None = None) -> dict:
        existing_rules = (
            self._extract_existing_rules(existing_routing)
            if existing_routing
            else []
        )
        forced = self._build_forced_rules()

        # Порядок приоритета:
        #   1. block-правила
        #   2. принудительные правила
        #   3. правило балансировщика
        #   4. остальные ручные правила
        all_rules: list[dict] = []
        all_rules.extend(r for r in existing_rules if r.get("outboundTag") == "block")
        all_rules.extend(forced)
        all_rules.append({
            "inboundTag": ["redirect", "tproxy"],
            "balancerTag": "balancer",
            "type": "field",
        })
        all_rules.extend(r for r in existing_rules if r.get("outboundTag") != "block")

        return {
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": all_rules,
                "balancers": [{
                    "tag": "balancer",
                    "selector": self.proxy_tags,
                    "strategy": {"type": "leastPing"},
                    "fallbackTag": "direct",
                }],
            }
        }

    # ── observatory ──────────────────────────

    def build_observatory(
        self,
        probe_url: str = DEFAULT_PROBE_URL,
        probe_interval: str = DEFAULT_PROBE_INTERVAL,
    ) -> dict:
        return {
            "observatory": {
                "subjectSelector": self.proxy_tags,
                "probeUrl": probe_url,
                "probeInterval": probe_interval,
                "enableConcurrency": True,
            }
        }

    # ── запись на диск ───────────────────────

    def save_all(
        self,
        directory: str | Path,
        existing_routing: dict | None = None,
        existing_observatory: dict | None = None,
    ) -> tuple[Path, Path, Path]:
        base = Path(directory)

        # outbounds
        out_path = base / FILE_OUTBOUNDS
        write_json_with_header(out_path, self.build_outbounds())

        # routing
        rt_path = base / FILE_ROUTING
        write_json_with_header(
            rt_path,
            self.build_routing(existing_routing),
            "Настройка маршрутизации с балансировщиком и принудительными правилами",
        )

        # observatory — извлекаем настройки из существующего файла
        probe_url = DEFAULT_PROBE_URL
        probe_interval = DEFAULT_PROBE_INTERVAL
        if existing_observatory and "observatory" in existing_observatory:
            obs = existing_observatory["observatory"]
            probe_url = obs.get("probeUrl", probe_url)
            probe_interval = obs.get("probeInterval", probe_interval)

        obs_path = base / FILE_OBSERVATORY
        write_json_with_header(
            obs_path,
            self.build_observatory(probe_url, probe_interval),
            "Автоматический мониторинг доступности прокси",
        )

        return out_path, rt_path, obs_path


# ──────────────────────────────────────────────
# GUI
# ──────────────────────────────────────────────

class Application:
    """Главное окно приложения."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry(APP_GEOMETRY)

        # Состояние
        self.entries: list[tuple[str, str]] = []
        self.forced_rules: dict[str, ForcedRules] = {}

        # Пути к загруженным конфигам
        self._existing: dict[str, str | None] = {
            "outbounds": None,
            "routing": None,
            "observatory": None,
        }

        self._build_ui()

    # ── helpers для путей ────────────────────

    def _set_existing_path(self, key: str, path: str | None) -> None:
        self._existing[key] = path
        var = self._path_vars[key]
        var.set(path or "")

    def _get_existing_path(self, key: str) -> str | None:
        return self._existing[key]

    # ── построение интерфейса ────────────────

    def _build_ui(self) -> None:
        self._path_vars: dict[str, tk.StringVar] = {}
        self._build_load_panel()
        self._build_input_panel()
        self._build_forced_rules_panel()
        self._build_connections_list()
        self._build_action_bar()
        self._build_info_panel()
        self._update_proxy_combo()

    def _build_load_panel(self) -> None:
        frame = ttk.LabelFrame(self.root, text="Загрузить существующие файлы конфигурации", padding=10)
        frame.pack(fill="x", padx=10, pady=5)

        file_defs = [
            ("outbounds", f"{FILE_OUTBOUNDS}:"),
            ("routing", f"{FILE_ROUTING}:"),
            ("observatory", f"{FILE_OBSERVATORY}:"),
        ]
        loaders = {
            "outbounds": self._load_outbounds,
            "routing": self._load_routing,
            "observatory": self._load_observatory,
        }

        for key, label_text in file_defs:
            row = ttk.Frame(frame)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=label_text, width=22).pack(side="left")
            var = tk.StringVar()
            self._path_vars[key] = var
            ttk.Entry(row, textvariable=var, width=50).pack(side="left", padx=5)
            ttk.Button(row, text="Обзор…", command=lambda k=key: self._browse_file(k)).pack(side="left", padx=2)
            ttk.Button(row, text="Загрузить", command=loaders[key]).pack(side="left", padx=2)

        ttk.Button(frame, text="Загрузить все файлы из папки", command=self._load_all_from_folder).pack(pady=5)

    def _build_input_panel(self) -> None:
        frame = ttk.LabelFrame(self.root, text="Добавить новое подключение", padding=10)
        frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(frame, text="Tag:").grid(row=0, column=0, sticky="w", padx=5)
        self._tag_entry = ttk.Entry(frame, width=20)
        self._tag_entry.grid(row=0, column=1, sticky="w", padx=5)

        ttk.Label(frame, text="VLESS URL:").grid(row=1, column=0, sticky="w", padx=5)
        self._url_entry = ttk.Entry(frame, width=60)
        self._url_entry.grid(row=1, column=1, sticky="w", padx=5)

        btn = ttk.Frame(frame)
        btn.grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(btn, text="Добавить", command=self._add_entry).pack(side="left", padx=5)
        ttk.Button(btn, text="Очистить поля", command=self._clear_inputs).pack(side="left", padx=5)

    def _build_forced_rules_panel(self) -> None:
        frame = ttk.LabelFrame(self.root, text="Принудительные правила (обход балансировщика)", padding=10)
        frame.pack(fill="x", padx=10, pady=5)

        sel = ttk.Frame(frame)
        sel.pack(fill="x", pady=5)

        ttk.Label(sel, text="Прокси:").pack(side="left", padx=5)
        self._forced_proxy_var = tk.StringVar()
        self._forced_proxy_combo = ttk.Combobox(sel, textvariable=self._forced_proxy_var, width=15)
        self._forced_proxy_combo.pack(side="left", padx=5)

        ttk.Label(sel, text="Тип:").pack(side="left", padx=5)
        self._forced_type_var = tk.StringVar(value="domain")
        ttk.Combobox(sel, textvariable=self._forced_type_var, values=["domain", "ip"], width=10).pack(side="left", padx=5)

        ttk.Label(sel, text="Значение:").pack(side="left", padx=5)
        self._forced_value_entry = ttk.Entry(sel, width=30)
        self._forced_value_entry.pack(side="left", padx=5)
        ttk.Button(sel, text="Добавить правило", command=self._add_forced_rule).pack(side="left", padx=5)

        disp = ttk.Frame(frame)
        disp.pack(fill="x", pady=5)
        self._rules_text = tk.Text(disp, height=6, width=80)
        self._rules_text.pack(side="left", fill="x", expand=True)
        scrollbar = ttk.Scrollbar(disp, orient="vertical", command=self._rules_text.yview)
        scrollbar.pack(side="right", fill="y")
        self._rules_text.configure(yscrollcommand=scrollbar.set)

        ttk.Button(frame, text="Очистить все правила", command=self._clear_all_rules).pack(pady=5)

    def _build_connections_list(self) -> None:
        frame = ttk.LabelFrame(self.root, text="Добавленные подключения", padding=10)
        frame.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ("tag", "url")
        self._tree = ttk.Treeview(frame, columns=columns, show="headings", height=4)
        self._tree.heading("tag", text="Tag")
        self._tree.heading("url", text="VLESS URL (сокращённо)")
        self._tree.column("tag", width=100)
        self._tree.column("url", width=700)

        sb = ttk.Scrollbar(frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        ttk.Button(frame, text="Удалить выбранное", command=self._delete_entry).pack(pady=5)

    def _build_action_bar(self) -> None:
        frame = ttk.Frame(self.root)
        frame.pack(fill="x", padx=10, pady=10)
        ttk.Button(frame, text="Сгенерировать все файлы", command=self._generate_all, width=25).pack(side="left", padx=5)
        ttk.Button(frame, text="Очистить всё", command=self._clear_all).pack(side="left", padx=5)

    def _build_info_panel(self) -> None:
        frame = ttk.LabelFrame(self.root, text="Информация", padding=10)
        frame.pack(fill="x", padx=10, pady=5)
        info = (
            "Генерируемые файлы:\n"
            f"  {FILE_OUTBOUNDS}  — список прокси\n"
            f"  {FILE_ROUTING}   — балансировщик + принудительные правила\n"
            f"  {FILE_OBSERVATORY} — мониторинг доступности\n\n"
            "Принудительные правила имеют высший приоритет и направляют "
            "трафик на указанный прокси в обход балансировщика."
        )
        ttk.Label(frame, text=info, justify="left").pack()

    # ── загрузка файлов ──────────────────────

    def _browse_file(self, key: str) -> None:
        path = filedialog.askopenfilename(
            title="Выберите файл",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if path:
            self._set_existing_path(key, path)

    def _load_all_from_folder(self) -> None:
        folder = filedialog.askdirectory(title="Выберите папку с файлами конфигурации")
        if not folder:
            return

        mapping = {
            "outbounds": (FILE_OUTBOUNDS, self._load_outbounds),
            "routing": (FILE_ROUTING, self._load_routing),
            "observatory": (FILE_OBSERVATORY, self._load_observatory),
        }
        loaded = 0
        for key, (filename, loader) in mapping.items():
            fp = os.path.join(folder, filename)
            if os.path.exists(fp):
                self._set_existing_path(key, fp)
                if loader(silent=True):
                    loaded += 1

        if loaded:
            messagebox.showinfo("Успех", f"Загружено {loaded} файл(ов) из папки:\n{folder}")
        else:
            messagebox.showwarning("Предупреждение", "Файлы конфигурации не найдены в выбранной папке.")

    def _load_outbounds(self, silent: bool = False) -> bool:
        path = self._get_existing_path("outbounds")
        if not path or not os.path.exists(path):
            if not silent:
                messagebox.showerror("Ошибка", "Файл не выбран или не существует")
            return False

        try:
            data = read_json_with_comments(path)
        except Exception as exc:
            if not silent:
                messagebox.showerror("Ошибка", f"Не удалось прочитать файл:\n{exc}")
            return False

        if "outbounds" not in data:
            if not silent:
                messagebox.showerror("Ошибка", "Отсутствует поле 'outbounds'")
            return False

        self.entries.clear()
        for item in self._tree.get_children():
            self._tree.delete(item)

        count = 0
        for ob in data["outbounds"]:
            tag = ob.get("tag", "")
            if tag in STANDARD_TAGS:
                continue
            try:
                vnext = ob["settings"]["vnext"][0]
                uid = vnext["users"][0]["id"]
                addr = vnext["address"]
                port = vnext["port"]
                vless_url = f"vless://{uid}@{addr}:{port}"
            except (KeyError, IndexError):
                continue

            self.entries.append((tag, vless_url))
            short = vless_url[:60] + "…" if len(vless_url) > 60 else vless_url
            self._tree.insert("", "end", values=(tag, short))
            count += 1

        self._update_proxy_combo()
        if not silent:
            messagebox.showinfo("Успех", f"Загружено {count} прокси")
        return True

    def _load_routing(self, silent: bool = False) -> bool:
        path = self._get_existing_path("routing")
        if not path or not os.path.exists(path):
            if not silent:
                messagebox.showerror("Ошибка", "Файл не выбран или не существует")
            return False

        try:
            data = read_json_with_comments(path)
        except Exception as exc:
            if not silent:
                messagebox.showerror("Ошибка", f"Не удалось прочитать файл:\n{exc}")
            return False

        self.forced_rules.clear()
        for rule in data.get("routing", {}).get("rules", []):
            otag = rule.get("outboundTag")
            if not otag or otag in STANDARD_TAGS or otag == "balancer":
                continue
            fr = self.forced_rules.setdefault(otag, ForcedRules())
            for d in rule.get("domain", []):
                if d not in fr.domains:
                    fr.domains.append(d)
            for ip in rule.get("ip", []):
                if ip not in fr.ips:
                    fr.ips.append(ip)

        self._update_rules_display()
        if not silent:
            total = sum(r.total for r in self.forced_rules.values())
            messagebox.showinfo("Успех", f"Загружено {total} принудительных правил")
        return True

    def _load_observatory(self, silent: bool = False) -> bool:
        path = self._get_existing_path("observatory")
        if not path or not os.path.exists(path):
            if not silent:
                messagebox.showerror("Ошибка", "Файл не выбран или не существует")
            return False

        try:
            data = read_json_with_comments(path)
        except Exception as exc:
            if not silent:
                messagebox.showerror("Ошибка", f"Не удалось прочитать файл:\n{exc}")
            return False

        if "observatory" not in data:
            if not silent:
                messagebox.showerror("Ошибка", "Отсутствует поле 'observatory'")
            return False

        if not silent:
            subjects = data["observatory"].get("subjectSelector", [])
            messagebox.showinfo("Успех", f"Загружен observatory.json\nОтслеживаемые прокси: {', '.join(subjects)}")
        return True

    # ── управление записями ──────────────────

    def _update_proxy_combo(self) -> None:
        tags = [t for t, _ in self.entries]
        self._forced_proxy_combo["values"] = tags
        if tags:
            self._forced_proxy_combo.set(tags[0])

    def _add_entry(self) -> None:
        tag = self._tag_entry.get().strip()
        url = self._url_entry.get().strip()

        if not tag or not url:
            messagebox.showerror("Ошибка", "Заполните оба поля (Tag и VLESS URL)")
            return

        if not url.startswith("vless://"):
            messagebox.showerror("Ошибка", "URL должен начинаться с vless://")
            return

        # Валидируем URL сразу
        try:
            parse_vless_url(url)
        except Exception as exc:
            messagebox.showerror("Ошибка", f"Невалидный VLESS URL:\n{exc}")
            return

        if any(t == tag for t, _ in self.entries):
            messagebox.showerror("Ошибка", f"Тег '{tag}' уже существует")
            return

        short = url[:60] + "…" if len(url) > 60 else url
        self.entries.append((tag, url))
        self._tree.insert("", "end", values=(tag, short))
        self._update_proxy_combo()

        self._tag_entry.delete(0, tk.END)
        self._url_entry.delete(0, tk.END)

    def _delete_entry(self) -> None:
        sel = self._tree.selection()
        if not sel:
            messagebox.showwarning("Предупреждение", "Выберите запись для удаления")
            return

        tag = self._tree.item(sel[0])["values"][0]
        self.entries = [(t, u) for t, u in self.entries if t != tag]
        self._tree.delete(sel[0])
        self.forced_rules.pop(tag, None)
        self._update_rules_display()
        self._update_proxy_combo()

    def _clear_inputs(self) -> None:
        self._tag_entry.delete(0, tk.END)
        self._url_entry.delete(0, tk.END)

    def _clear_all(self) -> None:
        if not messagebox.askyesno("Подтверждение", "Очистить весь список?"):
            return
        self.entries.clear()
        self.forced_rules.clear()
        self._update_rules_display()
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._update_proxy_combo()
        for key in self._existing:
            self._set_existing_path(key, None)

    # ── принудительные правила ───────────────

    def _add_forced_rule(self) -> None:
        proxy = self._forced_proxy_var.get()
        rtype = self._forced_type_var.get()
        value = self._forced_value_entry.get().strip()

        if not proxy:
            messagebox.showerror("Ошибка", "Выберите прокси")
            return
        if not value:
            messagebox.showerror("Ошибка", "Введите значение")
            return
        if not any(t == proxy for t, _ in self.entries):
            messagebox.showerror("Ошибка", f"Прокси '{proxy}' не найден среди подключений")
            return

        fr = self.forced_rules.setdefault(proxy, ForcedRules())
        target = fr.domains if rtype == "domain" else fr.ips
        if value not in target:
            target.append(value)

        self._forced_value_entry.delete(0, tk.END)
        self._update_rules_display()

    def _update_rules_display(self) -> None:
        self._rules_text.delete("1.0", tk.END)
        if not self.forced_rules:
            self._rules_text.insert(tk.END, "Нет принудительных правил")
            return

        for proxy, rules in self.forced_rules.items():
            self._rules_text.insert(tk.END, f"\n=== {proxy} ===\n")
            if rules.domains:
                self._rules_text.insert(tk.END, "  Домены:\n")
                for d in rules.domains:
                    self._rules_text.insert(tk.END, f"    - {d}\n")
            if rules.ips:
                self._rules_text.insert(tk.END, "  IP-адреса:\n")
                for ip in rules.ips:
                    self._rules_text.insert(tk.END, f"    - {ip}\n")

    def _clear_all_rules(self) -> None:
        if messagebox.askyesno("Подтверждение", "Очистить все принудительные правила?"):
            self.forced_rules.clear()
            self._update_rules_display()

    # ── генерация ────────────────────────────

    def _generate_all(self) -> None:
        if not self.entries:
            messagebox.showwarning("Предупреждение", "Нет записей для генерации")
            return

        dir_path = filedialog.askdirectory(
            title="Выберите папку для сохранения (например, /opt/etc/xray/configs/)",
        )
        if not dir_path:
            return

        try:
            # Загружаем существующие данные для merge
            existing_routing = None
            rp = self._get_existing_path("routing")
            if rp and os.path.exists(rp):
                try:
                    existing_routing = read_json_with_comments(rp)
                except Exception:
                    pass

            existing_observatory = None
            op = self._get_existing_path("observatory")
            if op and os.path.exists(op):
                try:
                    existing_observatory = read_json_with_comments(op)
                except Exception:
                    pass

            gen = ConfigGenerator(self.entries, self.forced_rules)
            gen.save_all(dir_path, existing_routing, existing_observatory)

            # Отчёт
            report = self._build_report(dir_path)
            messagebox.showinfo("Успех", report)

        except Exception as exc:
            messagebox.showerror("Ошибка", f"Не удалось создать файлы:\n{exc}")

    def _build_report(self, dir_path: str) -> str:
        lines = [
            f"Файлы успешно созданы в папке:\n{dir_path}\n",
            f"  {FILE_OUTBOUNDS} — {len(self.entries)} прокси",
            f"  {FILE_ROUTING} — балансировщик + правила",
            f"  {FILE_OBSERVATORY} — мониторинг\n",
        ]

        total_forced = sum(r.total for r in self.forced_rules.values())
        if total_forced:
            lines.append(f"Принудительных правил: {total_forced}")
            for proxy, rules in self.forced_rules.items():
                if not rules.is_empty:
                    lines.append(f"  {proxy}: {len(rules.domains)} доменов, {len(rules.ips)} IP")
            lines.append("")

        lines.append("Прокси в балансировщике:")
        for i, (tag, _) in enumerate(self.entries, 1):
            extra = ""
            if tag in self.forced_rules and not self.forced_rules[tag].is_empty:
                extra = " (есть принудительные правила)"
            lines.append(f"  {i}. {tag}{extra}")

        # Проверка policy
        policy_path = os.path.join(dir_path, FILE_POLICY)
        if os.path.exists(policy_path):
            new_path = os.path.join(dir_path, FILE_POLICY_NEW)
            lines.append(f"\nВНИМАНИЕ: обнаружен {FILE_POLICY}")
            lines.append(f"Выполните: mv {policy_path} {new_path}")

        lines.append("\nПосле копирования файлов выполните:\n  xkeen -restart")
        return "\n".join(lines)


# ──────────────────────────────────────────────
# Точка входа
# ──────────────────────────────────────────────

def main() -> None:
    root = tk.Tk()
    Application(root)
    root.mainloop()


if __name__ == "__main__":
    main()
