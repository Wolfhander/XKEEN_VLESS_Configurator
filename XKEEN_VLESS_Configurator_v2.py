import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
from urllib.parse import urlparse, parse_qs, unquote
import os
import re

class VlessOutboundGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("VLESS Outbound Generator для Xkeen - Расширенная версия")
        self.root.geometry("900x700")
        
        # Список для хранения записей (tag, vless_url)
        self.entries = []
        
        # Словарь для хранения принудительных правил {прокси: {domains: [], ips: []}}
        self.forced_rules = {}
        
        # Путь к существующему routing.json (если есть)
        self.existing_routing_path = None
        
        self.create_widgets()
        
    def create_widgets(self):
        # Верхняя панель для ввода данных
        input_frame = ttk.LabelFrame(self.root, text="Добавить новое подключение", padding=10)
        input_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(input_frame, text="Tag:").grid(row=0, column=0, sticky="w", padx=5)
        self.tag_entry = ttk.Entry(input_frame, width=20)
        self.tag_entry.grid(row=0, column=1, sticky="w", padx=5)
        
        ttk.Label(input_frame, text="VLESS URL:").grid(row=1, column=0, sticky="w", padx=5)
        self.url_entry = ttk.Entry(input_frame, width=60)
        self.url_entry.grid(row=1, column=1, sticky="w", padx=5)
        
        # Кнопки
        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        ttk.Button(btn_frame, text="Добавить", command=self.add_entry).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Очистить поля", command=self.clear_entries).pack(side="left", padx=5)
        
        # Панель для загрузки существующего routing.json
        routing_frame = ttk.LabelFrame(self.root, text="Загрузить существующий routing.json (для сохранения ручных правил)", padding=10)
        routing_frame.pack(fill="x", padx=10, pady=5)
        
        self.routing_path_var = tk.StringVar()
        ttk.Entry(routing_frame, textvariable=self.routing_path_var, width=60).pack(side="left", padx=5)
        ttk.Button(routing_frame, text="Обзор...", command=self.load_routing_file).pack(side="left", padx=5)
        ttk.Button(routing_frame, text="Очистить", command=self.clear_routing_file).pack(side="left", padx=5)
        
        # Панель для принудительных правил
        forced_frame = ttk.LabelFrame(self.root, text="Принудительные правила (обход балансировщика)", padding=10)
        forced_frame.pack(fill="x", padx=10, pady=5)
        
        # Выбор прокси для правила
        rule_selector_frame = ttk.Frame(forced_frame)
        rule_selector_frame.pack(fill="x", pady=5)
        
        ttk.Label(rule_selector_frame, text="Прокси:").pack(side="left", padx=5)
        self.forced_proxy_var = tk.StringVar()
        self.forced_proxy_combo = ttk.Combobox(rule_selector_frame, textvariable=self.forced_proxy_var, width=15)
        self.forced_proxy_combo.pack(side="left", padx=5)
        self.forced_proxy_combo.bind('<<ComboboxSelected>>', self.on_proxy_selected)
        
        ttk.Label(rule_selector_frame, text="Тип:").pack(side="left", padx=5)
        self.forced_type_var = tk.StringVar(value="domain")
        self.forced_type_combo = ttk.Combobox(rule_selector_frame, textvariable=self.forced_type_var, values=["domain", "ip"], width=10)
        self.forced_type_combo.pack(side="left", padx=5)
        
        ttk.Label(rule_selector_frame, text="Значение:").pack(side="left", padx=5)
        self.forced_value_entry = ttk.Entry(rule_selector_frame, width=30)
        self.forced_value_entry.pack(side="left", padx=5)
        
        ttk.Button(rule_selector_frame, text="Добавить правило", command=self.add_forced_rule).pack(side="left", padx=5)
        
        # Текстовое поле для отображения правил
        rules_display_frame = ttk.Frame(forced_frame)
        rules_display_frame.pack(fill="x", pady=5)
        
        self.rules_text = tk.Text(rules_display_frame, height=6, width=80)
        self.rules_text.pack(side="left", fill="x", expand=True)
        
        scrollbar = ttk.Scrollbar(rules_display_frame, orient="vertical", command=self.rules_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.rules_text.configure(yscrollcommand=scrollbar.set)
        
        # Кнопка очистки правил
        ttk.Button(forced_frame, text="Очистить все правила", command=self.clear_all_rules).pack(pady=5)
        
        # Список добавленных записей
        list_frame = ttk.LabelFrame(self.root, text="Добавленные подключения", padding=10)
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Создаем Treeview для отображения записей
        columns = ("tag", "url")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=4)
        
        self.tree.heading("tag", text="Tag")
        self.tree.heading("url", text="VLESS URL (сокращенно)")
        self.tree.column("tag", width=100)
        self.tree.column("url", width=650)
        
        # Добавляем скроллбар
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Кнопка удаления выбранной записи
        ttk.Button(list_frame, text="Удалить выбранное", command=self.delete_entry).pack(pady=5)
        
        # Нижняя панель с кнопками действий
        action_frame = ttk.Frame(self.root)
        action_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(action_frame, text="Сгенерировать все файлы", command=self.generate_all_files, width=20).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Очистить все", command=self.clear_all).pack(side="left", padx=5)
        
        # Информационная панель
        info_frame = ttk.LabelFrame(self.root, text="Информация", padding=10)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        info_text = "Будут сгенерированы/обновлены файлы:\n"
        info_text += "• 04_outbounds.json - список прокси\n"
        info_text += "• 05_routing.json - балансировщик + ваши ручные правила + принудительные правила\n"
        info_text += "• 06_observatory.json - мониторинг доступности\n\n"
        info_text += "Принудительные правила имеют высший приоритет и отправляют трафик на указанный прокси в обход балансировщика."
        
        ttk.Label(info_frame, text=info_text, justify="left").pack()
        
        # Обновляем список прокси в комбобоксе
        self.update_proxy_combo()
        
    def update_proxy_combo(self):
        """Обновляет список доступных прокси в комбобоксе"""
        proxy_tags = [tag for tag, _ in self.entries]
        self.forced_proxy_combo['values'] = proxy_tags
        if proxy_tags:
            self.forced_proxy_combo.set(proxy_tags[0])
    
    def on_proxy_selected(self, event):
        """Обработчик выбора прокси"""
        pass
    
    def add_forced_rule(self):
        """Добавляет принудительное правило"""
        proxy = self.forced_proxy_var.get()
        rule_type = self.forced_type_var.get()
        value = self.forced_value_entry.get().strip()
        
        if not proxy:
            messagebox.showerror("Ошибка", "Выберите прокси")
            return
        
        if not value:
            messagebox.showerror("Ошибка", "Введите значение")
            return
        
        # Проверяем, существует ли такой прокси
        proxy_exists = False
        for tag, _ in self.entries:
            if tag == proxy:
                proxy_exists = True
                break
        
        if not proxy_exists:
            messagebox.showerror("Ошибка", f"Прокси '{proxy}' не найден")
            return
        
        # Инициализируем словарь для прокси если его нет
        if proxy not in self.forced_rules:
            self.forced_rules[proxy] = {"domains": [], "ips": []}
        
        # Добавляем правило
        if rule_type == "domain":
            if value not in self.forced_rules[proxy]["domains"]:
                self.forced_rules[proxy]["domains"].append(value)
        else:  # ip
            if value not in self.forced_rules[proxy]["ips"]:
                self.forced_rules[proxy]["ips"].append(value)
        
        # Очищаем поле ввода
        self.forced_value_entry.delete(0, tk.END)
        
        # Обновляем отображение правил
        self.update_rules_display()
    
    def update_rules_display(self):
        """Обновляет текстовое поле с правилами"""
        self.rules_text.delete(1.0, tk.END)
        
        if not self.forced_rules:
            self.rules_text.insert(tk.END, "Нет принудительных правил")
            return
        
        for proxy, rules in self.forced_rules.items():
            self.rules_text.insert(tk.END, f"\n=== {proxy} ===\n")
            
            if rules["domains"]:
                self.rules_text.insert(tk.END, "  Домены:\n")
                for domain in rules["domains"]:
                    self.rules_text.insert(tk.END, f"    • {domain}\n")
            
            if rules["ips"]:
                self.rules_text.insert(tk.END, "  IP-адреса:\n")
                for ip in rules["ips"]:
                    self.rules_text.insert(tk.END, f"    • {ip}\n")
    
    def clear_all_rules(self):
        """Очищает все принудительные правила"""
        if messagebox.askyesno("Подтверждение", "Очистить все принудительные правила?"):
            self.forced_rules.clear()
            self.update_rules_display()
    
    def load_routing_file(self):
        """Загружает существующий файл routing.json"""
        file_path = filedialog.askopenfilename(
            title="Выберите существующий 05_routing.json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            self.routing_path_var.set(file_path)
            self.existing_routing_path = file_path
            
            # Пытаемся извлечь существующие правила
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = ''
                    for line in f:
                        if not line.strip().startswith('//'):
                            content += line
                    existing_routing = json.loads(content)
                    
                    # Извлекаем правила с конкретными outboundTag
                    if 'routing' in existing_routing and 'rules' in existing_routing['routing']:
                        for rule in existing_routing['routing']['rules']:
                            if 'outboundTag' in rule and rule['outboundTag'] not in ['direct', 'block', 'balancer']:
                                proxy = rule['outboundTag']
                                if proxy not in self.forced_rules:
                                    self.forced_rules[proxy] = {"domains": [], "ips": []}
                                
                                if 'domain' in rule:
                                    for domain in rule['domain']:
                                        if domain not in self.forced_rules[proxy]["domains"]:
                                            self.forced_rules[proxy]["domains"].append(domain)
                                
                                if 'ip' in rule:
                                    for ip in rule['ip']:
                                        if ip not in self.forced_rules[proxy]["ips"]:
                                            self.forced_rules[proxy]["ips"].append(ip)
                        
                        self.update_rules_display()
                        messagebox.showinfo("Успех", f"Загружен файл:\n{file_path}\n\nИзвлечено {sum(len(r['domains']) + len(r['ips']) for r in self.forced_rules.values())} принудительных правил")
                    else:
                        messagebox.showinfo("Успех", f"Загружен файл:\n{file_path}\n\nРучные правила будут сохранены")
            except Exception as e:
                messagebox.showwarning("Предупреждение", f"Не удалось извлечь правила: {str(e)}")
    
    def clear_routing_file(self):
        """Очищает путь к загруженному routing.json"""
        self.routing_path_var.set("")
        self.existing_routing_path = None
    
    def add_entry(self):
        tag = self.tag_entry.get().strip()
        vless_url = self.url_entry.get().strip()
        
        if not tag or not vless_url:
            messagebox.showerror("Ошибка", "Пожалуйста, заполните оба поля")
            return
        
        if not vless_url.startswith("vless://"):
            messagebox.showerror("Ошибка", "Неверный формат URL. Должен начинаться с vless://")
            return
        
        # Проверяем уникальность тега
        for existing_tag, _ in self.entries:
            if existing_tag == tag:
                messagebox.showerror("Ошибка", f"Тег '{tag}' уже существует")
                return
        
        # Сокращаем URL для отображения
        short_url = vless_url[:60] + "..." if len(vless_url) > 60 else vless_url
        
        self.entries.append((tag, vless_url))
        self.tree.insert("", "end", values=(tag, short_url))
        
        # Обновляем список прокси в комбобоксе
        self.update_proxy_combo()
        
        # Очищаем поля ввода
        self.tag_entry.delete(0, tk.END)
        self.url_entry.delete(0, tk.END)
        
    def delete_entry(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Предупреждение", "Пожалуйста, выберите запись для удаления")
            return
        
        item = self.tree.item(selected[0])
        tag = item['values'][0]
        
        # Удаляем из списка
        for i, (existing_tag, _) in enumerate(self.entries):
            if existing_tag == tag:
                del self.entries[i]
                break
        
        # Удаляем из дерева
        self.tree.delete(selected[0])
        
        # Удаляем принудительные правила для этого прокси
        if tag in self.forced_rules:
            del self.forced_rules[tag]
            self.update_rules_display()
        
        # Обновляем список прокси в комбобоксе
        self.update_proxy_combo()
        
    def clear_entries(self):
        self.tag_entry.delete(0, tk.END)
        self.url_entry.delete(0, tk.END)
        
    def clear_all(self):
        if messagebox.askyesno("Подтверждение", "Очистить весь список?"):
            self.entries.clear()
            self.forced_rules.clear()
            self.update_rules_display()
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.update_proxy_combo()
    
    def parse_vless_url(self, url):
        """Парсит VLESS URL и возвращает словарь с параметрами"""
        try:
            # Удаляем префикс vless://
            url_without_protocol = url[8:]
            
            # Сначала отделяем фрагмент (#...) если есть
            if '#' in url_without_protocol:
                url_without_protocol, _ = url_without_protocol.split('#', 1)
            
            # Теперь разбираем основную часть
            if '?' in url_without_protocol:
                main_part, query_part = url_without_protocol.split('?', 1)
                # Разбираем параметры запроса
                query_params = {}
                for param in query_part.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        # Декодируем URL-кодированные значения
                        query_params[key] = unquote(value)
                    else:
                        query_params[param] = ''
            else:
                main_part = url_without_protocol
                query_params = {}
            
            # Парсим основную часть (uuid@host:port)
            if '@' in main_part:
                user_info, host_port = main_part.split('@', 1)
                uuid = user_info
            else:
                uuid = main_part
                host_port = ''
            
            # Парсим host и port
            if ':' in host_port:
                host, port_str = host_port.split(':', 1)
                # Очищаем порт от возможных нечисловых символов
                port_str = re.sub(r'[^0-9]', '', port_str)
                try:
                    port = int(port_str) if port_str else 443
                except ValueError:
                    port = 443
            else:
                host = host_port
                port = 443
            
            # Извлекаем параметры из query
            security = query_params.get('security', 'reality')
            encryption = query_params.get('encryption', 'none')
            pbk = query_params.get('pbk', '')
            fp = query_params.get('fp', 'chrome')
            flow = query_params.get('flow', '')
            sni = query_params.get('sni', host)
            type_param = query_params.get('type', 'tcp')
            
            # Очищаем параметры от возможных нежелательных символов
            network = type_param.strip()
            # Убеждаемся, что network содержит только допустимое значение
            if network not in ['tcp', 'kcp', 'ws', 'http', 'quic', 'grpc']:
                network = 'tcp'
            
            # Если flow пустой, устанавливаем значение по умолчанию
            if not flow:
                flow = 'xtls-rprx-vision'
            
            # Если pbk пустой, используем публичный ключ по умолчанию из примера
            if not pbk:
                pbk = 'F8tqvcuJUSVbxv_i9ZsVOef3EPwULzzDqgvmj3vWNlA'
            
            # Очищаем host и sni от возможных проблемных символов
            host = host.strip()
            sni = sni.strip()
            
            return {
                'uuid': uuid,
                'host': host,
                'port': port,
                'security': security,
                'encryption': encryption,
                'pbk': pbk,
                'fp': fp,
                'flow': flow,
                'sni': sni,
                'network': network
            }
        except Exception as e:
            raise Exception(f"Ошибка парсинга URL: {str(e)}")
    
    def generate_outbounds_json(self, base_dir):
        """Генерирует 04_outbounds.json"""
        outbounds = []
        
        for tag, vless_url in self.entries:
            try:
                params = self.parse_vless_url(vless_url)
                
                # Создаем базовую структуру outbound
                outbound = {
                    "tag": tag,
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": params['host'],
                                "port": params['port'],
                                "users": [
                                    {
                                        "id": params['uuid'],
                                        "flow": params['flow'],
                                        "encryption": params['encryption'],
                                        "level": 0
                                    }
                                ]
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": params['network'],
                        "security": params['security'],
                        "realitySettings": {
                            "publicKey": params['pbk'],
                            "fingerprint": params['fp'],
                            "serverName": params['sni'],
                            "shortId": "",
                            "spiderX": "/"
                        }
                    }
                }
                
                outbounds.append(outbound)
                
            except Exception as e:
                raise Exception(f"Ошибка при обработке URL для тега '{tag}': {str(e)}")
        
        outbounds.append({
            "tag": "direct",
            "protocol": "freedom"
        })
        
        outbounds.append({
            "tag": "block",
            "protocol": "blackhole",
            "settings": {
                "response": {
                    "type": "http"
                }
            }
        })
        
        result = {"outbounds": outbounds}
        
        file_path = os.path.join(base_dir, "04_outbounds.json")
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        return file_path
    
    def extract_rules_from_existing(self, existing_routing):
        """Извлекает ручные правила из существующего routing.json"""
        manual_rules = []
        
        if not existing_routing or 'routing' not in existing_routing or 'rules' not in existing_routing['routing']:
            return manual_rules
        
        for rule in existing_routing['routing']['rules']:
            # Пропускаем правила с balancerTag
            if 'balancerTag' in rule:
                continue
            
            # Пропускаем правила с outboundTag, которые мы будем генерировать отдельно
            if 'outboundTag' in rule and rule['outboundTag'] in ['direct', 'block']:
                # Сохраняем direct и block правила, но с проверкой
                if rule['outboundTag'] == 'direct' and not rule.get('domain') and not rule.get('ip'):
                    # Это правило fallback - пропускаем
                    continue
                manual_rules.append(rule)
            elif 'outboundTag' not in rule:
                # Правила без outboundTag (например, с balancerTag мы уже пропустили)
                manual_rules.append(rule)
        
        return manual_rules
    
    def generate_forced_rules(self):
        """Генерирует правила для принудительной маршрутизации"""
        forced_rules = []
        
        for proxy, rules in self.forced_rules.items():
            rule = {
                "inboundTag": ["redirect", "tproxy"],
                "outboundTag": proxy,
                "type": "field"
            }
            
            if rules["domains"]:
                rule["domain"] = rules["domains"]
            
            if rules["ips"]:
                rule["ip"] = rules["ips"]
            
            # Добавляем правило только если есть хоть что-то
            if rules["domains"] or rules["ips"]:
                forced_rules.append(rule)
        
        return forced_rules
    
    def generate_routing_json(self, base_dir):
        """Генерирует 05_routing.json с балансировщиком, ручными и принудительными правилами"""
        
        proxy_tags = [tag for tag, _ in self.entries]
        
        # Загружаем существующий routing.json если есть
        existing_rules = []
        if self.existing_routing_path and os.path.exists(self.existing_routing_path):
            try:
                with open(self.existing_routing_path, 'r', encoding='utf-8') as f:
                    # Удаляем комментарии (строки, начинающиеся с //)
                    content = ''
                    for line in f:
                        if not line.strip().startswith('//'):
                            content += line
                    existing_routing = json.loads(content)
                    existing_rules = self.extract_rules_from_existing(existing_routing)
            except Exception as e:
                messagebox.showwarning("Предупреждение", 
                    f"Не удалось загрузить существующий routing.json: {str(e)}\n\nБудет создан новый файл.")
        
        # Генерируем принудительные правила
        forced_rules = self.generate_forced_rules()
        
        # Создаем новое правило для балансировщика
        balancer_rule = {
            "inboundTag": ["redirect", "tproxy"],
            "balancerTag": "balancer",
            "type": "field"
        }
        
        # Собираем все правила в правильном порядке приоритета
        all_rules = []
        
        # 1. Сначала правила блокировки (высший приоритет)
        for rule in existing_rules:
            if rule.get('outboundTag') == 'block':
                all_rules.append(rule)
        
        # 2. Затем принудительные правила (обход балансировщика)
        all_rules.extend(forced_rules)
        
        # 3. Затем правило балансировщика
        all_rules.append(balancer_rule)
        
        # 4. Затем все остальные ручные правила
        for rule in existing_rules:
            if rule.get('outboundTag') != 'block':
                all_rules.append(rule)
        
        routing = {
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": all_rules,
                "balancers": [
                    {
                        "tag": "balancer",
                        "selector": proxy_tags,
                        "strategy": {
                            "type": "leastPing"
                        },
                        "fallbackTag": "direct"
                    }
                ]
            }
        }
        
        file_path = os.path.join(base_dir, "05_routing.json")
        with open(file_path, 'w', encoding='utf-8') as f:
            # Записываем с комментарием в начале
            f.write('// Настройка маршрутизации с балансировщиком и принудительными правилами\n')
            json.dump(routing, f, indent=2, ensure_ascii=False)
        
        return file_path
    
    def generate_observatory_json(self, base_dir):
        """Генерирует 06_observatory.json для мониторинга прокси"""
        
        proxy_tags = [tag for tag, _ in self.entries]
        
        observatory = {
            "observatory": {
                "subjectSelector": proxy_tags,
                "probeUrl": "https://www.gstatic.com/generate_204",
                "probeInterval": "60s",
                "enableConcurrency": True
            }
        }
        
        file_path = os.path.join(base_dir, "06_observatory.json")
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write('// Автоматический мониторинг доступности прокси\n')
            json.dump(observatory, f, indent=2, ensure_ascii=False)
        
        return file_path
    
    def check_policy_file(self, base_dir):
        """Проверяет наличие policy.json и дает рекомендации"""
        policy_path = os.path.join(base_dir, "06_policy.json")
        if os.path.exists(policy_path):
            return True, policy_path
        return False, None
    
    def generate_all_files(self):
        if not self.entries:
            messagebox.showwarning("Предупреждение", "Нет записей для генерации")
            return
        
        dir_path = filedialog.askdirectory(title="Выберите папку для сохранения файлов (например, /opt/etc/xray/configs/)")
        
        if not dir_path:
            return
        
        try:
            outbounds_path = self.generate_outbounds_json(dir_path)
            routing_path = self.generate_routing_json(dir_path)
            observatory_path = self.generate_observatory_json(dir_path)
            
            # Проверяем наличие policy.json
            has_policy, policy_path = self.check_policy_file(dir_path)
            
            report = f"✅ Файлы успешно созданы в папке:\n{dir_path}\n\n"
            report += f"📄 04_outbounds.json - {len(self.entries)} прокси\n"
            report += f"📄 05_routing.json - балансировщик + принудительные правила\n"
            report += f"📄 06_observatory.json - мониторинг каждые 60с\n\n"
            
            # Подсчитываем принудительные правила
            total_forced = sum(len(rules['domains']) + len(rules['ips']) for rules in self.forced_rules.values())
            if total_forced > 0:
                report += f"🔒 Принудительные правила ({total_forced} шт.):\n"
                for proxy, rules in self.forced_rules.items():
                    if rules['domains'] or rules['ips']:
                        report += f"  • {proxy}: {len(rules['domains'])} доменов, {len(rules['ips'])} IP\n"
                report += "\n"
            
            report += "Список прокси в балансировщике:\n"
            for i, (tag, _) in enumerate(self.entries, 1):
                forced = " (есть принудительные правила)" if tag in self.forced_rules and (self.forced_rules[tag]['domains'] or self.forced_rules[tag]['ips']) else ""
                report += f"  {i}. {tag}{forced}\n"
            
            if has_policy:
                report += f"\n⚠️  ВНИМАНИЕ: Обнаружен файл 06_policy.json\n"
                report += f"   Выполните команду:\n"
                report += f"   mv {policy_path} {os.path.join(dir_path, '10_policy.json')}\n"
            
            if self.existing_routing_path:
                report += f"\n✅ Ручные правила из {os.path.basename(self.existing_routing_path)} сохранены"
            
            # Показываем команду для перезапуска
            report += f"\n\n🔄 После копирования файлов выполните:\n   xkeen -restart"
            
            messagebox.showinfo("Успех", report)
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось создать файлы: {str(e)}")

def main():
    root = tk.Tk()
    app = VlessOutboundGenerator(root)
    root.mainloop()

if __name__ == "__main__":
    main()