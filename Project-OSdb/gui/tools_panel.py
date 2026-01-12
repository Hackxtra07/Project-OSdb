"""
Tools Panel - Security and Utility Tools Collection
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import hashlib
import subprocess
import threading
import json
import logging
import os

logger = logging.getLogger(__name__)

class ToolsPanel:
    """Collection of security and OSINT tools"""
    
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        
        self.main_frame = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_light'])
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.build_ui()
        
    def build_ui(self):
        # Tools Selection Sidebar
        paned = tk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        sidebar = tk.Frame(paned, bg=self.app.theme_manager.colors['bg_medium'], width=200)
        paned.add(sidebar)
        
        self.content_area = tk.Frame(paned, bg=self.app.theme_manager.colors['bg_light'])
        paned.add(self.content_area)
        
        # Tools List
        tools = [
            ("🔐 Password Gen", self.show_password_gen),
            ("🔢 Hash Calc", self.show_hasher),
            ("🌐 Network Tools", self.show_network),
            ("🕵️ OSINT Lookup", self.show_osint),
            ("🛡️ Encryption", self.show_crypto)
        ]
        
        tk.Label(sidebar, text="Tools", font=("Arial", 14, "bold"), bg=sidebar['bg'], fg="white").pack(pady=10)
        
        for text, cmd in tools:
            tk.Button(sidebar, text=text, command=cmd, anchor='w', padx=20, pady=10,
                     bg=sidebar['bg'], fg="white", relief='flat').pack(fill=tk.X)
                     
        # Default view
        self.show_password_gen()
        
    def clear_content(self):
        for widget in self.content_area.winfo_children():
            widget.destroy()
            
    def show_password_gen(self):
        self.clear_content()
        frame = self.content_area
        
        tk.Label(frame, text="Password Generator", font=("Arial", 16, "bold")).pack(pady=20)
        
        res_var = tk.StringVar()
        entry = tk.Entry(frame, textvariable=res_var, font=("Courier", 14), width=30)
        entry.pack(pady=10)
        
        def gen():
            res_var.set(self.app.encryption.generate_secure_password())
            
        tk.Button(frame, text="Generate", command=gen, bg="#4CAF50", fg="white").pack(pady=10)

    def show_hasher(self):
        self.clear_content()
        frame = self.content_area
        
        tk.Label(frame, text="Hash Calculator", font=("Arial", 16, "bold")).pack(pady=20)
        
        tk.Label(frame, text="Input Text:").pack()
        txt = tk.Text(frame, height=5, width=50)
        txt.pack(pady=5)
        
        res_frame = tk.Frame(frame)
        res_frame.pack(fill=tk.X, padx=20)
        
        results = {}
        for algo in ['MD5', 'SHA1', 'SHA256']:
            tk.Label(res_frame, text=f"{algo}:").pack(anchor='w')
            var = tk.StringVar()
            tk.Entry(res_frame, textvariable=var, width=60, state='readonly').pack(anchor='w', pady=2)
            results[algo] = var
            
        def calc():
            data = txt.get("1.0", tk.END).strip().encode()
            if not data: return
            results['MD5'].set(hashlib.md5(data).hexdigest())
            results['SHA1'].set(hashlib.sha1(data).hexdigest())
            results['SHA256'].set(hashlib.sha256(data).hexdigest())
            
        tk.Button(frame, text="Calculate Hashes", command=calc).pack(pady=20)

    def show_network(self):
        self.clear_content()
        frame = self.content_area
        
        tk.Label(frame, text="Network Tools", font=("Arial", 16, "bold")).pack(pady=20)
        
        input_var = tk.StringVar()
        tk.Entry(frame, textvariable=input_var, width=30, font=("Arial", 12)).pack(pady=5)
        
        out = tk.Text(frame, height=15, width=60, bg='black', fg='#00ff00', font=("Courier", 10))
        out.pack(pady=10)
        
        def run_ping():
            target = input_var.get()
            if not target: return
            out.delete("1.0", tk.END)
            out.insert("1.0", f"Pinging {target}...\n")
            
            def _ping():
                try:
                    res = subprocess.check_output(['ping', '-c', '4', target], stderr=subprocess.STDOUT)
                    out.insert(tk.END, res.decode())
                except Exception as e:
                    out.insert(tk.END, f"Error: {e}")
            threading.Thread(target=_ping).start()
            
        tk.Button(frame, text="Ping", command=run_ping).pack()

    def show_osint(self):
        self.clear_content()
        frame = self.content_area
        
        tk.Label(frame, text="OSINT Lookup", font=("Arial", 16, "bold")).pack(pady=20)
        
        # Lookup type
        tk.Label(frame, text="Lookup Type:").pack()
        lookup_type_var = tk.StringVar(value="ip")
        type_frame = tk.Frame(frame)
        type_frame.pack(pady=5)
        
        ttk.Radiobutton(type_frame, text="IP Address", variable=lookup_type_var, value="ip").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(type_frame, text="Domain", variable=lookup_type_var, value="domain").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(type_frame, text="Hash", variable=lookup_type_var, value="hash").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(type_frame, text="Email", variable=lookup_type_var, value="email").pack(side=tk.LEFT, padx=5)
        
        tk.Label(frame, text="Target (IP/Domain/Hash/Email):").pack()
        target_var = tk.StringVar()
        tk.Entry(frame, textvariable=target_var, width=40, font=("Arial", 11)).pack(pady=5)
        
        out = tk.Text(frame, height=15, width=80, bg='#1e1e1e', fg='#00ff00', font=("Courier", 10))
        out.pack(pady=10)
        
        def lookup():
            target = target_var.get().strip()
            lookup_type = lookup_type_var.get()
            
            if not target:
                out.delete("1.0", tk.END)
                out.insert("1.0", "Error: Please enter a target")
                return
            
            out.delete("1.0", tk.END)
            out.insert("1.0", f"🔍 Running OSINT lookup for {target}...\n\n")
            out.update()
            
            try:
                # Get API manager
                if hasattr(self.app, 'api_manager'):
                    api_manager = self.app.api_manager
                    
                    results = []
                    
                    # VirusTotal lookup
                    if lookup_type in ['ip', 'domain', 'hash']:
                        out.insert(tk.END, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                        out.insert(tk.END, "🔴 VirusTotal\n")
                        out.insert(tk.END, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                        out.update()
                        
                        vt_result = api_manager.virustotal_lookup(target, lookup_type)
                        out.insert(tk.END, f"Status: {vt_result.status}\n")
                        if vt_result.data:
                            out.insert(tk.END, f"Response: {json.dumps(vt_result.data, indent=2)[:500]}...\n")
                        if vt_result.error:
                            out.insert(tk.END, f"Error: {vt_result.error}\n")
                        out.insert(tk.END, "\n")
                        results.append(vt_result)
                    
                    # Shodan lookup
                    if lookup_type == 'ip':
                        out.insert(tk.END, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                        out.insert(tk.END, "🟠 Shodan\n")
                        out.insert(tk.END, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                        out.update()
                        
                        shodan_result = api_manager.shodan_lookup(target)
                        out.insert(tk.END, f"Status: {shodan_result.status}\n")
                        if shodan_result.data:
                            out.insert(tk.END, f"Response: {json.dumps(shodan_result.data, indent=2)[:500]}...\n")
                        if shodan_result.error:
                            out.insert(tk.END, f"Error: {shodan_result.error}\n")
                        out.insert(tk.END, "\n")
                        results.append(shodan_result)
                    
                    # Hunter.io email verify
                    if lookup_type == 'email':
                        out.insert(tk.END, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                        out.insert(tk.END, "🟡 Hunter.io\n")
                        out.insert(tk.END, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                        out.update()
                        
                        hunter_result = api_manager.hunter_email_verify(target)
                        out.insert(tk.END, f"Status: {hunter_result.status}\n")
                        if hunter_result.data:
                            out.insert(tk.END, f"Response: {json.dumps(hunter_result.data, indent=2)[:500]}...\n")
                        if hunter_result.error:
                            out.insert(tk.END, f"Error: {hunter_result.error}\n")
                        out.insert(tk.END, "\n")
                        results.append(hunter_result)
                    
                    # WHOIS lookup
                    if lookup_type == 'domain':
                        out.insert(tk.END, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                        out.insert(tk.END, "🟢 WHOIS\n")
                        out.insert(tk.END, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                        out.update()
                        
                        whois_result = api_manager.whois_lookup(target)
                        out.insert(tk.END, f"Status: {whois_result.status}\n")
                        if whois_result.data:
                            out.insert(tk.END, f"Response: {str(whois_result.data)[:500]}...\n")
                        if whois_result.error:
                            out.insert(tk.END, f"Error: {whois_result.error}\n")
                        out.insert(tk.END, "\n")
                        results.append(whois_result)
                    
                    # GeoIP lookup
                    if lookup_type == 'ip':
                        out.insert(tk.END, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                        out.insert(tk.END, "🟣 GeoIP\n")
                        out.insert(tk.END, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                        out.update()
                        
                        geo_result = api_manager.geo_ip(target)
                        out.insert(tk.END, f"Status: {geo_result.status}\n")
                        if geo_result.data:
                            out.insert(tk.END, f"Response: {json.dumps(geo_result.data, indent=2)[:500]}...\n")
                        if geo_result.error:
                            out.insert(tk.END, f"Error: {geo_result.error}\n")
                        out.insert(tk.END, "\n")
                        results.append(geo_result)
                    
                    # Save results to database
                    if results and hasattr(self.app, 'db'):
                        query = """INSERT INTO api_results 
                                 (user_id, api_name, query, result, status, timestamp)
                                 VALUES (?, ?, ?, ?, ?, datetime('now'))"""
                        for result in results:
                            try:
                                self.app.db.execute_query(query, (
                                    self.app.current_user_id,
                                    result.source,
                                    target,
                                    json.dumps(result.data) if result.data else None,
                                    result.status
                                ))
                            except Exception as e:
                                logger.error(f"Failed to save result: {e}")
                    
                    out.insert(tk.END, "✓ Lookup complete")
                else:
                    out.insert(tk.END, "Error: API manager not available\n")
                    out.insert(tk.END, "Please configure API keys in Settings")
            
            except Exception as e:
                logger.error(f"OSINT lookup failed: {e}")
                out.insert(tk.END, f"❌ Lookup failed: {e}")
        
        tk.Button(frame, text="Run Lookup", command=lookup, bg="#2196F3", fg="white", font=("Arial", 11, "bold")).pack(pady=10)

    def show_crypto(self):
        self.clear_content()
        frame = self.content_area
        tk.Label(frame, text="File Encryption/Decryption", font=("Arial", 16, "bold")).pack(pady=20)
        
        # Algorithm selection
        tk.Label(frame, text="Algorithm:").pack()
        algo_var = tk.StringVar(value="aes_gcm")
        algo_frame = tk.Frame(frame)
        algo_frame.pack(pady=5)
        
        ttk.Radiobutton(algo_frame, text="AES-256-GCM", variable=algo_var, value="aes_gcm").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(algo_frame, text="ChaCha20", variable=algo_var, value="chacha20").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(algo_frame, text="Fernet", variable=algo_var, value="fernet").pack(side=tk.LEFT, padx=5)
        
        # File selection
        tk.Label(frame, text="Select File:").pack()
        file_path_var = tk.StringVar()
        file_frame = tk.Frame(frame)
        file_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Entry(file_frame, textvariable=file_path_var, state='readonly', width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        def select_file():
            from tkinter import filedialog
            filename = filedialog.askopenfilename()
            if filename:
                file_path_var.set(filename)
        
        tk.Button(file_frame, text="Browse", command=select_file).pack(side=tk.LEFT, padx=5)
        
        # Password
        tk.Label(frame, text="Password:").pack(pady=(10, 5))
        password_var = tk.StringVar()
        password_entry = tk.Entry(frame, textvariable=password_var, show='*', width=40)
        password_entry.pack()
        
        # Show password
        show_pass_var = tk.BooleanVar()
        def toggle_show():
            password_entry.config(show='' if show_pass_var.get() else '*')
        tk.Checkbutton(frame, text="Show Password", variable=show_pass_var, command=toggle_show).pack()
        
        # Output
        tk.Label(frame, text="Status:").pack(pady=(10, 5))
        out = tk.Text(frame, height=8, width=70, bg='white', fg='black')
        out.pack(pady=5)
        out.config(state='disabled')
        
        def encrypt_file():
            try:
                file_path = file_path_var.get()
                password = password_var.get()
                
                if not file_path or not password:
                    out.config(state='normal')
                    out.delete('1.0', tk.END)
                    out.insert('1.0', "Error: Please select a file and enter a password")
                    out.config(state='disabled')
                    return
                
                out.config(state='normal')
                out.delete('1.0', tk.END)
                out.insert('1.0', f"Encrypting {file_path}...\n")
                out.update()
                
                # Generate key from password
                key, salt = self.app.encryption.generate_key(password)
                
                # Encrypt file
                output_path = file_path + ".encrypted"
                success = self.app.encryption.encrypt_file(file_path, output_path, key, algo_var.get())
                
                if success:
                    # Save salt for later decryption
                    salt_file = output_path + ".salt"
                    with open(salt_file, 'wb') as f:
                        f.write(salt)
                    
                    out.insert(tk.END, f"✓ Encryption successful!\n")
                    out.insert(tk.END, f"Encrypted file: {output_path}\n")
                    out.insert(tk.END, f"Salt file: {salt_file}\n")
                    out.insert(tk.END, f"\nKeep the salt file safe for decryption later.")
                else:
                    out.insert(tk.END, "✗ Encryption failed")
                
                out.config(state='disabled')
            except Exception as e:
                out.config(state='normal')
                out.delete('1.0', tk.END)
                out.insert('1.0', f"Error: {e}")
                out.config(state='disabled')
        
        def decrypt_file():
            try:
                file_path = file_path_var.get()
                password = password_var.get()
                
                if not file_path or not password:
                    out.config(state='normal')
                    out.delete('1.0', tk.END)
                    out.insert('1.0', "Error: Please select a file and enter a password")
                    out.config(state='disabled')
                    return
                
                out.config(state='normal')
                out.delete('1.0', tk.END)
                out.insert('1.0', f"Decrypting {file_path}...\n")
                out.update()
                
                # Try to load salt
                salt_file = file_path + ".salt"
                if os.path.exists(salt_file):
                    with open(salt_file, 'rb') as f:
                        salt = f.read()
                    key, _ = self.app.encryption.generate_key(password, salt)
                else:
                    # Try without salt (compatibility)
                    key, _ = self.app.encryption.generate_key(password)
                
                # Decrypt file
                output_path = file_path.replace('.encrypted', '.decrypted')
                if output_path == file_path:
                    output_path = file_path + ".decrypted"
                
                success = self.app.encryption.decrypt_file(file_path, output_path, key)
                
                if success:
                    out.insert(tk.END, f"✓ Decryption successful!\n")
                    out.insert(tk.END, f"Decrypted file: {output_path}\n")
                else:
                    out.insert(tk.END, "✗ Decryption failed")
                
                out.config(state='disabled')
            except Exception as e:
                out.config(state='normal')
                out.delete('1.0', tk.END)
                out.insert('1.0', f"Error: {e}")
                out.config(state='disabled')
        
        # Buttons
        button_frame = tk.Frame(frame)
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="🔒 Encrypt File", command=encrypt_file, 
                 bg="#4CAF50", fg="white", width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="🔓 Decrypt File", command=decrypt_file, 
                 bg="#FF9800", fg="white", width=15).pack(side=tk.LEFT, padx=5)
