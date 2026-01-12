"""
Credentials Manager - Manage passwords and accounts
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import logging
import json
import re
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class CredentialsManager:
    """Manage stored credentials"""
    
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.db = app.db
        self.user_id = app.current_user_id
        self.selected_credential = None
        self.show_passwords = False
        
        # Main layout
        self.container = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_light'])
        self.container.pack(fill=tk.BOTH, expand=True)
        
        self.setup_ui()
        self.load_credentials()
        
    def setup_ui(self):
        """Setup credentials UI"""
        # Toolbar
        toolbar = tk.Frame(self.container, bg=self.app.theme_manager.colors['bg_medium'])
        toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(toolbar, text="➕ New Credential", command=self.new_credential,
                 bg=self.app.theme_manager.colors['accent_success'],
                 fg=self.app.theme_manager.colors['fg_primary']).pack(side=tk.LEFT, padx=5)
        
        tk.Button(toolbar, text="✏️ Edit", command=self.edit_credential,
                 bg=self.app.theme_manager.colors['accent_info'],
                 fg=self.app.theme_manager.colors['fg_primary']).pack(side=tk.LEFT, padx=5)
        
        tk.Button(toolbar, text="🗑️ Delete", command=self.delete_credential,
                 bg=self.app.theme_manager.colors['accent_danger'],
                 fg=self.app.theme_manager.colors['fg_primary']).pack(side=tk.LEFT, padx=5)
        
        tk.Button(toolbar, text="🔍 Check Breach", command=self.check_breach,
                 bg="#FF9800",
                 fg=self.app.theme_manager.colors['fg_primary']).pack(side=tk.LEFT, padx=5)
                 
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_credentials)
        tk.Entry(toolbar, textvariable=self.search_var, width=20).pack(side=tk.RIGHT, padx=5)
        tk.Label(toolbar, text="Search:", bg=self.app.theme_manager.colors['bg_medium'],
                fg=self.app.theme_manager.colors['fg_primary']).pack(side=tk.RIGHT)
                 
        tk.Label(self.container, text="Credentials Manager", font=("Arial", 18, "bold"),
                bg=self.app.theme_manager.colors['bg_light'],
                fg=self.app.theme_manager.colors['fg_primary']).pack(pady=10)
                
        # Credentials list
        columns = ("Service", "Username", "Category", "Strength", "Modified")
        self.tree = ttk.Treeview(self.container, columns=columns, show="headings", height=15)
        
        self.tree.heading("Service", text="Service")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Category", text="Category")
        self.tree.heading("Strength", text="Strength")
        self.tree.heading("Modified", text="Modified")
        
        self.tree.column("Service", width=150)
        self.tree.column("Username", width=150)
        self.tree.column("Category", width=100)
        self.tree.column("Strength", width=80)
        self.tree.column("Modified", width=100)
        
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.tree.bind("<<TreeviewSelect>>", self.on_credential_select)
        
        # Details panel
        details_frame = tk.Frame(self.container, bg=self.app.theme_manager.colors['bg_medium'], height=150)
        details_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(details_frame, text="Credential Details:", font=("Arial", 10, "bold"),
                bg=details_frame['bg'], fg=self.app.theme_manager.colors['fg_primary']).pack(anchor='w', padx=10, pady=5)
        
        self.details_text = tk.Text(details_frame, height=6, width=80, bg='white', fg='black')
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.details_text.config(state='disabled')

    def load_credentials(self):
        """Load credentials from database"""
        self.tree.delete(*self.tree.get_children())
        try:
            query = "SELECT * FROM credentials WHERE user_id = ? ORDER BY last_updated DESC"
            results = self.db.execute_query(query, (self.user_id,))
            
            for row in results:
                strength = self.get_strength_label(row['password_strength'])
                self.tree.insert("", tk.END, iid=row['id'], values=(
                    row['service'],
                    row['username'],
                    row['category'],
                    strength,
                    row['last_updated'][:10] if row['last_updated'] else ""
                ))
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")
            messagebox.showerror("Error", f"Failed to load credentials: {e}")

    def filter_credentials(self, *args):
        """Filter credentials by search term"""
        search_term = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())
        
        try:
            query = "SELECT * FROM credentials WHERE user_id = ? ORDER BY last_updated DESC"
            results = self.db.execute_query(query, (self.user_id,))
            
            for row in results:
                if search_term in row['service'].lower() or \
                   search_term in (row['username'] or "").lower() or \
                   search_term in (row['category'] or "").lower():
                    strength = self.get_strength_label(row['password_strength'])
                    self.tree.insert("", tk.END, iid=row['id'], values=(
                        row['service'],
                        row['username'],
                        row['category'],
                        strength,
                        row['last_updated'][:10] if row['last_updated'] else ""
                    ))
        except Exception as e:
            logger.error(f"Filter failed: {e}")

    def on_credential_select(self, event):
        """Handle credential selection"""
        selection = self.tree.selection()
        if not selection:
            return
        
        cred_id = selection[0]
        query = "SELECT * FROM credentials WHERE id = ?"
        row = self.db.execute_query(query, (cred_id,), fetch_all=False)
        
        if row:
            self.selected_credential = dict(row)
            self.show_credential_details(row)

    def show_credential_details(self, row):
        """Display credential details"""
        try:
            # Decrypt password
            password = self.app.encryption.decrypt_data(row['password_encrypted'], self.app.user_key)
            
            details = f"""Service: {row['service']}
Username: {row['username']}
Password: {'*' * 8 if not self.show_passwords else password}
Category: {row['category']}
URL: {row['url'] or 'N/A'}
Notes: {row['notes'] or 'N/A'}
Tags: {row['tags'] or '[]'}
Strength: {self.get_strength_label(row['password_strength'])}
Expires: {row['expires_at'] or 'Never'}
Last Modified: {row['last_updated']}"""
            
            self.details_text.config(state='normal')
            self.details_text.delete('1.0', tk.END)
            self.details_text.insert('1.0', details)
            self.details_text.config(state='disabled')
        except Exception as e:
            self.details_text.config(state='normal')
            self.details_text.delete('1.0', tk.END)
            self.details_text.insert('1.0', f"Error displaying details: {e}")
            self.details_text.config(state='disabled')

    def new_credential(self):
        """Create new credential"""
        dialog = tk.Toplevel(self.parent)
        dialog.title("New Credential")
        dialog.geometry("500x600")
        
        # Service
        tk.Label(dialog, text="Service Name:").grid(row=0, column=0, sticky='w', padx=10, pady=10)
        service_var = tk.StringVar()
        tk.Entry(dialog, textvariable=service_var, width=40).grid(row=0, column=1, padx=10, pady=10)
        
        # Username
        tk.Label(dialog, text="Username:").grid(row=1, column=0, sticky='w', padx=10, pady=10)
        username_var = tk.StringVar()
        tk.Entry(dialog, textvariable=username_var, width=40).grid(row=1, column=1, padx=10, pady=10)
        
        # Password
        tk.Label(dialog, text="Password:").grid(row=2, column=0, sticky='w', padx=10, pady=10)
        password_var = tk.StringVar()
        password_entry = tk.Entry(dialog, textvariable=password_var, width=40, show='*')
        password_entry.grid(row=2, column=1, padx=10, pady=10)
        
        # Show password checkbox
        show_pass_var = tk.BooleanVar()
        def toggle_show():
            password_entry.config(show='' if show_pass_var.get() else '*')
        tk.Checkbutton(dialog, text="Show", variable=show_pass_var, command=toggle_show).grid(row=2, column=2)
        
        # Generate button
        def gen_password():
            password_var.set(self.app.encryption.generate_secure_password())
        tk.Button(dialog, text="Generate", command=gen_password, width=10).grid(row=3, column=1, sticky='w', padx=10)
        
        # URL
        tk.Label(dialog, text="URL:").grid(row=4, column=0, sticky='w', padx=10, pady=10)
        url_var = tk.StringVar()
        tk.Entry(dialog, textvariable=url_var, width=40).grid(row=4, column=1, padx=10, pady=10)
        
        # Category
        tk.Label(dialog, text="Category:").grid(row=5, column=0, sticky='w', padx=10, pady=10)
        category_var = tk.StringVar()
        categories = ["Social Media", "Email", "Banking", "Shopping", "Work", "Government", "Education", "Entertainment"]
        category_combo = ttk.Combobox(dialog, textvariable=category_var, values=categories, width=37)
        category_combo.grid(row=5, column=1, padx=10, pady=10)
        
        # Tags
        tk.Label(dialog, text="Tags (comma-separated):").grid(row=6, column=0, sticky='w', padx=10, pady=10)
        tags_var = tk.StringVar()
        tk.Entry(dialog, textvariable=tags_var, width=40).grid(row=6, column=1, padx=10, pady=10)
        
        # Notes
        tk.Label(dialog, text="Notes:").grid(row=7, column=0, sticky='w', padx=10, pady=10)
        notes_var = tk.StringVar()
        tk.Entry(dialog, textvariable=notes_var, width=40).grid(row=7, column=1, padx=10, pady=10)
        
        # Expires at
        tk.Label(dialog, text="Expires At (optional):").grid(row=8, column=0, sticky='w', padx=10, pady=10)
        expires_var = tk.StringVar()
        tk.Entry(dialog, textvariable=expires_var, width=40).grid(row=8, column=1, padx=10, pady=10)
        
        # Buttons
        def save():
            try:
                if not service_var.get() or not password_var.get():
                    messagebox.showerror("Error", "Service and Password are required")
                    return
                
                # Encrypt password
                encrypted_password = self.app.encryption.encrypt_data(password_var.get(), self.app.user_key)
                
                # Check password strength
                strength = self.calculate_password_strength(password_var.get())
                
                # Convert tags
                tags = json.dumps(tags_var.get().split(',')) if tags_var.get() else "[]"
                
                query = """INSERT INTO credentials 
                          (user_id, service, username, password_encrypted, url, category, 
                           tags, notes, password_strength, password_last_changed, expires_at)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)"""
                
                self.db.execute_query(query, (
                    self.user_id,
                    service_var.get(),
                    username_var.get(),
                    encrypted_password,
                    url_var.get(),
                    category_var.get() or "General",
                    tags,
                    notes_var.get(),
                    strength,
                    expires_var.get() or None
                ))
                
                logger.info(f"Credential created for {service_var.get()}")
                messagebox.showinfo("Success", "Credential saved successfully")
                dialog.destroy()
                self.load_credentials()
            except Exception as e:
                logger.error(f"Failed to save credential: {e}")
                messagebox.showerror("Error", f"Failed to save: {e}")
        
        tk.Button(dialog, text="Save", command=save, bg="#4CAF50", fg="white", width=10).grid(row=9, column=1, sticky='w', padx=10, pady=20)
        tk.Button(dialog, text="Cancel", command=dialog.destroy, width=10).grid(row=9, column=2, padx=10, pady=20)

    def edit_credential(self):
        """Edit selected credential"""
        if not self.selected_credential:
            messagebox.showwarning("Warning", "Please select a credential to edit")
            return
        
        cred = self.selected_credential
        dialog = tk.Toplevel(self.parent)
        dialog.title(f"Edit: {cred['service']}")
        dialog.geometry("500x600")
        
        # Service
        tk.Label(dialog, text="Service Name:").grid(row=0, column=0, sticky='w', padx=10, pady=10)
        service_var = tk.StringVar(value=cred['service'])
        tk.Entry(dialog, textvariable=service_var, width=40).grid(row=0, column=1, padx=10, pady=10)
        
        # Username
        tk.Label(dialog, text="Username:").grid(row=1, column=0, sticky='w', padx=10, pady=10)
        username_var = tk.StringVar(value=cred['username'] or "")
        tk.Entry(dialog, textvariable=username_var, width=40).grid(row=1, column=1, padx=10, pady=10)
        
        # Password
        tk.Label(dialog, text="Password:").grid(row=2, column=0, sticky='w', padx=10, pady=10)
        password_var = tk.StringVar()
        try:
            password_var.set(self.app.encryption.decrypt_data(cred['password_encrypted'], self.app.user_key))
        except:
            password_var.set("")
        
        password_entry = tk.Entry(dialog, textvariable=password_var, width=40, show='*')
        password_entry.grid(row=2, column=1, padx=10, pady=10)
        
        # Show password checkbox
        show_pass_var = tk.BooleanVar()
        def toggle_show():
            password_entry.config(show='' if show_pass_var.get() else '*')
        tk.Checkbutton(dialog, text="Show", variable=show_pass_var, command=toggle_show).grid(row=2, column=2)
        
        # URL
        tk.Label(dialog, text="URL:").grid(row=4, column=0, sticky='w', padx=10, pady=10)
        url_var = tk.StringVar(value=cred['url'] or "")
        tk.Entry(dialog, textvariable=url_var, width=40).grid(row=4, column=1, padx=10, pady=10)
        
        # Category
        tk.Label(dialog, text="Category:").grid(row=5, column=0, sticky='w', padx=10, pady=10)
        category_var = tk.StringVar(value=cred['category'] or "General")
        categories = ["Social Media", "Email", "Banking", "Shopping", "Work", "Government", "Education", "Entertainment"]
        category_combo = ttk.Combobox(dialog, textvariable=category_var, values=categories, width=37)
        category_combo.grid(row=5, column=1, padx=10, pady=10)
        
        # Tags
        tk.Label(dialog, text="Tags (comma-separated):").grid(row=6, column=0, sticky='w', padx=10, pady=10)
        tags_str = ",".join(json.loads(cred['tags'] or "[]")) if cred['tags'] else ""
        tags_var = tk.StringVar(value=tags_str)
        tk.Entry(dialog, textvariable=tags_var, width=40).grid(row=6, column=1, padx=10, pady=10)
        
        # Notes
        tk.Label(dialog, text="Notes:").grid(row=7, column=0, sticky='w', padx=10, pady=10)
        notes_var = tk.StringVar(value=cred['notes'] or "")
        tk.Entry(dialog, textvariable=notes_var, width=40).grid(row=7, column=1, padx=10, pady=10)
        
        # Expires at
        tk.Label(dialog, text="Expires At (optional):").grid(row=8, column=0, sticky='w', padx=10, pady=10)
        expires_var = tk.StringVar(value=cred['expires_at'] or "")
        tk.Entry(dialog, textvariable=expires_var, width=40).grid(row=8, column=1, padx=10, pady=10)
        
        # Buttons
        def save():
            try:
                # Encrypt password if changed
                try:
                    old_password = self.app.encryption.decrypt_data(cred['password_encrypted'], self.app.user_key)
                except:
                    old_password = ""
                
                password_changed = password_var.get() != old_password
                encrypted_password = self.app.encryption.encrypt_data(password_var.get(), self.app.user_key) if password_changed else cred['password_encrypted']
                
                # Check password strength
                strength = self.calculate_password_strength(password_var.get())
                
                # Convert tags
                tags = json.dumps(tags_var.get().split(',')) if tags_var.get() else "[]"
                
                query = """UPDATE credentials SET 
                          service=?, username=?, password_encrypted=?, url=?, category=?,
                          tags=?, notes=?, password_strength=?, expires_at=?, last_updated=datetime('now')
                          WHERE id=?"""
                
                self.db.execute_query(query, (
                    service_var.get(),
                    username_var.get(),
                    encrypted_password,
                    url_var.get(),
                    category_var.get() or "General",
                    tags,
                    notes_var.get(),
                    strength,
                    expires_var.get() or None,
                    cred['id']
                ))
                
                logger.info(f"Credential updated for {service_var.get()}")
                messagebox.showinfo("Success", "Credential updated successfully")
                dialog.destroy()
                self.load_credentials()
            except Exception as e:
                logger.error(f"Failed to update credential: {e}")
                messagebox.showerror("Error", f"Failed to update: {e}")
        
        tk.Button(dialog, text="Save", command=save, bg="#4CAF50", fg="white", width=10).grid(row=9, column=1, sticky='w', padx=10, pady=20)
        tk.Button(dialog, text="Cancel", command=dialog.destroy, width=10).grid(row=9, column=2, padx=10, pady=20)

    def delete_credential(self):
        """Delete selected credential"""
        if not self.selected_credential:
            messagebox.showwarning("Warning", "Please select a credential to delete")
            return
        
        if messagebox.askyesno("Confirm", f"Delete credential for {self.selected_credential['service']}?"):
            try:
                query = "DELETE FROM credentials WHERE id = ?"
                self.db.execute_query(query, (self.selected_credential['id'],))
                messagebox.showinfo("Success", "Credential deleted")
                self.load_credentials()
                self.selected_credential = None
            except Exception as e:
                logger.error(f"Failed to delete: {e}")
                messagebox.showerror("Error", f"Failed to delete: {e}")

    def check_breach(self):
        """Check if credential appears in known breaches"""
        if not self.selected_credential:
            messagebox.showwarning("Warning", "Please select a credential")
            return
        
        try:
            # Show checking dialog
            check_window = tk.Toplevel(self.parent)
            check_window.title("Breach Check in Progress")
            check_window.geometry("400x150")
            
            tk.Label(check_window, text="Checking password against breach databases...", 
                    font=("Arial", 10)).pack(pady=20)
            
            progress = ttk.Progressbar(check_window, mode='indeterminate')
            progress.pack(fill=tk.X, padx=20, pady=20)
            progress.start()
            
            check_window.update()
            
            # Get password and check
            password = self.app.encryption.decrypt_data(self.selected_credential['password_encrypted'], self.app.user_key)
            
            # Use breach checker
            if hasattr(self.app, 'breach_checker'):
                result = self.app.breach_checker.check_password_breach(password)
            else:
                result = {'status': 'error', 'message': 'Breach checker not available'}
            
            progress.stop()
            check_window.destroy()
            
            # Update database with result
            result_str = result.get('status', 'unknown')
            query = "UPDATE credentials SET breach_check_result=?, last_breach_check=datetime('now') WHERE id=?"
            self.db.execute_query(query, (result_str, self.selected_credential['id']))
            
            # Show result
            if result['status'] == 'breached':
                messagebox.showwarning("⚠️ PASSWORD COMPROMISED", 
                                     f"This password has been found in {result['breach_count']} known breaches!\n\n"
                                     f"Action: {result['action']}\n\n"
                                     "You should change this password immediately.")
            elif result['status'] == 'clean':
                messagebox.showinfo("✓ Password Safe", 
                                  f"{result['message']}\n\nAction: {result['action']}")
            elif result['status'] == 'rate_limited':
                messagebox.showwarning("Rate Limited", 
                                     f"{result['message']}\n\nAction: {result['action']}")
            else:
                messagebox.showinfo("Breach Check", result['message'])
            
            self.load_credentials()
        except Exception as e:
            logger.error(f"Breach check failed: {e}")
            messagebox.showerror("Error", f"Breach check failed: {e}")

    def calculate_password_strength(self, password: str) -> int:
        """Calculate password strength (1-5)"""
        score = 0
        
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'[0-9]', password):
            score += 1
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            score += 1
        
        return min(5, max(1, (score + 1) // 2))

    def get_strength_label(self, strength: int) -> str:
        """Get strength label"""
        labels = {
            1: "Very Weak",
            2: "Weak",
            3: "Fair",
            4: "Good",
            5: "Strong"
        }
        return labels.get(strength or 1, "Unknown")
