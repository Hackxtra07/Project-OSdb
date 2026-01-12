"""
Settings Panel - Application Configuration and Management
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import logging
import os
import configparser

logger = logging.getLogger(__name__)

class SettingsPanel:
    """Application settings and user configuration"""
    
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.db = app.db
        
        self.main_frame = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_light'])
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.create_tabs()
        
    def create_tabs(self):
        # 1. Profile
        tab_profile = tk.Frame(self.notebook, bg=self.app.theme_manager.colors['bg_light'])
        self.notebook.add(tab_profile, text="User Profile")
        self.build_profile_tab(tab_profile)
        
        # 2. Security
        tab_sec = tk.Frame(self.notebook, bg=self.app.theme_manager.colors['bg_light'])
        self.notebook.add(tab_sec, text="Security")
        self.build_security_tab(tab_sec)
        
        # 3. API Keys
        tab_api = tk.Frame(self.notebook, bg=self.app.theme_manager.colors['bg_light'])
        self.notebook.add(tab_api, text="API Keys")
        self.build_api_tab(tab_api)
        
        # 4. Backup
        tab_backup = tk.Frame(self.notebook, bg=self.app.theme_manager.colors['bg_light'])
        self.notebook.add(tab_backup, text="Backup/Restore")
        self.build_backup_tab(tab_backup)
        
        # 5. Import/Export
        tab_import_export = tk.Frame(self.notebook, bg=self.app.theme_manager.colors['bg_light'])
        self.notebook.add(tab_import_export, text="Import/Export")
        self.build_import_export_tab(tab_import_export)

    def build_profile_tab(self, parent):
        tk.Label(parent, text="User Profile Settings", font=("Arial", 14, "bold"), bg=parent['bg']).pack(pady=20)
        
        f = tk.Frame(parent, bg=parent['bg'])
        f.pack()
        
        tk.Label(f, text="Username:", bg=parent['bg']).grid(row=0, column=0, pady=5, sticky='e')
        tk.Label(f, text=self.app.current_user['username'], font=("Arial", 12, "bold"), bg=parent['bg']).grid(row=0, column=1, pady=5, sticky='w')
        
        tk.Label(f, text="Email:", bg=parent['bg']).grid(row=1, column=0, pady=5, sticky='e')
        self.email_var = tk.StringVar(value=self.app.current_user['email'])
        tk.Entry(f, textvariable=self.email_var).grid(row=1, column=1, pady=5)
        
        tk.Button(f, text="Update Profile", command=self.update_profile).grid(row=2, columnspan=2, pady=20)

    def build_security_tab(self, parent):
        tk.Label(parent, text="Security Settings", font=("Arial", 14, "bold"), bg=parent['bg']).pack(pady=20)
        
        f = tk.Frame(parent, bg=parent['bg'])
        f.pack()
        
        # Change Password
        tk.Button(f, text="Change Password", command=self.open_change_password_dialog, 
                 bg=self.app.theme_manager.colors['accent_primary'],
                 fg="#ffffff", padx=20, pady=10).pack(pady=5)
        
        # 2FA
        self.twofa_var = tk.BooleanVar(value=bool(self.app.current_user.get('twofa_enabled')))
        tk.Checkbutton(f, text="Enable Two-Factor Authentication (2FA)", variable=self.twofa_var, 
                      command=self.toggle_2fa, bg=parent['bg']).pack(pady=10)
        
        tk.Label(f, text="Session Timeout (mins):", bg=parent['bg']).pack(pady=5)
        self.timeout_var = tk.IntVar(value=self.app.session_timeout_minutes)
        timeout_frame = tk.Frame(f, bg=parent['bg'])
        timeout_frame.pack(pady=5)
        tk.Spinbox(timeout_frame, from_=1, to=120, textvariable=self.timeout_var, width=10).pack(side=tk.LEFT, padx=5)
        tk.Button(timeout_frame, text="Save Timeout Setting", 
                 command=self.save_timeout_setting, bg=self.app.theme_manager.colors['accent_primary'],
                 fg="#ffffff").pack(side=tk.LEFT, padx=5)

    def build_api_tab(self, parent):
        tk.Label(parent, text="API Integrations", font=("Arial", 14, "bold"), bg=parent['bg']).pack(pady=20)
        
        f = tk.Frame(parent, bg=parent['bg'])
        f.pack()
        
        apis = [
            ("VirusTotal API Key", "virustotal"),
            ("Shodan API Key", "shodan"),
            ("Hunter.io API Key", "hunter")
        ]
        
        self.api_vars = {}
        for i, (label, key) in enumerate(apis):
            tk.Label(f, text=label, bg=parent['bg']).grid(row=i, column=0, padx=10, pady=5, sticky='e')
            var = tk.StringVar()
            # In a real app, load existing keys
            tk.Entry(f, textvariable=var, width=40, show="*").grid(row=i, column=1, padx=10, pady=5)
            self.api_vars[key] = var
            
        tk.Button(f, text="Save Keys", command=self.save_api_keys).grid(row=len(apis), columnspan=2, pady=20)

    def build_backup_tab(self, parent):
        tk.Label(parent, text="Database Backup & Restore", font=("Arial", 14, "bold"), bg=parent['bg']).pack(pady=20)
        
        tk.Button(parent, text="Create Backup Now", command=self.create_backup, height=2, width=20).pack(pady=10)
        
        tk.Label(parent, text="Restore from File:", bg=parent['bg']).pack(pady=(20, 5))
        tk.Button(parent, text="Select Backup File...", command=self.restore_backup).pack(pady=5)

    def update_profile(self):
        email = self.email_var.get()
        self.db.execute_query("UPDATE users SET email = ? WHERE id = ?", (email, self.app.current_user_id))
        self.app.current_user['email'] = email
        messagebox.showinfo("Success", "Profile updated")

    def toggle_2fa(self):
        enabled = self.twofa_var.get()
        self.db.execute_query("UPDATE users SET twofa_enabled = ? WHERE id = ?", (1 if enabled else 0, self.app.current_user_id))
        status = "enabled" if enabled else "disabled"
        messagebox.showinfo("2FA", f"Two-factor authentication {status}")

    def open_change_password_dialog(self):
        """Open password change dialog"""
        dialog = tk.Toplevel(self.parent)
        dialog.title("Change Password")
        dialog.geometry("400x350")
        dialog.resizable(False, False)
        
        # Center on screen
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (dialog.winfo_screenheight() // 2) - (350 // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Configure style
        bg = self.app.theme_manager.colors['bg_medium']
        fg = self.app.theme_manager.colors['fg_primary']
        dialog.config(bg=bg)
        
        frame = tk.Frame(dialog, bg=bg)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        tk.Label(frame, text="Change Your Password", font=("Arial", 14, "bold"),
                bg=bg, fg=fg).pack(pady=(0, 20))
        
        # Current password
        tk.Label(frame, text="Current Password:", bg=bg, fg=fg).pack(anchor='w', pady=(10, 0))
        current_pass_var = tk.StringVar()
        tk.Entry(frame, textvariable=current_pass_var, show='*', width=40).pack(pady=(0, 15))
        
        # New password
        tk.Label(frame, text="New Password:", bg=bg, fg=fg).pack(anchor='w', pady=(10, 0))
        new_pass_var = tk.StringVar()
        tk.Entry(frame, textvariable=new_pass_var, show='*', width=40).pack(pady=(0, 15))
        
        # Confirm password
        tk.Label(frame, text="Confirm New Password:", bg=bg, fg=fg).pack(anchor='w', pady=(10, 0))
        confirm_pass_var = tk.StringVar()
        tk.Entry(frame, textvariable=confirm_pass_var, show='*', width=40).pack(pady=(0, 15))
        
        # Password strength indicator
        strength_label = tk.Label(frame, text="Password Strength: ", bg=bg, fg=fg)
        strength_label.pack(anchor='w', pady=(10, 5))
        
        def update_strength(*args):
            password = new_pass_var.get()
            strength = self.calculate_password_strength(password)
            strength_colors = {
                'Weak': '#f44336',
                'Medium': '#ff9800',
                'Strong': '#4caf50',
                'Very Strong': '#4caf50'
            }
            color = strength_colors.get(strength, '#cccccc')
            strength_label.config(text=f"Password Strength: {strength}", fg=color)
        
        new_pass_var.trace('w', update_strength)
        
        # Buttons
        button_frame = tk.Frame(frame, bg=bg)
        button_frame.pack(fill=tk.X, pady=20)
        
        def save_password():
            try:
                current = current_pass_var.get()
                new_pass = new_pass_var.get()
                confirm = confirm_pass_var.get()
                
                # Validation
                if not current or not new_pass or not confirm:
                    messagebox.showerror("Error", "All fields are required")
                    return
                
                if new_pass != confirm:
                    messagebox.showerror("Error", "New passwords do not match")
                    return
                
                if len(new_pass) < 8:
                    messagebox.showerror("Error", "New password must be at least 8 characters")
                    return
                
                # Verify current password
                user_data = self.db.execute_query(
                    "SELECT password_hash FROM users WHERE id = ?",
                    (self.app.current_user_id,),
                    fetch_all=False
                )
                
                if not user_data:
                    messagebox.showerror("Error", "User not found")
                    return
                
                # Hash current password to compare
                import hashlib
                current_hash = hashlib.sha256(current.encode()).hexdigest()
                
                if current_hash != user_data['password_hash']:
                    messagebox.showerror("Error", "Current password is incorrect")
                    return
                
                # Hash new password
                new_hash = hashlib.sha256(new_pass.encode()).hexdigest()
                
                # Update password
                self.db.execute_query(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (new_hash, self.app.current_user_id)
                )
                
                # Log password change
                self.db.log_audit(self.app.current_user_id, "PASSWORD_CHANGED", 
                                 "User changed their password")
                
                messagebox.showinfo("Success", "Password changed successfully!")
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to change password: {e}")
        
        tk.Button(button_frame, text="Change Password",
                 command=save_password,
                 bg=self.app.theme_manager.colors['accent_primary'],
                 fg="#ffffff", padx=20, pady=8).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="Cancel",
                 command=dialog.destroy,
                 bg=self.app.theme_manager.colors['bg_light'],
                 fg=fg, padx=20, pady=8).pack(side=tk.RIGHT, padx=5)

    def calculate_password_strength(self, password: str) -> str:
        """Calculate password strength"""
        score = 0
        
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        
        if score < 2:
            return "Weak"
        elif score < 4:
            return "Medium"
        elif score < 5:
            return "Strong"
        else:
            return "Very Strong"

    def save_timeout_setting(self):
        """Save session timeout setting"""
        try:
            timeout_minutes = self.timeout_var.get()
            
            # Update in main app
            self.app.session_timeout_minutes = timeout_minutes
            
            # Save to config file
            import configparser
            config = configparser.ConfigParser()
            if os.path.exists('config.ini'):
                config.read('config.ini')
            
            if not config.has_section('session'):
                config.add_section('session')
            
            config.set('session', 'timeout_minutes', str(timeout_minutes))
            
            with open('config.ini', 'w') as f:
                config.write(f)
            
            # Reset idle timer with new timeout
            self.app.reset_idle_timer()
            
            messagebox.showinfo("Success", f"Session timeout set to {timeout_minutes} minutes")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save timeout setting: {e}")

    def save_api_keys(self):
        # Save to DB or Config
        # using app.api_manager to set
        for key, var in self.api_vars.items():
            val = var.get()
            if val:
                self.app.api_manager.set_api_key(key, val)
        messagebox.showinfo("Success", "API Keys saved")

    def create_backup(self):
        path = self.db.backup_database()
        if path:
            messagebox.showinfo("Backup", f"Backup created successfully:\n{path}")
        else:
            messagebox.showerror("Error", "Backup failed")

    def restore_backup(self):
        f = filedialog.askopenfilename(filetypes=[("Zip files", "*.zip")])
        if f:
            messagebox.showinfo("Restore", "Restore functionality would act here (restart required).")

    def build_import_export_tab(self, parent):
        """Import/Export data"""
        tk.Label(parent, text="Data Import/Export", font=("Arial", 14, "bold"), bg=parent['bg']).pack(pady=20)
        
        # Export section
        tk.Label(parent, text="Export Your Data", font=("Arial", 12, "bold"), bg=parent['bg']).pack(pady=10)
        
        export_frame = tk.Frame(parent, bg=parent['bg'])
        export_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(export_frame, text="Format:", bg=parent['bg']).pack(side=tk.LEFT, padx=5)
        export_format = tk.StringVar(value="json")
        ttk.Combobox(export_frame, textvariable=export_format, 
                    values=["json", "csv", "zip"], state="readonly", width=10).pack(side=tk.LEFT, padx=5)
        
        # Include options
        include_frame = tk.LabelFrame(parent, text="Include in Export", bg=parent['bg'], padx=10, pady=10)
        include_frame.pack(fill=tk.X, padx=20, pady=10)
        
        export_creds = tk.BooleanVar(value=True)
        export_notes = tk.BooleanVar(value=True)
        export_projects = tk.BooleanVar(value=True)
        
        tk.Checkbutton(include_frame, text="Credentials", variable=export_creds, bg=parent['bg']).pack(anchor='w')
        tk.Checkbutton(include_frame, text="Notes", variable=export_notes, bg=parent['bg']).pack(anchor='w')
        tk.Checkbutton(include_frame, text="Projects/Tasks/Evidence", variable=export_projects, bg=parent['bg']).pack(anchor='w')
        
        def export_data():
            try:
                filename = filedialog.asksaveasfilename(
                    defaultextension=f".{export_format.get()}",
                    filetypes=[
                        ("JSON files", "*.json"),
                        ("CSV files", "*.csv"),
                        ("ZIP files", "*.zip")
                    ]
                )
                
                if not filename:
                    return
                
                if hasattr(self.app, 'data_manager'):
                    success = self.app.data_manager.export_all_data(
                        self.app.current_user_id,
                        filename,
                        format_type=export_format.get(),
                        include_credentials=export_creds.get(),
                        include_notes=export_notes.get(),
                        include_projects=export_projects.get()
                    )
                    
                    if success:
                        messagebox.showinfo("Success", f"Data exported to:\n{filename}")
                    else:
                        messagebox.showerror("Error", "Export failed")
                else:
                    messagebox.showerror("Error", "Data manager not available")
            except Exception as e:
                logger.error(f"Export failed: {e}")
                messagebox.showerror("Error", f"Export failed: {e}")
        
        tk.Button(parent, text="Export Data", command=export_data, bg="#4CAF50", fg="white", height=2, width=20).pack(pady=10)
        
        # Import section
        tk.Label(parent, text="Import Data", font=("Arial", 12, "bold"), bg=parent['bg']).pack(pady=(20, 10))
        
        def import_data():
            try:
                filename = filedialog.askopenfilename(
                    filetypes=[
                        ("JSON files", "*.json"),
                        ("ZIP files", "*.zip")
                    ]
                )
                
                if not filename:
                    return
                
                if hasattr(self.app, 'data_manager'):
                    result = self.app.data_manager.import_data(
                        self.app.current_user_id,
                        filename
                    )
                    
                    message = f"Import Results:\n"
                    message += f"Credentials: {result.get('credentials', 0)}\n"
                    message += f"Notes: {result.get('notes', 0)}\n"
                    message += f"Projects: {result.get('projects', 0)}\n"
                    message += f"Tasks: {result.get('tasks', 0)}\n"
                    message += f"Evidence: {result.get('evidence', 0)}\n"
                    
                    if result.get('errors'):
                        message += f"\nErrors: {len(result['errors'])}"
                    
                    if result.get('success'):
                        messagebox.showinfo("Import Complete", message)
                    else:
                        messagebox.showwarning("Import Error", f"Import failed: {result.get('error')}")
                else:
                    messagebox.showerror("Error", "Data manager not available")
            except Exception as e:
                logger.error(f"Import failed: {e}")
                messagebox.showerror("Error", f"Import failed: {e}")
        
        tk.Button(parent, text="Import Data", command=import_data, bg="#2196F3", fg="white", height=2, width=20).pack(pady=10)
        
        tk.Label(parent, text="Warning: Importing will add new records to your database.", 
                font=("Arial", 9), fg="orange", bg=parent['bg']).pack(pady=10)
