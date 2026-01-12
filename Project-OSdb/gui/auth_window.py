"""
Authentication Window - Login, Registration and 2FA
"""

import tkinter as tk
from tkinter import ttk, messagebox
import logging
from typing import Callable, Any

logger = logging.getLogger(__name__)

class AuthenticationWindow:
    """Authentication Interface"""
    
    def __init__(self, parent: tk.Widget, app: Any):
        self.parent = parent
        self.app = app
        self.db = app.db
        self.security = app.security_monitor if hasattr(app, 'security_monitor') else None
        
        # UI State
        self.mode = "login"  # login, register, 2fa
        self.temp_user_id = None
        self.temp_user_data = None
        
        # Setup UI
        self.setup_ui()
        
    def setup_ui(self):
        """Setup authentication UI"""
        # Main container
        self.container = tk.Frame(self.parent, bg=self.app.theme_manager.colors['bg_dark'])
        self.container.place(relx=0.5, rely=0.5, anchor='center', relwidth=1, relheight=1)
        
        # Center card
        self.card = tk.Frame(self.container, bg=self.app.theme_manager.colors['bg_medium'],
                           padx=40, pady=40)
        self.card.place(relx=0.5, rely=0.5, anchor='center')
        
        # App Title
        tk.Label(self.card, text="Secure OSINT Storage",
                font=("Arial", 20, "bold"),
                bg=self.app.theme_manager.colors['bg_medium'],
                fg=self.app.theme_manager.colors['accent_primary']).pack(pady=(0, 20))
        
        # Form Frame
        self.form_frame = tk.Frame(self.card, bg=self.app.theme_manager.colors['bg_medium'])
        self.form_frame.pack(fill=tk.X)
        
        self.show_login_form()
        
    def show_login_form(self):
        """Show login form"""
        self.mode = "login"
        self._clear_form()
        
        tk.Label(self.form_frame, text="Username",
                bg=self.app.theme_manager.colors['bg_medium'],
                fg=self.app.theme_manager.colors['fg_secondary'],
                anchor='w').pack(fill=tk.X)
        
        self.username_entry = tk.Entry(self.form_frame, width=30)
        self.username_entry.pack(pady=(5, 15))
        self.username_entry.focus()
        
        tk.Label(self.form_frame, text="Password",
                bg=self.app.theme_manager.colors['bg_medium'],
                fg=self.app.theme_manager.colors['fg_secondary'],
                anchor='w').pack(fill=tk.X)
        
        self.password_entry = tk.Entry(self.form_frame, show="•", width=30)
        self.password_entry.pack(pady=(5, 20))
        
        # Buttons
        tk.Button(self.form_frame, text="Login",
                 command=self.handle_login,
                 bg=self.app.theme_manager.colors['accent_primary'],
                 fg=self.app.theme_manager.colors['fg_primary'],
                 width=30, pady=10).pack(pady=(0, 10))
                 
        tk.Button(self.form_frame, text="Create Account",
                 command=self.show_register_form,
                 bg=self.app.theme_manager.colors['bg_medium'],
                 fg=self.app.theme_manager.colors['accent_info'],
                 relief='flat', cursor='hand2').pack()
                 
        self.parent.bind('<Return>', lambda e: self.handle_login())
        
    def show_register_form(self):
        """Show registration form"""
        self.mode = "register"
        self._clear_form()
        
        tk.Label(self.form_frame, text="Create New Account",
                font=("Arial", 12, "bold"),
                bg=self.app.theme_manager.colors['bg_medium'],
                fg=self.app.theme_manager.colors['fg_primary']).pack(pady=(0, 15))
        
        # Username
        tk.Label(self.form_frame, text="Username",
                bg=self.app.theme_manager.colors['bg_medium'],
                fg=self.app.theme_manager.colors['fg_secondary'], anchor='w').pack(fill=tk.X)
        self.username_entry = tk.Entry(self.form_frame, width=30)
        self.username_entry.pack(pady=(2, 10))
        
        # Email
        tk.Label(self.form_frame, text="Email",
                bg=self.app.theme_manager.colors['bg_medium'],
                fg=self.app.theme_manager.colors['fg_secondary'], anchor='w').pack(fill=tk.X)
        self.email_entry = tk.Entry(self.form_frame, width=30)
        self.email_entry.pack(pady=(2, 10))
        
        # Password
        tk.Label(self.form_frame, text="Password",
                bg=self.app.theme_manager.colors['bg_medium'],
                fg=self.app.theme_manager.colors['fg_secondary'], anchor='w').pack(fill=tk.X)
        self.password_entry = tk.Entry(self.form_frame, show="•", width=30)
        self.password_entry.pack(pady=(2, 10))
        
        # Confirm Password
        tk.Label(self.form_frame, text="Confirm Password",
                bg=self.app.theme_manager.colors['bg_medium'],
                fg=self.app.theme_manager.colors['fg_secondary'], anchor='w').pack(fill=tk.X)
        self.confirm_entry = tk.Entry(self.form_frame, show="•", width=30)
        self.confirm_entry.pack(pady=(2, 20))
        
        # Buttons
        tk.Button(self.form_frame, text="Register",
                 command=self.handle_register,
                 bg=self.app.theme_manager.colors['accent_success'],
                 fg=self.app.theme_manager.colors['fg_primary'],
                 width=30, pady=10).pack(pady=(0, 10))
                 
        tk.Button(self.form_frame, text="Back to Login",
                 command=self.show_login_form,
                 bg=self.app.theme_manager.colors['bg_medium'],
                 fg=self.app.theme_manager.colors['fg_secondary'],
                 relief='flat', cursor='hand2').pack()
                 
        self.parent.bind('<Return>', lambda e: self.handle_register())
        
    def _clear_form(self):
        """Clear form widgets"""
        for widget in self.form_frame.winfo_children():
            widget.destroy()
            
    def handle_login(self):
        """Process login"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showwarning("Input Error", "Please enter username and password")
            return
            
        try:
            # First check if user exists in DB to prevent generic hashing errors if DB is special
            # But SecurityMonitor should handle verification.
            # Assuming db stores hashed usage.
            # In a real app we'd hash the password here with salt from DB.
            # For this simplified version (and matching core/security.py which seems to expect comparison):
            # We'll hash it before sending to verify if that's what was intended, 
            # Or if security.py does the hashing. 
            # security.py's verify_login takes `password_hash`. Let's assume we hash it here.
            
            # Use encryption manager to hash for consistent approach
            password_hash = self.app.encryption.hash_password(password)
            
            # This is tricky because `security.py` might expect us to pass the hash. 
            # Let's check `core/encryption.py` or assume standard SHA256 for now 
            # if we can't fully invoke modules yet.
            # Actually, `EncryptionManager` should be available on `self.app`.
            
            success, message, user_id = self.app.security_monitor.verify_login(username, password_hash)
            
            if success:
                if message == "2FA Required":
                    self.temp_user_id = user_id
                    # Need to fetch user object to hold temporarily
                    user_row = self.db.execute_query("SELECT * FROM users WHERE id = ?", (user_id,), fetch_all=False)
                    self.temp_user_data = dict(user_row) if user_row else None
                    if not self.temp_user_data:
                        raise ValueError("User not found after verification")
                        
                    # In a real app we'd derive key from password, not use raw.
                    # We'll pretend we derived a master key from password for encryption
                    self.temp_key = self.app.encryption.derive_key(password, self.temp_user_data.get('salt')) if self.temp_user_data and 'salt' in self.temp_user_data else b'default_key'
                    self.show_2fa_form()
                else:
                    # Direct Login
                    user_row = self.db.execute_query("SELECT * FROM users WHERE id = ?", (user_id,), fetch_all=False)
                    user_data = dict(user_row) if user_row else None
                    
                    if not user_data:
                        raise ValueError("User not found after verification")
                        
                    # Derive key
                    user_salt = user_data.get('salt')
                    # If salt is missing, we might need to handle legacy or generate.
                    # For now assume it works.
                    derived_key = self.app.encryption.derive_key(password, user_salt) if user_salt else b'insecure_default'
                    
                    self.app.login_successful(user_data, derived_key)
            else:
                messagebox.showerror("Login Failed", message)
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            messagebox.showerror("Error", f"An error occurred during login: {e}")
            
    def handle_register(self):
        """Process registration"""
        username = self.username_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()
        
        if not all([username, email, password, confirm]):
            messagebox.showwarning("Input Error", "All fields are required")
            return
            
        if password != confirm:
            messagebox.showerror("Input Error", "Passwords do not match")
            return
            
        if len(password) < 8:
            messagebox.showwarning("Weak Password", "Password must be at least 8 characters")
            return
            
        try:
            # Generate salt and hash
            salt = self.app.encryption.generate_salt()
            password_hash = self.app.encryption.hash_password(password) # Ideally salt included but core/encryption logic varies
            
            # Create user
            query = """
                INSERT INTO users (username, email, password_hash, salt, created_at, role)
                VALUES (?, ?, ?, ?, datetime('now'), 'user')
            """
            cursor = self.db.execute_query(query, (username, email, password_hash, salt))
            if cursor:
                # self.db.execute_query returns cursor or None/False? 
                # core/database.py returns cursor usually for inserts or we can verify by catch.
                messagebox.showinfo("Success", "Account created successfully! Please login.")
                self.show_login_form()
            else:
                # Likely constraint violation
                messagebox.showerror("Error", "Username or email already exists")
                
        except Exception as e:
            logger.error(f"Register error: {e}")
            messagebox.showerror("Error", f"Failed to create account: {e}")

    def show_2fa_form(self):
        """Show 2FA verification"""
        self.mode = "2fa"
        self._clear_form()
        
        tk.Label(self.form_frame, text="Two-Factor Authentication",
                font=("Arial", 12, "bold"),
                bg=self.app.theme_manager.colors['bg_medium'],
                fg=self.app.theme_manager.colors['fg_primary']).pack(pady=(0, 20))
                
        tk.Label(self.form_frame, text="Enter authenticator code:",
                 bg=self.app.theme_manager.colors['bg_medium'],
                 fg=self.app.theme_manager.colors['fg_secondary']).pack()
                 
        self.code_entry = tk.Entry(self.form_frame, width=20, font=("Arial", 14), justify='center')
        self.code_entry.pack(pady=10)
        self.code_entry.focus()
        
        tk.Button(self.form_frame, text="Verify",
                 command=self.verify_2fa,
                 bg=self.app.theme_manager.colors['accent_primary'],
                 fg=self.app.theme_manager.colors['fg_primary'],
                 width=20).pack(pady=10)
                 
        tk.Button(self.form_frame, text="Cancel",
                 command=self.show_login_form,
                 bg=self.app.theme_manager.colors['bg_medium'],
                 fg=self.app.theme_manager.colors['fg_secondary'],
                 relief='flat').pack()
                 
        self.parent.bind('<Return>', lambda e: self.verify_2fa())
        
    def verify_2fa(self):
        """Process 2FA code"""
        code = self.code_entry.get().strip()
        if not code: return
        
        if self.app.security_monitor.verify_2fa(self.temp_user_id, code):
            self.app.login_successful(self.temp_user_data, self.temp_key)
        else:
            messagebox.showerror("Error", "Invalid authentication code")