"""
Main Application Window - Enhanced with modular panels and complete functionality
"""

import tkinter as tk
from tkinter import ttk, messagebox, Menu, font, filedialog
import logging
import threading
import time
import json
import webbrowser
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import os
import sys

# Import GUI panels
# Note: We use lazy imports or try/except to handle circular deps or missing files during dev
try:
    from gui.auth_window import AuthenticationWindow
    from gui.dashboard import DashboardPanel
    from gui.credentials_manager import CredentialsManager
    from gui.notes_manager import NotesManager
    from gui.projects_manager import ProjectsManager
    from gui.tools_panel import ToolsPanel
    from gui.settings_panel import SettingsPanel
    from gui.widgets.theme_manager import ThemeManager
except ImportError:
    # Fallback for development if modules aren't fully ready
    pass

# Import core modules
from core.database import DatabaseManager
from core.encryption import EncryptionManager
from core.security import SecurityMonitor
from core.backup import BackupManager
from core.api_integrations import APIIntegrationManager

# Import utilities
from utils.helpers import Helpers
from utils.constants import *

logger = logging.getLogger(__name__)

class MainApplication:
    """Main application window with all enhanced features"""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        
        # Initialize theme manager first to get colors
        try:
            from gui.widgets.theme_manager import ThemeManager
            self.theme_manager = ThemeManager()
        except ImportError:
            # Fallback mock if not ready
            class MockTheme:
                colors = {'bg_dark': '#1e1e1e', 'bg_light': '#2d2d2d', 'bg_medium': '#252526', 
                          'fg_primary': '#ffffff', 'accent_primary': '#007acc', 
                          'fg_secondary': '#cccccc', 'accent_success': '#4caf50', 
                          'accent_warning': '#ff9800', 'accent_danger': '#f44336',
                          'accent_error': '#f44336', 'accent_info': '#2196f3', 'border': '#3e3e42'}
                available_themes = ['dark']
                themes = {'dark': {'name': 'Dark'}}
                def setup_styles(self, root): pass
                def load_settings(self): pass
            self.theme_manager = MockTheme()

        self.root.title("Secure OSINT Storage Pro v2.0")
        
        # Set application icon
        self.set_window_icon()
        
        # Configure window
        self.root.geometry("1280x800")
        self.root.minsize(1024, 768)
        
        # Initialize managers
        self.initialize_managers()
        
        # Application state
        self.current_user = None
        self.current_user_id = None
        self.user_key = None
        self.session_id = None
        self.login_time = None
        self.is_locked = False
        
        # Session timeout settings
        self.session_timeout_minutes = 30  # Default 30 minutes
        self.idle_timer = None
        self.warning_timer = None
        self.countdown_timer = None
        self.idle_seconds_remaining = 0
        self.warning_shown = False
        
        # GUI components
        self.menu_bar = None
        self.sidebar_frame = None
        self.main_content = None
        self.status_bar = None
        self.current_panel = None
        
        # Panels dictionary
        self.panels = {}
        
        # Shortcut registry
        self.shortcuts = {}
        
        # Auto-save timer
        self.auto_save_timer = None
        
        # Initialize GUI
        self.setup_window()
        
        # Show authentication
        self.show_authentication()
        
        # Start background services
        self.start_background_services()
        
        # Bind global events
        self.bind_global_events()
        
        logger.info("Main application initialized")
    
    def set_window_icon(self):
        """Set application window icon"""
        try:
            # Try different icon paths
            icon_paths = [
                "assets/icons/app_icon.ico",
                "assets/icons/app_icon.png",
                "assets/icons/icon.ico",
                "assets/icons/icon.png"
            ]
            
            for icon_path in icon_paths:
                if os.path.exists(icon_path):
                    if icon_path.endswith('.ico'):
                        self.root.iconbitmap(icon_path)
                    elif icon_path.endswith('.png'):
                        icon = tk.PhotoImage(file=icon_path)
                        self.root.iconphoto(True, icon)
                    break
        except Exception as e:
            logger.warning(f"Could not set window icon: {e}")
    
    def initialize_managers(self):
        """Initialize all manager instances"""
        try:
            # Database manager
            self.db = DatabaseManager("data/database.db")
            
            # Encryption manager
            self.encryption = EncryptionManager()
            
            # Security monitor
            self.security_monitor = SecurityMonitor(self.db)
            
            # Backup manager
            self.backup_manager = BackupManager(self.db, self.encryption)
            
            # API integration manager
            self.api_manager = APIIntegrationManager()
            
            # Breach checker
            from core.breach_checker import BreachChecker
            self.breach_checker = BreachChecker()
            
            # Data import/export manager
            from core.data_import_export import DataImportExportManager
            self.data_manager = DataImportExportManager(self.db, self.encryption)
            
        except Exception as e:
            logger.error(f"Failed to initialize managers: {e}")
            messagebox.showerror("Initialization Error", 
                               f"Failed to initialize application: {e}")
            sys.exit(1)
    
    def setup_window(self):
        """Setup main window components"""
        # Configure styles
        self.theme_manager.setup_styles(self.root)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create main container
        self.main_container = tk.PanedWindow(self.root, 
                                           orient=tk.HORIZONTAL,
                                           sashrelief='raised',
                                           sashwidth=5,
                                           bg=self.theme_manager.colors['bg_dark'])
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create sidebar (initially hidden)
        self.sidebar_frame = tk.Frame(self.main_container, 
                                     width=250,
                                     bg=self.theme_manager.colors['bg_dark'])
        # Don't add to panedwindow yet, will be added after login
        
        # Create main content area
        self.main_content = tk.Frame(self.main_container,
                                    bg=self.theme_manager.colors['bg_medium'])
        self.main_container.add(self.main_content)
        
        # Create status bar
        self.create_status_bar()
        
        # Apply initial theme settings
        self.theme_manager.load_settings()
    
    def create_menu_bar(self):
        """Create enhanced menu bar with all features"""
        self.menu_bar = Menu(self.root, 
                           bg=self.theme_manager.colors['bg_medium'],
                           fg=self.theme_manager.colors['fg_primary'],
                           tearoff=0)
        self.root.config(menu=self.menu_bar)
        
        # File menu
        file_menu = Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=file_menu)
        
        file_menu.add_command(label="Global Search", command=self.open_global_search, accelerator="Ctrl+F")
        file_menu.add_separator()
        file_menu.add_command(label="Dashboard", command=lambda: self.show_panel('dashboard'), accelerator="Ctrl+D")
        file_menu.add_separator()
        file_menu.add_command(label="New Project", command=self.new_project, accelerator="Ctrl+N")
        file_menu.add_command(label="New Credential", command=self.new_credential, accelerator="Ctrl+Shift+C")
        file_menu.add_command(label="New Note", command=self.new_note, accelerator="Ctrl+Shift+N")
        file_menu.add_separator()
        file_menu.add_command(label="Lock Session", command=self.lock_session, accelerator="Ctrl+L")
        file_menu.add_command(label="Logout", command=self.logout, accelerator="Ctrl+Q")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit_application, accelerator="Alt+F4")

        # View menu
        view_menu = Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="View", menu=view_menu)
        
        # Theme submenu
        theme_menu = Menu(view_menu, tearoff=0)
        view_menu.add_cascade(label="Theme", menu=theme_menu)
        for theme_id in self.theme_manager.available_themes:
            try:
                theme_name = self.theme_manager.themes[theme_id]['name']
                theme_menu.add_command(label=theme_name, command=lambda t=theme_id: self.change_theme(t))
            except: pass

        # Panels menu
        panels_menu = Menu(view_menu, tearoff=0)
        view_menu.add_cascade(label="Panels", menu=panels_menu)
        panels_menu.add_command(label="Dashboard", command=lambda: self.show_panel('dashboard'))
        panels_menu.add_command(label="Credentials", command=lambda: self.show_panel('credentials'))
        panels_menu.add_command(label="Notes", command=lambda: self.show_panel('notes'))
        panels_menu.add_command(label="Projects", command=lambda: self.show_panel('projects'))
        panels_menu.add_command(label="Tools", command=lambda: self.show_panel('tools'))
        panels_menu.add_command(label="Settings", command=lambda: self.show_panel('settings'))

        # Help menu
        help_menu = Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        
        self.bind_shortcuts()

    def create_status_bar(self):
        """Create enhanced status bar"""
        self.status_bar = tk.Frame(self.root, bg=self.theme_manager.colors['bg_medium'], height=25)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = tk.Label(self.status_bar, text="Ready", 
                                   bg=self.theme_manager.colors['bg_medium'],
                                   fg=self.theme_manager.colors['fg_secondary'],
                                   font=("Arial", 9))
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        self.user_label = tk.Label(self.status_bar, text="Not logged in",
                                 bg=self.theme_manager.colors['bg_medium'],
                                 fg=self.theme_manager.colors['fg_secondary'],
                                 font=("Arial", 9))
        self.user_label.pack(side=tk.RIGHT, padx=10)
        
        self.timer_label = tk.Label(self.status_bar, text="00:00:00",
                                  bg=self.theme_manager.colors['bg_medium'],
                                  fg=self.theme_manager.colors['fg_secondary'],
                                  font=("Arial", 9))
        self.timer_label.pack(side=tk.RIGHT, padx=10)

    def bind_shortcuts(self):
        """Bind keyboard shortcuts"""
        self.root.bind('<Control-f>', lambda e: self.open_global_search())
        self.root.bind('<Control-d>', lambda e: self.show_panel('dashboard'))
        self.root.bind('<Control-c>', lambda e: self.show_panel('credentials'))
        self.root.bind('<Control-n>', lambda e: self.show_panel('notes'))
        self.root.bind('<Control-p>', lambda e: self.show_panel('projects'))
        self.root.bind('<Control-t>', lambda e: self.show_panel('tools'))
        self.root.bind('<Control-s>', lambda e: self.show_panel('settings'))
        self.root.bind('<Control-l>', lambda e: self.lock_session())
        self.root.bind('<Control-q>', lambda e: self.logout())
        self.root.bind('<Control-N>', lambda e: self.new_project())

    def bind_global_events(self):
        """Bind global window events"""
        self.root.bind('<FocusIn>', self.on_window_focus)
        self.root.bind('<FocusOut>', self.on_window_blur)
        
        # Idle timer reset
        self.root.bind('<Motion>', self.reset_idle_timer)
        self.root.bind('<Key>', self.reset_idle_timer)
        self.idle_timer = None
    
    def on_window_focus(self, event):
        self.status_label.config(text="Active")
        
    def on_window_blur(self, event):
        self.status_label.config(text="Inactive")

    def reset_idle_timer(self, event=None):
        """Reset idle timer on user activity"""
        if self.idle_timer:
            self.root.after_cancel(self.idle_timer)
        if self.warning_timer:
            self.root.after_cancel(self.warning_timer)
        if self.countdown_timer:
            self.root.after_cancel(self.countdown_timer)
            
        self.warning_shown = False
        
        if self.current_user_id and not self.is_locked:
            # Set timeout duration in milliseconds
            timeout_ms = self.session_timeout_minutes * 60 * 1000
            warning_ms = timeout_ms - (2 * 60 * 1000)  # 2 minutes before timeout
            
            # Schedule warning (2 minutes before timeout)
            if self.session_timeout_minutes > 2:
                self.warning_timer = self.root.after(warning_ms, self.show_timeout_warning)
            
            # Schedule automatic lock
            self.idle_timer = self.root.after(timeout_ms, self.lock_session)
            
            # Update status bar with timeout info
            self.update_timeout_status()

    def update_timeout_status(self):
        """Update status bar with session timeout info"""
        if hasattr(self, 'status_bar') and self.status_bar:
            timeout_label = None
            for widget in self.status_bar.winfo_children():
                if hasattr(widget, 'timeout_label'):
                    timeout_label = widget
                    break
            
            if timeout_label:
                timeout_label.config(text=f"Session timeout: {self.session_timeout_minutes}m")

    def show_timeout_warning(self):
        """Show warning dialog 2 minutes before session timeout"""
        if self.warning_shown or self.is_locked:
            return
        
        self.warning_shown = True
        
        # Create warning window
        warning_window = tk.Toplevel(self.root)
        warning_window.title("Session Timeout Warning")
        warning_window.geometry("400x200")
        warning_window.resizable(False, False)
        warning_window.attributes('-topmost', True)
        
        # Center on screen
        warning_window.update_idletasks()
        x = (warning_window.winfo_screenwidth() // 2) - (400 // 2)
        y = (warning_window.winfo_screenheight() // 2) - (200 // 2)
        warning_window.geometry(f"+{x}+{y}")
        
        # Configure style
        bg_color = self.theme_manager.colors['bg_dark']
        fg_color = self.theme_manager.colors['fg_primary']
        warning_color = self.theme_manager.colors['accent_warning']
        
        warning_window.config(bg=bg_color)
        
        # Warning icon and message
        frame = tk.Frame(warning_window, bg=bg_color)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(frame, text="⏱️ SESSION TIMEOUT WARNING", 
                font=("Arial", 14, "bold"),
                bg=bg_color, fg=warning_color).pack(pady=(0, 15))
        
        tk.Label(frame, 
                text="Your session will expire in 2 minutes due to inactivity.\n\n"
                     "Click 'Continue Session' to reset the timeout,\n"
                     "or your session will be automatically locked.",
                font=("Arial", 10),
                bg=bg_color, fg=fg_color,
                justify=tk.CENTER, wraplength=350).pack(pady=10)
        
        # Buttons
        button_frame = tk.Frame(frame, bg=bg_color)
        button_frame.pack(fill=tk.X, pady=15)
        
        tk.Button(button_frame, text="Continue Session",
                 command=lambda: [warning_window.destroy(), self.reset_idle_timer()],
                 bg=self.theme_manager.colors['accent_primary'],
                 fg="#ffffff",
                 font=("Arial", 10, "bold"),
                 padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="Lock Session",
                 command=lambda: [warning_window.destroy(), self.lock_session()],
                 bg=self.theme_manager.colors['accent_error'],
                 fg="#ffffff",
                 font=("Arial", 10),
                 padx=15, pady=8).pack(side=tk.RIGHT, padx=5)

    def show_authentication(self):
        """Show authentication window"""
        self.clear_main_content()
        # Ensure sidebar is hidden
        self.main_container.forget(self.sidebar_frame)
        self.main_container.forget(self.main_content)
        self.main_container.add(self.main_content)
        
        try:
            from gui.auth_window import AuthenticationWindow
            self.auth_window = AuthenticationWindow(self.main_content, self)
        except ImportError:
            # Create a simple mock auth if file missing
            tk.Label(self.main_content, text="Authentication Module Missing", fg="red").pack(pady=20)
            tk.Button(self.main_content, text="Emergency Login", command=lambda: self.login_successful({'id': 1, 'username': 'admin', 'email': 'admin@local', 'twofa_enabled': False}, b'key')).pack()

        self.user_label.config(text="Not logged in")
    
    def load_session_timeout_setting(self):
        """Load session timeout setting from config file"""
        try:
            import configparser
            config = configparser.ConfigParser()
            if os.path.exists('config.ini'):
                config.read('config.ini')
                if config.has_section('session'):
                    timeout = config.get('session', 'timeout_minutes', fallback='30')
                    self.session_timeout_minutes = int(timeout)
                    logger.info(f"Loaded session timeout: {self.session_timeout_minutes} minutes")
        except Exception as e:
            logger.error(f"Failed to load session timeout setting: {e}")
            self.session_timeout_minutes = 30  # Default fallback

    def login_successful(self, user_data: Dict[str, Any], user_key: bytes):
        """Handle successful login"""
        self.current_user = user_data
        self.current_user_id = user_data['id']
        self.user_key = user_key
        self.login_time = datetime.now()
        self.is_locked = False
        
        # Load session timeout setting from config
        self.load_session_timeout_setting()
        
        self.user_label.config(text=f"User: {user_data['username']}")
        self.start_session_timer()
        self.show_main_interface()
        
        # Log success
        self.db.log_audit(self.current_user_id, "LOGIN_SUCCESS", f"User {user_data['username']} logged in")

    def show_main_interface(self):
        """Show main application interface"""
        self.clear_main_content()
        self.create_sidebar()
        
         # Add sidebar to panedwindow with fixed width
        self.main_container.add(self.sidebar_frame, width=250, stretch='never')
        self.main_container.add(self.main_content, stretch='always')
        
        self.show_panel('dashboard')
    
    def create_sidebar(self):
        """Create application sidebar"""
        # Clear existing
        for widget in self.sidebar_frame.winfo_children():
            widget.destroy()
            
        self.sidebar_frame.config(bg=self.theme_manager.colors['bg_dark'])
        
        # User Profile
        profile_frame = tk.Frame(self.sidebar_frame, bg=self.theme_manager.colors['bg_dark'])
        profile_frame.pack(fill=tk.X, padx=10, pady=20)
        
        tk.Label(profile_frame, text=self.current_user['username'],
                font=("Arial", 14, "bold"),
                bg=self.theme_manager.colors['bg_dark'],
                fg=self.theme_manager.colors['fg_primary']).pack()
                
        tk.Label(profile_frame, text="Online",
                font=("Arial", 9),
                bg=self.theme_manager.colors['bg_dark'],
                fg=self.theme_manager.colors['accent_success']).pack()

        # Navigation
        nav_frame = tk.Frame(self.sidebar_frame, bg=self.theme_manager.colors['bg_dark'])
        nav_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=10)
        
        buttons = [
            ("Dashboard", 'dashboard'),
            ("Credentials", 'credentials'),
            ("Secure Notes", 'notes'),
            ("Projects", 'projects'),
            ("Tools", 'tools'),
            ("Settings", 'settings')
        ]
        
        for text, panel_id in buttons:
            btn = tk.Button(nav_frame, text=text,
                          command=lambda p=panel_id: self.show_panel(p),
                          bg=self.theme_manager.colors['bg_medium'],
                          fg=self.theme_manager.colors['fg_primary'],
                          relief='flat', anchor='w', padx=15, pady=8)
            btn.pack(fill=tk.X, pady=2)

    def show_panel(self, panel_name: str):
        """Switch to specific panel"""
        if self.is_locked:
            return
            
        self.clear_main_content()
        self.current_panel = panel_name
        
        # Instantiate panel if not already created (or recreate every time for freshness)
        # Using lazy instantiation
        try:
            if panel_name == 'dashboard':
                from gui.dashboard import DashboardPanel
                DashboardPanel(self.main_content, self)
            elif panel_name == 'credentials':
                from gui.credentials_manager import CredentialsManager
                CredentialsManager(self.main_content, self)
            elif panel_name == 'notes':
                from gui.notes_manager import NotesManager
                NotesManager(self.main_content, self)
            elif panel_name == 'projects':
                from gui.projects_manager import ProjectsManager
                ProjectsManager(self.main_content, self)
            elif panel_name == 'tools':
                from gui.tools_panel import ToolsPanel
                ToolsPanel(self.main_content, self)
            elif panel_name == 'settings':
                from gui.settings_panel import SettingsPanel
                SettingsPanel(self.main_content, self)
            else:
                tk.Label(self.main_content, text=f"Panel '{panel_name}' not implemented").pack(pady=20)
        except ImportError as e:
            logger.error(f"Failed to load panel {panel_name}: {e}")
            tk.Label(self.main_content, text=f"Error loading {panel_name}: {e}", fg='red').pack()

    def clear_main_content(self):
        """Clear main content area"""
        for widget in self.main_content.winfo_children():
            widget.destroy()
            
    def lock_session(self, event=None):
        """Lock application session"""
        self.is_locked = True
        self.clear_main_content()
        self.main_container.forget(self.sidebar_frame)
        
        lock_frame = tk.Frame(self.main_content, bg=self.theme_manager.colors['bg_dark'])
        lock_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(lock_frame, text="Session Locked", font=("Arial", 24),
                bg=self.theme_manager.colors['bg_dark'],
                fg=self.theme_manager.colors['fg_primary']).pack(pady=(100, 20))
                
        tk.Button(lock_frame, text="Unlock", command=self.unlock_session,
                 bg=self.theme_manager.colors['accent_primary'],
                 fg=self.theme_manager.colors['fg_primary'],
                 font=("Arial", 12), padx=20, pady=10).pack()
                 
    def unlock_session(self):
        """Unlock application session"""
        # Shows auth dialog again
        self.show_authentication()

    def logout(self, event=None):
        """Logout user"""
        self.current_user = None
        self.current_user_id = None
        self.user_key = None
        self.is_locked = False
        self.show_authentication()
        
    def quit_application(self, event=None):
        """Exit application"""
        if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
            self.cleanup()
            self.root.destroy()
            sys.exit(0)

    def cleanup(self):
        """Clean up resources before exit"""
        logger.info("Cleaning up resources...")
        try:
            # Stop security monitor
            if hasattr(self, 'security_monitor'):
                self.security_monitor.stop()
            
            # Close database connections
            if hasattr(self, 'db'):
                self.db.close_all()
                
            logger.info("Cleanup completed")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    # --- Feature Methods ---
    def new_project(self, event=None):
        self.show_panel('projects')
        # Here you would typically trigger the 'New Project' dialog in the projects manager
    
    def new_credential(self, event=None):
        self.show_panel('credentials')
        # Trigger new credential dialog
        
    def new_note(self, event=None):
        self.show_panel('notes')
        # Trigger new note dialog

    def open_global_search(self, event=None):
        """Open global search dialog"""
        if not self.current_user_id:
            return
        
        try:
            from gui.global_search import GlobalSearchDialog
            GlobalSearchDialog(self.root, self)
        except Exception as e:
            logger.error(f"Failed to open global search: {e}")

    def change_theme(self, theme_id):
        """Change application theme"""
        self.theme_manager.apply_theme(theme_id)
        
        # Update root and main containers
        self.root.config(bg=self.theme_manager.colors['bg_medium'])
        self.main_container.config(bg=self.theme_manager.colors['bg_medium'])
        self.sidebar_frame.config(bg=self.theme_manager.colors['bg_dark'])
        self.main_content.config(bg=self.theme_manager.colors['bg_medium'])
        
        # Update menu bar colors
        self.menu_bar.config(bg=self.theme_manager.colors['bg_medium'],
                           fg=self.theme_manager.colors['fg_primary'])
        
        # Update status bar colors
        self.status_bar.config(bg=self.theme_manager.colors['bg_medium'])
        for widget in self.status_bar.winfo_children():
            widget.config(bg=self.theme_manager.colors['bg_medium'],
                         fg=self.theme_manager.colors['fg_secondary'])
        
        # Re-render sidebar to apply new colors
        if self.current_user_id:
            self.create_sidebar()
        
        # Re-render current panel to apply theme
        if self.current_panel:
            self.show_panel(self.current_panel)
    def show_about(self):
        messagebox.showinfo("About", "Secure OSINT Storage Pro\nVersion 2.0\n\nA secure tool for managing OSINT investigations.")

    def start_session_timer(self):
        def update_timer():
            if self.login_time and self.current_user_id:
                duration = datetime.now() - self.login_time
                self.timer_label.config(text=str(duration).split('.')[0])
                self.root.after(1000, update_timer)
        update_timer()

    def start_background_services(self):
        """Start background monitoring and backup"""
        # These are started by their respective managers' init or dedicated methods
        if hasattr(self, 'backup_manager'):
            # Scheduler is already started in BackupManager.__init__
            pass

    # --- Placeholder Actions ---
    def import_data(self, event=None): messagebox.showinfo("Info", "Import feature coming soon")
    def export_data(self, event=None): messagebox.showinfo("Info", "Export feature coming soon")
    def create_backup(self, event=None): self.backup_manager.create_backup(self.current_user_id, "manual")
    def restore_backup(self, event=None): messagebox.showinfo("Info", "Use backup manager to restore")
    def undo(self, event=None): pass
    def redo(self, event=None): pass
    def cut(self, event=None): self.root.focus_get().event_generate('<<Cut>>')
    def copy(self, event=None): self.root.focus_get().event_generate('<<Copy>>')
    def paste(self, event=None): self.root.focus_get().event_generate('<<Paste>>')
    def select_all(self, event=None): self.root.focus_get().event_generate('<<SelectAll>>')
    def find(self, event=None): pass
    def replace(self, event=None): pass
    def find_next(self, event=None): pass
    def refresh_view(self, event=None): 
        if self.current_panel: self.show_panel(self.current_panel)
    def zoom_in(self, event=None): pass
    def zoom_out(self, event=None): pass
    def zoom_reset(self, event=None): pass
