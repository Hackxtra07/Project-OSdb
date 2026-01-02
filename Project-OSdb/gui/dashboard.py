"""
Dashboard Panel - Overview of system status and quick stats
"""

import tkinter as tk
from tkinter import ttk
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class DashboardPanel:
    """Main dashboard overview"""
    
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        
        # Main layout
        self.container = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_medium'])
        self.container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        self.setup_header()
        self.setup_stats()
        self.setup_recent_activity()
        
    def setup_header(self):
        """Dashboard header"""
        header = tk.Frame(self.container, bg=self.app.theme_manager.colors['bg_medium'])
        header.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(header, text=f"Welcome back, {self.app.current_user['username']}", 
                font=("Arial", 24, "bold"),
                bg=self.app.theme_manager.colors['bg_medium'],
                fg=self.app.theme_manager.colors['fg_primary']).pack(side=tk.LEFT)
                
        tk.Label(header, text=datetime.now().strftime("%A, %B %d, %Y"),
                font=("Arial", 12),
                bg=self.app.theme_manager.colors['bg_medium'],
                fg=self.app.theme_manager.colors['fg_secondary']).pack(side=tk.RIGHT)

    def setup_stats(self):
        """System statistics"""
        stats_frame = tk.Frame(self.container, bg=self.app.theme_manager.colors['bg_medium'])
        stats_frame.pack(fill=tk.X, pady=10)
        
        # Get stats from DB
        try:
            stats = self.app.db.get_statistics(self.app.current_user_id)
        except:
            stats = {'credentials': {'total': 0}, 'notes': {'total': 0}, 'projects': {'total': 0}}
            
        # Create cards
        self.create_stat_card(stats_frame, "Credentials", str(stats.get('credentials', {}).get('total', 0)), 
                            "🔐", self.app.theme_manager.colors['accent_primary'], 0)
        self.create_stat_card(stats_frame, "Secure Notes", str(stats.get('notes', {}).get('total', 0)), 
                            "📝", self.app.theme_manager.colors['accent_success'], 1)
        self.create_stat_card(stats_frame, "Projects", str(stats.get('projects', {}).get('total', 0)), 
                            "📁", self.app.theme_manager.colors['accent_info'], 2)
        self.create_stat_card(stats_frame, "Security Score", "A+", 
                            "🛡️", self.app.theme_manager.colors['accent_warning'], 3)

    def create_stat_card(self, parent, title, value, icon, color, col):
        """Create a statistic card"""
        card = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_medium'], padx=20, pady=20)
        card.grid(row=0, column=col, padx=10, sticky="ew")
        parent.grid_columnconfigure(col, weight=1)
        
        tk.Label(card, text=icon, font=("Arial", 30), bg=self.app.theme_manager.colors['bg_medium'], fg=color).pack(anchor='w')
        tk.Label(card, text=value, font=("Arial", 24, "bold"), bg=self.app.theme_manager.colors['bg_medium'], 
                fg=self.app.theme_manager.colors['fg_primary']).pack(anchor='w', pady=(5,0))
        tk.Label(card, text=title, font=("Arial", 10), bg=self.app.theme_manager.colors['bg_medium'], 
                fg=self.app.theme_manager.colors['fg_secondary']).pack(anchor='w')

    def setup_recent_activity(self):
        """Recent activity log"""
        # Placeholder for now
        pass
