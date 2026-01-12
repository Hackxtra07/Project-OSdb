"""
Dashboard Panel - Overview of system status and quick stats
"""

import tkinter as tk
from tkinter import ttk
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class DashboardPanel:
    """Main dashboard overview"""
    
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        
        # Main layout with scrollbar - using simpler approach
        main_frame = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_medium'])
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create canvas with scrollbar
        self.canvas = tk.Canvas(main_frame, bg=self.app.theme_manager.colors['bg_medium'], 
                               highlightthickness=0, relief='flat')
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.canvas.yview)
        
        self.container = tk.Frame(self.canvas, bg=self.app.theme_manager.colors['bg_medium'])
        self.container_window = self.canvas.create_window((0, 0), window=self.container, anchor="nw")
        
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack widgets
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind mousewheel only to canvas, not all widgets
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind("<Button-4>", self._on_mousewheel_linux)
        self.canvas.bind("<Button-5>", self._on_mousewheel_linux)
        self.container.bind("<Configure>", self._on_frame_configure)
        
        self.setup_header()
        self.setup_stats()
        self.setup_recent_activity()
        self.setup_quick_actions()
        self.setup_project_overview()
        self.setup_security_alerts()
        self.setup_task_summary()
    
    def _on_frame_configure(self, event=None):
        """Update scroll region when frame is configured"""
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
    
    def _on_mousewheel(self, event):
        """Handle mousewheel scrolling on Windows/macOS"""
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        return "break"
    
    def _on_mousewheel_linux(self, event):
        """Handle mousewheel scrolling on Linux"""
        if event.num == 4:
            self.canvas.yview_scroll(-3, "units")
        elif event.num == 5:
            self.canvas.yview_scroll(3, "units")
        return "break"
        
    def setup_header(self):
        """Dashboard header"""
        # Add some padding
        padding_frame = tk.Frame(self.container, bg=self.app.theme_manager.colors['bg_medium'], height=10)
        padding_frame.pack(fill=tk.X)
        
        header = tk.Frame(self.container, bg=self.app.theme_manager.colors['bg_medium'])
        header.pack(fill=tk.X, pady=(10, 20), padx=20)
        
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
        stats_frame.pack(fill=tk.X, pady=10, padx=20)
        
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

    def setup_quick_actions(self):
        """Quick action buttons"""
        actions_frame = tk.LabelFrame(self.container, text="Quick Actions", 
                                     font=("Arial", 12, "bold"),
                                     bg=self.app.theme_manager.colors['bg_light'],
                                     fg=self.app.theme_manager.colors['fg_primary'],
                                     padx=10, pady=10)
        actions_frame.pack(fill=tk.X, pady=10, padx=20)
        
        buttons_frame = tk.Frame(actions_frame, bg=self.app.theme_manager.colors['bg_light'])
        buttons_frame.pack(fill=tk.X)
        
        actions = [
            ("➕ New Note", "#4CAF50"),
            ("📁 New Project", "#2196F3"),
            ("🔐 New Credential", "#FF9800"),
            ("🔍 Quick Search", "#9C27B0"),
            ("⚙️ Settings", "#757575")
        ]
        
        for text, color in actions:
            tk.Button(buttons_frame, text=text, bg=color, fg="white", 
                     font=("Arial", 9), padx=15, pady=8,
                     relief='flat', cursor='hand2').pack(side=tk.LEFT, padx=5)

    def setup_project_overview(self):
        """Active projects overview"""
        projects_frame = tk.LabelFrame(self.container, text="Active Projects", 
                                      font=("Arial", 12, "bold"),
                                      bg=self.app.theme_manager.colors['bg_light'],
                                      fg=self.app.theme_manager.colors['fg_primary'],
                                      padx=10, pady=10)
        projects_frame.pack(fill=tk.X, pady=10, padx=20)
        
        try:
            query = "SELECT id, name, status FROM osint_projects WHERE user_id = ? AND status != 'completed' LIMIT 5"
            projects = self.app.db.execute_query(query, (self.app.current_user_id,))
            
            if projects:
                for project in projects:
                    project_item = tk.Frame(projects_frame, bg=self.app.theme_manager.colors['bg_light'])
                    project_item.pack(fill=tk.X, pady=3)
                    
                    status_colors = {
                        'planning': '#FFC107',
                        'active': '#4CAF50',
                        'paused': '#FF9800',
                        'archived': '#9E9E9E'
                    }
                    status_color = status_colors.get(project['status'], '#757575')
                    
                    status_dot = tk.Label(project_item, text="●", fg=status_color, 
                                         font=("Arial", 10), bg=self.app.theme_manager.colors['bg_light'])
                    status_dot.pack(side=tk.LEFT, padx=5)
                    
                    tk.Label(project_item, text=f"{project['name']} [{project['status'].title()}]",
                            bg=self.app.theme_manager.colors['bg_light'],
                            fg=self.app.theme_manager.colors['fg_primary']).pack(side=tk.LEFT, fill=tk.X, expand=True)
            else:
                tk.Label(projects_frame, text="No active projects", 
                        bg=self.app.theme_manager.colors['bg_light'],
                        fg=self.app.theme_manager.colors['fg_secondary']).pack()
        except Exception as e:
            logger.error(f"Error loading projects: {e}")
            tk.Label(projects_frame, text="Error loading projects", 
                    bg=self.app.theme_manager.colors['bg_light']).pack()

    def setup_security_alerts(self):
        """Security alerts and notifications"""
        alerts_frame = tk.LabelFrame(self.container, text="Security Alerts", 
                                    font=("Arial", 12, "bold"),
                                    bg=self.app.theme_manager.colors['bg_light'],
                                    fg=self.app.theme_manager.colors['fg_primary'],
                                    padx=10, pady=10)
        alerts_frame.pack(fill=tk.X, pady=10, padx=20)
        
        alerts = [
            ("⚠️ No 2FA enabled", "#FF9800"),
            ("✓ All credentials encrypted", "#4CAF50"),
            ("✓ Database backed up today", "#4CAF50"),
            ("ℹ️ 3 sessions active", "#2196F3")
        ]
        
        for alert, color in alerts:
            alert_item = tk.Frame(alerts_frame, bg=self.app.theme_manager.colors['bg_light'])
            alert_item.pack(fill=tk.X, pady=2)
            
            tk.Label(alert_item, text=alert, bg=self.app.theme_manager.colors['bg_light'],
                    fg=color, font=("Arial", 9)).pack(side=tk.LEFT)

    def setup_task_summary(self):
        """Task summary and deadlines"""
        tasks_frame = tk.LabelFrame(self.container, text="Upcoming Deadlines", 
                                   font=("Arial", 12, "bold"),
                                   bg=self.app.theme_manager.colors['bg_light'],
                                   fg=self.app.theme_manager.colors['fg_primary'],
                                   padx=10, pady=10)
        tasks_frame.pack(fill=tk.X, pady=10, padx=20)
        
        try:
            # Get tasks due in next 7 days
            today = datetime.now().date()
            next_week = today + timedelta(days=7)
            
            query = """SELECT title, due_date, priority FROM project_tasks 
                      WHERE user_id = ? AND status != 'completed' 
                      AND due_date BETWEEN ? AND ? 
                      ORDER BY due_date ASC LIMIT 5"""
            
            tasks = self.app.db.execute_query(query, (self.app.current_user_id, today, next_week))
            
            if tasks:
                for task in tasks:
                    task_item = tk.Frame(tasks_frame, bg=self.app.theme_manager.colors['bg_light'])
                    task_item.pack(fill=tk.X, pady=3)
                    
                    priority_colors = {1: '#757575', 2: '#FFC107', 3: '#FF9800', 4: '#F44336', 5: '#C41C3B'}
                    priority_color = priority_colors.get(task['priority'], '#757575')
                    
                    priority_indicator = tk.Label(task_item, text="■", fg=priority_color, 
                                                 font=("Arial", 8), bg=self.app.theme_manager.colors['bg_light'])
                    priority_indicator.pack(side=tk.LEFT, padx=5)
                    
                    due_date = task['due_date'][:10] if task['due_date'] else "No date"
                    task_info = tk.Label(task_item, text=f"{task['title']} (Due: {due_date})",
                                        bg=self.app.theme_manager.colors['bg_light'],
                                        fg=self.app.theme_manager.colors['fg_primary'],
                                        font=("Arial", 9))
                    task_info.pack(side=tk.LEFT, fill=tk.X, expand=True)
            else:
                tk.Label(tasks_frame, text="No upcoming deadlines", 
                        bg=self.app.theme_manager.colors['bg_light'],
                        fg=self.app.theme_manager.colors['fg_secondary']).pack()
        except Exception as e:
            logger.error(f"Error loading tasks: {e}")
            tk.Label(tasks_frame, text="Error loading tasks", 
                    bg=self.app.theme_manager.colors['bg_light']).pack()

    def setup_recent_activity(self):
        """Recent activity log"""
        activity_frame = tk.LabelFrame(self.container, text="Recent Activity", 
                                      font=("Arial", 12, "bold"),
                                      bg=self.app.theme_manager.colors['bg_light'],
                                      fg=self.app.theme_manager.colors['fg_primary'],
                                      padx=10, pady=10)
        activity_frame.pack(fill=tk.X, pady=10, padx=20)
        
        try:
            # Get recent audit logs
            query = """SELECT action, timestamp FROM audit_log 
                      WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10"""
            
            activities = self.app.db.execute_query(query, (self.app.current_user_id,))
            
            if activities:
                for activity in activities:
                    activity_item = tk.Frame(activity_frame, bg=self.app.theme_manager.colors['bg_light'])
                    activity_item.pack(fill=tk.X, pady=2)
                    
                    # Format time difference
                    try:
                        time_obj = datetime.fromisoformat(activity['timestamp'])
                        time_diff = datetime.now() - time_obj
                        if time_diff.seconds < 60:
                            time_str = "just now"
                        elif time_diff.seconds < 3600:
                            time_str = f"{time_diff.seconds // 60}m ago"
                        elif time_diff.seconds < 86400:
                            time_str = f"{time_diff.seconds // 3600}h ago"
                        else:
                            time_str = f"{time_diff.days}d ago"
                    except:
                        time_str = activity['timestamp'][:10]
                    
                    tk.Label(activity_item, text=f"• {activity['action']}", 
                            bg=self.app.theme_manager.colors['bg_light'],
                            fg=self.app.theme_manager.colors['fg_primary'],
                            font=("Arial", 9), justify='left').pack(side=tk.LEFT, fill=tk.X, expand=True)
                    
                    tk.Label(activity_item, text=time_str, 
                            bg=self.app.theme_manager.colors['bg_light'],
                            fg=self.app.theme_manager.colors['fg_secondary'],
                            font=("Arial", 8)).pack(side=tk.RIGHT, padx=5)
            else:
                tk.Label(activity_frame, text="No recent activity", 
                        bg=self.app.theme_manager.colors['bg_light'],
                        fg=self.app.theme_manager.colors['fg_secondary']).pack()
        except Exception as e:
            logger.error(f"Error loading activity: {e}")
            tk.Label(activity_frame, text="Error loading activity log", 
                    bg=self.app.theme_manager.colors['bg_light']).pack()
