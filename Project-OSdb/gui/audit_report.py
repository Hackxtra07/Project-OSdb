"""
Credential Audit Report - Analyze credential security
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import logging
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

class CredentialAuditReport:
    """Credential security audit and report generation"""
    
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.db = app.db
        
        # Main frame
        self.frame = tk.Frame(parent, bg=app.theme_manager.colors['bg_medium'])
        self.frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header
        tk.Label(self.frame, text="Credential Security Audit Report",
                font=("Arial", 18, "bold"),
                bg=self.app.theme_manager.colors['bg_medium'],
                fg=self.app.theme_manager.colors['fg_primary']).pack(pady=(0, 20))
        
        # Build audit report
        self.build_report()
    
    def build_report(self):
        """Build credential audit report"""
        # Create notebook for different views
        notebook = ttk.Notebook(self.frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Tab 1: Overview
        overview_frame = tk.Frame(notebook, bg=self.app.theme_manager.colors['bg_medium'])
        notebook.add(overview_frame, text="Overview")
        self.build_overview(overview_frame)
        
        # Tab 2: Weak Passwords
        weak_frame = tk.Frame(notebook, bg=self.app.theme_manager.colors['bg_medium'])
        notebook.add(weak_frame, text="Weak Passwords")
        self.build_weak_passwords(weak_frame)
        
        # Tab 3: Outdated Passwords
        outdated_frame = tk.Frame(notebook, bg=self.app.theme_manager.colors['bg_medium'])
        notebook.add(outdated_frame, text="Outdated Passwords")
        self.build_outdated_passwords(outdated_frame)
        
        # Tab 4: Breach Check Status
        breach_frame = tk.Frame(notebook, bg=self.app.theme_manager.colors['bg_medium'])
        notebook.add(breach_frame, text="Breach Status")
        self.build_breach_status(breach_frame)
        
        # Button frame
        button_frame = tk.Frame(self.frame, bg=self.app.theme_manager.colors['bg_medium'])
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        tk.Button(button_frame, text="Export Report (PDF)", 
                 command=self.export_pdf,
                 bg=self.app.theme_manager.colors['accent_primary'],
                 fg="#ffffff", padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="Export Report (CSV)",
                 command=self.export_csv,
                 bg=self.app.theme_manager.colors['accent_primary'],
                 fg="#ffffff", padx=15, pady=8).pack(side=tk.LEFT, padx=5)
    
    def build_overview(self, parent):
        """Build overview statistics"""
        stats = self.get_statistics()
        
        content_frame = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_light'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Create stat cards
        stats_data = [
            ("Total Credentials", stats['total'], "#2196F3"),
            ("Weak Passwords", stats['weak_count'], "#f44336"),
            ("Outdated Passwords", stats['outdated_count'], "#ff9800"),
            ("Breached Passwords", stats['breached_count'], "#d32f2f"),
            ("Password Change Needed", stats['needs_change'], "#ff5722"),
        ]
        
        for i, (label, value, color) in enumerate(stats_data):
            self.create_stat_card(content_frame, label, value, color, i)
        
        # Security score
        score = self.calculate_security_score(stats)
        score_frame = tk.Frame(content_frame, bg=self.app.theme_manager.colors['bg_dark'],
                              relief=tk.RAISED, bd=2)
        score_frame.grid(row=2, column=0, columnspan=3, sticky='ew', padx=10, pady=20)
        
        tk.Label(score_frame, text=f"Overall Security Score: {score}%",
                font=("Arial", 16, "bold"),
                bg=self.app.theme_manager.colors['bg_dark'],
                fg=self.get_score_color(score)).pack(pady=20)
    
    def build_weak_passwords(self, parent):
        """List weak passwords"""
        content_frame = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_medium'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Get weak passwords
        query = """
            SELECT id, service, username, password_strength 
            FROM credentials 
            WHERE user_id = ? AND password_strength < 3
            ORDER BY password_strength ASC
        """
        results = self.db.execute_query(query, (self.app.current_user_id,))
        
        if not results:
            tk.Label(content_frame, text="No weak passwords found! ✓",
                    font=("Arial", 12),
                    bg=self.app.theme_manager.colors['bg_medium'],
                    fg=self.app.theme_manager.colors['accent_success']).pack(pady=20)
            return
        
        # Tree view
        columns = ("Service", "Username", "Strength")
        tree = ttk.Treeview(content_frame, columns=columns, height=15)
        tree.heading("#0", text="Weak Passwords")
        tree.heading("Service", text="Service")
        tree.heading("Username", text="Username")
        tree.heading("Strength", text="Strength Level")
        
        tree.column("#0", width=0, stretch=False)
        tree.column("Service", width=200)
        tree.column("Username", width=200)
        tree.column("Strength", width=150)
        
        strength_labels = {0: "Very Weak", 1: "Weak", 2: "Fair"}
        
        for row in results:
            tree.insert("", tk.END, values=(
                row['service'],
                row['username'],
                strength_labels.get(row['password_strength'], 'Unknown')
            ))
        
        tree.pack(fill=tk.BOTH, expand=True)
    
    def build_outdated_passwords(self, parent):
        """List outdated passwords"""
        content_frame = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_medium'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Get outdated passwords (not changed in 90 days)
        cutoff_date = (datetime.now() - timedelta(days=90)).isoformat()
        
        query = """
            SELECT id, service, username, password_last_changed
            FROM credentials 
            WHERE user_id = ? AND password_last_changed < ?
            ORDER BY password_last_changed ASC
        """
        results = self.db.execute_query(query, (self.app.current_user_id, cutoff_date))
        
        if not results:
            tk.Label(content_frame, text="All passwords updated within 90 days! ✓",
                    font=("Arial", 12),
                    bg=self.app.theme_manager.colors['bg_medium'],
                    fg=self.app.theme_manager.colors['accent_success']).pack(pady=20)
            return
        
        # Tree view
        columns = ("Service", "Username", "Last Changed (Days Ago)")
        tree = ttk.Treeview(content_frame, columns=columns, height=15)
        tree.heading("#0", text="Outdated Passwords")
        tree.heading("Service", text="Service")
        tree.heading("Username", text="Username")
        tree.heading("Last Changed (Days Ago)", text="Days Since Change")
        
        tree.column("#0", width=0, stretch=False)
        tree.column("Service", width=200)
        tree.column("Username", width=200)
        tree.column("Last Changed (Days Ago)", width=150)
        
        for row in results:
            days_ago = (datetime.now() - datetime.fromisoformat(row['password_last_changed'])).days
            tree.insert("", tk.END, values=(
                row['service'],
                row['username'],
                f"{days_ago} days"
            ))
        
        tree.pack(fill=tk.BOTH, expand=True)
    
    def build_breach_status(self, parent):
        """Show breach check status"""
        content_frame = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_medium'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        query = """
            SELECT id, service, username, breach_check_result, last_breach_check
            FROM credentials 
            WHERE user_id = ?
            ORDER BY last_breach_check DESC
        """
        results = self.db.execute_query(query, (self.app.current_user_id,))
        
        # Tree view
        columns = ("Service", "Username", "Status", "Last Checked")
        tree = ttk.Treeview(content_frame, columns=columns, height=15)
        tree.heading("#0", text="Breach Check Status")
        tree.heading("Service", text="Service")
        tree.heading("Username", text="Username")
        tree.heading("Status", text="Status")
        tree.heading("Last Checked", text="Last Checked")
        
        tree.column("#0", width=0, stretch=False)
        tree.column("Service", width=150)
        tree.column("Username", width=150)
        tree.column("Status", width=100)
        tree.column("Last Checked", width=150)
        
        for row in results:
            status = row['breach_check_result'] or 'Not Checked'
            last_checked = row['last_breach_check'] or 'Never'
            tree.insert("", tk.END, values=(
                row['service'],
                row['username'],
                status,
                last_checked
            ))
        
        tree.pack(fill=tk.BOTH, expand=True)
    
    def get_statistics(self):
        """Get credential statistics"""
        query = "SELECT COUNT(*) as total FROM credentials WHERE user_id = ?"
        total_result = self.db.execute_query(query, (self.app.current_user_id,), fetch_all=False)
        
        query = "SELECT COUNT(*) as count FROM credentials WHERE user_id = ? AND password_strength < 3"
        weak_result = self.db.execute_query(query, (self.app.current_user_id,), fetch_all=False)
        
        query = "SELECT COUNT(*) as count FROM credentials WHERE user_id = ? AND password_last_changed < ?"
        cutoff = (datetime.now() - timedelta(days=90)).isoformat()
        outdated_result = self.db.execute_query(query, (self.app.current_user_id, cutoff), fetch_all=False)
        
        query = "SELECT COUNT(*) as count FROM credentials WHERE user_id = ? AND breach_check_result = 'breached'"
        breached_result = self.db.execute_query(query, (self.app.current_user_id,), fetch_all=False)
        
        needs_change = weak_result['count'] + outdated_result['count']
        
        return {
            'total': total_result['total'] or 0,
            'weak_count': weak_result['count'] or 0,
            'outdated_count': outdated_result['count'] or 0,
            'breached_count': breached_result['count'] or 0,
            'needs_change': needs_change or 0
        }
    
    def calculate_security_score(self, stats):
        """Calculate overall security score (0-100)"""
        if stats['total'] == 0:
            return 100
        
        total = stats['total']
        score = 100
        
        # Deduct points for weak passwords
        score -= (stats['weak_count'] / total) * 20
        
        # Deduct points for outdated passwords
        score -= (stats['outdated_count'] / total) * 15
        
        # Deduct points for breached passwords
        score -= (stats['breached_count'] / total) * 25
        
        return max(0, int(score))
    
    def get_score_color(self, score):
        """Get color for security score"""
        if score >= 80:
            return '#4caf50'  # Green
        elif score >= 60:
            return '#ff9800'  # Orange
        else:
            return '#f44336'  # Red
    
    def create_stat_card(self, parent, title, value, color, column):
        """Create a statistic card"""
        card = tk.Frame(parent, bg=color, relief=tk.RAISED, bd=2)
        card.grid(row=0, column=column, sticky='ew', padx=10, pady=10)
        parent.grid_columnconfigure(column, weight=1)
        
        tk.Label(card, text=str(value), font=("Arial", 24, "bold"),
                bg=color, fg="#ffffff").pack(pady=(10, 0))
        tk.Label(card, text=title, font=("Arial", 10),
                bg=color, fg="#ffffff").pack(pady=(0, 10))
    
    def export_pdf(self):
        """Export report as PDF"""
        try:
            messagebox.showinfo("Export", "PDF export functionality coming soon!")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")
    
    def export_csv(self):
        """Export report as CSV"""
        try:
            file = filedialog.asksaveasfilename(defaultextension=".csv",
                                               filetypes=[("CSV files", "*.csv")])
            if not file:
                return
            
            stats = self.get_statistics()
            
            with open(file, 'w') as f:
                f.write("Credential Audit Report\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n\n")
                f.write("Statistics\n")
                f.write(f"Total Credentials,{stats['total']}\n")
                f.write(f"Weak Passwords,{stats['weak_count']}\n")
                f.write(f"Outdated Passwords,{stats['outdated_count']}\n")
                f.write(f"Breached Passwords,{stats['breached_count']}\n")
            
            messagebox.showinfo("Success", f"Report exported to {file}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")
