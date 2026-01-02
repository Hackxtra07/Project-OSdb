"""
Global Search - Search across all data (credentials, notes, projects)
"""

import tkinter as tk
from tkinter import ttk
import logging

logger = logging.getLogger(__name__)

class GlobalSearchDialog:
    """Global search across all application data"""
    
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.db = app.db
        self.results = []
        
        # Create dialog
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Global Search")
        self.dialog.geometry("800x600")
        self.dialog.resizable(True, True)
        
        # Center on screen
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (800 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (600 // 2)
        self.dialog.geometry(f"+{x}+{y}")
        
        # Configure style
        bg_color = app.theme_manager.colors['bg_medium']
        fg_color = app.theme_manager.colors['fg_primary']
        self.dialog.config(bg=bg_color)
        
        # Create UI
        self.build_ui(bg_color, fg_color)
        
    def build_ui(self, bg_color, fg_color):
        """Build search interface"""
        # Search box
        search_frame = tk.Frame(self.dialog, bg=bg_color)
        search_frame.pack(fill=tk.X, padx=20, pady=15)
        
        tk.Label(search_frame, text="Search:", bg=bg_color, fg=fg_color).pack(side=tk.LEFT, padx=(0, 10))
        
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.on_search)
        
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, width=50, font=("Arial", 11))
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        search_entry.focus()
        
        # Filter options
        filter_frame = tk.Frame(self.dialog, bg=bg_color)
        filter_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(filter_frame, text="Filter by:", bg=bg_color, fg=fg_color).pack(side=tk.LEFT, padx=(0, 10))
        
        self.filter_var = tk.StringVar(value="All")
        filters = ["All", "Credentials", "Notes", "Projects"]
        
        for f in filters:
            tk.Radiobutton(filter_frame, text=f, variable=self.filter_var, value=f,
                          command=self.on_search, bg=bg_color, fg=fg_color).pack(side=tk.LEFT, padx=5)
        
        # Results area
        results_frame = tk.Frame(self.dialog, bg=bg_color)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))
        
        # Results treeview
        columns = ("Type", "Name", "Details")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, height=20)
        self.results_tree.heading("#0", text="Results")
        self.results_tree.heading("Type", text="Type")
        self.results_tree.heading("Name", text="Name/Service")
        self.results_tree.heading("Details", text="Details")
        
        self.results_tree.column("#0", width=0, stretch=False)
        self.results_tree.column("Type", width=80)
        self.results_tree.column("Name", width=250)
        self.results_tree.column("Details", width=350)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscroll=scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click to open result
        self.results_tree.bind("<Double-1>", self.on_result_double_click)
        
        # Status bar
        self.status_label = tk.Label(self.dialog, text="Ready to search",
                                    bg=bg_color, fg=fg_color, anchor='w')
        self.status_label.pack(fill=tk.X, padx=20, pady=(0, 10))
    
    def on_search(self, *args):
        """Perform search"""
        search_term = self.search_var.get().strip()
        filter_type = self.filter_var.get()
        
        if not search_term or len(search_term) < 2:
            self.results_tree.delete(*self.results_tree.get_children())
            self.status_label.config(text="Enter at least 2 characters to search")
            return
        
        self.results = []
        
        # Search credentials
        if filter_type in ["All", "Credentials"]:
            self.search_credentials(search_term)
        
        # Search notes
        if filter_type in ["All", "Notes"]:
            self.search_notes(search_term)
        
        # Search projects
        if filter_type in ["All", "Projects"]:
            self.search_projects(search_term)
        
        # Display results
        self.display_results()
    
    def search_credentials(self, search_term):
        """Search in credentials"""
        query = """
            SELECT id, service, username, url, category 
            FROM credentials 
            WHERE user_id = ? AND (
                service LIKE ? OR 
                username LIKE ? OR 
                url LIKE ? OR 
                category LIKE ?
            )
            LIMIT 50
        """
        term = f"%{search_term}%"
        results = self.db.execute_query(query, 
                                       (self.app.current_user_id, term, term, term, term))
        
        for row in results:
            self.results.append({
                'type': 'Credential',
                'name': row['service'],
                'details': f"Username: {row['username']} | Category: {row['category']}",
                'id': row['id'],
                'data': row
            })
    
    def search_notes(self, search_term):
        """Search in notes"""
        query = """
            SELECT id, title, category, tags
            FROM secure_notes 
            WHERE user_id = ? AND (
                title LIKE ? OR 
                tags LIKE ? OR 
                category LIKE ?
            )
            LIMIT 50
        """
        term = f"%{search_term}%"
        results = self.db.execute_query(query,
                                       (self.app.current_user_id, term, term, term))
        
        for row in results:
            self.results.append({
                'type': 'Note',
                'name': row['title'],
                'details': f"Category: {row['category']} | Tags: {row['tags']}",
                'id': row['id'],
                'data': row
            })
    
    def search_projects(self, search_term):
        """Search in projects"""
        query = """
            SELECT id, name, status, description
            FROM projects 
            WHERE user_id = ? AND (
                name LIKE ? OR 
                description LIKE ? OR 
                status LIKE ?
            )
            LIMIT 50
        """
        term = f"%{search_term}%"
        results = self.db.execute_query(query,
                                       (self.app.current_user_id, term, term, term))
        
        for row in results:
            self.results.append({
                'type': 'Project',
                'name': row['name'],
                'details': f"Status: {row['status']} | {row['description'][:50]}...",
                'id': row['id'],
                'data': row
            })
    
    def display_results(self):
        """Display search results"""
        # Clear tree
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Add results
        for result in self.results:
            self.results_tree.insert("", tk.END, values=(
                result['type'],
                result['name'],
                result['details']
            ), tags=(result['id'],))
        
        # Update status
        count = len(self.results)
        self.status_label.config(text=f"Found {count} result(s)")
    
    def on_result_double_click(self, event):
        """Open selected result"""
        selection = self.results_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        result_id = self.results_tree.item(item, "tags")[0]
        
        # Find result in list
        for result in self.results:
            if str(result['id']) == result_id:
                result_type = result['type']
                
                if result_type == 'Credential':
                    # Show credential details (could open in parent)
                    pass
                elif result_type == 'Note':
                    # Load note
                    pass
                elif result_type == 'Project':
                    # Load project
                    pass
                
                break
