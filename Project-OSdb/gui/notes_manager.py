"""
Notes Manager - Advanced note taking with encryption and versioning
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, font
import json
from datetime import datetime
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class NotesManager:
    """Advanced note management with encryption and version control"""
    
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.db = app.db
        self.encryption = app.encryption
        self.user_id = app.current_user_id
        
        # State
        self.current_note = None
        self.filter_category = "All"
        self.search_term = ""
        
        # Create main frame
        self.main_frame = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_light'])
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Build UI
        self.build_ui()
        
        # Load data
        self.load_notes()
        self.load_categories()
    
    def build_ui(self):
        """Build notes interface"""
        # Split pane
        paned = tk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL, sashrelief='raised', sashwidth=5)
        paned.pack(fill=tk.BOTH, expand=True)
        
        # Left sidebar (List)
        sidebar = tk.Frame(paned, bg=self.app.theme_manager.colors['bg_light'], width=300)
        self.create_sidebar(sidebar)
        paned.add(sidebar)
        
        # Right content (Editor)
        content = tk.Frame(paned, bg=self.app.theme_manager.colors['bg_light'])
        self.create_editor(content)
        paned.add(content)
        
        # Set sash position
        paned.sash_place(0, 300, 0)

    def create_sidebar(self, parent):
        """Create sidebar with notes list"""
        # Toolbar
        toolbar = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_medium'])
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(toolbar, text="➕ New Note", command=self.new_note,
                 bg=self.app.theme_manager.colors['accent_success'],
                 fg=self.app.theme_manager.colors['fg_primary']).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Search & Filter
        filter_frame = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_light'])
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.search_var = tk.StringVar()
        entry = tk.Entry(filter_frame, textvariable=self.search_var)
        entry.pack(fill=tk.X, pady=(0, 5))
        entry.bind('<KeyRelease>', self.on_search)
        
        self.cat_filter_var = tk.StringVar(value="All")
        self.cat_filter = ttk.Combobox(filter_frame, textvariable=self.cat_filter_var, state="readonly")
        self.cat_filter.pack(fill=tk.X)
        self.cat_filter.bind('<<ComboboxSelected>>', self.on_filter)
        
        # Notes List
        self.notes_list = ttk.Treeview(parent, columns=("Title", "Date"), show="headings")
        self.notes_list.heading("Title", text="Title")
        self.notes_list.heading("Date", text="Updated")
        self.notes_list.column("Title", width=180)
        self.notes_list.column("Date", width=100)
        
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.notes_list.yview)
        self.notes_list.configure(yscrollcommand=scrollbar.set)
        
        self.notes_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        self.notes_list.bind('<<TreeviewSelect>>', self.on_select_note)
        
    def create_editor(self, parent):
        """Create note editor"""
        # Header (Title & Actions)
        header = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_light'])
        header.pack(fill=tk.X, padx=10, pady=10)
        
        # Title Entry
        self.title_var = tk.StringVar()
        tk.Entry(header, textvariable=self.title_var, font=("Arial", 14, "bold"),
                bg=self.app.theme_manager.colors['bg_light'],
                fg=self.app.theme_manager.colors['fg_primary'],
                relief="flat").pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Toolbar actions
        actions = tk.Frame(header, bg=self.app.theme_manager.colors['bg_light'])
        actions.pack(side=tk.RIGHT)
        
        buttons = [
            ("💾 Save", self.save_note, self.app.theme_manager.colors['accent_primary']),
            ("🗑️ Delete", self.delete_note, self.app.theme_manager.colors['accent_danger']),
            ("📄 Export", self.export_note, self.app.theme_manager.colors['accent_info']),
            ("🔒 Encrypt", self.toggle_encryption, self.app.theme_manager.colors['accent_warning']),
            ("🕰️ History", self.view_history, "#9C27B0")
        ]
        
        for text, cmd, color in buttons:
            tk.Button(actions, text=text, command=cmd, bg=color,
                     fg=self.app.theme_manager.colors['fg_primary'],
                     font=("Arial", 9)).pack(side=tk.LEFT, padx=2)
            
        # Meta info
        meta_frame = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_light'])
        meta_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Category
        tk.Label(meta_frame, text="Category:", bg=self.app.theme_manager.colors['bg_light'],
                fg=self.app.theme_manager.colors['fg_secondary']).pack(side=tk.LEFT)
        self.category_var = tk.StringVar()
        self.category_combo = ttk.Combobox(meta_frame, textvariable=self.category_var, width=15)
        self.category_combo.pack(side=tk.LEFT, padx=5)
        
        # Tags
        tk.Label(meta_frame, text="Tags:", bg=self.app.theme_manager.colors['bg_light'],
                fg=self.app.theme_manager.colors['fg_secondary']).pack(side=tk.LEFT, padx=(10, 0))
        self.tags_var = tk.StringVar()
        tk.Entry(meta_frame, textvariable=self.tags_var, width=30).pack(side=tk.LEFT, padx=5)
        
        # Formatting Toolbar
        format_bar = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_medium'])
        format_bar.pack(fill=tk.X, padx=10)
        
        formats = [
            ("B", self.bold_text), ("I", self.italic_text), ("U", self.underline_text)
        ]
        for text, cmd in formats:
            tk.Button(format_bar, text=text, command=cmd, width=3,
                     font=("Times", 10, "bold")).pack(side=tk.LEFT, padx=1)

        # Editor Text Area
        self.editor = tk.Text(parent, font=("Arial", 11), wrap=tk.WORD,
                             undo=True, bg=self.app.theme_manager.colors['bg_light'],
                             fg=self.app.theme_manager.colors['fg_primary'])
        self.editor.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Scrollbar for editor
        scroll = ttk.Scrollbar(parent, orient="vertical", command=self.editor.yview)
        self.editor.configure(yscrollcommand=scroll.set)
        
        # Status
        self.status = tk.Label(parent, text="Ready", anchor='e',
                              bg=self.app.theme_manager.colors['bg_medium'],
                              fg=self.app.theme_manager.colors['fg_secondary'])
        self.status.pack(fill=tk.X)

        # Configure tags for formatting
        self.editor.tag_configure("bold", font=("Arial", 11, "bold"))
        self.editor.tag_configure("italic", font=("Arial", 11, "italic"))
        self.editor.tag_configure("underline", underline=True)

    def load_notes(self):
        """Load notes list"""
        self.notes_list.delete(*self.notes_list.get_children())
        query = "SELECT id, title, last_modified, category FROM secure_notes WHERE user_id = ?"
        params = [self.user_id]
        
        if self.filter_category != "All":
            query += " AND category = ?"
            params.append(self.filter_category)
            
        if self.search_term:
            query += " AND (title LIKE ? OR tags LIKE ?)"
            term = f"%{self.search_term}%"
            params.extend([term, term])
            
        query += " ORDER BY last_modified DESC"
        
        results = self.db.execute_query(query, params)
        for row in results:
            self.notes_list.insert("", tk.END, values=(row['title'], row['last_modified']), iid=row['id'])

    def load_categories(self):
        """Load categories"""
        query = "SELECT DISTINCT category FROM secure_notes WHERE user_id = ?"
        results = self.db.execute_query(query, (self.user_id,))
        cats = ["All"] + [r['category'] for r in results if r['category']]
        self.cat_filter['values'] = cats
        self.category_combo['values'] = cats[1:] # Exclude 'All' for editor

    def new_note(self):
        """Reset editor for new note"""
        self.current_note = None
        self.title_var.set("Untitled Note")
        self.category_var.set("General")
        self.tags_var.set("")
        self.editor.delete("1.0", tk.END)
        self.status.config(text="New Note")

    def save_note(self):
        """Save current note"""
        title = self.title_var.get().strip() or "Untitled"
        content = self.editor.get("1.0", tk.END).strip()
        category = self.category_var.get() or "General"
        tags = json.dumps([t.strip() for t in self.tags_var.get().split(",") if t.strip()])
        
        # Encrypt content
        encrypted_content = self.encryption.encrypt_data(content, self.app.user_key)
        
        if self.current_note:
            query = """
                UPDATE secure_notes 
                SET title=?, content_encrypted=?, category=?, tags=?, last_modified=CURRENT_TIMESTAMP
                WHERE id=? AND user_id=?
            """
            self.db.execute_query(query, (title, encrypted_content, category, tags, self.current_note['id'], self.user_id))
        else:
            query = """
                INSERT INTO secure_notes (user_id, title, content_encrypted, category, tags)
                VALUES (?, ?, ?, ?, ?)
            """
            self.db.execute_query(query, (self.user_id, title, encrypted_content, category, tags))
            
        self.load_notes()
        self.load_categories()
        messagebox.showinfo("Saved", "Note saved successfully!")

    def on_select_note(self, event):
        """Load selected note"""
        sel = self.notes_list.selection()
        if not sel: return
        note_id = sel[0]
        
        query = "SELECT * FROM secure_notes WHERE id = ?"
        row = self.db.execute_query(query, (note_id,), fetch_all=False)
        if row:
            self.current_note = dict(row)
            self.title_var.set(row['title'])
            self.category_var.set(row['category'])
            tags = json.loads(row['tags']) if row['tags'] else []
            self.tags_var.set(", ".join(tags))
            
            try:
                content = self.encryption.decrypt_data(row['content_encrypted'], self.app.user_key)
                self.editor.delete("1.0", tk.END)
                self.editor.insert("1.0", content)
            except Exception as e:
                messagebox.showerror("Error", "Failed to decrypt note!")
                logger.error(f"Decryption failed: {e}")

    def delete_note(self):
        """Delete current note"""
        if not self.current_note: return
        if messagebox.askyesno("Confirm", "Delete this note?"):
            self.db.execute_query("DELETE FROM secure_notes WHERE id=?", (self.current_note['id'],))
            self.new_note()
            self.load_notes()

    def export_note(self):
        """Export note to file"""
        if not self.editor.get("1.0", tk.END).strip(): return
        
        f = filedialog.asksaveasfilename(defaultextension=".txt", 
                                       filetypes=[("Text", "*.txt"), ("HTML", "*.html")])
        if not f: return
        
        content = self.editor.get("1.0", tk.END)
        if f.endswith(".html"):
            content = f"<html><body><h1>{self.title_var.get()}</h1><pre>{content}</pre></body></html>"
            
        with open(f, "w") as file:
            file.write(content)
            
    def toggle_encryption(self):
        """Toggle encryption status (Dummy implementation as all are encrypted in DB)"""
        # In this implementation, everything is encrypted at rest in DB.
        # This could be used for 'visual' locking or additional password protection in future.
        messagebox.showinfo("Info", "All notes are automatically encrypted in the database.")

    def view_history(self):
        """View version history"""
        if not self.current_note: return
        # Placeholder
        messagebox.showinfo("History", f"Version: {self.current_note.get('version', 1)}\nLast Modified: {self.current_note.get('last_modified')}")

    def bold_text(self):
        self._toggle_tag("bold")
        
    def italic_text(self):
        self._toggle_tag("italic")
        
    def underline_text(self):
        self._toggle_tag("underline")

    def _toggle_tag(self, tag):
        try:
            if self.editor.tag_ranges("sel"):
                current_tags = self.editor.tag_names("sel.first")
                if tag in current_tags:
                    self.editor.tag_remove(tag, "sel.first", "sel.last")
                else:
                    self.editor.tag_add(tag, "sel.first", "sel.last")
        except: pass

    def on_search(self, event):
        self.search_term = self.search_var.get()
        self.load_notes()

    def on_filter(self, event):
        self.filter_category = self.cat_filter_var.get()
        self.load_notes()
