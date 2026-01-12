"""
Notes Manager - Advanced note taking with encryption, versioning, and file attachments
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, font, colorchooser
import json
from datetime import datetime
import logging
from typing import Optional, Dict, Any
import os
import sys
import shutil
from pathlib import Path

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
        self.attachments = {}
        self.formatting_data = {}
        
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
            ("🔄 Update", self.update_note, "#FF6F00"),
            ("🗑️ Delete", self.delete_note, self.app.theme_manager.colors['accent_danger']),
            ("📄 Export", self.export_note, self.app.theme_manager.colors['accent_info']),
            ("📎 Attach", self.attach_file, "#FF9800"),
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
        
        # Advanced Formatting Toolbar
        format_bar = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_medium'])
        format_bar.pack(fill=tk.X, padx=10, pady=5)
        
        # Text formatting buttons
        tk.Label(format_bar, text="Format:", bg=self.app.theme_manager.colors['bg_medium'],
                fg=self.app.theme_manager.colors['fg_primary']).pack(side=tk.LEFT, padx=5)
        
        format_buttons = [
            ("B", self.bold_text, "bold"),
            ("I", self.italic_text, "italic"),
            ("U", self.underline_text, "underline"),
            ("S", self.strikethrough_text, "strikethrough"),
            ("H", self.highlight_text, "highlight")
        ]
        
        for text, cmd, _ in format_buttons:
            tk.Button(format_bar, text=text, command=cmd, width=3,
                     font=("Times", 10, "bold"), bg="#E0E0E0").pack(side=tk.LEFT, padx=1)
        
        # Font size selector
        tk.Label(format_bar, text="Size:", bg=self.app.theme_manager.colors['bg_medium'],
                fg=self.app.theme_manager.colors['fg_primary']).pack(side=tk.LEFT, padx=(10, 5))
        
        self.font_size_var = tk.StringVar(value="11")
        size_combo = ttk.Combobox(format_bar, textvariable=self.font_size_var, 
                                 values=["8", "10", "11", "12", "14", "16", "18", "20"], 
                                 width=5, state="readonly")
        size_combo.pack(side=tk.LEFT, padx=2)
        size_combo.bind("<<ComboboxSelected>>", self.change_font_size)
        
        # Font color button
        tk.Button(format_bar, text="🎨 Color", command=self.change_text_color,
                 bg="#E0E0E0").pack(side=tk.LEFT, padx=5)
        
        # Background highlight color
        tk.Button(format_bar, text="🖍️ BG", command=self.change_bg_color,
                 bg="#E0E0E0").pack(side=tk.LEFT, padx=2)
        
        # Clear formatting
        tk.Button(format_bar, text="Clear", command=self.clear_formatting,
                 bg="#E0E0E0").pack(side=tk.LEFT, padx=5)

        # Editor Text Area with enhanced features
        editor_frame = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_light'])
        editor_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.editor = tk.Text(editor_frame, font=("Arial", 11), wrap=tk.WORD,
                             undo=True, bg=self.app.theme_manager.colors['bg_light'],
                             fg=self.app.theme_manager.colors['fg_primary'])
        self.editor.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar for editor
        scroll = ttk.Scrollbar(editor_frame, orient="vertical", command=self.editor.yview)
        self.editor.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Attachments Section
        attach_frame = tk.LabelFrame(parent, text="📎 Attachments", 
                                    bg=self.app.theme_manager.colors['bg_light'],
                                    fg=self.app.theme_manager.colors['fg_primary'],
                                    font=("Arial", 10, "bold"))
        attach_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.attachments_list = tk.Listbox(attach_frame, height=3,
                                          bg=self.app.theme_manager.colors['bg_light'],
                                          fg=self.app.theme_manager.colors['fg_primary'])
        self.attachments_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        attach_btn_frame = tk.Frame(attach_frame, bg=self.app.theme_manager.colors['bg_light'])
        attach_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(attach_btn_frame, text="➕ Add File", command=self.attach_file,
                 bg="#4CAF50", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(attach_btn_frame, text="🗑️ Remove", command=self.remove_attachment,
                 bg="#F44336", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(attach_btn_frame, text="📂 Open", command=self.open_attachment,
                 bg="#2196F3", fg="white").pack(side=tk.LEFT, padx=2)
        
        self.attachments_list.bind('<Double-1>', lambda e: self.open_attachment())
        
        # Status
        self.status = tk.Label(parent, text="Ready", anchor='e',
                              bg=self.app.theme_manager.colors['bg_medium'],
                              fg=self.app.theme_manager.colors['fg_secondary'])
        self.status.pack(fill=tk.X)

        # Configure tags for formatting
        self.editor.tag_configure("bold", font=("Arial", 11, "bold"))
        self.editor.tag_configure("italic", font=("Arial", 11, "italic"))
        self.editor.tag_configure("underline", underline=True)
        self.editor.tag_configure("strikethrough", overstrike=True)
        self.editor.tag_configure("highlight", background="yellow", foreground="black")
        
        # Color tags
        self.current_text_color = "#000000"
        self.current_bg_color = None
        
        # Store attachments
        self.attachments = {}

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
        self.attachments = {}
        self.formatting_data = {}
        self.attachments_list.delete(0, tk.END)
        # Remove all formatting tags from editor
        for tag in self.editor.tag_names():
            self.editor.tag_remove(tag, "1.0", tk.END)
        self.status.config(text="New Note")

    def save_note(self):
        """Save current note (creates new note)"""
        title = self.title_var.get().strip() or "Untitled"
        content = self.editor.get("1.0", tk.END).strip()
        category = self.category_var.get() or "General"
        tags = json.dumps([t.strip() for t in self.tags_var.get().split(",") if t.strip()])
        
        # Extract formatting information from the editor
        formatting_data = self._extract_formatting()
        
        # Encrypt content
        encrypted_content = self.encryption.encrypt_data(content, self.app.user_key)
        
        # Prepare metadata with attachments and formatting
        metadata = {
            'attachments': self.attachments,
            'formatting': formatting_data
        }
        metadata_json = json.dumps(metadata)
        
        # Always create a new note with Save button
        try:
            query = """
                INSERT INTO secure_notes (user_id, title, content_encrypted, category, tags, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            """
            result = self.db.execute_query(query, (self.user_id, title, encrypted_content, category, tags, metadata_json))
            
            # Get the newly created note ID and set current_note
            query_get_id = "SELECT * FROM secure_notes WHERE user_id = ? AND title = ? ORDER BY id DESC LIMIT 1"
            new_note = self.db.execute_query(query_get_id, (self.user_id, title), fetch_all=False)
            if new_note:
                self.current_note = dict(new_note)
                self.status.config(text="✓ New note created! Use 'Update' to modify it.")
            
            self.load_notes()
            self.load_categories()
            messagebox.showinfo("Saved", "New note created successfully!\n\nUse the 'Update' button to modify existing notes.")
        except Exception as e:
            logger.error(f"Failed to create note: {e}")
            messagebox.showerror("Error", f"Failed to save note: {e}")

    def update_note(self):
        """Update the currently loaded note"""
        if not self.current_note:
            messagebox.showwarning("Warning", "Please select a note to update")
            return
        
        title = self.title_var.get().strip() or "Untitled"
        content = self.editor.get("1.0", tk.END).strip()
        category = self.category_var.get() or "General"
        tags = json.dumps([t.strip() for t in self.tags_var.get().split(",") if t.strip()])
        
        # Extract formatting information from the editor
        formatting_data = self._extract_formatting()
        
        # Encrypt content
        encrypted_content = self.encryption.encrypt_data(content, self.app.user_key)
        
        # Prepare metadata with attachments and formatting
        metadata = {
            'attachments': self.attachments,
            'formatting': formatting_data
        }
        metadata_json = json.dumps(metadata)
        
        # Update the note
        try:
            query = """
                UPDATE secure_notes 
                SET title=?, content_encrypted=?, category=?, tags=?, last_modified=CURRENT_TIMESTAMP,
                    metadata=?
                WHERE id=? AND user_id=?
            """
            self.db.execute_query(query, (title, encrypted_content, category, tags, metadata_json, 
                                         self.current_note['id'], self.user_id))
            
            # Refresh current_note from database
            query_refresh = "SELECT * FROM secure_notes WHERE id = ?"
            updated_note = self.db.execute_query(query_refresh, (self.current_note['id'],), fetch_all=False)
            if updated_note:
                self.current_note = dict(updated_note)
            
            self.status.config(text="✓ Note updated successfully!")
            self.load_notes()
            self.load_categories()
            messagebox.showinfo("Updated", "Note updated successfully!")
        except Exception as e:
            logger.error(f"Failed to update note: {e}")
            messagebox.showerror("Error", f"Failed to update note: {e}")

    def on_select_note(self, event):
        """Load selected note"""
        sel = self.notes_list.selection()
        if not sel: return
        note_id = sel[0]
        
        query = "SELECT * FROM secure_notes WHERE id = ?"
        row = self.db.execute_query(query, (note_id,), fetch_all=False)
        if row:
            self.current_note = dict(row)
            title = row['title']
            self.title_var.set(title)
            self.category_var.set(row['category'])
            tags = json.loads(row['tags']) if row['tags'] else []
            self.tags_var.set(", ".join(tags))
            
            # Load attachments and formatting
            try:
                meta = json.loads(row['metadata']) if row['metadata'] else {}
                self.attachments = meta.get('attachments', {})
                self.formatting_data = meta.get('formatting', {})
            except:
                self.attachments = {}
                self.formatting_data = {}
            
            self.refresh_attachments_list()
            
            try:
                content = self.encryption.decrypt_data(row['content_encrypted'], self.app.user_key)
                self.editor.delete("1.0", tk.END)
                self.editor.insert("1.0", content)
                
                # Apply stored formatting
                self._apply_formatting()
                
                self.status.config(text=f"✓ Loaded: {title}")
            except Exception as e:
                messagebox.showerror("Error", "Failed to decrypt note!")
                logger.error(f"Decryption failed: {e}")

    def delete_note(self):
        """Delete current note"""
        if not self.current_note: return
        if messagebox.askyesno("Confirm", "Delete this note permanently?"):
            self.db.execute_query("DELETE FROM secure_notes WHERE id=?", (self.current_note['id'],))
            self.new_note()
            self.load_notes()
            self.status.config(text="✓ Note deleted")

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
        
        self.status.config(text=f"✓ Exported to {Path(f).name}")
        messagebox.showinfo("Exported", f"Note exported successfully!")
            
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

    def attach_file(self):
        """Attach file to note"""
        files = filedialog.askopenfilenames(title="Select files to attach")
        if not files:
            return
        
        for file_path in files:
            try:
                file_name = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)
                
                # Store file metadata
                self.attachments[file_name] = {
                    'path': file_path,
                    'size': file_size,
                    'added': datetime.now().isoformat()
                }
                
                self.refresh_attachments_list()
                self.status.config(text=f"✓ Attached: {file_name}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to attach file: {e}")
                logger.error(f"Attachment error: {e}")
    
    def refresh_attachments_list(self):
        """Refresh attachments display"""
        self.attachments_list.delete(0, tk.END)
        for name, info in self.attachments.items():
            size_kb = info['size'] / 1024
            self.attachments_list.insert(tk.END, f"📎 {name} ({size_kb:.1f} KB)")
    
    def remove_attachment(self):
        """Remove selected attachment"""
        sel = self.attachments_list.curselection()
        if not sel:
            messagebox.showwarning("Warning", "No attachment selected")
            return
        
        idx = sel[0]
        file_names = list(self.attachments.keys())
        if idx < len(file_names):
            file_name = file_names[idx]
            del self.attachments[file_name]
            self.refresh_attachments_list()
            self.status.config(text=f"✓ Removed: {file_name}")
    
    def open_attachment(self):
        """Open selected attachment"""
        sel = self.attachments_list.curselection()
        if not sel:
            messagebox.showwarning("Warning", "No attachment selected")
            return
        
        idx = sel[0]
        file_names = list(self.attachments.keys())
        if idx < len(file_names):
            file_name = file_names[idx]
            file_path = self.attachments[file_name]['path']
            
            if os.path.exists(file_path):
                try:
                    if os.name == 'nt':  # Windows
                        os.startfile(file_path)
                    elif os.name == 'posix':  # macOS and Linux
                        os.system(f'open "{file_path}"' if sys.platform == 'darwin' else f'xdg-open "{file_path}"')
                    self.status.config(text=f"✓ Opening: {file_name}")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not open file: {e}")
            else:
                messagebox.showerror("Error", "File not found")

    def bold_text(self):
        self._toggle_tag("bold")
        
    def italic_text(self):
        self._toggle_tag("italic")
        
    def underline_text(self):
        self._toggle_tag("underline")
    
    def strikethrough_text(self):
        self._toggle_tag("strikethrough")
    
    def highlight_text(self):
        self._toggle_tag("highlight")
    
    def change_text_color(self):
        """Change text color"""
        color = colorchooser.askcolor(color=self.current_text_color)
        if color[1]:
            self.current_text_color = color[1]
            try:
                if self.editor.tag_ranges("sel"):
                    tag_name = f"color_{color[1]}"
                    self.editor.tag_configure(tag_name, foreground=color[1])
                    self.editor.tag_add(tag_name, "sel.first", "sel.last")
                    self.status.config(text=f"✓ Text color changed")
            except:
                pass
    
    def change_bg_color(self):
        """Change background highlight color"""
        color = colorchooser.askcolor()
        if color[1]:
            self.current_bg_color = color[1]
            try:
                if self.editor.tag_ranges("sel"):
                    tag_name = f"bg_{color[1]}"
                    self.editor.tag_configure(tag_name, background=color[1])
                    self.editor.tag_add(tag_name, "sel.first", "sel.last")
                    self.status.config(text=f"✓ Background color changed")
            except:
                pass
    
    def change_font_size(self, event=None):
        """Change font size"""
        try:
            size = int(self.font_size_var.get())
            if self.editor.tag_ranges("sel"):
                tag_name = f"size_{size}"
                self.editor.tag_configure(tag_name, font=("Arial", size))
                self.editor.tag_add(tag_name, "sel.first", "sel.last")
                self.status.config(text=f"✓ Font size changed to {size}")
        except:
            pass
    
    def clear_formatting(self):
        """Clear all formatting from selected text"""
        try:
            if self.editor.tag_ranges("sel"):
                for tag in self.editor.tag_names("sel.first"):
                    if tag not in ("sel",):
                        self.editor.tag_remove(tag, "sel.first", "sel.last")
                self.status.config(text="✓ Formatting cleared")
        except:
            pass

    def _toggle_tag(self, tag):
        try:
            if self.editor.tag_ranges("sel"):
                current_tags = self.editor.tag_names("sel.first")
                if tag in current_tags:
                    self.editor.tag_remove(tag, "sel.first", "sel.last")
                else:
                    self.editor.tag_add(tag, "sel.first", "sel.last")
        except: pass

    def _extract_formatting(self):
        """Extract all formatting from the editor text"""
        formatting = {}
        
        # Get all text with positions
        content = self.editor.get("1.0", tk.END)
        
        # For each tag type, find all ranges
        for tag in ['bold', 'italic', 'underline', 'strikethrough', 'highlight']:
            ranges = self.editor.tag_ranges(tag)
            if ranges:
                tag_list = []
                for i in range(0, len(ranges), 2):
                    start = self.editor.index(ranges[i])
                    end = self.editor.index(ranges[i+1])
                    # Convert indices to character positions
                    start_pos = self._index_to_position(start, content)
                    end_pos = self._index_to_position(end, content)
                    tag_list.append({'start': start_pos, 'end': end_pos})
                if tag_list:
                    formatting[tag] = tag_list
        
        # Handle color tags
        for tag in self.editor.tag_names():
            if tag.startswith('color_'):
                ranges = self.editor.tag_ranges(tag)
                if ranges:
                    color = tag.replace('color_', '')
                    if 'colors' not in formatting:
                        formatting['colors'] = {}
                    color_list = []
                    for i in range(0, len(ranges), 2):
                        start = self.editor.index(ranges[i])
                        end = self.editor.index(ranges[i+1])
                        start_pos = self._index_to_position(start, content)
                        end_pos = self._index_to_position(end, content)
                        color_list.append({'start': start_pos, 'end': end_pos})
                    if color_list:
                        formatting['colors'][color] = color_list
        
        # Handle background colors
        for tag in self.editor.tag_names():
            if tag.startswith('bg_'):
                ranges = self.editor.tag_ranges(tag)
                if ranges:
                    bg_color = tag.replace('bg_', '')
                    if 'bg_colors' not in formatting:
                        formatting['bg_colors'] = {}
                    bg_list = []
                    for i in range(0, len(ranges), 2):
                        start = self.editor.index(ranges[i])
                        end = self.editor.index(ranges[i+1])
                        start_pos = self._index_to_position(start, content)
                        end_pos = self._index_to_position(end, content)
                        bg_list.append({'start': start_pos, 'end': end_pos})
                    if bg_list:
                        formatting['bg_colors'][bg_color] = bg_list
        
        return formatting

    def _index_to_position(self, index, content):
        """Convert tk.Text index to character position in string"""
        try:
            parts = index.split('.')
            line = int(parts[0]) - 1
            col = int(parts[1])
            
            lines = content.split('\n')
            pos = 0
            for i in range(line):
                pos += len(lines[i]) + 1  # +1 for newline
            pos += col
            return pos
        except:
            return 0

    def _position_to_index(self, pos, content):
        """Convert character position to tk.Text index"""
        try:
            lines = content.split('\n')
            current_pos = 0
            for line_num, line in enumerate(lines):
                line_len = len(line)
                if current_pos + line_len >= pos:
                    col = pos - current_pos
                    return f"{line_num + 1}.{col}"
                current_pos += line_len + 1  # +1 for newline
            return f"{len(lines)}.{len(lines[-1])}"
        except:
            return "1.0"

    def _apply_formatting(self):
        """Apply stored formatting to the loaded content"""
        if not hasattr(self, 'formatting_data') or not self.formatting_data:
            return
        
        try:
            content = self.editor.get("1.0", tk.END)
            
            # Apply standard tags
            for tag in ['bold', 'italic', 'underline', 'strikethrough', 'highlight']:
                if tag in self.formatting_data:
                    for range_info in self.formatting_data[tag]:
                        start_idx = self._position_to_index(range_info['start'], content)
                        end_idx = self._position_to_index(range_info['end'], content)
                        self.editor.tag_add(tag, start_idx, end_idx)
            
            # Apply color tags
            if 'colors' in self.formatting_data:
                for color, ranges in self.formatting_data['colors'].items():
                    tag_name = f"color_{color}"
                    self.editor.tag_configure(tag_name, foreground=color)
                    for range_info in ranges:
                        start_idx = self._position_to_index(range_info['start'], content)
                        end_idx = self._position_to_index(range_info['end'], content)
                        self.editor.tag_add(tag_name, start_idx, end_idx)
            
            # Apply background colors
            if 'bg_colors' in self.formatting_data:
                for bg_color, ranges in self.formatting_data['bg_colors'].items():
                    tag_name = f"bg_{bg_color}"
                    self.editor.tag_configure(tag_name, background=bg_color)
                    for range_info in ranges:
                        start_idx = self._position_to_index(range_info['start'], content)
                        end_idx = self._position_to_index(range_info['end'], content)
                        self.editor.tag_add(tag_name, start_idx, end_idx)
        except Exception as e:
            logger.error(f"Failed to apply formatting: {e}")

    def on_search(self, event):
        self.search_term = self.search_var.get()
        self.load_notes()

    def on_filter(self, event):
        self.filter_category = self.cat_filter_var.get()
        self.load_notes()
