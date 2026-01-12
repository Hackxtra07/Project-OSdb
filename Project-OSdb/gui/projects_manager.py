"""
Projects Manager - OSINT Project Management and Investigation Tracking
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from datetime import datetime
import json
import logging
import os
from utils.calendar_picker import CalendarPicker, DatePickerButton

# Try to import matplotlib, but make it optional
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

logger = logging.getLogger(__name__)

class ProjectsManager:
    """Manage OSINT projects, tasks, and evidence"""
    
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.db = app.db
        self.user_id = app.current_user_id
        self.current_project = None
        self.selected_evidence = None
        self.selected_task = None
        
        self.main_frame = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_light'])
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.build_ui()
        self.load_projects()
        
    def build_ui(self):
        """Build UI components"""
        # Split view: Projects list (left), Details (right)
        paned = tk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL, sashrelief='raised')
        paned.pack(fill=tk.BOTH, expand=True)
        
        # Sidebar
        sidebar = tk.Frame(paned, bg=self.app.theme_manager.colors['bg_light'], width=250)
        self.create_sidebar(sidebar)
        paned.add(sidebar)
        
        # Details Area (Notebook)
        self.notebook = ttk.Notebook(paned)
        paned.add(self.notebook)
        
        # Tabs
        self.tab_dashboard = tk.Frame(self.notebook, bg=self.app.theme_manager.colors['bg_light'])
        self.tab_tasks = tk.Frame(self.notebook, bg=self.app.theme_manager.colors['bg_light'])
        self.tab_evidence = tk.Frame(self.notebook, bg=self.app.theme_manager.colors['bg_light'])
        self.tab_report = tk.Frame(self.notebook, bg=self.app.theme_manager.colors['bg_light'])
        
        self.notebook.add(self.tab_dashboard, text="Dashboard")
        self.notebook.add(self.tab_tasks, text="Tasks")
        self.notebook.add(self.tab_evidence, text="Evidence")
        self.notebook.add(self.tab_report, text="Reports")
        
        self.create_dashboard_tab()
        self.create_tasks_tab()
        self.create_evidence_tab()
        self.create_report_tab()
        
    def create_sidebar(self, parent):
        """Projects list"""
        lbl = tk.Label(parent, text="My Projects", font=("Arial", 12, "bold"),
                      bg=self.app.theme_manager.colors['bg_medium'], fg=self.app.theme_manager.colors['fg_primary'])
        lbl.pack(fill=tk.X, pady=5)
        
        buttons_frame = tk.Frame(parent, bg=self.app.theme_manager.colors['bg_light'])
        buttons_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(buttons_frame, text="➕ New", command=self.create_project,
                 bg="#4CAF50", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(buttons_frame, text="🗑️ Delete", command=self.delete_project,
                 bg="#F44336", fg="white").pack(side=tk.LEFT, padx=2)
        
        self.projects_tree = ttk.Treeview(parent, columns=("Status"), show="tree headings")
        self.projects_tree.heading("#0", text="Project Name")
        self.projects_tree.heading("Status", text="Status")
        self.projects_tree.column("Status", width=80)
        self.projects_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.projects_tree.bind("<<TreeviewSelect>>", self.on_project_select)

    def create_dashboard_tab(self):
        """Project overview"""
        frame = self.tab_dashboard
        
        # Project Info Header
        self.lbl_project_name = tk.Label(frame, text="Select a Project", font=("Arial", 18, "bold"),
                                        bg=frame['bg'])
        self.lbl_project_name.pack(pady=10)
        
        # Stats container
        stats_frame = tk.Frame(frame, bg=frame['bg'])
        stats_frame.pack(fill=tk.X, padx=20)
        
        self.lbl_status = tk.Label(stats_frame, text="Status: -", bg=frame['bg'])
        self.lbl_status.pack(side=tk.LEFT, padx=10)
        
        self.task_stats = tk.Label(stats_frame, text="Tasks: 0/0", bg=frame['bg'])
        self.task_stats.pack(side=tk.LEFT, padx=10)
        
        self.evidence_stats = tk.Label(stats_frame, text="Evidence: 0", bg=frame['bg'])
        self.evidence_stats.pack(side=tk.LEFT, padx=10)
        
        # Timeline visualization frame
        self.timeline_frame = tk.Frame(frame, bg='white', height=300)
        self.timeline_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    def create_tasks_tab(self):
        """Tasks management"""
        frame = self.tab_tasks
        
        toolbar = tk.Frame(frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        tk.Button(toolbar, text="Add Task", command=self.add_task, 
                 bg=self.app.theme_manager.colors['accent_success']).pack(side=tk.LEFT)
        tk.Button(toolbar, text="Edit", command=self.edit_task, 
                 bg=self.app.theme_manager.colors['accent_info']).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Delete", command=self.delete_task, 
                 bg=self.app.theme_manager.colors['accent_danger']).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Mark Complete", command=self.mark_complete, 
                 bg="#4CAF50").pack(side=tk.LEFT, padx=5)
        
        columns = ("Title", "Status", "Priority", "Due Date", "Assigned")
        self.task_tree = ttk.Treeview(frame, columns=columns, show="headings", height=10)
        
        self.task_tree.heading("Title", text="Title")
        self.task_tree.heading("Status", text="Status")
        self.task_tree.heading("Priority", text="Priority")
        self.task_tree.heading("Due Date", text="Due Date")
        self.task_tree.heading("Assigned", text="Assigned To")
        
        self.task_tree.column("Title", width=250)
        self.task_tree.column("Status", width=100)
        self.task_tree.column("Priority", width=80)
        self.task_tree.column("Due Date", width=100)
        self.task_tree.column("Assigned", width=100)
        
        self.task_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.task_tree.bind("<<TreeviewSelect>>", self.on_task_select)
        
        # Summary
        summary_frame = tk.Frame(frame, bg=self.app.theme_manager.colors['bg_medium'])
        summary_frame.pack(fill=tk.X, padx=5, pady=5)
        self.task_summary = tk.Label(summary_frame, text="No project selected", 
                                    bg=summary_frame['bg'])
        self.task_summary.pack(anchor='w', padx=10, pady=5)

    def create_evidence_tab(self):
        """Evidence collection"""
        frame = self.tab_evidence
        
        toolbar = tk.Frame(frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        tk.Button(toolbar, text="➕ Add Evidence", command=self.add_evidence,
                 bg="#4CAF50", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(toolbar, text="🗑️ Delete Evidence", command=self.delete_evidence,
                 bg="#F44336", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(toolbar, text="✏️ Edit Evidence", command=self.edit_evidence,
                 bg="#2196F3", fg="white").pack(side=tk.LEFT, padx=2)
        
        columns = ("Type", "Description", "Date", "Score")
        self.evidence_tree = ttk.Treeview(frame, columns=columns, show="headings")
        for col in columns:
            self.evidence_tree.heading(col, text=col)
        self.evidence_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.evidence_tree.bind("<<TreeviewSelect>>", self.on_evidence_select)

    def load_projects(self):
        self.projects_tree.delete(*self.projects_tree.get_children())
        query = "SELECT id, name, status FROM osint_projects WHERE user_id = ?"
        results = self.db.execute_query(query, (self.user_id,))
        for row in results:
            self.projects_tree.insert("", tk.END, text=row['name'], values=(row['status'],), iid=row['id'])

    def on_project_select(self, event):
        sel = self.projects_tree.selection()
        if not sel: return
        self.load_project_details(sel[0])

    def load_project_details(self, project_id):
        query = "SELECT * FROM osint_projects WHERE id = ?"
        row = self.db.execute_query(query, (project_id,), fetch_all=False)
        self.current_project = dict(row)
        
        self.lbl_project_name.config(text=row['name'])
        self.lbl_status.config(text=f"Status: {row['status']}")
        
        # Load evidence
        self.load_evidence(project_id)
        
        # Load tasks
        self.load_tasks(project_id)
        
        # Update visualizations
        self.update_dashboard_visualization(project_id)

    def load_evidence(self, project_id):
        self.evidence_tree.delete(*self.evidence_tree.get_children())
        query = "SELECT * FROM investigation_evidence WHERE project_id = ?"
        results = self.db.execute_query(query, (project_id,))
        for row in results:
            self.evidence_tree.insert("", tk.END, iid=row['id'], values=(
                row['evidence_type'], row['description'], row['collected_date'], row['credibility_score']
            ))

    def create_project(self):
        name = simpledialog.askstring("New Project", "Project Name:")
        if not name: return
        query = "INSERT INTO osint_projects (user_id, name, status) VALUES (?, ?, 'active')"
        self.db.execute_query(query, (self.user_id, name))
        self.load_projects()

    def add_evidence(self):
        if not self.current_project: return
        # Placeholder dialog
        desc = simpledialog.askstring("Evidence", "Description:")
        if desc:
            query = """INSERT INTO investigation_evidence 
                     (project_id, user_id, evidence_type, description) 
                     VALUES (?, ?, 'manual', ?)"""
            self.db.execute_query(query, (self.current_project['id'], self.user_id, desc))
            self.load_evidence(self.current_project['id'])

    def load_tasks(self, project_id):
        """Load tasks for project"""
        self.task_tree.delete(*self.task_tree.get_children())
        query = "SELECT * FROM project_tasks WHERE project_id = ? ORDER BY due_date ASC, priority DESC"
        results = self.db.execute_query(query, (project_id,))
        
        for row in results:
            self.task_tree.insert("", tk.END, iid=row['id'], values=(
                row['title'],
                row['status'],
                row['priority'],
                row['due_date'][:10] if row['due_date'] else "",
                row['assigned_to'] or ""
            ))
        
        # Update summary
        completed = sum(1 for r in results if r['status'] == 'completed')
        total = len(list(results))
        self.task_summary.config(text=f"Tasks: {completed}/{total} completed")

    def on_task_select(self, event):
        """Handle task selection"""
        selection = self.task_tree.selection()
        if selection:
            self.selected_task = selection[0]
        else:
            self.selected_task = None

    def add_task(self):
        """Add task to project"""
        if not self.current_project:
            messagebox.showwarning("Warning", "Please select a project first")
            return
        
        dialog = tk.Toplevel(self.parent)
        dialog.title("New Task")
        dialog.geometry("500x400")
        
        # Title
        tk.Label(dialog, text="Task Title:").grid(row=0, column=0, sticky='w', padx=10, pady=10)
        title_var = tk.StringVar()
        tk.Entry(dialog, textvariable=title_var, width=40).grid(row=0, column=1, padx=10, pady=10)
        
        # Description
        tk.Label(dialog, text="Description:").grid(row=1, column=0, sticky='w', padx=10, pady=10)
        desc_var = tk.StringVar()
        tk.Entry(dialog, textvariable=desc_var, width=40).grid(row=1, column=1, padx=10, pady=10)
        
        # Status
        tk.Label(dialog, text="Status:").grid(row=2, column=0, sticky='w', padx=10, pady=10)
        status_var = tk.StringVar(value="pending")
        ttk.Combobox(dialog, textvariable=status_var, 
                    values=["pending", "in_progress", "review", "completed", "cancelled"],
                    width=37).grid(row=2, column=1, padx=10, pady=10)
        
        # Priority
        tk.Label(dialog, text="Priority:").grid(row=3, column=0, sticky='w', padx=10, pady=10)
        priority_var = tk.StringVar(value="1")
        ttk.Combobox(dialog, textvariable=priority_var, values=["1", "2", "3", "4", "5"],
                    width=37).grid(row=3, column=1, padx=10, pady=10)
        
        # Assigned to
        tk.Label(dialog, text="Assigned To:").grid(row=4, column=0, sticky='w', padx=10, pady=10)
        assigned_var = tk.StringVar()
        tk.Entry(dialog, textvariable=assigned_var, width=40).grid(row=4, column=1, padx=10, pady=10)
        
        # Due date with calendar picker
        tk.Label(dialog, text="Due Date:").grid(row=5, column=0, sticky='w', padx=10, pady=10)
        date_picker = DatePickerButton(dialog)
        date_picker.grid(row=5, column=1, sticky='w', padx=10, pady=10)
        
        def save():
            try:
                if not title_var.get():
                    messagebox.showerror("Error", "Task title is required")
                    return
                
                query = """INSERT INTO project_tasks 
                          (project_id, user_id, title, description, status, priority, assigned_to, due_date)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)"""
                
                self.db.execute_query(query, (
                    self.current_project['id'],
                    self.user_id,
                    title_var.get(),
                    desc_var.get(),
                    status_var.get(),
                    int(priority_var.get()),
                    assigned_var.get() or None,
                    date_picker.get()
                ))
                
                messagebox.showinfo("Success", "Task created")
                dialog.destroy()
                self.load_tasks(self.current_project['id'])
            except Exception as e:
                logger.error(f"Failed to create task: {e}")
                messagebox.showerror("Error", f"Failed to create task: {e}")
        
        tk.Button(dialog, text="Save", command=save, bg="#4CAF50", fg="white").grid(row=6, column=1, sticky='w', padx=10, pady=20)

    def edit_task(self):
        """Edit selected task"""
        if not self.selected_task:
            messagebox.showwarning("Warning", "Please select a task")
            return
        
        query = "SELECT * FROM project_tasks WHERE id = ?"
        task = self.db.execute_query(query, (self.selected_task,), fetch_all=False)
        
        dialog = tk.Toplevel(self.parent)
        dialog.title(f"Edit Task: {task['title']}")
        dialog.geometry("500x400")
        
        # Title
        tk.Label(dialog, text="Task Title:").grid(row=0, column=0, sticky='w', padx=10, pady=10)
        title_var = tk.StringVar(value=task['title'])
        tk.Entry(dialog, textvariable=title_var, width=40).grid(row=0, column=1, padx=10, pady=10)
        
        # Description
        tk.Label(dialog, text="Description:").grid(row=1, column=0, sticky='w', padx=10, pady=10)
        desc_var = tk.StringVar(value=task['description'] or "")
        tk.Entry(dialog, textvariable=desc_var, width=40).grid(row=1, column=1, padx=10, pady=10)
        
        # Status
        tk.Label(dialog, text="Status:").grid(row=2, column=0, sticky='w', padx=10, pady=10)
        status_var = tk.StringVar(value=task['status'])
        ttk.Combobox(dialog, textvariable=status_var, 
                    values=["pending", "in_progress", "review", "completed", "cancelled"],
                    width=37).grid(row=2, column=1, padx=10, pady=10)
        
        # Priority
        tk.Label(dialog, text="Priority:").grid(row=3, column=0, sticky='w', padx=10, pady=10)
        priority_var = tk.StringVar(value=str(task['priority']))
        ttk.Combobox(dialog, textvariable=priority_var, values=["1", "2", "3", "4", "5"],
                    width=37).grid(row=3, column=1, padx=10, pady=10)
        
        # Assigned to
        tk.Label(dialog, text="Assigned To:").grid(row=4, column=0, sticky='w', padx=10, pady=10)
        assigned_var = tk.StringVar(value=task['assigned_to'] or "")
        tk.Entry(dialog, textvariable=assigned_var, width=40).grid(row=4, column=1, padx=10, pady=10)
        
        # Due date with calendar picker
        tk.Label(dialog, text="Due Date:").grid(row=5, column=0, sticky='w', padx=10, pady=10)
        date_picker = DatePickerButton(dialog, initial_date=task['due_date'] or None)
        date_picker.grid(row=5, column=1, sticky='w', padx=10, pady=10)
        
        def save():
            try:
                query = """UPDATE project_tasks SET 
                          title=?, description=?, status=?, priority=?, assigned_to=?, due_date=?,
                          updated_at=datetime('now')
                          WHERE id=?"""
                
                self.db.execute_query(query, (
                    title_var.get(),
                    desc_var.get(),
                    status_var.get(),
                    int(priority_var.get()),
                    assigned_var.get() or None,
                    date_picker.get(),
                    self.selected_task
                ))
                
                messagebox.showinfo("Success", "Task updated")
                dialog.destroy()
                self.load_tasks(self.current_project['id'])
            except Exception as e:
                logger.error(f"Failed to update task: {e}")
                messagebox.showerror("Error", f"Failed to update: {e}")
        
        tk.Button(dialog, text="Save", command=save, bg="#4CAF50", fg="white").grid(row=6, column=1, sticky='w', padx=10, pady=20)

    def delete_task(self):
        """Delete selected task"""
        if not self.selected_task:
            messagebox.showwarning("Warning", "Please select a task")
            return
        
        if messagebox.askyesno("Confirm", "Delete this task?"):
            try:
                query = "DELETE FROM project_tasks WHERE id = ?"
                self.db.execute_query(query, (self.selected_task,))
                messagebox.showinfo("Success", "Task deleted")
                self.load_tasks(self.current_project['id'])
            except Exception as e:
                logger.error(f"Failed to delete task: {e}")
                messagebox.showerror("Error", f"Failed to delete: {e}")

    def mark_complete(self):
        """Mark task as completed"""
        if not self.selected_task:
            messagebox.showwarning("Warning", "Please select a task")
            return
        
        try:
            query = "UPDATE project_tasks SET status='completed', completed_date=datetime('now') WHERE id=?"
            self.db.execute_query(query, (self.selected_task,))
            messagebox.showinfo("Success", "Task marked as completed")
            self.load_tasks(self.current_project['id'])
        except Exception as e:
            logger.error(f"Failed to mark complete: {e}")
            messagebox.showerror("Error", f"Failed to mark complete: {e}")

    def update_dashboard_visualization(self, project_id):
        """Update dashboard with project statistics visualization"""
        try:
            # Clear previous visualization
            for widget in self.timeline_frame.winfo_children():
                widget.destroy()
            
            # Get statistics
            tasks_query = "SELECT COUNT(*) as total, SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed FROM project_tasks WHERE project_id = ?"
            tasks_result = self.db.execute_query(tasks_query, (project_id,), fetch_all=False)
            total_tasks = tasks_result['total'] or 0
            completed_tasks = tasks_result['completed'] or 0
            
            evidence_query = "SELECT COUNT(*) as total FROM investigation_evidence WHERE project_id = ?"
            evidence_result = self.db.execute_query(evidence_query, (project_id,), fetch_all=False)
            total_evidence = evidence_result['total'] or 0
            
            # Update stats labels
            self.task_stats.config(text=f"Tasks: {completed_tasks}/{total_tasks}")
            self.evidence_stats.config(text=f"Evidence: {total_evidence}")
            
            # If matplotlib is available, use it
            if HAS_MATPLOTLIB:
                self._create_matplotlib_visualization(project_id)
            else:
                # Use tkinter-based visualization
                self._create_tkinter_visualization(project_id)
            
        except Exception as e:
            logger.error(f"Visualization error: {e}")
            # Show error message in frame
            error_label = tk.Label(self.timeline_frame, text=f"Error: {str(e)}", 
                                  fg='red', bg='white', padx=20, pady=20)
            error_label.pack()

    def _create_matplotlib_visualization(self, project_id):
        """Create visualization using matplotlib"""
        try:
            # Create matplotlib figure with subplots
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(10, 5))
            fig.patch.set_facecolor('white')
            
            # 1. Task Status Pie Chart
            task_statuses = self.db.execute_query(
                "SELECT status, COUNT(*) as count FROM project_tasks WHERE project_id = ? GROUP BY status",
                (project_id,)
            )
            if task_statuses:
                statuses = [row['status'] for row in task_statuses]
                counts = [row['count'] for row in task_statuses]
                colors = ['#4CAF50', '#FFC107', '#FF9800', '#F44336', '#9E9E9E']
                ax1.pie(counts, labels=statuses, autopct='%1.1f%%', colors=colors, startangle=90)
                ax1.set_title('Task Status Distribution', fontweight='bold')
            else:
                ax1.text(0.5, 0.5, 'No Tasks', ha='center', va='center', fontsize=12)
                ax1.set_title('Task Status Distribution')
            
            # 2. Evidence Types Bar Chart
            evidence_types = self.db.execute_query(
                "SELECT evidence_type, COUNT(*) as count FROM investigation_evidence WHERE project_id = ? GROUP BY evidence_type",
                (project_id,)
            )
            if evidence_types:
                types = [row['evidence_type'] for row in evidence_types]
                counts = [row['count'] for row in evidence_types]
                ax2.bar(range(len(types)), counts, color='#2196F3')
                ax2.set_xticks(range(len(types)))
                ax2.set_xticklabels(types, rotation=45, ha='right')
                ax2.set_ylabel('Count')
                ax2.set_title('Evidence by Type', fontweight='bold')
            else:
                ax2.text(0.5, 0.5, 'No Evidence', ha='center', va='center', fontsize=12, transform=ax2.transAxes)
                ax2.set_title('Evidence by Type')
            
            # 3. Task Progress Bar
            tasks_result = self.db.execute_query(
                "SELECT COUNT(*) as total, SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed FROM project_tasks WHERE project_id = ?",
                (project_id,), fetch_all=False
            )
            total_tasks = tasks_result['total'] or 0
            completed_tasks = tasks_result['completed'] or 0
            
            if total_tasks > 0:
                progress_pct = (completed_tasks / total_tasks) * 100
                ax3.barh(['Project Progress'], [progress_pct], color='#4CAF50', height=0.5)
                ax3.set_xlim(0, 100)
                ax3.set_xlabel('Completion %')
                ax3.text(progress_pct/2, 0, f'{progress_pct:.1f}%', ha='center', va='center', 
                        color='white', fontweight='bold')
                ax3.set_title('Overall Task Progress', fontweight='bold')
            else:
                ax3.text(0.5, 0.5, 'No Tasks', ha='center', va='center', fontsize=12, transform=ax3.transAxes)
                ax3.set_title('Overall Task Progress')
            
            # 4. Priority Distribution
            priority_query = "SELECT priority, COUNT(*) as count FROM project_tasks WHERE project_id = ? GROUP BY priority"
            priority_data = self.db.execute_query(priority_query, (project_id,))
            if priority_data:
                priorities = sorted([row['priority'] for row in priority_data])
                counts = [next((r['count'] for r in priority_data if r['priority'] == p), 0) for p in priorities]
                priority_labels = ['Low', 'Medium', 'High', 'Urgent', 'Critical']
                ax4.bar(range(len(priorities)), counts, color='#FF9800')
                ax4.set_xticks(range(len(priorities)))
                ax4.set_xticklabels([priority_labels[p-1] if p <= len(priority_labels) else f'P{p}' for p in priorities])
                ax4.set_ylabel('Count')
                ax4.set_title('Tasks by Priority', fontweight='bold')
            else:
                ax4.text(0.5, 0.5, 'No Tasks', ha='center', va='center', fontsize=12, transform=ax4.transAxes)
                ax4.set_title('Tasks by Priority')
            
            plt.tight_layout()
            
            # Embed matplotlib figure in tkinter
            canvas = FigureCanvasTkAgg(fig, master=self.timeline_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
        except Exception as e:
            logger.error(f"Matplotlib visualization error: {e}")
            raise

    def _create_tkinter_visualization(self, project_id):
        """Create visualization using pure tkinter (no matplotlib)"""
        # Create a grid of stats panels
        panels_frame = tk.Frame(self.timeline_frame, bg='white')
        panels_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Get statistics
        tasks_query = "SELECT COUNT(*) as total, SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed FROM project_tasks WHERE project_id = ?"
        tasks_result = self.db.execute_query(tasks_query, (project_id,), fetch_all=False)
        total_tasks = tasks_result['total'] or 0
        completed_tasks = tasks_result['completed'] or 0
        
        # 1. Task Progress Panel
        progress_frame = tk.LabelFrame(panels_frame, text="Task Progress", font=("Arial", 10, "bold"), 
                                      bg='#f0f0f0', padx=10, pady=10)
        progress_frame.pack(fill=tk.X, pady=5)
        
        if total_tasks > 0:
            progress = (completed_tasks / total_tasks) * 100
            tk.Label(progress_frame, text=f"{completed_tasks}/{total_tasks} Tasks Complete", 
                    bg='#f0f0f0').pack()
            
            # Progress bar
            progress_bar_frame = tk.Frame(progress_frame, bg='white', height=30, relief='sunken')
            progress_bar_frame.pack(fill=tk.X, pady=5)
            
            progress_fill = tk.Frame(progress_bar_frame, bg='#4CAF50', height=30)
            progress_fill.place(relwidth=progress/100, relheight=1)
            
            progress_label = tk.Label(progress_bar_frame, text=f"{progress:.1f}%", 
                                     bg='#4CAF50', fg='white', font=("Arial", 10, "bold"))
            progress_label.place(relx=0.5, rely=0.5, anchor='center')
        else:
            tk.Label(progress_frame, text="No tasks", bg='#f0f0f0').pack()
        
        # 2. Task Status Distribution
        task_statuses = self.db.execute_query(
            "SELECT status, COUNT(*) as count FROM project_tasks WHERE project_id = ? GROUP BY status",
            (project_id,)
        )
        
        status_frame = tk.LabelFrame(panels_frame, text="Task Status Distribution", font=("Arial", 10, "bold"),
                                    bg='#f0f0f0', padx=10, pady=10)
        status_frame.pack(fill=tk.X, pady=5)
        
        if task_statuses:
            for row in task_statuses:
                status_label = tk.Label(status_frame, text=f"  {row['status'].title()}: {row['count']}", 
                                       bg='#f0f0f0', justify='left')
                status_label.pack(anchor='w')
        else:
            tk.Label(status_frame, text="No tasks", bg='#f0f0f0').pack()
        
        # 3. Evidence Statistics
        evidence_types = self.db.execute_query(
            "SELECT evidence_type, COUNT(*) as count FROM investigation_evidence WHERE project_id = ? GROUP BY evidence_type",
            (project_id,)
        )
        
        evidence_frame = tk.LabelFrame(panels_frame, text="Evidence by Type", font=("Arial", 10, "bold"),
                                      bg='#f0f0f0', padx=10, pady=10)
        evidence_frame.pack(fill=tk.X, pady=5)
        
        if evidence_types:
            for row in evidence_types:
                evidence_label = tk.Label(evidence_frame, text=f"  {row['evidence_type'].title()}: {row['count']}", 
                                         bg='#f0f0f0', justify='left')
                evidence_label.pack(anchor='w')
        else:
            tk.Label(evidence_frame, text="No evidence", bg='#f0f0f0').pack()
        
        # 4. Priority Distribution
        priority_data = self.db.execute_query(
            "SELECT priority, COUNT(*) as count FROM project_tasks WHERE project_id = ? GROUP BY priority ORDER BY priority",
            (project_id,)
        )
        
        priority_frame = tk.LabelFrame(panels_frame, text="Tasks by Priority", font=("Arial", 10, "bold"),
                                      bg='#f0f0f0', padx=10, pady=10)
        priority_frame.pack(fill=tk.X, pady=5)
        
        priority_labels_map = {1: 'Low', 2: 'Medium', 3: 'High', 4: 'Urgent', 5: 'Critical'}
        
        if priority_data:
            for row in priority_data:
                p_label = priority_labels_map.get(row['priority'], f"P{row['priority']}")
                priority_label = tk.Label(priority_frame, text=f"  {p_label}: {row['count']}", 
                                         bg='#f0f0f0', justify='left')
                priority_label.pack(anchor='w')
        else:
            tk.Label(priority_frame, text="No tasks", bg='#f0f0f0').pack()
            error_label.pack()

    def delete_project(self):
        """Delete selected project and all related data"""
        sel = self.projects_tree.selection()
        if not sel:
            messagebox.showwarning("Warning", "Please select a project to delete")
            return
        
        project_id = sel[0]
        query = "SELECT name FROM osint_projects WHERE id = ?"
        row = self.db.execute_query(query, (project_id,), fetch_all=False)
        
        if not row:
            messagebox.showerror("Error", "Project not found")
            return
        
        project_name = row['name']
        
        # Confirmation dialog
        if messagebox.askyesno("Confirm Delete", 
                              f"Delete project '{project_name}' and ALL associated data?\n\nThis will delete:\n- Tasks\n- Evidence\n- All project information\n\nThis cannot be undone!"):
            try:
                # Delete all related data (cascading will handle this with proper FK)
                self.db.execute_query("DELETE FROM osint_projects WHERE id = ? AND user_id = ?", 
                                     (project_id, self.user_id))
                
                messagebox.showinfo("Success", f"Project '{project_name}' and all related data deleted")
                self.load_projects()
                
                # Clear display
                self.current_project = None
                self.lbl_project_name.config(text="Select a Project")
                self.lbl_status.config(text="Status: -")
                self.task_tree.delete(*self.task_tree.get_children())
                self.evidence_tree.delete(*self.evidence_tree.get_children())
                
            except Exception as e:
                logger.error(f"Failed to delete project: {e}")
                messagebox.showerror("Error", f"Failed to delete project: {e}")

    def on_evidence_select(self, event):
        """Handle evidence selection"""
        selection = self.evidence_tree.selection()
        if selection:
            self.selected_evidence = selection[0]
            logger.debug(f"Selected evidence ID: {self.selected_evidence}")
        else:
            self.selected_evidence = None

    def delete_evidence(self):
        """Delete selected evidence"""
        if not self.selected_evidence:
            messagebox.showwarning("Warning", "Please select evidence to delete")
            return
        
        if not self.current_project:
            messagebox.showwarning("Warning", "No project selected")
            return
        
        # Get evidence info
        query = "SELECT * FROM investigation_evidence WHERE id = ?"
        evidence = self.db.execute_query(query, (self.selected_evidence,), fetch_all=False)
        
        if not evidence:
            messagebox.showerror("Error", f"Evidence not found (ID: {self.selected_evidence})")
            logger.error(f"Evidence with ID {self.selected_evidence} not found in database")
            self.selected_evidence = None
            return
        
        # Convert Row to dict
        evidence = dict(evidence)
        ev_desc = evidence.get('description', 'Unknown evidence')[:50]
        
        # Confirmation dialog
        if messagebox.askyesno("Confirm Delete", 
                              f"Delete this evidence?\n\n'{ev_desc}...'\n\nThis action cannot be undone!"):
            try:
                self.db.execute_query("DELETE FROM investigation_evidence WHERE id = ?", 
                                     (self.selected_evidence,))
                
                self.selected_evidence = None
                messagebox.showinfo("Success", "Evidence deleted")
                self.load_evidence(self.current_project['id'])
                
            except Exception as e:
                logger.error(f"Failed to delete evidence: {e}")
                messagebox.showerror("Error", f"Failed to delete evidence: {e}")

    def edit_evidence(self):
        """Edit selected evidence"""
        if not self.selected_evidence:
            messagebox.showwarning("Warning", "Please select evidence to edit")
            return
        
        # Get evidence info
        query = "SELECT * FROM investigation_evidence WHERE id = ?"
        evidence = self.db.execute_query(query, (self.selected_evidence,), fetch_all=False)
        
        if not evidence:
            messagebox.showerror("Error", f"Evidence not found (ID: {self.selected_evidence})")
            logger.error(f"Evidence with ID {self.selected_evidence} not found in database")
            self.selected_evidence = None
            return
        
        # Convert Row to dict
        evidence = dict(evidence)
        
        dialog = tk.Toplevel(self.parent)
        dialog.title(f"Edit Evidence")
        dialog.geometry("650x600")
        
        # Initialize attachments from metadata
        meta = {}
        try:
            if evidence.get('metadata'):
                meta = json.loads(evidence.get('metadata', '{}'))
        except:
            pass
        attachments = meta.get('attachments', {})
        
        # Type
        tk.Label(dialog, text="Evidence Type:").grid(row=0, column=0, sticky='w', padx=10, pady=10)
        type_var = tk.StringVar(value=evidence.get('evidence_type', 'manual'))
        ttk.Combobox(dialog, textvariable=type_var, 
                    values=["manual", "screenshot", "document", "url", "archive", "other"],
                    width=50).grid(row=0, column=1, padx=10, pady=10)
        
        # Description
        tk.Label(dialog, text="Description:").grid(row=1, column=0, sticky='w', padx=10, pady=10)
        desc_var = tk.StringVar(value=evidence.get('description', ''))
        tk.Entry(dialog, textvariable=desc_var, width=50).grid(row=1, column=1, padx=10, pady=10)
        
        # Content
        tk.Label(dialog, text="Content:").grid(row=2, column=0, sticky='nw', padx=10, pady=10)
        content_text = tk.Text(dialog, width=50, height=5)
        content_text.grid(row=2, column=1, padx=10, pady=10)
        content_value = evidence.get('content', '')
        if content_value is None:
            content_value = ''
        content_text.insert("1.0", str(content_value))
        
        # Source URL
        tk.Label(dialog, text="Source URL:").grid(row=3, column=0, sticky='w', padx=10, pady=10)
        source_var = tk.StringVar(value=evidence.get('source_url', ''))
        tk.Entry(dialog, textvariable=source_var, width=50).grid(row=3, column=1, padx=10, pady=10)
        
        # Credibility Score
        tk.Label(dialog, text="Credibility Score (1-5):").grid(row=4, column=0, sticky='w', padx=10, pady=10)
        score_var = tk.StringVar(value=str(evidence.get('credibility_score', 3)))
        ttk.Combobox(dialog, textvariable=score_var, values=["1", "2", "3", "4", "5"],
                    width=50).grid(row=4, column=1, padx=10, pady=10)
        
        # Verified
        tk.Label(dialog, text="Verified:").grid(row=5, column=0, sticky='w', padx=10, pady=10)
        verified_var = tk.BooleanVar(value=bool(evidence.get('verified')))
        tk.Checkbutton(dialog, variable=verified_var).grid(row=5, column=1, sticky='w', padx=10)
        
        # Collection Date with calendar picker
        tk.Label(dialog, text="Collection Date:").grid(row=6, column=0, sticky='w', padx=10, pady=10)
        date_picker = DatePickerButton(dialog)
        date_picker.grid(row=6, column=1, sticky='w', padx=10, pady=10)
        
        # File Attachments Section
        tk.Label(dialog, text="📎 Attachments:").grid(row=7, column=0, sticky='nw', padx=10, pady=10)
        
        # Attachments listbox
        attachments_frame = tk.Frame(dialog)
        attachments_frame.grid(row=7, column=1, sticky='ew', padx=10, pady=10)
        
        attachments_list = tk.Listbox(attachments_frame, height=3, width=50)
        attachments_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(attachments_frame, orient='vertical', command=attachments_list.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        attachments_list.configure(yscrollcommand=scrollbar.set)
        
        # Populate attachments list
        for filename in attachments.keys():
            attachments_list.insert(tk.END, filename)
        
        # Attachment buttons
        def add_attachment():
            file_path = filedialog.askopenfilename(
                title="Select file to attach",
                initialdir=os.path.expanduser("~")
            )
            if file_path:
                filename = os.path.basename(file_path)
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    attachments[filename] = {
                        'path': file_path,
                        'size': os.path.getsize(file_path),
                        'content': content[:1000] + ('...' if len(content) > 1000 else '')  # Preview
                    }
                    attachments_list.insert(tk.END, filename)
                    messagebox.showinfo("Success", f"File '{filename}' attached")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to attach file: {e}")
        
        def remove_attachment():
            selection = attachments_list.curselection()
            if selection:
                filename = attachments_list.get(selection[0])
                del attachments[filename]
                attachments_list.delete(selection[0])
                messagebox.showinfo("Success", f"File '{filename}' removed")
        
        def open_attachment():
            selection = attachments_list.curselection()
            if selection:
                filename = attachments_list.get(selection[0])
                if filename in attachments:
                    file_data = attachments[filename]
                    # Show content in a text window
                    content_window = tk.Toplevel(dialog)
                    content_window.title(f"View: {filename}")
                    content_window.geometry("600x400")
                    
                    text_widget = tk.Text(content_window, wrap=tk.WORD)
                    text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
                    text_widget.insert("1.0", file_data.get('content', ''))
                    text_widget.config(state='disabled')
        
        attach_btn_frame = tk.Frame(dialog)
        attach_btn_frame.grid(row=8, column=1, sticky='w', padx=10, pady=5)
        
        tk.Button(attach_btn_frame, text="➕ Add File", command=add_attachment, 
                 bg="#4CAF50", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(attach_btn_frame, text="🗑️ Remove", command=remove_attachment,
                 bg="#F44336", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(attach_btn_frame, text="👁️ View", command=open_attachment,
                 bg="#2196F3", fg="white").pack(side=tk.LEFT, padx=2)
        
        def save():
            try:
                # Prepare metadata with attachments
                metadata = {'attachments': attachments}
                metadata_json = json.dumps(metadata)
                
                query = """UPDATE investigation_evidence 
                          SET evidence_type=?, description=?, content=?, source_url=?,
                              credibility_score=?, verified=?, metadata=?
                          WHERE id=?"""
                
                self.db.execute_query(query, (
                    type_var.get(),
                    desc_var.get(),
                    content_text.get("1.0", tk.END).strip(),
                    source_var.get() or None,
                    int(score_var.get()),
                    1 if verified_var.get() else 0,
                    metadata_json,
                    self.selected_evidence
                ))
                
                messagebox.showinfo("Success", "Evidence updated")
                dialog.destroy()
                self.load_evidence(self.current_project['id'])
            except Exception as e:
                logger.error(f"Failed to update evidence: {e}")
                messagebox.showerror("Error", f"Failed to update: {e}")
        
        def cancel():
            dialog.destroy()
        
        # Button frame at bottom
        button_frame = tk.Frame(dialog)
        button_frame.grid(row=9, column=0, columnspan=2, sticky='ew', padx=10, pady=20)
        
        tk.Button(button_frame, text="💾 Save", command=save, bg="#4CAF50", fg="white", width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="❌ Cancel", command=cancel, bg="#F44336", fg="white", width=15).pack(side=tk.LEFT, padx=5)

    def create_report_tab(self):
        """Report generation and export"""
        frame = self.tab_report
        
        tk.Label(frame, text="Generate Report", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Report type
        tk.Label(frame, text="Report Type:").pack()
        report_type_var = tk.StringVar(value="summary")
        type_frame = tk.Frame(frame)
        type_frame.pack(pady=5)
        
        ttk.Radiobutton(type_frame, text="Summary", variable=report_type_var, value="summary").pack(anchor='w')
        ttk.Radiobutton(type_frame, text="Detailed", variable=report_type_var, value="detailed").pack(anchor='w')
        ttk.Radiobutton(type_frame, text="Evidence Only", variable=report_type_var, value="evidence").pack(anchor='w')
        ttk.Radiobutton(type_frame, text="Timeline", variable=report_type_var, value="timeline").pack(anchor='w')
        
        # Format
        tk.Label(frame, text="Export Format:").pack()
        format_frame = tk.Frame(frame)
        format_frame.pack(pady=5)
        
        format_var = tk.StringVar(value="pdf")
        ttk.Radiobutton(format_frame, text="PDF", variable=format_var, value="pdf").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="HTML", variable=format_var, value="html").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="JSON", variable=format_var, value="json").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="CSV", variable=format_var, value="csv").pack(side=tk.LEFT, padx=5)
        
        # Include options
        include_frame = tk.LabelFrame(frame, text="Include in Report", padx=10, pady=10)
        include_frame.pack(fill=tk.BOTH, padx=10, pady=10)
        
        include_summary = tk.BooleanVar(value=True)
        include_evidence = tk.BooleanVar(value=True)
        include_tasks = tk.BooleanVar(value=True)
        include_api = tk.BooleanVar(value=False)
        
        tk.Checkbutton(include_frame, text="Project Summary", variable=include_summary).pack(anchor='w')
        tk.Checkbutton(include_frame, text="Evidence", variable=include_evidence).pack(anchor='w')
        tk.Checkbutton(include_frame, text="Tasks", variable=include_tasks).pack(anchor='w')
        tk.Checkbutton(include_frame, text="API Results", variable=include_api).pack(anchor='w')
        
        def generate_report():
            if not self.current_project:
                messagebox.showwarning("Warning", "Please select a project")
                return
            
            try:
                from tkinter import filedialog
                
                filename = filedialog.asksaveasfilename(
                    defaultextension=f".{format_var.get()}",
                    filetypes=[
                        ("PDF files", "*.pdf"),
                        ("HTML files", "*.html"),
                        ("JSON files", "*.json"),
                        ("CSV files", "*.csv")
                    ]
                )
                
                if not filename:
                    return
                
                # Generate report content
                report = self.generate_report_content(
                    report_type_var.get(),
                    include_summary.get(),
                    include_evidence.get(),
                    include_tasks.get(),
                    include_api.get()
                )
                
                # Export to format
                self.export_report(filename, report, format_var.get())
                messagebox.showinfo("Success", f"Report exported to {filename}")
            except Exception as e:
                logger.error(f"Report generation failed: {e}")
                messagebox.showerror("Error", f"Failed to generate report: {e}")
        
        tk.Button(frame, text="Generate Report", command=generate_report, 
                 bg="#2196F3", fg="white", font=("Arial", 12, "bold")).pack(pady=20)

    def generate_report_content(self, report_type, include_summary, include_evidence, include_tasks, include_api):
        """Generate report content as dict"""
        report = {
            'title': f"OSINT Project Report: {self.current_project['name']}",
            'generated_at': datetime.now().isoformat(),
            'project': dict(self.current_project)
        }
        
        if include_summary:
            report['summary'] = {
                'name': self.current_project['name'],
                'status': self.current_project['status'],
                'priority': self.current_project['priority'],
                'start_date': self.current_project['start_date'],
                'end_date': self.current_project['end_date'],
                'description': self.current_project['description']
            }
        
        if include_evidence:
            query = "SELECT * FROM investigation_evidence WHERE project_id = ?"
            evidence = self.db.execute_query(query, (self.current_project['id'],))
            report['evidence'] = [dict(e) for e in evidence]
        
        if include_tasks:
            query = "SELECT * FROM project_tasks WHERE project_id = ?"
            tasks = self.db.execute_query(query, (self.current_project['id'],))
            report['tasks'] = [dict(t) for t in tasks]
        
        if include_api:
            query = "SELECT * FROM api_results WHERE user_id = ? LIMIT 100"
            api_results = self.db.execute_query(query, (self.user_id,))
            report['api_results'] = [dict(r) for r in api_results]
        
        return report

    def export_report(self, filename, report, format_type):
        """Export report in specified format"""
        if format_type == 'json':
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        
        elif format_type == 'csv':
            import csv
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Field', 'Value'])
                for key, value in report.get('summary', {}).items():
                    writer.writerow([key, value])
                writer.writerow([''])
                writer.writerow(['Evidence'])
                if 'evidence' in report:
                    for ev in report['evidence']:
                        writer.writerow(['Type', ev.get('evidence_type')])
                        writer.writerow(['Description', ev.get('description')])
                        writer.writerow([''])
        
        elif format_type == 'html':
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>{report['title']}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #2196F3; }}
                    h2 {{ color: #555; margin-top: 30px; }}
                    table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                    th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
                    th {{ background-color: #2196F3; color: white; }}
                </style>
            </head>
            <body>
                <h1>{report['title']}</h1>
                <p>Generated: {report['generated_at']}</p>
                
                <h2>Project Summary</h2>
                <p>Name: {report['project']['name']}</p>
                <p>Status: {report['project']['status']}</p>
                <p>Priority: {report['project']['priority']}</p>
                
                {'<h2>Evidence</h2>' if 'evidence' in report else ''}
                {''.join([f"<p><strong>{e.get('evidence_type')}</strong>: {e.get('description')}</p>" for e in report.get('evidence', [])]) if 'evidence' in report else ''}
                
                {'<h2>Tasks</h2>' if 'tasks' in report else ''}
                {''.join([f"<p>[{t.get('status')}] {t.get('title')}</p>" for t in report.get('tasks', [])]) if 'tasks' in report else ''}
            </body>
            </html>
            """
            with open(filename, 'w') as f:
                f.write(html_content)
        
        elif format_type == 'pdf':
            try:
                from reportlab.lib.pagesizes import letter
                from reportlab.lib.styles import getSampleStyleSheet
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
                
                doc = SimpleDocTemplate(filename, pagesize=letter)
                story = []
                styles = getSampleStyleSheet()
                
                # Title
                story.append(Paragraph(report['title'], styles['Heading1']))
                story.append(Spacer(1, 12))
                story.append(Paragraph(f"Generated: {report['generated_at']}", styles['Normal']))
                story.append(Spacer(1, 12))
                
                # Summary
                if 'summary' in report:
                    story.append(Paragraph("Project Summary", styles['Heading2']))
                    for key, value in report['summary'].items():
                        story.append(Paragraph(f"<b>{key}:</b> {value}", styles['Normal']))
                    story.append(Spacer(1, 12))
                
                # Evidence
                if 'evidence' in report:
                    story.append(PageBreak())
                    story.append(Paragraph("Evidence", styles['Heading2']))
                    for e in report['evidence']:
                        story.append(Paragraph(f"<b>{e.get('evidence_type')}</b>: {e.get('description')}", styles['Normal']))
                    story.append(Spacer(1, 12))
                
                # Tasks
                if 'tasks' in report:
                    story.append(PageBreak())
                    story.append(Paragraph("Tasks", styles['Heading2']))
                    for t in report['tasks']:
                        story.append(Paragraph(f"[{t.get('status')}] {t.get('title')}", styles['Normal']))
                
                doc.build(story)
            except ImportError:
                messagebox.showwarning("Warning", "reportlab not installed. Exporting as HTML instead.")
                self.export_report(filename.replace('.pdf', '.html'), report, 'html')
