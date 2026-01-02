"""
Projects Manager - OSINT Project Management and Investigation Tracking
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from datetime import datetime
import json
import logging
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

logger = logging.getLogger(__name__)

class ProjectsManager:
    """Manage OSINT projects, tasks, and evidence"""
    
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.db = app.db
        self.user_id = app.current_user_id
        self.current_project = None
        
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
        
        tk.Button(parent, text="New Project", command=self.create_project).pack(fill=tk.X, padx=5)
        
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
        
        # Timeline placeholder
        self.timeline_frame = tk.Frame(frame, bg='white', height=200)
        self.timeline_frame.pack(fill=tk.X, padx=20, pady=20)
        tk.Label(self.timeline_frame, text="Activity Timeline (Visualization)").pack(pady=80)

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
        tk.Button(toolbar, text="Add Evidence", command=self.add_evidence).pack(side=tk.LEFT)
        
        columns = ("Type", "Description", "Date", "Score")
        self.evidence_tree = ttk.Treeview(frame, columns=columns, show="headings")
        for col in columns:
            self.evidence_tree.heading(col, text=col)
        self.evidence_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

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

    def load_evidence(self, project_id):
        self.evidence_tree.delete(*self.evidence_tree.get_children())
        query = "SELECT * FROM investigation_evidence WHERE project_id = ?"
        results = self.db.execute_query(query, (project_id,))
        for row in results:
            self.evidence_tree.insert("", tk.END, values=(
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
        
        # Due date
        tk.Label(dialog, text="Due Date (YYYY-MM-DD):").grid(row=5, column=0, sticky='w', padx=10, pady=10)
        due_var = tk.StringVar()
        tk.Entry(dialog, textvariable=due_var, width=40).grid(row=5, column=1, padx=10, pady=10)
        
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
                    due_var.get() or None
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
        if not hasattr(self, 'selected_task') or not self.selected_task:
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
        
        # Due date
        tk.Label(dialog, text="Due Date (YYYY-MM-DD):").grid(row=5, column=0, sticky='w', padx=10, pady=10)
        due_var = tk.StringVar(value=task['due_date'] or "")
        tk.Entry(dialog, textvariable=due_var, width=40).grid(row=5, column=1, padx=10, pady=10)
        
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
                    due_var.get() or None,
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
        if not hasattr(self, 'selected_task') or not self.selected_task:
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
        if not hasattr(self, 'selected_task') or not self.selected_task:
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
