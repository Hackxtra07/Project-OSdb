"""
Calendar Date Picker Utility
Provides a reusable date picker widget for date selection with calendar interface
"""

import tkinter as tk
from tkinter import ttk
from datetime import datetime, timedelta
import calendar


class CalendarPicker:
    """Standalone calendar date picker - no external dependencies"""
    
    def __init__(self, parent, initial_date=None, on_select=None):
        """
        Initialize calendar picker
        
        Args:
            parent: Parent widget
            initial_date: Starting date (str 'YYYY-MM-DD' or datetime object, default=today)
            on_select: Callback function when date is selected, receives date string 'YYYY-MM-DD'
        """
        self.parent = parent
        self.on_select = on_select
        self.selected_date = None
        
        # Parse initial date
        if initial_date:
            if isinstance(initial_date, str):
                try:
                    self.current_date = datetime.strptime(initial_date, '%Y-%m-%d')
                except (ValueError, TypeError):
                    self.current_date = datetime.now()
            else:
                self.current_date = initial_date
        else:
            self.current_date = datetime.now()
    
    def show(self):
        """Display calendar picker dialog"""
        dialog = tk.Toplevel(self.parent)
        dialog.title("Select Date")
        dialog.geometry("400x350")
        dialog.resizable(False, False)
        
        # Make it modal
        dialog.transient(self.parent)
        dialog.grab_set()
        
        # Header with month/year
        header = tk.Frame(dialog, bg="#2c3e50")
        header.pack(fill=tk.X, padx=5, pady=5)
        
        nav_frame = tk.Frame(header, bg="#2c3e50")
        nav_frame.pack(fill=tk.X, padx=5, pady=10)
        
        # Navigation buttons
        tk.Button(nav_frame, text="◀", command=lambda: self.prev_month(dialog, content_frame),
                 bg="#34495e", fg="white", width=3).pack(side=tk.LEFT)
        
        self.month_label = tk.Label(nav_frame, text="", font=("Arial", 14, "bold"),
                                    bg="#2c3e50", fg="white")
        self.month_label.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=10)
        
        tk.Button(nav_frame, text="▶", command=lambda: self.next_month(dialog, content_frame),
                 bg="#34495e", fg="white", width=3).pack(side=tk.LEFT)
        
        # Calendar content frame
        content_frame = tk.Frame(dialog, bg="white")
        content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Today button
        today_frame = tk.Frame(dialog, bg="white")
        today_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(today_frame, text="Today", command=lambda: self.select_today(dialog),
                 bg="#3498db", fg="white", width=10).pack(side=tk.LEFT, padx=2)
        
        tk.Button(today_frame, text="Clear", command=lambda: self.clear_date(dialog),
                 bg="#95a5a6", fg="white", width=10).pack(side=tk.LEFT, padx=2)
        
        tk.Button(today_frame, text="Cancel", command=dialog.destroy,
                 bg="#e74c3c", fg="white", width=10).pack(side=tk.LEFT, padx=2)
        
        # Initial render
        self.render_calendar(content_frame)
        
        # Center dialog on parent
        dialog.update_idletasks()
        x = self.parent.winfo_x() + (self.parent.winfo_width() // 2) - (dialog.winfo_width() // 2)
        y = self.parent.winfo_y() + (self.parent.winfo_height() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        return self.selected_date
    
    def render_calendar(self, parent):
        """Render calendar grid"""
        # Clear existing widgets
        for widget in parent.winfo_children():
            widget.destroy()
        
        # Update month/year label
        self.month_label.config(text=self.current_date.strftime("%B %Y"))
        
        # Days of week header
        days_header = tk.Frame(parent, bg="white")
        days_header.pack(fill=tk.X, padx=5, pady=5)
        
        day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        for day_name in day_names:
            is_weekend = day_names.index(day_name) >= 5
            tk.Label(days_header, text=day_name, font=("Arial", 10, "bold"),
                    bg="#ecf0f1" if not is_weekend else "#ffcccc", width=5).pack(side=tk.LEFT, padx=1, pady=1)
        
        # Calendar grid
        cal_frame = tk.Frame(parent, bg="white")
        cal_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Get calendar
        month_cal = calendar.monthcalendar(self.current_date.year, self.current_date.month)
        
        for week_num, week in enumerate(month_cal):
            week_frame = tk.Frame(cal_frame, bg="white")
            week_frame.pack(fill=tk.X)
            
            for day_num, day in enumerate(week):
                if day == 0:
                    # Empty cell
                    tk.Label(week_frame, text="", width=5, height=2).pack(side=tk.LEFT, padx=1, pady=1)
                else:
                    # Date button
                    is_weekend = day_num >= 5
                    is_today = (day == datetime.now().day and 
                               self.current_date.month == datetime.now().month and
                               self.current_date.year == datetime.now().year)
                    
                    is_selected = (day == self.current_date.day)
                    
                    bg_color = "#3498db" if is_selected else ("#ffcccc" if is_weekend else "#ecf0f1")
                    fg_color = "white" if is_selected else "black"
                    font_weight = "bold" if is_today else "normal"
                    
                    btn = tk.Button(week_frame, text=str(day), width=5, height=2,
                                   bg=bg_color, fg=fg_color, font=("Arial", 10, font_weight),
                                   command=lambda d=day: self.select_date(d, parent.winfo_toplevel()))
                    btn.pack(side=tk.LEFT, padx=1, pady=1)
    
    def select_date(self, day, dialog):
        """Select a date"""
        self.current_date = self.current_date.replace(day=day)
        self.selected_date = self.current_date.strftime('%Y-%m-%d')
        
        if self.on_select:
            self.on_select(self.selected_date)
        
        dialog.destroy()
    
    def select_today(self, dialog):
        """Select today's date"""
        self.selected_date = datetime.now().strftime('%Y-%m-%d')
        
        if self.on_select:
            self.on_select(self.selected_date)
        
        dialog.destroy()
    
    def clear_date(self, dialog):
        """Clear date selection"""
        self.selected_date = None
        
        if self.on_select:
            self.on_select(None)
        
        dialog.destroy()
    
    def prev_month(self, dialog, content_frame):
        """Go to previous month"""
        first_day = self.current_date.replace(day=1)
        last_day = first_day - timedelta(days=1)
        self.current_date = last_day.replace(day=1)
        self.render_calendar(content_frame)
    
    def next_month(self, dialog, content_frame):
        """Go to next month"""
        last_day = self.current_date.replace(day=calendar.monthrange(self.current_date.year, 
                                                                     self.current_date.month)[1])
        next_day = last_day + timedelta(days=1)
        self.current_date = next_day.replace(day=1)
        self.render_calendar(content_frame)


class DatePickerButton(tk.Frame):
    """Composite widget: Date display + Calendar picker button"""
    
    def __init__(self, parent, initial_date=None, **kwargs):
        """
        Initialize date picker button widget
        
        Args:
            parent: Parent widget
            initial_date: Initial date string 'YYYY-MM-DD'
        """
        super().__init__(parent, **kwargs)
        
        self.date_var = tk.StringVar(value=initial_date or "")
        
        # Display frame
        date_display = tk.Entry(self, textvariable=self.date_var, width=15, state='readonly')
        date_display.pack(side=tk.LEFT, padx=2)
        
        # Calendar button
        tk.Button(self, text="📅", command=self.pick_date, width=3).pack(side=tk.LEFT, padx=2)
    
    def pick_date(self):
        """Open calendar picker"""
        current = self.date_var.get()
        picker = CalendarPicker(self, initial_date=current, on_select=self.set_date)
        picker.show()
    
    def set_date(self, date_str):
        """Set selected date"""
        self.date_var.set(date_str or "")
    
    def get(self):
        """Get current date value"""
        return self.date_var.get() or None
    
    def set(self, date_str):
        """Set date value"""
        self.date_var.set(date_str or "")
