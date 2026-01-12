"""
Theme Manager - GUI Styling
"""

import tkinter as tk
from tkinter import ttk
import json
import os

class ThemeManager:
    """Manages application themes and styles"""
    
    def __init__(self):
        # Theme color definitions
        self.theme_palettes = {
            'dark': {
                'bg_dark': '#1e1e1e',
                'bg_medium': '#252526',
                'bg_light': '#2d2d2d',
                'fg_primary': '#ffffff',
                'fg_secondary': '#cccccc',
                'accent_primary': '#007acc',
                'accent_secondary': '#0098ff',
                'accent_success': '#4caf50',
                'accent_warning': '#ff9800',
                'accent_error': '#f44336',
                'accent_danger': '#f44336',
                'accent_info': '#2196f3',
                'border': '#3e3e42'
            },
            'light': {
                'bg_dark': '#f5f5f5',
                'bg_medium': '#ffffff',
                'bg_light': '#e8e8e8',
                'fg_primary': '#1e1e1e',
                'fg_secondary': '#555555',
                'accent_primary': '#0078d4',
                'accent_secondary': '#0063b1',
                'accent_success': '#107c10',
                'accent_warning': '#ff8c00',
                'accent_error': '#e81123',
                'accent_danger': '#e81123',
                'accent_info': '#0078d4',
                'border': '#cccccc'
            },
            'cyberpunk': {
                'bg_dark': '#0a0e27',
                'bg_medium': '#16213e',
                'bg_light': '#1a2947',
                'fg_primary': '#00ff88',
                'fg_secondary': '#00d4ff',
                'accent_primary': '#ff006e',
                'accent_secondary': '#ff0080',
                'accent_success': '#00ff88',
                'accent_warning': '#ffbe0b',
                'accent_error': '#ff006e',
                'accent_danger': '#ff006e',
                'accent_info': '#00d4ff',
                'border': '#ff006e'
            },
            'forest': {
                'bg_dark': '#1a3a2d',
                'bg_medium': '#2d5c4c',
                'bg_light': '#3a6f5f',
                'fg_primary': '#e8f4f0',
                'fg_secondary': '#b8d4cc',
                'accent_primary': '#4caf50',
                'accent_secondary': '#66bb6a',
                'accent_success': '#66bb6a',
                'accent_warning': '#fbc02d',
                'accent_error': '#d32f2f',
                'accent_danger': '#d32f2f',
                'accent_info': '#29b6f6',
                'border': '#4caf50'
            }
        }
        
        # Current colors (will be set based on current theme)
        self.colors = self.theme_palettes['dark'].copy()
        
        self.available_themes = ['dark', 'light', 'cyberpunk', 'forest']
        self.themes = {
            'dark': {'name': 'Dark Modern'},
            'light': {'name': 'Light Clean'},
            'cyberpunk': {'name': 'Cyberpunk'},
            'forest': {'name': 'Forest'}
        }
        
        self.current_theme = 'dark'
        self.root = None
        self.style = None
        
    def setup_styles(self, root: tk.Tk):
        """Configure ttk styles"""
        self.root = root
        self.style = ttk.Style(root)
        self.style.theme_use('clam')
        
        self._apply_styles()
        
    def _apply_styles(self):
        """Apply current colors to all styles"""
        if not self.style:
            return
            
        # Configure common styles
        self.style.configure('.',
            background=self.colors['bg_medium'],
            foreground=self.colors['fg_primary'],
            fieldbackground=self.colors['bg_light']
        )
        
        self.style.configure('TFrame', background=self.colors['bg_medium'])
        
        self.style.configure('TButton',
            background=self.colors['bg_light'],
            foreground=self.colors['fg_primary'],
            borderwidth=1,
            focuscolor=self.colors['accent_primary']
        )
        
        self.style.map('TButton',
            background=[('active', self.colors['accent_primary'])],
            foreground=[('active', '#ffffff')]
        )
        
        self.style.configure('Accent.TButton',
            background=self.colors['accent_primary'],
            foreground='#ffffff'
        )
        
        self.style.map('Accent.TButton',
            background=[('active', self.colors['accent_secondary'])]
        )
        
        self.style.configure('Treeview',
            background=self.colors['bg_light'],
            foreground=self.colors['fg_primary'],
            fieldbackground=self.colors['bg_light']
        )
        
        self.style.configure('Treeview.Heading',
            background=self.colors['bg_dark'],
            foreground=self.colors['fg_primary'],
            relief='flat'
        )
        
        if self.root:
            self.root.configure(bg=self.colors['bg_medium'])

    def load_settings(self):
        """Load saved theme settings"""
        # Try to load from config file
        try:
            if os.path.exists('config.ini'):
                import configparser
                config = configparser.ConfigParser()
                config.read('config.ini')
                if config.has_section('THEME'):
                    theme = config.get('THEME', 'current', fallback='dark')
                    if theme in self.available_themes:
                        self.apply_theme(theme)
        except Exception as e:
            print(f"Could not load theme settings: {e}")

    def apply_theme(self, theme_id: str):
        """Apply selected theme"""
        if theme_id not in self.available_themes:
            return False
            
        self.current_theme = theme_id
        # Update colors from the palette
        old_bg = self.colors.get('bg_medium', 'unknown')
        self.colors = self.theme_palettes[theme_id].copy()
        new_bg = self.colors.get('bg_medium', 'unknown')
        
        print(f"DEBUG ThemeManager.apply_theme: {theme_id}, bg_medium: {old_bg} -> {new_bg}")
        
        # Re-apply all styles
        self._apply_styles()
        
        # Save theme preference
        self._save_theme_preference(theme_id)
        
        return True

    def _save_theme_preference(self, theme_id: str):
        """Save theme preference to config file"""
        try:
            import configparser
            config = configparser.ConfigParser()
            
            if os.path.exists('config.ini'):
                config.read('config.ini')
            
            if not config.has_section('THEME'):
                config.add_section('THEME')
            
            config.set('THEME', 'current', theme_id)
            
            with open('config.ini', 'w') as f:
                config.write(f)
        except Exception as e:
            print(f"Could not save theme preference: {e}")