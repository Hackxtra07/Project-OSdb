#!/usr/bin/env python3
"""
Secure OSINT Storage System - Main Entry Point
Enhanced version with modular architecture
"""

import sys
import os
import logging
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Configure logging before imports
from utils.logger import setup_logging
setup_logging()

logger = logging.getLogger(__name__)

try:
    import tkinter as tk
    from gui.main_window import MainApplication
    
    def main():
        """Main application entry point"""
        try:
            logger.info("Starting Secure OSINT Storage System...")
            
            # Check for required directories
            required_dirs = ['data', 'data/backups', 'assets/icons', 'logs']
            for dir_path in required_dirs:
                os.makedirs(dir_path, exist_ok=True)
            
            # Create root window
            root = tk.Tk()
            root.title("🔐 Secure OSINT Storage Pro v2.0")
            
            # Set window icon
            try:
                icon_path = project_root / 'assets' / 'icons' / 'app_icon.png'
                if icon_path.exists():
                    icon = tk.PhotoImage(file=str(icon_path))
                    root.iconphoto(True, icon)
            except:
                pass
            
            # Create application instance
            app = MainApplication(root)
            
            # Handle window close
            def on_closing():
                app.cleanup()
                root.quit()
            
            root.protocol("WM_DELETE_WINDOW", on_closing)
            
            # Ensure window is visible
            root.update()
            root.deiconify()
            root.lift()
            root.focus_force()
            
            # Start application
            logger.info("Entering main loop")
            root.mainloop()
            
        except Exception as e:
            logger.error(f"Application failed to start: {e}", exc_info=True)
            sys.exit(1)
    
    if __name__ == "__main__":
        main()
        
except ImportError as e:
    logger.error(f"Import error: {e}")
    print(f"Error: {e}")
    print("Please install required dependencies:")
    print("pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    logger.error(f"Fatal error: {e}", exc_info=True)
    sys.exit(1)