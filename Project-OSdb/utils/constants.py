"""
Application Constants
"""

import os

# Application Info
APP_NAME = "Secure OSINT Storage Pro"
APP_VERSION = "2.0.0"
APP_AUTHOR = "HackXtra"

# Directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_DIR = os.path.join(BASE_DIR, "logs")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")

# Database
DEFAULT_DB_PATH = os.path.join(DATA_DIR, "database.db")

# Window
DEFAULT_WINDOW_WIDTH = 1280
DEFAULT_WINDOW_HEIGHT = 800
MIN_WINDOW_WIDTH = 1024
MIN_WINDOW_HEIGHT = 768

# Security
MIN_PASSWORD_LENGTH = 12
PBKDF2_ITERATIONS = 310000
SESSION_TIMEOUT = 1800  # 30 minutes

# File Types
SUPPORTED_IMAGE_FORMATS = [".jpg", ".jpeg", ".png", ".bmp", ".gif"]
SUPPORTED_DOC_FORMATS = [".txt", ".pdf", ".doc", ".docx", ".csv", ".json"]

# Themes
DEFAULT_THEME = "dark"