"""
Enhanced Database Manager with connection pooling and advanced features
"""

import sqlite3
import hashlib
import json
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Advanced database management with connection pooling and caching"""
    
    def __init__(self, db_path: str = "data/database.db"):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._connection_pool = []
        self._max_pool_size = 5
        self._cache = {}
        self._cache_timeout = 300  # 5 minutes
        
        # Initialize database
        self._init_database()
        
    @contextmanager
    def get_connection(self):
        """Get database connection from pool"""
        conn = None
        try:
            with self._lock:
                if self._connection_pool:
                    conn = self._connection_pool.pop()
                else:
                    conn = self._create_connection()
            
            yield conn
        finally:
            if conn:
                with self._lock:
                    if len(self._connection_pool) < self._max_pool_size:
                        self._connection_pool.append(conn)
                    else:
                        conn.close()
    
    def _create_connection(self):
        """Create new database connection"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA cache_size = -2000")  # 2MB cache
        return conn
    
    def _init_database(self):
        """Initialize database with all tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table with enhanced security fields
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    role TEXT DEFAULT 'user',
                    pin_hash TEXT,
                    twofa_secret TEXT,
                    twofa_enabled INTEGER DEFAULT 0,
                    twofa_method TEXT DEFAULT 'totp',
                    backup_codes TEXT,
                    security_level INTEGER DEFAULT 2,
                    login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP,
                    last_login TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT DEFAULT '{}',
                    api_keys TEXT DEFAULT '{}',
                    yubikey_id TEXT,
                    biometric_data TEXT,
                    CONSTRAINT chk_security_level CHECK (security_level BETWEEN 1 AND 4)
                )
            ''')
            
            # Migration: Check for role column in existing table
            try:
                cursor.execute("SELECT role FROM users LIMIT 1")
            except sqlite3.OperationalError:
                # Column missing, add it
                logger.info("Migrating schema: Adding role column to users table")
                cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
            
            # Credentials table with enhanced fields
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    service TEXT NOT NULL,
                    username TEXT,
                    password_encrypted TEXT NOT NULL,
                    url TEXT,
                    category TEXT DEFAULT 'General',
                    tags TEXT DEFAULT '[]',
                    notes TEXT,
                    security_level INTEGER DEFAULT 1,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    password_strength INTEGER,
                    password_last_changed TIMESTAMP,
                    breach_check_result TEXT,
                    last_breach_check TIMESTAMP,
                    auto_fill_data TEXT DEFAULT '{}',
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    CONSTRAINT chk_password_strength CHECK (password_strength BETWEEN 1 AND 5)
                )
            ''')
            
            # Secure notes with versioning
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS secure_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    content_encrypted TEXT NOT NULL,
                    category TEXT DEFAULT 'General',
                    tags TEXT DEFAULT '[]',
                    is_encrypted INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    version INTEGER DEFAULT 1,
                    previous_version_id INTEGER,
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (previous_version_id) REFERENCES secure_notes (id)
                )
            ''')
            
            # OSINT projects with collaboration
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS osint_projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    status TEXT DEFAULT 'active',
                    priority INTEGER DEFAULT 1,
                    tags TEXT DEFAULT '[]',
                    start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_date TIMESTAMP,
                    collaborators TEXT DEFAULT '[]',
                    budget REAL DEFAULT 0.0,
                    client_name TEXT,
                    client_email TEXT,
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    CONSTRAINT chk_priority CHECK (priority BETWEEN 1 AND 5),
                    CONSTRAINT chk_status CHECK (status IN ('planning', 'active', 'paused', 'completed', 'archived'))
                )
            ''')
            
            # Project tasks for investigation tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS project_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    status TEXT DEFAULT 'pending',
                    priority INTEGER DEFAULT 1,
                    assigned_to TEXT,
                    due_date TIMESTAMP,
                    completed_date TIMESTAMP,
                    tags TEXT DEFAULT '[]',
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (project_id) REFERENCES osint_projects (id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    CONSTRAINT chk_task_priority CHECK (priority BETWEEN 1 AND 5),
                    CONSTRAINT chk_task_status CHECK (status IN ('pending', 'in_progress', 'review', 'completed', 'cancelled'))
                )
            ''')
            
            # Investigation evidence
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS investigation_evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    evidence_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    content TEXT,
                    file_path TEXT,
                    source_url TEXT,
                    collected_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    credibility_score INTEGER DEFAULT 3,
                    verified BOOLEAN DEFAULT 0,
                    tags TEXT DEFAULT '[]',
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (project_id) REFERENCES osint_projects (id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    CONSTRAINT chk_credibility CHECK (credibility_score BETWEEN 1 AND 5)
                )
            ''')
            
            # API integration results
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    api_name TEXT NOT NULL,
                    query TEXT NOT NULL,
                    result TEXT,
                    status TEXT DEFAULT 'success',
                    response_time REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')
            
            # Threat intelligence feeds
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    severity TEXT DEFAULT 'medium',
                    description TEXT,
                    ioc TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    confidence REAL DEFAULT 0.5,
                    mitigation TEXT,
                    metadata TEXT DEFAULT '{}',
                    CONSTRAINT chk_severity CHECK (severity IN ('low', 'medium', 'high', 'critical'))
                )
            ''')
            
            # Categories for tagging
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    type TEXT NOT NULL,
                    color TEXT DEFAULT '#CCCCCC',
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Audit Log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    details TEXT,
                    severity TEXT DEFAULT 'info',
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Security Events
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    source_ip TEXT,
                    target_user TEXT,
                    status TEXT DEFAULT 'open',
                    resolved INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolution_notes TEXT
                )
            ''')

            
            # Create indexes
            self._create_indexes(cursor)
            
            # Create triggers
            self._create_triggers(cursor)
            
            conn.commit()
            
            # Initialize default data
            self._initialize_default_data(cursor)
            
            conn.commit()
    
    def _create_indexes(self, cursor):
        """Create database indexes"""
        indexes = [
            # Users indexes
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            "CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login)",
            
            # Credentials indexes
            "CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_credentials_service ON credentials(service)",
            "CREATE INDEX IF NOT EXISTS idx_credentials_category ON credentials(category)",
            "CREATE INDEX IF NOT EXISTS idx_credentials_expires ON credentials(expires_at)",
            
            # Notes indexes
            "CREATE INDEX IF NOT EXISTS idx_notes_user_id ON secure_notes(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_notes_title ON secure_notes(title)",
            "CREATE INDEX IF NOT EXISTS idx_notes_category ON secure_notes(category)",
            
            # Projects indexes
            "CREATE INDEX IF NOT EXISTS idx_projects_user_id ON osint_projects(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_projects_status ON osint_projects(status)",
            "CREATE INDEX IF NOT EXISTS idx_projects_priority ON osint_projects(priority)",
            
            # Evidence indexes
            "CREATE INDEX IF NOT EXISTS idx_evidence_project_id ON investigation_evidence(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_evidence_type ON investigation_evidence(evidence_type)",
            "CREATE INDEX IF NOT EXISTS idx_evidence_credibility ON investigation_evidence(credibility_score)",
            
            # Threat intelligence indexes
            "CREATE INDEX IF NOT EXISTS idx_threat_severity ON threat_intelligence(severity)",
            "CREATE INDEX IF NOT EXISTS idx_threat_last_seen ON threat_intelligence(last_seen)",
        ]
        
        for index in indexes:
            try:
                cursor.execute(index)
            except Exception as e:
                logger.error(f"Failed to create index: {e}")
    
    def _create_triggers(self, cursor):
        """Create database triggers"""
        triggers = [
            '''
            CREATE TRIGGER IF NOT EXISTS update_user_timestamp 
            AFTER UPDATE ON users 
            BEGIN
                UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END;
            ''',
            '''
            CREATE TRIGGER IF NOT EXISTS update_note_version
            BEFORE UPDATE ON secure_notes
            WHEN NEW.content_encrypted != OLD.content_encrypted
            BEGIN
                INSERT INTO secure_notes (user_id, title, content_encrypted, category, tags, 
                                        is_encrypted, created_at, last_modified, 
                                        previous_version_id, metadata)
                SELECT user_id, title, OLD.content_encrypted, category, tags, 
                       is_encrypted, created_at, CURRENT_TIMESTAMP, 
                       NULL, metadata
                FROM secure_notes WHERE id = OLD.id;
                
                UPDATE secure_notes 
                SET version = OLD.version + 1,
                    previous_version_id = (SELECT last_insert_rowid())
                WHERE id = OLD.id;
            END;
            ''',
            '''
            CREATE TRIGGER IF NOT EXISTS credential_auto_expire
            AFTER UPDATE OF expires_at ON credentials
            WHEN NEW.expires_at < CURRENT_TIMESTAMP
            BEGIN
                UPDATE credentials SET security_level = 4 WHERE id = NEW.id;
            END;
            '''
        ]
        
        for trigger in triggers:
            try:
                cursor.execute(trigger)
            except Exception as e:
                logger.error(f"Failed to create trigger: {e}")
    
    def _initialize_default_data(self, cursor):
        """Initialize default categories and tags"""
        # Default categories for credentials
        default_categories = [
            ('Social Media', '#FF6B6B'),
            ('Email', '#4ECDC4'),
            ('Banking', '#45B7D1'),
            ('Shopping', '#96CEB4'),
            ('Work', '#FFEAA7'),
            ('Government', '#DDA0DD'),
            ('Education', '#98D8C8'),
            ('Entertainment', '#F7DC6F'),
        ]
        
        for name, color in default_categories:
            cursor.execute('''
                INSERT OR IGNORE INTO categories (name, type, color)
                VALUES (?, 'credential', ?)
            ''', (name, color))
    
    def hash_password(self, password: str, salt: bytes) -> str:
        """Hash password with salt using Argon2 (simulated with PBKDF2)"""
        return hashlib.pbkdf2_hmac(
            'sha512', 
            password.encode(), 
            salt, 
            310000,  # OWASP recommended iterations for PBKDF2
            dklen=64
        ).hex()
    
    def log_audit(self, user_id: int, action: str, details: str = "", 
                 severity: str = "info", ip: str = None, user_agent: str = None):
        """Log audit event"""
        cache_key = f"audit_{user_id}_{action}_{severity}"
        current_time = time.time()
        
        # Rate limiting for audit logs
        if cache_key in self._cache:
            last_log = self._cache[cache_key]
            if current_time - last_log < 1:  # 1 second cooldown
                return
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_log (user_id, action, details, severity, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, action, details, severity, ip, user_agent))
            conn.commit()
        
        self._cache[cache_key] = current_time
    
    def log_security_event(self, user_id: Optional[int], event_type: str, 
                          description: str, severity: str, ip: str = None):
        """Log security event"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_events (
                    event_type, severity, description, source_ip, target_user, status
                ) VALUES (?, ?, ?, ?, ?, 'open')
            ''', (event_type, severity, description, ip, str(user_id) if user_id else None))
            conn.commit()

    
    def backup_database(self, backup_path: str = None) -> str:
        """Create encrypted database backup"""
        import shutil
        import zipfile
        from datetime import datetime
        
        if backup_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"data/backups/backup_{timestamp}.zip"
        
        try:
            # Create backup directory
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Backup database file
                zipf.write(self.db_path, "database.db")
                
                # Backup configuration
                config_data = {
                    'backup_date': datetime.now().isoformat(),
                    'database_version': '2.0',
                    'backup_type': 'full'
                }
                zipf.writestr("config.json", json.dumps(config_data, indent=2))
            
            logger.info(f"Database backup created: {backup_path}")
            return backup_path
            
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return None
    
    def vacuum(self):
        """Optimize database"""
        with self.get_connection() as conn:
            conn.execute("VACUUM")
            conn.commit()
        logger.info("Database optimized")
    
    def get_statistics(self, user_id: int = None) -> Dict[str, Any]:
        """Get database statistics"""
        stats = {}
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # User-specific stats
            if user_id:
                # Credential stats
                cursor.execute('''
                    SELECT COUNT(*) as total,
                           SUM(CASE WHEN password_strength <= 2 THEN 1 ELSE 0 END) as weak,
                           SUM(CASE WHEN expires_at < datetime('now') THEN 1 ELSE 0 END) as expired
                    FROM credentials WHERE user_id = ?
                ''', (user_id,))
                cred_stats = cursor.fetchone()
                stats['credentials'] = dict(cred_stats)
                
                # Note stats
                cursor.execute('''
                    SELECT COUNT(*) as total,
                           COUNT(DISTINCT category) as categories
                    FROM secure_notes WHERE user_id = ?
                ''', (user_id,))
                note_stats = cursor.fetchone()
                stats['notes'] = dict(note_stats)
                
                # Project stats
                cursor.execute('''
                    SELECT COUNT(*) as total,
                           SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
                           SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed
                    FROM osint_projects WHERE user_id = ?
                ''', (user_id,))
                project_stats = cursor.fetchone()
                stats['projects'] = dict(project_stats)
            
            # System-wide stats
            cursor.execute("SELECT COUNT(*) FROM users")
            stats['total_users'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM audit_log WHERE timestamp > datetime('now', '-24 hours')")
            stats['audit_events_24h'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM security_events WHERE resolved = 0")
            stats['active_security_events'] = cursor.fetchone()[0]
        
        return stats
    
    def execute_query(self, query: str, params: tuple = None, fetch_all: bool = True):
        """Execute SQL query with error handling"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                if fetch_all:
                    result = cursor.fetchall()
                else:
                    result = cursor.fetchone()
                
                if not query.strip().upper().startswith('SELECT'):
                    conn.commit()
                
                return result
        except Exception as e:
            logger.error(f"Query failed: {e}\nQuery: {query}\nParams: {params}")
            raise
    
    def close_all(self):
        """Close all database connections"""
        with self._lock:
            for conn in self._connection_pool:
                try:
                    conn.close()
                except:
                    pass
            self._connection_pool.clear()