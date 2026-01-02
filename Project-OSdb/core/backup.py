"""
Advanced Backup and Restore Management
"""

import os
import json
import zipfile
import shutil
import tempfile
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import logging
import threading
import schedule
import time

logger = logging.getLogger(__name__)

class BackupManager:
    """Complete backup management with encryption, scheduling, and cloud sync"""
    
    def __init__(self, db_manager, encryption_manager):
        self.db = db_manager
        self.encryption = encryption_manager
        self.backup_dir = "data/backups"
        self.cloud_sync_dir = None
        self.retention_days = 30
        
        # Create backup directory
        os.makedirs(self.backup_dir, exist_ok=True)
        
        # Backup schedules
        self.schedules = {
            'daily': {'interval': 24, 'enabled': True},
            'weekly': {'interval': 168, 'enabled': True},
            'monthly': {'interval': 720, 'enabled': True}
        }
        
        # Start scheduler thread
        self.scheduler_thread = threading.Thread(target=self.run_scheduler, daemon=True)
        self.scheduler_thread.start()
        
        logger.info(f"Backup manager initialized. Backups stored in: {self.backup_dir}")
    
    def run_scheduler(self):
        """Run backup scheduler"""
        # Schedule daily backup at 2 AM
        schedule.every().day.at("02:00").do(self.create_scheduled_backup, 'daily')
        
        # Schedule weekly backup on Sunday at 3 AM
        schedule.every().sunday.at("03:00").do(self.create_scheduled_backup, 'weekly')
        
        # Schedule monthly backup on 1st at 4 AM
        schedule.every().day.at("04:00").do(self.check_monthly_backup)
        
        while True:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                time.sleep(60)
    
    def check_monthly_backup(self):
        """Check if monthly backup is needed"""
        today = datetime.now()
        if today.day == 1:  # First day of month
            self.create_scheduled_backup('monthly')
    
    def create_scheduled_backup(self, backup_type: str):
        """Create scheduled backup"""
        if not self.schedules[backup_type]['enabled']:
            return
        
        try:
            logger.info(f"Creating scheduled {backup_type} backup")
            
            # Create backup
            backup_data = self.create_backup(
                user_id=0,  # System backup
                backup_type=backup_type,
                description=f"Scheduled {backup_type} backup"
            )
            
            if backup_data['success']:
                logger.info(f"Scheduled {backup_type} backup created: {backup_data['filename']}")
                
                # Apply retention policy
                self.apply_retention_policy(backup_type)
                
                # Sync to cloud if configured
                if self.cloud_sync_dir:
                    self.sync_to_cloud(backup_data['filepath'])
            
        except Exception as e:
            logger.error(f"Failed to create scheduled backup: {e}")
    
    def create_backup(self, user_id: int, backup_type: str = "full", 
                     password: str = None, description: str = "") -> Dict[str, Any]:
        """Create encrypted backup"""
        backup_id = hashlib.md5(f"{datetime.now().timestamp()}".encode()).hexdigest()[:8]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"backup_{backup_type}_{timestamp}_{backup_id}.zip"
        filepath = os.path.join(self.backup_dir, filename)
        
        try:
            # Create temporary directory
            temp_dir = tempfile.mkdtemp()
            
            # Backup database
            db_backup_path = os.path.join(temp_dir, "database.db")
            shutil.copy2(self.db.db_path, db_backup_path)
            
            # Backup configuration
            config_data = self.get_system_config()
            config_path = os.path.join(temp_dir, "config.json")
            with open(config_path, 'w') as f:
                json.dump(config_data, f, indent=2, default=str)
            
            # Backup user data if specified
            if user_id > 0:
                user_data = self.export_user_data(user_id)
                user_path = os.path.join(temp_dir, "user_data.json")
                with open(user_path, 'w') as f:
                    json.dump(user_data, f, indent=2, default=str)
            
            # Create zip archive
            with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, temp_dir)
                        zipf.write(file_path, arcname)
            
            # Encrypt if password provided
            if password:
                encrypted_path = filepath + ".enc"
                key, _ = self.encryption.generate_key(password)
                
                # Read zip file
                with open(filepath, 'rb') as f:
                    zip_data = f.read()
                
                # Encrypt
                encrypted_data = self.encryption.encrypt_data(zip_data, key)
                
                # Write encrypted file
                with open(encrypted_path, 'wb') as f:
                    f.write(encrypted_data.encode() if isinstance(encrypted_data, str) else encrypted_data)
                
                # Remove original zip
                os.remove(filepath)
                filepath = encrypted_path
            
            # Cleanup temp directory
            shutil.rmtree(temp_dir)
            
            # Calculate file size
            file_size = os.path.getsize(filepath)
            
            # Log backup creation
            self.db.log_audit(user_id, "BACKUP_CREATED", 
                            f"Created {backup_type} backup: {filename} ({self.format_size(file_size)})")
            
            # Record backup in database
            self.record_backup(user_id, filename, filepath, backup_type, file_size, description)
            
            return {
                'success': True,
                'filename': filename,
                'filepath': filepath,
                'size': file_size,
                'size_formatted': self.format_size(file_size),
                'backup_id': backup_id,
                'timestamp': timestamp,
                'encrypted': password is not None
            }
            
        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def restore_backup(self, backup_path: str, user_id: int, 
                      password: str = None) -> Dict[str, Any]:
        """Restore from backup"""
        try:
            original_path = backup_path
            
            # Decrypt if encrypted
            if backup_path.endswith('.enc'):
                if not password:
                    return {'success': False, 'error': 'Password required for encrypted backup'}
                
                # Read encrypted file
                with open(backup_path, 'rb') as f:
                    encrypted_data = f.read()
                
                # Decrypt
                key, _ = self.encryption.generate_key(password)
                decrypted_data = self.encryption.decrypt_data(encrypted_data, key)
                
                # Write decrypted file
                temp_path = backup_path.replace('.enc', '.decrypted')
                with open(temp_path, 'wb') as f:
                    f.write(decrypted_data.encode() if isinstance(decrypted_data, str) else decrypted_data)
                
                backup_path = temp_path
            
            # Create temporary directory for extraction
            temp_dir = tempfile.mkdtemp()
            
            # Extract backup
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                zipf.extractall(temp_dir)
            
            # Restore database
            db_backup = os.path.join(temp_dir, "database.db")
            if os.path.exists(db_backup):
                # Create backup of current database
                current_backup = f"{self.db.db_path}.restore_backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2(self.db.db_path, current_backup)
                
                # Restore from backup
                shutil.copy2(db_backup, self.db.db_path)
                
                # Reinitialize database connection
                self.db.init_database()
            
            # Restore user data if exists
            user_data_path = os.path.join(temp_dir, "user_data.json")
            if os.path.exists(user_data_path):
                with open(user_data_path, 'r') as f:
                    user_data = json.load(f)
                # User data restoration would be implemented here
            
            # Cleanup
            shutil.rmtree(temp_dir)
            if backup_path != original_path:
                os.remove(backup_path)
            
            # Log restoration
            self.db.log_audit(user_id, "BACKUP_RESTORED", 
                            f"Restored from backup: {os.path.basename(original_path)}")
            
            return {'success': True}
            
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def export_user_data(self, user_id: int) -> Dict[str, Any]:
        """Export all user data"""
        cursor = self.db.conn.cursor()
        
        data = {
            'export_info': {
                'user_id': user_id,
                'export_date': datetime.now().isoformat(),
                'export_version': '2.0'
            },
            'user_profile': {},
            'credentials': [],
            'notes': [],
            'projects': [],
            'audit_logs': []
        }
        
        try:
            # Get user profile
            cursor.execute('''
                SELECT username, email, security_level, twofa_enabled, 
                       created_at, last_login
                FROM users WHERE id = ?
            ''', (user_id,))
            user = cursor.fetchone()
            if user:
                data['user_profile'] = dict(user)
            
            # Get credentials (without encrypted passwords)
            cursor.execute('''
                SELECT id, service, username, url, category, tags, notes,
                       security_level, last_updated, expires_at, password_strength
                FROM credentials WHERE user_id = ?
            ''', (user_id,))
            data['credentials'] = [dict(row) for row in cursor.fetchall()]
            
            # Get notes (without encrypted content)
            cursor.execute('''
                SELECT id, title, category, tags, created_at, last_modified, version
                FROM secure_notes WHERE user_id = ?
            ''', (user_id,))
            data['notes'] = [dict(row) for row in cursor.fetchall()]
            
            # Get projects
            cursor.execute('''
                SELECT id, name, description, status, priority, tags,
                       start_date, end_date, collaborators
                FROM osint_projects WHERE user_id = ?
            ''', (user_id,))
            data['projects'] = [dict(row) for row in cursor.fetchall()]
            
            # Get audit logs
            cursor.execute('''
                SELECT action, details, timestamp, severity, ip_address
                FROM audit_log WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT 1000
            ''', (user_id,))
            data['audit_logs'] = [dict(row) for row in cursor.fetchall()]
            
        except Exception as e:
            logger.error(f"Failed to export user data: {e}")
        
        return data
    
    def get_system_config(self) -> Dict[str, Any]:
        """Get system configuration for backup"""
        cursor = self.db.conn.cursor()
        
        config = {
            'backup_info': {
                'backup_date': datetime.now().isoformat(),
                'system_version': '2.0',
                'backup_type': 'system'
            },
            'system_stats': {},
            'user_stats': {}
        }
        
        try:
            # Get system statistics
            cursor.execute("SELECT COUNT(*) as user_count FROM users")
            config['user_stats']['total_users'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) as cred_count FROM credentials")
            config['system_stats']['total_credentials'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) as note_count FROM secure_notes")
            config['system_stats']['total_notes'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) as project_count FROM osint_projects")
            config['system_stats']['total_projects'] = cursor.fetchone()[0]
            
            # Database info
            config['system_stats']['database_size'] = os.path.getsize(self.db.db_path)
            config['system_stats']['database_size_formatted'] = self.format_size(
                os.path.getsize(self.db.db_path))
            
        except Exception as e:
            logger.error(f"Failed to get system config: {e}")
        
        return config
    
    def record_backup(self, user_id: int, filename: str, filepath: str, 
                     backup_type: str, size: int, description: str = ""):
        """Record backup in database"""
        try:
            cursor = self.db.conn.cursor()
            
            cursor.execute('''
                INSERT INTO data_exports 
                (user_id, export_type, file_path, file_size, description)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, backup_type, filepath, size, description))
            
            self.db.conn.commit()
            
        except Exception as e:
            logger.error(f"Failed to record backup: {e}")
    
    def apply_retention_policy(self, backup_type: str):
        """Apply backup retention policy"""
        try:
            backup_files = []
            
            # List backup files
            for filename in os.listdir(self.backup_dir):
                if filename.startswith(f"backup_{backup_type}_") and filename.endswith(('.zip', '.zip.enc')):
                    filepath = os.path.join(self.backup_dir, filename)
                    mtime = os.path.getmtime(filepath)
                    backup_files.append({
                        'filename': filename,
                        'filepath': filepath,
                        'mtime': mtime,
                        'date': datetime.fromtimestamp(mtime)
                    })
            
            # Sort by date (oldest first)
            backup_files.sort(key=lambda x: x['mtime'])
            
            # Determine how many to keep based on type
            if backup_type == 'daily':
                keep_count = 7  # Keep 7 daily backups
            elif backup_type == 'weekly':
                keep_count = 4  # Keep 4 weekly backups
            elif backup_type == 'monthly':
                keep_count = 12  # Keep 12 monthly backups
            else:
                keep_count = 30  # Default: 30 days
            
            # Delete old backups
            if len(backup_files) > keep_count:
                to_delete = backup_files[:len(backup_files) - keep_count]
                
                for backup in to_delete:
                    try:
                        os.remove(backup['filepath'])
                        logger.info(f"Deleted old backup: {backup['filename']}")
                        
                        # Log deletion
                        self.db.log_audit(0, "BACKUP_DELETED",
                                        f"Deleted old {backup_type} backup: {backup['filename']}")
                    except Exception as e:
                        logger.error(f"Failed to delete backup {backup['filename']}: {e}")
        
        except Exception as e:
            logger.error(f"Failed to apply retention policy: {e}")
    
    def sync_to_cloud(self, filepath: str):
        """Sync backup to cloud storage"""
        if not self.cloud_sync_dir:
            return
        
        try:
            filename = os.path.basename(filepath)
            dest_path = os.path.join(self.cloud_sync_dir, filename)
            
            # Copy to cloud directory
            shutil.copy2(filepath, dest_path)
            
            logger.info(f"Synced backup to cloud: {filename}")
            
        except Exception as e:
            logger.error(f"Cloud sync failed: {e}")
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List all available backups"""
        backups = []
        
        try:
            for filename in os.listdir(self.backup_dir):
                if filename.startswith('backup_') and filename.endswith(('.zip', '.zip.enc')):
                    filepath = os.path.join(self.backup_dir, filename)
                    stat = os.stat(filepath)
                    
                    # Parse backup info from filename
                    parts = filename.split('_')
                    if len(parts) >= 4:
                        backup_type = parts[1]
                        timestamp = parts[2]
                        
                        try:
                            backup_date = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
                        except:
                            backup_date = datetime.fromtimestamp(stat.st_mtime)
                        
                        backups.append({
                            'filename': filename,
                            'filepath': filepath,
                            'type': backup_type,
                            'date': backup_date,
                            'size': stat.st_size,
                            'size_formatted': self.format_size(stat.st_size),
                            'encrypted': filename.endswith('.enc'),
                            'age_days': (datetime.now() - backup_date).days
                        })
            
            # Sort by date (newest first)
            backups.sort(key=lambda x: x['date'], reverse=True)
            
        except Exception as e:
            logger.error(f"Failed to list backups: {e}")
        
        return backups
    
    def get_backup_stats(self) -> Dict[str, Any]:
        """Get backup statistics"""
        backups = self.list_backups()
        
        stats = {
            'total_backups': len(backups),
            'total_size': 0,
            'by_type': {},
            'oldest_backup': None,
            'newest_backup': None
        }
        
        for backup in backups:
            stats['total_size'] += backup['size']
            
            # Count by type
            backup_type = backup['type']
            if backup_type not in stats['by_type']:
                stats['by_type'][backup_type] = 0
            stats['by_type'][backup_type] += 1
            
            # Track oldest and newest
            if not stats['oldest_backup'] or backup['date'] < stats['oldest_backup']:
                stats['oldest_backup'] = backup['date']
            if not stats['newest_backup'] or backup['date'] > stats['newest_backup']:
                stats['newest_backup'] = backup['date']
        
        stats['total_size_formatted'] = self.format_size(stats['total_size'])
        
        if stats['oldest_backup']:
            stats['oldest_backup_days'] = (datetime.now() - stats['oldest_backup']).days
        if stats['newest_backup']:
            stats['newest_backup_days'] = (datetime.now() - stats['newest_backup']).days
        
        return stats
    
    def verify_backup(self, filepath: str, password: str = None) -> Dict[str, Any]:
        """Verify backup integrity"""
        try:
            temp_path = filepath
            
            # Decrypt if needed
            if filepath.endswith('.enc'):
                if not password:
                    return {'success': False, 'error': 'Password required'}
                
                # Read and decrypt
                with open(filepath, 'rb') as f:
                    encrypted_data = f.read()
                
                key, _ = self.encryption.generate_key(password)
                decrypted_data = self.encryption.decrypt_data(encrypted_data, key)
                
                # Write to temp file
                temp_path = tempfile.mktemp(suffix='.zip')
                with open(temp_path, 'wb') as f:
                    f.write(decrypted_data.encode() if isinstance(decrypted_data, str) else decrypted_data)
            
            # Verify zip integrity
            with zipfile.ZipFile(temp_path, 'r') as zipf:
                # Test zip file
                test_result = zipf.testzip()
                
                if test_result is not None:
                    return {'success': False, 'error': f'Corrupted file in archive: {test_result}'}
                
                # List contents
                file_list = zipf.namelist()
                
                # Check for essential files
                essential_files = ['database.db', 'config.json']
                missing_files = [f for f in essential_files if f not in file_list]
                
                if missing_files:
                    return {'success': False, 'error': f'Missing essential files: {missing_files}'}
            
            # Cleanup temp file
            if temp_path != filepath and os.path.exists(temp_path):
                os.remove(temp_path)
            
            return {
                'success': True,
                'file_count': len(file_list),
                'contains_database': 'database.db' in file_list,
                'contains_config': 'config.json' in file_list,
                'file_size': os.path.getsize(filepath)
            }
            
        except Exception as e:
            # Cleanup temp file on error
            if 'temp_path' in locals() and temp_path != filepath and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
            
            return {'success': False, 'error': str(e)}
    
    def format_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    def cleanup_old_backups(self, max_age_days: int = None):
        """Cleanup backups older than specified days"""
        if max_age_days is None:
            max_age_days = self.retention_days
        
        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        backups = self.list_backups()
        
        deleted_count = 0
        for backup in backups:
            if backup['date'] < cutoff_date:
                try:
                    os.remove(backup['filepath'])
                    deleted_count += 1
                    logger.info(f"Deleted old backup: {backup['filename']}")
                except Exception as e:
                    logger.error(f"Failed to delete backup {backup['filename']}: {e}")
        
        return deleted_count
    
    def export_to_format(self, user_id: int, format: str = "json") -> Dict[str, Any]:
        """Export user data to different formats"""
        try:
            user_data = self.export_user_data(user_id)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if format.lower() == "json":
                filename = f"export_{user_id}_{timestamp}.json"
                filepath = os.path.join("data/exports", filename)
                
                os.makedirs("data/exports", exist_ok=True)
                
                with open(filepath, 'w') as f:
                    json.dump(user_data, f, indent=2, default=str)
                
                return {
                    'success': True,
                    'filename': filename,
                    'filepath': filepath,
                    'format': 'json',
                    'size': os.path.getsize(filepath)
                }
            
            elif format.lower() == "csv":
                # CSV export would require additional implementation
                return {'success': False, 'error': 'CSV export not implemented yet'}
            
            else:
                return {'success': False, 'error': f'Unsupported format: {format}'}
            
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return {'success': False, 'error': str(e)}