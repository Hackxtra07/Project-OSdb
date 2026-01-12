"""
Utility Helper Functions
"""

import os
import sys
import json
import hashlib
import random
import string
import tempfile
import subprocess
import platform
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
import logging
import inspect
import traceback
import uuid
import re
import socket
import ipaddress
import itertools

logger = logging.getLogger(__name__)

class Helpers:
    """Collection of helper functions"""
    
    @staticmethod
    def generate_id(length: int = 8) -> str:
        """Generate random ID"""
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    @staticmethod
    def calculate_checksum(file_path: str, algorithm: str = "sha256") -> str:
        """Calculate file checksum"""
        hash_func = getattr(hashlib, algorithm)()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    @staticmethod
    def format_timestamp(timestamp: Union[str, datetime], 
                        format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
        """Format timestamp"""
        if isinstance(timestamp, str):
            try:
                # Try different date formats
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", 
                           "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f"]:
                    try:
                        timestamp = datetime.strptime(timestamp, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    return timestamp  # Return original if can't parse
            except:
                return timestamp
        
        if isinstance(timestamp, datetime):
            return timestamp.strftime(format_str)
        
        return str(timestamp)
    
    @staticmethod
    def format_duration(seconds: int) -> str:
        """Format duration in human readable format"""
        if seconds < 60:
            return f"{seconds} seconds"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes} minutes"
        elif seconds < 86400:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours}h {minutes}m"
        else:
            days = seconds // 86400
            hours = (seconds % 86400) // 3600
            return f"{days}d {hours}h"
    
    @staticmethod
    def format_size(size_bytes: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    @staticmethod
    def get_file_info(file_path: str) -> Dict[str, Any]:
        """Get detailed file information"""
        try:
            stat = os.stat(file_path)
            
            return {
                'path': file_path,
                'filename': os.path.basename(file_path),
                'size': stat.st_size,
                'size_formatted': Helpers.format_size(stat.st_size),
                'created': datetime.fromtimestamp(stat.st_ctime),
                'modified': datetime.fromtimestamp(stat.st_mtime),
                'accessed': datetime.fromtimestamp(stat.st_atime),
                'checksum_md5': Helpers.calculate_checksum(file_path, 'md5'),
                'checksum_sha256': Helpers.calculate_checksum(file_path, 'sha256'),
                'extension': os.path.splitext(file_path)[1].lower(),
                'is_file': os.path.isfile(file_path),
                'is_dir': os.path.isdir(file_path)
            }
        except Exception as e:
            logger.error(f"Failed to get file info for {file_path}: {e}")
            return {}
    
    @staticmethod
    def safe_json_loads(json_str: str, default: Any = None) -> Any:
        """Safely load JSON string"""
        try:
            return json.loads(json_str)
        except:
            return default
    
    @staticmethod
    def safe_json_dumps(data: Any, default: Any = None) -> str:
        """Safely dump to JSON string"""
        try:
            return json.dumps(data, default=str)
        except:
            return default or "{}"
    
    @staticmethod
    def dict_to_query_params(params: Dict[str, Any]) -> str:
        """Convert dictionary to query parameters"""
        if not params:
            return ""
        
        param_list = []
        for key, value in params.items():
            if value is not None:
                param_list.append(f"{key}={value}")
        
        return "?" + "&".join(param_list)
    
    @staticmethod
    def mask_sensitive_data(text: str, mask_char: str = "*") -> str:
        """Mask sensitive data like passwords, emails, etc."""
        if not text:
            return text
        
        # Mask email addresses
        text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', 
                     lambda m: m.group(0)[0] + mask_char * 5 + m.group(0)[-1], text)
        
        # Mask passwords in JSON
        password_patterns = [
            r'"password":\s*"[^"]*"',
            r'"password_encrypted":\s*"[^"]*"',
            r'"token":\s*"[^"]*"',
            r'"api_key":\s*"[^"]*"',
            r'"secret":\s*"[^"]*"'
        ]
        
        for pattern in password_patterns:
            text = re.sub(pattern, 
                         lambda m: m.group(0).split(':')[0] + ': "' + mask_char * 8 + '"', 
                         text, flags=re.IGNORECASE)
        
        # Mask credit card numbers
        text = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
                     mask_char * 16, text)
        
        # Mask phone numbers
        text = re.sub(r'\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b',
                     mask_char * 10, text)
        
        return text
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_mac_address(mac: str) -> bool:
        """Validate MAC address"""
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(pattern, mac))
    
    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """Get system information"""
        info = {
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'hostname': socket.gethostname(),
            'username': os.getenv('USER') or os.getenv('USERNAME') or 'Unknown',
            'cwd': os.getcwd(),
            'cpu_count': os.cpu_count() or 1
        }
        
        # Get IP addresses
        try:
            info['ip_addresses'] = Helpers.get_ip_addresses()
        except:
            info['ip_addresses'] = []
        
        # Get memory info if available
        try:
            import psutil
            memory = psutil.virtual_memory()
            info['memory_total'] = memory.total
            info['memory_available'] = memory.available
            info['memory_used'] = memory.used
            info['memory_percent'] = memory.percent
        except:
            pass
        
        # Get disk usage
        try:
            disk = psutil.disk_usage('/')
            info['disk_total'] = disk.total
            info['disk_used'] = disk.used
            info['disk_free'] = disk.free
            info['disk_percent'] = disk.percent
        except:
            pass
        
        return info
    
    @staticmethod
    def get_ip_addresses() -> List[str]:
        """Get all IP addresses of the system"""
        addresses = []
        
        try:
            # Get hostname
            hostname = socket.gethostname()
            
            # Get all IP addresses
            for addr in socket.getaddrinfo(hostname, None):
                ip = addr[4][0]
                if ip not in addresses and not ip.startswith('127.'):
                    addresses.append(ip)
            
            # Also try socket connection method
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            if local_ip not in addresses:
                addresses.append(local_ip)
            
        except Exception as e:
            logger.error(f"Failed to get IP addresses: {e}")
        
        return addresses
    
    @staticmethod
    def execute_command(command: str, timeout: int = 30) -> Tuple[bool, str, str]:
        """Execute shell command with timeout"""
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                success = process.returncode == 0
                return success, stdout.strip(), stderr.strip()
            except subprocess.TimeoutExpired:
                process.kill()
                return False, "", f"Command timed out after {timeout} seconds"
            
        except Exception as e:
            return False, "", str(e)
    
    @staticmethod
    def create_temp_file(content: str = "", suffix: str = ".tmp") -> str:
        """Create temporary file"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
                if content:
                    f.write(content)
                return f.name
        except Exception as e:
            logger.error(f"Failed to create temp file: {e}")
            return ""
    
    @staticmethod
    def chunk_list(lst: List, chunk_size: int) -> List[List]:
        """Split list into chunks"""
        return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]
    
    @staticmethod
    def flatten_list(nested_list: List) -> List:
        """Flatten nested list"""
        result = []
        for item in nested_list:
            if isinstance(item, list):
                result.extend(Helpers.flatten_list(item))
            else:
                result.append(item)
        return result
    
    @staticmethod
    def remove_duplicates(lst: List) -> List:
        """Remove duplicates while preserving order"""
        seen = set()
        result = []
        for item in lst:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result
    
    @staticmethod
    def get_function_name() -> str:
        """Get name of current function"""
        return inspect.currentframe().f_back.f_code.co_name
    
    @staticmethod
    def get_caller_info() -> Dict[str, Any]:
        """Get information about function caller"""
        frame = inspect.currentframe().f_back.f_back
        info = {
            'function': frame.f_code.co_name,
            'file': frame.f_code.co_filename,
            'line': frame.f_lineno,
            'module': inspect.getmodule(frame).__name__ if inspect.getmodule(frame) else 'Unknown'
        }
        return info
    
    @staticmethod
    def log_exception(exc: Exception, context: str = ""):
        """Log exception with context"""
        exc_info = {
            'type': type(exc).__name__,
            'message': str(exc),
            'context': context,
            'traceback': traceback.format_exc(),
            'timestamp': datetime.now().isoformat(),
            'caller': Helpers.get_caller_info()
        }
        
        logger.error(f"Exception: {exc_info}")
        return exc_info
    
    @staticmethod
    def retry_operation(func, max_attempts: int = 3, delay: float = 1.0, 
                       exceptions: tuple = (Exception,)):
        """Retry operation with exponential backoff"""
        for attempt in range(max_attempts):
            try:
                return func()
            except exceptions as e:
                if attempt == max_attempts - 1:
                    raise e
                
                wait_time = delay * (2 ** attempt)  # Exponential backoff
                logger.warning(f"Attempt {attempt + 1} failed, retrying in {wait_time:.1f}s: {e}")
                time.sleep(wait_time)
    
    @staticmethod
    def generate_password(length: int = 12, include_symbols: bool = True) -> str:
        """Generate random password"""
        chars = string.ascii_letters + string.digits
        if include_symbols:
            chars += string.punctuation
        
        # Ensure at least one of each type
        password = [
            random.choice(string.ascii_lowercase),
            random.choice(string.ascii_uppercase),
            random.choice(string.digits)
        ]
        
        if include_symbols:
            password.append(random.choice(string.punctuation))
        
        # Fill remaining length
        remaining = length - len(password)
        if remaining > 0:
            password.extend(random.choice(chars) for _ in range(remaining))
        
        # Shuffle
        random.shuffle(password)
        
        return ''.join(password)
    
    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculate password entropy"""
        if not password:
            return 0.0
        
        # Character set size
        charset = 0
        if any(c.islower() for c in password):
            charset += 26
        if any(c.isupper() for c in password):
            charset += 26
        if any(c.isdigit() for c in password):
            charset += 10
        if any(c in string.punctuation for c in password):
            charset += 32
        
        if charset == 0:
            return 0.0
        
        # Entropy formula: log2(charset^length)
        entropy = len(password) * (charset ** 0.5)
        return round(entropy, 2)
    
    @staticmethod
    def is_safe_filename(filename: str) -> bool:
        """Check if filename is safe"""
        # Check for dangerous characters
        dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        if any(char in filename for char in dangerous_chars):
            return False
        
        # Check for reserved names (Windows)
        reserved_names = ['CON', 'PRN', 'AUX', 'NUL', 
                         'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
                         'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']
        
        name_without_ext = os.path.splitext(filename)[0].upper()
        if name_without_ext in reserved_names:
            return False
        
        # Check length
        if len(filename) > 255:
            return False
        
        return True
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename"""
        # Replace dangerous characters
        dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Remove leading/trailing spaces and dots
        filename = filename.strip('. ')
        
        # Ensure not empty
        if not filename:
            filename = 'unnamed'
        
        # Truncate if too long
        if len(filename) > 200:
            name, ext = os.path.splitext(filename)
            filename = name[:200 - len(ext)] + ext
        
        return filename
    
    @staticmethod
    def backup_file(file_path: str) -> str:
        """Create backup of file"""
        if not os.path.exists(file_path):
            return ""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{file_path}.backup_{timestamp}"
        
        try:
            shutil.copy2(file_path, backup_path)
            logger.info(f"Created backup: {backup_path}")
            return backup_path
        except Exception as e:
            logger.error(f"Failed to backup file {file_path}: {e}")
            return ""
    
    @staticmethod
    def restore_backup(file_path: str) -> bool:
        """Restore from latest backup"""
        if not os.path.exists(file_path):
            return False
        
        # Find latest backup
        backup_pattern = f"{file_path}.backup_*"
        backups = sorted(glob.glob(backup_pattern))
        
        if not backups:
            return False
        
        latest_backup = backups[-1]
        
        try:
            shutil.copy2(latest_backup, file_path)
            logger.info(f"Restored from backup: {latest_backup}")
            return True
        except Exception as e:
            logger.error(f"Failed to restore from backup {latest_backup}: {e}")
            return False
    
    @staticmethod
    def get_file_mime_type(file_path: str) -> str:
        """Get MIME type of file"""
        try:
            import mimetypes
            mime_type, encoding = mimetypes.guess_type(file_path)
            return mime_type or 'application/octet-stream'
        except:
            return 'application/octet-stream'
    
    @staticmethod
    def is_binary_file(file_path: str) -> bool:
        """Check if file is binary"""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\x00' in chunk
        except:
            return False
    
    @staticmethod
    def count_file_lines(file_path: str) -> int:
        """Count lines in file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except:
            return 0
    
    @staticmethod
    def find_files(directory: str, pattern: str = "*", 
                  recursive: bool = True) -> List[str]:
        """Find files matching pattern"""
        import fnmatch
        
        matches = []
        
        if recursive:
            for root, dirs, files in os.walk(directory):
                for filename in fnmatch.filter(files, pattern):
                    matches.append(os.path.join(root, filename))
        else:
            for filename in fnmatch.filter(os.listdir(directory), pattern):
                filepath = os.path.join(directory, filename)
                if os.path.isfile(filepath):
                    matches.append(filepath)
        
        return matches
    
    @staticmethod
    def create_directory_structure(base_path: str, structure: Dict[str, Any]):
        """Create directory structure"""
        for name, content in structure.items():
            path = os.path.join(base_path, name)
            
            if isinstance(content, dict):
                # It's a directory
                os.makedirs(path, exist_ok=True)
                Helpers.create_directory_structure(path, content)
            else:
                # It's a file
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, 'w') as f:
                    f.write(str(content))
    
    @staticmethod
    def get_relative_time(dt: datetime) -> str:
        """Get relative time string (e.g., "2 hours ago")"""
        now = datetime.now()
        diff = now - dt
        
        if diff.days > 365:
            years = diff.days // 365
            return f"{years} year{'s' if years > 1 else ''} ago"
        elif diff.days > 30:
            months = diff.days // 30
            return f"{months} month{'s' if months > 1 else ''} ago"
        elif diff.days > 0:
            return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        else:
            return "just now"