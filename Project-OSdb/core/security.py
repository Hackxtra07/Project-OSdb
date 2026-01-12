"""
Advanced Security Monitoring and Threat Detection
"""

import sqlite3
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
import hashlib
import json
import ipaddress
import re

logger = logging.getLogger(__name__)

class SecurityMonitor:
    """Real-time security monitoring and threat detection"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.suspicious_ips = set()
        self.failed_attempts = {}
        self.login_patterns = {}
        self.geo_cache = {}
        self.threat_intelligence = {}
        
        # Security thresholds
        self.thresholds = {
            'failed_logins': 5,  # Max failed attempts per 15 minutes
            'login_frequency': 10,  # Max logins per hour from same IP
            'password_attempts': 3,  # Max password attempts per session
            'session_duration': 8,  # Max session hours
        }
        
        # Start monitoring thread
        self.running = True
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("Security monitor initialized")
    
    def monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self.check_suspicious_activity()
                self.cleanup_old_data()
                self.update_threat_intelligence()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                time.sleep(60)
    
    def check_suspicious_activity(self):
        """Check for suspicious activity"""
        try:
            # Check failed login attempts
            self.detect_brute_force()
            
            # Check unusual login patterns
            self.detect_unusual_patterns()
            
            # Check for credential stuffing
            self.detect_credential_stuffing()
            
            # Check session anomalies
            self.detect_session_anomalies()
            
            # Log security status
            if self.suspicious_ips:
                logger.warning(f"Detected {len(self.suspicious_ips)} suspicious IPs")
                
        except Exception as e:
            logger.error(f"Failed to check suspicious activity: {e}")
    
    def detect_brute_force(self):
        """Detect brute force attacks"""
        # Check for multiple failed logins in short time
        query = '''
            SELECT ip_address, COUNT(*) as attempts
            FROM audit_log 
            WHERE action = 'LOGIN_FAILED' 
            AND timestamp > datetime('now', '-15 minutes')
            GROUP BY ip_address
            HAVING attempts >= ?
        '''
        
        results = self.db.execute_query(query, (self.thresholds['failed_logins'],))
        
        for row in results:
            ip = row['ip_address']
            attempts = row['attempts']
            
            if ip not in self.suspicious_ips:
                self.suspicious_ips.add(ip)
                
                # Log security event
                self.db.log_security_event(
                    None, "BRUTE_FORCE_DETECTED",
                    f"Brute force attack detected from {ip} ({attempts} attempts)",
                    "high", ip
                )
                
                # Block IP temporarily
                self.block_ip(ip, minutes=30)
                
                logger.warning(f"Brute force detected from {ip}: {attempts} attempts")
    
    def detect_unusual_patterns(self):
        """Detect unusual login patterns"""
        # Check for logins from unusual locations
        query = '''
            SELECT user_id, ip_address, COUNT(*) as logins
            FROM audit_log 
            WHERE action = 'LOGIN_SUCCESS'
            AND timestamp > datetime('now', '-1 hour')
            GROUP BY user_id, ip_address
            HAVING logins > ?
        '''
        
        results = self.db.execute_query(query, (self.thresholds['login_frequency'],))
        
        for row in results:
            user_id = row['user_id']
            ip = row['ip_address']
            logins = row['logins']
            
            # Check if this is a new IP for the user
            user_ips = self.get_user_ips(user_id)
            if ip not in user_ips:
                self.db.log_security_event(
                    user_id, "UNUSUAL_LOGIN_LOCATION",
                    f"Login from new IP: {ip} ({logins} attempts)",
                    "medium", ip
                )
    
    def detect_credential_stuffing(self):
        """Detect credential stuffing attacks"""
        # Check for multiple usernames from same IP
        query = '''
            SELECT ip_address, COUNT(DISTINCT details) as usernames
            FROM audit_log 
            WHERE action = 'LOGIN_FAILED'
            AND timestamp > datetime('now', '-30 minutes')
            GROUP BY ip_address
            HAVING usernames > 3
        '''
        
        results = self.db.execute_query(query)
        
        for row in results:
            ip = row['ip_address']
            usernames = row['usernames']
            
            self.db.log_security_event(
                None, "CREDENTIAL_STUFFING",
                f"Credential stuffing detected from {ip} ({usernames} usernames)",
                "high", ip
            )
    
    def detect_session_anomalies(self):
        """Detect abnormal session behavior"""
        # Check for long sessions
        query = '''
            SELECT user_id, ip_address, 
                   julianday('now') - julianday(timestamp) as hours
            FROM audit_log 
            WHERE action = 'LOGIN_SUCCESS'
            AND timestamp > datetime('now', '-24 hours')
            AND hours > ?
        '''
        
        results = self.db.execute_query(query, (self.thresholds['session_duration'],))
        
        for row in results:
            user_id = row['user_id']
            ip = row['ip_address']
            hours = row['hours']
            
            self.db.log_security_event(
                user_id, "LONG_SESSION",
                f"Unusually long session detected: {float(hours):.1f} hours from {ip}",
                "low", ip
            )
    
    def monitor_login_attempt(self, username: str, ip: str, success: bool):
        """Monitor individual login attempt"""
        current_time = datetime.now()
        
        if not success:
            # Track failed attempts
            key = f"{username}_{ip}"
            if key not in self.failed_attempts:
                self.failed_attempts[key] = []
            
            self.failed_attempts[key].append(current_time)
            
            # Clean old attempts
            self.failed_attempts[key] = [
                t for t in self.failed_attempts[key] 
                if current_time - t < timedelta(minutes=15)
            ]
            
            # Check threshold
            if len(self.failed_attempts[key]) >= self.thresholds['failed_logins']:
                if ip not in self.suspicious_ips:
                    self.suspicious_ips.add(ip)
                    self.db.log_security_event(
                        None, "BRUTE_FORCE_ATTEMPT",
                        f"Multiple failed login attempts for {username} from {ip}",
                        "high", ip
                    )
        
        # Track successful login patterns
        if success:
            user_key = f"user_{username}"
            if user_key not in self.login_patterns:
                self.login_patterns[user_key] = []
            
            self.login_patterns[user_key].append({
                'time': current_time,
                'ip': ip,
                'success': True
            })
            
            # Keep only last 100 logins
            self.login_patterns[user_key] = self.login_patterns[user_key][-100:]
            
    def verify_login(self, username: str, password_hash: str) -> tuple[bool, str, Optional[int]]:
        """
        Verify login credentials.
        Returns: (success, message, user_id)
        """
        try:
            # Fetch user by username
            user_res = self.db.execute_query("SELECT * FROM users WHERE username = ?", (username,), fetch_all=False)
            
            if not user_res:
                return False, "Invalid username or password", None
            
            user = dict(user_res)
            
            # Check if account is locked
            if user['locked_until']:
                locked_until = datetime.strptime(user['locked_until'], "%Y-%m-%d %H:%M:%S")
                if locked_until > datetime.now():
                    return False, f"Account locked until {user['locked_until']}", user['id']
            
            if user['password_hash'] == password_hash:
                # Login Success
                # Reset login attempts
                self.db.execute_query("UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = ?", (user['id'],))
                self.db.log_audit(user['id'], 'LOGIN_SUCCESS', f"Login successful for {username}")
                
                # Check 2FA
                if user['twofa_enabled']:
                    return True, "2FA Required", user['id']
                
                return True, "Login Successful", user['id']
            else:
                # Login Failed
                self._handle_failed_login(user)
                return False, "Invalid username or password", None
                
        except Exception as e:
            logger.error(f"Login verification failed: {e}")
            return False, f"Login error: {str(e)}", None

    def _handle_failed_login(self, user):
        """Handle failed login attempts and locking"""
        attempts = user['login_attempts'] + 1
        
        if attempts >= self.thresholds['failed_logins']:
            # Lock account
            lock_time = datetime.now() + timedelta(minutes=15)
            self.db.execute_query("UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?", 
                                (attempts, lock_time, user['id']))
            self.db.log_audit(user['id'], 'ACCOUNT_LOCKED', f"Account locked due to too many failed attempts")
        else:
            self.db.execute_query("UPDATE users SET login_attempts = ? WHERE id = ?", (attempts, user['id']))
            self.db.log_audit(user['id'], 'LOGIN_FAILED', f"Invalid password attempt")

    def verify_2fa(self, user_id: int, code: str) -> bool:
        """Verify 2FA code"""
        try:
            import pyotp
            user_res = self.db.execute_query("SELECT twofa_secret FROM users WHERE id = ?", (user_id,), fetch_all=False)
            if not user_res or not user_res['twofa_secret']:
                return False
                
            totp = pyotp.TOTP(user_res['twofa_secret'])
            if totp.verify(code):
                self.db.log_audit(user_id, '2FA_SUCCESS', "Two-factor authentication verified")
                return True
            
            self.db.log_audit(user_id, '2FA_FAILED', "Invalid 2FA code")
            return False
        except Exception as e:
            logger.error(f"2FA verification failed: {e}")
            return False

    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation"""
        is_suspicious = ip in self.suspicious_ips
        
        # Check if IP is private/local
        try:
            ip_obj = ipaddress.ip_address(ip)
            is_private = ip_obj.is_private
        except:
            is_private = False
        
        # Check geo location (simulated)
        country = self.get_ip_country(ip)
        
        # Check threat intelligence
        threat_level = self.check_threat_intelligence(ip)
        
        return {
            'ip': ip,
            'is_suspicious': is_suspicious,
            'is_private': is_private,
            'country': country,
            'threat_level': threat_level,
            'recommendation': 'block' if is_suspicious else 'allow'
        }
    
    def get_ip_country(self, ip: str) -> str:
        """Get country for IP (simulated)"""
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        
        if ip.startswith('192.168.') or ip.startswith('10.'):
            country = "Local Network"
        elif ip.startswith('172.16.'):
            country = "Private Network"
        else:
            country = "Unknown"
        
        self.geo_cache[ip] = country
        return country
    
    def check_threat_intelligence(self, ip: str) -> str:
        """Check threat intelligence for IP"""
        if ip in self.threat_intelligence:
            return self.threat_intelligence[ip]
        
        threat_level = "low"
        
        # Check for known malicious patterns
        malicious_patterns = [
            r'^185\.', r'^94\.', r'^5\.'
        ]
        
        for pattern in malicious_patterns:
            if re.match(pattern, ip):
                threat_level = "high"
                break
        
        # Check security events
        result = self.db.execute_query('''
            SELECT COUNT(*) as attacks
            FROM security_events 
            WHERE source_ip = ?
            AND severity IN ('high', 'critical')
            AND timestamp > datetime('now', '-30 days')
        ''', (ip,), fetch_all=False)
        
        if result and result['attacks'] > 0:
            threat_level = "medium" if threat_level == "low" else threat_level
        
        self.threat_intelligence[ip] = threat_level
        return threat_level
    
    def block_ip(self, ip: str, minutes: int = 30):
        """Block IP temporarily"""
        self.db.log_security_event(None, "IP_BLOCKED", f"IP {ip} blocked for {minutes} minutes", "high", ip)
    
    def get_user_ips(self, user_id: int) -> Set[str]:
        """Get all IPs used by a user"""
        results = self.db.execute_query('''
            SELECT DISTINCT ip_address
            FROM audit_log 
            WHERE user_id = ?
            AND ip_address IS NOT NULL
            AND timestamp > datetime('now', '-30 days')
        ''', (user_id,))
        
        return {row['ip_address'] for row in results}
    
    def cleanup_old_data(self):
        """Cleanup old monitoring data"""
        current_time = datetime.now()
        
        # Clean failed attempts older than 1 hour
        for key in list(self.failed_attempts.keys()):
            self.failed_attempts[key] = [
                t for t in self.failed_attempts[key]
                if current_time - t < timedelta(hours=1)
            ]
            if not self.failed_attempts[key]:
                del self.failed_attempts[key]
        
        # Clean login patterns older than 7 days
        for key in list(self.login_patterns.keys()):
            self.login_patterns[key] = [
                log for log in self.login_patterns[key]
                if current_time - log['time'] < timedelta(days=7)
            ]
            if not self.login_patterns[key]:
                del self.login_patterns[key]
        
        # Clean old geo cache
        if len(self.geo_cache) > 1000:
            self.geo_cache = dict(list(self.geo_cache.items())[-500:])
    
    def update_threat_intelligence(self):
        """Update threat intelligence data"""
        results = self.db.execute_query('''
            SELECT source_ip as ip_address, COUNT(*) as events
            FROM security_events 
            WHERE severity IN ('high', 'critical')
            AND timestamp > datetime('now', '-7 days')
            GROUP BY source_ip
            HAVING events > 1
        ''')
        
        for row in results:
            ip = row['ip_address']
            events = row['events']
            
            if events > 5:
                self.threat_intelligence[ip] = "critical"
            elif events > 2:
                self.threat_intelligence[ip] = "high"
            else:
                self.threat_intelligence[ip] = "medium"

    def stop(self):
        self.running = False