"""
Input validation utilities
"""

import re
import ipaddress
from urllib.parse import urlparse
import email_validator
from typing import Optional, Tuple

class Validators:
    """Collection of validation functions"""
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, Optional[str]]:
        """Validate email address"""
        try:
            email_validator.validate_email(email)
            return True, None
        except email_validator.EmailNotValidError as e:
            return False, str(e)
    
    @staticmethod
    def validate_password(password: str, min_length: int = 8) -> Tuple[bool, Optional[str]]:
        """Validate password strength"""
        if len(password) < min_length:
            return False, f"Password must be at least {min_length} characters"
        
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return False, "Password must contain at least one special character"
        
        return True, None
    
    @staticmethod
    def validate_url(url: str) -> Tuple[bool, Optional[str]]:
        """Validate URL"""
        try:
            result = urlparse(url)
            if all([result.scheme, result.netloc]):
                return True, None
            return False, "Invalid URL format"
        except:
            return False, "Invalid URL"
    
    @staticmethod
    def validate_ip(ip: str) -> Tuple[bool, Optional[str]]:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True, None
        except ValueError:
            return False, "Invalid IP address"
    
    @staticmethod
    def validate_domain(domain: str) -> Tuple[bool, Optional[str]]:
        """Validate domain name"""
        pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$'
        if re.match(pattern, domain):
            return True, None
        return False, "Invalid domain name"
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, Optional[str]]:
        """Validate username"""
        if len(username) < 3:
            return False, "Username must be at least 3 characters"
        
        if len(username) > 50:
            return False, "Username must be less than 50 characters"
        
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            return False, "Username can only contain letters, numbers, dots, underscores, and hyphens"
        
        return True, None
    
    @staticmethod
    def validate_pin(pin: str) -> Tuple[bool, Optional[str]]:
        """Validate PIN"""
        if not pin.isdigit():
            return False, "PIN must contain only digits"
        
        if len(pin) < 4 or len(pin) > 6:
            return False, "PIN must be 4-6 digits"
        
        return True, None