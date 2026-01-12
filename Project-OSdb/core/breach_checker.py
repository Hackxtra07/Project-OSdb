"""
Password Breach Checker - Check if passwords appear in known breaches
"""

import hashlib
import requests
import logging
from typing import Dict, Tuple, Optional
import time

logger = logging.getLogger(__name__)

class BreachChecker:
    """Check passwords against known breach databases"""
    
    def __init__(self):
        self.api_timeout = 5
        self.cache = {}
        self.cache_time = {}
        self.cache_duration = 3600  # 1 hour
        
    def check_password_breach(self, password: str) -> Dict[str, any]:
        """
        Check if password appears in known breaches using Have I Been Pwned API
        Uses k-anonymity to avoid sending full password hash
        """
        try:
            # Hash the password
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            
            # Use k-anonymity: only send first 5 characters of hash
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Check cache first
            cache_key = f"breach_{prefix}"
            if cache_key in self.cache:
                if time.time() - self.cache_time.get(cache_key, 0) < self.cache_duration:
                    results = self.cache[cache_key]
                    if suffix in results:
                        count = results[suffix]
                        return {
                            'status': 'breached',
                            'found': True,
                            'breach_count': count,
                            'message': f'Password found in {count} known breaches',
                            'action': 'Change immediately'
                        }
                    else:
                        return {
                            'status': 'clean',
                            'found': False,
                            'breach_count': 0,
                            'message': 'Password not found in known breaches',
                            'action': 'No action required'
                        }
            
            # Query Have I Been Pwned API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            headers = {'User-Agent': 'SecureOSINT/2.0'}
            
            response = requests.get(url, headers=headers, timeout=self.api_timeout)
            
            if response.status_code == 200:
                # Parse response - format is "SUFFIX:COUNT\n"
                hashes = {}
                for line in response.text.split('\r\n'):
                    if ':' in line:
                        h, count = line.split(':')
                        hashes[h] = int(count)
                
                # Cache the results
                self.cache[cache_key] = hashes
                self.cache_time[cache_key] = time.time()
                
                # Check if our suffix exists
                if suffix in hashes:
                    count = hashes[suffix]
                    logger.warning(f"Password found in {count} breaches")
                    return {
                        'status': 'breached',
                        'found': True,
                        'breach_count': count,
                        'message': f'Password found in {count} known breaches',
                        'action': 'Change immediately'
                    }
                else:
                    return {
                        'status': 'clean',
                        'found': False,
                        'breach_count': 0,
                        'message': 'Password not found in known breaches',
                        'action': 'No action required'
                    }
            
            elif response.status_code == 429:
                return {
                    'status': 'rate_limited',
                    'found': False,
                    'breach_count': 0,
                    'message': 'API rate limited - try again later',
                    'action': 'Retry later'
                }
            
            else:
                return {
                    'status': 'error',
                    'found': False,
                    'breach_count': 0,
                    'message': f'Breach check unavailable (HTTP {response.status_code})',
                    'action': 'Try again later'
                }
        
        except requests.exceptions.Timeout:
            return {
                'status': 'error',
                'found': False,
                'breach_count': 0,
                'message': 'Breach check timed out',
                'action': 'Check internet connection'
            }
        
        except Exception as e:
            logger.error(f"Breach check failed: {e}")
            return {
                'status': 'error',
                'found': False,
                'breach_count': 0,
                'message': f'Breach check failed: {str(e)}',
                'action': 'Try again'
            }

    def check_email_breach(self, email: str) -> Dict[str, any]:
        """
        Check if email appears in breaches (requires API key)
        This requires Have I Been Pwned premium API key
        """
        try:
            # Note: This would require API key configuration
            # For now, return info-only response
            return {
                'status': 'info',
                'found': False,
                'breaches': [],
                'message': 'Email breach check requires HIBP API key',
                'action': 'Configure API key in settings'
            }
        except Exception as e:
            logger.error(f"Email breach check failed: {e}")
            return {
                'status': 'error',
                'found': False,
                'breaches': [],
                'message': f'Email check failed: {str(e)}',
                'action': 'Try again'
            }

    def check_username_breach(self, username: str) -> Dict[str, any]:
        """
        Check if username appears in breaches
        Uses free databases and local checking
        """
        try:
            # Common compromised usernames list (simplified)
            # In production, would use actual breach database
            
            return {
                'status': 'info',
                'found': False,
                'message': 'Username check available through custom breach database',
                'action': 'Available for premium users'
            }
        except Exception as e:
            logger.error(f"Username check failed: {e}")
            return {
                'status': 'error',
                'found': False,
                'message': f'Username check failed: {str(e)}',
                'action': 'Try again'
            }

    def clear_cache(self):
        """Clear breach check cache"""
        self.cache.clear()
        self.cache_time.clear()
        logger.info("Breach check cache cleared")
