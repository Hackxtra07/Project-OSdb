"""
API Integration Manager - OSINT Data Collection
"""

import requests
import logging
import json
import socket
import whois
import shodan
from typing import Dict, Any, List, Optional
import configparser
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class APIResult:
    source: str
    data: Any
    status: str
    timestamp: str = None
    error: str = None

class APIIntegrationManager:
    """Manages integrations with external OSINT APIs"""
    
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')
        
        # Initialize API clients
        self._init_virustotal()
        self._init_shodan()
        self._init_hunter()
        
    def _init_virustotal(self):
        self.vt_key = self.config['api'].get('virustotal_key', '')
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        
    def _init_shodan(self):
        self.shodan_key = self.config['api'].get('shodan_key', '')
        self.shodan_base_url = "https://api.shodan.io"
        # Keep client for backwards compatibility if needed
        try:
            if self.shodan_key:
                self.shodan_client = shodan.Shodan(self.shodan_key)
            else:
                self.shodan_client = None
        except Exception as e:
            logger.error(f"Failed to init Shodan: {e}")
            self.shodan_client = None
            
    def _init_hunter(self):
        self.hunter_key = self.config['api'].get('hunter_key', '')
        self.hunter_base_url = "https://api.hunter.io/v2"

    def set_api_key(self, service: str, api_key: str):
        """Set API key for a service"""
        try:
            if not self.config.has_section('api'):
                self.config.add_section('api')
            
            # Map service names to config keys
            config_key_map = {
                'virustotal': 'virustotal_key',
                'shodan': 'shodan_key',
                'hunter': 'hunter_key',
            }
            
            config_key = config_key_map.get(service.lower(), f'{service.lower()}_key')
            self.config.set('api', config_key, api_key)
            
            # Save to config file
            with open('config.ini', 'w') as f:
                self.config.write(f)
            
            # Update instance variables
            if service.lower() == 'virustotal':
                self.vt_key = api_key
            elif service.lower() == 'shodan':
                self.shodan_key = api_key
                self._init_shodan()  # Re-initialize client
            elif service.lower() == 'hunter':
                self.hunter_key = api_key
            
            logger.info(f"API key set for {service}")
            return True
        except Exception as e:
            logger.error(f"Failed to set API key for {service}: {e}")
            return False

    def virustotal_lookup(self, indicator: str, type: str = "ip") -> APIResult:
        """Query VirusTotal"""
        if not self.vt_key:
            return APIResult("VirusTotal", None, "skipped", error="API key missing")
            
        try:
            headers = {"x-apikey": self.vt_key}
            
            if type == "ip":
                endpoint = f"{self.vt_base_url}/ip_addresses/{indicator}"
            elif type == "domain":
                endpoint = f"{self.vt_base_url}/domains/{indicator}"
            elif type == "hash":
                endpoint = f"{self.vt_base_url}/files/{indicator}"
            else:
                return APIResult("VirusTotal", None, "error", error="Invalid type")
                
            response = requests.get(endpoint, headers=headers, timeout=10)
            
            if response.status_code == 200:
                return APIResult("VirusTotal", response.json(), "success", datetime.now().isoformat())
            else:
                return APIResult("VirusTotal", None, "error", error=f"HTTP {response.status_code}")
                
        except Exception as e:
            logger.error(f"VirusTotal lookup failed: {e}")
            return APIResult("VirusTotal", None, "error", error=str(e))

    def shodan_lookup(self, ip: str) -> APIResult:
        """Query Shodan using REST API
        
        Shodan API endpoints:
        - /shodan/host/{ip} - Get host information
        Query params: key (API key)
        """
        if not self.shodan_key:
            return APIResult("Shodan", None, "skipped", error="API key missing")
            
        try:
            # Shodan REST endpoint for host lookup
            url = f"{self.shodan_base_url}/shodan/host/{ip}"
            params = {
                'key': self.shodan_key
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                return APIResult("Shodan", response.json(), "success", datetime.now().isoformat())
            elif response.status_code == 401:
                return APIResult("Shodan", None, "error", error="Unauthorized - Invalid API key")
            elif response.status_code == 403:
                return APIResult("Shodan", None, "error", error="Forbidden - Quota exceeded or access denied")
            elif response.status_code == 404:
                return APIResult("Shodan", None, "error", error="Host not found in Shodan database")
            else:
                return APIResult("Shodan", None, "error", error=f"HTTP {response.status_code}")
                
        except Exception as e:
            logger.error(f"Shodan lookup failed: {e}")
            return APIResult("Shodan", None, "error", error=str(e))

    def hunter_email_verify(self, email: str) -> APIResult:
        """Verify email using Hunter.io"""
        if not self.hunter_key:
            return APIResult("Hunter.io", None, "skipped", error="API key missing")
            
        try:
            params = {
                "email": email,
                "api_key": self.hunter_key
            }
            response = requests.get(f"{self.hunter_base_url}/email-verifier", params=params, timeout=10)
            
            if response.status_code == 200:
                return APIResult("Hunter.io", response.json(), "success", datetime.now().isoformat())
            else:
                return APIResult("Hunter.io", None, "error", error=f"HTTP {response.status_code}")
        except Exception as e:
            logger.error(f"Hunter.io lookup failed: {e}")
            return APIResult("Hunter.io", None, "error", error=str(e))

    def whois_lookup(self, domain: str) -> APIResult:
        """Perform WHOIS lookup"""
        try:
            w = whois.whois(domain)
            # Convert to dict safely
            return APIResult("WHOIS", dict(w), "success", datetime.now().isoformat())
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")
            return APIResult("WHOIS", None, "error", error=str(e))
            
    def geo_ip(self, ip: str) -> APIResult:
        """Get IP Geolocation (using free API)"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                return APIResult("GeoIP", response.json(), "success", datetime.now().isoformat())
            return APIResult("GeoIP", None, "error", error=f"HTTP {response.status_code}")
        except Exception as e:
            return APIResult("GeoIP", None, "error", error=str(e))

    def get_headers(self) -> Dict[str, str]:
        """Get standard headers for requests"""
        return {
            'User-Agent': 'SecureOSINT/2.0',
            'Accept': 'application/json'
        }