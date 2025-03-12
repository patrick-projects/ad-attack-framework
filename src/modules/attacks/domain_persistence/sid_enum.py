"""
Domain SID enumeration functionality.
Implements various methods to obtain domain SIDs including:
- lookupsid.py for anonymous enumeration
- Get-DomainSID for authenticated enumeration
- SharpHound for comprehensive enumeration
"""

from ..attack_base import AttackBase
from typing import Optional, Dict, List, Tuple
import subprocess
import re

class SIDEnumeration(AttackBase):
    def __init__(self):
        """Initialize SID enumeration module"""
        super().__init__()
        
    def enumerate_domain_sid(self, domain: str, dc_ip: str,
                           username: Optional[str] = None,
                           password: Optional[str] = None) -> Optional[str]:
        """
        Enumerate domain SID using multiple methods
        
        Args:
            domain: Domain name
            dc_ip: Domain Controller IP
            username: Optional username for authenticated enumeration
            password: Optional password for authenticated enumeration
            
        Returns:
            Domain SID if found, None otherwise
        """
        # Try authenticated methods first if credentials provided
        if username and password:
            sid = self._get_sid_authenticated(domain, dc_ip, username, password)
            if sid:
                self._store_sid(domain, sid)
                return sid
                
        # Fall back to anonymous enumeration
        sid = self._get_sid_anonymous(domain, dc_ip)
        if sid:
            self._store_sid(domain, sid)
            return sid
            
        return None
        
    def _get_sid_authenticated(self, domain: str, dc_ip: str,
                             username: str, password: str) -> Optional[str]:
        """
        Get domain SID using authenticated methods
        
        Args:
            domain: Domain name
            dc_ip: Domain Controller IP
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            Domain SID if found, None otherwise
        """
        try:
            # First try PowerShell Get-DomainSID
            ps_cmd = f"Get-DomainSID -Domain {domain}"
            cmd = [
                'powershell.exe',
                '-Command',
                ps_cmd
            ]
            
            self.log_status(f"Attempting to get SID using Get-DomainSID")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Look for SID pattern in output
            sid_match = re.search(r'S-1-5-21-\d+-\d+-\d+', result.stdout)
            if sid_match:
                sid = sid_match.group(0)
                self.log_success(f"Found domain SID: {sid}")
                return sid
                
            # If PowerShell fails, try lookupsid.py with credentials
            cmd = [
                'lookupsid.py',
                f'{domain}/{username}:{password}@{dc_ip}',
                '0'
            ]
            
            self.log_status("Attempting to get SID using lookupsid.py")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse lookupsid.py output
            sid_match = re.search(r'Domain SID is: (S-1-5-21-\d+-\d+-\d+)', result.stdout)
            if sid_match:
                sid = sid_match.group(1)
                self.log_success(f"Found domain SID: {sid}")
                return sid
                
        except Exception as e:
            self.log_error(f"Authenticated SID enumeration failed: {str(e)}")
            
        return None
        
    def _get_sid_anonymous(self, domain: str, dc_ip: str) -> Optional[str]:
        """
        Get domain SID using anonymous enumeration
        
        Args:
            domain: Domain name
            dc_ip: Domain Controller IP
            
        Returns:
            Domain SID if found, None otherwise
        """
        try:
            # Try lookupsid.py with anonymous access
            cmd = [
                'lookupsid.py',
                '-domain-sids',
                f'{domain}/@{dc_ip}',
                '0'
            ]
            
            self.log_status("Attempting anonymous SID enumeration")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse lookupsid.py output
            sid_match = re.search(r'Domain SID is: (S-1-5-21-\d+-\d+-\d+)', result.stdout)
            if sid_match:
                sid = sid_match.group(1)
                self.log_success(f"Found domain SID through anonymous enumeration: {sid}")
                return sid
                
        except Exception as e:
            self.log_error(f"Anonymous SID enumeration failed: {str(e)}")
            
        return None
        
    def _store_sid(self, domain: str, sid: str):
        """
        Store domain SID in database
        
        Args:
            domain: Domain name
            sid: Domain SID
        """
        try:
            self.db.add_domain_sid(domain, sid)
            self.log_status(f"Stored SID for domain {domain}")
        except Exception as e:
            self.log_error(f"Failed to store domain SID: {str(e)}")
            
    def get_stored_sid(self, domain: str) -> Optional[str]:
        """
        Retrieve stored SID for domain
        
        Args:
            domain: Domain name
            
        Returns:
            Stored SID if found, None otherwise
        """
        try:
            return self.db.get_domain_sid(domain)
        except Exception as e:
            self.log_error(f"Failed to retrieve domain SID: {str(e)}")
            return None
            
    def enumerate_all_trust_sids(self, domain: str, dc_ip: str,
                                username: Optional[str] = None,
                                password: Optional[str] = None) -> List[Dict]:
        """
        Enumerate SIDs for domain and all trusted domains
        
        Args:
            domain: Primary domain name
            dc_ip: Domain Controller IP
            username: Optional username for authentication
            password: Optional password for authentication
            
        Returns:
            List of dicts containing domain names and their SIDs
        """
        results = []
        
        # Get primary domain SID
        primary_sid = self.enumerate_domain_sid(domain, dc_ip, username, password)
        if primary_sid:
            results.append({
                'domain': domain,
                'sid': primary_sid,
                'type': 'primary'
            })
            
        # Get trust relationships
        trusts = self.db.get_domain_trusts(domain)
        if trusts:
            for trust in trusts:
                trust_domain = trust['domain']
                trust_sid = self.enumerate_domain_sid(trust_domain, dc_ip, username, password)
                if trust_sid:
                    results.append({
                        'domain': trust_domain,
                        'sid': trust_sid,
                        'type': trust['type'],
                        'direction': trust['direction']
                    })
                    
        return results 