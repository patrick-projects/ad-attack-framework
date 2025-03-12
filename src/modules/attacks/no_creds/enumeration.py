"""
No Credentials Enumeration Module

Implements enumeration techniques from the OCD mindmap that don't require credentials:
- Network scanning and service discovery
- Anonymous access checks
- Zone transfer attempts
- LDAP anonymous queries
- User enumeration through Kerberos
"""

from typing import Dict, List, Optional, Callable
from .base_no_creds import BaseNoCredsAttack
import json
import re

class Enumeration(BaseNoCredsAttack):
    """Implementation of no-credentials enumeration techniques"""
    
    @property
    def required_tools(self) -> Dict[str, str]:
        return {
            'nmap': 'nmap',
            'ldapsearch': 'ldap-utils',
            'kerbrute': 'kerbrute',
            'dig': 'dnsutils',
            'enum4linux-ng': 'enum4linux-ng',
            'nxc': 'netexec'  # Modern replacement for CrackMapExec
        }
    
    def _run_attack(self, target: str, options: Optional[Dict] = None,
                    callback: Optional[Callable] = None) -> bool:
        """
        Run enumeration techniques
        
        Args:
            target: Target to enumerate
            options: Optional configuration options
            callback: Optional callback for progress updates
            
        Returns:
            bool: True if any valuable information was found
        """
        try:
            # Track if we found anything valuable
            found_valuable_info = False
            
            # Initial port scan
            if callback:
                callback('progress', {'message': 'Starting initial port scan...'})
                
            ports = self._scan_ports(target)
            if ports:
                found_valuable_info = True
                self.add_finding({
                    'type': 'ports',
                    'description': 'Open ports found',
                    'details': ports
                })
            
            # Find DC IP if target is a domain
            if '.' in target:
                dc_ip = self._find_dc(target)
                if dc_ip:
                    target = dc_ip
                    self.add_finding({
                        'type': 'domain',
                        'description': 'Domain Controller found',
                        'details': {'dc_ip': dc_ip}
                    })
            
            # Try zone transfer
            if callback:
                callback('progress', {'message': 'Attempting zone transfer...'})
            
            zones = self._try_zone_transfer(target)
            if zones:
                found_valuable_info = True
                self.add_finding({
                    'type': 'dns',
                    'description': 'Zone transfer successful',
                    'details': zones
                })
            
            # Check anonymous access
            if callback:
                callback('progress', {'message': 'Checking anonymous access...'})
                
            anon_access = self._check_anonymous_access(target)
            if anon_access:
                found_valuable_info = True
                self.add_finding({
                    'type': 'anonymous_access',
                    'description': 'Anonymous access available',
                    'details': anon_access
                })
            
            # Enumerate users through Kerberos
            if callback:
                callback('progress', {'message': 'Enumerating users via Kerberos...'})
                
            users = self._enumerate_users(target)
            if users:
                found_valuable_info = True
                self.add_finding({
                    'type': 'users',
                    'description': 'Users enumerated via Kerberos',
                    'details': users
                })
            
            return found_valuable_info
            
        except Exception as e:
            self.logger.error(f"Enumeration error: {str(e)}")
            return False
    
    def _scan_ports(self, target: str) -> Dict:
        """Perform port scanning"""
        # Quick TCP scan
        cmd = [
            'nmap', '-sS', '-p-', '--min-rate=1000',
            '-T4', '--open', target
        ]
        result = self.run_cmd(cmd, silent=True)
        
        # Parse open ports
        ports = {
            'tcp': [],
            'services': {}
        }
        
        for line in result.stdout.splitlines():
            if '/tcp' in line and 'open' in line:
                port = line.split('/')[0]
                ports['tcp'].append(port)
        
        if ports['tcp']:
            # Detailed scan of open ports
            cmd = [
                'nmap', '-sV', '-sC',
                '-p', ','.join(ports['tcp']),
                target
            ]
            result = self.run_cmd(cmd, silent=True)
            
            # Parse service info
            current_port = None
            for line in result.stdout.splitlines():
                if '/tcp' in line and 'open' in line:
                    current_port = line.split('/')[0]
                    service = line.split('open')[1].strip()
                    ports['services'][current_port] = {'service': service}
        
        return ports
    
    def _find_dc(self, domain: str) -> Optional[str]:
        """Find Domain Controller IP"""
        try:
            # Try SRV record lookup
            cmd = [
                'dig', 'SRV',
                f'_ldap._tcp.dc._msdcs.{domain}'
            ]
            result = self.run_cmd(cmd, silent=True)
            
            # Parse DC IP
            for line in result.stdout.splitlines():
                if 'IN' in line and 'SRV' in line:
                    parts = line.split()
                    if len(parts) >= 8:
                        dc_host = parts[7].rstrip('.')
                        # Resolve hostname to IP
                        cmd = ['dig', '+short', dc_host]
                        result = self.run_cmd(cmd, silent=True)
                        if result.stdout.strip():
                            return result.stdout.strip()
            
            return None
            
        except:
            return None
    
    def _try_zone_transfer(self, target: str) -> List[Dict]:
        """Attempt DNS zone transfer"""
        zones = []
        
        try:
            # First get NS records
            cmd = ['dig', 'NS', target]
            result = self.run_cmd(cmd, silent=True)
            
            # Parse nameservers
            nameservers = []
            for line in result.stdout.splitlines():
                if 'IN' in line and 'NS' in line:
                    ns = line.split()[-1].rstrip('.')
                    nameservers.append(ns)
            
            # Try zone transfer from each NS
            for ns in nameservers:
                cmd = ['dig', 'AXFR', f'@{ns}', target]
                result = self.run_cmd(cmd, silent=True)
                
                if 'Transfer failed.' not in result.stdout:
                    zones.append({
                        'nameserver': ns,
                        'records': result.stdout
                    })
            
            return zones
            
        except:
            return zones
    
    def _check_anonymous_access(self, target: str) -> Dict:
        """Check for anonymous access to services"""
        access = {
            'smb': False,
            'ldap': False,
            'shares': []
        }
        
        try:
            # Check SMB
            cmd = ['nxc', 'smb', target, '-u', '', '-p', '']
            result = self.run_cmd(cmd, silent=True)
            
            if 'STATUS_ACCESS_DENIED' not in result.stdout:
                access['smb'] = True
                
                # Enumerate shares
                cmd = ['enum4linux-ng', '-A', '-u', '', '-p', '', target]
                result = self.run_cmd(cmd, silent=True)
                
                # Parse shares
                for line in result.stdout.splitlines():
                    if 'Disk' in line and '|' in line:
                        share = line.split('|')[0].strip()
                        access['shares'].append(share)
            
            # Check LDAP
            cmd = ['ldapsearch', '-x', '-h', target, '-s', 'base']
            result = self.run_cmd(cmd, silent=True)
            
            if result.returncode == 0:
                access['ldap'] = True
            
            return access
            
        except:
            return access
    
    def _enumerate_users(self, target: str) -> List[Dict]:
        """Enumerate users through Kerberos"""
        users = []
        
        try:
            # Use kerbrute for user enumeration
            cmd = [
                'kerbrute', 'userenum',
                '--dc', target,
                '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt'
            ]
            result = self.run_cmd(cmd, silent=True)
            
            # Parse valid users
            for line in result.stdout.splitlines():
                if 'VALID USERNAME:' in line:
                    username = line.split(':')[1].strip()
                    users.append({
                        'username': username,
                        'source': 'kerbrute'
                    })
            
            # Try RID cycling with nxc
            cmd = ['nxc', 'smb', target, '--rid-brute']
            result = self.run_cmd(cmd, silent=True)
            
            # Parse users from RID cycling
            for line in result.stdout.splitlines():
                if 'SidTypeUser' in line:
                    match = re.search(r'(\S+) \(SidTypeUser\)', line)
                    if match:
                        username = match.group(1)
                        if not any(u['username'] == username for u in users):
                            users.append({
                                'username': username,
                                'source': 'rid_cycling'
                            })
            
            return users
            
        except:
            return users 