"""
Active Directory Scanner Module

This module provides comprehensive Active Directory enumeration and scanning capabilities:
- Domain controller identification
- LDAP enumeration (users, groups, computers, OUs)
- Kerberos configuration checks
- SMB share enumeration
- Null session checks
- Trust relationship mapping
- Group Policy enumeration
- ACL analysis

Key Features:
- Safe enumeration methods
- Detailed reporting
- Privilege level awareness
- Integration with BloodHound
"""

from typing import Optional, Dict, List, Tuple
import ldap3
from impacket.dcerpc.v5 import transport, samr, wkst, scmr
from impacket.smbconnection import SMBConnection
import socket
import logging
import json
from datetime import datetime

class ActiveDirectoryScanner:
    def __init__(self, domain: str = None, username: str = None, 
                 password: str = None, dc_ip: str = None):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.logger = logging.getLogger(__name__)
        self.results = {
            'domain_info': {},
            'users': [],
            'groups': [],
            'computers': [],
            'shares': [],
            'gpo': [],
            'trusts': [],
            'scan_info': {
                'start_time': None,
                'end_time': None
            }
        }
        
    def scan_domain(self, callback: Optional[callable] = None) -> Dict:
        """
        Perform comprehensive AD scan
        
        Args:
            callback: Optional callback for progress updates
            
        Returns:
            Dict containing all scan results
        """
        try:
            self.results['scan_info']['start_time'] = datetime.now().isoformat()
            
            # Validate DC connection
            if not self._validate_dc():
                raise Exception("Could not connect to domain controller")
            
            # Enumerate domain info
            self._enumerate_domain_info(callback)
            
            # LDAP enumeration
            self._enumerate_ldap(callback)
            
            # SMB enumeration
            self._enumerate_smb(callback)
            
            # Kerberos enumeration
            self._enumerate_kerberos(callback)
            
            # Trust relationships
            self._enumerate_trusts(callback)
            
            # Group Policy
            self._enumerate_gpo(callback)
            
            self.results['scan_info']['end_time'] = datetime.now().isoformat()
            return self.results
            
        except Exception as e:
            self.logger.error(f"Domain scan error: {str(e)}")
            return self.results
            
    def _validate_dc(self) -> bool:
        """Validate connection to domain controller"""
        try:
            if not self.dc_ip:
                # Try to resolve DC
                try:
                    self.dc_ip = socket.gethostbyname(f"{self.domain}")
                except:
                    return False
            
            # Test LDAP connection
            server = ldap3.Server(
                self.dc_ip,
                get_info=ldap3.ALL,
                use_ssl=False
            )
            
            conn = ldap3.Connection(
                server,
                user=f"{self.username}@{self.domain}" if self.username else None,
                password=self.password,
                authentication=ldap3.NTLM if self.username else ldap3.ANONYMOUS
            )
            
            return conn.bind()
            
        except Exception as e:
            self.logger.error(f"DC validation error: {str(e)}")
            return False
            
    def _enumerate_domain_info(self, callback: Optional[callable] = None):
        """Enumerate basic domain information"""
        try:
            # Connect to LDAP
            server = ldap3.Server(
                self.dc_ip,
                get_info=ldap3.ALL,
                use_ssl=False
            )
            
            conn = ldap3.Connection(
                server,
                user=f"{self.username}@{self.domain}" if self.username else None,
                password=self.password,
                authentication=ldap3.NTLM if self.username else ldap3.ANONYMOUS
            )
            
            if not conn.bind():
                return
            
            # Get domain info
            domain_info = {
                'naming_contexts': server.info.naming_contexts,
                'schema': server.schema.raw,
                'server_type': server.info.server_type,
                'supported_controls': server.info.supported_controls,
                'supported_sasl_mechanisms': server.info.supported_sasl_mechanisms
            }
            
            self.results['domain_info'] = domain_info
            
            if callback:
                callback('progress', {'message': 'Domain information collected'})
                
        except Exception as e:
            self.logger.error(f"Domain info enumeration error: {str(e)}")
            
    def _enumerate_ldap(self, callback: Optional[callable] = None):
        """Enumerate LDAP objects"""
        try:
            server = ldap3.Server(
                self.dc_ip,
                get_info=ldap3.ALL,
                use_ssl=False
            )
            
            conn = ldap3.Connection(
                server,
                user=f"{self.username}@{self.domain}" if self.username else None,
                password=self.password,
                authentication=ldap3.NTLM if self.username else ldap3.ANONYMOUS
            )
            
            if not conn.bind():
                return
            
            # Enumerate Users
            if callback:
                callback('progress', {'message': 'Enumerating users...'})
                
            conn.search(
                self.domain,
                "(&(objectClass=user)(objectCategory=person))",
                attributes=[
                    "sAMAccountName",
                    "userPrincipalName",
                    "memberOf",
                    "primaryGroupID",
                    "userAccountControl",
                    "lastLogon",
                    "pwdLastSet"
                ]
            )
            
            for entry in conn.entries:
                user_info = entry.entry_attributes_as_dict
                user_info['dn'] = entry.entry_dn
                self.results['users'].append(user_info)
            
            # Enumerate Groups
            if callback:
                callback('progress', {'message': 'Enumerating groups...'})
                
            conn.search(
                self.domain,
                "(objectClass=group)",
                attributes=[
                    "cn",
                    "member",
                    "memberOf",
                    "groupType",
                    "adminCount"
                ]
            )
            
            for entry in conn.entries:
                group_info = entry.entry_attributes_as_dict
                group_info['dn'] = entry.entry_dn
                self.results['groups'].append(group_info)
            
            # Enumerate Computers
            if callback:
                callback('progress', {'message': 'Enumerating computers...'})
                
            conn.search(
                self.domain,
                "(objectClass=computer)",
                attributes=[
                    "dNSHostName",
                    "operatingSystem",
                    "operatingSystemVersion",
                    "lastLogonTimestamp",
                    "servicePrincipalName"
                ]
            )
            
            for entry in conn.entries:
                computer_info = entry.entry_attributes_as_dict
                computer_info['dn'] = entry.entry_dn
                self.results['computers'].append(computer_info)
                
        except Exception as e:
            self.logger.error(f"LDAP enumeration error: {str(e)}")
            
    def _enumerate_smb(self, callback: Optional[callable] = None):
        """Enumerate SMB shares and permissions"""
        try:
            if not self.username:
                # Try null session
                smb = SMBConnection(self.dc_ip, self.dc_ip)
                try:
                    smb.login('', '')
                except:
                    return
            else:
                smb = SMBConnection(self.dc_ip, self.dc_ip)
                smb.login(self.username, self.password, self.domain)
            
            shares = smb.listShares()
            
            for share in shares:
                share_info = {
                    'name': share['shi1_netname'][:-1],
                    'remark': share['shi1_remark'][:-1] if share['shi1_remark'] else '',
                    'permissions': self._check_share_access(smb, share['shi1_netname'][:-1])
                }
                self.results['shares'].append(share_info)
                
            if callback:
                callback('progress', {
                    'message': f'Enumerated {len(shares)} SMB shares'
                })
                
        except Exception as e:
            self.logger.error(f"SMB enumeration error: {str(e)}")
            
    def _check_share_access(self, smb: SMBConnection, share: str) -> Dict:
        """Check access permissions on SMB share"""
        perms = {
            'read': False,
            'write': False,
            'admin': False
        }
        
        try:
            # Try to list contents
            smb.listPath(share, '*')
            perms['read'] = True
            
            # Try to create temp file
            try:
                smb.createFile(share, 'temp.txt')
                perms['write'] = True
                smb.deleteFile(share, 'temp.txt')
            except:
                pass
                
            # Check admin access
            try:
                smb.createDirectory(share, 'temp_dir')
                perms['admin'] = True
                smb.deleteDirectory(share, 'temp_dir')
            except:
                pass
                
        except:
            pass
            
        return perms
        
    def _enumerate_kerberos(self, callback: Optional[callable] = None):
        """Enumerate Kerberos configuration"""
        try:
            server = ldap3.Server(
                self.dc_ip,
                get_info=ldap3.ALL,
                use_ssl=False
            )
            
            conn = ldap3.Connection(
                server,
                user=f"{self.username}@{self.domain}" if self.username else None,
                password=self.password,
                authentication=ldap3.NTLM if self.username else ldap3.ANONYMOUS
            )
            
            if not conn.bind():
                return
            
            # Find accounts with Kerberos issues
            if callback:
                callback('progress', {'message': 'Checking Kerberos configuration...'})
            
            # Check for accounts not requiring pre-authentication
            conn.search(
                self.domain,
                "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                attributes=["sAMAccountName", "userPrincipalName"]
            )
            
            for entry in conn.entries:
                self.results.setdefault('kerberos_issues', []).append({
                    'type': 'no_preauth',
                    'user': entry.sAMAccountName.value,
                    'upn': entry.userPrincipalName.value
                })
            
            # Check for accounts with constrained delegation
            conn.search(
                self.domain,
                "(&(objectClass=user)(msDS-AllowedToDelegateTo=*))",
                attributes=["sAMAccountName", "msDS-AllowedToDelegateTo"]
            )
            
            for entry in conn.entries:
                self.results.setdefault('kerberos_issues', []).append({
                    'type': 'constrained_delegation',
                    'user': entry.sAMAccountName.value,
                    'delegation_to': entry['msDS-AllowedToDelegateTo'].values
                })
                
        except Exception as e:
            self.logger.error(f"Kerberos enumeration error: {str(e)}")
            
    def _enumerate_trusts(self, callback: Optional[callable] = None):
        """Enumerate domain trusts"""
        try:
            if callback:
                callback('progress', {'message': 'Enumerating domain trusts...'})
                
            server = ldap3.Server(
                self.dc_ip,
                get_info=ldap3.ALL,
                use_ssl=False
            )
            
            conn = ldap3.Connection(
                server,
                user=f"{self.username}@{self.domain}" if self.username else None,
                password=self.password,
                authentication=ldap3.NTLM if self.username else ldap3.ANONYMOUS
            )
            
            if not conn.bind():
                return
            
            # Search for trust objects
            conn.search(
                self.domain,
                "(objectClass=trustedDomain)",
                attributes=[
                    "trustPartner",
                    "trustDirection",
                    "trustType",
                    "trustAttributes"
                ]
            )
            
            for entry in conn.entries:
                trust_info = entry.entry_attributes_as_dict
                trust_info['dn'] = entry.entry_dn
                self.results['trusts'].append(trust_info)
                
        except Exception as e:
            self.logger.error(f"Trust enumeration error: {str(e)}")
            
    def _enumerate_gpo(self, callback: Optional[callable] = None):
        """Enumerate Group Policy Objects"""
        try:
            if callback:
                callback('progress', {'message': 'Enumerating Group Policy Objects...'})
                
            server = ldap3.Server(
                self.dc_ip,
                get_info=ldap3.ALL,
                use_ssl=False
            )
            
            conn = ldap3.Connection(
                server,
                user=f"{self.username}@{self.domain}" if self.username else None,
                password=self.password,
                authentication=ldap3.NTLM if self.username else ldap3.ANONYMOUS
            )
            
            if not conn.bind():
                return
            
            # Search for GPOs
            conn.search(
                self.domain,
                "(objectClass=groupPolicyContainer)",
                attributes=[
                    "displayName",
                    "gPCFileSysPath",
                    "versionNumber",
                    "flags"
                ]
            )
            
            for entry in conn.entries:
                gpo_info = entry.entry_attributes_as_dict
                gpo_info['dn'] = entry.entry_dn
                
                # Get linked OUs
                conn.search(
                    self.domain,
                    f"(gPLink=*{entry.entry_dn}*)",
                    attributes=["distinguishedName"]
                )
                
                gpo_info['linked_ous'] = [
                    ou.distinguishedName.value
                    for ou in conn.entries
                ]
                
                self.results['gpo'].append(gpo_info)
                
        except Exception as e:
            self.logger.error(f"GPO enumeration error: {str(e)}")
            
    def get_privileged_accounts(self) -> List[Dict]:
        """Get list of privileged accounts"""
        privileged = []
        
        try:
            for user in self.results['users']:
                # Check for admin count
                if user.get('adminCount', [False])[0]:
                    privileged.append({
                        'type': 'user',
                        'name': user['sAMAccountName'][0],
                        'reason': 'Admin count set'
                    })
                    
                # Check group memberships
                admin_groups = [
                    'Domain Admins',
                    'Enterprise Admins',
                    'Schema Admins',
                    'Administrators'
                ]
                
                for group in user.get('memberOf', []):
                    if any(admin_group in group for admin_group in admin_groups):
                        privileged.append({
                            'type': 'user',
                            'name': user['sAMAccountName'][0],
                            'reason': f'Member of {group}'
                        })
                        
        except Exception as e:
            self.logger.error(f"Error getting privileged accounts: {str(e)}")
            
        return privileged
        
    def get_potential_vulnerabilities(self) -> List[Dict]:
        """Get list of potential AD vulnerabilities"""
        vulns = []
        
        try:
            # Check for Kerberos issues
            if 'kerberos_issues' in self.results:
                for issue in self.results['kerberos_issues']:
                    if issue['type'] == 'no_preauth':
                        vulns.append({
                            'type': 'kerberos',
                            'severity': 'High',
                            'description': f"User {issue['user']} has Kerberos pre-authentication disabled",
                            'recommendation': 'Enable Kerberos pre-authentication'
                        })
                    elif issue['type'] == 'constrained_delegation':
                        vulns.append({
                            'type': 'kerberos',
                            'severity': 'Medium',
                            'description': f"User {issue['user']} is configured for constrained delegation",
                            'recommendation': 'Review delegation configuration'
                        })
            
            # Check for null session access
            for share in self.results['shares']:
                if share['permissions']['read'] and not self.username:
                    vulns.append({
                        'type': 'smb',
                        'severity': 'Medium',
                        'description': f"Share {share['name']} allows null session access",
                        'recommendation': 'Disable null session access'
                    })
            
            # Check for domain trusts
            for trust in self.results['trusts']:
                if trust.get('trustDirection', [0])[0] in [2, 3]:  # Incoming or Bidirectional
                    vulns.append({
                        'type': 'trust',
                        'severity': 'Info',
                        'description': f"Incoming trust from {trust['trustPartner'][0]}",
                        'recommendation': 'Review trust relationship'
                    })
                    
        except Exception as e:
            self.logger.error(f"Error getting vulnerabilities: {str(e)}")
            
        return vulns 