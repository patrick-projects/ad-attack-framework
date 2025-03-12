"""
Quick Vulnerability Scanner Module for Kali Linux

This module implements quick vulnerability scanning capabilities based on the OCD mindmap:
- Network-based vulnerability scanning using modern tools
- Service enumeration and vulnerability checks
- Active Directory security assessment including ADCS vulnerabilities (ESC1-8)
- Credential access and privilege escalation detection
- Poisoning and relay attack surface detection
- Network device vulnerability detection (Cisco Smart Install)
- Web vulnerability scanning using Nuclei

Key Features:
- Remote target assessment
- Integration with current Kali Linux tools (2024)
- Both authenticated and unauthenticated checks
- Comprehensive vulnerability reporting
- References to appropriate attack modules for exploitation
"""

from typing import Optional, Dict, List, Callable
import subprocess
import json
import logging
from datetime import datetime
import os
import tempfile
from pathlib import Path
import shutil
import time
import base64

class QuickVulnScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.results = {
            'web_vulns': [],
            'service_vulns': [],
            'quick_wins': [],
            'attack_surface': {
                'poisoning': [],
                'relay': [],
                'coercion': [],
                'time_based': [],
                'network_devices': [],
                'web': []  # Added for web vulnerabilities
            },
            'scan_info': {
                'start_time': None,
                'end_time': None,
                'recommended_modules': []
            }
        }
        self.credentials = None
        self._check_required_tools()
        
    def _check_required_tools(self):
        """Verify all required tools are installed"""
        required_tools = {
            'nmap': 'nmap',
            'netexec': 'netexec',  # Modern replacement for CrackMapExec
            'bloodhound-python': 'bloodhound-python',
            'ldeep': 'ldeep',  # Modern LDAP enumeration
            'kerbrute': 'kerbrute',  # Modern Kerberos testing
            'responder': 'responder',
            'feroxbuster': 'feroxbuster',  # Modern web enumeration
            'certipy': 'certipy-ad',  # ADCS exploitation
            'ntlmrelayx': 'impacket-ntlmrelayx',  # NTLM relay attacks
            'mitm6': 'mitm6',
            'bettercap': 'bettercap',
            'nc': 'netcat',  # Required for Smart Install checks
            'nuclei': 'nuclei'  # Added Nuclei for web scanning
        }
        
        missing_tools = []
        for tool, package in required_tools.items():
            if not shutil.which(tool):
                missing_tools.append(f"{tool} ({package})")
        
        if missing_tools:
            raise RuntimeError(f"Missing required tools: {', '.join(missing_tools)}. Please install using 'apt install'")

    def scan_target(self, target: str, credentials: Optional[Dict] = None, callback: Optional[Callable] = None) -> bool:
        """
        Perform quick vulnerability scan against remote target
        
        Args:
            target: Target IP/hostname
            credentials: Optional dict with 'username' and 'password' or 'hash'
            callback: Optional callback for progress updates
        """
        try:
            self.credentials = credentials
            self.results['scan_info']['start_time'] = datetime.now().isoformat()
            
            # Initial port scan
            self._initial_port_scan(target, callback)
            
            # Service-specific checks
            self._check_services(target, callback)
            
            # Quick win checks
            self._check_quick_wins(target, callback)
            
            # Web vulnerability scanning with Nuclei
            self._scan_web_vulnerabilities(target, callback)
            
            self.results['scan_info']['end_time'] = datetime.now().isoformat()
            return True
            
        except Exception as e:
            self.logger.error(f"Quick scan error: {str(e)}")
            return False

    def _initial_port_scan(self, target: str, callback: Optional[Callable] = None):
        """Perform initial port scan to identify services"""
        try:
            if callback:
                callback('progress', {'message': 'Starting initial port scan...'})
            
            # Fast initial TCP scan
            cmd = [
                'nmap', '-sS', '-p-', '--min-rate=1000', '-T4',
                '--open', target
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse open ports for service scanning
            open_ports = []
            for line in process.stdout.splitlines():
                if '/tcp' in line and 'open' in line:
                    port = line.split('/')[0]
                    open_ports.append(port)
            
            # Detailed service scan on open ports
            if open_ports:
                ports = ','.join(open_ports)
                cmd = [
                    'nmap', '-sV', '-sC', '-p', ports,
                    '--script=vuln,default,auth,exploit',
                    target
                ]
                
                process = subprocess.run(cmd, capture_output=True, text=True)
                
                # Process results
                self._process_nmap_results(process.stdout, callback)
                
        except Exception as e:
            self.logger.error(f"Port scan error: {str(e)}")

    def _check_services(self, target: str, callback: Optional[Callable] = None):
        """Check for specific vulnerable services"""
        services = {
            'smb': self._check_smb,
            'ldap': self._check_ldap,
            'kerberos': self._check_kerberos,
            'mssql': self._check_mssql,
            'winrm': self._check_winrm,
            'rdp': self._check_rdp,
            'adcs': self._check_adcs,
            'smart_install': self._check_smart_install  # Added Smart Install check
        }
        
        # Add attack surface checks
        self._check_poisoning_surface(target, callback)
        self._check_relay_surface(target, callback)
        self._check_time_based_surface(target, callback)
        
        for service_name, check_func in services.items():
            try:
                if callback:
                    callback('progress', {
                        'message': f'Checking {service_name} service...'
                    })
                check_func(target, callback)
            except Exception as e:
                self.logger.error(f"Error checking {service_name}: {str(e)}")

    def _check_poisoning_surface(self, target: str, callback: Optional[Callable] = None):
        """Check for poisoning attack surfaces"""
        try:
            # Check LLMNR/NBT-NS/mDNS
            cmd = ['nmap', '-sU', '-p137,5353', '--script', 'broadcast-dns-service-discovery,nbstat', target]
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if 'LLMNR' in process.stdout or 'NBT-NS' in process.stdout:
                vuln = {
                    'type': 'poisoning',
                    'name': 'Name Resolution Poisoning',
                    'protocols': ['LLMNR', 'NBT-NS', 'mDNS'],
                    'severity': 'High',
                    'description': 'Name resolution protocols enabled and vulnerable to poisoning',
                    'recommendation': 'Disable LLMNR and NBT-NS, restrict mDNS',
                    'attack_module': 'poisoning_attacks.PoisoningAttacks'
                }
                self.results['attack_surface']['poisoning'].append(vuln)
                self.results['scan_info']['recommended_modules'].append('poisoning_attacks')

            # Check IPv6/DHCPv6
            cmd = ['nmap', '-6', '-sU', '-p547', '--script', 'dhcpv6-discover', target]
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if 'DHCPv6' in process.stdout:
                vuln = {
                    'type': 'poisoning',
                    'name': 'DHCPv6 Poisoning',
                    'protocols': ['IPv6', 'DHCPv6'],
                    'severity': 'High',
                    'description': 'DHCPv6 enabled and vulnerable to WPAD attacks',
                    'recommendation': 'Disable IPv6 if not required, implement DHCPv6 security controls',
                    'attack_module': 'poisoning_attacks.PoisoningAttacks'
                }
                self.results['attack_surface']['poisoning'].append(vuln)
                self.results['scan_info']['recommended_modules'].append('poisoning_attacks')

            # Check WPAD configuration
            cmd = ['nmap', '-p80,443', '--script', 'http-wpad-discovery', target]
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if 'WPAD' in process.stdout:
                vuln = {
                    'type': 'poisoning',
                    'name': 'WPAD Poisoning',
                    'protocols': ['HTTP', 'WPAD'],
                    'severity': 'High',
                    'description': 'WPAD enabled and vulnerable to proxy configuration attacks',
                    'recommendation': 'Disable WPAD or implement secure proxy configuration',
                    'attack_module': 'poisoning_attacks.PoisoningAttacks'
                }
                self.results['attack_surface']['poisoning'].append(vuln)

        except Exception as e:
            self.logger.error(f"Poisoning surface check error: {str(e)}")

    def _check_relay_surface(self, target: str, callback: Optional[Callable] = None):
        """Check for relay attack surfaces"""
        try:
            # Check SMB signing
            cmd = ['netexec', 'smb', target, '--gen-relay-list', '/tmp/relay_targets.txt']
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if os.path.exists('/tmp/relay_targets.txt') and os.path.getsize('/tmp/relay_targets.txt') > 0:
                with open('/tmp/relay_targets.txt', 'r') as f:
                    relay_targets = f.read().splitlines()
                
                vuln = {
                    'type': 'relay',
                    'name': 'NTLM Relay',
                    'protocols': ['SMB'],
                    'severity': 'High',
                    'description': f'SMB signing not enforced on {len(relay_targets)} targets',
                    'recommendation': 'Enable SMB signing requirements',
                    'attack_module': 'coercion_attacks.CoercionAttacks',
                    'affected_targets': relay_targets
                }
                self.results['attack_surface']['relay'].append(vuln)
                self.results['scan_info']['recommended_modules'].append('coercion_attacks')
            
            os.remove('/tmp/relay_targets.txt')

            # Check LDAP signing
            cmd = ['netexec', 'ldap', target, '--auth-verify']
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if 'Signing not required' in process.stdout:
                vuln = {
                    'type': 'relay',
                    'name': 'LDAP Relay',
                    'protocols': ['LDAP'],
                    'severity': 'High',
                    'description': 'LDAP signing not enforced',
                    'recommendation': 'Enable LDAP signing and channel binding',
                    'attack_module': 'coercion_attacks.CoercionAttacks'
                }
                self.results['attack_surface']['relay'].append(vuln)

            # Check HTTP endpoints for potential relay
            cmd = ['nmap', '-p80,443', '--script', 'http-ntlm-info', target]
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if 'NTLM' in process.stdout:
                vuln = {
                    'type': 'relay',
                    'name': 'HTTP NTLM Relay',
                    'protocols': ['HTTP'],
                    'severity': 'High',
                    'description': 'HTTP endpoints accepting NTLM authentication',
                    'recommendation': 'Enable Extended Protection for Authentication (EPA)',
                    'attack_module': 'coercion_attacks.CoercionAttacks'
                }
                self.results['attack_surface']['relay'].append(vuln)

        except Exception as e:
            self.logger.error(f"Relay surface check error: {str(e)}")

    def _check_time_based_surface(self, target: str, callback: Optional[Callable] = None):
        """Check for time-based attack surfaces"""
        try:
            # Check Kerberos time sync
            cmd = ['nmap', '-p88', '--script', 'krb5-enum-users', target]
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode == 0:
                vuln = {
                    'type': 'time_based',
                    'name': 'Kerberos Time Attack Surface',
                    'protocols': ['Kerberos'],
                    'severity': 'Medium',
                    'description': 'Kerberos service available for time-based attacks',
                    'recommendation': 'Ensure tight time synchronization',
                    'attack_module': 'time_attacks.TimeAttacks'
                }
                self.results['attack_surface']['time_based'].append(vuln)
                self.results['scan_info']['recommended_modules'].append('time_attacks')

        except Exception as e:
            self.logger.error(f"Time-based surface check error: {str(e)}")

    def _check_smb(self, target: str, callback: Optional[Callable] = None):
        """Check for SMB vulnerabilities using modern tools"""
        try:
            # Use netexec instead of enum4linux and old crackmapexec
            cmd = [
                'netexec', 'smb', target,
                '--gen-relay-list', 'relay_targets.txt',
                '--shares'
            ]
            
            if self.credentials:
                cmd.extend([
                    '-u', self.credentials['username'],
                    '-p', self.credentials['password']
                ])
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            # Process netexec results
            if 'signing:False' in process.stdout:
                vuln = {
                    'type': 'service',
                    'service': 'smb',
                    'name': 'SMB Signing Disabled',
                    'severity': 'High',
                    'description': 'SMB signing not enforced - vulnerable to NTLM relay',
                    'recommendation': 'Enable SMB signing requirements'
                }
                self.results['service_vulns'].append(vuln)
            
            if 'Pwn3d!' in process.stdout:
                vuln = {
                    'type': 'service',
                    'service': 'smb',
                    'name': 'SMB Admin Access',
                    'severity': 'Critical',
                    'description': 'Administrative access available via SMB',
                    'recommendation': 'Review and restrict SMB access'
                }
                self.results['service_vulns'].append(vuln)
                    
        except Exception as e:
            self.logger.error(f"SMB check error: {str(e)}")

    def _check_ldap(self, target: str, callback: Optional[Callable] = None):
        """Check for LDAP vulnerabilities using modern tools"""
        try:
            # Use ldeep instead of ldapsearch/windapsearch
            cmd = [
                'ldeep', 'ldap',
                '--host', target,
                'dump'
            ]
            
            if self.credentials:
                cmd.extend([
                    '--username', self.credentials['username'],
                    '--password', self.credentials['password']
                ])
            else:
                cmd.append('--anonymous')
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode == 0:
                if '--anonymous' in cmd:
                    vuln = {
                        'type': 'service',
                        'service': 'ldap',
                        'name': 'Anonymous LDAP Binding',
                        'severity': 'High',
                        'description': 'LDAP server allows anonymous binding',
                        'recommendation': 'Disable anonymous LDAP binding'
                    }
                    self.results['service_vulns'].append(vuln)
                
                # Check for sensitive data exposure
                if 'Domain Admins' in process.stdout:
                    vuln = {
                        'type': 'service',
                        'service': 'ldap',
                        'name': 'Sensitive Group Enumeration',
                        'severity': 'Medium',
                        'description': 'Able to enumerate sensitive AD groups',
                        'recommendation': 'Review LDAP query permissions'
                    }
                    self.results['service_vulns'].append(vuln)
            
            # Use bloodhound-python for deeper AD enumeration
            if self.credentials:
                cmd = [
                    'bloodhound-python',
                    '-u', self.credentials['username'],
                    '-p', self.credentials['password'],
                    '-d', target.split('.', 1)[1] if '.' in target else target,
                    '-ns', target,
                    '--collect', 'All'
                ]
                
                process = subprocess.run(cmd, capture_output=True, text=True)
                
        except Exception as e:
            self.logger.error(f"LDAP check error: {str(e)}")

    def _check_kerberos(self, target: str, callback: Optional[Callable] = None):
        """Check for Kerberos vulnerabilities using modern tools"""
        try:
            # Use kerbrute for user enumeration
            cmd = [
                'kerbrute',
                'userenum',
                '--dc', target,
                '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt'
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            # Use impacket for specific attacks when credentials are available
            if self.credentials:
                domain = target.split('.', 1)[1] if '.' in target else target
                
                # Kerberoasting
                cmd = [
                    'impacket-GetUserSPNs',
                    f"{domain}/{self.credentials['username']}",
                    '-dc-ip', target,
                    '-request'
                ]
                
                if 'password' in self.credentials:
                    cmd.extend(['-password', self.credentials['password']])
                elif 'hash' in self.credentials:
                    cmd.extend(['-hashes', self.credentials['hash']])
                
                process = subprocess.run(cmd, capture_output=True, text=True)
                
                if '$krb5tgs$' in process.stdout:
                    vuln = {
                        'type': 'service',
                        'service': 'kerberos',
                        'name': 'Kerberoastable Accounts',
                        'severity': 'High',
                        'description': 'Service accounts vulnerable to Kerberoasting found',
                        'recommendation': 'Review service account password policies'
                    }
                    self.results['service_vulns'].append(vuln)
            
            # AS-REP Roasting check
            cmd = [
                'impacket-GetNPUsers',
                f"{target}/",
                '-dc-ip', target,
                '-request',
                '-format', 'hashcat'
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if '$krb5asrep$' in process.stdout:
                vuln = {
                    'type': 'service',
                    'service': 'kerberos',
                    'name': 'AS-REP Roasting',
                    'severity': 'High',
                    'description': 'Users vulnerable to AS-REP Roasting found',
                    'recommendation': 'Enable Kerberos pre-authentication'
                }
                self.results['service_vulns'].append(vuln)
                
        except Exception as e:
            self.logger.error(f"Kerberos check error: {str(e)}")

    def _check_mssql(self, target: str, callback: Optional[Callable] = None):
        """Check for MSSQL vulnerabilities"""
        try:
            # Try common MSSQL misconfigurations
            cmd = [
                'nmap', '-p1433', '--script', 'ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes',
                '--script-args', 'mssql.instance-port=1433,mssql.username=sa,mssql.password=sa',
                target
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            # Check authenticated access with CrackMapExec
            if self.credentials:
                cmd = [
                    'crackmapexec', 'mssql', target,
                    '-u', self.credentials['username'],
                    '-p', self.credentials['password']
                ]
                
                process = subprocess.run(cmd, capture_output=True, text=True)
                
                if 'Pwn3d!' in process.stdout:
                    vuln = {
                        'type': 'service',
                        'service': 'mssql',
                        'name': 'MSSQL Admin Access',
                        'severity': 'Critical',
                        'description': 'Administrative access available to MSSQL',
                        'recommendation': 'Review and restrict MSSQL permissions'
                    }
                    self.results['service_vulns'].append(vuln)
                    
        except Exception as e:
            self.logger.error(f"MSSQL check error: {str(e)}")

    def _check_winrm(self, target: str, callback: Optional[Callable] = None):
        """Check for WinRM vulnerabilities"""
        try:
            # Check WinRM access with evil-winrm
            if self.credentials:
                cmd = [
                    'evil-winrm', '-i', target,
                    '-u', self.credentials['username'],
                    '-p', self.credentials['password'],
                    '-c', 'exit'
                ]
                
                process = subprocess.run(cmd, capture_output=True, text=True)
                
                if 'Evil-WinRM shell' in process.stdout:
                    vuln = {
                        'type': 'service',
                        'service': 'winrm',
                        'name': 'WinRM Access',
                        'severity': 'Critical',
                        'description': 'Remote PowerShell access available via WinRM',
                        'recommendation': 'Review and restrict WinRM access'
                    }
                    self.results['service_vulns'].append(vuln)
                    
        except Exception as e:
            self.logger.error(f"WinRM check error: {str(e)}")

    def _check_rdp(self, target: str, callback: Optional[Callable] = None):
        """Check for RDP vulnerabilities"""
        try:
            # Check for RDP security settings
            cmd = [
                'nmap', '-p3389', '--script', 'rdp-enum-encryption,rdp-vuln-ms12-020',
                target
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if 'VULNERABLE' in process.stdout:
                vuln = {
                    'type': 'service',
                    'service': 'rdp',
                    'name': 'RDP Vulnerability',
                    'severity': 'High',
                    'description': 'RDP service vulnerable to known exploits',
                    'recommendation': 'Apply security patches and harden RDP configuration'
                }
                self.results['service_vulns'].append(vuln)
            
            # Check NLA settings
            if 'NLA: Disabled' in process.stdout:
                vuln = {
                    'type': 'service',
                    'service': 'rdp',
                    'name': 'RDP NLA Disabled',
                    'severity': 'Medium',
                    'description': 'Network Level Authentication is disabled',
                    'recommendation': 'Enable NLA for RDP'
                }
                self.results['service_vulns'].append(vuln)
                
        except Exception as e:
            self.logger.error(f"RDP check error: {str(e)}")

    def _check_adcs(self, target: str, callback: Optional[Callable] = None):
        """Check for ADCS vulnerabilities using modern tools"""
        try:
            # First check if ADCS is running
            cmd = ['nmap', '-p443,135,49671', '--script', 'ssl-cert,msrpc-enum', target]
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if 'Active Directory Certificate Services' not in process.stdout:
                return
            
            # Use certipy for comprehensive ADCS enumeration
            if self.credentials:
                domain = target.split('.', 1)[1] if '.' in target else target
                output_file = '/tmp/adcs_enum.json'
                
                cmd = [
                    'certipy', 'find',
                    '-u', self.credentials['username'],
                    '-p', self.credentials['password'],
                    '-dc-ip', target,
                    '-output', output_file,
                    domain
                ]
                
                process = subprocess.run(cmd, capture_output=True, text=True)
                
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        certipy_data = json.load(f)
                    self._process_adcs_results(certipy_data)
                    os.remove(output_file)
            
            # Use netexec for additional ADCS checks
            cmd = ['netexec', 'ldap', target, '--adcs']
            if self.credentials:
                cmd.extend([
                    '-u', self.credentials['username'],
                    '-p', self.credentials['password']
                ])
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            self._process_netexec_adcs_results(process.stdout)
            
        except Exception as e:
            self.logger.error(f"ADCS check error: {str(e)}")

    def _process_adcs_results(self, data: dict):
        """Process certipy ADCS enumeration results"""
        try:
            if 'Certificate Authorities' in data:
                for ca in data['Certificate Authorities'].values():
                    # Check for web enrollment vulnerabilities
                    if ca.get('Web Enrollment'):
                        vuln = {
                            'type': 'service',
                            'service': 'adcs',
                            'name': 'ADCS Web Enrollment Enabled',
                            'severity': 'Medium',
                            'description': 'Web enrollment interface is enabled and may be vulnerable to ESC1',
                            'recommendation': 'Review web enrollment security settings'
                        }
                        self.results['service_vulns'].append(vuln)
            
            if 'Certificate Templates' in data:
                for template in data['Certificate Templates'].values():
                    # Check for ESC1 (Web Enrollment)
                    if template.get('Client Authentication') and template.get('Enrollable by') == 'Domain Users':
                        vuln = {
                            'type': 'service',
                            'service': 'adcs',
                            'name': 'ESC1 - Vulnerable Template',
                            'severity': 'Critical',
                            'description': f"Template {template['Name']} allows domain user enrollment with client auth",
                            'recommendation': 'Review and restrict template enrollment permissions'
                        }
                        self.results['service_vulns'].append(vuln)
                    
                    # Check for ESC2 (SAN Attribute)
                    if template.get('Client Authentication') and template.get('Enrollee Supplies Subject'):
                        vuln = {
                            'type': 'service',
                            'service': 'adcs',
                            'name': 'ESC2 - SAN Attribute',
                            'severity': 'Critical',
                            'description': f"Template {template['Name']} allows SAN specification",
                            'recommendation': 'Disable SAN specification in template'
                        }
                        self.results['service_vulns'].append(vuln)
                    
                    # Check for ESC3 (Agent Templates)
                    if template.get('Enrollment Agent'):
                        vuln = {
                            'type': 'service',
                            'service': 'adcs',
                            'name': 'ESC3 - Agent Template',
                            'severity': 'High',
                            'description': f"Template {template['Name']} allows enrollment agent",
                            'recommendation': 'Review enrollment agent templates'
                        }
                        self.results['service_vulns'].append(vuln)
                    
                    # Check for ESC4 (Vulnerable ACL)
                    if template.get('Vulnerable Flags', []):
                        vuln = {
                            'type': 'service',
                            'service': 'adcs',
                            'name': 'ESC4 - Vulnerable ACL',
                            'severity': 'Critical',
                            'description': f"Template {template['Name']} has vulnerable ACL configuration",
                            'recommendation': 'Review and fix template ACL permissions'
                        }
                        self.results['service_vulns'].append(vuln)

        except Exception as e:
            self.logger.error(f"Error processing certipy ADCS results: {str(e)}")

    def _process_netexec_adcs_results(self, output: str):
        """Process netexec ADCS scan results"""
        try:
            # Check for ESC8 (NTLM Relay to ADCS HTTP Endpoints)
            if 'WebEnrollment' in output:
                vuln = {
                    'type': 'service',
                    'service': 'adcs',
                    'name': 'ESC8 - NTLM Relay Risk',
                    'severity': 'Critical',
                    'description': 'ADCS web enrollment endpoint may be vulnerable to NTLM relay',
                    'recommendation': 'Enable EPA and Extended Protection for Authentication'
                }
                self.results['service_vulns'].append(vuln)
            
            # Parse template vulnerabilities
            for line in output.splitlines():
                if 'ESC' in line and 'VULNERABLE' in line:
                    template = line.split('Template:')[1].split()[0] if 'Template:' in line else 'Unknown'
                    esc_type = line.split('ESC')[1].split()[0]
                    
                    vuln = {
                        'type': 'service',
                        'service': 'adcs',
                        'name': f'ESC{esc_type} - Vulnerable Template',
                        'severity': 'Critical',
                        'description': f'Template {template} is vulnerable to ESC{esc_type}',
                        'recommendation': 'Review and secure certificate template'
                    }
                    self.results['service_vulns'].append(vuln)
                
        except Exception as e:
            self.logger.error(f"Error processing netexec ADCS results: {str(e)}")

    def _check_quick_wins(self, target: str, callback: Optional[Callable] = None):
        """Check for quick win vulnerabilities"""
        try:
            checks = [
                self._check_eternal_blue,
                self._check_zerologon,
                self._check_petitpotam,
                self._check_printnightmare,
                self._check_ntlm_relay
            ]
            
            for check in checks:
                try:
                    if callback:
                        callback('progress', {
                            'message': f'Running {check.__name__}...'
                        })
                    check(target, callback)
                except Exception as e:
                    self.logger.error(f"Error in {check.__name__}: {str(e)}")
                    
        except Exception as e:
            self.logger.error(f"Quick wins check error: {str(e)}")

    def _check_eternal_blue(self, target: str, callback: Optional[Callable] = None):
        """Check for EternalBlue vulnerability"""
        try:
            cmd = [
                'nmap', '-p445', '--script', 'smb-vuln-ms17-010',
                target
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if 'VULNERABLE' in process.stdout:
                vuln = {
                    'type': 'quick_win',
                    'name': 'EternalBlue',
                    'severity': 'Critical',
                    'description': 'System vulnerable to EternalBlue (MS17-010)',
                    'recommendation': 'Apply MS17-010 patch immediately'
                }
                self.results['quick_wins'].append(vuln)
                
        except Exception as e:
            self.logger.error(f"EternalBlue check error: {str(e)}")

    def _check_zerologon(self, target: str, callback: Optional[Callable] = None):
        """Check for Zerologon vulnerability"""
        try:
            cmd = [
                'nmap', '-p445', '--script', 'smb-protocols',
                target
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            # Additional check with cve-2020-1472-checker if available
            cmd = [
                'python3', '/usr/share/doc/python3-impacket/examples/cve-2020-1472-checker.py',
                target
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if 'Vulnerable' in process.stdout:
                vuln = {
                    'type': 'quick_win',
                    'name': 'Zerologon',
                    'severity': 'Critical',
                    'description': 'Domain Controller vulnerable to Zerologon (CVE-2020-1472)',
                    'recommendation': 'Apply security patches immediately'
                }
                self.results['quick_wins'].append(vuln)
                
        except Exception as e:
            self.logger.error(f"Zerologon check error: {str(e)}")

    def _check_petitpotam(self, target: str, callback: Optional[Callable] = None):
        """Check for PetitPotam vulnerability"""
        try:
            # Use crackmapexec to check for PetitPotam
            cmd = [
                'crackmapexec', 'smb', target,
                '-M', 'petitpotam'
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if 'VULNERABLE' in process.stdout:
                vuln = {
                    'type': 'quick_win',
                    'name': 'PetitPotam',
                    'severity': 'High',
                    'description': 'System vulnerable to PetitPotam attack',
                    'recommendation': 'Apply security patches and disable NTLM authentication'
                }
                self.results['quick_wins'].append(vuln)
                
        except Exception as e:
            self.logger.error(f"PetitPotam check error: {str(e)}")

    def _check_printnightmare(self, target: str, callback: Optional[Callable] = None):
        """Check for PrintNightmare vulnerability"""
        try:
            cmd = [
                'rpcdump.py', target,
                '|', 'grep', 'MS-RPRN'
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if 'Print System Remote Protocol' in process.stdout:
                vuln = {
                    'type': 'quick_win',
                    'name': 'PrintNightmare',
                    'severity': 'Critical',
                    'description': 'Print Spooler service potentially vulnerable to PrintNightmare',
                    'recommendation': 'Apply security patches or disable Print Spooler'
                }
                self.results['quick_wins'].append(vuln)
                
        except Exception as e:
            self.logger.error(f"PrintNightmare check error: {str(e)}")

    def _check_ntlm_relay(self, target: str, callback: Optional[Callable] = None):
        """Check for NTLM Relay opportunities"""
        try:
            # Check SMB signing
            cmd = [
                'crackmapexec', 'smb', target,
                '--gen-relay-list', 'relay_targets.txt'
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if os.path.exists('relay_targets.txt') and os.path.getsize('relay_targets.txt') > 0:
                vuln = {
                    'type': 'quick_win',
                    'name': 'NTLM Relay',
                    'severity': 'High',
                    'description': 'System vulnerable to NTLM relay attacks',
                    'recommendation': 'Enable SMB signing and disable NTLM authentication'
                }
                self.results['quick_wins'].append(vuln)
                
                # Cleanup
                os.remove('relay_targets.txt')
                
        except Exception as e:
            self.logger.error(f"NTLM Relay check error: {str(e)}")

    def _check_smart_install(self, target: str, callback: Optional[Callable] = None):
        """Check for Cisco Smart Install vulnerability"""
        try:
            # Check if Smart Install is running (TCP 4786)
            cmd = ['nmap', '-p4786', '-sS', '-Pn', target]
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if '4786/tcp open' in process.stdout:
                # Verify it's actually Smart Install with a banner grab
                cmd = ['nc', '-nv', '-w2', target, '4786']
                process = subprocess.run(cmd, capture_output=True, text=True)
                
                # Smart Install devices typically respond with specific patterns
                if any(pattern in process.stdout for pattern in [b'\x00\x00\x00\x01', b'smart_install']):
                    vuln = {
                        'type': 'network_devices',
                        'name': 'Cisco Smart Install',
                        'protocols': ['TCP/4786'],
                        'severity': 'Critical',
                        'description': 'Cisco Smart Install protocol detected - potentially vulnerable to configuration extraction and code execution',
                        'recommendation': 'Disable Smart Install if not in use or restrict access',
                        'attack_module': 'network_device_attacks.SmartInstallExploit',
                        'device_info': {
                            'port': 4786,
                            'protocol': 'smart_install'
                        }
                    }
                    self.results['attack_surface']['network_devices'].append(vuln)
                    self.results['scan_info']['recommended_modules'].append('network_device_attacks')
                    
                    if callback:
                        callback('progress', {
                            'message': 'Found vulnerable Cisco Smart Install service'
                        })

        except Exception as e:
            self.logger.error(f"Smart Install check error: {str(e)}")

    def _scan_web_vulnerabilities(self, target: str, callback: Optional[Callable] = None):
        """
        Perform web vulnerability scanning using Nuclei
        Only scans targets with detected web services
        Uses low rate limiting for stealth
        Provides continuous progress updates
        
        Args:
            target: Target IP/hostname
            callback: Optional callback for progress updates
        """
        try:
            # Check if we have any web services detected
            web_services = [s for s in self.results.get('service_vulns', []) 
                          if s.get('service') in ['http', 'https']]
            
            if not web_services:
                self.logger.info("No web services detected, skipping Nuclei scan")
                return

            if callback:
                callback('progress', {'message': 'Starting Nuclei web vulnerability scan...'})
                callback('progress', {'message': f'Found {len(web_services)} web services to scan'})

            # Create temporary directory for Nuclei output
            with tempfile.TemporaryDirectory() as temp_dir:
                output_file = os.path.join(temp_dir, 'nuclei_output.json')
                
                # Build target list with ports
                targets = []
                for service in web_services:
                    port = service.get('port', '')
                    if port:
                        targets.append(f"{target}:{port}")
                    else:
                        targets.append(target)
                
                if callback:
                    callback('progress', {'message': f'Scanning targets: {", ".join(targets)}'})
                
                # Run Nuclei scan with reduced scope and rate limiting
                cmd = [
                    'nuclei',
                    '-target', ','.join(targets),
                    '-json',  # JSON output format
                    '-o', output_file,
                    '-severity', 'critical,high',  # Only Critical and High
                    '-stats',  # Show statistics
                    '-silent',  # Reduce noise
                    '-rl', '4',  # Rate limit to 4 requests/second
                    '-c', '2',  # Use only 2 concurrent workers
                    '-timeout', '10',  # 10 second timeout per template
                    '-tags', 'cve,rce,injection,auth-bypass,default-login',  # Focus on critical issues
                    '-v'  # Verbose output for more status updates
                ]
                
                # Run initial scan
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)
                
                # Track scan statistics
                templates_executed = 0
                vulnerabilities_found = 0
                last_update_time = time.time()
                
                # Monitor progress with more detailed updates
                while True:
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break
                    
                    if output:
                        # Extract useful information from output
                        if 'templates' in output.lower():
                            templates_executed += 1
                        if 'high' in output.lower() or 'critical' in output.lower():
                            vulnerabilities_found += 1
                        
                        # Provide status update every 5 seconds
                        current_time = time.time()
                        if current_time - last_update_time >= 5:
                            status_msg = f"Progress: {templates_executed} templates executed, {vulnerabilities_found} vulnerabilities found"
                            if callback:
                                callback('progress', {'message': status_msg})
                            self.logger.info(status_msg)
                            last_update_time = current_time
                        
                        # Always show vulnerability findings immediately
                        if '[' in output and ']' in output and any(level in output for level in ['high', 'critical']):
                            if callback:
                                callback('progress', {'message': f"Found: {output.strip()}"})
                
                if callback:
                    callback('progress', {
                        'message': f"Completed initial scan: {templates_executed} templates executed, {vulnerabilities_found} vulnerabilities found"
                    })
                
                # Process results if file exists
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        for line in f:
                            try:
                                result = json.loads(line)
                                vuln = {
                                    'type': 'web',
                                    'name': result.get('template-id', 'Unknown'),
                                    'severity': result.get('info', {}).get('severity', 'Unknown'),
                                    'description': result.get('info', {}).get('description', ''),
                                    'template': result.get('template', ''),
                                    'matched': result.get('matched-at', ''),
                                    'timestamp': result.get('timestamp', ''),
                                    'tags': result.get('info', {}).get('tags', []),
                                    'cve': result.get('info', {}).get('classification', {}).get('cve-id', []),
                                    'cwe': result.get('info', {}).get('classification', {}).get('cwe-id', [])
                                }
                                
                                # Add to results
                                self.results['attack_surface']['web'].append(vuln)
                                
                                # Log finding
                                finding_msg = f"Found {vuln['severity']} web vulnerability: {vuln['name']} at {vuln['matched']}"
                                self.logger.info(finding_msg)
                                if callback:
                                    callback('vulnerability', vuln)
                                    callback('progress', {'message': finding_msg})
                            except json.JSONDecodeError:
                                continue
                
                if callback:
                    callback('progress', {'message': 'Starting technology detection scan...'})
                
                # Run minimal technology detection
                cmd = [
                    'nuclei',
                    '-target', ','.join(targets),
                    '-t', 'technologies',  # Technology detection templates
                    '-json',
                    '-o', output_file,
                    '-silent',
                    '-rl', '4',  # Keep same rate limiting
                    '-c', '2',
                    '-v'  # Verbose output
                ]
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)
                
                # Monitor technology detection progress
                while True:
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break
                    if output and callback and '[' in output:
                        callback('progress', {'message': f"Technology detection: {output.strip()}"})
                
                # Process technology detection results
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        for line in f:
                            try:
                                result = json.loads(line)
                                tech = {
                                    'type': 'technology',
                                    'name': result.get('template-id', 'Unknown'),
                                    'details': result.get('info', {}).get('description', ''),
                                    'matched': result.get('matched-at', '')
                                }
                                
                                # Add to results and notify
                                self.results['attack_surface']['web'].append(tech)
                                tech_msg = f"Detected technology: {tech['name']} at {tech['matched']}"
                                if callback:
                                    callback('technology', tech)
                                    callback('progress', {'message': tech_msg})
                            except json.JSONDecodeError:
                                continue

                if callback:
                    callback('progress', {'message': 'Web vulnerability scanning completed'})

        except Exception as e:
            error_msg = f"Nuclei web scan error: {str(e)}"
            self.logger.error(error_msg)
            if callback:
                callback('progress', {'message': error_msg})

    def get_attack_recommendations(self) -> Dict:
        """Get recommended attack modules based on findings"""
        recommendations = {
            'modules': list(set(self.results['scan_info']['recommended_modules'])),
            'attack_surface': self.results['attack_surface']
        }
        return recommendations 