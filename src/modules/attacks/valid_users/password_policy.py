"""
Password Policy Enumeration Module

Enumerates password policies and tracks authentication attempts to prevent lockouts:
- Gets password policy from DC (lockout threshold, duration, etc.)
- Tracks authentication attempts per user in SQLite database
- Provides safe thresholds for password spraying
"""

from typing import Dict, List, Optional, Callable
from .base_valid_users import BaseValidUsersAttack
import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path

class PasswordPolicy(BaseValidUsersAttack):
    """Implementation of password policy enumeration and attempt tracking"""
    
    def __init__(self):
        super().__init__()
        self.db_path = Path.home() / '.pentest' / 'auth_attempts.db'
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    @property
    def required_tools(self) -> Dict[str, str]:
        return {
            'nxc': 'netexec',  # For policy enumeration
            'ldapsearch': 'ldap-utils'  # Backup method
        }
    
    def _init_db(self) -> None:
        """Initialize SQLite database for tracking attempts"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS auth_attempts (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                username TEXT NOT NULL,
                source TEXT NOT NULL,
                success INTEGER DEFAULT 0
            )''')
            
            conn.execute('''CREATE TABLE IF NOT EXISTS password_policies (
                id INTEGER PRIMARY KEY,
                target TEXT UNIQUE NOT NULL,
                policy TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )''')
    
    def _run_attack(self, target: str, options: Optional[Dict] = None,
                    callback: Optional[Callable] = None) -> bool:
        """
        Enumerate password policy
        
        Args:
            target: Target to enumerate
            options: Optional configuration
            callback: Optional callback for progress updates
            
        Returns:
            bool: True if policy was found
        """
        try:
            if callback:
                callback('progress', {'message': 'Enumerating password policy...'})
            
            # Try to get policy with nxc first
            policy = self._get_policy_nxc(target)
            
            # Fallback to LDAP if nxc fails
            if not policy:
                policy = self._get_policy_ldap(target)
            
            if policy:
                # Store policy in database
                self._save_policy(target, policy)
                
                # Add as finding
                self.add_finding({
                    'type': 'password_policy',
                    'description': 'Password policy enumerated',
                    'details': policy
                })
                
                if callback:
                    callback('progress', {
                        'message': 'Password policy found',
                        'policy': policy
                    })
                
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Policy enumeration error: {str(e)}")
            return False
    
    def _get_policy_nxc(self, target: str) -> Optional[Dict]:
        """Get password policy using NetExec"""
        try:
            cmd = ['nxc', 'smb', target, '--pass-pol']
            result = self.run_cmd(cmd, silent=True)
            
            policy = {}
            
            for line in result.stdout.splitlines():
                if 'Minimum password length:' in line:
                    policy['min_length'] = int(line.split(':')[1].strip())
                elif 'Account lockout threshold:' in line:
                    policy['lockout_threshold'] = int(line.split(':')[1].strip())
                elif 'Account lockout duration:' in line:
                    policy['lockout_duration'] = int(line.split(':')[1].strip())
                elif 'Reset account lockout after:' in line:
                    policy['lockout_reset'] = int(line.split(':')[1].strip())
                elif 'Password complexity:' in line:
                    policy['complexity'] = line.split(':')[1].strip().lower() == 'enabled'
            
            return policy if policy else None
            
        except Exception as e:
            self.logger.error(f"NetExec policy error: {str(e)}")
            return None
    
    def _get_policy_ldap(self, target: str) -> Optional[Dict]:
        """Get password policy using LDAP"""
        try:
            cmd = [
                'ldapsearch', '-x', '-h', target,
                '-b', 'DC=domain,DC=local',  # Base DN (needs to be adjusted)
                '(objectClass=domainDNS)',
                'pwdProperties', 'pwdHistoryLength',
                'lockoutThreshold', 'lockoutDuration'
            ]
            result = self.run_cmd(cmd, silent=True)
            
            policy = {}
            
            for line in result.stdout.splitlines():
                if 'pwdProperties:' in line:
                    props = int(line.split(':')[1].strip())
                    policy['complexity'] = bool(props & 1)
                elif 'pwdHistoryLength:' in line:
                    policy['history_length'] = int(line.split(':')[1].strip())
                elif 'lockoutThreshold:' in line:
                    policy['lockout_threshold'] = int(line.split(':')[1].strip())
                elif 'lockoutDuration:' in line:
                    # Convert from 100-nanosecond intervals to minutes
                    duration = int(line.split(':')[1].strip())
                    policy['lockout_duration'] = duration // 600000000
            
            return policy if policy else None
            
        except Exception as e:
            self.logger.error(f"LDAP policy error: {str(e)}")
            return None
    
    def _save_policy(self, target: str, policy: Dict) -> None:
        """Save password policy to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''INSERT OR REPLACE INTO password_policies 
                (target, policy, timestamp) VALUES (?, ?, ?)''',
                (target, json.dumps(policy), datetime.now().isoformat()))
    
    def get_policy(self, target: str) -> Optional[Dict]:
        """Get stored password policy for target"""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                'SELECT policy FROM password_policies WHERE target = ?',
                (target,)
            ).fetchone()
            
            if row:
                return json.loads(row[0])
        return None
    
    def add_attempt(self, target: str, username: str, source: str,
                   success: bool = False) -> None:
        """Record an authentication attempt"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''INSERT INTO auth_attempts
                (timestamp, target, username, source, success)
                VALUES (?, ?, ?, ?, ?)''',
                (datetime.now().isoformat(), target, username,
                 source, 1 if success else 0))
    
    def get_recent_attempts(self, target: str, username: str,
                          minutes: int = 30) -> int:
        """Get number of recent auth attempts for user"""
        with sqlite3.connect(self.db_path) as conn:
            cutoff = (datetime.now() - timedelta(minutes=minutes)).isoformat()
            
            count = conn.execute('''SELECT COUNT(*) FROM auth_attempts
                WHERE target = ? AND username = ? AND timestamp > ?''',
                (target, username, cutoff)).fetchone()[0]
            
            return count
    
    def is_safe_to_spray(self, target: str, username: str) -> bool:
        """Check if it's safe to attempt auth for user"""
        policy = self.get_policy(target)
        if not policy:
            # If no policy found, be conservative
            return self.get_recent_attempts(target, username) < 3
            
        threshold = policy.get('lockout_threshold', 3)
        if threshold == 0:  # No lockout
            return True
            
        # Leave buffer of 2 attempts before lockout
        safe_threshold = max(1, threshold - 2)
        
        # Check attempts within lockout reset window
        window = policy.get('lockout_reset', 30)  # Default 30 minutes
        attempts = self.get_recent_attempts(target, username, minutes=window)
        
        return attempts < safe_threshold 