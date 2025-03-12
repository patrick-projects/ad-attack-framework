"""
Base Valid Users Attack Module

This module defines the base class for attacks that use valid usernames but no passwords.
These attacks focus on techniques like:
- Password spraying
- AS-REP Roasting
- Password policy enumeration
- Account lockout testing
"""

from typing import Dict, List
from ..base_attack import BaseAttack

class BaseValidUsersAttack(BaseAttack):
    """Base class for attacks using valid usernames"""
    
    @property
    def attack_type(self) -> str:
        return "valid_users"
    
    @property
    def prerequisites(self) -> List[str]:
        return [
            "List of valid usernames",
            "Network access to target",
            "Target service must be accessible"
        ]
        
    def check_prerequisites(self, target: str) -> bool:
        """
        Check if prerequisites are met
        
        Args:
            target: Target to check
            
        Returns:
            bool: True if prerequisites are met
        """
        try:
            # Basic connectivity check
            result = self.run_cmd(['ping', '-c', '1', '-W', '1', target], silent=True)
            return result.returncode == 0
        except:
            return False 