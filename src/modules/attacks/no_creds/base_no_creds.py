"""
Base No Credentials Attack Module

This module defines the base class for all no-credentials attack modules.
These attacks focus on techniques that don't require any prior credentials:
- Network enumeration
- Service discovery
- Quick wins (e.g., EternalBlue, Zerologon)
- Time-based attacks
"""

from typing import Dict, List
from ..base_attack import BaseAttack

class BaseNoCredsAttack(BaseAttack):
    """Base class for no-credentials attacks"""
    
    @property
    def attack_type(self) -> str:
        return "no_creds"
    
    @property
    def prerequisites(self) -> List[str]:
        return [
            "Network access to target",
            "No credentials required",
            "Target services must be accessible"
        ]
        
    def check_prerequisites(self, target: str) -> bool:
        """
        Check if target is accessible
        
        Args:
            target: Target to check
            
        Returns:
            bool: True if target is accessible
        """
        try:
            # Basic connectivity check
            result = self.run_cmd(['ping', '-c', '1', '-W', '1', target], silent=True)
            return result.returncode == 0
        except:
            return False 