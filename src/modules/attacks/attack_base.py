"""
Base class for all attack modules providing common functionality.
Implements logging, real-time feedback through callbacks, and credential tracking.
All attack modules inherit from this class to ensure consistent behavior and logging.
"""

from typing import Dict, List, Callable, Optional
import logging
from ...database.db_manager import DatabaseManager

class AttackBase:
    """Base class for all attacks"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.logger = logging.getLogger(__name__)
        self.callback = None
        
    def set_callback(self, callback: Callable[[str, Dict], None]):
        """Set callback for real-time updates"""
        self.callback = callback
        
    def notify(self, event_type: str, data: Dict):
        """Send notification through callback if set"""
        if self.callback:
            self.callback(event_type, data)
            
    def log_success(self, message: str):
        """Log success message"""
        self.logger.info(message)
        self.notify("success", {"message": message})
        
    def log_error(self, message: str):
        """Log error message"""
        self.logger.error(message)
        self.notify("error", {"message": message})
        
    def log_status(self, message: str):
        """Log status update"""
        self.logger.info(message)
        self.notify("status", {"message": message})
        
    def log_credential(self, username: str, domain: str, password: str = None, hash: str = None, ticket: str = None):
        """Log discovered credential"""
        cred_type = "password" if password else "hash" if hash else "ticket"
        value = password or hash or ticket
        
        self.notify("credential", {
            "username": username,
            "domain": domain,
            "type": cred_type,
            "value": value
        })
        
        # Save to database
        self.db.save_credential(username, domain, cred_type, value) 