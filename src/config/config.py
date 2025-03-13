"""
Configuration module for AD Attack Framework
"""

import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class LoggingConfig:
    """Logging configuration"""
    log_dir: str = "logs"
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    log_file: str = "ad_attack.log"

@dataclass
class ADConfig:
    """Active Directory configuration"""
    domain: Optional[str] = None
    dc_ip: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    hash: Optional[str] = None
    use_kerberos: bool = False
    use_ntlm: bool = True
    timeout: int = 30
    verbose: bool = False

    def __post_init__(self):
        # Create log directory if it doesn't exist
        os.makedirs("logs", exist_ok=True) 