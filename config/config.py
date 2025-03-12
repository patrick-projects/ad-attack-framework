from dataclasses import dataclass
from typing import List, Optional

@dataclass
class ADConfig:
    target_domain: str = ""
    dc_ip: str = ""
    username: str = ""
    password: str = ""
    domain_admin_groups: List[str] = None
    laps_enabled: bool = False
    kerberos_enabled: bool = True
    smb_signing_required: bool = True

    def __post_init__(self):
        if self.domain_admin_groups is None:
            self.domain_admin_groups = [
                "Domain Admins",
                "Enterprise Admins",
                "Administrators"
            ]

class ScanConfig:
    PORTS_TO_SCAN = [
        53,    # DNS
        88,    # Kerberos
        135,   # RPC
        139,   # NetBIOS
        389,   # LDAP
        445,   # SMB
        464,   # Kerberos Password Change
        636,   # LDAPS
        3268,  # Global Catalog
        3269,  # Global Catalog SSL
        5985,  # WinRM HTTP
        5986   # WinRM HTTPS
    ]

    TIMEOUT = 30
    THREADS = 10
    
class AttackConfig:
    KERBEROAST_THRESHOLD = 1000  # Maximum number of service accounts to target
    MAX_PASSWORD_ATTEMPTS = 3
    SPRAY_DELAY = 30  # Seconds between password spray attempts
    BLOODHOUND_COLLECTORS = [
        "Group",
        "LocalAdmin",
        "Session",
        "LoggedOn",
        "Trusts",
        "ACL",
        "Container",
        "RDP",
        "DCOM",
        "PSRemote"
    ]

class LoggingConfig:
    LOG_LEVEL = "INFO"
    LOG_FILE = "ad_pentest.log"
    REPORT_DIRECTORY = "reports"
    EVIDENCE_DIRECTORY = "evidence" 