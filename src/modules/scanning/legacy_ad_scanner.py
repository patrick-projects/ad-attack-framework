import logging
from typing import List, Dict, Optional
import nmap
import ldap3
from impacket.dcerpc.v5 import transport, samr
from impacket.smbconnection import SMBConnection
from config.config import ScanConfig, ADConfig

class ADScanner:
    def __init__(self, config: ADConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._nm = nmap.PortScanner()
        
    def scan_network(self, target_subnet: str) -> Dict:
        """
        Perform initial network scan to identify AD infrastructure
        """
        try:
            ports = ",".join(map(str, ScanConfig.PORTS_TO_SCAN))
            self._nm.scan(
                hosts=target_subnet,
                arguments=f"-sS -n -Pn -p{ports} --open"
            )
            return self._nm.all_hosts()
        except Exception as e:
            self.logger.error(f"Network scan failed: {str(e)}")
            return {}

    def enumerate_ldap(self) -> Dict:
        """
        Enumerate LDAP to gather AD information
        """
        results = {
            "users": [],
            "groups": [],
            "computers": [],
            "ou": []
        }
        
        try:
            server = ldap3.Server(
                self.config.dc_ip,
                get_info=ldap3.ALL,
                use_ssl=False
            )
            
            conn = ldap3.Connection(
                server,
                user=f"{self.config.username}@{self.config.target_domain}",
                password=self.config.password,
                authentication=ldap3.NTLM
            )
            
            if not conn.bind():
                self.logger.error("LDAP bind failed")
                return results
                
            # Enumerate Users
            conn.search(
                self.config.target_domain,
                "(&(objectClass=user)(objectCategory=person))",
                attributes=["sAMAccountName", "userPrincipalName", "memberOf"]
            )
            results["users"] = conn.entries
            
            # Enumerate Groups
            conn.search(
                self.config.target_domain,
                "(objectClass=group)",
                attributes=["cn", "member"]
            )
            results["groups"] = conn.entries
            
            # Enumerate Computers
            conn.search(
                self.config.target_domain,
                "(objectClass=computer)",
                attributes=["dNSHostName", "operatingSystem"]
            )
            results["computers"] = conn.entries
            
            return results
            
        except Exception as e:
            self.logger.error(f"LDAP enumeration failed: {str(e)}")
            return results

    def check_smb_signing(self, target_ip: str) -> bool:
        """
        Check if SMB signing is enforced
        """
        try:
            smb = SMBConnection(target_ip, target_ip)
            smb.login("", "")
            return smb.isSigningRequired()
        except Exception as e:
            self.logger.error(f"SMB signing check failed: {str(e)}")
            return False

    def enumerate_null_sessions(self, target_ip: str) -> List[str]:
        """
        Attempt to enumerate information via null sessions
        """
        results = []
        try:
            rpctransport = transport.SMBTransport(
                target_ip,
                445,
                r"\samr",
                username="",
                password=""
            )
            
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            
            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]
            
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]
            
            for domain in domains:
                results.append(domain["Name"])
                
            return results
            
        except Exception as e:
            self.logger.error(f"Null session enumeration failed: {str(e)}")
            return results

    def check_kerberos_configuration(self) -> Dict:
        """
        Check Kerberos configuration and potential misconfigurations
        """
        results = {
            "pre_auth_not_required": [],
            "delegation_configured": [],
            "spn_configured": []
        }
        
        # Implementation would include checks for:
        # - Users with Kerberos pre-authentication disabled
        # - Users/computers with unconstrained delegation
        # - Service Principal Names (SPNs)
        
        return results 