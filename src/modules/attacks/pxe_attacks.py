"""
Implementation of PXE boot attacks against Active Directory environments.
Provides capabilities to discover PXE boot servers, analyze boot configurations,
and potentially capture or modify boot images. Uses netexec for initial discovery
and custom implementations for deeper analysis.
"""

from typing import List, Dict, Optional, Callable
from .attack_base import AttackBase
import subprocess
import socket
import threading
import time
from datetime import datetime

class PXEAttacks(AttackBase):
    def __init__(self):
        super().__init__()
        self.stop_scan = False
        self.scan_thread = None
        self.results = {
            'dhcp_servers': [],
            'tftp_servers': [],
            'boot_files': [],
            'vulnerabilities': []
        }
        
    def discover_pxe_servers(self, target: str, callback: Optional[Callable] = None) -> bool:
        """
        Discover PXE boot servers in the network using netexec and custom checks
        
        Args:
            target: Target network/domain
            callback: Optional callback for real-time updates
        """
        self.stop_scan = False
        self.results = {
            'dhcp_servers': [],
            'tftp_servers': [],
            'boot_files': [],
            'vulnerabilities': []
        }
        
        def scan_thread():
            try:
                # First use netexec to find potential servers
                cmd = [
                    'netexec', 'smb', target,
                    '--shares',
                    '--json'
                ]
                
                self.log_status("Searching for potential PXE servers...")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                while not self.stop_scan:
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break
                        
                    if output:
                        try:
                            result = json.loads(output)
                            # Look for REMINST, NETLOGON, SYSVOL shares
                            if 'shares' in result:
                                for share in result['shares']:
                                    share_name = share.get('name', '').upper()
                                    if share_name in ['REMINST', 'NETLOGON', 'SYSVOL']:
                                        server = {
                                            'ip': result.get('host'),
                                            'share': share_name,
                                            'type': 'potential_pxe_server'
                                        }
                                        self.results['dhcp_servers'].append(server)
                                        if callback:
                                            callback('discovery', server)
                                        
                        except json.JSONDecodeError:
                            pass
                            
                process.terminate()
                
                # Now check for TFTP servers
                for server in self.results['dhcp_servers']:
                    if self.stop_scan:
                        break
                        
                    ip = server['ip']
                    self.log_status(f"Checking for TFTP service on {ip}")
                    
                    # Check UDP 69 (TFTP)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(2)
                    
                    try:
                        # Send TFTP read request for common boot files
                        for file in ['pxelinux.0', 'boot.ini', 'bootmgr']:
                            if self.stop_scan:
                                break
                                
                            request = b'\x00\x01' + file.encode() + b'\x00' + b'octet\x00'
                            sock.sendto(request, (ip, 69))
                            
                            try:
                                data, _ = sock.recvfrom(512)
                                if data:
                                    tftp_server = {
                                        'ip': ip,
                                        'file': file,
                                        'type': 'tftp_server'
                                    }
                                    self.results['tftp_servers'].append(tftp_server)
                                    if callback:
                                        callback('discovery', tftp_server)
                                    
                                    # Try to analyze boot files
                                    self._analyze_boot_file(ip, file, callback)
                            except socket.timeout:
                                pass
                                
                    except Exception as e:
                        self.log_error(f"Error checking TFTP on {ip}: {str(e)}")
                    finally:
                        sock.close()
                        
                # Check for common vulnerabilities
                self._check_vulnerabilities(callback)
                
                # Log summary
                self.log_success(
                    f"PXE server discovery complete:\n"
                    f"- DHCP/PXE Servers: {len(self.results['dhcp_servers'])}\n"
                    f"- TFTP Servers: {len(self.results['tftp_servers'])}\n"
                    f"- Boot Files: {len(self.results['boot_files'])}\n"
                    f"- Vulnerabilities: {len(self.results['vulnerabilities'])}"
                )
                
            except Exception as e:
                self.log_error(f"PXE server discovery error: {str(e)}")
                if callback:
                    callback('error', {'error': str(e)})
                    
        self.scan_thread = threading.Thread(target=scan_thread)
        self.scan_thread.start()
        return True
        
    def _analyze_boot_file(self, ip: str, filename: str, callback: Optional[Callable] = None):
        """Analyze discovered boot files for configurations and vulnerabilities"""
        try:
            # Create TFTP client to download file
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            request = b'\x00\x01' + filename.encode() + b'\x00' + b'octet\x00'
            sock.sendto(request, (ip, 69))
            
            # Receive file data
            file_data = b''
            block_number = 1
            
            while True:
                try:
                    data, _ = sock.recvfrom(516)
                    opcode = int.from_bytes(data[0:2], 'big')
                    
                    if opcode == 3:  # Data packet
                        file_data += data[4:]
                        # Send ACK
                        ack = b'\x00\x04' + block_number.to_bytes(2, 'big')
                        sock.sendto(ack, (ip, 69))
                        block_number += 1
                        
                        if len(data) < 516:  # Last packet
                            break
                    elif opcode == 5:  # Error
                        break
                except socket.timeout:
                    break
                    
            if file_data:
                # Analyze the boot file
                boot_file = {
                    'ip': ip,
                    'filename': filename,
                    'size': len(file_data),
                    'type': 'boot_file',
                    'timestamp': datetime.now().isoformat()
                }
                
                # Look for interesting configurations
                try:
                    text_data = file_data.decode('utf-8', errors='ignore')
                    if 'DEFAULT' in text_data:
                        boot_file['has_default_config'] = True
                    if 'TIMEOUT' in text_data:
                        boot_file['has_timeout'] = True
                    if 'MENU' in text_data:
                        boot_file['has_menu'] = True
                    if 'USERNAME' in text_data or 'PASSWORD' in text_data:
                        boot_file['has_credentials'] = True
                        
                except:
                    pass
                    
                self.results['boot_files'].append(boot_file)
                if callback:
                    callback('analysis', boot_file)
                    
                # Save to database
                self.db.add_pxe_file(
                    ip=ip,
                    filename=filename,
                    data=file_data,
                    metadata=boot_file
                )
                
        except Exception as e:
            self.log_error(f"Error analyzing boot file {filename} from {ip}: {str(e)}")
        finally:
            sock.close()
            
    def _check_vulnerabilities(self, callback: Optional[Callable] = None):
        """Check for common PXE boot vulnerabilities"""
        for server in self.results['tftp_servers']:
            ip = server['ip']
            
            # Check for unauthenticated access
            if self._check_anonymous_tftp(ip):
                vuln = {
                    'ip': ip,
                    'type': 'vulnerability',
                    'name': 'anonymous_tftp',
                    'description': 'TFTP server allows anonymous access',
                    'severity': 'High'
                }
                self.results['vulnerabilities'].append(vuln)
                if callback:
                    callback('vulnerability', vuln)
                    
            # Check for unencrypted credentials in boot files
            for boot_file in self.results['boot_files']:
                if boot_file['ip'] == ip and boot_file.get('has_credentials'):
                    vuln = {
                        'ip': ip,
                        'type': 'vulnerability',
                        'name': 'plaintext_credentials',
                        'description': f"Boot file {boot_file['filename']} contains plaintext credentials",
                        'severity': 'High'
                    }
                    self.results['vulnerabilities'].append(vuln)
                    if callback:
                        callback('vulnerability', vuln)
                        
    def _check_anonymous_tftp(self, ip: str) -> bool:
        """Check if TFTP server allows anonymous access"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            # Try to read a non-existent file
            request = b'\x00\x01' + b'test123.txt\x00' + b'octet\x00'
            sock.sendto(request, (ip, 69))
            
            try:
                data, _ = sock.recvfrom(512)
                # If we get an error about file not found (rather than access denied)
                # server likely allows anonymous access
                if data[0:2] == b'\x00\x05' and b'File not found' in data:
                    return True
            except socket.timeout:
                pass
                
            return False
            
        except Exception:
            return False
        finally:
            sock.close()
            
    def stop(self):
        """Stop any running PXE scans"""
        self.stop_scan = True
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join()
            self.log_status("PXE scan stopped") 