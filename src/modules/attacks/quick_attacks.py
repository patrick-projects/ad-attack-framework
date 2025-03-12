"""
Implementation of quick compromise attacks against Active Directory.
Provides automated checks and exploitation of common vulnerabilities like
Zerologon, MS17-010, Log4Shell, ProxyShell, and various service-specific attacks.
Uses netexec for initial enumeration and vulnerability detection.
"""

from typing import List, Dict, Optional, Callable
from .attack_base import AttackBase
import subprocess
import threading
import json
from datetime import datetime
import requests
from urllib.parse import urljoin
import socket

class QuickAttacks(AttackBase):
    def __init__(self):
        super().__init__()
        self.stop_attack = False
        self.attack_thread = None
        self.results = {
            'web_vulns': [],
            'service_vulns': [],
            'critical_vulns': []
        }
        
    def check_exchange(self, target: str, callback: Optional[Callable] = None) -> bool:
        """
        Check for Exchange vulnerabilities including ProxyShell
        
        Args:
            target: Target host/IP
            callback: Optional callback for real-time updates
        """
        self.stop_attack = False
        
        def scan_thread():
            try:
                # First use netexec to identify Exchange servers
                cmd = [
                    'netexec', 'ldap', target,
                    '--exchange',
                    '--json'
                ]
                
                self.log_status("Checking for Exchange servers...")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                exchange_servers = []
                while not self.stop_attack:
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break
                        
                    if output:
                        try:
                            result = json.loads(output)
                            if result.get('exchange'):
                                exchange_servers.append(result['host'])
                                if callback:
                                    callback('discovery', {
                                        'host': result['host'],
                                        'type': 'exchange_server'
                                    })
                        except json.JSONDecodeError:
                            pass
                            
                process.terminate()
                
                # Check each Exchange server for vulnerabilities
                for server in exchange_servers:
                    if self.stop_attack:
                        break
                        
                    # Check ProxyShell (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207)
                    self._check_proxyshell(server, callback)
                    
                    # Check CVE-2024-29855 (Veeam Recovery Orchestrator auth bypass)
                    self._check_veeam_vuln(server, callback)
                    
                # Log summary
                self.log_success(
                    f"Exchange checks complete:\n"
                    f"- Servers found: {len(exchange_servers)}\n"
                    f"- Vulnerabilities: {len(self.results['web_vulns'])}"
                )
                
            except Exception as e:
                self.log_error(f"Exchange check error: {str(e)}")
                if callback:
                    callback('error', {'error': str(e)})
                    
        self.attack_thread = threading.Thread(target=scan_thread)
        self.attack_thread.start()
        return True
        
    def check_web_services(self, target: str, callback: Optional[Callable] = None) -> bool:
        """
        Check for vulnerable web services (GLPI, Log4Shell, etc)
        
        Args:
            target: Target network/domain
            callback: Optional callback for real-time updates
        """
        self.stop_attack = False
        
        def scan_thread():
            try:
                # Use netexec to identify web services
                cmd = [
                    'netexec', 'http', target,
                    '--url-file', 'web_paths.txt',
                    '--json'
                ]
                
                self.log_status("Checking for vulnerable web services...")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                while not self.stop_attack:
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break
                        
                    if output:
                        try:
                            result = json.loads(output)
                            if result.get('http'):
                                self._check_web_vulns(result['host'], result['http'], callback)
                        except json.JSONDecodeError:
                            pass
                            
                process.terminate()
                
            except Exception as e:
                self.log_error(f"Web service check error: {str(e)}")
                if callback:
                    callback('error', {'error': str(e)})
                    
        self.attack_thread = threading.Thread(target=scan_thread)
        self.attack_thread.start()
        return True
        
    def check_critical_vulns(self, target: str, callback: Optional[Callable] = None) -> bool:
        """
        Check for critical vulnerabilities (Zerologon, MS17-010, etc)
        
        Args:
            target: Target network/domain
            callback: Optional callback for real-time updates
        """
        self.stop_attack = False
        
        def scan_thread():
            try:
                # Use netexec to identify potential targets
                cmd = [
                    'netexec', 'smb', target,
                    '--gen-relay-list',
                    '--zerologon',
                    '--ms17-010',
                    '--json'
                ]
                
                self.log_status("Checking for critical vulnerabilities...")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                while not self.stop_attack:
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break
                        
                    if output:
                        try:
                            result = json.loads(output)
                            
                            # Check Zerologon
                            if result.get('zerologon'):
                                vuln = {
                                    'host': result['host'],
                                    'type': 'zerologon',
                                    'description': 'Vulnerable to Zerologon (CVE-2020-1472)',
                                    'severity': 'Critical'
                                }
                                self.results['critical_vulns'].append(vuln)
                                if callback:
                                    callback('vulnerability', vuln)
                                    
                            # Check MS17-010
                            if result.get('ms17-010'):
                                vuln = {
                                    'host': result['host'],
                                    'type': 'ms17_010',
                                    'description': 'Vulnerable to EternalBlue (MS17-010)',
                                    'severity': 'Critical'
                                }
                                self.results['critical_vulns'].append(vuln)
                                if callback:
                                    callback('vulnerability', vuln)
                                    
                        except json.JSONDecodeError:
                            pass
                            
                process.terminate()
                
                # Log summary
                self.log_success(
                    f"Critical vulnerability checks complete:\n"
                    f"- Vulnerabilities found: {len(self.results['critical_vulns'])}"
                )
                
            except Exception as e:
                self.log_error(f"Critical vulnerability check error: {str(e)}")
                if callback:
                    callback('error', {'error': str(e)})
                    
        self.attack_thread = threading.Thread(target=scan_thread)
        self.attack_thread.start()
        return True
        
    def _check_proxyshell(self, server: str, callback: Optional[Callable] = None):
        """Check for ProxyShell vulnerabilities"""
        try:
            # Check for Autodiscover endpoint
            url = f"https://{server}/autodiscover/autodiscover.json"
            headers = {
                'User-Agent': 'Microsoft WinRM Client',
                'Content-Type': 'application/json'
            }
            
            try:
                response = requests.get(url, headers=headers, verify=False, timeout=5)
                if response.status_code == 401:  # Expected for ProxyShell
                    vuln = {
                        'host': server,
                        'type': 'proxyshell',
                        'description': 'Potentially vulnerable to ProxyShell',
                        'severity': 'Critical',
                        'url': url
                    }
                    self.results['web_vulns'].append(vuln)
                    if callback:
                        callback('vulnerability', vuln)
            except requests.exceptions.RequestException:
                pass
                
        except Exception as e:
            self.log_error(f"ProxyShell check error on {server}: {str(e)}")
            
    def _check_veeam_vuln(self, server: str, callback: Optional[Callable] = None):
        """Check for Veeam vulnerabilities"""
        try:
            # Check common Veeam ports
            ports = [9392, 9393]  # Common Veeam ports
            
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((server, port))
                    if result == 0:
                        vuln = {
                            'host': server,
                            'type': 'veeam',
                            'description': f'Potential Veeam service on port {port}',
                            'severity': 'High',
                            'port': port
                        }
                        self.results['service_vulns'].append(vuln)
                        if callback:
                            callback('vulnerability', vuln)
                except:
                    pass
                finally:
                    sock.close()
                    
        except Exception as e:
            self.log_error(f"Veeam check error on {server}: {str(e)}")
            
    def _check_web_vulns(self, host: str, http_info: dict, callback: Optional[Callable] = None):
        """Check for web service vulnerabilities"""
        try:
            headers = http_info.get('headers', {})
            server = headers.get('Server', '')
            
            # Check GLPI
            if 'glpi' in server.lower() or '/glpi/' in http_info.get('url', ''):
                vuln = {
                    'host': host,
                    'type': 'glpi',
                    'description': 'GLPI instance detected',
                    'severity': 'High',
                    'url': http_info.get('url')
                }
                self.results['web_vulns'].append(vuln)
                if callback:
                    callback('vulnerability', vuln)
                    
            # Check Log4Shell
            log4j_headers = {
                'X-Api-Version': '${jndi:ldap://test}',
                'User-Agent': '${jndi:ldap://test}'
            }
            
            try:
                response = requests.get(
                    http_info.get('url', ''),
                    headers=log4j_headers,
                    verify=False,
                    timeout=5
                )
                
                if 'java' in server.lower() or 'tomcat' in server.lower():
                    vuln = {
                        'host': host,
                        'type': 'log4shell',
                        'description': 'Potential Log4Shell vulnerability (Java-based server)',
                        'severity': 'Critical',
                        'url': http_info.get('url')
                    }
                    self.results['web_vulns'].append(vuln)
                    if callback:
                        callback('vulnerability', vuln)
            except requests.exceptions.RequestException:
                pass
                
        except Exception as e:
            self.log_error(f"Web vulnerability check error on {host}: {str(e)}")
            
    def check_mssql(self, target: str, callback: Optional[Callable] = None) -> bool:
        """
        Check for MSSQL vulnerabilities and trusted links
        
        Args:
            target: Target network/domain
            callback: Optional callback for real-time updates
        """
        self.stop_attack = False
        
        def scan_thread():
            try:
                # Use netexec to identify MSSQL servers
                cmd = [
                    'netexec', 'mssql', target,
                    '--get-trusted-links',
                    '--json'
                ]
                
                self.log_status("Checking for MSSQL servers and trusted links...")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                while not self.stop_attack:
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break
                        
                    if output:
                        try:
                            result = json.loads(output)
                            if result.get('mssql'):
                                # Check for trusted links
                                if result.get('trusted_links'):
                                    vuln = {
                                        'host': result['host'],
                                        'type': 'mssql_trusted_links',
                                        'description': f"MSSQL trusted links found: {', '.join(result['trusted_links'])}",
                                        'severity': 'High',
                                        'links': result['trusted_links']
                                    }
                                    self.results['service_vulns'].append(vuln)
                                    if callback:
                                        callback('vulnerability', vuln)
                        except json.JSONDecodeError:
                            pass
                            
                process.terminate()
                
            except Exception as e:
                self.log_error(f"MSSQL check error: {str(e)}")
                if callback:
                    callback('error', {'error': str(e)})
                    
        self.attack_thread = threading.Thread(target=scan_thread)
        self.attack_thread.start()
        return True
        
    def check_veeam(self, target: str, callback: Optional[Callable] = None) -> bool:
        """
        Check for Veeam vulnerabilities (CVE-2024-29855, CVE-2024-29849, CVE-2024-40711)
        
        Args:
            target: Target network/domain
            callback: Optional callback for real-time updates
        """
        self.stop_attack = False
        
        def scan_thread():
            try:
                # First use netexec to identify potential Veeam servers
                cmd = [
                    'netexec', 'smb', target,
                    '--shares',
                    '--json'
                ]
                
                self.log_status("Checking for Veeam servers...")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                veeam_servers = []
                while not self.stop_attack:
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break
                        
                    if output:
                        try:
                            result = json.loads(output)
                            # Look for Veeam shares or services
                            if any('veeam' in share.get('name', '').lower() for share in result.get('shares', [])):
                                veeam_servers.append(result['host'])
                                if callback:
                                    callback('discovery', {
                                        'host': result['host'],
                                        'type': 'veeam_server'
                                    })
                        except json.JSONDecodeError:
                            pass
                            
                process.terminate()
                
                # Check each Veeam server for vulnerabilities
                for server in veeam_servers:
                    if self.stop_attack:
                        break
                        
                    # Check CVE-2024-29855 (Veeam Recovery Orchestrator auth bypass)
                    self._check_veeam_orchestrator(server, callback)
                    
                    # Check CVE-2024-29849 (Veeam Backup Enterprise Manager auth bypass)
                    self._check_veeam_backup(server, callback)
                    
                    # Check CVE-2024-40711 (Veeam backup unserialize)
                    self._check_veeam_unserialize(server, callback)
                    
            except Exception as e:
                self.log_error(f"Veeam check error: {str(e)}")
                if callback:
                    callback('error', {'error': str(e)})
                    
        self.attack_thread = threading.Thread(target=scan_thread)
        self.attack_thread.start()
        return True
        
    def check_tomcat(self, target: str, callback: Optional[Callable] = None) -> bool:
        """
        Check for Tomcat/JBoss manager vulnerabilities
        
        Args:
            target: Target network/domain
            callback: Optional callback for real-time updates
        """
        self.stop_attack = False
        
        def scan_thread():
            try:
                # Use netexec to identify web servers
                cmd = [
                    'netexec', 'http', target,
                    '--url-file', 'web_paths.txt',
                    '--json'
                ]
                
                self.log_status("Checking for Tomcat/JBoss servers...")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                while not self.stop_attack:
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break
                        
                    if output:
                        try:
                            result = json.loads(output)
                            if result.get('http'):
                                headers = result['http'].get('headers', {})
                                server = headers.get('Server', '').lower()
                                
                                # Check for Tomcat/JBoss
                                if 'tomcat' in server or 'jboss' in server:
                                    # Check manager endpoints
                                    self._check_manager_endpoints(result['host'], result['http'].get('url', ''), callback)
                        except json.JSONDecodeError:
                            pass
                            
                process.terminate()
                
            except Exception as e:
                self.log_error(f"Tomcat/JBoss check error: {str(e)}")
                if callback:
                    callback('error', {'error': str(e)})
                    
        self.attack_thread = threading.Thread(target=scan_thread)
        self.attack_thread.start()
        return True
        
    def _check_veeam_orchestrator(self, server: str, callback: Optional[Callable] = None):
        """Check for Veeam Recovery Orchestrator auth bypass"""
        try:
            # Check common ports
            ports = [9898, 9393]
            
            for port in ports:
                url = f"https://{server}:{port}/"
                try:
                    response = requests.get(url, verify=False, timeout=5)
                    if 'Veeam' in response.text and 'Recovery Orchestrator' in response.text:
                        vuln = {
                            'host': server,
                            'type': 'veeam_orchestrator',
                            'description': 'Potential Veeam Recovery Orchestrator auth bypass (CVE-2024-29855)',
                            'severity': 'Critical',
                            'url': url
                        }
                        self.results['web_vulns'].append(vuln)
                        if callback:
                            callback('vulnerability', vuln)
                except requests.exceptions.RequestException:
                    pass
                    
        except Exception as e:
            self.log_error(f"Veeam Orchestrator check error on {server}: {str(e)}")
            
    def _check_veeam_backup(self, server: str, callback: Optional[Callable] = None):
        """Check for Veeam Backup Enterprise Manager auth bypass"""
        try:
            # Check common ports
            ports = [9392, 9393]
            
            for port in ports:
                url = f"https://{server}:{port}/"
                try:
                    response = requests.get(url, verify=False, timeout=5)
                    if 'Veeam' in response.text and 'Backup Enterprise Manager' in response.text:
                        vuln = {
                            'host': server,
                            'type': 'veeam_backup',
                            'description': 'Potential Veeam Backup Enterprise Manager auth bypass (CVE-2024-29849)',
                            'severity': 'Critical',
                            'url': url
                        }
                        self.results['web_vulns'].append(vuln)
                        if callback:
                            callback('vulnerability', vuln)
                except requests.exceptions.RequestException:
                    pass
                    
        except Exception as e:
            self.log_error(f"Veeam Backup check error on {server}: {str(e)}")
            
    def _check_veeam_unserialize(self, server: str, callback: Optional[Callable] = None):
        """Check for Veeam backup unserialize vulnerability"""
        try:
            # Check common ports
            ports = [9392, 9393]
            
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((server, port))
                    if result == 0:
                        vuln = {
                            'host': server,
                            'type': 'veeam_unserialize',
                            'description': 'Potential Veeam backup unserialize vulnerability (CVE-2024-40711)',
                            'severity': 'Critical',
                            'port': port
                        }
                        self.results['service_vulns'].append(vuln)
                        if callback:
                            callback('vulnerability', vuln)
                except:
                    pass
                finally:
                    sock.close()
                    
        except Exception as e:
            self.log_error(f"Veeam unserialize check error on {server}: {str(e)}")
            
    def _check_manager_endpoints(self, host: str, base_url: str, callback: Optional[Callable] = None):
        """Check for Tomcat/JBoss manager endpoints"""
        try:
            manager_paths = [
                '/manager/html',
                '/manager/status',
                '/jmx-console',
                '/web-console',
                '/admin-console'
            ]
            
            for path in manager_paths:
                url = urljoin(base_url, path)
                try:
                    response = requests.get(url, verify=False, timeout=5)
                    if response.status_code == 401:  # Auth required
                        vuln = {
                            'host': host,
                            'type': 'manager_endpoint',
                            'description': f'Found {path} endpoint requiring authentication',
                            'severity': 'High',
                            'url': url
                        }
                        self.results['web_vulns'].append(vuln)
                        if callback:
                            callback('vulnerability', vuln)
                except requests.exceptions.RequestException:
                    pass
                    
        except Exception as e:
            self.log_error(f"Manager endpoint check error on {host}: {str(e)}")
            
    def _check_java_rmi(self, host: str, callback: Optional[Callable] = None):
        """Check for Java RMI endpoints"""
        try:
            # Check common RMI ports
            ports = [1098, 1099, 4444, 8083]
            
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        vuln = {
                            'host': host,
                            'type': 'java_rmi',
                            'description': f'Found potential Java RMI endpoint on port {port}',
                            'severity': 'High',
                            'port': port
                        }
                        self.results['service_vulns'].append(vuln)
                        if callback:
                            callback('vulnerability', vuln)
                except:
                    pass
                finally:
                    sock.close()
                    
        except Exception as e:
            self.log_error(f"Java RMI check error on {host}: {str(e)}")
            
    def stop(self):
        """Stop any running quick attacks"""
        self.stop_attack = True
        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join()
            self.log_status("Quick attack stopped") 