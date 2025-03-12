"""
Network scanning module that uses nmap and netexec for comprehensive enumeration.
Includes vulnerability scanning using nmap-vulners script for identifying high and critical vulnerabilities.
"""

from typing import Optional, Callable, Dict, List
import subprocess
import json
import xml.etree.ElementTree as ET
from datetime import datetime
import threading
import re

class NetworkScanner:
    def __init__(self):
        self.stop_scan = False
        self.scan_thread = None
        self.results = {
            'hosts': [],
            'services': [],
            'vulnerabilities': []
        }
        
    def scan_network(self, target: str, callback: Optional[Callable] = None) -> bool:
        """
        Perform comprehensive network scan using nmap and netexec
        
        Args:
            target: Target network/domain
            callback: Optional callback for real-time updates
        """
        self.stop_scan = False
        
        def scan_thread():
            try:
                # First run nmap with service detection and vulners script
                self.log_status("Starting nmap vulnerability scan...")
                
                # Create temporary files for output
                nmap_xml = "nmap_scan.xml"
                
                # Run nmap scan with service detection and vulners script
                cmd = [
                    'nmap', '-sV', '--script', 'vulners',
                    '-oX', nmap_xml,
                    target
                ]
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                while not self.stop_scan:
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break
                        
                    if output:
                        if callback:
                            callback('progress', {'message': output.decode().strip()})
                            
                process.terminate()
                
                # Parse nmap results
                self._parse_nmap_results(nmap_xml, callback)
                
                # Now use netexec for additional enumeration
                self._run_netexec_scan(target, callback)
                
                # Log summary
                self.log_success(
                    f"Network scan complete:\n"
                    f"- Hosts found: {len(self.results['hosts'])}\n"
                    f"- Services: {len(self.results['services'])}\n"
                    f"- Vulnerabilities: {len(self.results['vulnerabilities'])}"
                )
                
            except Exception as e:
                self.log_error(f"Network scan error: {str(e)}")
                if callback:
                    callback('error', {'error': str(e)})
                    
        self.scan_thread = threading.Thread(target=scan_thread)
        self.scan_thread.start()
        return True
        
    def _parse_nmap_results(self, xml_file: str, callback: Optional[Callable] = None):
        """Parse nmap XML output and extract vulnerabilities"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('.//host'):
                # Get host info
                addr = host.find('.//address').get('addr')
                hostname = host.find('.//hostname')
                hostname = hostname.get('name') if hostname is not None else None
                
                # Add to hosts list
                host_info = {
                    'ip': addr,
                    'hostname': hostname,
                    'timestamp': datetime.now().isoformat()
                }
                self.results['hosts'].append(host_info)
                
                if callback:
                    callback('discovery', {
                        'host': addr,
                        'type': 'host',
                        'hostname': hostname
                    })
                    
                # Process each port
                for port in host.findall('.//port'):
                    if port.get('state') == 'open':
                        port_id = port.get('portid')
                        service = port.find('.//service')
                        if service is not None:
                            service_name = service.get('name')
                            product = service.get('product', '')
                            version = service.get('version', '')
                            
                            # Add to services list
                            service_info = {
                                'host': addr,
                                'port': port_id,
                                'service': service_name,
                                'product': product,
                                'version': version,
                                'timestamp': datetime.now().isoformat()
                            }
                            self.results['services'].append(service_info)
                            
                            if callback:
                                callback('discovery', {
                                    'host': addr,
                                    'type': 'service',
                                    'service': service_name,
                                    'port': port_id
                                })
                                
                            # Check for vulnerabilities
                            script = port.find('.//script[@id="vulners"]')
                            if script is not None:
                                vulners_output = script.get('output')
                                self._parse_vulners_output(addr, port_id, service_name, vulners_output, callback)
                                
        except Exception as e:
            self.log_error(f"Error parsing nmap results: {str(e)}")
            
    def _parse_vulners_output(self, host: str, port: str, service: str, output: str, callback: Optional[Callable] = None):
        """Parse vulners script output and extract high/critical vulnerabilities"""
        try:
            # Regular expression to match CVE lines with CVSS scores
            cve_pattern = r'(CVE-\d{4}-\d+)\s+(\d+\.\d+)\s+(.+)'
            
            for line in output.split('\n'):
                match = re.search(cve_pattern, line)
                if match:
                    cve_id = match.group(1)
                    cvss_score = float(match.group(2))
                    description = match.group(3).strip()
                    
                    # Only process high (>= 7.0) and critical (>= 9.0) vulnerabilities
                    if cvss_score >= 7.0:
                        severity = 'Critical' if cvss_score >= 9.0 else 'High'
                        
                        vuln = {
                            'host': host,
                            'port': port,
                            'service': service,
                            'type': 'cve',
                            'cve_id': cve_id,
                            'cvss_score': cvss_score,
                            'severity': severity,
                            'description': description,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        self.results['vulnerabilities'].append(vuln)
                        
                        if callback:
                            callback('vulnerability', vuln)
                            
        except Exception as e:
            self.log_error(f"Error parsing vulners output: {str(e)}")
            
    def _run_netexec_scan(self, target: str, callback: Optional[Callable] = None):
        """Run additional enumeration using netexec"""
        try:
            # Run SMB scan
            cmd = [
                'netexec', 'smb', target,
                '--shares',
                '--users',
                '--groups',
                '--loggedon-users',
                '--sessions',
                '--json'
            ]
            
            self.log_status("Starting netexec SMB enumeration...")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            while not self.stop_scan:
                output = process.stdout.readline()
                if not output and process.poll() is not None:
                    break
                    
                if output:
                    try:
                        result = json.loads(output)
                        if callback:
                            if result.get('shares'):
                                callback('discovery', {
                                    'host': result['host'],
                                    'type': 'shares',
                                    'shares': result['shares']
                                })
                            if result.get('users'):
                                callback('discovery', {
                                    'host': result['host'],
                                    'type': 'users',
                                    'users': result['users']
                                })
                    except json.JSONDecodeError:
                        pass
                        
            process.terminate()
            
            # Run LDAP scan
            cmd = [
                'netexec', 'ldap', target,
                '--trusted-for-delegation',
                '--password-not-required',
                '--admin-count',
                '--json'
            ]
            
            self.log_status("Starting netexec LDAP enumeration...")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            while not self.stop_scan:
                output = process.stdout.readline()
                if not output and process.poll() is not None:
                    break
                    
                if output:
                    try:
                        result = json.loads(output)
                        if callback:
                            if result.get('delegation'):
                                callback('discovery', {
                                    'host': result['host'],
                                    'type': 'delegation',
                                    'accounts': result['delegation']
                                })
                            if result.get('password_not_required'):
                                callback('discovery', {
                                    'host': result['host'],
                                    'type': 'no_password',
                                    'accounts': result['password_not_required']
                                })
                    except json.JSONDecodeError:
                        pass
                        
            process.terminate()
            
        except Exception as e:
            self.log_error(f"Netexec scan error: {str(e)}")
            
    def log_status(self, message: str):
        """Log status message"""
        print(f"[*] {message}")
        
    def log_success(self, message: str):
        """Log success message"""
        print(f"[+] {message}")
        
    def log_error(self, message: str):
        """Log error message"""
        print(f"[-] {message}")
        
    def stop(self):
        """Stop any running scans"""
        self.stop_scan = True
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join()
            self.log_status("Scan stopped") 