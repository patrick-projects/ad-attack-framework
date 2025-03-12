import sqlite3
from datetime import datetime
from pathlib import Path
import json
from typing import Optional, List, Dict

class DatabaseManager:
    def __init__(self, db_path="scan_results.db"):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create tables for different scan results
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS live_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                hostname TEXT,
                scan_date TIMESTAMP,
                is_dc BOOLEAN DEFAULT 0
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS smb_shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_ip TEXT NOT NULL,
                share_name TEXT NOT NULL,
                access_type TEXT,
                scan_date TIMESTAMP,
                additional_info TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ldap_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dc_ip TEXT NOT NULL,
                result_type TEXT NOT NULL,
                data TEXT,
                scan_date TIMESTAMP
            )
        ''')

        # New tables for additional features
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_policy (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                min_length INTEGER,
                complexity_enabled BOOLEAN,
                history_length INTEGER,
                lockout_threshold INTEGER,
                lockout_duration INTEGER,
                scan_date TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS discovered_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                domain TEXT NOT NULL,
                source TEXT,
                additional_info TEXT,
                scan_date TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS asrep_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                domain TEXT NOT NULL,
                hash TEXT,
                scan_date TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS service_scan (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT,
                version TEXT,
                additional_info TEXT,
                scan_date TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                port INTEGER,
                service TEXT,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                cve_id TEXT,
                cvss_score REAL,
                metadata TEXT,
                timestamp TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS nmap_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service TEXT,
                product TEXT,
                version TEXT,
                script_id TEXT,
                script_output TEXT,
                timestamp TIMESTAMP
            )
        ''')

        conn.commit()
        conn.close()

    def save_live_host(self, ip_address: str, hostname: str = None, is_dc: bool = False):
        """Save discovered live host"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO live_hosts (ip_address, hostname, scan_date, is_dc)
            VALUES (?, ?, ?, ?)
        ''', (ip_address, hostname, datetime.now(), is_dc))
        
        conn.commit()
        conn.close()

    def save_smb_share(self, host_ip: str, share_name: str, access_type: str, additional_info: dict = None):
        """Save discovered SMB share"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO smb_shares (host_ip, share_name, access_type, scan_date, additional_info)
            VALUES (?, ?, ?, ?, ?)
        ''', (host_ip, share_name, access_type, datetime.now(), 
              json.dumps(additional_info) if additional_info else None))
        
        conn.commit()
        conn.close()

    def save_ldap_result(self, dc_ip: str, result_type: str, data: dict):
        """Save LDAP enumeration result"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO ldap_results (dc_ip, result_type, data, scan_date)
            VALUES (?, ?, ?, ?)
        ''', (dc_ip, result_type, json.dumps(data), datetime.now()))
        
        conn.commit()
        conn.close()

    def get_dc_ip(self) -> str:
        """Get the most recently discovered DC IP"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ip_address FROM live_hosts 
            WHERE is_dc = 1 
            ORDER BY scan_date DESC 
            LIMIT 1
        ''')
        
        result = cursor.fetchone()
        conn.close()
        
        return result[0] if result else None

    def get_live_hosts(self) -> list:
        """Get all discovered live hosts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT ip_address, hostname, is_dc FROM live_hosts')
        results = cursor.fetchall()
        
        conn.close()
        return results

    def get_smb_shares(self, host_ip: str = None) -> list:
        """Get discovered SMB shares, optionally filtered by host"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if host_ip:
            cursor.execute('''
                SELECT host_ip, share_name, access_type, additional_info 
                FROM smb_shares WHERE host_ip = ?
            ''', (host_ip,))
        else:
            cursor.execute('''
                SELECT host_ip, share_name, access_type, additional_info 
                FROM smb_shares
            ''')
            
        results = cursor.fetchall()
        conn.close()
        return results 

    def add_vulnerability(self, host: str, port: Optional[int], service: Optional[str],
                         vuln_type: str, severity: str, description: str,
                         cve_id: Optional[str] = None, cvss_score: Optional[float] = None,
                         metadata: Optional[dict] = None) -> bool:
        """
        Add a vulnerability to the database
        
        Args:
            host: Target host
            port: Optional port number
            service: Optional service name
            vuln_type: Type of vulnerability (e.g., 'cve', 'misconfiguration')
            severity: Severity level ('Critical', 'High', etc)
            description: Description of the vulnerability
            cve_id: Optional CVE ID
            cvss_score: Optional CVSS score
            metadata: Optional additional data as dict
        """
        try:
            metadata_json = json.dumps(metadata) if metadata else None
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO vulnerabilities (
                    host, port, service, type, severity, description,
                    cve_id, cvss_score, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                host, port, service, vuln_type, severity, description,
                cve_id, cvss_score, metadata_json
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error adding vulnerability: {str(e)}")
            return False
        
    def add_nmap_result(self, host: str, port: int, protocol: str,
                        service: Optional[str] = None, product: Optional[str] = None,
                        version: Optional[str] = None, script_id: Optional[str] = None,
                        script_output: Optional[str] = None) -> bool:
        """
        Add nmap scan result to the database
        
        Args:
            host: Target host
            port: Port number
            protocol: Protocol (tcp/udp)
            service: Optional service name
            product: Optional product name
            version: Optional version string
            script_id: Optional NSE script ID
            script_output: Optional NSE script output
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO nmap_scans (
                    host, port, protocol, service, product,
                    version, script_id, script_output
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                host, port, protocol, service, product,
                version, script_id, script_output
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error adding nmap result: {str(e)}")
            return False
        
    def get_vulnerabilities(self, severity: Optional[str] = None,
                           vuln_type: Optional[str] = None,
                           host: Optional[str] = None) -> List[Dict]:
        """
        Get vulnerabilities from the database
        
        Args:
            severity: Optional severity filter
            vuln_type: Optional type filter
            host: Optional host filter
            
        Returns:
            List of vulnerability dictionaries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = "SELECT * FROM vulnerabilities WHERE 1=1"
            params = []
            
            if severity:
                query += " AND severity = ?"
                params.append(severity)
                
            if vuln_type:
                query += " AND type = ?"
                params.append(vuln_type)
                
            if host:
                query += " AND host = ?"
                params.append(host)
                
            query += " ORDER BY timestamp DESC"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            vulns = []
            for row in rows:
                vuln = {
                    'host': row[1],
                    'port': row[2],
                    'service': row[3],
                    'type': row[4],
                    'cve_id': row[5],
                    'cvss_score': row[6],
                    'severity': row[7],
                    'description': row[8],
                    'metadata': json.loads(row[9]) if row[9] else None,
                    'timestamp': row[10]
                }
                vulns.append(vuln)
                
            conn.close()
            return vulns
            
        except Exception as e:
            print(f"Error getting vulnerabilities: {str(e)}")
            return []
        
    def get_nmap_results(self, host: Optional[str] = None,
                         port: Optional[int] = None) -> List[Dict]:
        """
        Get nmap scan results from the database
        
        Args:
            host: Optional host filter
            port: Optional port filter
            
        Returns:
            List of nmap result dictionaries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = "SELECT * FROM nmap_scans WHERE 1=1"
            params = []
            
            if host:
                query += " AND host = ?"
                params.append(host)
                
            if port:
                query += " AND port = ?"
                params.append(port)
                
            query += " ORDER BY timestamp DESC"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            results = []
            for row in rows:
                result = {
                    'host': row[1],
                    'port': row[2],
                    'protocol': row[3],
                    'service': row[4],
                    'product': row[5],
                    'version': row[6],
                    'script_id': row[7],
                    'script_output': row[8],
                    'timestamp': row[9]
                }
                results.append(result)
                
            conn.close()
            return results
            
        except Exception as e:
            print(f"Error getting nmap results: {str(e)}")
            return [] 