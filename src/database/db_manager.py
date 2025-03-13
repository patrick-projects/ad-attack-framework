"""
Database Manager Module for AD Attack Framework
"""

import sqlite3
from pathlib import Path
from typing import Dict, List, Optional
import json

class DatabaseManager:
    def __init__(self, db_path: str = "ad_attack.db"):
        self.db_path = db_path
        self._init_db()
        
    def _init_db(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create hosts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                hostname TEXT,
                os TEXT,
                timestamp TEXT,
                UNIQUE(ip)
            )
        ''')
        
        # Create services table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                port INTEGER,
                service TEXT,
                version TEXT,
                timestamp TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts (id)
            )
        ''')
        
        # Create vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                type TEXT,
                severity TEXT,
                description TEXT,
                timestamp TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def add_host(self, ip: str, hostname: Optional[str] = None, os: Optional[str] = None) -> int:
        """Add a new host to the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO hosts (ip, hostname, os, timestamp)
                VALUES (?, ?, ?, datetime('now'))
            ''', (ip, hostname, os))
            
            host_id = cursor.execute('SELECT id FROM hosts WHERE ip = ?', (ip,)).fetchone()[0]
            conn.commit()
            return host_id
            
        finally:
            conn.close()
            
    def add_service(self, host_id: int, port: int, service: str, version: Optional[str] = None):
        """Add a service to a host"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO services (host_id, port, service, version, timestamp)
                VALUES (?, ?, ?, ?, datetime('now'))
            ''', (host_id, port, service, version))
            conn.commit()
            
        finally:
            conn.close()
            
    def add_vulnerability(self, host_id: int, vuln_type: str, severity: str, description: str):
        """Add a vulnerability to a host"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO vulnerabilities (host_id, type, severity, description, timestamp)
                VALUES (?, ?, ?, ?, datetime('now'))
            ''', (host_id, vuln_type, severity, description))
            conn.commit()
            
        finally:
            conn.close()
            
    def get_hosts(self) -> List[Dict]:
        """Get all hosts from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT h.*, 
                       GROUP_CONCAT(DISTINCT s.port || ':' || s.service) as services,
                       GROUP_CONCAT(DISTINCT v.type || ':' || v.severity) as vulnerabilities
                FROM hosts h
                LEFT JOIN services s ON h.id = s.host_id
                LEFT JOIN vulnerabilities v ON h.id = v.host_id
                GROUP BY h.id
            ''')
            
            columns = [description[0] for description in cursor.description]
            results = []
            
            for row in cursor.fetchall():
                result = dict(zip(columns, row))
                result['services'] = result['services'].split(',') if result['services'] else []
                result['vulnerabilities'] = result['vulnerabilities'].split(',') if result['vulnerabilities'] else []
                results.append(result)
                
            return results
            
        finally:
            conn.close() 