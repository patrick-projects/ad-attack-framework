"""
BloodHound integration for automated Active Directory enumeration and analysis.
Supports data collection, path analysis, and attack planning using the BloodHound Python API.
Includes neo4j database management for Kali integration.
"""

from ..attack_base import AttackBase
from typing import Optional, Dict, List, Set
import subprocess
import json
import os
from datetime import datetime
import time
from neo4j import GraphDatabase

class BloodHoundEnum(AttackBase):
    def __init__(self):
        """Initialize BloodHound enumeration module"""
        super().__init__()
        self.collection_methods = {
            'DCOnly': ['Group', 'LocalAdmin', 'Session', 'Trusts', 'ACL', 'ObjectProps', 'Container'],
            'Default': ['Default'],
            'All': ['All']
        }
        self.neo4j_uri = "bolt://localhost:7687"
        self.neo4j_user = "neo4j"
        self.neo4j_pass = "bloodhound"
        
    def setup_neo4j(self, password: Optional[str] = None) -> bool:
        """
        Setup neo4j database for BloodHound
        
        Args:
            password: Optional password to set for neo4j
            
        Returns:
            bool indicating success/failure
        """
        try:
            # Start neo4j service
            self.log_status("Starting neo4j service")
            subprocess.run(['service', 'neo4j', 'start'], check=True)
            time.sleep(5)  # Wait for service to start
            
            if password:
                # Set neo4j password
                cmd = [
                    'neo4j-admin',
                    'set-initial-password',
                    password
                ]
                subprocess.run(cmd, check=True)
                self.neo4j_pass = password
                
            # Test connection
            driver = GraphDatabase.driver(
                self.neo4j_uri,
                auth=(self.neo4j_user, self.neo4j_pass)
            )
            with driver.session() as session:
                result = session.run("MATCH (n) RETURN count(n) as count")
                count = result.single()["count"]
                self.log_success(f"Connected to neo4j database. Node count: {count}")
                
            driver.close()
            return True
            
        except Exception as e:
            self.log_error(f"Neo4j setup failed: {str(e)}")
            return False
            
    def start_bloodhound_gui(self) -> bool:
        """
        Start BloodHound GUI in Kali
        
        Returns:
            bool indicating success/failure
        """
        try:
            # Start BloodHound in background
            cmd = [
                'bloodhound',
                '--no-sandbox'
            ]
            
            self.log_status("Starting BloodHound GUI")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait briefly to check if process started
            time.sleep(3)
            if process.poll() is None:
                self.log_success("BloodHound GUI started successfully")
                return True
                
            self.log_error("Failed to start BloodHound GUI")
            return False
            
        except Exception as e:
            self.log_error(f"BloodHound GUI start failed: {str(e)}")
            return False
            
    def collect_data(self, domain: str, username: str, password: str,
                    collection_method: str = 'Default',
                    zip_filename: Optional[str] = None) -> bool:
        """
        Collect AD data using SharpHound
        
        Args:
            domain: Domain to enumerate
            username: Username for authentication
            password: Password for authentication
            collection_method: Collection method (DCOnly, Default, All)
            zip_filename: Optional custom name for output file
            
        Returns:
            bool indicating success/failure
        """
        try:
            if collection_method not in self.collection_methods:
                self.log_error(f"Invalid collection method: {collection_method}")
                return False
                
            # Generate output filename if not provided
            if not zip_filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                zip_filename = f"bloodhound_{domain}_{timestamp}.zip"
                
            # Ensure output directory exists
            output_dir = os.path.join(os.getcwd(), 'loot', 'bloodhound')
            os.makedirs(output_dir, exist_ok=True)
            zip_path = os.path.join(output_dir, zip_filename)
            
            # Build SharpHound command
            cmd = [
                'SharpHound.exe',
                '-c', ','.join(self.collection_methods[collection_method]),
                '-d', domain,
                '--zipfilename', zip_path
            ]
            
            if username and password:
                cmd.extend([
                    '-u', username,
                    '-p', password
                ])
                
            self.log_status(f"Starting BloodHound collection for {domain}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if os.path.exists(zip_path):
                self.log_success(f"BloodHound data collected: {zip_path}")
                
                # Store collection metadata
                self.db.add_bloodhound_collection({
                    'domain': domain,
                    'timestamp': datetime.now().isoformat(),
                    'method': collection_method,
                    'zip_file': zip_path
                })
                
                # Try to import data into neo4j
                if self.import_bloodhound_zip(zip_path):
                    self.log_success("Data imported into neo4j database")
                else:
                    self.log_error("Failed to import data into neo4j")
                    
                return True
                
            self.log_error("BloodHound collection failed")
            return False
            
        except Exception as e:
            self.log_error(f"BloodHound collection failed: {str(e)}")
            return False
            
    def import_bloodhound_zip(self, zip_path: str) -> bool:
        """
        Import BloodHound zip file into neo4j database
        
        Args:
            zip_path: Path to BloodHound zip file
            
        Returns:
            bool indicating success/failure
        """
        try:
            # Extract zip file
            import zipfile
            extract_dir = os.path.join(os.path.dirname(zip_path), 'extracted')
            os.makedirs(extract_dir, exist_ok=True)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
                
            # Import each JSON file into neo4j
            for filename in os.listdir(extract_dir):
                if filename.endswith('.json'):
                    file_path = os.path.join(extract_dir, filename)
                    
                    # Use bloodhound-python to import
                    cmd = [
                        'bloodhound-python',
                        '--zip', file_path,
                        '--uri', self.neo4j_uri,
                        '--user', self.neo4j_user,
                        '--password', self.neo4j_pass
                    ]
                    
                    self.log_status(f"Importing {filename}")
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if "Successfully imported" not in result.stdout:
                        self.log_error(f"Failed to import {filename}")
                        return False
                        
            return True
            
        except Exception as e:
            self.log_error(f"Data import failed: {str(e)}")
            return False
            
    def clear_database(self) -> bool:
        """
        Clear all data from neo4j database
        
        Returns:
            bool indicating success/failure
        """
        try:
            driver = GraphDatabase.driver(
                self.neo4j_uri,
                auth=(self.neo4j_user, self.neo4j_pass)
            )
            
            with driver.session() as session:
                # Delete all nodes and relationships
                session.run("MATCH (n) DETACH DELETE n")
                self.log_success("Database cleared successfully")
                
            driver.close()
            return True
            
        except Exception as e:
            self.log_error(f"Database clear failed: {str(e)}")
            return False
            
    def get_database_stats(self) -> Dict:
        """
        Get statistics about the current neo4j database
        
        Returns:
            Dict containing database statistics
        """
        try:
            driver = GraphDatabase.driver(
                self.neo4j_uri,
                auth=(self.neo4j_user, self.neo4j_pass)
            )
            
            stats = {}
            with driver.session() as session:
                # Get counts for different node types
                node_types = ['User', 'Group', 'Computer', 'Domain', 'GPO']
                for node_type in node_types:
                    result = session.run(f"MATCH (n:{node_type}) RETURN count(n) as count")
                    stats[node_type] = result.single()["count"]
                    
                # Get relationship counts
                result = session.run("MATCH ()-[r]->() RETURN count(r) as count")
                stats['relationships'] = result.single()["count"]
                
            driver.close()
            return stats
            
        except Exception as e:
            self.log_error(f"Failed to get database stats: {str(e)}")
            return {}
            
    def analyze_paths_to_da(self, domain: str) -> List[Dict]:
        """
        Analyze paths to Domain Admin using BloodHound's Python API
        
        Args:
            domain: Domain to analyze
            
        Returns:
            List of attack paths to Domain Admin
        """
        try:
            from bloodhound.ad.domain import AD
            from bloodhound.ad.authentication import ADAuthentication
            
            self.log_status("Analyzing paths to Domain Admin")
            
            # Initialize BloodHound connection
            auth = ADAuthentication(domain=domain)
            ad = AD(auth=auth, domain=domain)
            
            # Query for paths to Domain Admins
            query = """
            MATCH (n:User)
            MATCH (g:Group {name: 'DOMAIN ADMINS@DOMAIN.LOCAL'})
            MATCH p = shortestPath((n)-[*1..]->(g))
            RETURN p
            """
            
            results = ad.run_query(query)
            paths = []
            
            for result in results:
                path = {
                    'start_node': result.start_node['name'],
                    'end_node': result.end_node['name'],
                    'relationships': [rel.type for rel in result.relationships],
                    'length': len(result.relationships)
                }
                paths.append(path)
                
            self.log_success(f"Found {len(paths)} paths to Domain Admin")
            return paths
            
        except Exception as e:
            self.log_error(f"Path analysis failed: {str(e)}")
            return []
            
    def find_kerberoastable_users(self, domain: str) -> List[Dict]:
        """
        Find Kerberoastable users using BloodHound data
        
        Args:
            domain: Domain to analyze
            
        Returns:
            List of Kerberoastable users and their properties
        """
        try:
            from bloodhound.ad.domain import AD
            from bloodhound.ad.authentication import ADAuthentication
            
            self.log_status("Searching for Kerberoastable users")
            
            # Initialize BloodHound connection
            auth = ADAuthentication(domain=domain)
            ad = AD(auth=auth, domain=domain)
            
            # Query for Kerberoastable users
            query = """
            MATCH (u:User {hasspn:true})
            RETURN u.name, u.displayname, u.description, u.title
            """
            
            results = ad.run_query(query)
            users = []
            
            for result in results:
                user = {
                    'username': result['u.name'],
                    'displayname': result['u.displayname'],
                    'description': result['u.description'],
                    'title': result['u.title']
                }
                users.append(user)
                
            self.log_success(f"Found {len(users)} Kerberoastable users")
            return users
            
        except Exception as e:
            self.log_error(f"Kerberoastable user search failed: {str(e)}")
            return []
            
    def find_dangerous_acls(self, domain: str) -> List[Dict]:
        """
        Find dangerous ACL configurations using BloodHound data
        
        Args:
            domain: Domain to analyze
            
        Returns:
            List of dangerous ACL configurations
        """
        try:
            from bloodhound.ad.domain import AD
            from bloodhound.ad.authentication import ADAuthentication
            
            self.log_status("Analyzing ACL configurations")
            
            # Initialize BloodHound connection
            auth = ADAuthentication(domain=domain)
            ad = AD(auth=auth, domain=domain)
            
            # Query for dangerous ACLs
            query = """
            MATCH (n)-[r:GenericAll|GenericWrite|WriteOwner|WriteDacl|AllExtendedRights]->(m)
            WHERE NOT n.name STARTS WITH 'DOMAIN ADMINS@'
            RETURN n.name as principal, type(r) as right, m.name as target
            """
            
            results = ad.run_query(query)
            acls = []
            
            for result in results:
                acl = {
                    'principal': result['principal'],
                    'right': result['right'],
                    'target': result['target']
                }
                acls.append(acl)
                
            self.log_success(f"Found {len(acls)} dangerous ACL configurations")
            return acls
            
        except Exception as e:
            self.log_error(f"ACL analysis failed: {str(e)}")
            return []
            
    def suggest_attack_paths(self, domain: str, 
                           current_user: str) -> List[Dict]:
        """
        Suggest attack paths based on current user context
        
        Args:
            domain: Domain to analyze
            current_user: Current user context
            
        Returns:
            List of suggested attack paths
        """
        try:
            from bloodhound.ad.domain import AD
            from bloodhound.ad.authentication import ADAuthentication
            
            self.log_status(f"Analyzing attack paths for {current_user}")
            
            # Initialize BloodHound connection
            auth = ADAuthentication(domain=domain)
            ad = AD(auth=auth, domain=domain)
            
            # Query for attack paths from current user
            query = f"""
            MATCH (n:User {{name:'{current_user}'}})-[r:MemberOf|HasSession|GenericAll|GenericWrite|WriteOwner|WriteDacl|AllExtendedRights*1..3]->(m)
            WHERE m.highvalue=true
            RETURN DISTINCT m.name as target, 
                   [rel in relationships(p) | type(rel)] as attack_path,
                   length(p) as path_length
            ORDER BY path_length ASC
            """
            
            results = ad.run_query(query)
            paths = []
            
            for result in results:
                path = {
                    'target': result['target'],
                    'attack_path': result['attack_path'],
                    'path_length': result['path_length']
                }
                paths.append(path)
                
            self.log_success(f"Found {len(paths)} potential attack paths")
            return paths
            
        except Exception as e:
            self.log_error(f"Attack path analysis failed: {str(e)}")
            return [] 