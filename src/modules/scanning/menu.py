"""
Terminal-based menu interface for the scanning module.
Provides user interaction for network scanning features including host discovery,
share enumeration, LDAP queries, password policies, and user enumeration.
Displays real-time feedback and allows viewing of previous scan results.
"""

from typing import Optional
import os
from modules.scanning.scanner import NetworkScanner
from database.db_manager import DatabaseManager

class ScanningMenu:
    def __init__(self):
        self.scanner = NetworkScanner()
        self.db = DatabaseManager()

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_menu(self):
        self.clear_screen()
        print("""
╔══════════════════════════════════════╗
║         Network Scanning Menu         ║
╠══════════════════════════════════════╣
║ 1. Discover Live Hosts               ║
║ 2. Enumerate SMB Shares              ║
║ 3. Enumerate LDAP                    ║
║ 4. Password Policy Enumeration       ║
║ 5. User Enumeration                  ║
║ 6. AS-REP Roasting                   ║
║ 7. Service Scanning                  ║
║ 8. View Previous Results             ║
║ 0. Back to Main Menu                 ║
╚══════════════════════════════════════╝
""")

    def scan_callback(self, event_type: str, data: dict):
        """Handle real-time feedback from scanner"""
        if event_type == "status":
            print(f"\n[*] {data['message']}")
        elif event_type == "progress":
            print(f"\r[*] Processing host {data['current']}/{data['total']}: {data['host']}", end='')
        elif event_type == "discovery":
            print(f"\n[+] {data['message']}")
        elif event_type == "result":
            host = data['host']
            dc_status = "[DC]" if host['is_dc'] else ""
            hostname = f"({host['hostname']})" if host['hostname'] else ""
            print(f"\n[+] Found: {host['ip']} {hostname} {dc_status}")
        elif event_type == "error":
            print(f"\n[-] Error: {data['message']}")
        elif event_type == "success":
            print(f"\n[+] {data['message']}")
        elif event_type == "share_found":
            share = data['share']
            print(f"\n[+] Found share: {share['name']} (Access: {share['access']}, Type: {share['type']})")

    def handle_live_host_discovery(self):
        self.clear_screen()
        print("\n=== Live Host Discovery ===")
        
        subnet = input("\nEnter target subnet (e.g., 192.168.1.0/24): ")
        print("\nStarting live host discovery...")
        
        hosts = self.scanner.discover_live_hosts(subnet, callback=self.scan_callback)
        
        print("\n\nScan Summary:")
        print("=" * 50)
        print(f"Total hosts found: {len(hosts)}")
        print(f"Domain Controllers found: {sum(1 for host in hosts if host['is_dc'])}")
        
        input("\nPress Enter to continue...")

    def handle_smb_enumeration(self):
        self.clear_screen()
        print("\n=== SMB Share Enumeration ===")
        
        # Get list of previously discovered hosts
        hosts = self.db.get_live_hosts()
        
        if not hosts:
            print("\nNo hosts discovered yet. Please run live host discovery first.")
            input("\nPress Enter to continue...")
            return
            
        print("\nDiscovered hosts:")
        for i, (ip, hostname, is_dc) in enumerate(hosts, 1):
            dc_status = "[DC]" if is_dc else ""
            hostname_str = f"({hostname})" if hostname else ""
            print(f"{i}. {ip} {hostname_str} {dc_status}")
            
        try:
            choice = int(input("\nSelect host number to scan (0 to scan all): "))
            
            if choice == 0:
                target_hosts = [ip for ip, _, _ in hosts]
            elif 1 <= choice <= len(hosts):
                target_hosts = [hosts[choice-1][0]]
            else:
                print("Invalid choice")
                return
                
            for target_ip in target_hosts:
                shares = self.scanner.enumerate_smb_shares(target_ip, callback=self.scan_callback)
                
                if not shares:
                    print(f"\nNo accessible shares found on {target_ip}")
                    
        except ValueError:
            print("Invalid input")
            
        input("\nPress Enter to continue...")

    def handle_ldap_enumeration(self):
        self.clear_screen()
        print("\n=== LDAP Enumeration ===")
        
        # Get the DC IP from database
        dc_ip = self.db.get_dc_ip()
        
        if not dc_ip:
            print("\nNo Domain Controller discovered yet. Please run live host discovery first.")
            input("\nPress Enter to continue...")
            return
            
        print(f"\nUsing discovered DC: {dc_ip}")
        print("\nAttempting anonymous LDAP enumeration...")
        
        results = self.scanner.enumerate_ldap(dc_ip)
        
        if results['users'] or results['groups'] or results['computers']:
            print("\nEnumeration Results:")
            print("=" * 50)
            
            print("\nUsers found:", len(results['users']))
            print("Groups found:", len(results['groups']))
            print("Computers found:", len(results['computers']))
            
            # Ask if user wants to see detailed results
            if input("\nShow detailed results? (y/n): ").lower() == 'y':
                if results['users']:
                    print("\nUsers:")
                    print("-" * 30)
                    for user in results['users'][:10]:  # Show first 10 users
                        print(user.entry_dn)
                    if len(results['users']) > 10:
                        print(f"... and {len(results['users'])-10} more")
                        
                if results['groups']:
                    print("\nGroups:")
                    print("-" * 30)
                    for group in results['groups'][:10]:
                        print(group.entry_dn)
                    if len(results['groups']) > 10:
                        print(f"... and {len(results['groups'])-10} more")
        else:
            print("\nNo results found or enumeration failed")
            
        input("\nPress Enter to continue...")

    def handle_password_policy(self):
        self.clear_screen()
        print("\n=== Password Policy Enumeration ===")
        
        # Get the DC IP from database
        dc_ip = self.db.get_dc_ip()
        
        if not dc_ip:
            print("\nNo Domain Controller discovered yet. Please run live host discovery first.")
            input("\nPress Enter to continue...")
            return
            
        domain = input("\nEnter domain name (e.g., domain.local): ")
        print(f"\nEnumerating password policy from DC: {dc_ip}")
        
        policy = self.scanner.enumerate_password_policy(dc_ip, domain)
        
        if policy:
            print("\nPassword Policy:")
            print("=" * 50)
            print(f"Minimum Length: {policy.get('min_length', 'Unknown')}")
            print(f"Complexity Enabled: {policy.get('complexity_enabled', 'Unknown')}")
            print(f"Password History: {policy.get('history_length', 'Unknown')} passwords")
            print(f"Lockout Threshold: {policy.get('lockout_threshold', 'Unknown')} attempts")
            print(f"Lockout Duration: {policy.get('lockout_duration', 'Unknown')} minutes")
        else:
            print("\nFailed to enumerate password policy")
            
        input("\nPress Enter to continue...")

    def handle_user_enumeration(self):
        self.clear_screen()
        print("\n=== User Enumeration ===")
        
        # Get the DC IP from database
        dc_ip = self.db.get_dc_ip()
        
        if not dc_ip:
            print("\nNo Domain Controller discovered yet. Please run live host discovery first.")
            input("\nPress Enter to continue...")
            return
            
        domain = input("\nEnter domain name (e.g., domain.local): ")
        
        print("\nSelect wordlist source:")
        print("1. Load from file")
        print("2. Use common username patterns")
        print("3. Use discovered usernames")
        
        choice = input("\nSelect option: ")
        
        userlist = []
        if choice == "1":
            wordlist_path = input("\nEnter path to wordlist file: ")
            try:
                with open(wordlist_path, 'r') as f:
                    userlist = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"\nError reading wordlist: {str(e)}")
                input("\nPress Enter to continue...")
                return
        elif choice == "2":
            # Common username patterns
            patterns = ['administrator', 'admin', 'guest', 'user', 'backup', 'service']
            userlist = patterns
        elif choice == "3":
            # Use previously discovered users
            users = self.db.get_discovered_users(domain)
            if not users:
                print("\nNo users discovered yet.")
                input("\nPress Enter to continue...")
                return
            userlist = [user[1] for user in users]  # username is second column
        else:
            print("\nInvalid choice")
            input("\nPress Enter to continue...")
            return
            
        print(f"\nAttempting to enumerate users on {dc_ip}...")
        valid_users = self.scanner.bruteforce_users(dc_ip, domain, userlist)
        
        if valid_users:
            print("\nValid users found:")
            print("=" * 50)
            for user in valid_users:
                print(user)
        else:
            print("\nNo valid users found")
            
        input("\nPress Enter to continue...")

    def handle_asrep_roast(self):
        self.clear_screen()
        print("\n=== AS-REP Roasting ===")
        
        # Get the DC IP from database
        dc_ip = self.db.get_dc_ip()
        
        if not dc_ip:
            print("\nNo Domain Controller discovered yet. Please run live host discovery first.")
            input("\nPress Enter to continue...")
            return
            
        domain = input("\nEnter domain name (e.g., domain.local): ")
        
        print("\nSelect target users:")
        print("1. Use all discovered users")
        print("2. Specify userlist file")
        
        choice = input("\nSelect option: ")
        
        userlist = None  # None will use discovered users from database
        if choice == "2":
            wordlist_path = input("\nEnter path to userlist file: ")
            try:
                with open(wordlist_path, 'r') as f:
                    userlist = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"\nError reading userlist: {str(e)}")
                input("\nPress Enter to continue...")
                return
                
        print(f"\nAttempting AS-REP Roasting on {dc_ip}...")
        results = self.scanner.asrep_roast(dc_ip, domain, userlist)
        
        if results:
            print("\nAS-REP Roastable accounts found:")
            print("=" * 50)
            for username, hash_data in results.items():
                print(f"User: {username}")
                print(f"Hash: {hash_data['sessionKey']}")
                print("-" * 30)
        else:
            print("\nNo AS-REP Roastable accounts found")
            
        input("\nPress Enter to continue...")

    def handle_service_scanning(self):
        self.clear_screen()
        print("\n=== Service Scanning ===")
        
        # Get list of previously discovered hosts
        hosts = self.db.get_live_hosts()
        
        if not hosts:
            print("\nNo hosts discovered yet. Please run live host discovery first.")
            input("\nPress Enter to continue...")
            return
            
        print("\nDiscovered hosts:")
        for i, (ip, hostname, is_dc) in enumerate(hosts, 1):
            dc_status = "[DC]" if is_dc else ""
            hostname_str = f"({hostname})" if hostname else ""
            print(f"{i}. {ip} {hostname_str} {dc_status}")
            
        try:
            choice = int(input("\nSelect host number to scan (0 to scan all): "))
            
            if choice == 0:
                target_hosts = [ip for ip, _, _ in hosts]
            elif 1 <= choice <= len(hosts):
                target_hosts = [hosts[choice-1][0]]
            else:
                print("Invalid choice")
                return
                
            for target_ip in target_hosts:
                print(f"\nScanning services on {target_ip}...")
                services = self.scanner.scan_network_services(target_ip)
                
                if services:
                    print(f"\nServices found on {target_ip}:")
                    print("=" * 50)
                    for port, info in services.items():
                        print(f"Port {port}/{info['state']}")
                        print(f"Service: {info['service']}")
                        if info['version']:
                            print(f"Version: {info['version']}")
                        if info['product']:
                            print(f"Product: {info['product']}")
                        print("-" * 30)
                else:
                    print(f"No services found on {target_ip}")
                    
        except ValueError:
            print("Invalid input")
            
        input("\nPress Enter to continue...")

    def handle_view_results(self):
        self.clear_screen()
        print("\n=== View Previous Results ===")
        
        print("""
1. View Live Hosts
2. View SMB Shares
3. View LDAP Results
4. View Password Policies
5. View Discovered Users
6. View AS-REP Results
7. View Service Scans
0. Back
""")
        
        choice = input("\nSelect option: ")
        
        if choice == "1":
            hosts = self.db.get_live_hosts()
            print("\nDiscovered Hosts:")
            print("=" * 50)
            for ip, hostname, is_dc in hosts:
                dc_status = "[DC]" if is_dc else ""
                hostname_str = f"({hostname})" if hostname else ""
                print(f"{ip} {hostname_str} {dc_status}")
                
        elif choice == "2":
            shares = self.db.get_smb_shares()
            print("\nDiscovered SMB Shares:")
            print("=" * 50)
            for host_ip, share_name, access_type, additional_info in shares:
                print(f"Host: {host_ip}")
                print(f"Share: {share_name}")
                print(f"Access: {access_type}")
                print("-" * 30)
                
        elif choice == "3":
            # Implementation for viewing LDAP results would go here
            print("\nLDAP results viewer not implemented yet")
            
        elif choice == "4":
            policies = self.db.get_password_policy()
            print("\nDiscovered Password Policies:")
            print("=" * 50)
            for policy in policies:
                print(f"Domain: {policy[1]}")
                print(f"Min Length: {policy[2]}")
                print(f"Complexity: {'Enabled' if policy[3] else 'Disabled'}")
                print(f"History: {policy[4]} passwords")
                print("-" * 30)
                
        elif choice == "5":
            users = self.db.get_discovered_users()
            print("\nDiscovered Users:")
            print("=" * 50)
            for user in users:
                print(f"Username: {user[1]}")
                print(f"Domain: {user[2]}")
                print(f"Source: {user[3]}")
                print("-" * 30)
                
        elif choice == "6":
            results = self.db.get_asrep_results()
            print("\nAS-REP Roasting Results:")
            print("=" * 50)
            for username, domain, hash_value in results:
                print(f"User: {username}")
                print(f"Domain: {domain}")
                print(f"Hash: {hash_value}")
                print("-" * 30)
                
        elif choice == "7":
            scans = self.db.get_service_scans()
            print("\nService Scan Results:")
            print("=" * 50)
            current_host = None
            for scan in scans:
                if scan[1] != current_host:
                    current_host = scan[1]
                    print(f"\nHost: {current_host}")
                print(f"Port {scan[2]}: {scan[3]}")
                if scan[4]:  # version
                    print(f"Version: {scan[4]}")
                print("-" * 30)
                
        input("\nPress Enter to continue...")

    def run(self):
        while True:
            self.print_menu()
            choice = input("\nSelect option: ")
            
            if choice == "1":
                self.handle_live_host_discovery()
            elif choice == "2":
                self.handle_smb_enumeration()
            elif choice == "3":
                self.handle_ldap_enumeration()
            elif choice == "4":
                self.handle_password_policy()
            elif choice == "5":
                self.handle_user_enumeration()
            elif choice == "6":
                self.handle_asrep_roast()
            elif choice == "7":
                self.handle_service_scanning()
            elif choice == "8":
                self.handle_view_results()
            elif choice == "0":
                break
            else:
                print("Invalid option") 