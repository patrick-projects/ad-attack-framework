"""
Terminal-based menu interface for the attack module.

This module provides a comprehensive interface for conducting Active Directory penetration tests.
It orchestrates various attack techniques including:
- Password attacks (spray/bruteforce)
- Poisoning/MITM attacks (LLMNR/NBT-NS/mDNS/IPv6/WPAD/ARP)
- Coercion attacks (PetitPotam/PrinterBug)
- ADCS attacks (ESC1-ESC8)
- Trust relationship attacks
- Post-exploitation actions
- BloodHound-based enumeration and analysis

The menu system follows a modular approach where each attack type has its own
handler method and can maintain state between operations. Results are tracked
and can be viewed or exported at any time.
"""

from typing import Optional, Dict, List
import os
from .password_attacks import PasswordAttacks
from .poisoning_attacks import PoisoningAttacks
from .coercion_attacks import CoercionAttacks
from .time_attacks import TimeAttacks
from .pxe_attacks import PXEAttacks
from .quick_attacks import QuickAttacks
from .privesc_attacks import PrivEscAttacks
from ...database.db_manager import DatabaseManager
import json
from datetime import datetime
from .bloodhound_enum import BloodHoundEnum
from colorama import Fore, Style, init
import sys

# Initialize colorama
init()

class AttackMenu:
    def __init__(self):
        """
        Initialize the attack menu system.
        Sets up individual attack modules and database connection.
        """
        self.db = DatabaseManager()
        self.password_attacks = PasswordAttacks()
        self.poisoning_attacks = PoisoningAttacks()
        self.coercion_attacks = CoercionAttacks()
        self.time_attacks = TimeAttacks()
        self.pxe_attacks = PXEAttacks()
        self.quick_attacks = QuickAttacks()
        self.privesc_attacks = PrivEscAttacks()
        self.bloodhound = BloodHoundEnum()
        self.banner = f"""{Fore.CYAN}
    /\___/\  Active Directory
   (  o o  )  Attack Framework
   (  =^=  ) 
    (--m--)  
   /      \    
  /        \   Made with 😺 by
 /          \  Patrick Crumbaugh
/            \ 
==============
{Style.RESET_ALL}"""
        
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def print_menu(self):
        self.clear_screen()
        print("""
╔══════════════════════════════════════╗
║           Attack Menu                ║
╠══════════════════════════════════════╣
║ Quick Compromise:                    ║
║   1. Check Critical Vulnerabilities  ║
║   2. Check Exchange Vulnerabilities  ║
║   3. Check Web Services             ║
║   4. Check MSSQL Servers            ║
║   5. Check Veeam Services           ║
║   6. Check Tomcat/JBoss             ║
║                                      ║
║ Password Attacks:                    ║
║   7. Password Spray                  ║
║   8. Password Bruteforce            ║
║                                      ║
║ Poisoning/MITM Attacks:             ║
║   9. LLMNR Poisoning                ║
║   10. NBT-NS Poisoning              ║
║   11. mDNS Poisoning                ║
║   12. IPv6 Poisoning                ║
║   13. WPAD/PAC Poisoning            ║
║   14. ARP Poisoning                 ║
║   15. Traffic Manipulation          ║
║                                      ║
║ Privilege Escalation:               ║
║   16. Service Hijacking             ║
║   17. Token Privileges              ║
║   18. Registry Exploits             ║
║   19. Scheduled Tasks               ║
║   20. Named Pipe Impersonation      ║
║                                      ║
║ Coercion Attacks:                    ║
║   21. PetitPotam                    ║
║   22. PrinterBug                    ║
║                                      ║
║ Time-Based Attacks:                  ║
║   23. Kerberoasting                 ║
║   24. Check Time Synchronization    ║
║                                      ║
║ PXE Attacks:                         ║
║   25. PXE Attacks                   ║
║                                      ║
║ 26. View Attack Results             ║
║ 0. Back to Main Menu                ║
╚══════════════════════════════════════╝
""")

    def attack_callback(self, event_type: str, data: dict):
        """Handle real-time feedback from attacks"""
        if event_type == "status":
            print(f"\n[*] {data['message']}")
        elif event_type == "progress":
            if 'total' in data:
                print(f"\r[*] Progress: {data['current']}/{data['total']} - {data.get('username', '')}", end='')
            else:
                print(f"\r[*] {data.get('message', '')}", end='')
        elif event_type == "success":
            print(f"\n[+] {data['message']}")
        elif event_type == "error":
            print(f"\n[-] {data['message']}")
        elif event_type == "credential":
            if data.get('type') == 'PASSWORD':
                print(f"\n[!] CLEARTEXT PASSWORD FOUND!")
                print(f"[!] User: {data['username']}@{data['domain']}")
                print(f"[!] Password: {data['password']}")
            else:
                print(f"\n[+] Found credential - User: {data['username']}@{data.get('domain', '')} ({data['type']})")
        elif event_type == "discovery":
            print(f"\n[+] Discovered {data['type']}: {data['host']}")
        elif event_type == "vulnerability":
            print(f"\n[!] {data['type']} - {data['description']}")
            print(f"    Host: {data['host']}")
            print(f"    Severity: {data['severity']}")
            if 'url' in data:
                print(f"    URL: {data['url']}")
            if 'port' in data:
                print(f"    Port: {data['port']}")

    def handle_quick_attacks(self, attack_type: str):
        """
        Handle quick compromise attacks for rapid assessment.
        
        Supports scanning for:
        - Critical vulnerabilities (e.g., MS17-010, ZeroLogon)
        - Exchange server vulnerabilities
        - Web application vulnerabilities
        - MSSQL server misconfigurations
        - Backup software vulnerabilities (Veeam)
        - Application server issues (Tomcat/JBoss)
        
        Args:
            attack_type: Type of quick scan to perform
        """
        self.clear_screen()
        print(f"\n=== Quick Compromise - {attack_type} ===")
        
        # Get list of discovered hosts from database
        hosts = self.db.get_live_hosts()
        
        if not hosts:
            print("\nNo hosts discovered yet. Please run network scanning first.")
            input("\nPress Enter to continue...")
            return
            
        # Filter hosts based on attack type
        if attack_type == "Exchange":
            target_hosts = [h for h in hosts if self.db.has_service(h[0], 'exchange')]
            if not target_hosts:
                print("\nNo Exchange servers discovered. Please run service enumeration first.")
                input("\nPress Enter to continue...")
                return
        elif attack_type == "Web Services":
            target_hosts = [h for h in hosts if self.db.has_service(h[0], 'http') or self.db.has_service(h[0], 'https')]
            if not target_hosts:
                print("\nNo web services discovered. Please run service enumeration first.")
                input("\nPress Enter to continue...")
                return
        elif attack_type == "MSSQL":
            target_hosts = [h for h in hosts if self.db.has_service(h[0], 'mssql')]
            if not target_hosts:
                print("\nNo MSSQL servers discovered. Please run service enumeration first.")
                input("\nPress Enter to continue...")
                return
        elif attack_type == "Veeam":
            target_hosts = [h for h in hosts if self.db.has_service(h[0], 'veeam')]
            if not target_hosts:
                print("\nNo Veeam services discovered. Please run service enumeration first.")
                input("\nPress Enter to continue...")
                return
        elif attack_type == "Tomcat":
            target_hosts = [h for h in hosts if self.db.has_service(h[0], 'http') or self.db.has_service(h[0], 'https')]
            if not target_hosts:
                print("\nNo web services discovered. Please run service enumeration first.")
                input("\nPress Enter to continue...")
                return
            
        # For critical vulns, we'll check all hosts
        target = input("\nEnter target IP/range (or press enter for all discovered hosts): ").strip()
        if not target:
            target = ','.join([h[0] for h in hosts])
        
        print("\nStarting vulnerability checks...")
        
        if attack_type == "Critical":
            self.quick_attacks.check_critical_vulns(target, callback=self.attack_callback)
        elif attack_type == "Exchange":
            self.quick_attacks.check_exchange(target, callback=self.attack_callback)
        elif attack_type == "Web Services":
            self.quick_attacks.check_web_services(target, callback=self.attack_callback)
        elif attack_type == "MSSQL":
            self.quick_attacks.check_mssql(target, callback=self.attack_callback)
        elif attack_type == "Veeam":
            self.quick_attacks.check_veeam(target, callback=self.attack_callback)
        else:  # Tomcat/JBoss
            self.quick_attacks.check_tomcat(target, callback=self.attack_callback)
        
        input("\nPress enter to stop the checks...")
        self.quick_attacks.stop()

    def handle_password_spray(self):
        """
        Handle password spraying attacks against domain users.
        
        Features:
        - Multiple user source options (file, discovered, common)
        - Protocol selection (SMB, Kerberos)
        - Configurable delay between attempts
        - Real-time feedback and result tracking
        - Automatic lockout prevention
        """
        self.clear_screen()
        print("\n=== Password Spray Attack ===")
        
        # Get the DC IP from database
        dc_ip = self.db.get_dc_ip()
        if not dc_ip:
            print("\nNo Domain Controller discovered yet. Please run network scanning first.")
            input("\nPress Enter to continue...")
            return
            
        domain = input("\nEnter domain name (e.g., domain.local): ")
        password = input("Enter password to spray: ")
        
        print("\nSelect user source:")
        print("1. Load from file")
        print("2. Use discovered users")
        print("3. Use common usernames")
        
        choice = input("\nSelect option: ")
        
        userlist = []
        if choice == "1":
            filepath = input("\nEnter path to user list file: ")
            try:
                with open(filepath, 'r') as f:
                    userlist = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"\nError reading file: {str(e)}")
                input("\nPress Enter to continue...")
                return
        elif choice == "2":
            users = self.db.get_discovered_users(domain)
            if not users:
                print("\nNo users discovered yet.")
                input("\nPress Enter to continue...")
                return
            userlist = [user[1] for user in users]  # username is second column
        elif choice == "3":
            userlist = ['administrator', 'admin', 'user', 'backup', 'service', 'guest']
        else:
            print("\nInvalid choice")
            input("\nPress Enter to continue...")
            return
            
        print("\nSelect protocol:")
        print("1. SMB")
        print("2. Kerberos")
        
        protocol = input("\nSelect option: ")
        protocol = 'smb' if protocol == "1" else 'kerberos'
        
        delay = int(input("\nEnter delay between attempts (seconds, 0 for no delay): "))
        
        self.password_attacks.set_callback(self.attack_callback)
        results = self.password_attacks.password_spray(
            dc_ip, domain, userlist, password, protocol, delay
        )
        
        if results:
            print("\nValid credentials found:")
            print("=" * 50)
            for username, pwd in results.items():
                print(f"Username: {username}")
                print(f"Password: {pwd}")
                print("-" * 30)
        else:
            print("\nNo valid credentials found")
            
        input("\nPress Enter to continue...")

    def handle_password_bruteforce(self):
        self.clear_screen()
        print("\n=== Password Bruteforce Attack ===")
        
        # Get the DC IP from database
        dc_ip = self.db.get_dc_ip()
        if not dc_ip:
            print("\nNo Domain Controller discovered yet. Please run network scanning first.")
            input("\nPress Enter to continue...")
            return
            
        domain = input("\nEnter domain name (e.g., domain.local): ")
        username = input("Enter username to bruteforce: ")
        
        print("\nSelect password source:")
        print("1. Load from file")
        print("2. Use common passwords")
        
        choice = input("\nSelect option: ")
        
        wordlist = []
        if choice == "1":
            filepath = input("\nEnter path to password list file: ")
            try:
                with open(filepath, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"\nError reading file: {str(e)}")
                input("\nPress Enter to continue...")
                return
        elif choice == "2":
            wordlist = ['password', 'Password1', 'Password123', 'Welcome123', 'Admin123', 'P@ssw0rd']
        else:
            print("\nInvalid choice")
            input("\nPress Enter to continue...")
            return
            
        print("\nSelect protocol:")
        print("1. SMB")
        print("2. Kerberos")
        
        protocol = input("\nSelect option: ")
        protocol = 'smb' if protocol == "1" else 'kerberos'
        
        threads = int(input("\nEnter number of threads (1-10): "))
        threads = max(1, min(10, threads))
        
        delay = int(input("\nEnter delay between attempts (seconds, 0 for no delay): "))
        
        self.password_attacks.set_callback(self.attack_callback)
        password = self.password_attacks.bruteforce_user(
            dc_ip, domain, username, wordlist, protocol, threads, delay
        )
        
        if password:
            print("\nValid password found!")
            print("=" * 50)
            print(f"Username: {username}")
            print(f"Password: {password}")
        else:
            print("\nNo valid password found")
            
        input("\nPress Enter to continue...")

    def handle_poisoning(self, attack_type: str):
        """
        Handle network poisoning and MITM attacks.
        
        Supported attack types:
        - LLMNR/NBT-NS/mDNS poisoning
        - IPv6 DNS takeover
        - WPAD/PAC injection
        - ARP poisoning
        - Traffic manipulation
        
        Features:
        - Automatic relay target detection
        - Post-exploitation integration
        - Real-time credential capture
        
        Args:
            attack_type: Type of poisoning attack to perform
        """
        self.clear_screen()
        print(f"\n=== {attack_type} Attack ===")
        
        interface = input("\nEnter interface to listen on (default: 0.0.0.0): ") or "0.0.0.0"
        
        if attack_type in ["LLMNR", "NBT-NS", "mDNS"]:
            respond_ip = input("Enter IP to respond with (default: interface IP): ") or None
            
            # Check for potential relay targets
            targets = self.db.get_smb_targets(signing_required=False)
            if targets:
                print(f"\nFound {len(targets)} potential relay targets (SMB signing not required):")
                for ip, hostname, _ in targets:
                    hostname_str = f"({hostname})" if hostname else ""
                    print(f"  - {ip} {hostname_str}")
                relay = input("\nAttempt to relay captured hashes? (y/n): ").lower() == 'y'
                
                if relay:
                    print("\nRelay Options:")
                    print("1. Basic relay (attempt authentication only)")
                    print("2. Advanced relay (attempt secretsdump on successful admin access)")
                    relay_option = input("\nSelect option (1-2): ")
                    post_exploit = relay_option == "2"
                else:
                    post_exploit = False
            else:
                print("\nNo potential relay targets found (all discovered hosts require SMB signing)")
                relay = False
                post_exploit = False
            
            if attack_type == "LLMNR":
                self.poisoning_attacks.start_llmnr_poisoning(interface, respond_ip, relay, post_exploit)
            elif attack_type == "NBT-NS":
                self.poisoning_attacks.start_nbtns_poisoning(interface, respond_ip, relay, post_exploit)
            else:  # mDNS
                self.poisoning_attacks.start_mdns_poisoning(interface, respond_ip, relay, post_exploit)
                
        elif attack_type == "IPv6":
            respond_ip = input("Enter IPv6 address to respond with (default: interface IPv6): ") or None
            relay = input("\nAttempt to relay captured hashes? (y/n): ").lower() == 'y'
            post_exploit = False
            if relay:
                post_exploit = input("Attempt post-exploitation on successful relay? (y/n): ").lower() == 'y'
                
            self.poisoning_attacks.start_ipv6_poisoning(interface, respond_ip, relay, post_exploit)
            
        elif attack_type == "WPAD/PAC":
            proxy_ip = input("Enter proxy IP address: ")
            proxy_port = int(input("Enter proxy port (default: 8080): ") or "8080")
            use_ssl = input("Use HTTPS for WPAD? (y/n): ").lower() == 'y'
            
            self.poisoning_attacks.start_wpad_poisoning(interface, proxy_ip, proxy_port, use_ssl)
            
        elif attack_type == "ARP":
            target_ip = input("Enter target IP to poison: ")
            gateway_ip = input("Enter gateway IP: ")
            interval = int(input("Enter interval between packets (seconds, default: 1): ") or "1")
            
            self.poisoning_attacks.start_arp_poisoning(interface, target_ip, gateway_ip, interval)
            
        else:  # Traffic Manipulation
            target_ip = input("Enter target IP: ")
            print("\nSelect protocol to manipulate:")
            print("1. HTTP")
            print("2. SMB")
            protocol = input("\nSelect option (1-2): ")
            protocol = 'http' if protocol == "1" else 'smb'
            
            port = int(input(f"\nEnter {protocol.upper()} port: "))
            
            print("\nSelect manipulation type:")
            print("1. Inject content")
            print("2. Protocol downgrade")
            manip_type = input("\nSelect option (1-2): ")
            manip_type = 'inject' if manip_type == "1" else 'downgrade'
            
            self.poisoning_attacks.start_traffic_manipulation(
                interface, target_ip, protocol, port, manip_type
            )
            
        print("\nPoisoning attack started. Press Enter to stop...")
        print("\nMonitoring for authentication attempts...")
        if 'relay' in locals() and relay:
            print("ntlmrelayx.py started - watching for successful relays...")
            if post_exploit:
                print("Post-exploitation enabled - will attempt secretsdump on admin access...")
        input()
        
        self.poisoning_attacks.stop_poisoning()
        print("\nPoisoning attack stopped")
        input("\nPress Enter to continue...")

    def handle_coercion(self, attack_type: str):
        """
        Handle authentication coercion attacks.
        
        Implements:
        - PetitPotam (MS-EFSR abuse)
        - PrinterBug (MS-RPRN abuse)
        
        The attacks force target systems to authenticate to an attacker-controlled
        system, enabling potential relay attacks.
        
        Args:
            attack_type: Type of coercion attack ("PetitPotam" or "PrinterBug")
        """
        self.clear_screen()
        print(f"\n=== {attack_type} Coercion Attack ===")
        
        # Get list of discovered hosts
        hosts = self.db.get_live_hosts()
        
        if not hosts:
            print("\nNo hosts discovered yet. Please run network scanning first.")
            input("\nPress Enter to continue...")
            return
            
        print("\nDiscovered hosts:")
        for i, (ip, hostname, is_dc) in enumerate(hosts, 1):
            dc_status = "[DC]" if is_dc else ""
            hostname_str = f"({hostname})" if hostname else ""
            print(f"{i}. {ip} {hostname_str} {dc_status}")
            
        try:
            choice = int(input("\nSelect target host number: "))
            if not (1 <= choice <= len(hosts)):
                print("Invalid choice")
                return
                
            target_ip = hosts[choice-1][0]
            listener_ip = input("\nEnter listener IP: ")
            listener_port = int(input("Enter listener port (default: 445): ") or "445")
            
            self.coercion_attacks.set_callback(self.attack_callback)
            
            if attack_type == "PetitPotam":
                success = self.coercion_attacks.petitpotam(target_ip, listener_ip, listener_port)
            else:  # PrinterBug
                success = self.coercion_attacks.printerbug(target_ip, listener_ip, listener_port)
                
            if success:
                print(f"\n{attack_type} coercion successful!")
            else:
                print(f"\n{attack_type} coercion failed")
                
        except ValueError:
            print("Invalid input")
            
        input("\nPress Enter to continue...")

    def handle_time_attacks(self):
        """
        Handle time-based Active Directory attacks.
        
        Implements:
        1. Kerberoasting
           - SPN scanning
           - Ticket requests
           - Hash extraction
        2. Time synchronization attacks
           - DC time skew detection
           - Ticket lifetime abuse
        """
        while True:
            print("\nTime-Based Attacks:")
            print("1. Kerberoasting")
            print("2. Check Time Synchronization")
            print("3. Back")
            
            choice = input("\nEnter choice (1-3): ")
            
            if choice == "1":
                target = input("Enter target domain/DC: ")
                username = input("Enter username (optional, press enter to skip): ").strip()
                password = None
                if username:
                    password = input("Enter password: ").strip()
                    
                print("\nStarting Kerberoasting attack...")
                self.time_attacks.kerberoast(
                    target=target,
                    username=username if username else None,
                    password=password if password else None,
                    callback=self.attack_callback
                )
                
                input("\nPress enter to stop the attack...")
                self.time_attacks.stop()
                
            elif choice == "2":
                target = input("Enter target domain/DC: ")
                
                print("\nChecking time synchronization...")
                self.time_attacks.check_time_sync(
                    target=target,
                    callback=self.attack_callback
                )
                
                input("\nPress enter to stop the check...")
                self.time_attacks.stop()
                
            elif choice == "3":
                break

    def handle_pxe_attacks(self):
        # Implementation of handle_pxe_attacks method
        pass

    def handle_view_results(self):
        self.clear_screen()
        print("\n=== View Attack Results ===")
        
        print("""
1. View Summary of All Findings
2. View Quick Attack Results
3. View Password Spray Results
4. View Bruteforce Results
5. View Captured Hashes
6. View Cleartext Credentials
7. View Coercion Attempts
8. View Time Attack Results
9. View PXE Attack Results
10. Export All Findings
0. Back
""")
        
        choice = input("\nSelect option: ")
        
        if choice == "1":
            self._view_summary()
        elif choice == "2":
            self._view_quick_results()
        elif choice == "3":
            self._view_password_spray_results()
        elif choice == "4":
            self._view_bruteforce_results()
        elif choice == "5":
            self._view_hash_results()
        elif choice == "6":
            self._view_cleartext_results()
        elif choice == "7":
            self._view_coercion_results()
        elif choice == "8":
            self._view_time_results()
        elif choice == "9":
            self._view_pxe_results()
        elif choice == "10":
            self._export_all_findings()
        elif choice == "0":
            return
        else:
            print("Invalid option")

    def _view_summary(self):
        """
        Display comprehensive summary of all findings.
        
        Includes:
        - Domain Information
            * Domain Controllers
            * Trust Relationships
            * ADCS Infrastructure
        - Critical Findings
            * Vulnerabilities by severity
            * Compromised credentials
        - Attack Status
            * Successful exploits
            * Captured hashes/tickets
        """
        self.clear_screen()
        print("\n=== SUMMARY OF ALL FINDINGS ===")
        print("=" * 60)

        # Get statistics
        creds = self.privesc_attacks.get_credentials_from_db()
        cleartext = [c for c in creds if c.get('type') == 'cleartext']
        hashes = [c for c in creds if c.get('type') == 'hash']
        
        # Get critical and high vulnerabilities
        critical_vulns = self.db.get_vulnerabilities(severity='Critical')
        high_vulns = self.db.get_vulnerabilities(severity='High')
        
        # Get domain info
        dc_ip = self.db.get_dc_ip()
        live_hosts = self.db.get_live_hosts()
        users = self.db.get_discovered_users()
        shares = self.db.get_smb_shares()
        asrep = self.db.get_asrep_results()
        services = self.db.get_service_scans()
        trusts = self.db.get_domain_trusts()

        # Display Domain Information
        print("\n[+] DOMAIN INFORMATION:")
        
        # Display Domain Controllers
        dcs = [h for h in live_hosts if h[2]]  # h[2] is is_dc flag
        if dcs:
            print("  [*] Domain Controllers:")
            for dc_ip, hostname, _ in dcs:
                hostname_str = f" ({hostname})" if hostname else ""
                print(f"    • {dc_ip}{hostname_str}")
                # Get DC services and roles
                dc_services = [s for s in services if s[0] == dc_ip]
                for service in dc_services:
                    if service[3] in ['LDAP', 'LDAPS', 'DNS', 'Kerberos', 'SMB']:
                        print(f"      - {service[3]} on port {service[2]}")
        else:
            print("  • No Domain Controllers discovered")

        # Display Trust Relationships
        if trusts:
            print("\n  [*] Domain Trust Relationships:")
            for trust in trusts:
                direction = trust.get('direction', 'Unknown')
                trust_type = trust.get('type', 'Unknown')
                print(f"    • {trust['domain']} ({direction} - {trust_type})")
                if trust.get('vulnerable'):
                    print(f"      ! Potential vulnerabilities: {trust['vulnerable']}")

        # Display ADCS Information
        adcs_servers = []
        for host_ip, hostname, _ in live_hosts:
            # Check for ADCS related services
            host_services = [s for s in services if s[0] == host_ip]
            for service in host_services:
                if any(adcs_svc in str(service[3]).lower() for adcs_svc in ['certsrv', 'pki', 'ca']):
                    adcs_servers.append((host_ip, hostname, service))

        if adcs_servers:
            print("\n  [*] Active Directory Certificate Services:")
            for server_ip, hostname, service in adcs_servers:
                hostname_str = f" ({hostname})" if hostname else ""
                print(f"    • {server_ip}{hostname_str}")
                print(f"      - {service[3]} on port {service[2]}")
                # Check for known ADCS vulnerabilities
                adcs_vulns = [v for v in critical_vulns + high_vulns 
                            if v['host'] == server_ip and 'adcs' in v['type'].lower()]
                if adcs_vulns:
                    print("      ! Vulnerabilities:")
                    for vuln in adcs_vulns:
                        print(f"        - {vuln['type']}: {vuln['description']}")

        # Display general domain stats
        print(f"\n  [*] Domain Statistics:")
        print(f"    • Total Live Hosts: {len(live_hosts)}")
        print(f"    • Users Discovered: {len(users)}")
        print(f"    • SMB Shares: {len(shares)}")
        print(f"    • Trust Relationships: {len(trusts)}")

        # Display Critical Findings
        print("\n[+] CRITICAL FINDINGS:")
        if critical_vulns:
            print("  [!] Critical Vulnerabilities:")
            for vuln in critical_vulns:
                print(f"    • {vuln['type']} on {vuln['host']}")
                print(f"      - {vuln['description']}")
        if high_vulns:
            print("\n  [!] High Severity Vulnerabilities:")
            for vuln in high_vulns:
                print(f"    • {vuln['type']} on {vuln['host']}")
                print(f"      - {vuln['description']}")

        # Display Credential Status
        print("\n[+] CREDENTIAL FINDINGS:")
        if cleartext:
            print("  [!] Cleartext Credentials:")
            for cred in cleartext:
                print(f"    • {cred['username']}@{cred.get('domain', 'WORKGROUP')} ({cred['source']})")
        if hashes:
            print("\n  [!] Password Hashes:")
            print(f"    • Total Unique Hashes: {len(hashes)}")
            for cred in hashes[:3]:  # Show first 3 as example
                print(f"    • {cred['username']} ({cred['source']})")
            if len(hashes) > 3:
                print(f"    • ... and {len(hashes)-3} more")

        # Display Service Information
        if services:
            print("\n[+] INTERESTING SERVICES:")
            service_count = {}
            for service in services:
                svc = service[3]  # service name from tuple
                if svc:
                    service_count[svc] = service_count.get(svc, 0) + 1
            for svc, count in service_count.items():
                print(f"  • {svc}: {count} instances")

        # Display Attack Status
        print("\n[+] ATTACK STATUS:")
        if asrep:
            print(f"  • AS-REP Roastable Accounts: {len(asrep)}")
        spray_results = self.db.get_password_spray_results()
        if spray_results:
            print(f"  • Successful Password Sprays: {len(spray_results)}")
        coercion_results = self.db.get_coercion_attempts()
        if coercion_results:
            successful = sum(1 for r in coercion_results if r[3])  # r[3] is success boolean
            print(f"  • Successful Coercion Attacks: {successful}/{len(coercion_results)}")

        input("\nPress Enter to continue...")

    def _export_all_findings(self):
        """
        Export all attack findings to a JSON report.
        
        Exports:
        - Domain information and structure
        - Discovered vulnerabilities
        - Captured credentials
        - Service enumeration results
        - Attack attempt history
        
        Creates a timestamped report file in the reports directory.
        """
        try:
            findings = {
                "timestamp": datetime.now().isoformat(),
                "domain_info": {
                    "dc_ip": self.db.get_dc_ip(),
                    "live_hosts": self.db.get_live_hosts(),
                    "discovered_users": self.db.get_discovered_users(),
                    "smb_shares": self.db.get_smb_shares()
                },
                "vulnerabilities": {
                    "critical": self.db.get_vulnerabilities(severity='Critical'),
                    "high": self.db.get_vulnerabilities(severity='High'),
                    "medium": self.db.get_vulnerabilities(severity='Medium')
                },
                "credentials": self.privesc_attacks.get_credentials_from_db(),
                "services": self.db.get_service_scans(),
                "attack_results": {
                    "asrep": self.db.get_asrep_results(),
                    "password_spray": self.db.get_password_spray_results(),
                    "coercion": self.db.get_coercion_attempts(),
                    "time_based": self.db.get_time_checks()
                }
            }

            # Create reports directory if it doesn't exist
            os.makedirs('reports', exist_ok=True)
            
            # Generate filename with timestamp
            filename = f"reports/findings_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(filename, 'w') as f:
                json.dump(findings, f, indent=2, default=str)
            
            print(f"\n[+] Successfully exported findings to {filename}")
            
        except Exception as e:
            print(f"\n[-] Error exporting findings: {str(e)}")
        
        input("\nPress Enter to continue...")

    def _view_quick_results(self):
        """View quick attack results"""
        print("\nQuick Attack Results:")
        
        # Get critical vulnerabilities
        critical_vulns = self.db.get_vulnerabilities(severity='Critical')
        if critical_vulns:
            print("\nCritical Vulnerabilities:")
            for vuln in critical_vulns:
                print(f"\nType: {vuln['type']}")
                print(f"Host: {vuln['host']}")
                print(f"Description: {vuln['description']}")
                print(f"Discovered: {vuln['timestamp']}")
                if vuln.get('url'):
                    print(f"URL: {vuln['url']}")
                if vuln.get('port'):
                    print(f"Port: {vuln['port']}")
                
        # Get web vulnerabilities
        web_vulns = self.db.get_vulnerabilities(type='web')
        if web_vulns:
            print("\nWeb Service Vulnerabilities:")
            for vuln in web_vulns:
                print(f"\nType: {vuln['type']}")
                print(f"Host: {vuln['host']}")
                print(f"Description: {vuln['description']}")
                print(f"Severity: {vuln['severity']}")
                print(f"URL: {vuln.get('url', 'N/A')}")
                print(f"Discovered: {vuln['timestamp']}")
                
        if not critical_vulns and not web_vulns:
            print("No quick attack results found")
        
        input("\nPress enter to continue...")

    def _view_password_spray_results(self):
        results = self.db.get_password_spray_results()
        print("\nPassword Spray Results:")
        print("=" * 50)
        for result in results:
            print(f"Domain: {result[1]}")
            print(f"Username: {result[2]}")
            print(f"Password: {result[3]}")
            print(f"Protocol: {result[4]}")
            print(f"Date: {result[5]}")
            print("-" * 30)

    def _view_bruteforce_results(self):
        results = self.db.get_bruteforce_results()
        print("\nBruteforce Results:")
        print("=" * 50)
        for result in results:
            print(f"Domain: {result[1]}")
            print(f"Username: {result[2]}")
            print(f"Password: {result[3]}")
            print(f"Protocol: {result[4]}")
            print(f"Date: {result[5]}")
            print("-" * 30)

    def _view_hash_results(self):
        results = self.db.get_captured_hashes()
        print("\nCaptured Hashes:")
        print("=" * 50)
        for result in results:
            print(f"Source: {result[1]}")
            print(f"Username: {result[2]}")
            print(f"Hash: {result[3]}")
            print(f"Date: {result[4]}")
            print("-" * 30)

    def _view_cleartext_results(self):
        results = self.db.get_cleartext_credentials()
        print("\nCleartext Credentials:")
        print("=" * 50)
        for result in results:
            cred_type = result[3]
            print(f"[!] {cred_type} Credentials:")
            print(f"Source: {result[1]}")
            if result[4]:  # If domain exists
                print(f"Domain: {result[4]}")
            print(f"Username: {result[2]}")
            print(f"Password: {result[5]}")
            print(f"Captured: {result[6]}")
            print("-" * 30)

    def _view_coercion_results(self):
        results = self.db.get_coercion_attempts()
        print("\nCoercion Attempts:")
        print("=" * 50)
        for result in results:
            print(f"Target: {result[1]}")
            print(f"Attack Type: {result[2]}")
            print(f"Success: {'Yes' if result[3] else 'No'}")
            print(f"Date: {result[4]}")
            print("-" * 30)

    def _view_time_results(self):
        """View time-based attack results"""
        print("\nTime Attack Results:")
        
        # Get Kerberoasting results
        kerberoast_results = self.db.get_ticket_hashes(attack_type='Kerberoasting')
        if kerberoast_results:
            print("\nKerberoasting Results:")
            for result in kerberoast_results:
                print(f"\nUsername: {result['username']}")
                print(f"SPN: {result['spn']}")
                print(f"Hash: {result['hash'][:60]}...")
                if 'encryption_type' in result.get('metadata', {}):
                    print(f"Encryption: {result['metadata']['encryption_type']}")
                print(f"Timestamp: {result['timestamp']}")
                
        # Get time sync results
        time_results = self.db.get_time_checks()
        if time_results:
            print("\nTime Synchronization Results:")
            for result in time_results:
                print(f"\nTarget: {result['target']}")
                print(f"Time Difference: {result['time_diff']:.2f} seconds")
                if result.get('metadata', {}).get('vulnerable'):
                    print(f"Vulnerable: {result['metadata']['description']}")
                print(f"Timestamp: {result['timestamp']}")
                
        if not kerberoast_results and not time_results:
            print("No time attack results found")
        
        input("\nPress enter to continue...")

    def _view_pxe_results(self):
        # Implementation of _view_pxe_results method
        pass

    def _get_active_session(self) -> Optional[Dict]:
        """
        Get information about any active attack session.
        
        Checks for:
        1. Active poisoning/MITM sessions
        2. Recent successful relays
        3. Recently captured credentials
        
        Returns:
            Dict containing session info or None if no active session
        """
        # Check poisoning/MITM active session
        if hasattr(self.poisoning_attacks, 'current_session'):
            return self.poisoning_attacks.current_session
        
        # Check recent successful relays
        relay_session = self.db.get_latest_relay_session()
        if relay_session:
            return {
                'username': relay_session['username'],
                'domain': relay_session['domain'],
                'host': relay_session['target_host'],
                'hash': relay_session.get('hash'),
                'password': relay_session.get('password'),
                'source': 'relay'
            }
        
        # Check recent credential captures
        latest_cred = self.db.get_latest_credential()
        if latest_cred:
            return {
                'username': latest_cred['username'],
                'domain': latest_cred.get('domain', ''),
                'hash': latest_cred.get('hash'),
                'password': latest_cred.get('password'),
                'source': latest_cred['source']
            }
        
        return None

    def _suggest_next_actions(self, success_type: str, target_info: Dict):
        """
        Suggest potential next steps based on current success.
        
        Different suggestions based on:
        - Captured hashes -> Try relay or cracking
        - Successful relay -> Check for privesc
        - Privilege escalation -> Extract credentials or lateral movement
        
        Args:
            success_type: Type of successful action
            target_info: Information about the compromised target
        """
        print("\nPossible next actions:")
        
        if success_type == 'hash_capture':
            # Check for relay targets
            relay_targets = self.db.get_smb_targets(signing_required=False)
            if relay_targets:
                print("1. Attempt to relay captured hash")
                print(f"   Found {len(relay_targets)} potential relay targets")
            
            # Check for password cracking options
            print("2. Attempt to crack captured hash")
            print("3. Use hash for pass-the-hash attack")
        
        elif success_type == 'relay':
            print("1. Check for privilege escalation opportunities")
            print("2. Attempt lateral movement")
            print("3. Extract credentials from target")
        
        elif success_type == 'privesc':
            print("1. Extract credentials with elevated privileges")
            print("2. Install persistence mechanism")
            print("3. Pivot to other systems")
        
        choice = input("\nSelect next action (or press enter to continue): ").strip()
        if choice:
            self._handle_next_action(success_type, choice, target_info)

    def _handle_next_action(self, success_type: str, choice: str, target_info: Dict):
        """Handle user's choice of next action"""
        if success_type == 'hash_capture' and choice == '1':
            # Setup relay attack
            self.handle_poisoning('relay', captured_hash=target_info['hash'])
        elif success_type == 'relay' and choice == '1':
            # Check privesc options
            self.handle_privesc('auto', target=target_info['host'])
        elif success_type == 'privesc' and choice == '1':
            # Extract creds with elevated privs
            self.handle_credential_extraction(target_info['host'], elevated=True)

    def handle_privesc(self, attack_type: str, target: Optional[str] = None):
        """
        Handle privilege escalation attacks.
        
        Supports multiple vectors:
        1. Service Hijacking
        2. Token Privileges
        3. Registry Exploits
        4. Scheduled Tasks
        5. Named Pipe Impersonation
        
        Uses active session info or stored credentials for authentication.
        Includes automatic enumeration of potential privesc paths.
        """
        self.clear_screen()
        print(f"\n=== Privilege Escalation - {attack_type} ===")
        
        # Get active session from any module
        session = self._get_active_session()
        
        if not session:
            # No active session, check database for credentials
            creds = self.privesc_attacks.get_credentials_from_db()
            if not creds:
                print("\nNo credentials available. Please capture credentials first.")
                print("\nSuggested actions:")
                print("1. Start LLMNR/NBT-NS poisoning to capture hashes")
                print("2. Attempt password spraying with common credentials")
                print("3. Check for anonymous/null session access")
                input("\nPress Enter to continue...")
                return
            
            print("\nAvailable credentials:")
            for i, cred in enumerate(creds, 1):
                cred_type = "Password" if cred['type'] == 'cleartext' else "Hash"
                print(f"{i}. {cred['username']} ({cred_type}) from {cred['source']}")
                
            try:
                choice = int(input("\nSelect credentials to use (or 0 to cancel): "))
                if choice == 0:
                    return
                if not (1 <= choice <= len(creds)):
                    print("Invalid choice")
                    return
                    
                selected_cred = creds[choice-1]
                session = {
                    'username': selected_cred['username'],
                    'domain': selected_cred.get('domain', ''),
                    'password': selected_cred.get('password'),
                    'hash': selected_cred.get('hash')
                }
            except ValueError:
                print("Invalid input")
                return
                
        # Get target host
        hosts = self.db.get_live_hosts()
        if not hosts:
            print("\nNo hosts discovered yet. Please run network scanning first.")
            input("\nPress Enter to continue...")
            return
            
        print("\nDiscovered hosts:")
        for i, (ip, hostname, is_dc) in enumerate(hosts, 1):
            dc_status = "[DC]" if is_dc else ""
            hostname_str = f"({hostname})" if hostname else ""
            print(f"{i}. {ip} {hostname_str} {dc_status}")
            
        try:
            choice = int(input("\nSelect target host number: "))
            if not (1 <= choice <= len(hosts)):
                print("Invalid choice")
                return
                
            target_ip = hosts[choice-1][0]
            session['host'] = target_ip
            
            # Set the session for privesc attempts
            self.privesc_attacks.set_session(session)
            
            if attack_type == "Service Hijacking":
                self._handle_service_hijack(target_ip)
            elif attack_type == "Token Privileges":
                self._handle_token_privs(target_ip)
            elif attack_type == "Registry Exploits":
                self._handle_registry_exploit(target_ip)
            elif attack_type == "Scheduled Tasks":
                self._handle_scheduled_task(target_ip)
            else:  # Named Pipe Impersonation
                self._handle_named_pipe(target_ip)
                
        except ValueError:
            print("Invalid input")
            
        input("\nPress Enter to continue...")

    def _handle_service_hijack(self, target: str, services: Optional[List[Dict]] = None):
        """
        Handle service hijacking privilege escalation.
        
        Attack process:
        1. Enumerate vulnerable services
        2. Check service permissions
        3. Generate/deploy payload
        4. Trigger service restart
        
        Args:
            target: Target host IP
            services: Optional pre-enumerated vulnerable services
        """
        if not services:
            services = self.privesc_attacks.check_service_hijack(target)
        
        if services:
            print("\nVulnerable services found:")
            for i, service in enumerate(services, 1):
                print(f"{i}. {service['name']} ({service['binary_path']})")
                if service.get('start_type'):
                    print(f"   Start Type: {service['start_type']}")
                if service.get('description'):
                    print(f"   Description: {service['description']}")
                
            try:
                choice = int(input("\nSelect service to exploit (or 0 to cancel): "))
                if choice != 0 and 1 <= choice <= len(services):
                    print("\nPayload options:")
                    print("1. Use custom payload")
                    print("2. Generate reverse shell")
                    print("3. Generate service binary")
                    
                    payload_choice = input("\nSelect payload option: ")
                    
                    if payload_choice == "1":
                        payload = input("\nEnter path to payload executable: ")
                        if not os.path.exists(payload):
                            print("Invalid payload path")
                            return
                    elif payload_choice in ["2", "3"]:
                        # Generate appropriate payload
                        callback_host = input("Enter callback host IP: ")
                        callback_port = input("Enter callback port: ")
                        payload = self._generate_payload(payload_choice, callback_host, callback_port)
                    else:
                        print("Invalid choice")
                        return
                    
                    if self.privesc_attacks.exploit_service_hijack(target, services[choice-1], payload):
                        print("\nService hijack successful!")
                        self._suggest_next_actions('privesc', {'host': target, 'service': services[choice-1]['name']})
                    else:
                        print("\nService hijack failed")
            except ValueError:
                print("Invalid input")
        else:
            print("\nNo vulnerable services found")
            print("\nSuggested actions:")
            print("1. Check for unquoted service paths")
            print("2. Check service DLL hijacking")
            print("3. Try different privilege escalation vector")

    def _handle_token_privs(self, target: str, privs: Optional[Dict] = None):
        """
        Handle token privilege abuse for privilege escalation.
        
        Checks for and exploits:
        - SeImpersonatePrivilege
        - SeDebugPrivilege
        - SeBackupPrivilege
        
        Args:
            target: Target host IP
            privs: Optional pre-enumerated privileges
        """
        if not privs:
            privs = self.privesc_attacks.check_token_privs(target)
        
        if privs:
            print("\nAvailable privileges:")
            exploitable = ['SeImpersonatePrivilege', 'SeDebugPrivilege', 'SeBackupPrivilege']
            available_privs = []
            
            for priv, enabled in privs.items():
                if priv in exploitable:
                    status = "ENABLED" if enabled else "disabled"
                    if enabled:
                        available_privs.append(priv)
                    print(f"- {priv} ({status})")
                    if priv == 'SeImpersonatePrivilege':
                        print("  Can be used for token impersonation attacks")
                    elif priv == 'SeDebugPrivilege':
                        print("  Can be used to access other processes")
                    elif priv == 'SeBackupPrivilege':
                        print("  Can be used to read sensitive files")
                    
            if available_privs:
                priv = input("\nEnter privilege to exploit (or press enter to cancel): ").strip()
                if priv in available_privs:
                    print(f"\nExploiting {priv}...")
                    if self.privesc_attacks.exploit_token_privs(target, priv):
                        print(f"\n{priv} exploitation successful!")
                        self._suggest_next_actions('privesc', {'host': target, 'privilege': priv})
                    else:
                        print(f"\n{priv} exploitation failed")
            else:
                print("\nNo enabled exploitable privileges found")
        else:
            print("\nNo token privileges found")
            print("\nSuggested actions:")
            print("1. Try different privilege escalation vector")
            print("2. Check for service privileges")
            print("3. Look for alternative attack paths")

    def _handle_registry_exploit(self, target: str, reg_keys: Optional[List[Dict]] = None):
        """Handle registry exploitation"""
        if not reg_keys:
            reg_keys = self.privesc_attacks.check_registry_exploits(target)
        
        if reg_keys:
            print("\nVulnerable registry keys found:")
            for i, key in enumerate(reg_keys, 1):
                print(f"{i}. {key['path']}")
                print(f"   Vulnerability: {key['vulnerability']}")
                if key.get('description'):
                    print(f"   Description: {key['description']}")
                
            try:
                choice = int(input("\nSelect registry key to exploit (or 0 to cancel): "))
                if choice != 0 and 1 <= choice <= len(reg_keys):
                    print("\nPayload options:")
                    print("1. Use custom payload")
                    print("2. Generate reverse shell")
                    print("3. Generate registry payload")
                    
                    payload_choice = input("\nSelect payload option: ")
                    
                    if payload_choice == "1":
                        payload = input("\nEnter path to payload executable: ")
                        if not os.path.exists(payload):
                            print("Invalid payload path")
                            return
                    elif payload_choice in ["2", "3"]:
                        callback_host = input("Enter callback host IP: ")
                        callback_port = input("Enter callback port: ")
                        payload = self._generate_payload(payload_choice, callback_host, callback_port)
                    else:
                        print("Invalid choice")
                        return
                    
                    if self.privesc_attacks.exploit_registry(target, reg_keys[choice-1], payload):
                        print("\nRegistry exploit successful!")
                        self._suggest_next_actions('privesc', {'host': target, 'registry': reg_keys[choice-1]['path']})
                    else:
                        print("\nRegistry exploit failed")
            except ValueError:
                print("Invalid input")
        else:
            print("\nNo vulnerable registry keys found")
            print("\nSuggested actions:")
            print("1. Check for autorun locations")
            print("2. Check for weak permissions")
            print("3. Try different privilege escalation vector")

    def _handle_scheduled_task(self, target: str, tasks: Optional[List[Dict]] = None):
        """Handle scheduled task exploitation"""
        if not tasks:
            tasks = self.privesc_attacks.check_scheduled_tasks(target)
        
        if tasks:
            print("\nVulnerable scheduled tasks found:")
            for i, task in enumerate(tasks, 1):
                print(f"{i}. {task['name']} ({task['path']})")
                print(f"   Vulnerability: {task['vulnerability']}")
                if task.get('description'):
                    print(f"   Description: {task['description']}")
                
            try:
                choice = int(input("\nSelect task to exploit (or 0 to cancel): "))
                if choice != 0 and 1 <= choice <= len(tasks):
                    print("\nPayload options:")
                    print("1. Use custom payload")
                    print("2. Generate reverse shell")
                    print("3. Generate task payload")
                    
                    payload_choice = input("\nSelect payload option: ")
                    
                    if payload_choice == "1":
                        payload = input("\nEnter path to payload executable: ")
                        if not os.path.exists(payload):
                            print("Invalid payload path")
                            return
                    elif payload_choice in ["2", "3"]:
                        callback_host = input("Enter callback host IP: ")
                        callback_port = input("Enter callback port: ")
                        payload = self._generate_payload(payload_choice, callback_host, callback_port)
                    else:
                        print("Invalid choice")
                        return
                    
                    if self.privesc_attacks.exploit_scheduled_task(target, tasks[choice-1], payload):
                        print("\nScheduled task exploit successful!")
                        self._suggest_next_actions('privesc', {'host': target, 'task': tasks[choice-1]['name']})
                    else:
                        print("\nScheduled task exploit failed")
            except ValueError:
                print("Invalid input")
        else:
            print("\nNo vulnerable scheduled tasks found")
            print("\nSuggested actions:")
            print("1. Check for weak task permissions")
            print("2. Check for modifiable task directories")
            print("3. Try different privilege escalation vector")

    def _handle_named_pipe(self, target: str, pipes: Optional[List[Dict]] = None):
        """Handle named pipe exploitation"""
        if not pipes:
            pipes = self.privesc_attacks.check_named_pipes(target)
        
        if pipes:
            print("\nVulnerable named pipes found:")
            for i, pipe in enumerate(pipes, 1):
                print(f"{i}. {pipe['name']}")
                print(f"   Vulnerability: {pipe['vulnerability']}")
                if pipe.get('description'):
                    print(f"   Description: {pipe['description']}")
                
            try:
                choice = int(input("\nSelect pipe to exploit (or 0 to cancel): "))
                if choice != 0 and 1 <= choice <= len(pipes):
                    if self.privesc_attacks.exploit_named_pipe(target, pipes[choice-1]):
                        print("\nNamed pipe exploitation successful!")
                        self._suggest_next_actions('privesc', {'host': target, 'pipe': pipes[choice-1]['name']})
                    else:
                        print("\nNamed pipe exploitation failed")
            except ValueError:
                print("Invalid input")
        else:
            print("\nNo vulnerable named pipes found")
            print("\nSuggested actions:")
            print("1. Check for custom named pipes")
            print("2. Check for pipe permissions")
            print("3. Try different privilege escalation vector")

    def _generate_payload(self, payload_type: str, callback_host: str, callback_port: str) -> str:
        """Generate payload for privilege escalation"""
        # Implementation of payload generation
        pass

    def handle_trust_attacks(self):
        """
        Handle Active Directory trust relationship attacks.
        
        Provides capabilities for:
        1. Trust Relationship Enumeration
        2. Foreign Group Membership Detection
        3. Trust Ticket Attacks
        4. SID History Abuse
        
        Uses various tools and techniques to exploit trust relationships
        between domains in a forest or between forests.
        """
        while True:
            self.clear_screen()
            print("\n=== Trust Relationship Attacks ===")
            print("1. Enumerate Trust Relationships")
            print("2. Check for Foreign Group Membership")
            print("3. Exploit Trust Tickets")
            print("4. Check SID History Abuse")
            print("5. Return to Main Menu")
            
            choice = input("\nSelect an option: ")
            
            if choice == "1":
                domain = input("Enter domain name: ")
                dc_ip = input("Enter DC IP: ")
                username = input("Enter username (optional): ")
                password = input("Enter password (optional): ")
                
                self.trust_attacks.enumerate_trusts(
                    domain, dc_ip,
                    username if username else None,
                    password if password else None
                )
                
            elif choice == "2":
                domain = input("Enter domain name: ")
                dc_ip = input("Enter DC IP: ")
                
                foreign_groups = self.trust_attacks.get_foreign_groups(domain, dc_ip)
                if foreign_groups:
                    print("\nFound groups with foreign membership:")
                    for group in foreign_groups:
                        print(f"\n• {group['name']} ({group['domain']})")
                        print("  Foreign Groups:")
                        for fg in group['foreign_groups']:
                            print(f"  - {fg}")
                            
            elif choice == "3":
                domain = input("Enter current domain: ")
                target_domain = input("Enter target trusted domain: ")
                trust_key = input("Enter trust key (NTLM hash or AES key): ")
                username = input("Enter username to impersonate: ")
                sid = input("Enter SID (optional): ")
                
                self.trust_attacks.exploit_trust_ticket(
                    domain, target_domain, trust_key,
                    username, sid if sid else None
                )
                
            elif choice == "4":
                domain = input("Enter current domain: ")
                target_domain = input("Enter target trusted domain: ")
                username = input("Enter username: ")
                password = input("Enter password: ")
                
                self.trust_attacks.exploit_sid_history(
                    domain, target_domain,
                    username, password
                )
                
            elif choice == "5":
                break
                
            input("\nPress Enter to continue...")

    def handle_adcs_attacks(self):
        """
        Handle Active Directory Certificate Services (ADCS) attacks.
        
        Provides a menu-driven interface for:
        1. ADCS Environment Enumeration
        2. ESC1-8 Vulnerability Exploitation
        3. Post-exploitation Actions
            - NTDS.dit extraction
            - Domain Admin account creation
        
        Each option includes proper error handling and user feedback.
        Results are stored in the database for later analysis.
        """
        while True:
            self.clear_screen()
            print("\n=== ADCS Attacks ===")
            print("1. Enumerate ADCS Environment")
            print("2. ESC1 - Web Enrollment Attack")
            print("3. ESC2 - SAN Attribute Attack")
            print("4. ESC3 - Machine Account Attack")
            print("5. ESC4 - Domain Controller Attack")
            print("6. ESC5 - Key Material Archive Attack")
            print("7. ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2")
            print("8. ESC7 - CA Access Control Attack")
            print("9. ESC8 - NTLM Relay Attack")
            print("\nPost-Exploitation:")
            print("10. Extract NTDS.dit")
            print("11. Create Domain Admin")
            print("12. Return to Main Menu")
            
            choice = input("\nSelect an option: ")
            
            if choice == "1":
                domain = input("Enter domain name: ")
                dc_ip = input("Enter DC IP: ")
                username = input("Enter username (optional): ")
                password = input("Enter password (optional): ")
                
                self.coercion_attacks.enumerate_adcs(
                    domain, dc_ip,
                    username if username else None,
                    password if password else None
                )
                
            elif choice == "2":
                domain = input("Enter domain name: ")
                dc_ip = input("Enter DC IP: ")
                username = input("Enter username: ")
                password = input("Enter password: ")
                template = input("Enter vulnerable template name: ")
                
                self.coercion_attacks.exploit_esc1(
                    domain, dc_ip, username,
                    password, template
                )
                
            elif choice == "3":
                domain = input("Enter domain name: ")
                dc_ip = input("Enter DC IP: ")
                username = input("Enter username: ")
                password = input("Enter password: ")
                template = input("Enter vulnerable template name: ")
                target_upn = input("Enter target UPN to impersonate: ")
                
                self.coercion_attacks.exploit_esc2(
                    domain, dc_ip, username,
                    password, template, target_upn
                )
                
            elif choice == "4":
                domain = input("Enter domain name: ")
                dc_ip = input("Enter DC IP: ")
                username = input("Enter username: ")
                password = input("Enter password: ")
                template = input("Enter vulnerable template name: ")
                target_machine = input("Enter target machine name: ")
                
                self.coercion_attacks.exploit_esc3(
                    domain, dc_ip, username,
                    password, template, target_machine
                )
                
            elif choice == "5":
                domain = input("Enter domain name: ")
                dc_ip = input("Enter DC IP: ")
                username = input("Enter username: ")
                password = input("Enter password: ")
                template = input("Enter vulnerable template name: ")
                target_dc = input("Enter target DC name: ")
                
                self.coercion_attacks.exploit_esc4(
                    domain, dc_ip, username,
                    password, template, target_dc
                )
                
            elif choice == "6":
                domain = input("Enter domain name: ")
                dc_ip = input("Enter DC IP: ")
                username = input("Enter username: ")
                password = input("Enter password: ")
                ca_name = input("Enter CA name: ")
                target_user = input("Enter target user to recover key material for: ")
                
                self.coercion_attacks.exploit_esc5(
                    domain, dc_ip, username,
                    password, ca_name, target_user
                )
                
            elif choice == "7":
                domain = input("Enter domain name: ")
                dc_ip = input("Enter DC IP: ")
                username = input("Enter username: ")
                password = input("Enter password: ")
                ca_name = input("Enter CA name: ")
                
                self.coercion_attacks.exploit_esc6(
                    domain, dc_ip, username,
                    password, ca_name
                )
                
            elif choice == "8":
                domain = input("Enter domain name: ")
                dc_ip = input("Enter DC IP: ")
                username = input("Enter username: ")
                password = input("Enter password: ")
                ca_name = input("Enter CA name: ")
                target_template = input("Enter template to modify: ")
                
                self.coercion_attacks.exploit_esc7(
                    domain, dc_ip, username,
                    password, ca_name, target_template
                )
                
            elif choice == "9":
                domain = input("Enter domain name: ")
                dc_ip = input("Enter DC IP: ")
                username = input("Enter username: ")
                password = input("Enter password: ")
                relay_host = input("Enter relay host IP: ")
                
                self.coercion_attacks.exploit_esc8(
                    domain, dc_ip, username,
                    password, relay_host
                )
                
            elif choice == "10":
                domain = input("Enter domain name: ")
                dc_ip = input("Enter DC IP: ")
                username = input("Enter username with Domain Admin rights: ")
                
                print("\nAuthentication method:")
                print("1. Use password")
                print("2. Use certificate")
                auth_choice = input("\nSelect option (1-2): ")
                
                if auth_choice == "1":
                    password = input("Enter password: ")
                    self.coercion_attacks.post_exploit_ntds(
                        domain, dc_ip, username,
                        password=password
                    )
                elif auth_choice == "2":
                    cert_path = input("Enter path to certificate file (.pfx): ")
                    self.coercion_attacks.post_exploit_ntds(
                        domain, dc_ip, username,
                        cert_path=cert_path
                    )
                else:
                    print("Invalid choice")
                    
            elif choice == "11":
                domain = input("Enter domain name: ")
                dc_ip = input("Enter DC IP: ")
                username = input("Enter username with Domain Admin rights: ")
                
                print("\nAuthentication method:")
                print("1. Use password")
                print("2. Use certificate")
                auth_choice = input("\nSelect option (1-2): ")
                
                new_admin = input("\nEnter new admin username (or press enter for random): ").strip()
                new_pass = input("Enter new admin password (or press enter for random): ").strip()
                
                if auth_choice == "1":
                    password = input("Enter current admin password: ")
                    self.coercion_attacks.create_domain_admin(
                        domain, dc_ip, username,
                        password=password,
                        new_admin=new_admin if new_admin else None,
                        new_pass=new_pass if new_pass else None
                    )
                elif auth_choice == "2":
                    cert_path = input("Enter path to certificate file (.pfx): ")
                    self.coercion_attacks.create_domain_admin(
                        domain, dc_ip, username,
                        cert_path=cert_path,
                        new_admin=new_admin if new_admin else None,
                        new_pass=new_pass if new_pass else None
                    )
                else:
                    print("Invalid choice")
                
            elif choice == "12":
                break
                
            input("\nPress Enter to continue...")

    def handle_bloodhound(self):
        """
        Handle BloodHound-based enumeration and analysis.
        
        Provides capabilities for:
        1. Data Collection
        2. Path Analysis
        3. ACL Analysis
        4. Attack Path Suggestions
        
        Integrates with neo4j database and BloodHound GUI in Kali.
        Results are stored for later analysis.
        """
        while True:
            self.clear_screen()
            print("\n=== BloodHound Analysis ===")
            print("1. Setup neo4j Database")
            print("2. Start BloodHound GUI")
            print("3. Collect Domain Data")
            print("4. Analyze Paths to Domain Admin")
            print("5. Find Kerberoastable Users")
            print("6. Analyze Dangerous ACLs")
            print("7. Get Attack Path Suggestions")
            print("8. View Database Statistics")
            print("9. Clear Database")
            print("10. Return to Main Menu")
            
            choice = input("\nSelect an option: ")
            
            if choice == "1":
                password = input("Enter neo4j password (or press enter for default): ")
                if self.bloodhound.setup_neo4j(password if password else None):
                    print("\nNeo4j setup successful")
                else:
                    print("\nNeo4j setup failed")
                    
            elif choice == "2":
                if self.bloodhound.start_bloodhound_gui():
                    print("\nBloodHound GUI started")
                else:
                    print("\nFailed to start BloodHound GUI")
                    
            elif choice == "3":
                domain = input("Enter domain name: ")
                username = input("Enter username (optional): ")
                password = input("Enter password (optional): ")
                
                print("\nSelect collection method:")
                print("1. DCOnly (Lightweight)")
                print("2. Default")
                print("3. All (Most comprehensive)")
                method_choice = input("\nSelect option (1-3): ")
                
                method_map = {
                    "1": "DCOnly",
                    "2": "Default",
                    "3": "All"
                }
                
                if method_choice in method_map:
                    if self.bloodhound.collect_data(
                        domain,
                        username if username else None,
                        password if password else None,
                        collection_method=method_map[method_choice]
                    ):
                        print("\nData collection successful")
                    else:
                        print("\nData collection failed")
                else:
                    print("\nInvalid collection method")
                    
            elif choice == "4":
                domain = input("Enter domain name: ")
                paths = self.bloodhound.analyze_paths_to_da(domain)
                
                if paths:
                    print("\nPaths to Domain Admin:")
                    for i, path in enumerate(paths, 1):
                        print(f"\nPath {i}:")
                        print(f"Start: {path['start_node']}")
                        print(f"End: {path['end_node']}")
                        print(f"Length: {path['length']}")
                        print("Relationships:", ' -> '.join(path['relationships']))
                        
            elif choice == "5":
                domain = input("Enter domain name: ")
                users = self.bloodhound.find_kerberoastable_users(domain)
                
                if users:
                    print("\nKerberoastable Users:")
                    for user in users:
                        print(f"\nUsername: {user['username']}")
                        if user['displayname']:
                            print(f"Display Name: {user['displayname']}")
                        if user['description']:
                            print(f"Description: {user['description']}")
                        if user['title']:
                            print(f"Title: {user['title']}")
                            
            elif choice == "6":
                domain = input("Enter domain name: ")
                acls = self.bloodhound.find_dangerous_acls(domain)
                
                if acls:
                    print("\nDangerous ACL Configurations:")
                    for acl in acls:
                        print(f"\nPrincipal: {acl['principal']}")
                        print(f"Right: {acl['right']}")
                        print(f"Target: {acl['target']}")
                        
            elif choice == "7":
                domain = input("Enter domain name: ")
                current_user = input("Enter current user context: ")
                paths = self.bloodhound.suggest_attack_paths(domain, current_user)
                
                if paths:
                    print("\nSuggested Attack Paths:")
                    for i, path in enumerate(paths, 1):
                        print(f"\nPath {i}:")
                        print(f"Target: {path['target']}")
                        print(f"Attack Path: {' -> '.join(path['attack_path'])}")
                        print(f"Path Length: {path['path_length']}")
                        
            elif choice == "8":
                stats = self.bloodhound.get_database_stats()
                
                if stats:
                    print("\nDatabase Statistics:")
                    for node_type, count in stats.items():
                        print(f"{node_type}: {count}")
                        
            elif choice == "9":
                confirm = input("Are you sure you want to clear the database? (y/n): ")
                if confirm.lower() == 'y':
                    if self.bloodhound.clear_database():
                        print("\nDatabase cleared successfully")
                    else:
                        print("\nFailed to clear database")
                        
            elif choice == "10":
                break
                
            input("\nPress Enter to continue...")

    def suggest_attack_sequence(self, current_state: Dict) -> List[Dict]:
        """
        Suggest next attack sequence based on current state.
        
        Provides intelligent suggestions based on:
        - Discovered hosts and services
        - Current access level
        - BloodHound analysis results
        - Previous attack results
        
        Returns:
            List of suggested attacks with context
        """
        suggestions = []
        
        # Initial enumeration if no hosts discovered
        if not self.db.get_live_hosts():
            suggestions.append({
                'priority': 'High',
                'action': 'Quick Vulnerability Scan',
                'reason': 'No hosts discovered yet - initial enumeration needed',
                'menu_option': 1
            })
            return suggestions
            
        # Get current state information
        hosts = self.db.get_live_hosts()
        services = self.db.get_service_scans()
        creds = self.privesc_attacks.get_credentials_from_db()
        bloodhound_data = self.db.get_bloodhound_collections()
        
        # If we have hosts but no service information
        if hosts and not services:
            suggestions.append({
                'priority': 'High',
                'action': 'Service Enumeration',
                'reason': 'Hosts discovered but services unknown',
                'menu_option': 1
            })
            
        # If we have services that haven't been tested
        untested_services = self.get_untested_services()
        if untested_services:
            suggestions.append({
                'priority': 'High',
                'action': 'Test Discovered Services',
                'reason': f'Found {len(untested_services)} untested services',
                'details': untested_services,
                'menu_option': 1
            })
            
        # If we have no credentials yet
        if not creds:
            suggestions.extend([
                {
                    'priority': 'High',
                    'action': 'AS-REP Roasting',
                    'reason': 'No credentials captured yet - trying unauthenticated attack',
                    'menu_option': 3
                },
                {
                    'priority': 'Medium',
                    'action': 'Password Spray Attack',
                    'reason': 'No credentials captured yet - consider password spray with common passwords',
                    'warning': 'Use with caution - risk of account lockouts',
                    'menu_option': 2
                }
            ])
            
        # If we have credentials but no BloodHound data
        if creds and not bloodhound_data:
            suggestions.append({
                'priority': 'High',
                'action': 'BloodHound Collection',
                'reason': 'Credentials available but no BloodHound analysis performed',
                'menu_option': 8
            })
            
        # If we have BloodHound data, check for attack paths
        if bloodhound_data:
            # Get current user context if available
            session = self._get_active_session()
            if session and session.get('username'):
                paths = self.bloodhound.suggest_attack_paths(
                    session.get('domain', ''),
                    session['username']
                )
                if paths:
                    suggestions.append({
                        'priority': 'High',
                        'action': 'Follow BloodHound Attack Path',
                        'reason': f'Found {len(paths)} potential attack paths to high-value targets',
                        'details': paths[:3],  # Show top 3 paths
                        'menu_option': 8
                    })
                    
            # Check for dangerous ACLs
            acls = self.bloodhound.find_dangerous_acls(session.get('domain', ''))
            if acls:
                suggestions.append({
                    'priority': 'Medium',
                    'action': 'Exploit ACL Vulnerabilities',
                    'reason': f'Found {len(acls)} exploitable ACL configurations',
                    'details': acls[:3],  # Show top 3 ACLs
                    'menu_option': 8
                })
                
        # Check for ADCS presence
        adcs_servers = [s for s in services if any(x in s[3].lower() for x in ['certsrv', 'pki', 'ca'])]
        if adcs_servers:
            suggestions.append({
                'priority': 'High',
                'action': 'ADCS Enumeration',
                'reason': f'Found {len(adcs_servers)} potential ADCS servers',
                'details': adcs_servers,
                'menu_option': 5
            })
            
        return suggestions

    def get_untested_services(self) -> List[Dict]:
        """
        Get list of discovered services that haven't been tested.
        
        Returns:
            List of untested services with context
        """
        services = self.db.get_service_scans()
        tested = self.db.get_tested_services()
        untested = []
        
        for service in services:
            host, port, svc_name = service[0], service[2], service[3]
            if (host, port, svc_name) not in tested:
                untested.append({
                    'host': host,
                    'port': port,
                    'service': svc_name,
                    'suggested_test': self._get_suggested_test(svc_name)
                })
                
        return untested
        
    def _get_suggested_test(self, service_name: str) -> str:
        """Get suggested test based on service type"""
        service_lower = service_name.lower()
        if 'exchange' in service_lower:
            return 'Exchange Vulnerability Check'
        elif 'mssql' in service_lower:
            return 'MSSQL Security Check'
        elif any(x in service_lower for x in ['http', 'web']):
            return 'Web Vulnerability Scan'
        elif 'smb' in service_lower:
            return 'SMB Security Check'
        elif any(x in service_lower for x in ['certsrv', 'pki', 'ca']):
            return 'ADCS Security Check'
        return 'General Service Check'

    def test_discovered_services(self):
        """
        Systematically test discovered services with appropriate checks.
        Includes safety measures and user confirmation for potentially 
        dangerous tests.
        """
        untested = self.get_untested_services()
        if not untested:
            print("\nNo untested services found")
            return
            
        print("\n=== Service Testing ===")
        print(f"Found {len(untested)} untested services:")
        
        for i, svc in enumerate(untested, 1):
            print(f"\n{i}. {svc['service']} on {svc['host']}:{svc['port']}")
            print(f"   Suggested: {svc['suggested_test']}")
            
        print("\nSelect services to test:")
        print("1. Test all services")
        print("2. Select specific services")
        print("3. Cancel")
        
        choice = input("\nEnter choice (1-3): ")
        
        if choice == "1":
            confirm = input("\nWARNING: Testing all services may generate significant traffic.\nContinue? (y/n): ")
            if confirm.lower() != 'y':
                return
                
            for svc in untested:
                self._test_service(svc)
                
        elif choice == "2":
            while True:
                try:
                    svc_nums = input("\nEnter service numbers to test (comma-separated) or 'q' to quit: ")
                    if svc_nums.lower() == 'q':
                        break
                        
                    selected = [untested[int(n)-1] for n in svc_nums.split(',') if n.strip()]
                    for svc in selected:
                        self._test_service(svc)
                        
                except (ValueError, IndexError):
                    print("Invalid input")
                    continue
                    
                more = input("\nTest more services? (y/n): ")
                if more.lower() != 'y':
                    break
                    
    def _test_service(self, service: Dict):
        """
        Test a specific service with appropriate safety measures
        """
        print(f"\nTesting {service['service']} on {service['host']}:{service['port']}")
        
        try:
            if 'exchange' in service['service'].lower():
                self.quick_attacks.check_exchange(service['host'])
            elif 'mssql' in service['service'].lower():
                self.quick_attacks.check_mssql(service['host'])
            elif any(x in service['service'].lower() for x in ['http', 'web']):
                self.quick_attacks.check_web_services(service['host'])
            elif 'smb' in service['service'].lower():
                # Only check for basic vulnerabilities, no exploitation
                self.quick_attacks.check_smb(service['host'], safe_mode=True)
            elif any(x in service['service'].lower() for x in ['certsrv', 'pki', 'ca']):
                # Only enumerate ADCS, no exploitation
                self.coercion_attacks.enumerate_adcs(
                    domain=self.db.get_domain(),
                    dc_ip=service['host']
                )
                
            # Mark service as tested
            self.db.add_tested_service(
                service['host'],
                service['port'],
                service['service']
            )
            
        except Exception as e:
            print(f"Error testing service: {str(e)}")

    def integrate_bloodhound_findings(self):
        """
        Integrate BloodHound analysis results into the attack workflow
        """
        print("\n=== BloodHound Integration ===")
        
        # Get current session context
        session = self._get_active_session()
        if not session:
            print("\nNo active session - run BloodHound collection first")
            return
            
        domain = session.get('domain', '')
        if not domain:
            domain = input("\nEnter domain name: ")
            
        # Get attack paths
        paths = self.bloodhound.suggest_attack_paths(domain, session['username'])
        if paths:
            print("\nPotential Attack Paths:")
            for i, path in enumerate(paths, 1):
                print(f"\n{i}. Target: {path['target']}")
                print(f"   Path Length: {path['path_length']}")
                print(f"   Attack Path: {' -> '.join(path['attack_path'])}")
                
            print("\nSelect action:")
            print("1. Attempt path exploitation")
            print("2. Show detailed path analysis")
            print("3. Export paths to report")
            print("4. Cancel")
            
            choice = input("\nEnter choice (1-4): ")
            
            if choice == "1":
                path_num = int(input("\nSelect path number to attempt: "))
                if 1 <= path_num <= len(paths):
                    self._attempt_attack_path(paths[path_num-1])
            elif choice == "2":
                path_num = int(input("\nSelect path number to analyze: "))
                if 1 <= path_num <= len(paths):
                    self._analyze_attack_path(paths[path_num-1])
            elif choice == "3":
                self._export_attack_paths(paths)
                
        # Get dangerous ACLs
        acls = self.bloodhound.find_dangerous_acls(domain)
        if acls:
            print("\nDangerous ACL Configurations:")
            for i, acl in enumerate(acls, 1):
                print(f"\n{i}. Principal: {acl['principal']}")
                print(f"   Right: {acl['right']}")
                print(f"   Target: {acl['target']}")
                
        # Get Kerberoastable users
        users = self.bloodhound.find_kerberoastable_users(domain)
        if users:
            print("\nKerberoastable Users Found:")
            print("Consider running Kerberoasting attack")
            
        input("\nPress Enter to continue...")

    def display_banner(self):
        """Display the ASCII art banner"""
        os.system('clear' if os.name == 'posix' else 'cls')
        print(self.banner)
        print(f"{Fore.RED}⚠️  Warning: Use responsibly and only on systems you have permission to test{Style.RESET_ALL}\n")

    def display_menu(self):
        """Display the main menu"""
        self.display_banner()
        print(f"{Fore.GREEN}Available Attack Options:{Style.RESET_ALL}")
        print("1. Quick Vulnerability Scan")
        print("2. Password Attacks")
        print("3. Network Poisoning")
        print("4. Coercion Attacks")
        print("5. ADCS Attacks")
        print("6. Trust Relationship Attacks")
        print("7. Privilege Escalation")
        print("8. BloodHound Analysis")
        print("9. Domain Persistence")
        print("10. View Results")
        print("11. Export Results")
        print("0. Exit")
        print()

    def handle_menu(self):
        """Handle menu selection"""
        while True:
            self.display_menu()
            choice = input(f"{Fore.YELLOW}Select an option: {Style.RESET_ALL}")
            
            if choice == "0":
                print(f"{Fore.GREEN}Goodbye! Thanks for using the AD Attack Framework{Style.RESET_ALL}")
                sys.exit(0)
            elif choice == "1":
                self.handle_quick_scan()
            elif choice == "2":
                self.handle_password_attacks()
            elif choice == "3":
                self.handle_poisoning()
            elif choice == "4":
                self.handle_coercion()
            elif choice == "5":
                self.handle_adcs()
            elif choice == "6":
                self.handle_trust()
            elif choice == "7":
                self.handle_privesc()
            elif choice == "8":
                self.handle_bloodhound()
            elif choice == "9":
                self.handle_persistence()
            elif choice == "10":
                self.view_results()
            elif choice == "11":
                self.export_results()
            else:
                print(f"{Fore.RED}Invalid option. Please try again.{Style.RESET_ALL}")
                input("Press Enter to continue...")

    def run(self):
        while True:
            self.clear_screen()
            
            # Get attack suggestions
            current_state = {
                'valid_credentials': bool(self.privesc_attacks.get_credentials_from_db()),
                'network_access': bool(self.db.get_live_hosts()),
                'active_session': self._get_active_session()
            }
            suggestions = self.suggest_attack_sequence(current_state)
            
            # Display menu with suggestions
            print("\n=== Active Directory Attack Menu ===")
            if suggestions:
                print("\n[!] Suggested Next Actions:")
                for suggestion in suggestions:
                    print(f"\n• {suggestion['action']} (Priority: {suggestion['priority']})")
                    print(f"  Reason: {suggestion['reason']}")
                    if suggestion.get('warning'):
                        print(f"  Warning: {suggestion['warning']}")
                print("\n" + "="*50 + "\n")
            
            print("1. Quick Vulnerability Scan")
            print("2. Password Spray Attack")
            print("3. AS-REP Roasting")
            print("4. Kerberoasting")
            print("5. ADCS Attacks")
            print("6. Trust Relationship Attacks")
            print("7. Coercion Attacks")
            print("8. BloodHound Analysis")
            print("9. View Results")
            print("10. Export All Findings")
            print("11. Exit")
            
            choice = input("\nSelect an option: ")
            
            try:
                if choice == "1":
                    self.handle_quick_scan()
                elif choice == "2":
                    self.handle_password_spray()
                elif choice == "3":
                    self.handle_poisoning()
                elif choice == "4":
                    self.handle_coercion()
                elif choice == "5":
                    self.handle_adcs_attacks()
                elif choice == "6":
                    self.handle_trust_attacks()
                elif choice == "7":
                    self.handle_privesc()
                elif choice == "8":
                    self.handle_bloodhound()
                elif choice == "9":
                    self.handle_persistence()
                elif choice == "10":
                    self.handle_view_results()
                elif choice == "11":
                    print("\nExiting...")
                    break
                else:
                    print("\nInvalid option selected")
                    
            except Exception as e:
                print(f"\nError: {str(e)}")
                
            if choice != "11":
                input("\nPress Enter to continue...") 