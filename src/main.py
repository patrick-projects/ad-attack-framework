import logging
import argparse
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional
import os

from config.config import ADConfig, LoggingConfig
from modules.scanning.scanner import NetworkScanner
from modules.attacks.attack import ADAttacker
from modules.scanning.menu import ScanningMenu

class ADPentestOrchestrator:
    def __init__(self, config: ADConfig):
        self.config = config
        self.scanner = NetworkScanner()
        self.attacker = ADAttacker(config)
        self.setup_logging()
        
    def setup_logging(self):
        """
        Configure logging for the application
        """
        logging.basicConfig(
            level=getattr(logging, self.config.log_level),
            format=self.config.log_format,
            filename=self.config.log_file
        )
        self.logger = logging.getLogger(__name__)
        
        # Also log to console
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

    def run_assessment(self, target_subnet: str) -> Dict:
        """
        Run the complete AD assessment
        """
        results = {
            "timestamp": datetime.now().isoformat(),
            "target_domain": self.config.target_domain,
            "scan_results": {},
            "vulnerabilities": [],
            "attack_paths": []
        }
        
        try:
            # Phase 1: Network Discovery
            self.logger.info("Starting network discovery...")
            hosts = self.scanner.scan_network(target_subnet)
            results["scan_results"]["hosts"] = hosts
            
            # Phase 2: AD Enumeration
            self.logger.info("Starting AD enumeration...")
            ldap_results = self.scanner.enumerate_ldap()
            results["scan_results"]["ldap"] = ldap_results
            
            # Phase 3: Security Checks
            self.logger.info("Checking security configurations...")
            for host in hosts:
                smb_signing = self.scanner.check_smb_signing(host)
                if not smb_signing:
                    results["vulnerabilities"].append({
                        "host": host,
                        "type": "smb_signing_disabled",
                        "severity": "HIGH"
                    })
                    
            # Phase 4: Kerberos Attacks
            self.logger.info("Checking Kerberos vulnerabilities...")
            spn_list = [user["userPrincipalName"] for user in ldap_results["users"] 
                       if "userPrincipalName" in user]
            kerberoast_results = self.attacker.kerberoast(spn_list)
            if kerberoast_results:
                results["vulnerabilities"].append({
                    "type": "kerberoastable_accounts",
                    "accounts": list(kerberoast_results.keys()),
                    "severity": "HIGH"
                })
                
            # Phase 5: Check for Zero Logon
            self.logger.info("Checking for Zerologon vulnerability...")
            zerologon_result = self.attacker.zerologon_check()
            if zerologon_result["vulnerable"]:
                results["vulnerabilities"].append({
                    "type": "zerologon",
                    "details": zerologon_result["details"],
                    "severity": "CRITICAL"
                })
                
            # Save results
            self._save_results(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Assessment failed: {str(e)}")
            results["error"] = str(e)
            return results
            
    def _save_results(self, results: Dict):
        """
        Save assessment results to file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = Path(LoggingConfig.REPORT_DIRECTORY)
        report_dir.mkdir(exist_ok=True)
        
        report_file = report_dir / f"ad_assessment_{timestamp}.json"
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=4)
            
class MainMenu:
    def __init__(self):
        self.scanning_menu = ScanningMenu()
        self.show_legal_disclaimer()

    def show_legal_disclaimer(self):
        self.clear_screen()
        disclaimer = """
⚠️  LEGAL DISCLAIMER - READ CAREFULLY  ⚠️

This Active Directory Attack Framework is provided for EDUCATIONAL and AUTHORIZED TESTING PURPOSES ONLY.

By proceeding, you agree to the following conditions:
1. You have EXPLICIT WRITTEN PERMISSION from the owner of any systems you test
2. You will comply with all applicable local, state, and federal laws
3. You will only use this tool in authorized testing environments
4. You accept all risks and responsibilities associated with using this tool

The developers assume no liability and are not responsible for any misuse or damage.

Unauthorized testing of systems is ILLEGAL and may result in criminal charges.
"""
        print(disclaimer)
        input("\nPress Enter to acknowledge and continue...")

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_menu(self):
        self.clear_screen()
        print("""
╔══════════════════════════════════════╗
║    AD Penetration Testing Suite      ║
║        ⚠️  USE RESPONSIBLY ⚠️         ║
╠══════════════════════════════════════╣
║ 1. Network Scanning                  ║
║ 2. Attack Vectors (Coming Soon)      ║
║ 3. Persistence (Coming Soon)         ║
║ 4. Settings                          ║
║ 0. Exit                             ║
╚══════════════════════════════════════╝
""")

    def handle_settings(self):
        self.clear_screen()
        print("\n=== Settings ===")
        print("\nNo settings available yet.")
        input("\nPress Enter to continue...")

    def run(self):
        while True:
            self.print_menu()
            choice = input("\nSelect option: ")
            
            if choice == "1":
                self.scanning_menu.run()
            elif choice == "2":
                print("\nAttack vectors module coming soon!")
                input("\nPress Enter to continue...")
            elif choice == "3":
                print("\nPersistence module coming soon!")
                input("\nPress Enter to continue...")
            elif choice == "4":
                self.handle_settings()
            elif choice == "0":
                print("\nGoodbye!")
                break
            else:
                print("Invalid option")

def main():
    parser = argparse.ArgumentParser(description="Active Directory Penetration Testing Automation")
    parser.add_argument("--domain", required=True, help="Target domain")
    parser.add_argument("--dc-ip", required=True, help="Domain Controller IP")
    parser.add_argument("--username", help="Username for authentication")
    parser.add_argument("--password", help="Password for authentication")
    parser.add_argument("--subnet", required=True, help="Target subnet (e.g. 192.168.1.0/24)")
    
    args = parser.parse_args()
    
    config = ADConfig(
        target_domain=args.domain,
        dc_ip=args.dc_ip,
        username=args.username or "",
        password=args.password or ""
    )
    
    orchestrator = ADPentestOrchestrator(config)
    results = orchestrator.run_assessment(args.subnet)
    
    if results.get("error"):
        print(f"Assessment failed: {results['error']}")
        return 1
        
    print(f"Assessment completed. Results saved to {LoggingConfig.REPORT_DIRECTORY}")
    return 0

if __name__ == "__main__":
    menu = MainMenu()
    menu.run() 