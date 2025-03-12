# Active Directory Attack Framework

A comprehensive Active Directory penetration testing framework developed by Patrick Crumbaugh.

```
    /\___/\  Active Directory
   (  o o  )  Attack Framework
   (  =^=  ) 
    (--m--)  
   /      \    
  /        \   Made with 😺 by
 /          \  Patrick Crumbaugh
/            \ 
```

## Features

- **Quick Vulnerability Scanning**
  - Critical vulnerabilities
  - Exchange server vulnerabilities
  - Web application vulnerabilities
  - MSSQL server misconfigurations
  - Backup software vulnerabilities
  - Application server issues

- **Password Attacks**
  - Password spraying
  - Password bruteforce
  - AS-REP Roasting
  - Kerberoasting

- **Network Poisoning/MITM**
  - LLMNR/NBT-NS/mDNS poisoning
  - IPv6 DNS takeover
  - WPAD/PAC injection
  - ARP poisoning
  - Traffic manipulation

- **Authentication Coercion**
  - PetitPotam
  - PrinterBug
  - Other MS-RPC abuse

- **ADCS Attacks**
  - ESC1-8 implementations
  - Certificate template abuse
  - NTLM relay to ADCS

- **Domain Persistence**
  - Golden Tickets
  - Silver Tickets
  - Diamond Tickets
  - Skeleton Key
  - Custom SSP
  - DSRM modifications

- **BloodHound Integration**
  - Automated data collection
  - Attack path analysis
  - ACL abuse detection
  - Integrated attack suggestions

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/ad-attack-framework.git
cd ad-attack-framework
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Install additional system requirements (Kali Linux):
```bash
sudo apt install -y bloodhound neo4j responder impacket-scripts
```

## Usage

Run the main script:
```bash
python3 src/main.py
```

The framework provides an interactive menu-driven interface with:
- Automated attack suggestions
- Real-time feedback
- Result tracking
- Report generation

## Testing Environment

For testing, use the provided lab setup scripts in `scripts/lab_setup/`:
- Domain Controller (Windows Server 2019)
- Member Server (Windows Server 2019)
- Client Machine (Windows 10)
- Attack Machine (Kali Linux)

See `scripts/lab_setup/README.md` for detailed setup instructions.

## Security Notice

⚠️ This framework is for educational and authorized testing purposes only. Use responsibly and only on systems you have permission to test.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Patrick Crumbaugh

## Acknowledgments

- The BloodHound Project
- Impacket Project
- Responder Project
- Other open-source security tools and their contributors 