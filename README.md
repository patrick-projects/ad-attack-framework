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

Inspired by; https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap_ad_dark_classic_2025.03.excalidraw.svg
```

## ⚠️ Legal Disclaimer

This software is provided for educational and authorized testing purposes ONLY. Usage of this framework for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws.

**Requirements for Usage:**
- Explicit written permission from the owner of the systems you are testing
- Compliance with all relevant laws and regulations
- Testing only in authorized environments
- Understanding and accepting all risks and responsibilities

Developers assume no liability and are not responsible for any misuse or damage caused by this program.

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

## Acknowledgments

This framework was inspired by and builds upon the work of many security researchers and projects:

### Direct Inspiration
- Orange Cyberdefense's [GOAD (Game of Active Directory)](https://github.com/Orange-Cyberdefense/GOAD)
- SpecterOps' [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [Impacket](https://github.com/fortra/impacket)
- Laurent Gaffié's [Responder](https://github.com/lgandx/Responder)

### Additional Credits
- Will Schroeder (@harmj0y) and Lee Christensen (@tifkin_)'s research on Active Directory security
- Sean Metcalf's (@PyroTek3) Active Directory security research
- The [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) project
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
- All contributors to the Active Directory Security community

## Author

Patrick Crumbaugh

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 