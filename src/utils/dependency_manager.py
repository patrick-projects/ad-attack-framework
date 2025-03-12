"""
Dependency management utilities for ensuring required packages are installed
and handling package installation/verification.
"""

import subprocess
import sys
import pkg_resources
import os
from typing import List, Dict, Optional
import platform

class DependencyManager:
    def __init__(self):
        self.required_packages = {
            'impacket': '0.10.0',
            'cryptography': '41.0.1',
            'pyOpenSSL': '23.2.0',
            'ldap3': '2.9.1',
            'dnspython': '2.4.2',
            'requests': '2.31.0',
            'pyasn1': '0.5.0',
            'scapy': '2.5.0'
        }
        
        self.binary_dependencies = {
            'linux': [
                'gcc',
                'make',
                'python3-dev',
                'libssl-dev',
                'libffi-dev',
                'build-essential'
            ],
            'darwin': [
                'gcc',
                'make',
                'python3',
                'openssl',
                'libffi'
            ]
        }
        
    def check_python_packages(self) -> List[str]:
        """Check which required Python packages are missing"""
        missing = []
        for package, version in self.required_packages.items():
            try:
                pkg_resources.require(f"{package}>={version}")
            except (pkg_resources.DistributionNotFound, pkg_resources.VersionConflict):
                missing.append(package)
        return missing
        
    def install_python_packages(self, packages: List[str]) -> bool:
        """Install missing Python packages"""
        try:
            for package in packages:
                version = self.required_packages[package]
                print(f"Installing {package}>={version}...")
                subprocess.check_call([
                    sys.executable, 
                    "-m", 
                    "pip", 
                    "install", 
                    f"{package}>={version}"
                ])
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error installing packages: {str(e)}")
            return False
            
    def check_binary_dependencies(self) -> List[str]:
        """Check which required system binaries are missing"""
        system = platform.system().lower()
        if system not in self.binary_dependencies:
            return []
            
        missing = []
        for binary in self.binary_dependencies[system]:
            if not self._check_binary_exists(binary):
                missing.append(binary)
        return missing
        
    def install_binary_dependencies(self, packages: List[str]) -> bool:
        """Install missing system binaries"""
        system = platform.system().lower()
        
        if system == 'linux':
            try:
                # Try apt-get first
                subprocess.check_call([
                    "sudo",
                    "apt-get",
                    "update"
                ])
                subprocess.check_call([
                    "sudo",
                    "apt-get",
                    "install",
                    "-y"
                ] + packages)
                return True
            except subprocess.CalledProcessError:
                try:
                    # Try yum if apt-get fails
                    subprocess.check_call([
                        "sudo",
                        "yum",
                        "install",
                        "-y"
                    ] + packages)
                    return True
                except subprocess.CalledProcessError as e:
                    print(f"Error installing packages: {str(e)}")
                    return False
                    
        elif system == 'darwin':
            try:
                # Use homebrew on macOS
                if not self._check_binary_exists('brew'):
                    print("Homebrew not found. Please install Homebrew first.")
                    return False
                    
                subprocess.check_call([
                    "brew",
                    "install"
                ] + packages)
                return True
            except subprocess.CalledProcessError as e:
                print(f"Error installing packages: {str(e)}")
                return False
                
        return False
        
    def _check_binary_exists(self, binary: str) -> bool:
        """Check if a binary exists in PATH"""
        try:
            subprocess.check_call(
                ["which", binary],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return True
        except subprocess.CalledProcessError:
            return False
            
    def check_and_install_all(self) -> bool:
        """Check and install all dependencies"""
        # Check Python packages
        missing_packages = self.check_python_packages()
        if missing_packages:
            print("\nMissing Python packages:")
            for package in missing_packages:
                print(f"- {package}>={self.required_packages[package]}")
            
            install = input("\nInstall missing Python packages? (y/n): ").lower() == 'y'
            if install:
                if not self.install_python_packages(missing_packages):
                    return False
            else:
                return False
                
        # Check binary dependencies
        missing_binaries = self.check_binary_dependencies()
        if missing_binaries:
            print("\nMissing system dependencies:")
            for binary in missing_binaries:
                print(f"- {binary}")
            
            install = input("\nInstall missing system dependencies? (y/n): ").lower() == 'y'
            if install:
                if not self.install_binary_dependencies(missing_binaries):
                    return False
            else:
                return False
                
        return True 