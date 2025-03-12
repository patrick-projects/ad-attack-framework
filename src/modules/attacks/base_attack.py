"""
Base Attack Module

This module defines the base class for all attack modules. It provides:
- Common interface methods
- Logging and output formatting
- Result handling
- Tool checking
- Configuration management
"""

from typing import Optional, Dict, List, Union, Callable
import logging
import shutil
import subprocess
import json
from datetime import datetime
from pathlib import Path
from abc import ABC, abstractmethod

class BaseAttack(ABC):
    """Base class for all attack modules"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.results = {
            'success': False,
            'timestamp': None,
            'target': None,
            'findings': [],
            'credentials': [],
            'vulnerabilities': [],
            'attack_path': [],
            'artifacts': []
        }
        self._check_required_tools()
    
    @property
    @abstractmethod
    def required_tools(self) -> Dict[str, str]:
        """
        Dictionary of required tools and their package names
        Example: {'impacket-secretsdump': 'impacket-scripts'}
        """
        return {}
        
    @property
    @abstractmethod
    def attack_type(self) -> str:
        """Type of attack (e.g., 'no_creds', 'mitm', etc.)"""
        return ""
        
    @property
    @abstractmethod
    def prerequisites(self) -> List[str]:
        """List of prerequisites for this attack to work"""
        return []
        
    def _check_required_tools(self) -> None:
        """Verify all required tools are installed"""
        missing_tools = []
        for tool, package in self.required_tools.items():
            if not shutil.which(tool):
                missing_tools.append(f"{tool} ({package})")
        
        if missing_tools:
            raise RuntimeError(f"Missing required tools: {', '.join(missing_tools)}. Please install using 'apt install'")
    
    def check_prerequisites(self, target: str) -> bool:
        """
        Check if prerequisites are met for this attack
        
        Args:
            target: Target to check prerequisites against
            
        Returns:
            bool: True if prerequisites are met, False otherwise
        """
        # Implement basic prerequisite checking
        # Subclasses should override for specific checks
        return True
        
    def run(self, target: str, options: Optional[Dict] = None, 
            callback: Optional[Callable] = None) -> Dict:
        """
        Run the attack module
        
        Args:
            target: Target to attack
            options: Optional configuration options
            callback: Optional callback for progress updates
            
        Returns:
            Dict: Results of the attack
        """
        try:
            self.results['timestamp'] = datetime.now().isoformat()
            self.results['target'] = target
            
            if not self.check_prerequisites(target):
                self.logger.error("Prerequisites not met")
                return self.results
                
            if callback:
                callback('progress', {'message': f'Starting {self.__class__.__name__} attack'})
                
            # Run the actual attack implementation
            success = self._run_attack(target, options, callback)
            self.results['success'] = success
            
            if callback:
                callback('complete', {
                    'success': success,
                    'findings': len(self.results['findings'])
                })
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"Attack error: {str(e)}")
            if callback:
                callback('error', {'message': str(e)})
            return self.results
    
    @abstractmethod
    def _run_attack(self, target: str, options: Optional[Dict] = None,
                    callback: Optional[Callable] = None) -> bool:
        """
        Implement the actual attack logic
        
        Args:
            target: Target to attack
            options: Optional configuration options
            callback: Optional callback for progress updates
            
        Returns:
            bool: True if attack was successful, False otherwise
        """
        pass
        
    def add_finding(self, finding: Dict) -> None:
        """Add a finding to the results"""
        if 'timestamp' not in finding:
            finding['timestamp'] = datetime.now().isoformat()
        self.results['findings'].append(finding)
        
    def add_credential(self, credential: Dict) -> None:
        """Add a credential to the results"""
        if 'timestamp' not in credential:
            credential['timestamp'] = datetime.now().isoformat()
        self.results['credentials'].append(credential)
        
    def add_vulnerability(self, vulnerability: Dict) -> None:
        """Add a vulnerability to the results"""
        if 'timestamp' not in vulnerability:
            vulnerability['timestamp'] = datetime.now().isoformat()
        self.results['vulnerabilities'].append(vulnerability)
        
    def add_artifact(self, artifact: Dict) -> None:
        """Add an artifact to the results"""
        if 'timestamp' not in artifact:
            artifact['timestamp'] = datetime.now().isoformat()
        self.results['artifacts'].append(artifact)
        
    def save_results(self, output_file: Union[str, Path]) -> None:
        """Save results to a file"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
            
    def load_results(self, input_file: Union[str, Path]) -> None:
        """Load results from a file"""
        with open(input_file, 'r') as f:
            self.results = json.load(f)
            
    def run_cmd(self, cmd: List[str], silent: bool = False,
                callback: Optional[Callable] = None) -> subprocess.CompletedProcess:
        """
        Run a command and handle output
        
        Args:
            cmd: Command to run as list of strings
            silent: Whether to suppress output
            callback: Optional callback for progress updates
            
        Returns:
            CompletedProcess: Result of the command
        """
        try:
            if not silent and callback:
                callback('progress', {'message': f"Running: {' '.join(cmd)}"})
                
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            if not silent and callback:
                callback('output', {'output': process.stdout})
                
            return process
            
        except subprocess.CalledProcessError as e:
            if not silent:
                self.logger.error(f"Command failed: {str(e)}")
                if callback:
                    callback('error', {'message': str(e)})
            raise 