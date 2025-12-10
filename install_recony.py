#!/usr/bin/env python3
"""
Recony Installation Script
A professional installation script for the Recony Web Reconnaissance Tool.
Handles dependency checks, directory setup, and configuration.
"""

import os
import sys
import platform
import subprocess
import urllib.request
import urllib.error
import ssl
import shutil
import hashlib
from pathlib import Path
from typing import List, Tuple, Dict, Optional


class ReconyInstaller:
    """
    Professional installation manager for Recony Web Reconnaissance Tool.
    Handles system checks, dependency validation, and environment setup.
    """
    
    def __init__(self):
        self.script_dir = Path(__file__).parent
        self.install_dir = self.script_dir
        self.required_python_version = (3, 6)
        self.python_cmd = None
        
        # Required module files
        self.required_files = [
            "recony.py",
            "network_scan.py", 
            "dns_enum.py",
            "whois_module.py",
            "ssl_tls_enum.py",
            "http_fingerprint.py",
            "dir_enum.py",
            "subdomain_enum.py",
            "report_generator.py"
        ]
        
        # Wordlist URLs and destinations
        self.wordlists = {
            "common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
            "subdomains-top1million-5000.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
        }
        
        # Color codes for terminal output
        self.colors = {
            'RED': '\033[0;31m',
            'GREEN': '\033[0;32m', 
            'YELLOW': '\033[1;33m',
            'BLUE': '\033[0;34m',
            'NC': '\033[0m'
        }
        
    def log_info(self, message: str) -> None:
        """Log informational message."""
        print(f"{self.colors['BLUE']}[INFO]{self.colors['NC']} {message}")
        
    def log_success(self, message: str) -> None:
        """Log success message."""
        print(f"{self.colors['GREEN']}[SUCCESS]{self.colors['NC']} {message}")
        
    def log_warning(self, message: str) -> None:
        """Log warning message."""
        print(f"{self.colors['YELLOW']}[WARNING]{self.colors['NC']} {message}")
        
    def log_error(self, message: str) -> None:
        """Log error message."""
        print(f"{self.colors['RED']}[ERROR]{self.colors['NC']} {message}")

    def check_python_version(self) -> bool:
        """
        Check if Python version meets requirements.
        
        Returns:
            bool: True if Python version is sufficient
        """
        try:
            version = sys.version_info
            self.log_info(f"Python version: {sys.version}")
            
            if (version.major, version.minor) >= self.required_python_version:
                self.log_success(f"Python version meets requirement {self.required_python_version[0]}.{self.required_python_version[1]}+")
                return True
            else:
                self.log_error(f"Python {self.required_python_version[0]}.{self.required_python_version[1]}+ required, found {version.major}.{version.minor}")
                return False
                
        except Exception as e:
            self.log_error(f"Failed to check Python version: {e}")
            return False

    def check_required_modules(self) -> bool:
        """
        Check if all required Python modules are available.
        
        Returns:
            bool: True if all modules are available
        """
        required_modules = [
            'socket', 'json', 'logging', 'argparse', 'urllib', 'ssl', 
            'threading', 'queue', 're', 'time', 'datetime', 'pathlib'
        ]
        
        missing_modules = []
        
        for module in required_modules:
            try:
                __import__(module)
                self.log_info(f"Module available: {module}")
            except ImportError as e:
                missing_modules.append(module)
                self.log_error(f"Module missing: {module} - {e}")
        
        if not missing_modules:
            self.log_success("All required Python modules are available")
            return True
        else:
            self.log_error(f"Missing modules: {', '.join(missing_modules)}")
            return False

    def validate_installation_files(self) -> Tuple[bool, List[str]]:
        """
        Validate that all required module files exist and are valid Python.
        
        Returns:
            Tuple of (is_valid, missing_files)
        """
        missing_files = []
        valid_files = []
        
        for filename in self.required_files:
            file_path = self.install_dir / filename
            
            if not file_path.exists():
                missing_files.append(filename)
                self.log_error(f"Missing file: {filename}")
                continue
                
            # Validate Python syntax
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    compile(f.read(), filename, 'exec')
                valid_files.append(filename)
                self.log_success(f"Valid Python file: {filename}")
            except SyntaxError as e:
                missing_files.append(filename)
                self.log_error(f"Invalid Python syntax in {filename}: {e}")
            except Exception as e:
                missing_files.append(filename)
                self.log_error(f"Error reading {filename}: {e}")
        
        if not missing_files:
            self.log_success("All required files validated successfully")
            return True, []
        else:
            self.log_error(f"Missing or invalid files: {', '.join(missing_files)}")
            return False, missing_files

    def create_directory_structure(self) -> bool:
        """
        Create necessary directory structure for Recony.
        
        Returns:
            bool: True if directories created successfully
        """
        directories = [
            "results",
            "logs", 
            "wordlists",
            "backups"
        ]
        
        try:
            for dir_name in directories:
                dir_path = self.install_dir / dir_name
                dir_path.mkdir(exist_ok=True)
                self.log_success(f"Created directory: {dir_name}")
            
            # Set permissions on Unix-like systems
            if platform.system() in ['Linux', 'Darwin']:
                for dir_name in ['results', 'logs', 'wordlists']:
                    dir_path = self.install_dir / dir_name
                    os.chmod(dir_path, 0o755)
                self.log_success("Set directory permissions")
                
            return True
            
        except Exception as e:
            self.log_error(f"Failed to create directory structure: {e}")
            return False

    def download_wordlist(self, url: str, destination: Path) -> bool:
        """
        Download a wordlist from URL to destination.
        
        Args:
            url: Source URL
            destination: Destination path
            
        Returns:
            bool: True if download successful
        """
        try:
            # Create SSL context that doesn't verify certificates
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Download with progress indicator
            self.log_info(f"Downloading: {url}")
            
            with urllib.request.urlopen(url, timeout=30, context=context) as response:
                total_size = int(response.headers.get('content-length', 0))
                block_size = 8192
                downloaded = 0
                
                with open(destination, 'wb') as f:
                    while True:
                        buffer = response.read(block_size)
                        if not buffer:
                            break
                        downloaded += len(buffer)
                        f.write(buffer)
                        
                        # Show progress for large files
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            print(f"\rProgress: {percent:.1f}%", end='', flush=True)
                
                print()  # New line after progress
            
            # Verify file was downloaded
            if destination.exists() and destination.stat().st_size > 0:
                self.log_success(f"Downloaded: {destination.name}")
                return True
            else:
                self.log_error(f"Downloaded file is empty: {destination.name}")
                return False
                
        except urllib.error.URLError as e:
            self.log_error(f"URL error downloading {destination.name}: {e}")
            return False
        except urllib.error.HTTPError as e:
            self.log_error(f"HTTP error downloading {destination.name}: {e.code} {e.reason}")
            return False
        except Exception as e:
            self.log_error(f"Unexpected error downloading {destination.name}: {e}")
            return False

    def download_all_wordlists(self) -> bool:
        """
        Download all required wordlists.
        
        Returns:
            bool: True if all wordlists downloaded successfully
        """
        wordlist_dir = self.install_dir / "wordlists"
        success_count = 0
        total_count = len(self.wordlists)
        
        for filename, url in self.wordlists.items():
            destination = wordlist_dir / filename
            
            # Skip if file already exists and has content
            if destination.exists() and destination.stat().st_size > 0:
                self.log_warning(f"Wordlist already exists, skipping: {filename}")
                success_count += 1
                continue
                
            if self.download_wordlist(url, destination):
                success_count += 1
        
        if success_count == total_count:
            self.log_success("All wordlists downloaded successfully")
            return True
        elif success_count > 0:
            self.log_warning(f"Downloaded {success_count} out of {total_count} wordlists")
            return True
        else:
            self.log_error("Failed to download any wordlists")
            return False

    def set_file_permissions(self) -> bool:
        """
        Set executable permissions on Python scripts.
        
        Returns:
            bool: True if permissions set successfully
        """
        try:
            for filename in self.required_files:
                file_path = self.install_dir / filename
                if file_path.exists():
                    file_path.chmod(0o755)
                    self.log_info(f"Set executable permissions: {filename}")
            
            self.log_success("File permissions configured")
            return True
            
        except Exception as e:
            self.log_warning(f"Could not set file permissions: {e}")
            return False

    def create_configuration_file(self) -> bool:
        """
        Create default configuration file.
        
        Returns:
            bool: True if configuration file created successfully
        """
        config_content = f"""# Recony Configuration File
# Generated automatically by installation script
# {self.get_timestamp()}

[directories]
results = {self.install_dir / 'results'}
logs = {self.install_dir / 'logs'}
wordlists = {self.install_dir / 'wordlists'}
backups = {self.install_dir / 'backups'}

[defaults]
timeout = 5
max_threads = 50
output_format = json

[logging]
level = INFO
rotate = true
max_size_mb = 10
backup_count = 5

[network]
dns_server = 8.8.8.8
user_agent = Mozilla/5.0 (compatible; Recony-Scanner/1.0)

[security]
follow_redirects = true
verify_ssl = false
rate_limit_delay = 0.1
"""
        
        try:
            config_path = self.install_dir / "recony.conf"
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(config_content)
            
            self.log_success("Configuration file created: recony.conf")
            return True
            
        except Exception as e:
            self.log_error(f"Failed to create configuration file: {e}")
            return False

    def run_smoke_test(self) -> bool:
        """
        Run a basic smoke test to verify installation.
        
        Returns:
            bool: True if smoke test passes
        """
        try:
            self.log_info("Running smoke test...")
            
            # Test basic functionality
            result = subprocess.run([
                sys.executable, self.install_dir / "recony.py", "--help"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.log_success("Smoke test passed - tool is functional")
                return True
            else:
                self.log_error(f"Smoke test failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.log_error("Smoke test timed out")
            return False
        except Exception as e:
            self.log_error(f"Smoke test failed: {e}")
            return False

    def create_uninstall_script(self) -> bool:
        """
        Create an uninstall script for Recony.
        
        Returns:
            bool: True if uninstall script created successfully
        """
        uninstall_content = f"""#!/usr/bin/env python3
"""
        uninstall_content = f"""#!/usr/bin/env python3
\"\"\"
Recony Uninstall Script
Use with caution - this will remove all Recony files and data.
\"\"\"

import os
import shutil
from pathlib import Path

def main():
    script_dir = Path(__file__).parent
    install_dir = script_dir
    
    print("Recony Uninstall Script")
    print("=" * 50)
    print(f"This will remove Recony from: {install_dir}")
    print()
    print("Files and directories to be removed:")
    print("- All Recony Python modules")
    print("- results/ directory")
    print("- logs/ directory") 
    print("- wordlists/ directory")
    print("- backups/ directory")
    print("- Configuration files")
    print()
    
    response = input("Are you sure you want to continue? (yes/NO): ")
    if response.lower() not in ['yes', 'y']:
        print("Uninstall cancelled.")
        return
    
    # Files to remove
    files_to_remove = [
        "recony.py",
        "network_scan.py",
        "dns_enum.py", 
        "whois_module.py",
        "ssl_tls_enum.py",
        "http_fingerprint.py",
        "dir_enum.py",
        "subdomain_enum.py",
        "report_generator.py",
        "recony.conf",
        "install_recony.py",
        "uninstall_recony.py"
    ]
    
    # Directories to remove
    dirs_to_remove = [
        "results",
        "logs",
        "wordlists", 
        "backups"
    ]
    
    removed_count = 0
    
    # Remove files
    for filename in files_to_remove:
        file_path = install_dir / filename
        if file_path.exists():
            try:
                file_path.unlink()
                print(f"Removed: {filename}")
                removed_count += 1
            except Exception as e:
                print(f"Error removing {filename}: {e}")
    
    # Remove directories
    for dirname in dirs_to_remove:
        dir_path = install_dir / dirname
        if dir_path.exists():
            try:
                shutil.rmtree(dir_path)
                print(f"Removed: {dirname}/")
                removed_count += 1
            except Exception as e:
                print(f"Error removing {dirname}/: {e}")
    
    print(f"Uninstall completed. Removed {removed_count} items.")
    print("Note: Some files may remain if they were in use.")

if __name__ == "__main__":
    main()
"""
        
        try:
            uninstall_path = self.install_dir / "uninstall_recony.py"
            with open(uninstall_path, 'w', encoding='utf-8') as f:
                f.write(uninstall_content)
            
            # Make uninstall script executable
            uninstall_path.chmod(0o755)
            
            self.log_success("Uninstall script created: uninstall_recony.py")
            return True
            
        except Exception as e:
            self.log_error(f"Failed to create uninstall script: {e}")
            return False

    def get_timestamp(self) -> str:
        """Get current timestamp for logging."""
        from datetime import datetime
        return datetime.now().isoformat()

    def display_banner(self) -> None:
        """Display installation banner."""
        banner = f"""
        {self.colors['BLUE']}╔══════════════════════════════════════════════════════════════╗{self.colors['NC']}
        {self.colors['BLUE']}║                                                              ║{self.colors['NC']}
        {self.colors['BLUE']}║    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗   ██╗     ║{self.colors['NC']}
        {self.colors['BLUE']}║    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗ ██╔╝     ║{self.colors['NC']}
        {self.colors['BLUE']}║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚████╔╝      ║{self.colors['NC']}
        {self.colors['BLUE']}║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║  ╚██╔╝       ║{self.colors['NC']}
        {self.colors['BLUE']}║    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║   ██║        ║{self.colors['NC']}
        {self.colors['BLUE']}║    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝        ║{self.colors['NC']}
        {self.colors['BLUE']}║                                                              ║{self.colors['NC']}
        {self.colors['BLUE']}║                 Web Reconnaissance Tool v1.0                ║{self.colors['NC']}
        {self.colors['BLUE']}║                     Installation Script                     ║{self.colors['NC']}
        {self.colors['BLUE']}║                                                              ║{self.colors['NC']}
        {self.colors['BLUE']}╚══════════════════════════════════════════════════════════════╝{self.colors['NC']}
        """
        print(banner)

    def run_installation(self) -> bool:
        """
        Run complete installation process.
        
        Returns:
            bool: True if installation successful
        """
        self.display_banner()
        
        steps = [
            ("Checking Python version", self.check_python_version),
            ("Checking required modules", self.check_required_modules),
            ("Validating installation files", self.validate_installation_files),
            ("Creating directory structure", self.create_directory_structure),
            ("Downloading wordlists", self.download_all_wordlists),
            ("Setting file permissions", self.set_file_permissions),
            ("Creating configuration", self.create_configuration_file),
            ("Running smoke test", self.run_smoke_test),
            ("Creating uninstall script", self.create_uninstall_script)
        ]
        
        successful_steps = 0
        total_steps = len(steps)
        
        for step_name, step_function in steps:
            self.log_info(f"Step {successful_steps + 1}/{total_steps}: {step_name}")
            
            try:
                if step_function():
                    successful_steps += 1
                    self.log_success(f"Completed: {step_name}")
                else:
                    self.log_error(f"Failed: {step_name}")
                    # Continue with installation even if some steps fail
            except Exception as e:
                self.log_error(f"Error in {step_name}: {e}")
        
        # Final summary
        print("\n" + "="*60)
        if successful_steps == total_steps:
            self.log_success(f"Installation completed successfully! ({successful_steps}/{total_steps} steps)")
            print(f"\nQuick start:")
            print(f"  python recony.py --help")
            print(f"  python recony.py fullscan example.com")
            return True
        elif successful_steps >= total_steps * 0.7:  # At least 70% success
            self.log_warning(f"Installation partially completed ({successful_steps}/{total_steps} steps)")
            print(f"\nThe tool should work, but some features may be limited.")
            print(f"Check the errors above and consider re-running the installation.")
            return True
        else:
            self.log_error(f"Installation failed ({successful_steps}/{total_steps} steps)")
            print(f"\nThe installation encountered too many errors.")
            print(f"Please check the errors above and try again.")
            return False


def main():
    """Main installation entry point."""
    try:
        installer = ReconyInstaller()
        success = installer.run_installation()
        
        if success:
            print(f"\n{installer.colors['GREEN']}Recony is ready to use!{installer.colors['NC']}")
            sys.exit(0)
        else:
            print(f"\n{installer.colors['RED']}Installation failed.{installer.colors['NC']}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n{installer.colors['YELLOW']}Installation cancelled by user.{installer.colors['NC']}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{installer.colors['RED']}Unexpected error during installation: {e}{installer.colors['NC']}")
        sys.exit(1)


if __name__ == "__main__":
    main()