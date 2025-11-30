#!/usr/bin/env python3
"""
Recony - Professional Web Reconnaissance Framework
Main Controller Module

A comprehensive, modular, and multi-threaded web reconnaissance framework 
designed for cybersecurity professionals, red teamers, and bug bounty hunters.
This tool automates the process of information gathering by orchestrating 
multiple scanning techniques into a single, cohesive workflow.

Features:
- Parallel execution of specialized modules
- Network, DNS, Subdomain, Directory, HTTP, SSL, and Whois scanning
- Intelligent target validation and protocol handling
- Robust error handling and logging
- Multi-format reporting (JSON, HTML, TXT, CSV, MD)
- Automatic result archiving

Author: A0xVa10ri4n
Version: 3.1 (Stable)
GitHub: https://github.com/cybersecurity-expert/recony
License: MIT
"""

import argparse
import json
import logging
import os
import sys
import time
import traceback
import shutil
import platform
import socket
import threading
import concurrent.futures
import ipaddress
import zipfile
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from urllib.parse import urlparse

# ============================================================================
# CONFIGURATION & CONSTANTS
# ============================================================================

VERSION = "3.1"
BANNER = f"""
\033[94m
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗ ██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚████╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║  ╚██╔╝  
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║   ██║   
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   
\033[0m
    \033[1mProfessional Reconnaissance Framework v{VERSION}\033[0m
    \033[3mAutomated Information Gathering Engine\033[0m
"""

# Default configuration values
DEFAULT_CONFIG = {
    "timeout": 10,
    "threads": 50,
    "user_agent": "Recony/3.0 (Security Assessment Tool)",
    "verify_ssl": False,
    "retries": 2,
    "output_dir": "recony_results"
}

# Module registry mapping module names to filenames
MODULE_MAPPING = {
    'network': 'network_scan',
    'dns': 'dns_enum', 
    'whois': 'whois_module',
    'ssl': 'ssl_tls_enum',
    'http': 'http_fingerprint',
    'directory': 'dir_enum',
    'subdomain': 'subdomain_enum',
    'report': 'report_generator'
}

# ============================================================================
# UTILITY CLASSES
# ============================================================================

class LoggerSetup:
    """
    Handles complex logging configuration for the framework.
    Supports splitting logs between console (clean) and file (debug).
    """
    
    @staticmethod
    def setup(log_file: str, verbose: bool = False) -> logging.Logger:
        """
        Initialize the logging subsystem.
        """
        # Create root logger
        logger = logging.getLogger('recony')
        logger.handlers.clear() # Remove default handlers
        logger.setLevel(logging.DEBUG) # Capture everything at root level
        
        # 1. File Handler (Always DEBUG, detailed format)
        try:
            file_handler = logging.FileHandler(log_file, encoding='utf-8', mode='a')
            file_handler.setLevel(logging.DEBUG)
            file_fmt = logging.Formatter(
                '%(asctime)s [%(levelname)s] [%(threadName)s] %(module)s: %(message)s'
            )
            file_handler.setFormatter(file_fmt)
            logger.addHandler(file_handler)
        except Exception as e:
            print(f"Error setting up log file: {e}")

        return logger

class StatusPrinter:
    """
    Thread-safe printer for status messages with color support.
    """
    
    def __init__(self, no_color: bool = False):
        self.lock = threading.Lock()
        self.no_color = no_color
        
        # Define colors
        self.C_RESET = "\033[0m"
        self.C_BLUE = "\033[94m"
        self.C_GREEN = "\033[92m"
        self.C_YELLOW = "\033[93m"
        self.C_RED = "\033[91m"
        self.C_CYAN = "\033[96m"
        self.C_BOLD = "\033[1m"

    def print(self, message: str, status: str = "info", prefix: str = "") -> None:
        """
        Print a formatted status message.
        """
        icon_map = {
            "info": "🔵",
            "success": "🟢",
            "warning": "🟡",
            "error": "🔴",
            "running": "🔄",
            "debug": "🐛",
            "module": "📦"
        }
        
        color_map = {
            "info": self.C_BLUE,
            "success": self.C_GREEN,
            "warning": self.C_YELLOW,
            "error": self.C_RED,
            "running": self.C_CYAN,
            "debug": self.C_RESET,
            "module": self.C_BOLD
        }
        
        icon = icon_map.get(status, "•")
        color = color_map.get(status, self.C_BLUE)
        
        if self.no_color:
            color = ""
            reset = ""
        else:
            reset = self.C_RESET
            
        full_msg = f"{color}{icon} {prefix}{message}{reset}"
        
        with self.lock:
            print(full_msg)
            sys.stdout.flush()

# ============================================================================
# REPORTING MANAGER
# ============================================================================

class ReportManager:
    """
    Handles generation of various report formats and data persistence.
    """
    
    def __init__(self, output_dir: str, printer: StatusPrinter):
        self.output_dir = Path(output_dir)
        self.printer = printer
        self.csv_dir = self.output_dir / "csv"
        
        # Ensure directories exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.csv_dir.mkdir(parents=True, exist_ok=True)

    def save_json(self, data: Dict[str, Any], filename: str = "results.json") -> str:
        """Save results as JSON."""
        try:
            path = self.output_dir / filename
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            return str(path)
        except Exception as e:
            self.printer.print(f"Failed to save JSON: {e}", "error")
            return ""

    def save_text(self, data: Dict[str, Any], filename: str = "report.txt") -> str:
        """Generate a human-readable text report."""
        try:
            path = self.output_dir / filename
            with open(path, 'w', encoding='utf-8') as f:
                self._write_text_report(f, data)
            return str(path)
        except Exception as e:
            self.printer.print(f"Failed to save Text report: {e}", "error")
            return ""

    def _write_text_report(self, f, results: Dict[str, Any]):
        """Internal method to structure the text report."""
        scan_info = results.get('scan_info', {})
        f.write("=" * 80 + "\n")
        f.write(f"RECONY SCAN REPORT - {scan_info.get('target', 'Unknown')}\n")
        f.write("=" * 80 + "\n\n")
        
        # Meta Info
        f.write("SCAN METADATA\n")
        f.write("-" * 20 + "\n")
        f.write(f"Domain: {scan_info.get('domain', 'N/A')}\n")
        f.write(f"Start:  {scan_info.get('start_time', 'N/A')}\n")
        f.write(f"End:    {scan_info.get('end_time', 'N/A')}\n")
        f.write(f"Duration: {scan_info.get('duration_seconds', 0):.2f}s\n\n")
        
        # Modules
        modules = results.get('modules', {})
        
        # 1. Network
        if 'network' in modules:
            m = modules['network']
            f.write("NETWORK SCAN\n")
            f.write("-" * 20 + "\n")
            if m.get('status') == 'success':
                open_ports = m.get('port_scan', {}).get('open_ports', [])
                if open_ports:
                    f.write(f"{'PORT':<10}{'SERVICE':<20}{'PROTOCOL'}\n")
                    for p in open_ports:
                        f.write(f"{p['port']:<10}{p['service']:<20}{p['protocol']}\n")
                else:
                    f.write("No open ports found.\n")
            else:
                f.write(f"Scan failed: {m.get('error')}\n")
            f.write("\n")

        # 2. Subdomains
        if 'subdomain' in modules:
            m = modules['subdomain']
            f.write("SUBDOMAINS\n")
            f.write("-" * 20 + "\n")
            if m.get('status') == 'success':
                subs = m.get('discovered_subdomains', [])
                f.write(f"Total Discovered: {len(subs)}\n")
                for s in subs:
                    f.write(f"- {s.get('subdomain')} ({s.get('primary_ip')})\n")
            f.write("\n")
            
        # 3. HTTP Headers
        if 'http' in modules:
            m = modules['http']
            f.write("HTTP ANALYSIS\n")
            f.write("-" * 20 + "\n")
            if m.get('status') == 'success':
                f.write(f"Server: {m.get('server_banner', {}).get('server_banner', 'Unknown')}\n")
                techs = m.get('technologies', {}).get('technologies', {})
                if techs:
                    f.write("Technologies:\n")
                    for cat, t_list in techs.items():
                        f.write(f"  {cat}: {', '.join(t_list)}\n")
            f.write("\n")

        # 4. Directories
        if 'directory' in modules:
            m = modules['directory']
            f.write("DIRECTORY ENUMERATION\n")
            f.write("-" * 20 + "\n")
            if m.get('status') == 'success':
                results_list = m.get('enumeration', {}).get('results', [])
                f.write(f"Paths Found: {len(results_list)}\n")
                for r in results_list:
                    f.write(f"[{r.get('status_code')}] {r.get('path')} ({r.get('content_length')}b)\n")
            f.write("\n")

    def save_csv(self, data: Dict[str, Any]) -> List[str]:
        """Generate separate CSV files for relevant modules."""
        generated_files = []
        modules = data.get('modules', {})
        
        # Network CSV
        if 'network' in modules and modules['network'].get('status') == 'success':
            csv_path = self.csv_dir / "network_ports.csv"
            try:
                open_ports = modules['network'].get('port_scan', {}).get('open_ports', [])
                if open_ports:
                    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.DictWriter(f, fieldnames=['port', 'protocol', 'service'])
                        writer.writeheader()
                        writer.writerows(open_ports)
                    generated_files.append(str(csv_path))
            except Exception as e:
                self.printer.print(f"Error creating Network CSV: {e}", "error")

        # Subdomain CSV
        if 'subdomain' in modules and modules['subdomain'].get('status') == 'success':
            csv_path = self.csv_dir / "subdomains.csv"
            try:
                subs = modules['subdomain'].get('discovered_subdomains', [])
                if subs:
                    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                        # Flatten dictionary for CSV
                        rows = []
                        for s in subs:
                            rows.append({
                                'subdomain': s.get('subdomain'),
                                'ip': s.get('primary_ip'),
                                'status': s.get('status')
                            })
                        writer = csv.DictWriter(f, fieldnames=['subdomain', 'ip', 'status'])
                        writer.writeheader()
                        writer.writerows(rows)
                    generated_files.append(str(csv_path))
            except Exception as e:
                self.printer.print(f"Error creating Subdomain CSV: {e}", "error")

        return generated_files

    def archive_results(self) -> str:
        """Create a ZIP archive of the results directory."""
        archive_name = self.output_dir.with_suffix('.zip')
        try:
            with zipfile.ZipFile(archive_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(self.output_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, self.output_dir)
                        zipf.write(file_path, arcname)
            return str(archive_name)
        except Exception as e:
            self.printer.print(f"Failed to archive results: {e}", "error")
            return ""

# ============================================================================
# MAIN CONTROLLER
# ============================================================================

class ReconyController:
    """
    Orchestrates the execution of reconnaissance modules.
    Handles module loading, thread management, and error recovery.
    """
    
    def __init__(self):
        self.modules = {}
        self.printer = StatusPrinter()
        self.logger = None
        self.output_dir = None
        self.report_manager = None
        self.version = VERSION  # Fix: Initialize version here
        
    def initialize(self, args: argparse.Namespace) -> bool:
        """
        Perform initial setup tasks: logging, directory creation, module loading.
        """
        try:
            # 1. Setup Directories
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_dir = Path(args.output) / timestamp
            logs_dir = base_dir / "logs"
            
            base_dir.mkdir(parents=True, exist_ok=True)
            logs_dir.mkdir(parents=True, exist_ok=True)
            
            self.output_dir = str(base_dir)
            
            # 2. Setup Logging
            log_file = logs_dir / "recony_debug.log"
            self.logger = LoggerSetup.setup(str(log_file), args.verbose)
            self.printer.no_color = args.no_color
            
            self.printer.print(f"Initialized output directory: {self.output_dir}", "success")
            
            # 3. Setup Report Manager
            self.report_manager = ReportManager(self.output_dir, self.printer)
            
            # 4. Load Modules
            return self._load_modules()
            
        except Exception as e:
            print(f"CRITICAL: Failed to initialize controller: {e}")
            traceback.print_exc()
            return False

    def _load_modules(self) -> bool:
        """Dynamically import all scanning modules."""
        loaded = 0
        failed = []
        
        self.printer.print("Loading modules...", "running")
        
        for name, filename in MODULE_MAPPING.items():
            try:
                module = __import__(filename)
                self.modules[name] = module
                loaded += 1
                self.logger.debug(f"Loaded module: {name} from {filename}")
            except ImportError as e:
                failed.append(f"{name} ({e.msg})")
                self.logger.error(f"Failed to import {filename}: {e}")
            except Exception as e:
                failed.append(f"{name} (Unknown Error)")
                self.logger.error(f"Unexpected error importing {filename}: {e}")
                
        if failed:
            self.printer.print(f"Failed to load {len(failed)} modules: {', '.join(failed)}", "warning")
        
        self.printer.print(f"Successfully loaded {loaded}/{len(MODULE_MAPPING)} modules", "success")
        return loaded > 0

    def check_connection(self, host: str = "8.8.8.8", port: int = 53, timeout: int = 3) -> bool:
        """
        Check if the machine has internet connectivity.
        """
        try:
            socket.setdefaulttimeout(timeout)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
            return True
        except socket.error:
            self.printer.print("No internet connection detected.", "warning")
            return False

    def validate_target(self, target: str) -> Tuple[bool, str, str]:
        """
        Validate and categorize the target.
        Returns: Tuple(is_valid, type, clean_domain)
        """
        if not target:
            return False, "empty", ""
            
        target = target.strip()
        
        # Check IP
        try:
            ipaddress.ip_address(target)
            return True, "ip", target
        except ValueError:
            pass
            
        # Check URL
        if target.startswith(('http://', 'https://')):
            try:
                parsed = urlparse(target)
                if parsed.netloc:
                    return True, "url", parsed.netloc
            except:
                pass
                
        # Check Domain
        if '.' in target:
            if len(target) < 255 and all(c.isalnum() or c in '-.' for c in target):
                return True, "domain", target
                
        return False, "invalid", ""

    def run_module_safe(self, name: str, func, target: str, params: Dict) -> Dict[str, Any]:
        """
        Wrapper to run a module function safely.
        Fixes argument mismatch: Injects 'target' into 'params' and calls func(params).
        """
        self.printer.print(f"Starting {name} module...", "running")
        start_t = time.time()
        
        # Fix for Argument Mismatch:
        # Modules expect 1 arg (params dict), but we have target + params.
        # We must insert target into params with the correct key.
        if name in ['whois', 'dns', 'subdomain']:
            params['domain'] = target
        elif name == 'ssl':
            params['host'] = target
        elif name == 'directory':
            params['target_url'] = target
        else:
            # network, http
            params['target'] = target

        try:
            # Call the actual module function with ONE argument
            raw_result = func(params)
            
            # Normalize result (JSON string -> Dict)
            if isinstance(raw_result, str):
                try:
                    result = json.loads(raw_result)
                except json.JSONDecodeError:
                    self.logger.error(f"Module {name} returned invalid JSON: {raw_result[:100]}...")
                    return {
                        'status': 'error', 
                        'error': 'Invalid JSON output from module',
                        'raw': raw_result
                    }
            elif isinstance(raw_result, dict):
                result = raw_result
            else:
                return {'status': 'error', 'error': 'Unknown return type'}
                
            duration = time.time() - start_t
            result['duration'] = duration
            
            # Check for logical errors within the result
            if result.get('error'):
                self.printer.print(f"{name} finished with errors: {result['error']}", "error")
                self.logger.warning(f"Module {name} reported error: {result['error']}")
                result['status'] = 'error' # Enforce status
            else:
                self.printer.print(f"{name} completed successfully ({duration:.2f}s)", "success")
                result['status'] = 'success'
                
            return result
            
        except Exception as e:
            duration = time.time() - start_t
            self.printer.print(f"{name} crashed: {str(e)}", "error")
            self.logger.error(f"Module {name} exception: {traceback.format_exc()}")
            return {
                'status': 'error',
                'error': f"Exception: {str(e)}",
                'duration': duration
            }

    # ========================================================================
    # SCANNING LOGIC
    # ========================================================================

    def execute_scan(self, command: str, target: str, args: argparse.Namespace) -> None:
        """
        Main execution logic handling both single-module and full scans.
        """
        # Validate Target
        is_valid, target_type, domain = self.validate_target(target)
        if not is_valid:
            self.printer.print(f"Invalid target format: {target}", "error")
            return

        # Prepare Shared Parameters
        base_params = {
            'timeout': args.timeout,
            'verbose': args.verbose
        }
        
        results = {
            'scan_info': {
                'target': target,
                'domain': domain,
                'type': target_type,
                'command': command,
                'start_time': datetime.now().isoformat(),
                'version': self.version
            },
            'modules': {}
        }

        # --- COMMAND DISPATCHER ---
        
        # 1. NETWORK SCAN
        if command == 'network':
            params = {**base_params, 'max_threads': args.threads, 'ports': args.ports}
            # Network scan needs clean target (IP/Host) not URL
            net_target = domain if target_type == 'url' else target
            results['modules']['network'] = self.run_module_safe(
                'network', 
                self.modules['network'].run_module, 
                net_target, 
                params
            )

        # 2. DNS ENUMERATION
        elif command == 'dns':
            params = {**base_params, 'wordlist': args.wordlist, 'dns_server': args.dns_server}
            results['modules']['dns'] = self.run_module_safe(
                'dns',
                self.modules['dns'].run_module,
                domain,
                params
            )

        # 3. WHOIS LOOKUP
        elif command == 'whois':
            params = {**base_params, 'whois_server': args.whois_server}
            results['modules']['whois'] = self.run_module_safe(
                'whois',
                self.modules['whois'].run_module,
                domain,
                params
            )

        # 4. SUBDOMAIN ENUMERATION
        elif command == 'subs':
            params = {**base_params, 'max_workers': args.threads, 'wordlist': args.wordlist, 'max_subdomains': args.limit}
            results['modules']['subdomain'] = self.run_module_safe(
                'subdomain',
                self.modules['subdomain'].run_module,
                domain,
                params
            )

        # 5. DIRECTORY ENUMERATION
        elif command == 'dir':
            params = {**base_params, 'max_threads': args.threads, 'wordlist': args.wordlist}
            # Directory enum needs URL protocol
            dir_target = target
            if not target.startswith(('http://', 'https://')):
                dir_target = f"https://{target}"
            results['modules']['directory'] = self.run_module_safe(
                'directory',
                self.modules['directory'].run_module,
                dir_target,
                params
            )

        # 6. HTTP FINGERPRINT
        elif command == 'http':
            params = {**base_params, 'https': not args.no_https, 'port': args.port}
            results['modules']['http'] = self.run_module_safe(
                'http',
                self.modules['http'].run_module,
                target,
                params
            )

        # 7. SSL ANALYSIS
        elif command == 'ssl':
            params = {**base_params, 'port': args.port or 443}
            results['modules']['ssl'] = self.run_module_safe(
                'ssl',
                self.modules['ssl'].run_module,
                domain,
                params
            )

        # 8. FULL SCAN (PARALLEL)
        elif command == 'fullscan':
            self._run_full_scan_parallel(target, domain, target_type, args, results)

        # --- POST-SCAN PROCESSING ---
        self._finalize_scan(results, args.format)

    def _run_full_scan_parallel(self, target: str, domain: str, target_type: str, args: argparse.Namespace, results: Dict):
        """
        Orchestrates all modules in parallel using ThreadPoolExecutor.
        """
        self.printer.print(f"Starting optimized full scan on {target}...", "info")
        
        # Prepare targets for specific modules
        net_target = domain if target_type == 'url' else target
        dir_target = target if target.startswith(('http', 'https')) else f"https://{target}"
        
        # Define tasks (Module Name, Function, Target, Params)
        tasks = [
            ('whois', self.modules['whois'].run_module, domain, 
             {'timeout': 10}),
             
            ('dns', self.modules['dns'].run_module, domain, 
             {'timeout': 5, 'comprehensive': True}),
             
            ('subdomain', self.modules['subdomain'].run_module, domain, 
             {'timeout': 3, 'max_workers': args.threads}),
             
            ('network', self.modules['network'].run_module, net_target, 
             {'timeout': 3, 'max_threads': args.threads, 'scan_type': 'full'}),
             
            ('ssl', self.modules['ssl'].run_module, domain, 
             {'timeout': 10, 'port': 443, 'action': 'full_enum'}),
             
            ('http', self.modules['http'].run_module, net_target, 
             {'timeout': 10, 'use_https': True, 'analysis_type': 'full'}),
             
            ('directory', self.modules['directory'].run_module, dir_target, 
             {'timeout': 10, 'max_threads': 20, 'method': 'GET'})
        ]
        
        # Fast mode skips directory brute forcing if requested
        if args.fast:
            tasks = [t for t in tasks if t[0] != 'directory']
            self.printer.print("Fast mode enabled: Skipping directory enumeration", "warning")

        # Execute
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
            # Map futures to module names
            future_map = {
                executor.submit(self.run_module_safe, name, func, tgt, params): name 
                for name, func, tgt, params in tasks
            }
            
            # Process as they complete
            for future in concurrent.futures.as_completed(future_map):
                module_name = future_map[future]
                try:
                    res = future.result()
                    results['modules'][module_name] = res
                except Exception as e:
                    self.logger.error(f"Execution error in {module_name}: {e}")
                    results['modules'][module_name] = {'status': 'error', 'error': str(e)}

    def _finalize_scan(self, results: Dict[str, Any], output_formats: str) -> None:
        """
        Generate reports, calculate statistics, and cleanup.
        """
        results['scan_info']['end_time'] = datetime.now().isoformat()
        start = datetime.fromisoformat(results['scan_info']['start_time'])
        end = datetime.fromisoformat(results['scan_info']['end_time'])
        results['scan_info']['duration_seconds'] = (end - start).total_seconds()
        
        # Calculate Stats
        total = len(results['modules'])
        success = sum(1 for m in results['modules'].values() if m.get('status') == 'success')
        results['summary'] = {
            'total_modules': total,
            'successful': success,
            'failed': total - success,
            'success_rate': (success / total * 100) if total else 0
        }
        
        self.printer.print("\nGenerating reports...", "info")
        
        formats = [f.strip().lower() for f in output_formats.split(',')]
        
        if 'json' in formats:
            path = self.report_manager.save_json(results)
            if path: self.printer.print(f"JSON Report: {path}", "success")
            
        if 'txt' in formats:
            path = self.report_manager.save_text(results)
            if path: self.printer.print(f"Text Report: {path}", "success")
            
        if 'csv' in formats:
            paths = self.report_manager.save_csv(results)
            if paths: self.printer.print(f"CSV Files generated in {self.report_manager.csv_dir}", "success")
            
        if 'html' in formats and 'report' in self.modules:
            try:
                html_path = os.path.join(self.output_dir, "report.html")
                self.modules['report'].run_module({
                    'results_data': results,
                    'output_file': html_path
                })
                self.printer.print(f"HTML Dashboard: {html_path}", "success")
            except Exception as e:
                self.printer.print(f"HTML Generation failed: {e}", "warning")

        # Archive
        zip_path = self.report_manager.archive_results()
        if zip_path:
            self.printer.print(f"Scan Archive: {zip_path}", "success")

# ============================================================================
# CLI ARGUMENT PARSING
# ============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Recony - Professional Web Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  1. Full Scan (Recommended):
     python3 recony.py -o project_alpha fullscan example.com -j 100

  2. Network Only:
     python3 recony.py network 192.168.1.10 --ports 22,80,443,3389

  3. Subdomain Discovery (Aggressive):
     python3 recony.py subs example.com --limit 2000 --threads 100

  4. Directory Search with Custom Wordlist:
     python3 recony.py dir https://site.com --wordlist /path/to/list.txt

NOTES:
  - Global flags (-o, -f, -v) must strictly precede the command (fullscan, network, etc).
  - Use --threads/-j to increase speed on powerful connections.
        """
    )
    
    # Global Arguments
    global_group = parser.add_argument_group('Global Options')
    global_group.add_argument('-o', '--output', default=DEFAULT_CONFIG['output_dir'], help='Output directory')
    global_group.add_argument('-f', '--format', default='txt,json,html,csv', help='Output formats (comma separated)')
    global_group.add_argument('-v', '--verbose', action='store_true', help='Enable debug logging')
    global_group.add_argument('--no-color', action='store_true', help='Disable colored output')
    
    subparsers = parser.add_subparsers(dest='command', help='Scan Modules')
    
    # Module: Network
    net = subparsers.add_parser('network', help='Port scanning and service detection')
    net.add_argument('target', help='Target IP or Hostname')
    net.add_argument('-t', '--timeout', type=int, default=3)
    net.add_argument('-j', '--threads', type=int, default=50)
    net.add_argument('--ports', help='Ports to scan (e.g. "80,443" or "1-1000")')
    
    # Module: DNS
    dns = subparsers.add_parser('dns', help='DNS record enumeration')
    dns.add_argument('domain', help='Target Domain')
    dns.add_argument('-t', '--timeout', type=int, default=5)
    dns.add_argument('-w', '--wordlist', help='Subdomain wordlist')
    dns.add_argument('--dns-server', help='Custom DNS resolver')
    
    # Module: Whois
    whois = subparsers.add_parser('whois', help='Whois registration info')
    whois.add_argument('domain', help='Target Domain')
    whois.add_argument('-t', '--timeout', type=int, default=10)
    whois.add_argument('--whois-server', help='Specific Whois server')
    
    # Module: SSL
    ssl = subparsers.add_parser('ssl', help='SSL/TLS certificate analysis')
    ssl.add_argument('target', help='Target Host')
    ssl.add_argument('-p', '--port', type=int, default=443)
    ssl.add_argument('-t', '--timeout', type=int, default=10)
    
    # Module: HTTP
    http = subparsers.add_parser('http', help='HTTP fingerprinting & headers')
    http.add_argument('target', help='Target URL/Host')
    http.add_argument('-t', '--timeout', type=int, default=10)
    http.add_argument('--no-https', action='store_true', help='Force HTTP only')
    http.add_argument('-p', '--port', type=int, help='Custom port')
    
    # Module: Directory
    dir_scan = subparsers.add_parser('dir', help='Directory brute-forcing')
    dir_scan.add_argument('target', help='Target URL')
    dir_scan.add_argument('-t', '--timeout', type=int, default=10)
    dir_scan.add_argument('-j', '--threads', type=int, default=20)
    dir_scan.add_argument('-w', '--wordlist', help='Custom wordlist path')
    
    # Module: Subdomain
    sub = subparsers.add_parser('subs', help='Subdomain discovery')
    sub.add_argument('domain', help='Target Domain')
    sub.add_argument('-t', '--timeout', type=int, default=3)
    sub.add_argument('-j', '--threads', type=int, default=50)
    sub.add_argument('-w', '--wordlist', help='Custom wordlist path')
    sub.add_argument('-l', '--limit', type=int, help='Limit number of results')
    
    # Module: Full Scan
    full = subparsers.add_parser('fullscan', help='Run all modules')
    full.add_argument('target', help='Target Domain/IP')
    full.add_argument('-t', '--timeout', type=int, default=5)
    full.add_argument('-j', '--threads', type=int, default=50, help='Global thread count')
    full.add_argument('--fast', action='store_true', help='Skip slow modules (Dir Enum)')
    
    return parser.parse_args()

# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    print(BANNER)
    
    # 1. Parse Arguments
    args = parse_args()
    if not args.command:
        print("Error: No command specified. Use -h for help.")
        sys.exit(1)
        
    # 2. Initialize Controller
    controller = ReconyController()
    if not controller.initialize(args):
        sys.exit(1)
        
    # 3. Connectivity Check
    if not controller.check_connection():
        # Proceed anyway but warn user, local scans might still work
        controller.printer.print("Warning: Continuing without internet access...", "warning")

    # 4. Get Target
    target = getattr(args, 'target', None) or getattr(args, 'domain', None)
    if not target:
        controller.printer.print("Error: Target not specified.", "error")
        sys.exit(1)

    # 5. Execute
    try:
        controller.execute_scan(args.command, target, args)
    except KeyboardInterrupt:
        controller.printer.print("\nScan interrupted by user.", "warning")
        sys.exit(130)
    except Exception as e:
        controller.printer.print(f"Fatal error: {e}", "error")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()