#!/usr/bin/env python3
"""
Recony - Professional Web Reconnaissance Framework
Main Controller Module

A comprehensive, modular, and multi-threaded web reconnaissance framework 
designed for cybersecurity professionals.

Features:
- Parallel execution of specialized modules
- Network, DNS, Subdomain, Directory, HTTP, SSL, and Whois scanning
- Intelligent target validation and protocol handling
- Robust error handling and logging
- Multi-format reporting (JSON, TXT, CSV, HTML)
- Automatic result archiving
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

VERSION = "3.4"
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

DEFAULT_CONFIG = {
    "timeout": 10,
    "threads": 50,
    "user_agent": "Recony/3.4 (Security Assessment Tool)",
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
    """Handles complex logging configuration for the framework."""
    @staticmethod
    def setup(log_file: str, verbose: bool = False) -> logging.Logger:
        logger = logging.getLogger('recony')
        logger.handlers.clear()
        logger.setLevel(logging.DEBUG)
        
        try:
            file_handler = logging.FileHandler(log_file, encoding='utf-8', mode='a')
            file_handler.setLevel(logging.DEBUG)
            file_fmt = logging.Formatter('%(asctime)s [%(levelname)s] [%(threadName)s] %(module)s: %(message)s')
            file_handler.setFormatter(file_fmt)
            logger.addHandler(file_handler)
        except Exception as e:
            print(f"Error setting up log file: {e}")

        return logger

class StatusPrinter:
    """Thread-safe printer for status messages with color support."""
    def __init__(self, no_color: bool = False):
        self.lock = threading.Lock()
        self.no_color = no_color
        self.C_RESET = "\033[0m"
        self.C_BLUE = "\033[94m"
        self.C_GREEN = "\033[92m"
        self.C_YELLOW = "\033[93m"
        self.C_RED = "\033[91m"
        self.C_CYAN = "\033[96m"
        self.C_BOLD = "\033[1m"

    def print(self, message: str, status: str = "info", prefix: str = "") -> None:
        """Print a formatted status message."""
        # Support for raw printing (for modules like dir_enum that control formatting)
        if status == "raw":
            with self.lock:
                print(message)
                sys.stdout.flush()
            return

        icon_map = {
            "info": "🔵", "success": "🟢", "warning": "🟡",
            "error": "🔴", "running": "🔄", "debug": "🐛", "module": "📦"
        }
        
        color_map = {
            "info": self.C_BLUE, "success": self.C_GREEN, "warning": self.C_YELLOW,
            "error": self.C_RED, "running": self.C_CYAN, "debug": self.C_RESET, "module": self.C_BOLD
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
    """Handles generation of various report formats and data persistence."""
    
    def __init__(self, output_dir: str, printer: StatusPrinter):
        self.output_dir = Path(output_dir)
        self.printer = printer
        self.csv_dir = self.output_dir / "csv"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.csv_dir.mkdir(parents=True, exist_ok=True)

    def save_json(self, data: Dict[str, Any], filename: str = "results.json") -> str:
        try:
            path = self.output_dir / filename
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            return str(path)
        except Exception as e:
            self.printer.print(f"Failed to save JSON: {e}", "error")
            return ""

    def save_text(self, data: Dict[str, Any], filename: str = "report.txt") -> str:
        try:
            path = self.output_dir / filename
            with open(path, 'w', encoding='utf-8') as f:
                self._write_text_report(f, data)
            return str(path)
        except Exception as e:
            self.printer.print(f"Failed to save Text report: {e}", "error")
            return ""

    def _write_text_report(self, f, results: Dict[str, Any]):
        scan_info = results.get('scan_info', {})
        f.write("=" * 80 + "\n")
        f.write(f"RECONY SCAN REPORT - {scan_info.get('target', 'Unknown')}\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("SCAN METADATA\n")
        f.write("-" * 20 + "\n")
        f.write(f"Start:  {scan_info.get('start_time', 'N/A')}\n")
        f.write(f"End:    {scan_info.get('end_time', 'N/A')}\n")
        f.write(f"Type:   {scan_info.get('command', 'N/A')}\n\n")
        
        modules = results.get('modules', {})
        
        # 1. Network
        if 'network' in modules:
            m = modules['network']
            f.write("NETWORK SCAN\n" + "-" * 20 + "\n")
            if m.get('status') == 'success':
                open_ports = m.get('port_scan', {}).get('open_ports', [])
                if open_ports:
                    f.write(f"{'PORT':<10}{'SERVICE':<20}{'PROTOCOL'}\n")
                    for p in open_ports:
                        f.write(f"{p['port']:<10}{p.get('service', 'unknown'):<20}{p.get('protocol', 'tcp')}\n")
                else:
                    f.write("No open ports found.\n")
            else:
                f.write(f"Scan failed: {m.get('error')}\n")
            f.write("\n")

        # 2. DNS
        if 'dns' in modules:
            m = modules['dns']
            f.write("DNS ENUMERATION\n" + "-" * 20 + "\n")
            if m.get('status') == 'success':
                records = m.get('all_records', {}).get('queries', {})
                if records:
                    for rtype, rdata in records.items():
                        if rdata.get('success') and rdata.get('records'):
                            f.write(f"[{rtype}] Records:\n")
                            for rec in rdata['records']:
                                val = rec if isinstance(rec, str) else str(rec)
                                f.write(f"  - {val}\n")
                else:
                    f.write("No DNS records found.\n")
            elif m.get('status') == 'error':
                 f.write(f"Error: {m.get('error')}\n")
            f.write("\n")

        # 3. Subdomains
        if 'subdomain' in modules:
            m = modules['subdomain']
            f.write("SUBDOMAINS\n" + "-" * 20 + "\n")
            if m.get('status') == 'success':
                subs = m.get('discovered_subdomains', [])
                f.write(f"Total Discovered: {len(subs)}\n")
                for s in subs:
                    f.write(f"- {s.get('subdomain')} ({s.get('primary_ip', 'N/A')})\n")
            f.write("\n")

        # 4. HTTP
        if 'http' in modules:
            m = modules['http']
            f.write("HTTP ANALYSIS\n" + "-" * 20 + "\n")
            if m.get('status') == 'success':
                f.write(f"Server: {m.get('server_banner', {}).get('server_banner', 'Unknown')}\n")
                techs = m.get('technologies', {}).get('technologies', {})
                if techs:
                    f.write("Technologies Detected:\n")
                    for cat, t_list in techs.items():
                        f.write(f"  {cat}: {', '.join(t_list)}\n")
            f.write("\n")

        # 5. Directory
        if 'directory' in modules:
            m = modules['directory']
            f.write("DIRECTORY ENUMERATION\n" + "-" * 20 + "\n")
            if m.get('status') == 'success':
                results_list = m.get('enumeration', {}).get('results', [])
                f.write(f"Paths Found: {len(results_list)}\n")
                for r in results_list:
                    redir = f" -> {r.get('redirect')}" if r.get('redirect') else ""
                    f.write(f"[{r.get('status_code')}] {r.get('path')} ({r.get('size')}b){redir}\n")
            f.write("\n")

    def save_csv(self, data: Dict[str, Any]) -> List[str]:
        generated_files = []
        modules = data.get('modules', {})
        
        # Directory CSV
        if 'directory' in modules and modules['directory'].get('status') == 'success':
            csv_path = self.csv_dir / "directories.csv"
            try:
                paths = modules['directory'].get('enumeration', {}).get('results', [])
                if paths:
                    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.DictWriter(f, fieldnames=['status_code', 'path', 'size', 'redirect', 'url'])
                        writer.writeheader()
                        writer.writerows(paths)
                    generated_files.append(str(csv_path))
            except Exception: pass
            
        # Network CSV
        if 'network' in modules and modules['network'].get('status') == 'success':
             csv_path = self.csv_dir / "ports.csv"
             try:
                ports = modules['network'].get('port_scan', {}).get('open_ports', [])
                if ports:
                    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.DictWriter(f, fieldnames=['port', 'protocol', 'service'])
                        writer.writeheader()
                        writer.writerows(ports)
                    generated_files.append(str(csv_path))
             except Exception: pass

        return generated_files

    def archive_results(self) -> str:
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
    
    def __init__(self):
        self.modules = {}
        self.printer = StatusPrinter()
        self.logger = None
        self.output_dir = None
        self.report_manager = None
        self.version = VERSION
        
    def initialize(self, args: argparse.Namespace) -> bool:
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_dir = Path(args.output) / timestamp
            logs_dir = base_dir / "logs"
            
            base_dir.mkdir(parents=True, exist_ok=True)
            logs_dir.mkdir(parents=True, exist_ok=True)
            
            self.output_dir = str(base_dir)
            
            log_file = logs_dir / "recony_debug.log"
            self.logger = LoggerSetup.setup(str(log_file), args.verbose)
            self.printer.no_color = args.no_color
            
            self.printer.print(f"Initialized output directory: {self.output_dir}", "success")
            self.report_manager = ReportManager(self.output_dir, self.printer)
            
            return self._load_modules()
            
        except Exception as e:
            print(f"CRITICAL: Failed to initialize controller: {e}")
            traceback.print_exc()
            return False

    def _load_modules(self) -> bool:
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
                failed.append(f"{name} (Unknown)")
                self.logger.error(f"Error importing {filename}: {e}")
                
        if failed:
            self.printer.print(f"Failed to load: {', '.join(failed)}", "warning")
        
        self.printer.print(f"Successfully loaded {loaded}/{len(MODULE_MAPPING)} modules", "success")
        return loaded > 0

    def check_connection(self, host: str = "8.8.8.8", port: int = 53, timeout: int = 3) -> bool:
        try:
            socket.setdefaulttimeout(timeout)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
            return True
        except socket.error:
            self.printer.print("No internet connection detected.", "warning")
            return False

    def validate_target(self, target: str) -> Tuple[bool, str, str]:
        if not target: return False, "empty", ""
        target = target.strip()
        try:
            ipaddress.ip_address(target)
            return True, "ip", target
        except ValueError: pass
        if target.startswith(('http://', 'https://')):
            try:
                parsed = urlparse(target)
                if parsed.netloc: return True, "url", parsed.netloc
            except: pass
        if '.' in target:
            if len(target) < 255: return True, "domain", target
        return False, "invalid", ""

    def run_module_safe(self, name: str, func, target: str, params: Dict) -> Dict[str, Any]:
        self.printer.print(f"Starting {name} module...", "running")
        start_t = time.time()
        
        # Inject target into params based on module requirement
        if name in ['whois', 'dns', 'subdomain']:
            params['domain'] = target
        elif name == 'ssl':
            params['host'] = target
        elif name == 'directory':
            params['target_url'] = target
        else:
            params['target'] = target

        # Pass callback for modules that print real-time logs (like dir_enum)
        params['printer_callback'] = self.printer.print

        try:
            # Execute
            raw_result = func(params)
            
            # Normalize Result
            if isinstance(raw_result, str):
                try: result = json.loads(raw_result)
                except: return {'status': 'error', 'error': 'Invalid JSON output'}
            elif isinstance(raw_result, dict):
                result = raw_result
            else:
                return {'status': 'error', 'error': 'Unknown return type'}
                
            duration = time.time() - start_t
            result['duration'] = duration
            
            # Check status
            if result.get('status') == 'error':
                self.printer.print(f"{name} finished with errors: {result['error']}", "error")
            elif result.get('error'):
                self.printer.print(f"{name} reported error: {result['error']}", "error")
                result['status'] = 'error'
            else:
                self.printer.print(f"{name} completed successfully ({duration:.2f}s)", "success")
                result['status'] = 'success'
                
            return result
            
        except Exception as e:
            duration = time.time() - start_t
            self.printer.print(f"{name} crashed: {str(e)}", "error")
            return {'status': 'error', 'error': f"Exception: {str(e)}", 'duration': duration}

    def execute_scan(self, command: str, target: str, args: argparse.Namespace) -> None:
        # Validate Target
        is_valid, target_type, domain = self.validate_target(target)
        if not is_valid:
            self.printer.print(f"Invalid target format: {target}", "error")
            return

        base_params = {'timeout': args.timeout, 'verbose': args.verbose}
        
        results = {
            'scan_info': {
                'target': target, 'domain': domain, 'type': target_type,
                'command': command, 'start_time': datetime.now().isoformat(),
                'version': self.version
            },
            'modules': {}
        }

        # --- COMMAND DISPATCHER ---
        
        # 1. NETWORK
        if command == 'network':
            params = {**base_params, 'max_threads': args.threads, 'ports': args.ports}
            net_target = domain if target_type == 'url' else target
            results['modules']['network'] = self.run_module_safe('network', self.modules['network'].run_module, net_target, params)

        # 2. DNS
        elif command == 'dns':
            # FIX: Explicit None for wordlist if not set
            params = {**base_params, 'wordlist': getattr(args, 'wordlist', None), 'dns_server': args.dns_server}
            results['modules']['dns'] = self.run_module_safe('dns', self.modules['dns'].run_module, domain, params)

        # 3. WHOIS
        elif command == 'whois':
            params = {**base_params, 'whois_server': args.whois_server}
            results['modules']['whois'] = self.run_module_safe('whois', self.modules['whois'].run_module, domain, params)

        # 4. SUBDOMAIN
        elif command == 'subs':
            params = {**base_params, 'max_workers': args.threads, 'wordlist': args.wordlist, 'max_subdomains': args.limit}
            results['modules']['subdomain'] = self.run_module_safe('subdomain', self.modules['subdomain'].run_module, domain, params)

        # 5. DIRECTORY
        elif command == 'dir':
            params = {
                **base_params, 
                'max_threads': args.threads, 
                'wordlist': getattr(args, 'wordlist', None),
                'extensions': args.extensions,
                'exclude_status': args.exclude_status
            }
            # Directory enum needs URL protocol
            dir_target = target
            if not target.startswith(('http://', 'https://')):
                dir_target = f"https://{target}"
            results['modules']['directory'] = self.run_module_safe('directory', self.modules['directory'].run_module, dir_target, params)

        # 6. HTTP
        elif command == 'http':
            params = {**base_params, 'https': not args.no_https, 'port': args.port}
            results['modules']['http'] = self.run_module_safe('http', self.modules['http'].run_module, target, params)

        # 7. SSL
        elif command == 'ssl':
            params = {**base_params, 'port': args.port or 443}
            results['modules']['ssl'] = self.run_module_safe('ssl', self.modules['ssl'].run_module, domain, params)

        # 8. FULL SCAN
        elif command == 'fullscan':
            self._run_full_scan_parallel(target, domain, target_type, args, results)

        self._finalize_scan(results, args.format)

    def _run_full_scan_parallel(self, target: str, domain: str, target_type: str, args: argparse.Namespace, results: Dict):
        self.printer.print(f"Starting optimized full scan on {target}...", "info")
        net_target = domain if target_type == 'url' else target
        dir_target = target if target.startswith(('http', 'https')) else f"https://{target}"
        
        # Define tasks (Module Name, Function, Target, Params)
        tasks = [
            ('whois', self.modules['whois'].run_module, domain, {'timeout': 10}),
            ('dns', self.modules['dns'].run_module, domain, {'timeout': 5, 'comprehensive': True}),
            ('subdomain', self.modules['subdomain'].run_module, domain, {'timeout': 3, 'max_workers': args.threads}),
            ('network', self.modules['network'].run_module, net_target, {'timeout': 3, 'max_threads': args.threads, 'scan_type': 'full'}),
            ('ssl', self.modules['ssl'].run_module, domain, {'timeout': 10, 'port': 443, 'action': 'full_enum'}),
            ('http', self.modules['http'].run_module, net_target, {'timeout': 10, 'use_https': True, 'analysis_type': 'full'}),
            ('directory', self.modules['directory'].run_module, dir_target, {'timeout': 10, 'max_threads': 20, 'extensions': 'php,html,json'})
        ]
        
        if args.fast:
            tasks = [t for t in tasks if t[0] != 'directory']
            self.printer.print("Fast mode enabled: Skipping directory enumeration", "warning")

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
            future_map = {executor.submit(self.run_module_safe, name, func, tgt, params): name for name, func, tgt, params in tasks}
            for future in concurrent.futures.as_completed(future_map):
                module_name = future_map[future]
                try: results['modules'][module_name] = future.result()
                except Exception as e: results['modules'][module_name] = {'status': 'error', 'error': str(e)}

    def _finalize_scan(self, results: Dict[str, Any], output_formats: str) -> None:
        results['scan_info']['end_time'] = datetime.now().isoformat()
        
        self.printer.print("\nGenerating reports...", "info")
        formats = [f.strip().lower() for f in output_formats.split(',')]
        
        if 'json' in formats: 
            json_path = os.path.join(self.output_dir, "results.json")
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
            self.printer.print(f"JSON Report: {json_path}", "success")
        
        if 'txt' in formats: 
            path = self.report_manager.save_text(results)
            self.printer.print(f"Text Report: {path}", "success")
        
        if 'csv' in formats: self.report_manager.save_csv(results)
        
        if 'html' in formats and 'report' in self.modules:
            try:
                # Use the advanced report generator
                html_path = os.path.join(self.output_dir, "advanced_report.html")
                self.modules['report'].run_module({
                    'results_data': results, 
                    'output_file': html_path,
                    'title': f"Recony Security Report - {results['scan_info'].get('target', 'Unknown')}"
                })
                self.printer.print(f"Advanced HTML Report: {html_path}", "success")
            except Exception as e:
                self.printer.print(f"HTML Generation failed: {e}", "warning")
                # Fall back to basic HTML if available
                try:
                    html_path = os.path.join(self.output_dir, "report.html")
                    self.modules['report'].run_module({'results_data': results, 'output_file': html_path})
                    self.printer.print(f"Basic HTML Report: {html_path}", "success")
                except:
                    pass

        zip_path = self.report_manager.archive_results()
        if zip_path: self.printer.print(f"Results Archived: {zip_path}", "success")

def parse_args():
    parser = argparse.ArgumentParser(description="Recony - Professional Web Reconnaissance Framework", formatter_class=argparse.RawDescriptionHelpFormatter)
    
    global_group = parser.add_argument_group('Global Options')
    global_group.add_argument('-o', '--output', default=DEFAULT_CONFIG['output_dir'], help='Output directory')
    global_group.add_argument('-f', '--format', default='txt,json,html,csv', help='Output formats')
    global_group.add_argument('-v', '--verbose', action='store_true', help='Enable debug logging')
    global_group.add_argument('--no-color', action='store_true', help='Disable colored output')
    
    subparsers = parser.add_subparsers(dest='command', help='Scan Modules')
    
    # Network
    net = subparsers.add_parser('network', help='Port scanning')
    net.add_argument('target', help='Target IP/Host')
    net.add_argument('-t', '--timeout', type=int, default=3)
    net.add_argument('-j', '--threads', type=int, default=50)
    net.add_argument('--ports', help='Ports to scan')
    
    # DNS
    dns = subparsers.add_parser('dns', help='DNS info')
    dns.add_argument('domain', help='Target Domain')
    dns.add_argument('-t', '--timeout', type=int, default=5)
    dns.add_argument('-w', '--wordlist', help='Subdomain wordlist')
    dns.add_argument('--dns-server', help='Custom DNS resolver')
    
    # Whois
    whois = subparsers.add_parser('whois', help='Whois info')
    whois.add_argument('domain', help='Target Domain')
    whois.add_argument('-t', '--timeout', type=int, default=10)
    whois.add_argument('--whois-server', help='Specific Whois server')
    
    # SSL
    ssl = subparsers.add_parser('ssl', help='SSL analysis')
    ssl.add_argument('target', help='Target Host')
    ssl.add_argument('-p', '--port', type=int, default=443)
    ssl.add_argument('-t', '--timeout', type=int, default=10)
    
    # HTTP
    http = subparsers.add_parser('http', help='HTTP fingerprinting')
    http.add_argument('target', help='Target URL/Host')
    http.add_argument('-t', '--timeout', type=int, default=10)
    http.add_argument('--no-https', action='store_true', help='Force HTTP only')
    http.add_argument('-p', '--port', type=int, help='Custom port')
    
    # Directory
    dir_scan = subparsers.add_parser('dir', help='Directory brute-forcing')
    dir_scan.add_argument('target', help='Target URL')
    dir_scan.add_argument('-t', '--timeout', type=int, default=10)
    dir_scan.add_argument('-j', '--threads', type=int, default=30)
    dir_scan.add_argument('-w', '--wordlist', help='Custom wordlist path')
    dir_scan.add_argument('-e', '--extensions', help='Extensions (php,html)')
    dir_scan.add_argument('-x', '--exclude-status', type=int, nargs='+', help='Exclude status codes')
    
    # Subdomain
    sub = subparsers.add_parser('subs', help='Subdomain discovery')
    sub.add_argument('domain', help='Target Domain')
    sub.add_argument('-t', '--timeout', type=int, default=3)
    sub.add_argument('-j', '--threads', type=int, default=50)
    sub.add_argument('-w', '--wordlist', help='Custom wordlist')
    sub.add_argument('-l', '--limit', type=int, help='Limit results')
    
    # Full Scan
    full = subparsers.add_parser('fullscan', help='Run all modules')
    full.add_argument('target', help='Target Domain/IP')
    full.add_argument('-t', '--timeout', type=int, default=5)
    full.add_argument('-j', '--threads', type=int, default=50)
    full.add_argument('--fast', action='store_true', help='Skip directory enumeration')
    
    return parser.parse_args()

def main():
    print(BANNER)
    args = parse_args()
    if not args.command:
        print("Error: No command specified. Use -h for help.")
        sys.exit(1)
        
    controller = ReconyController()
    if not controller.initialize(args):
        sys.exit(1)
        
    if not controller.check_connection():
        controller.printer.print("Warning: Continuing without internet access...", "warning")

    target = getattr(args, 'target', None) or getattr(args, 'domain', None)
    if not target:
        controller.printer.print("Error: Target not specified.", "error")
        sys.exit(1)

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