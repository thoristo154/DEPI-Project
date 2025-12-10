#!/usr/bin/env python3
"""
Enhanced Directory & File Enumeration Module
Style: Dirsearch Replica
Features: Threaded, Colorized, Extension Support, Smart Wordlist Loading
"""

import threading
import queue
import time
import urllib.parse
import http.client
import ssl
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any

# ANSI Colors for Dirsearch-like output
C_RESET = "\033[0m"
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_BLUE = "\033[34m"
C_CYAN = "\033[36m"
C_MAGENTA = "\033[35m"
C_GREY = "\033[90m"

class DirectoryEnumerator:
    
    def __init__(self, timeout: int = 10, max_threads: int = 30, 
                 user_agent: str = None, printer_callback=None):
        self.timeout = timeout
        self.max_threads = max_threads
        self.user_agent = user_agent or "Recony-DirScanner/2.0"
        self.printer = printer_callback
        self.found_paths = []
        self.lock = threading.Lock()
        
        # Optimize SSL: Load once, verify none for speed
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    def _get_color(self, code: int) -> str:
        """Return ANSI color based on status code."""
        if 200 <= code < 300: return C_GREEN
        if 300 <= code < 400: return C_CYAN
        if 400 <= code < 500: return C_YELLOW  # 403 often interesting
        if code == 404: return C_GREY
        if code >= 500: return C_RED
        return C_RESET

    def _log_dirsearch_style(self, code: int, size: int, path: str, url: str, redirect: str = None):
        """Prints output exactly like Dirsearch."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = self._get_color(code)
        
        # Format: [TIME] CODE - SIZE - URL -> REDIRECT
        # Size formatted to right-align
        size_str = f"{size}B"
        
        msg = f"{C_YELLOW}[{timestamp}]{C_RESET} {color}{code:<3}{C_RESET} - {C_GREY}{size_str:>9}{C_RESET} - {path:<30}"
        
        if redirect:
            msg += f"  ->  {C_CYAN}{redirect}{C_RESET}"
        else:
            msg += f"  ->  {url}"

        # Use Recony's printer if available (passing 'raw' status to avoid double prefixing)
        if self.printer:
            self.printer(msg, "raw") 
        else:
            print(msg)

    def _request(self, host: str, port: int, method: str, path: str, use_https: bool) -> Dict:
        """Perform a highly optimized raw HTTP request."""
        conn = None
        try:
            if use_https:
                conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=self.ssl_context)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
            
            headers = {
                'User-Agent': self.user_agent,
                'Connection': 'keep-alive',
                'Accept': '*/*'
            }
            
            conn.request(method, path, headers=headers)
            resp = conn.getresponse()
            
            # Read body to get size and clear buffer
            body = resp.read()
            length = len(body)
            
            redirect_location = None
            if resp.status in [301, 302, 307, 308]:
                redirect_location = resp.getheader('Location')

            result = {
                'code': resp.status,
                'size': length,
                'redirect': redirect_location
            }
            conn.close()
            return result
        except Exception:
            if conn:
                try: conn.close()
                except: pass
            return None

    def _load_wordlist(self, custom_path: str = None) -> List[str]:
        """Loads wordlist from custom path or default 'wordlists' folder."""
        file_path = custom_path
        
        # If no custom path, look for default in ./wordlists/common.txt relative to this script
        if not file_path:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            default_path = os.path.join(base_dir, 'wordlists', 'common.txt')
            
            # Check if file exists
            if os.path.exists(default_path):
                file_path = default_path
                if self.printer: self.printer(f"Using default wordlist: {file_path}", "info")
            else:
                # Fallback list if file missing
                if self.printer: self.printer("Wordlist not found. Using internal fallback list.", "warning")
                return ['admin', 'login', 'dashboard', 'config', 'robots.txt', '.env', 'backup', 'api', 'uploads', 'images']

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            if self.printer:
                self.printer(f"Error loading wordlist {file_path}: {e}", "error")
            return []

    def run_dir_enum(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Main execution entry point."""
        target_url = params.get('target_url')
        custom_wordlist = params.get('wordlist')
        # Extensions can be passed as "php,html" or list
        extensions_arg = params.get('extensions', '') 
        exclude_status = params.get('exclude_status', []) # List of ints to exclude
        
        # Parse URL
        try:
            parsed = urllib.parse.urlparse(target_url)
            host = parsed.netloc
            scheme = parsed.scheme
            if not scheme:
                scheme = 'https'
                host = target_url # Simple fix if user forgot protocol
                
            use_https = (scheme == 'https')
            base_path = parsed.path if parsed.path.endswith('/') else parsed.path + '/'
            
            # Handle Port
            port = parsed.port
            if not port:
                port = 443 if use_https else 80
        except Exception as e:
            return {'status': 'error', 'error': f"Invalid URL: {e}"}

        # Prepare Wordlist & Extensions
        words = self._load_wordlist(custom_wordlist)
        
        # Process extensions
        # If extensions provided, we check word, word.ext1, word.ext2
        # If no extensions provided, we just check the word
        extensions = ['']
        if extensions_arg:
            if isinstance(extensions_arg, str):
                ext_list = extensions_arg.split(',')
            else:
                ext_list = extensions_arg
                
            for ext in ext_list:
                clean_ext = ext.strip()
                if not clean_ext: continue
                if not clean_ext.startswith('.'): clean_ext = '.' + clean_ext
                extensions.append(clean_ext)
        
        # Status Reporting
        if self.printer:
            self.printer(f"Target: {scheme}://{host}:{port}{base_path}", "info")
            self.printer(f"Wordlist: {len(words)} paths | Extensions: {extensions}", "info")
            self.printer(f"Threads: {self.max_threads}", "info")
            # Print Legend
            self.printer(f"Format: {C_YELLOW}[TIME]{C_RESET} CODE - SIZE - PATH -> REDIRECT", "raw")
            self.printer("-" * 60, "raw")

        # Queue Setup
        q = queue.Queue()
        for word in words:
            q.put(word)

        # Worker Function
        def worker():
            while not q.empty():
                try:
                    word = q.get_nowait()
                    
                    # Try word + extensions
                    for ext in extensions:
                        current_path = f"{base_path}{word}{ext}"
                        
                        # Fix double slashes just in case
                        current_path = current_path.replace('//', '/')
                        
                        res = self._request(host, port, "GET", current_path, use_https)
                        
                        if res:
                            code = res['code']
                            
                            # Filter status codes (Default exclude 404)
                            should_log = True
                            if code == 404: 
                                should_log = False
                            if code in exclude_status:
                                should_log = False
                                
                            if should_log:
                                full_url = f"{scheme}://{host}:{port}{current_path}"
                                
                                self._log_dirsearch_style(
                                    code, 
                                    res['size'], 
                                    current_path, 
                                    full_url, 
                                    res['redirect']
                                )
                                
                                with self.lock:
                                    self.found_paths.append({
                                        'path': current_path,
                                        'status_code': code,
                                        'size': res['size'],
                                        'url': full_url,
                                        'redirect': res['redirect']
                                    })
                                    
                except queue.Empty:
                    break
                except Exception:
                    pass
                finally:
                    q.task_done()

        # Start Threads
        threads = []
        for _ in range(min(self.max_threads, len(words))):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)
            
        for t in threads:
            t.join()

        if self.printer:
            self.printer("-" * 60, "raw")
            
        return {
            'status': 'success',
            'target': target_url,
            'enumeration': {
                'results': self.found_paths,
                'total_found': len(self.found_paths)
            }
        }

def run_module(params: Dict[str, Any]) -> Dict[str, Any]:
    printer = params.get('printer_callback')
    enum = DirectoryEnumerator(
        timeout=int(params.get('timeout', 10)),
        max_threads=int(params.get('max_threads', 30)),
        printer_callback=printer
    )
    return enum.run_dir_enum(params)