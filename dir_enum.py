#!/usr/bin/env python3
"""
Enhanced Directory & File Enumeration Module

A comprehensive web application directory and file enumeration tool
that performs multi-threaded scanning with automatic wordlist management.

Author: Cybersecurity Expert
Version: 2.0
"""

import os
import sys
import threading
import queue
import time
import json
import logging
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Any, Tuple
from argparse import Namespace
from urllib.parse import urljoin, urlparse
from http.client import HTTPResponse
import http.client
import ssl
import hashlib
import random
import socket

# Configure module logging
logger = logging.getLogger('dir_enum')

class DirectoryEnumerator:
    """
    An enhanced directory and file enumeration tool for web applications.
    Supports multi-threaded scanning, automatic wordlist management, and
    detailed response analysis.
    """
    
    # Enhanced common file extensions to try
    COMMON_EXTENSIONS = [
        '', '.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.jspx', 
        '.txt', '.bak', '.old', '.orig', '.backup', '.tar', '.gz', '.zip', 
        '.sql', '.json', '.xml', '.log', '.md', '.yml', '.yaml', '.conf',
        '.config', '.ini', '.env', '.pem', '.key', '.crt', '.csr'
    ]
    
    # Sensitive file patterns
    SENSITIVE_FILES = [
        '.env', '.git/config', '.htaccess', '.htpasswd', 'web.config',
        'config.php', 'settings.py', 'wp-config.php', 'database.yml',
        'backup.zip', 'dump.sql', 'password.txt', 'secret.key'
    ]
    
    # Default wordlist URLs
    DEFAULT_WORDLIST_URLS = [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"
    ]
    
    # Common HTTP status codes and their meanings
    STATUS_CODES = {
        200: "OK",
        301: "Moved Permanently",
        302: "Found",
        303: "See Other",
        307: "Temporary Redirect",
        308: "Permanent Redirect",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        500: "Internal Server Error",
        503: "Service Unavailable"
    }

    def __init__(self, timeout: int = 10, max_threads: int = 20, 
                 user_agent: str = None, follow_redirects: bool = True,
                 delay: float = 0):
        """
        Initialize the enhanced Directory Enumerator.
        
        Args:
            timeout: Request timeout in seconds
            max_threads: Maximum number of concurrent threads
            user_agent: Custom User-Agent string
            follow_redirects: Whether to follow HTTP redirects
            delay: Delay between requests in seconds
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.user_agent = user_agent or self._get_random_user_agent()
        self.follow_redirects = follow_redirects
        self.delay = delay
        self.results_queue = queue.Queue()
        self.scanned_paths = set()
        self.lock = threading.Lock()
        
        # SSL context for HTTPS requests
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        logger.info("DirectoryEnumerator initialized with timeout=%s, max_threads=%s", 
                   timeout, max_threads)

    def _get_random_user_agent(self) -> str:
        """
        Get a random realistic user agent string.
        
        Returns:
            User agent string
        """
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
        ]
        return random.choice(user_agents)

    def _ensure_wordlist_dir(self) -> str:
        """
        Ensure the wordlists directory exists.
        
        Returns:
            Path to wordlists directory
        """
        wordlist_dir = "./wordlists"
        try:
            if not os.path.exists(wordlist_dir):
                os.makedirs(wordlist_dir)
                logger.info("Created wordlists directory: %s", wordlist_dir)
            return wordlist_dir
        except Exception as e:
            logger.error("Failed to create wordlists directory: %s", e)
            raise

    def _download_wordlist(self, url: str, wordlist_path: str) -> bool:
        """
        Download a wordlist from a URL.
        
        Args:
            url: URL to download from
            wordlist_path: Path where to save the wordlist
            
        Returns:
            True if download successful, False otherwise
        """
        try:
            logger.info("Downloading wordlist from: %s", url)
            
            # Create request with headers
            request = urllib.request.Request(
                url,
                headers={'User-Agent': self.user_agent}
            )
            
            # Download with progress tracking
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                total_size = int(response.headers.get('content-length', 0))
                chunk_size = 8192
                downloaded = 0
                
                with open(wordlist_path, 'wb') as f:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            if int(percent) % 10 == 0:  # Log every 10%
                                logger.info("Download progress: %d%%", int(percent))
            
            logger.info("Successfully downloaded wordlist to: %s", wordlist_path)
            return True
            
        except urllib.error.URLError as e:
            logger.error("Failed to download wordlist: %s", e)
            return False
        except Exception as e:
            logger.error("Unexpected error during wordlist download: %s", e)
            return False

    def _validate_wordlist(self, wordlist_path: str) -> Tuple[bool, List[str]]:
        """
        Enhanced wordlist file validation and loading.
        
        Args:
            wordlist_path: Path to wordlist file
            
        Returns:
            Tuple of (is_valid, wordlist_entries)
        """
        try:
            if not os.path.exists(wordlist_path):
                logger.error("Wordlist file does not exist: %s", wordlist_path)
                return False, []
            
            if not os.path.isfile(wordlist_path):
                logger.error("Wordlist path is not a file: %s", wordlist_path)
                return False, []
            
            file_size = os.path.getsize(wordlist_path)
            if file_size == 0:
                logger.error("Wordlist file is empty: %s", wordlist_path)
                return False, []
            
            # Read and validate wordlist entries
            entries = []
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Remove comments at end of line
                        line = line.split('#')[0].strip()
                        if line:
                            entries.append(line)
            
            if not entries:
                logger.error("No valid entries found in wordlist: %s", wordlist_path)
                return False, []
            
            logger.info("Loaded %d entries from wordlist: %s", len(entries), wordlist_path)
            return True, entries
            
        except PermissionError:
            logger.error("Permission denied accessing wordlist: %s", wordlist_path)
            return False, []
        except Exception as e:
            logger.error("Error validating wordlist %s: %s", wordlist_path, e)
            return False, []

    def get_wordlist(self, custom_wordlist: Optional[str] = None) -> List[str]:
        """
        Enhanced wordlist management with multiple fallback options.
        
        Args:
            custom_wordlist: Path to custom wordlist file
            
        Returns:
            List of wordlist entries
        """
        wordlist_path = custom_wordlist
        
        if not wordlist_path:
            # Use default wordlist
            wordlist_dir = self._ensure_wordlist_dir()
            wordlist_path = os.path.join(wordlist_dir, "common.txt")
            
            if not os.path.exists(wordlist_path):
                logger.info("Default wordlist not found, attempting download...")
                success = False
                for url in self.DEFAULT_WORDLIST_URLS:
                    if self._download_wordlist(url, wordlist_path):
                        success = True
                        break
                if not success:
                    raise RuntimeError("Failed to download default wordlist from all sources")
        
        # Validate and load wordlist
        is_valid, entries = self._validate_wordlist(wordlist_path)
        if not is_valid:
            raise RuntimeError(f"Invalid wordlist: {wordlist_path}")
        
        return entries

    def _send_request(self, url: str, method: str = 'GET') -> Dict[str, Any]:
        """
        Enhanced HTTP request with comprehensive response analysis.
        
        Args:
            url: Target URL
            method: HTTP method (GET or HEAD)
            
        Returns:
            Dictionary with response details
        """
        result = {
            'url': url,
            'method': method,
            'status_code': None,
            'reason': None,
            'content_length': 0,
            'response_time': 0,
            'redirect_url': None,
            'headers': {},
            'content_hash': None,
            'error': None,
            'success': False
        }
        
        start_time = time.time()
        
        try:
            # Parse URL
            parsed = urlparse(url)
            host = parsed.netloc
            path = parsed.path or '/'
            
            # Create connection based on scheme
            if parsed.scheme == 'https':
                conn = http.client.HTTPSConnection(host, timeout=self.timeout, context=self.ssl_context)
            else:
                conn = http.client.HTTPConnection(host, timeout=self.timeout)
            
            # Send request
            headers = {
                'User-Agent': self.user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'close'
            }
            
            conn.request(method, path, headers=headers)
            response = conn.getresponse()
            
            # Read response content for GET requests
            content = b''
            if method == 'GET':
                content = response.read()
            
            result['status_code'] = response.status
            result['reason'] = response.reason
            result['content_length'] = len(content) if method == 'GET' else int(response.getheader('Content-Length', 0))
            result['response_time'] = round(time.time() - start_time, 3)
            result['success'] = True
            
            # Extract headers
            for header, value in response.getheaders():
                result['headers'][header] = value
            
            # Calculate content hash for GET requests
            if method == 'GET' and content:
                result['content_hash'] = hashlib.md5(content).hexdigest()
            
            # Handle redirects
            if response.status in [301, 302, 303, 307, 308] and self.follow_redirects:
                location = response.getheader('Location')
                if location:
                    result['redirect_url'] = urljoin(url, location)
            
            conn.close()
            
        except http.client.HTTPException as e:
            result['error'] = f"HTTP error: {e}"
        except socket.timeout:
            result['error'] = f"Request timeout after {self.timeout} seconds"
        except ConnectionRefusedError:
            result['error'] = "Connection refused"
        except Exception as e:
            result['error'] = f"Request error: {e}"
        
        return result

    def _is_interesting_response(self, response_info: Dict[str, Any]) -> bool:
        """
        Determine if a response is interesting based on various factors.
        
        Args:
            response_info: Response information dictionary
            
        Returns:
            True if response is interesting
        """
        if not response_info['success']:
            return False
        
        status_code = response_info['status_code']
        
        # Always log error status codes
        if status_code >= 400 and status_code != 404:
            return True
        
        # Log successful responses (200, 301, 302, etc.)
        if status_code in [200, 301, 302, 303, 307, 308]:
            return True
        
        # Log responses with interesting content characteristics
        if response_info['content_length'] > 0 and status_code != 404:
            return True
        
        return False

    def _classify_finding(self, response_info: Dict[str, Any], path: str) -> str:
        """
        Classify the finding based on response characteristics.
        
        Args:
            response_info: Response information
            path: Requested path
            
        Returns:
            Finding classification
        """
        status_code = response_info['status_code']
        
        if status_code == 200:
            # Check if it's a sensitive file
            if any(sensitive in path for sensitive in self.SENSITIVE_FILES):
                return "sensitive"
            elif path.endswith(('.php', '.asp', '.jsp', '.py')):
                return "executable"
            elif path.endswith(('.txt', '.log', '.sql', '.xml', '.json')):
                return "data_file"
            else:
                return "accessible"
        
        elif status_code in [301, 302, 303, 307, 308]:
            return "redirect"
        
        elif status_code == 401:
            return "unauthorized"
        
        elif status_code == 403:
            return "forbidden"
        
        elif status_code == 500:
            return "server_error"
        
        else:
            return "other"

    def worker_thread(self, target_url: str, wordlist_queue: queue.Queue, 
                     method: str, extensions: List[str], 
                     progress_callback: callable = None) -> None:
        """
        Enhanced worker thread for directory enumeration.
        
        Args:
            target_url: Base target URL
            wordlist_queue: Queue of paths to check
            method: HTTP method to use
            extensions: File extensions to try
            progress_callback: Callback for progress updates
        """
        while True:
            try:
                path = wordlist_queue.get_nowait()
            except queue.Empty:
                break
            
            try:
                # Try path with different extensions
                for ext in extensions:
                    test_path = f"{path}{ext}" if ext else path
                    full_url = urljoin(target_url, test_path)
                    
                    # Avoid duplicate scanning
                    with self.lock:
                        if full_url in self.scanned_paths:
                            wordlist_queue.task_done()
                            continue
                        self.scanned_paths.add(full_url)
                    
                    # Send request and get results
                    response_info = self._send_request(full_url, method)
                    
                    # Only log interesting responses
                    if self._is_interesting_response(response_info):
                        classification = self._classify_finding(response_info, test_path)
                        
                        result = {
                            'path': test_path,
                            'url': full_url,
                            'status_code': response_info['status_code'],
                            'status_reason': response_info['reason'],
                            'content_length': response_info['content_length'],
                            'response_time': response_info['response_time'],
                            'redirect_url': response_info['redirect_url'],
                            'method': method,
                            'classification': classification,
                            'headers': response_info.get('headers', {}),
                            'content_hash': response_info.get('content_hash')
                        }
                        
                        self.results_queue.put(result)
                        
                        logger.info("Found: %s [%d] [%s] [%d bytes] [%.3fs]", 
                                   test_path, response_info['status_code'],
                                   classification, response_info['content_length'],
                                   response_info['response_time'])
                    
                    # Call progress callback if provided
                    if progress_callback:
                        progress_callback()
                    
                    # Respect delay between requests
                    if self.delay > 0:
                        time.sleep(self.delay)
                    
            except Exception as e:
                logger.error("Error in worker thread for path %s: %s", path, e)
            finally:
                wordlist_queue.task_done()

    def enumerate_paths(self, target_url: str, wordlist_entries: List[str],
                       method: str = 'GET', use_extensions: bool = True,
                       progress_callback: callable = None) -> Dict[str, Any]:
        """
        Enhanced directory enumeration with progress tracking.
        
        Args:
            target_url: Base URL to scan
            wordlist_entries: List of paths to check
            method: HTTP method to use
            use_extensions: Whether to try different file extensions
            progress_callback: Callback for progress updates
            
        Returns:
            Dictionary with enumeration results
        """
        result = {
            'target_url': target_url,
            'scan_method': method,
            'total_paths_tested': 0,
            'interesting_paths_found': 0,
            'scan_duration': 0,
            'findings_by_classification': {},
            'results': [],
            'error': None
        }
        
        start_time = time.time()
        
        try:
            # Validate target URL
            parsed = urlparse(target_url)
            if not parsed.scheme or not parsed.netloc:
                result['error'] = f"Invalid target URL: {target_url}"
                return result
            
            # Test base URL first
            logger.info("Testing base URL: %s", target_url)
            base_test = self._send_request(target_url, method)
            if base_test['error']:
                result['error'] = f"Base URL unreachable: {base_test['error']}"
                return result
            
            logger.info("Base URL responded with status: %d", base_test['status_code'])
            
            # Prepare extensions
            extensions = self.COMMON_EXTENSIONS if use_extensions else ['']
            
            # Create queue and add paths
            wordlist_queue = queue.Queue()
            total_paths = len(wordlist_entries) * len(extensions)
            result['total_paths_tested'] = total_paths
            
            for path in wordlist_entries:
                wordlist_queue.put(path)
            
            # Start worker threads
            threads = []
            for _ in range(min(self.max_threads, len(wordlist_entries))):
                thread = threading.Thread(
                    target=self.worker_thread,
                    args=(target_url, wordlist_queue, method, extensions, progress_callback)
                )
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            # Wait for all threads to complete
            wordlist_queue.join()
            
            # Collect results
            interesting_paths = 0
            findings_by_classification = {}
            
            while not self.results_queue.empty():
                try:
                    result_item = self.results_queue.get_nowait()
                    result['results'].append(result_item)
                    interesting_paths += 1
                    
                    # Group by classification
                    classification = result_item['classification']
                    if classification not in findings_by_classification:
                        findings_by_classification[classification] = []
                    findings_by_classification[classification].append(result_item)
                    
                except queue.Empty:
                    break
            
            result['interesting_paths_found'] = interesting_paths
            result['findings_by_classification'] = findings_by_classification
            result['scan_duration'] = round(time.time() - start_time, 2)
            
            logger.info("Enumeration completed: %d interesting paths found in %.2f seconds", 
                       interesting_paths, result['scan_duration'])
            
        except Exception as e:
            result['error'] = f"Enumeration error: {e}"
            logger.error("Enumeration failed for %s: %s", target_url, e)
        
        return result

    def run_dir_enum(self, target_url: str, custom_wordlist: Optional[str] = None,
                    method: str = 'GET', use_extensions: bool = True,
                    progress_callback: callable = None) -> Dict[str, Any]:
        """
        Enhanced main directory enumeration runner.
        
        Args:
            target_url: Target URL to scan
            custom_wordlist: Path to custom wordlist file
            method: HTTP method to use
            use_extensions: Whether to try different file extensions
            progress_callback: Callback for progress updates
            
        Returns:
            Comprehensive enumeration results
        """
        full_result = {
            'target_url': target_url,
            'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'wordlist_source': 'default',
            'scan_parameters': {
                'method': method,
                'use_extensions': use_extensions,
                'max_threads': self.max_threads,
                'timeout': self.timeout
            },
            'enumeration': {},
            'summary': {},
            'error': None
        }
        
        logger.info("Starting directory enumeration for: %s", target_url)
        
        try:
            # Get wordlist
            wordlist_entries = self.get_wordlist(custom_wordlist)
            full_result['wordlist_source'] = (
                'custom' if custom_wordlist else 'default'
            )
            full_result['wordlist_entries_count'] = len(wordlist_entries)
            
            # Run enumeration
            enum_result = self.enumerate_paths(
                target_url, wordlist_entries, method, use_extensions, progress_callback
            )
            full_result['enumeration'] = enum_result
            
            # Generate enhanced summary
            if enum_result['error']:
                full_result['error'] = enum_result['error']
                full_result['summary'] = {'scan_successful': False}
            else:
                findings_by_class = enum_result.get('findings_by_classification', {})
                
                full_result['summary'] = {
                    'scan_successful': True,
                    'total_paths_tested': enum_result['total_paths_tested'],
                    'interesting_paths_found': enum_result['interesting_paths_found'],
                    'scan_duration_seconds': enum_result['scan_duration'],
                    'findings_breakdown': {
                        classification: len(items) 
                        for classification, items in findings_by_class.items()
                    },
                    'sensitive_findings': len(findings_by_class.get('sensitive', [])),
                    'executable_findings': len(findings_by_class.get('executable', [])),
                    'data_file_findings': len(findings_by_class.get('data_file', []))
                }
            
            logger.info("Directory enumeration completed for %s", target_url)
            
        except Exception as e:
            full_result['error'] = f"Directory enumeration failed: {e}"
            full_result['summary'] = {'scan_successful': False}
            logger.error("Directory enumeration failed for %s: %s", target_url, e)
        
        return full_result


def handle_dir_enum(args: Namespace) -> str:
    """
    Enhanced directory enumeration handler with better parameter processing.
    
    Args:
        args: argparse.Namespace with enumeration parameters
        
    Returns:
        JSON string with enumeration results
    """
    try:
        enumerator = DirectoryEnumerator(
            timeout=getattr(args, 'timeout', 10),
            max_threads=getattr(args, 'max_threads', 20),
            user_agent=getattr(args, 'user_agent', None),
            follow_redirects=getattr(args, 'follow_redirects', True),
            delay=getattr(args, 'delay', 0)
        )
        
        target_url = getattr(args, 'target_url', '')
        if not target_url:
            return json.dumps({'error': 'No target URL specified'}, indent=2)
        
        result = enumerator.run_dir_enum(
            target_url=target_url,
            custom_wordlist=getattr(args, 'wordlist', None),
            method=getattr(args, 'method', 'GET'),
            use_extensions=not getattr(args, 'no_extensions', False)
        )
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        error_result = {
            'error': f"Directory enumeration failed: {e}",
            'target_url': getattr(args, 'target_url', 'unknown')
        }
        return json.dumps(error_result, indent=2)


def run_module(params_dict: Dict[str, Any]) -> str:
    """
    Enhanced main module entry point for integration with orchestration tools.
    
    Args:
        params_dict: Dictionary containing enumeration parameters:
            - target_url: required, URL to enumerate
            - wordlist: optional, custom wordlist path
            - timeout: optional, request timeout in seconds
            - max_threads: optional, maximum concurrent threads
            - method: optional, HTTP method ('GET' or 'HEAD')
            - no_extensions: optional, skip file extensions
            - follow_redirects: optional, follow HTTP redirects
            - user_agent: optional, custom User-Agent string
            - delay: optional, delay between requests in seconds
            
    Returns:
        JSON string with enumeration results
    """
    try:
        # Create enumerator with provided parameters
        enumerator = DirectoryEnumerator(
            timeout=params_dict.get('timeout', 10),
            max_threads=params_dict.get('max_threads', 20),
            user_agent=params_dict.get('user_agent'),
            follow_redirects=params_dict.get('follow_redirects', True),
            delay=params_dict.get('delay', 0)
        )
        
        target_url = params_dict['target_url']
        custom_wordlist = params_dict.get('wordlist')
        method = params_dict.get('method', 'GET')
        use_extensions = not params_dict.get('no_extensions', False)
        
        # Run enumeration
        result = enumerator.run_dir_enum(
            target_url=target_url,
            custom_wordlist=custom_wordlist,
            method=method,
            use_extensions=use_extensions
        )
        
        return json.dumps(result, indent=2)
        
    except KeyError as e:
        error_result = {'error': f'Missing required parameter: {e}'}
        return json.dumps(error_result, indent=2)
    except Exception as e:
        error_result = {'error': f'Module execution failed: {e}'}
        return json.dumps(error_result, indent=2)


# Example usage and testing
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Directory & File Enumeration Module')
    parser.add_argument('target_url', help='Target URL to enumerate')
    parser.add_argument('--wordlist', help='Custom wordlist file path')
    parser.add_argument('--timeout', type=int, default=10, 
                       help='Request timeout in seconds')
    parser.add_argument('--max-threads', type=int, default=20,
                       help='Maximum concurrent threads')
    parser.add_argument('--method', choices=['GET', 'HEAD'], default='GET',
                       help='HTTP method to use')
    parser.add_argument('--no-extensions', action='store_true',
                       help='Skip trying file extensions')
    parser.add_argument('--no-redirects', action='store_true',
                       help='Do not follow redirects')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--delay', type=float, default=0,
                       help='Delay between requests in seconds')
    
    args = parser.parse_args()
    args.follow_redirects = not args.no_redirects
    
    # Execute enumeration and print results
    result_json = handle_dir_enum(args)
    print(result_json)