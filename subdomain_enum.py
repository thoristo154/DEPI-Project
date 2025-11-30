#!/usr/bin/env python3
"""
Enhanced Subdomain Enumeration Module
A professional subdomain discovery tool for cybersecurity assessments.
"""

import socket
import json
import logging
import os
import sys
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import dns.resolver
import dns.exception

# Configure logging
logger = logging.getLogger(__name__)

class SubdomainEnumerator:
    """
    An enhanced subdomain enumeration tool for security assessments.
    
    This class provides methods for brute-force subdomain discovery using
    wordlists, DNS resolution, and comprehensive result reporting.
    """
    
    def __init__(self, timeout: int = 3, max_workers: int = 50):
        """
        Initialize SubdomainEnumerator.
        
        Args:
            timeout: DNS resolution timeout in seconds (default: 3)
            max_workers: Maximum number of concurrent threads (default: 50)
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.default_wordlist_urls = [
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top500.txt"
        ]
        self.default_wordlist_path = "./wordlists/subdomains-top1million-5000.txt"
        
        # Common DNS resolvers
        self.dns_resolvers = [
            '8.8.8.8',      # Google
            '1.1.1.1',      # Cloudflare
            '9.9.9.9',      # Quad9
            '208.67.222.222', # OpenDNS
            '64.6.64.6'     # Verisign
        ]
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Ensure wordlists directory exists
        self._ensure_wordlist_directory()
    
    def _ensure_wordlist_directory(self) -> None:
        """
        Create wordlists directory if it doesn't exist.
        """
        wordlist_dir = os.path.dirname(self.default_wordlist_path)
        if not os.path.exists(wordlist_dir):
            os.makedirs(wordlist_dir)
            logger.info("Created wordlist directory: %s", wordlist_dir)
    
    def _download_wordlist(self, url: str, file_path: str) -> bool:
        """
        Download a wordlist from URL.
        
        Args:
            url: URL to download from
            file_path: Local file path to save to
            
        Returns:
            bool: True if download successful, False otherwise
        """
        logger.info("Downloading wordlist from %s", url)
        
        try:
            # Create request with timeout
            request = urllib.request.Request(
                url,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            # Download the wordlist
            with urllib.request.urlopen(request, timeout=30) as response:
                content = response.read().decode('utf-8')
            
            # Save to file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.info("Successfully downloaded wordlist to %s", file_path)
            return True
            
        except urllib.error.URLError as e:
            logger.error("Failed to download wordlist: %s", e)
            return False
        except urllib.error.HTTPError as e:
            logger.error("HTTP error downloading wordlist: %s - %s", e.code, e.reason)
            return False
        except Exception as e:
            logger.error("Unexpected error downloading wordlist: %s", e)
            return False
    
    def _validate_wordlist(self, wordlist_path: str) -> Tuple[bool, Optional[str]]:
        """
        Enhanced wordlist file validation.
        
        Args:
            wordlist_path: Path to the wordlist file
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if file exists
        if not os.path.exists(wordlist_path):
            return False, f"Wordlist file not found: {wordlist_path}"
        
        # Check if file is readable
        if not os.access(wordlist_path, os.R_OK):
            return False, f"Wordlist file is not readable: {wordlist_path}"
        
        # Check file size
        file_size = os.path.getsize(wordlist_path)
        if file_size == 0:
            return False, f"Wordlist file is empty: {wordlist_path}"
        
        # Check if file contains valid content
        try:
            valid_entries = 0
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        valid_entries += 1
                        # Check for reasonable length
                        if len(line) > 63:  # DNS label max length
                            logger.warning("Word %s at line %d exceeds DNS label length limit", line, line_num)
            
            if valid_entries == 0:
                return False, f"Wordlist file contains no valid entries: {wordlist_path}"
            
            logger.info("Wordlist validated: %s (%d bytes, %d entries)", 
                       wordlist_path, file_size, valid_entries)
            return True, None
            
        except Exception as e:
            return False, f"Error reading wordlist file: {e}"
    
    def _load_wordlist(self, wordlist_path: Optional[str] = None) -> List[str]:
        """
        Enhanced wordlist loading with multiple fallback options.
        
        Args:
            wordlist_path: Custom wordlist path (optional)
            
        Returns:
            List of subdomain prefixes
        """
        target_path = wordlist_path or self.default_wordlist_path
        
        # Validate custom wordlist if provided
        if wordlist_path:
            is_valid, error_msg = self._validate_wordlist(wordlist_path)
            if not is_valid:
                raise ValueError(f"Invalid wordlist: {error_msg}")
            logger.info("Using custom wordlist: %s", wordlist_path)
        else:
            # Handle default wordlist
            is_valid, error_msg = self._validate_wordlist(self.default_wordlist_path)
            if not is_valid:
                logger.warning("Default wordlist not available: %s", error_msg)
                logger.info("Attempting to download default wordlist...")
                success = False
                for url in self.default_wordlist_urls:
                    if self._download_wordlist(url, self.default_wordlist_path):
                        success = True
                        break
                if not success:
                    raise ValueError("Failed to download default wordlist. Please provide a custom wordlist.")
            logger.info("Using default wordlist: %s", self.default_wordlist_path)
        
        # Load wordlist entries
        try:
            with open(target_path, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            # Remove duplicates and sort
            wordlist = sorted(list(set(wordlist)))
            
            logger.info("Loaded %d unique subdomain prefixes from wordlist", len(wordlist))
            return wordlist
            
        except Exception as e:
            raise ValueError(f"Failed to load wordlist: {e}")
    
    def resolve_subdomain(self, subdomain: str, record_type: str = 'A') -> Dict[str, Any]:
        """
        Enhanced subdomain resolution with multiple DNS record types.
        
        Args:
            subdomain: Full subdomain to resolve (e.g., www.example.com)
            record_type: DNS record type to query (A, AAAA, CNAME, TXT, etc.)
            
        Returns:
            Dictionary containing resolution results
        """
        result = {
            "subdomain": subdomain,
            "record_type": record_type,
            "resolved_data": [],
            "resolved_ips": [],
            "status": "unknown",
            "response_time": 0,
            "error": None
        }
        
        start_time = time.time()
        
        try:
            # Use dnspython for robust DNS resolution
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            # Try multiple resolvers for redundancy
            for dns_server in self.dns_resolvers:
                try:
                    resolver.nameservers = [dns_server]
                    answers = resolver.resolve(subdomain, record_type)
                    
                    for rdata in answers:
                        record_data = str(rdata)
                        result["resolved_data"].append(record_data)
                        
                        # Extract IP addresses for A and AAAA records
                        if record_type in ['A', 'AAAA']:
                            result["resolved_ips"].append(record_data)
                    
                    result["status"] = "resolved"
                    result["dns_server"] = dns_server
                    logger.debug("Resolved %s (%s) -> %s using %s", 
                                subdomain, record_type, result["resolved_data"], dns_server)
                    break
                    
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    result["status"] = "nxdomain"
                    result["error"] = "Domain does not exist"
                    break
                except dns.resolver.Timeout:
                    continue  # Try next resolver
                except dns.exception.DNSException as e:
                    continue  # Try next resolver
            
            # If all resolvers failed
            if result["status"] == "unknown":
                result["status"] = "timeout"
                result["error"] = "All DNS resolvers timed out"
            
        except dns.resolver.NXDOMAIN:
            result["status"] = "nxdomain"
            result["error"] = "Domain does not exist"
        except dns.resolver.NoAnswer:
            result["status"] = "noanswer"
            result["error"] = f"No {record_type} records found"
        except dns.resolver.Timeout:
            result["status"] = "timeout"
            result["error"] = "DNS resolution timeout"
        except dns.exception.DNSException as e:
            result["status"] = "dns_error"
            result["error"] = f"DNS error: {e}"
        except Exception as e:
            result["status"] = "error"
            result["error"] = f"Unexpected error: {e}"
        
        result["response_time"] = time.time() - start_time
        return result
    
    def check_subdomain_exists(self, subdomain: str) -> Dict[str, Any]:
        """
        Check if subdomain exists using multiple DNS record types.
        
        Args:
            subdomain: Subdomain to check
            
        Returns:
            Dictionary with comprehensive subdomain information
        """
        result = {
            "subdomain": subdomain,
            "exists": False,
            "records": {},
            "primary_ip": None,
            "status": "unknown"
        }
        
        # Check multiple record types
        record_types = ['A', 'AAAA', 'CNAME']
        
        for record_type in record_types:
            resolution = self.resolve_subdomain(subdomain, record_type)
            result["records"][record_type] = resolution
            
            if resolution["status"] == "resolved":
                result["exists"] = True
                result["status"] = "active"
                
                # Set primary IP from A record if available
                if record_type == 'A' and resolution["resolved_ips"]:
                    result["primary_ip"] = resolution["resolved_ips"][0]
        
        return result
    
    def brute_force_subdomains(self, domain: str, 
                              wordlist_path: Optional[str] = None,
                              max_subdomains: Optional[int] = None,
                              record_types: List[str] = None) -> Dict[str, Any]:
        """
        Enhanced brute-force subdomain enumeration.
        
        Args:
            domain: Base domain to enumerate subdomains for
            wordlist_path: Path to custom wordlist (optional)
            max_subdomains: Maximum number of subdomains to test (optional)
            record_types: DNS record types to check (default: ['A'])
            
        Returns:
            Dictionary containing enumeration results
        """
        # Validate domain
        if not domain or not isinstance(domain, str):
            raise ValueError("Domain must be a non-empty string")
        
        domain = domain.strip().lower()
        if not all(part.isalnum() or part == '-' for part in domain.split('.')):
            raise ValueError("Invalid domain format")
        
        # Set default record types
        if record_types is None:
            record_types = ['A']
        
        logger.info("Starting subdomain enumeration for: %s", domain)
        
        # Load wordlist
        wordlist = self._load_wordlist(wordlist_path)
        
        # Apply limit if specified
        if max_subdomains and max_subdomains < len(wordlist):
            wordlist = wordlist[:max_subdomains]
            logger.info("Limited to %d subdomains", max_subdomains)
        
        results = {
            "domain": domain,
            "wordlist_source": wordlist_path or "default",
            "wordlist_size": len(wordlist),
            "record_types": record_types,
            "start_time": time.time(),
            "discovered_subdomains": [],
            "statistics": {
                "total_tested": 0,
                "resolved": 0,
                "nxdomain": 0,
                "timeout": 0,
                "errors": 0
            }
        }
        
        logger.info("Testing %d subdomains against %s", len(wordlist), domain)
        
        # Process subdomains with thread pool
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Create futures for all subdomains
            future_to_subdomain = {}
            for prefix in wordlist:
                subdomain = f"{prefix}.{domain}"
                future = executor.submit(self.check_subdomain_exists, subdomain)
                future_to_subdomain[future] = subdomain
            
            # Process completed futures
            completed = 0
            for future in as_completed(future_to_subdomain):
                completed += 1
                subdomain = future_to_subdomain[future]
                
                try:
                    subdomain_result = future.result()
                    results["statistics"]["total_tested"] += 1
                    
                    # Update statistics and collect results
                    if subdomain_result["exists"]:
                        results["statistics"]["resolved"] += 1
                        results["discovered_subdomains"].append(subdomain_result)
                        logger.info("Discovered: %s -> %s", 
                                   subdomain, subdomain_result.get("primary_ip", "N/A"))
                    else:
                        results["statistics"]["nxdomain"] += 1
                    
                    # Progress reporting
                    if completed % 100 == 0 or completed == len(wordlist):
                        progress = (completed / len(wordlist)) * 100
                        discovered = results["statistics"]["resolved"]
                        logger.info("Progress: %d/%d (%.1f%%) - Found: %d", 
                                   completed, len(wordlist), progress, discovered)
                        
                except Exception as e:
                    logger.error("Error processing %s: %s", subdomain, e)
                    results["statistics"]["errors"] += 1
        
        # Calculate completion time and statistics
        results["end_time"] = time.time()
        results["duration_seconds"] = results["end_time"] - results["start_time"]
        
        # Final statistics
        results["status"] = "completed"
        results["discovered_count"] = len(results["discovered_subdomains"])
        
        # Calculate additional metrics
        tested = results["statistics"]["total_tested"]
        discovered = results["discovered_count"]
        results["success_rate"] = (discovered / tested * 100) if tested > 0 else 0
        results["requests_per_second"] = tested / results["duration_seconds"] if results["duration_seconds"] > 0 else 0
        
        logger.info("Enumeration completed for %s", domain)
        logger.info("Discovered %d active subdomains", results["discovered_count"])
        logger.info("Total tested: %d", results["statistics"]["total_tested"])
        logger.info("Resolution rate: %.2f%%", results["success_rate"])
        logger.info("Duration: %.2f seconds", results["duration_seconds"])
        logger.info("Speed: %.2f requests/second", results["requests_per_second"])
        
        return results
    
    def passive_subdomain_discovery(self, domain: str) -> Dict[str, Any]:
        """
        Attempt passive subdomain discovery using public sources.
        Note: This is a placeholder for actual passive discovery implementation.
        
        Args:
            domain: Domain to discover subdomains for
            
        Returns:
            Dictionary with passive discovery results
        """
        logger.info("Attempting passive subdomain discovery for: %s", domain)
        
        # This would typically integrate with services like:
        # - SecurityTrails
        # - Shodan
        # - Censys
        # - VirusTotal
        # - etc.
        
        result = {
            "domain": domain,
            "method": "passive",
            "discovered": [],
            "sources_checked": [],
            "status": "not_implemented",
            "error": "Passive discovery not implemented in this version"
        }
        
        logger.warning("Passive subdomain discovery not fully implemented")
        return result
    
    def certificate_transparency_discovery(self, domain: str) -> Dict[str, Any]:
        """
        Discover subdomains from Certificate Transparency logs.
        
        Args:
            domain: Domain to discover subdomains for
            
        Returns:
            Dictionary with CT log discovery results
        """
        logger.info("Searching Certificate Transparency logs for: %s", domain)
        
        result = {
            "domain": domain,
            "method": "certificate_transparency",
            "discovered": [],
            "sources": ["crt.sh"],  # Common CT log aggregator
            "status": "completed"
        }
        
        try:
            # Use crt.sh API to get subdomains from certificate logs
            import requests
            
            api_url = f"https://crt.sh/json?q=%25.{domain}&exclude=expired"
            response = requests.get(api_url, timeout=self.timeout)
            
            if response.status_code == 200:
                certificates = response.json()
                subdomains = set()
                
                for cert in certificates:
                    common_name = cert.get('common_name', '')
                    if common_name and domain in common_name:
                        subdomains.add(common_name)
                    
                    # Also check subject alternative names
                    san_value = cert.get('name_value', '')
                    if san_value:
                        for name in san_value.split('\n'):
                            if domain in name:
                                subdomains.add(name)
                
                # Convert to list and sort
                discovered_list = sorted(list(subdomains))
                result["discovered"] = discovered_list
                result["discovered_count"] = len(discovered_list)
                
                logger.info("Found %d subdomains in CT logs", len(discovered_list))
                
            else:
                result["status"] = "error"
                result["error"] = f"CT API returned status {response.status_code}"
                
        except ImportError:
            result["status"] = "error"
            result["error"] = "Requests library required for CT discovery"
        except Exception as e:
            result["status"] = "error"
            result["error"] = f"CT discovery failed: {e}"
        
        return result
    
    def run_comprehensive_enumeration(self, domain: str, 
                                    wordlist_path: Optional[str] = None,
                                    max_subdomains: Optional[int] = None,
                                    include_passive: bool = True,
                                    include_ct: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive subdomain enumeration using multiple methods.
        
        Args:
            domain: Domain to enumerate
            wordlist_path: Custom wordlist path (optional)
            max_subdomains: Maximum subdomains to test (optional)
            include_passive: Include passive discovery methods
            include_ct: Include certificate transparency discovery
            
        Returns:
            Complete enumeration results
        """
        logger.info("Starting comprehensive subdomain enumeration for: %s", domain)
        
        start_time = time.time()
        
        results = {
            "domain": domain,
            "start_time": start_time,
            "methods_used": ["brute_force"],
            "all_discovered": [],
            "method_results": {},
            "summary": {}
        }
        
        # Method 1: Brute force (always included)
        brute_force_results = self.brute_force_subdomains(
            domain, wordlist_path, max_subdomains
        )
        results["method_results"]["brute_force"] = brute_force_results
        results["all_discovered"].extend([
            sub["subdomain"] for sub in brute_force_results["discovered_subdomains"]
        ])
        
        # Method 2: Certificate Transparency discovery
        if include_ct:
            try:
                ct_results = self.certificate_transparency_discovery(domain)
                results["method_results"]["certificate_transparency"] = ct_results
                results["methods_used"].append("certificate_transparency")
                
                if ct_results["status"] == "completed":
                    results["all_discovered"].extend(ct_results["discovered"])
                    
            except Exception as e:
                logger.error("CT discovery failed: %s", e)
                results["method_results"]["certificate_transparency"] = {
                    "status": "error",
                    "error": str(e)
                }
        
        # Method 3: Passive discovery
        if include_passive:
            try:
                passive_results = self.passive_subdomain_discovery(domain)
                results["method_results"]["passive"] = passive_results
                results["methods_used"].append("passive")
                
                # Note: Passive discovery is not fully implemented
                
            except Exception as e:
                logger.error("Passive discovery failed: %s", e)
                results["method_results"]["passive"] = {
                    "status": "error",
                    "error": str(e)
                }
        
        # Remove duplicates and sort
        results["all_discovered"] = sorted(list(set(results["all_discovered"])))
        results["unique_discovered_count"] = len(results["all_discovered"])
        
        # Calculate total duration
        results["end_time"] = time.time()
        results["duration_seconds"] = results["end_time"] - start_time
        
        # Generate comprehensive summary
        brute_force_count = len(brute_force_results["discovered_subdomains"])
        ct_count = len(results["method_results"].get("certificate_transparency", {}).get("discovered", []))
        
        results["summary"] = {
            "total_unique_subdomains": results["unique_discovered_count"],
            "brute_force_discovered": brute_force_count,
            "certificate_transparency_discovered": ct_count,
            "methods_used_count": len(results["methods_used"]),
            "total_duration": results["duration_seconds"],
            "enumeration_successful": True
        }
        
        logger.info("Comprehensive enumeration completed for %s", domain)
        logger.info("Discovered %d unique subdomains using %d methods", 
                   results["unique_discovered_count"], len(results["methods_used"]))
        
        return results


def run_module(params_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhanced main module entry point for integration with security tools.
    
    Args:
        params_dict: Dictionary containing module parameters:
            - domain: Target domain (required)
            - wordlist: Custom wordlist path (optional)
            - max_subdomains: Maximum subdomains to test (optional)
            - timeout: DNS resolution timeout (optional)
            - max_workers: Maximum concurrent threads (optional)
            - output_file: Path to save results (optional)
            - method: Enumeration method ('brute_force', 'comprehensive')
            - include_passive: Include passive discovery (optional)
            - include_ct: Include certificate transparency (optional)
    
    Returns:
        Dictionary containing enumeration results
    """
    try:
        # Validate required parameters
        if 'domain' not in params_dict:
            return {
                "status": "error",
                "error": "Missing required parameter: domain"
            }
        
        domain = params_dict['domain']
        wordlist = params_dict.get('wordlist')
        max_subdomains = params_dict.get('max_subdomains')
        timeout = params_dict.get('timeout', 3)
        max_workers = params_dict.get('max_workers', 50)
        method = params_dict.get('method', 'brute_force')
        include_passive = params_dict.get('include_passive', True)
        include_ct = params_dict.get('include_ct', True)
        
        # Initialize enumerator
        enumerator = SubdomainEnumerator(timeout=timeout, max_workers=max_workers)
        
        # Run appropriate enumeration method
        if method == 'comprehensive':
            results = enumerator.run_comprehensive_enumeration(
                domain=domain,
                wordlist_path=wordlist,
                max_subdomains=max_subdomains,
                include_passive=include_passive,
                include_ct=include_ct
            )
        else:  # brute_force (default)
            results = enumerator.brute_force_subdomains(
                domain=domain,
                wordlist_path=wordlist,
                max_subdomains=max_subdomains
            )
        
        # Save to file if requested
        output_file = params_dict.get('output_file')
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
                logger.info("Results saved to: %s", output_file)
                results["output_file"] = output_file
            except Exception as e:
                logger.error("Failed to save results to %s: %s", output_file, e)
        
        return results
        
    except Exception as e:
        logger.error("Module execution failed: %s", e)
        return {
            "status": "error",
            "error": str(e)
        }


def handle_subdomain_enum(args) -> None:
    """
    Enhanced CLI handler for subdomain enumeration module.
    
    Args:
        args: Command line arguments
    """
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Enhanced Subdomain Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com --wordlist custom_wordlist.txt
  %(prog)s example.com --max-subdomains 1000 --timeout 5
  %(prog)s example.com --output results.json --max-workers 20
  %(prog)s example.com --method comprehensive --include-ct
        """
    )
    
    parser.add_argument('domain', help='Target domain to enumerate subdomains for')
    parser.add_argument('--wordlist', help='Custom wordlist file path')
    parser.add_argument('--max-subdomains', type=int, 
                       help='Maximum number of subdomains to test')
    parser.add_argument('--timeout', type=int, default=3,
                       help='DNS resolution timeout in seconds (default: 3)')
    parser.add_argument('--max-workers', type=int, default=50,
                       help='Maximum concurrent threads (default: 50)')
    parser.add_argument('--output', help='Output file to save results (JSON)')
    parser.add_argument('--method', choices=['brute_force', 'comprehensive'],
                       default='brute_force', help='Enumeration method (default: brute_force)')
    parser.add_argument('--include-passive', action='store_true',
                       help='Include passive discovery methods')
    parser.add_argument('--include-ct', action='store_true',
                       help='Include certificate transparency discovery')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    # Parse arguments
    parsed_args = parser.parse_args(args)
    
    # Configure logging level
    if parsed_args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Prepare parameters
    params = {
        'domain': parsed_args.domain,
        'wordlist': parsed_args.wordlist,
        'max_subdomains': parsed_args.max_subdomains,
        'timeout': parsed_args.timeout,
        'max_workers': parsed_args.max_workers,
        'output_file': parsed_args.output,
        'method': parsed_args.method,
        'include_passive': parsed_args.include_passive,
        'include_ct': parsed_args.include_ct
    }
    
    # Execute module
    results = run_module(params)
    
    # Output results
    if parsed_args.output:
        print(f"Results saved to: {parsed_args.output}")
    else:
        print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    # CLI execution
    import sys
    handle_subdomain_enum(sys.argv[1:])