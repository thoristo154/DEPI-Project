#!/usr/bin/env python3
"""
Enhanced DNS Enumeration Module
A comprehensive DNS reconnaissance tool for cybersecurity assessments.
"""

import socket
import json
import logging
import time
from typing import Dict, List, Optional, Any
import dns.resolver
import dns.reversename
import dns.exception

# Configure logging (Use getLogger to avoid duplicate console output in Recony)
logger = logging.getLogger(__name__)

class DNSEnumerator:
    """
    An enhanced DNS enumeration tool for comprehensive domain reconnaissance.
    """
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.default_dns_servers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']  # Google, Cloudflare, Quad9
        
    def setup_resolver(self, dns_server: Optional[str] = None) -> dns.resolver.Resolver:
        """Set up DNS resolver with configured timeout and servers."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        
        if dns_server:
            resolver.nameservers = [dns_server]
        else:
            resolver.nameservers = self.default_dns_servers
            
        return resolver

    def safe_dns_query(self, domain: str, record_type: str, 
                      dns_server: Optional[str] = None) -> Dict[str, Any]:
        """Safely perform DNS queries with comprehensive error handling."""
        if not domain:
            return {"error": "Domain must be a non-empty string", "success": False}
            
        result = {
            "domain": domain,
            "record_type": record_type,
            "records": [],
            "success": False
        }
        
        try:
            resolver = self.setup_resolver(dns_server)
            
            if record_type == 'PTR':
                rev_name = dns.reversename.from_address(domain)
                answers = resolver.resolve(rev_name, 'PTR')
            else:
                answers = resolver.resolve(domain, record_type)
            
            records = []
            for rdata in answers:
                if record_type == 'MX':
                    records.append({
                        'preference': rdata.preference,
                        'exchange': str(rdata.exchange)
                    })
                elif record_type == 'TXT':
                    # Join TXT record strings
                    txt_data = ''.join([s.decode('utf-8') for s in rdata.strings])
                    records.append(txt_data)
                elif record_type == 'SOA':
                    records.append({
                        'mname': str(rdata.mname),
                        'rname': str(rdata.rname),
                        'serial': rdata.serial,
                        'expire': rdata.expire
                    })
                else:
                    records.append(str(rdata))
            
            result['records'] = records
            result['success'] = True
            
        except Exception as e:
            result['error'] = str(e)
        
        return result

    def get_all_records(self, domain: str, dns_server: Optional[str] = None) -> Dict[str, Any]:
        """Query all common DNS record types for a domain."""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        results = {
            'domain': domain,
            'queries': {},
            'total_records': 0
        }
        
        for record_type in record_types:
            query_result = self.safe_dns_query(domain, record_type, dns_server)
            results['queries'][record_type] = query_result
            if query_result['success']:
                results['total_records'] += len(query_result['records'])
        
        return results

    def subdomain_brute_force(self, domain: str, wordlist: List[str], 
                             max_workers: int = 10) -> Dict[str, Any]:
        """Perform subdomain brute-forcing using a wordlist."""
        
        # CRITICAL FIX: Check if wordlist exists and is not empty before proceeding
        if not wordlist or not isinstance(wordlist, list):
             return {
                "domain": domain,
                "method": "brute_force",
                "discovered": [],
                "count": 0,
                "error": "Invalid or empty wordlist provided",
                "status": "error"
            }

        import concurrent.futures
        
        discovered = []
        
        def check_subdomain(subdomain):
            res = self.safe_dns_query(subdomain, 'A')
            if res['success'] and res['records']:
                return {
                    "subdomain": subdomain,
                    "a_records": res['records']
                }
            return None
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                subdomains = [f"{word}.{domain}" for word in wordlist]
                
                future_to_sub = {
                    executor.submit(check_subdomain, sub): sub 
                    for sub in subdomains
                }
                
                for future in concurrent.futures.as_completed(future_to_sub):
                    result = future.result()
                    if result:
                        discovered.append(result)
            
            return {
                "domain": domain,
                "method": "brute_force",
                "discovered": discovered,
                "count": len(discovered),
                "status": "completed"
            }
            
        except Exception as e:
            return {
                "domain": domain,
                "error": str(e),
                "status": "error"
            }

def run_module(params_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Main entry point for Recony integration."""
    try:
        if 'domain' not in params_dict:
            return {"status": "error", "error": "Missing required parameter: domain"}
        
        domain = params_dict['domain']
        timeout = params_dict.get('timeout', 5)
        dns_server = params_dict.get('dns_server')
        
        enumerator = DNSEnumerator(timeout=timeout)
        
        # 1. Subdomain Brute Force (Only if wordlist is strictly provided)
        if params_dict.get('wordlist'):
            wordlist = params_dict['wordlist']
            # If wordlist is a file path string, load it
            if isinstance(wordlist, str):
                try:
                    with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                        wordlist = [line.strip() for line in f if line.strip()]
                except Exception as e:
                    return {"status": "error", "error": f"Failed to load wordlist: {e}"}
            
            return enumerator.subdomain_brute_force(
                domain, wordlist, params_dict.get('max_workers', 10)
            )
        
        # 2. Default: Get All Records
        else:
            all_records = enumerator.get_all_records(domain, dns_server)
            return {
                "status": "success",
                "all_records": all_records
            }
            
    except Exception as e:
        return {"status": "error", "error": str(e)}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(json.dumps(run_module({'domain': sys.argv[1]}), indent=2))