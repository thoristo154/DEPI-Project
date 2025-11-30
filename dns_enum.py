#!/usr/bin/env python3
"""
Enhanced DNS Enumeration Module
A comprehensive DNS reconnaissance tool for cybersecurity assessments.
"""

import socket
import json
import logging
import itertools
import time
from typing import Dict, List, Optional, Any, Union
import dns.resolver
import dns.reversename
import dns.exception

# Configure logging
logger = logging.getLogger(__name__)

class DNSEnumerator:
    """
    An enhanced DNS enumeration tool for comprehensive domain reconnaissance.
    
    This class provides methods to query various DNS record types and
    perform subdomain brute-forcing for security assessments.
    """
    
    def __init__(self, timeout: int = 5):
        """
        Initialize DNSEnumerator.
        
        Args:
            timeout: DNS query timeout in seconds (default: 5)
        """
        self.timeout = timeout
        self.default_dns_servers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']  # Google, Cloudflare, Quad9
        
    def setup_resolver(self, dns_server: Optional[str] = None) -> dns.resolver.Resolver:
        """
        Set up DNS resolver with configured timeout and servers.
        
        Args:
            dns_server: Optional custom DNS server
            
        Returns:
            Configured DNS resolver
        """
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
        """
        Safely perform DNS queries with comprehensive error handling.
        
        Args:
            domain: Domain name to query
            record_type: Type of DNS record (A, AAAA, MX, NS, TXT, CNAME, SOA)
            dns_server: Optional custom DNS server
            
        Returns:
            Dictionary with query results
            
        Raises:
            ValueError: For invalid domain or record type
        """
        if not domain or not isinstance(domain, str):
            raise ValueError("Domain must be a non-empty string")
            
        valid_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']
        if record_type not in valid_types:
            raise ValueError(f"Record type must be one of {valid_types}")
        
        # Clean and validate domain format
        domain = domain.strip().lower()
        if not domain or ' ' in domain:
            raise ValueError("Invalid domain format")
        
        result = {
            "domain": domain,
            "record_type": record_type,
            "records": [],
            "dns_server": dns_server or "default",
            "query_time": 0,
            "error": None,
            "success": False
        }
        
        start_time = time.time()
        
        try:
            resolver = self.setup_resolver(dns_server)
            
            if record_type == 'PTR':
                # Reverse DNS lookup
                rev_name = dns.reversename.from_address(domain)
                answers = resolver.resolve(rev_name, 'PTR')
            else:
                answers = resolver.resolve(domain, record_type)
            
            records = []
            for rdata in answers:
                if record_type == 'A':
                    records.append(str(rdata))
                elif record_type == 'AAAA':
                    records.append(str(rdata))
                elif record_type == 'MX':
                    records.append({
                        'preference': rdata.preference,
                        'exchange': str(rdata.exchange)
                    })
                elif record_type == 'NS':
                    records.append(str(rdata))
                elif record_type == 'TXT':
                    # Join TXT record strings
                    txt_data = ''.join([s.decode('utf-8') for s in rdata.strings])
                    records.append(txt_data)
                elif record_type == 'CNAME':
                    records.append(str(rdata))
                elif record_type == 'SOA':
                    records.append({
                        'mname': str(rdata.mname),
                        'rname': str(rdata.rname),
                        'serial': rdata.serial,
                        'refresh': rdata.refresh,
                        'retry': rdata.retry,
                        'expire': rdata.expire,
                        'minimum': rdata.minimum
                    })
                elif record_type == 'PTR':
                    records.append(str(rdata))
            
            result['records'] = records
            result['success'] = True
            result['count'] = len(records)
            
        except dns.resolver.NXDOMAIN:
            result['error'] = f"Domain {domain} does not exist"
        except dns.resolver.NoAnswer:
            result['error'] = f"No {record_type} records found for {domain}"
        except dns.resolver.Timeout:
            result['error'] = f"DNS query timeout for {domain}"
        except dns.exception.DNSException as e:
            result['error'] = f"DNS error: {e}"
        except Exception as e:
            result['error'] = f"Unexpected error: {e}"
        
        result['query_time'] = time.time() - start_time
        return result

    def query_a_record(self, domain: str, 
                      dns_server: Optional[str] = None) -> Dict[str, Any]:
        """
        Query A records for a domain.
        
        Args:
            domain: Domain name to query
            dns_server: Optional custom DNS server
            
        Returns:
            Dictionary containing A record results
        """
        logger.info("Querying A records for %s", domain)
        return self.safe_dns_query(domain, 'A', dns_server)

    def query_aaaa_record(self, domain: str, 
                         dns_server: Optional[str] = None) -> Dict[str, Any]:
        """
        Query AAAA records for a domain.
        
        Args:
            domain: Domain name to query
            dns_server: Optional custom DNS server
            
        Returns:
            Dictionary containing AAAA record results
        """
        logger.info("Querying AAAA records for %s", domain)
        return self.safe_dns_query(domain, 'AAAA', dns_server)

    def query_mx_record(self, domain: str, 
                       dns_server: Optional[str] = None) -> Dict[str, Any]:
        """
        Query MX records for a domain.
        
        Args:
            domain: Domain name to query
            dns_server: Optional custom DNS server
            
        Returns:
            Dictionary containing MX record results
        """
        logger.info("Querying MX records for %s", domain)
        return self.safe_dns_query(domain, 'MX', dns_server)

    def query_ns_record(self, domain: str, 
                       dns_server: Optional[str] = None) -> Dict[str, Any]:
        """
        Query NS records for a domain.
        
        Args:
            domain: Domain name to query
            dns_server: Optional custom DNS server
            
        Returns:
            Dictionary containing NS record results
        """
        logger.info("Querying NS records for %s", domain)
        return self.safe_dns_query(domain, 'NS', dns_server)

    def query_txt_record(self, domain: str, 
                        dns_server: Optional[str] = None) -> Dict[str, Any]:
        """
        Query TXT records for a domain.
        
        Args:
            domain: Domain name to query
            dns_server: Optional custom DNS server
            
        Returns:
            Dictionary containing TXT record results
        """
        logger.info("Querying TXT records for %s", domain)
        return self.safe_dns_query(domain, 'TXT', dns_server)

    def query_cname_record(self, domain: str, 
                          dns_server: Optional[str] = None) -> Dict[str, Any]:
        """
        Query CNAME records for a domain.
        
        Args:
            domain: Domain name to query
            dns_server: Optional custom DNS server
            
        Returns:
            Dictionary containing CNAME record results
        """
        logger.info("Querying CNAME records for %s", domain)
        return self.safe_dns_query(domain, 'CNAME', dns_server)

    def query_soa_record(self, domain: str, 
                        dns_server: Optional[str] = None) -> Dict[str, Any]:
        """
        Query SOA records for a domain.
        
        Args:
            domain: Domain name to query
            dns_server: Optional custom DNS server
            
        Returns:
            Dictionary containing SOA record results
        """
        logger.info("Querying SOA records for %s", domain)
        return self.safe_dns_query(domain, 'SOA', dns_server)

    def reverse_dns_lookup(self, ip_address: str, 
                          dns_server: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform reverse DNS lookup for an IP address.
        
        Args:
            ip_address: IP address to lookup
            dns_server: Optional custom DNS server
            
        Returns:
            Dictionary containing PTR record results
        """
        logger.info("Performing reverse DNS lookup for %s", ip_address)
        return self.safe_dns_query(ip_address, 'PTR', dns_server)

    def get_all_records(self, domain: str, 
                       dns_server: Optional[str] = None) -> Dict[str, Any]:
        """
        Query all common DNS record types for a domain.
        
        Args:
            domain: Domain name to query
            dns_server: Optional custom DNS server
            
        Returns:
            Dictionary containing all DNS record results
        """
        logger.info("Querying all common DNS records for %s", domain)
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        results = {
            'domain': domain,
            'dns_server': dns_server or 'default',
            'queries': {},
            'total_records': 0,
            'query_time': 0
        }
        
        start_time = time.time()
        
        for record_type in record_types:
            try:
                query_result = self.safe_dns_query(domain, record_type, dns_server)
                results['queries'][record_type] = query_result
                if query_result['success']:
                    results['total_records'] += len(query_result['records'])
            except Exception as e:
                results['queries'][record_type] = {
                    'error': str(e),
                    'success': False
                }
        
        results['query_time'] = time.time() - start_time
        return results

    def zone_transfer(self, domain: str, nameserver: Optional[str] = None) -> Dict[str, Any]:
        """
        Attempt DNS zone transfer (AXFR).
        
        Args:
            domain: Domain name to attempt zone transfer for
            nameserver: Specific nameserver to try zone transfer from
            
        Returns:
            Dictionary containing zone transfer results
        """
        logger.info("Attempting zone transfer for %s", domain)
        
        result = {
            'domain': domain,
            'nameserver': nameserver,
            'success': False,
            'records': [],
            'error': None
        }
        
        try:
            # If no nameserver specified, get NS records first
            if not nameserver:
                ns_result = self.query_ns_record(domain)
                if not ns_result['success'] or not ns_result['records']:
                    result['error'] = "No nameservers found for domain"
                    return result
                nameservers = ns_result['records']
            else:
                nameservers = [nameserver]
            
            zone_records = []
            
            for ns in nameservers:
                try:
                    # Create resolver for this nameserver
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [socket.gethostbyname(ns)]
                    resolver.timeout = self.timeout
                    resolver.lifetime = self.timeout
                    
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(resolver.nameservers[0], domain))
                    
                    # Extract records from zone
                    for name, node in zone.nodes.items():
                        rdatasets = node.rdatasets
                        for rdataset in rdatasets:
                            for rdata in rdataset:
                                zone_records.append({
                                    'name': str(name),
                                    'type': dns.rdatatype.to_text(rdataset.rdtype),
                                    'data': str(rdata)
                                })
                    
                    result['success'] = True
                    result['records'] = zone_records
                    logger.info("Zone transfer successful from %s", ns)
                    break
                    
                except (dns.xfr.TransferError, dns.exception.DNSException) as e:
                    logger.debug("Zone transfer failed from %s: %s", ns, e)
                    continue
                except Exception as e:
                    logger.debug("Unexpected error during zone transfer from %s: %s", ns, e)
                    continue
            
            if not result['success']:
                result['error'] = "Zone transfer failed from all nameservers"
                
        except Exception as e:
            result['error'] = f"Zone transfer error: {e}"
            logger.error("Zone transfer failed for %s: %s", domain, e)
        
        return result

    def subdomain_brute_force(self, domain: str, wordlist: List[str], 
                             max_workers: int = 10) -> Dict[str, Any]:
        """
        Perform subdomain brute-forcing using a wordlist.
        
        Args:
            domain: Base domain to test subdomains against
            wordlist: List of subdomain prefixes to test
            max_workers: Maximum concurrent workers
            
        Returns:
            Dictionary containing discovered subdomains
        """
        logger.info("Starting subdomain brute force for %s with %d words", domain, len(wordlist))
        
        import concurrent.futures
        
        discovered = []
        tested_count = 0
        
        start_time = time.time()
        
        def check_subdomain(subdomain):
            nonlocal tested_count
            tested_count += 1
            
            try:
                result = self.query_a_record(subdomain)
                if result['success'] and result['records']:
                    return {
                        "subdomain": subdomain,
                        "a_records": result['records'],
                        "query_time": result['query_time']
                    }
            except Exception as e:
                pass
            return None
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Create subdomains to test
                subdomains = [f"{word}.{domain}" for word in wordlist]
                
                # Submit all tasks
                future_to_subdomain = {
                    executor.submit(check_subdomain, subdomain): subdomain 
                    for subdomain in subdomains
                }
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    result = future.result()
                    if result:
                        discovered.append(result)
                        logger.info("Discovered subdomain: %s -> %s", 
                                   result['subdomain'], result['a_records'])
            
            duration = time.time() - start_time
            
            return {
                "domain": domain,
                "method": "brute_force",
                "discovered": discovered,
                "count": len(discovered),
                "tested": tested_count,
                "success_rate": (len(discovered) / tested_count * 100) if tested_count > 0 else 0,
                "duration": duration,
                "status": "completed"
            }
            
        except Exception as e:
            logger.error("Error during subdomain brute force: %s", e)
            return {
                "domain": domain,
                "method": "brute_force",
                "discovered": [],
                "count": 0,
                "tested": tested_count,
                "error": str(e),
                "status": "error"
            }

    def comprehensive_enumeration(self, domain: str, 
                                wordlist: Optional[List[str]] = None,
                                dns_server: Optional[str] = None,
                                attempt_zone_transfer: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive DNS enumeration.
        
        Args:
            domain: Domain to enumerate
            wordlist: Optional wordlist for subdomain brute force
            dns_server: Optional custom DNS server
            attempt_zone_transfer: Whether to attempt zone transfer
            
        Returns:
            Complete enumeration results
        """
        logger.info("Starting comprehensive DNS enumeration for %s", domain)
        
        start_time = time.time()
        
        results = {
            "domain": domain,
            "dns_server": dns_server or "default",
            "start_time": start_time,
            "all_records": self.get_all_records(domain, dns_server),
            "zone_transfer": {"attempted": False, "success": False},
            "subdomains": {"attempted": False, "discovered": []},
            "reverse_lookups": []
        }
        
        # Attempt zone transfer if requested
        if attempt_zone_transfer:
            results["zone_transfer"] = self.zone_transfer(domain)
        
        # Perform subdomain brute force if wordlist provided
        if wordlist:
            subdomain_results = self.subdomain_brute_force(domain, wordlist)
            results["subdomains"] = {
                "attempted": True,
                "results": subdomain_results
            }
        
        # Perform reverse DNS lookups for A records
        a_records = results["all_records"]["queries"].get("A", {}).get("records", [])
        for ip in a_records:
            reverse_result = self.reverse_dns_lookup(ip, dns_server)
            results["reverse_lookups"].append({
                "ip": ip,
                "result": reverse_result
            })
        
        results["end_time"] = time.time()
        results["duration"] = results["end_time"] - start_time
        
        # Generate summary
        total_records = results["all_records"]["total_records"]
        subdomain_count = len(results["subdomains"].get("results", {}).get("discovered", []))
        zone_success = results["zone_transfer"].get("success", False)
        
        results["summary"] = {
            "total_records": total_records,
            "subdomains_discovered": subdomain_count,
            "zone_transfer_successful": zone_success,
            "enumeration_successful": True
        }
        
        logger.info("Comprehensive DNS enumeration completed for %s in %.2f seconds", 
                   domain, results["duration"])
        
        return results


def run_module(params_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhanced main module entry point for integration.
    
    Args:
        params_dict: Dictionary containing module parameters:
            - domain: Target domain (required)
            - record_type: Specific record type to query (optional)
            - wordlist: List for subdomain brute force (optional)
            - timeout: DNS query timeout (optional)
            - dns_server: Custom DNS server (optional)
            - comprehensive: Whether to run full enumeration (optional)
            - zone_transfer: Whether to attempt zone transfer (optional)
    
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
        timeout = params_dict.get('timeout', 5)
        dns_server = params_dict.get('dns_server')
        
        enumerator = DNSEnumerator(timeout=timeout)
        
        # Single record type query
        if 'record_type' in params_dict:
            record_type = params_dict['record_type'].upper()
            
            if record_type == 'A':
                return enumerator.query_a_record(domain, dns_server)
            elif record_type == 'AAAA':
                return enumerator.query_aaaa_record(domain, dns_server)
            elif record_type == 'MX':
                return enumerator.query_mx_record(domain, dns_server)
            elif record_type == 'NS':
                return enumerator.query_ns_record(domain, dns_server)
            elif record_type == 'TXT':
                return enumerator.query_txt_record(domain, dns_server)
            elif record_type == 'CNAME':
                return enumerator.query_cname_record(domain, dns_server)
            elif record_type == 'SOA':
                return enumerator.query_soa_record(domain, dns_server)
            elif record_type == 'PTR':
                return enumerator.reverse_dns_lookup(domain, dns_server)
            else:
                return {
                    "status": "error",
                    "error": f"Unsupported record type: {record_type}"
                }
        
        # All records query
        elif params_dict.get('all_records', False):
            return enumerator.get_all_records(domain, dns_server)
        
        # Zone transfer attempt
        elif params_dict.get('zone_transfer', False):
            nameserver = params_dict.get('nameserver')
            return enumerator.zone_transfer(domain, nameserver)
        
        # Subdomain brute force
        elif 'wordlist' in params_dict:
            wordlist = params_dict['wordlist']
            if isinstance(wordlist, str):
                # Assume it's a file path
                try:
                    with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                        wordlist = [line.strip() for line in f if line.strip()]
                except Exception as e:
                    return {
                        "status": "error",
                        "error": f"Failed to load wordlist: {e}"
                    }
            
            max_workers = params_dict.get('max_workers', 10)
            return enumerator.subdomain_brute_force(domain, wordlist, max_workers)
        
        # Comprehensive enumeration
        elif params_dict.get('comprehensive', False):
            wordlist = params_dict.get('wordlist')
            attempt_zone_transfer = params_dict.get('zone_transfer', True)
            return enumerator.comprehensive_enumeration(
                domain, wordlist, dns_server, attempt_zone_transfer
            )
        
        # Default: all records without brute force
        else:
            return enumerator.get_all_records(domain, dns_server)
            
    except Exception as e:
        logger.error("Module execution failed: %s", e)
        return {
            "status": "error",
            "error": str(e)
        }


def handle_dns_enum(args) -> None:
    """
    CLI handler for DNS enumeration module.
    
    Args:
        args: Command line arguments
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced DNS Enumeration Tool')
    parser.add_argument('domain', help='Target domain to enumerate')
    parser.add_argument('--record-type', choices=['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR'],
                       help='Query specific record type')
    parser.add_argument('--all-records', action='store_true', 
                       help='Query all common record types')
    parser.add_argument('--zone-transfer', action='store_true',
                       help='Attempt DNS zone transfer')
    parser.add_argument('--nameserver', help='Specific nameserver for zone transfer')
    parser.add_argument('--wordlist', help='Path to wordlist for subdomain brute force')
    parser.add_argument('--comprehensive', action='store_true', 
                       help='Perform comprehensive enumeration')
    parser.add_argument('--timeout', type=int, default=5, help='DNS query timeout in seconds')
    parser.add_argument('--dns-server', help='Custom DNS server to use')
    parser.add_argument('--max-workers', type=int, default=10,
                       help='Maximum concurrent workers for brute force')
    parser.add_argument('--output', help='Output file for results (JSON)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args(args)
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Prepare parameters
    params = {
        'domain': args.domain,
        'timeout': args.timeout,
        'dns_server': args.dns_server
    }
    
    if args.record_type:
        params['record_type'] = args.record_type
    if args.all_records:
        params['all_records'] = True
    if args.zone_transfer:
        params['zone_transfer'] = True
    if args.nameserver:
        params['nameserver'] = args.nameserver
    if args.wordlist:
        params['wordlist'] = args.wordlist
    if args.comprehensive:
        params['comprehensive'] = True
    if args.max_workers:
        params['max_workers'] = args.max_workers
    
    # Execute module
    results = run_module(params)
    
    # Output results
    output_json = json.dumps(results, indent=2)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_json)
        print(f"Results saved to {args.output}")
    else:
        print(output_json)


if __name__ == "__main__":
    import sys
    handle_dns_enum(sys.argv[1:])