#!/usr/bin/env python3
"""
Enhanced WHOIS Lookup Module

A comprehensive WHOIS information retrieval tool that connects directly
to WHOIS servers via port 43 and parses domain registration information.

Author: Cybersecurity Expert
Version: 2.0
"""

import socket
import re
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from argparse import Namespace
from datetime import datetime
import time
import ssl

# Configure module logging
logger = logging.getLogger('whois_lookup')

class WhoisLookup:
    """
    An enhanced WHOIS lookup tool for retrieving domain registration information
    by connecting directly to WHOIS servers on port 43.
    """
    
    # Enhanced WHOIS servers for different TLDs
    WHOIS_SERVERS = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'edu': 'whois.educause.edu',
        'gov': 'whois.dotgov.gov',
        'info': 'whois.afilias.net',
        'biz': 'whois.biz',
        'io': 'whois.nic.io',
        'co': 'whois.nic.co',
        'uk': 'whois.nic.uk',
        'de': 'whois.denic.de',
        'fr': 'whois.nic.fr',
        'it': 'whois.nic.it',
        'nl': 'whois.domain-registry.nl',
        'eu': 'whois.eu',
        'cn': 'whois.cnnic.cn',
        'jp': 'whois.jprs.jp',
        'au': 'whois.auda.org.au',
        'ca': 'whois.cira.ca',
        'us': 'whois.nic.us',
        'mobi': 'whois.afilias.net',
        'tv': 'whois.nic.tv',
        'me': 'whois.nic.me',
        'app': 'whois.nic.google',
        'dev': 'whois.nic.google',
        'xyz': 'whois.nic.xyz',
        'online': 'whois.nic.online',
        'site': 'whois.nic.site',
        'tech': 'whois.nic.tech',
        'store': 'whois.nic.store',
        'fun': 'whois.nic.fun',
        'icu': 'whois.nic.icu'
    }
    
    # Enhanced WHOIS field patterns for parsing
    WHOIS_PATTERNS = {
        'domain_name': [
            r'Domain Name:\s*(.+)',
            r'domain:\s*(.+)',
            r'Domain:\s*(.+)',
            r'Domain name:\s*(.+)'
        ],
        'registrar': [
            r'Registrar:\s*(.+)',
            r'Registrar Name:\s*(.+)',
            r'Sponsoring Registrar:\s*(.+)',
            r'Registrar:\s*(.+)',
            r'registrar:\s*(.+)'
        ],
        'creation_date': [
            r'Creation Date:\s*(.+)',
            r'Created On:\s*(.+)',
            r'Registered on:\s*(.+)',
            r'Registration Time:\s*(.+)',
            r'Created:\s*(.+)',
            r'Domain Registration Date:\s*(.+)'
        ],
        'expiration_date': [
            r'Expiration Date:\s*(.+)',
            r'Registry Expiry Date:\s*(.+)',
            r'Expires on:\s*(.+)',
            r'Expiry Date:\s*(.+)',
            r'Expires:\s*(.+)',
            r'Registrar Registration Expiration Date:\s*(.+)'
        ],
        'updated_date': [
            r'Updated Date:\s*(.+)',
            r'Last Updated On:\s*(.+)',
            r'Modified:\s*(.+)',
            r'Last updated:\s*(.+)'
        ],
        'name_servers': [
            r'Name Server:\s*(.+)',
            r'nserver:\s*(.+)',
            r'Nameservers:\s*(.+)',
            r'Name Servers:\s*(.+)'
        ],
        'registrant_name': [
            r'Registrant Name:\s*(.+)',
            r'Registrant:\s*(.+)',
            r'Holder Name:\s*(.+)',
            r'Registrant Contact Name:\s*(.+)'
        ],
        'registrant_organization': [
            r'Registrant Organization:\s*(.+)',
            r'Registrant Org:\s*(.+)',
            r'Registrant\s*Organization:\s*(.+)'
        ],
        'registrant_email': [
            r'Registrant Email:\s*(.+)',
            r'Registrant Contact Email:\s*(.+)',
            r'Registrant E-mail:\s*(.+)'
        ],
        'registrant_country': [
            r'Registrant Country:\s*(.+)',
            r'Registrant Country Code:\s*(.+)',
            r'Registrant\s*Country:\s*(.+)'
        ],
        'admin_email': [
            r'Admin Email:\s*(.+)',
            r'Administrative Contact Email:\s*(.+)',
            r'Admin Contact Email:\s*(.+)'
        ],
        'tech_email': [
            r'Tech Email:\s*(.+)',
            r'Technical Contact Email:\s*(.+)',
            r'Tech Contact Email:\s*(.+)'
        ],
        'status': [
            r'Status:\s*(.+)',
            r'Domain Status:\s*(.+)',
            r'state:\s*(.+)'
        ],
        'registrar_iana_id': [
            r'Registrar IANA ID:\s*(\d+)',
            r'Registrar IANA ID:\s*(\d+)',
            r'IANA ID:\s*(\d+)'
        ]
    }

    def __init__(self, timeout: int = 10, whois_server: Optional[str] = None):
        """
        Initialize the enhanced WHOIS lookup tool.
        
        Args:
            timeout: Socket timeout in seconds
            whois_server: Specific WHOIS server to use (auto-detect if None)
        """
        self.timeout = timeout
        self.default_whois_server = whois_server
        logger.info("WhoisLookup initialized with timeout=%s", timeout)

    def raw_query(self, domain: str, whois_server: Optional[str] = None, 
                  retry_count: int = 2) -> Dict[str, Any]:
        """
        Perform enhanced raw WHOIS query with retry mechanism.
        
        Args:
            domain: Domain name to query
            whois_server: Specific WHOIS server to use
            retry_count: Number of retry attempts
            
        Returns:
            Dictionary with raw WHOIS data and metadata
        """
        result = {
            'domain': domain,
            'raw_output': '',
            'whois_server': whois_server,
            'query_time': datetime.now().isoformat(),
            'response_time': 0,
            'error': None,
            'success': False
        }
        
        start_time = time.time()
        
        for attempt in range(retry_count + 1):
            try:
                # Determine which WHOIS server to use
                if not whois_server:
                    whois_server = self._get_whois_server(domain)
                    result['whois_server'] = whois_server
                
                if not whois_server:
                    result['error'] = f"Could not determine WHOIS server for domain: {domain}"
                    logger.error(result['error'])
                    return result
                
                logger.info("Querying WHOIS server %s for domain %s (attempt %d)", 
                           whois_server, domain, attempt + 1)
                
                # Create socket connection with enhanced options
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.connect((whois_server, 43))
                    
                    # Send domain query with proper formatting
                    query = f"{domain}\r\n"
                    sock.send(query.encode('utf-8'))
                    
                    # Receive response with chunked reading
                    response = b''
                    while True:
                        try:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                            # Stop if we have enough data (WHOIS responses are typically small)
                            if len(response) > 65536:  # 64KB limit
                                break
                        except socket.timeout:
                            break
                    
                    result['raw_output'] = response.decode('utf-8', errors='ignore')
                    result['success'] = True
                    result['response_time'] = time.time() - start_time
                    
                    logger.info("Successfully retrieved WHOIS data for %s from %s (%.2fs)", 
                               domain, whois_server, result['response_time'])
                    
                    break  # Success, break retry loop
                    
            except socket.timeout:
                error_msg = f"WHOIS query timeout for {domain} on {whois_server}"
                if attempt == retry_count:
                    result['error'] = error_msg
                    logger.warning(error_msg)
                else:
                    logger.debug("Timeout on attempt %d, retrying...", attempt + 1)
                    time.sleep(1)  # Brief delay before retry
                    
            except ConnectionRefusedError:
                error_msg = f"Connection refused by WHOIS server {whois_server}"
                if attempt == retry_count:
                    result['error'] = error_msg
                    logger.error(error_msg)
                else:
                    logger.debug("Connection refused on attempt %d, retrying...", attempt + 1)
                    time.sleep(1)
                    
            except Exception as e:
                error_msg = f"WHOIS query error for {domain}: {e}"
                if attempt == retry_count:
                    result['error'] = error_msg
                    logger.error(error_msg)
                else:
                    logger.debug("Error on attempt %d, retrying...: %s", attempt + 1, e)
                    time.sleep(1)
        
        return result

    def parse_whois_output(self, raw_data: str) -> Dict[str, Any]:
        """
        Enhanced WHOIS output parsing with better field extraction.
        
        Args:
            raw_data: Raw WHOIS response text
            
        Returns:
            Structured WHOIS information
        """
        parsed_data = {}
        
        try:
            # Clean the raw data
            raw_data = self._clean_whois_data(raw_data)
            
            # Extract information using patterns
            for field, patterns in self.WHOIS_PATTERNS.items():
                for pattern in patterns:
                    matches = re.findall(pattern, raw_data, re.IGNORECASE | re.MULTILINE)
                    if matches:
                        # Clean and deduplicate matches
                        cleaned_matches = [self._clean_field_value(match.strip()) 
                                         for match in matches if match.strip()]
                        if cleaned_matches:
                            if field in ['name_servers']:
                                # Remove duplicates and sort
                                parsed_data[field] = sorted(list(set(cleaned_matches)))
                            elif field in ['status']:
                                # Keep all status values
                                parsed_data[field] = cleaned_matches
                            else:
                                # Take first valid match
                                parsed_data[field] = cleaned_matches[0]
                            break
            
            # Additional parsing for common formats
            self._enhance_parsed_data(parsed_data, raw_data)
            
            logger.info("Parsed %s WHOIS fields from raw data", len(parsed_data))
            
        except Exception as e:
            logger.error("Error parsing WHOIS output: %s", e)
            parsed_data['parse_error'] = str(e)
        
        return parsed_data

    def _clean_whois_data(self, raw_data: str) -> str:
        """
        Clean WHOIS data by removing irrelevant sections and normalizing.
        
        Args:
            raw_data: Raw WHOIS data
            
        Returns:
            Cleaned WHOIS data
        """
        # Remove common irrelevant sections
        patterns_to_remove = [
            r'>>>.*<<<',  # Header/footer markers
            r'Terms of Use:.+',  # Terms of use
            r'Access to.*',  # Access restrictions
            r'For more information.*',  # Informational footers
        ]
        
        cleaned_data = raw_data
        for pattern in patterns_to_remove:
            cleaned_data = re.sub(pattern, '', cleaned_data, flags=re.IGNORECASE | re.DOTALL)
        
        # Normalize line endings and remove excessive whitespace
        cleaned_data = re.sub(r'\r\n', '\n', cleaned_data)
        cleaned_data = re.sub(r'\n+', '\n', cleaned_data)
        cleaned_data = re.sub(r'[ \t]+', ' ', cleaned_data)
        
        return cleaned_data.strip()

    def _clean_field_value(self, value: str) -> str:
        """
        Clean individual field values.
        
        Args:
            value: Raw field value
            
        Returns:
            Cleaned field value
        """
        # Remove common prefixes/suffixes
        value = re.sub(r'^["\']|["\']$', '', value)  # Remove quotes
        value = re.sub(r'\\n', ' ', value)  # Replace newlines with spaces
        value = re.sub(r'\s+', ' ', value)  # Normalize whitespace
        
        return value.strip()

    def _enhance_parsed_data(self, parsed_data: Dict[str, Any], raw_data: str) -> None:
        """
        Enhance parsed data with additional parsing and cleaning.
        
        Args:
            parsed_data: Partially parsed WHOIS data
            raw_data: Raw WHOIS response text
        """
        try:
            # Extract all name servers more comprehensively
            if 'name_servers' not in parsed_data:
                ns_patterns = [
                    r'Name Server:\s*([^\n]+)',
                    r'nserver:\s*([^\n]+)',
                    r'Nameserver:\s*([^\n]+)'
                ]
                all_ns = []
                for pattern in ns_patterns:
                    matches = re.findall(pattern, raw_data, re.IGNORECASE)
                    all_ns.extend([ns.strip().lower() for ns in matches if ns.strip()])
                if all_ns:
                    parsed_data['name_servers'] = sorted(list(set(all_ns)))
            
            # Clean up domain name
            if 'domain_name' in parsed_data:
                parsed_data['domain_name'] = parsed_data['domain_name'].lower()
            
            # Extract registrar IANA ID if available
            if 'registrar_iana_id' not in parsed_data:
                registrar_id_match = re.search(r'Registrar IANA ID:\s*(\d+)', raw_data, re.IGNORECASE)
                if registrar_id_match:
                    parsed_data['registrar_iana_id'] = registrar_id_match.group(1)
            
            # Extract DNSSEC status
            dnssec_match = re.search(r'DNSSEC:\s*([^\n]+)', raw_data, re.IGNORECASE)
            if dnssec_match:
                parsed_data['dnssec'] = dnssec_match.group(1).strip()
            
            # Extract registrant contact information
            self._extract_contact_info(parsed_data, raw_data)
            
            # Parse dates into standardized format
            self._standardize_dates(parsed_data)
            
        except Exception as e:
            logger.debug("Error enhancing parsed data: %s", e)

    def _extract_contact_info(self, parsed_data: Dict[str, Any], raw_data: str) -> None:
        """
        Extract additional contact information from WHOIS data.
        
        Args:
            parsed_data: Parsed WHOIS data to enhance
            raw_data: Raw WHOIS data
        """
        # Extract phone numbers
        phone_patterns = [
            r'Registrant Phone:\s*([^\n]+)',
            r'Registrant Phone Number:\s*([^\n]+)',
            r'Admin Phone:\s*([^\n]+)',
            r'Tech Phone:\s*([^\n]+)'
        ]
        
        for pattern in phone_patterns:
            matches = re.findall(pattern, raw_data, re.IGNORECASE)
            if matches:
                field_name = re.search(r'(\w+)\s+Phone', pattern).group(1).lower() + '_phone'
                parsed_data[field_name] = matches[0].strip()

    def _standardize_dates(self, parsed_data: Dict[str, Any]) -> None:
        """
        Standardize date formats in parsed data.
        
        Args:
            parsed_data: Parsed WHOIS data with date fields
        """
        date_fields = ['creation_date', 'expiration_date', 'updated_date']
        
        for field in date_fields:
            if field in parsed_data:
                original_date = parsed_data[field]
                standardized = self._parse_date(original_date)
                if standardized:
                    parsed_data[f'{field}_standardized'] = standardized.isoformat()
                    # Calculate domain age for creation date
                    if field == 'creation_date':
                        self._calculate_domain_age(parsed_data, standardized)

    def _calculate_domain_age(self, parsed_data: Dict[str, Any], creation_date: datetime) -> None:
        """
        Calculate domain age based on creation date.
        
        Args:
            parsed_data: Parsed WHOIS data
            creation_date: Domain creation date
        """
        try:
            now = datetime.now()
            age_timedelta = now - creation_date
            parsed_data['domain_age_days'] = age_timedelta.days
            parsed_data['domain_age_years'] = round(age_timedelta.days / 365.25, 2)
            
            # Determine domain age category
            if age_timedelta.days < 30:
                parsed_data['domain_age_category'] = 'new'
            elif age_timedelta.days < 365:
                parsed_data['domain_age_category'] = 'recent'
            else:
                parsed_data['domain_age_category'] = 'established'
                
        except Exception as e:
            logger.debug("Error calculating domain age: %s", e)

    def get_domain_age(self, domain: str) -> Dict[str, Any]:
        """
        Enhanced domain age calculation with comprehensive information.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Domain age information
        """
        result = {
            'domain': domain,
            'creation_date': None,
            'expiration_date': None,
            'domain_age_days': None,
            'domain_age_years': None,
            'domain_age_category': None,
            'days_until_expiry': None,
            'error': None
        }
        
        try:
            # Get WHOIS data
            whois_result = self.raw_query(domain)
            if not whois_result['success']:
                result['error'] = whois_result['error']
                return result
            
            # Parse WHOIS output
            parsed_data = self.parse_whois_output(whois_result['raw_output'])
            
            if 'creation_date' not in parsed_data:
                result['error'] = "Creation date not found in WHOIS data"
                logger.warning("Creation date not found for domain %s", domain)
                return result
            
            # Extract dates
            creation_date = self._parse_date(parsed_data['creation_date'])
            expiration_date = None
            if 'expiration_date' in parsed_data:
                expiration_date = self._parse_date(parsed_data['expiration_date'])
            
            if not creation_date:
                result['error'] = f"Could not parse creation date: {parsed_data['creation_date']}"
                return result
            
            result['creation_date'] = creation_date.isoformat()
            result['creation_date_original'] = parsed_data['creation_date']
            
            if expiration_date:
                result['expiration_date'] = expiration_date.isoformat()
                result['expiration_date_original'] = parsed_data['expiration_date']
                
                # Calculate days until expiry
                now = datetime.now()
                if expiration_date > now:
                    result['days_until_expiry'] = (expiration_date - now).days
                else:
                    result['days_until_expiry'] = 0
            
            # Calculate age
            now = datetime.now()
            age_timedelta = now - creation_date
            result['domain_age_days'] = age_timedelta.days
            result['domain_age_years'] = round(age_timedelta.days / 365.25, 2)
            
            # Determine age category
            if age_timedelta.days < 30:
                result['domain_age_category'] = 'new'
            elif age_timedelta.days < 365:
                result['domain_age_category'] = 'recent'
            else:
                result['domain_age_category'] = 'established'
            
            logger.info("Domain %s age: %s days (%s years)", 
                       domain, result['domain_age_days'], result['domain_age_years'])
            
        except Exception as e:
            result['error'] = f"Error calculating domain age: {e}"
            logger.error("Domain age calculation failed for %s: %s", domain, e)
        
        return result

    def get_owner_info(self, domain: str) -> Dict[str, Any]:
        """
        Enhanced domain owner/registrant information extraction.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Owner information
        """
        result = {
            'domain': domain,
            'registrant_info': {},
            'admin_info': {},
            'tech_info': {},
            'privacy_protection': False,
            'error': None
        }
        
        try:
            # Get WHOIS data
            whois_result = self.raw_query(domain)
            if not whois_result['success']:
                result['error'] = whois_result['error']
                return result
            
            # Parse WHOIS output
            parsed_data = self.parse_whois_output(whois_result['raw_output'])
            
            # Extract registrant information
            registrant_fields = {
                'name': 'registrant_name',
                'organization': 'registrant_organization', 
                'email': 'registrant_email',
                'country': 'registrant_country'
            }
            
            for field, source_field in registrant_fields.items():
                if source_field in parsed_data:
                    result['registrant_info'][field] = parsed_data[source_field]
            
            # Extract admin information
            admin_fields = {
                'email': 'admin_email'
            }
            for field, source_field in admin_fields.items():
                if source_field in parsed_data:
                    result['admin_info'][field] = parsed_data[source_field]
            
            # Extract tech information
            tech_fields = {
                'email': 'tech_email'
            }
            for field, source_field in tech_fields.items():
                if source_field in parsed_data:
                    result['tech_info'][field] = parsed_data[source_field]
            
            # Check for privacy protection
            privacy_indicators = [
                'privacy', 'proxy', 'redacted', 'whois privacy', 
                'contact privacy', 'data protected'
            ]
            
            whois_text_lower = whois_result['raw_output'].lower()
            for indicator in privacy_indicators:
                if indicator in whois_text_lower:
                    result['privacy_protection'] = True
                    break
            
            # If no specific owner info found, include general contact info
            if not result['registrant_info']:
                general_fields = ['registrar', 'name_servers', 'status']
                for field in general_fields:
                    if field in parsed_data:
                        result['registrant_info'][field] = parsed_data[field]
            
            logger.info("Extracted owner info for %s: %s registrant fields", 
                       domain, len(result['registrant_info']))
            
        except Exception as e:
            result['error'] = f"Error extracting owner info: {e}"
            logger.error("Owner info extraction failed for %s: %s", domain, e)
        
        return result

    def run_full_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Perform complete enhanced WHOIS lookup with all available information.
        
        Args:
            domain: Domain name to query
            
        Returns:
            Comprehensive WHOIS information
        """
        full_result = {
            'domain': domain,
            'query_timestamp': datetime.now().isoformat(),
            'raw_query': {},
            'parsed_data': {},
            'domain_age': {},
            'owner_info': {},
            'summary': {},
            'error': None
        }
        
        logger.info("Starting full WHOIS lookup for domain: %s", domain)
        
        try:
            # Step 1: Raw WHOIS query
            full_result['raw_query'] = self.raw_query(domain)
            if not full_result['raw_query']['success']:
                full_result['error'] = full_result['raw_query']['error']
                return full_result
            
            # Step 2: Parse WHOIS data
            full_result['parsed_data'] = self.parse_whois_output(
                full_result['raw_query']['raw_output']
            )
            
            # Step 3: Calculate domain age
            full_result['domain_age'] = self.get_domain_age(domain)
            
            # Step 4: Extract owner information
            full_result['owner_info'] = self.get_owner_info(domain)
            
            # Generate comprehensive summary
            full_result['summary'] = {
                'domain_registered': 'creation_date' in full_result['parsed_data'],
                'registrar_found': 'registrar' in full_result['parsed_data'],
                'name_servers_found': 'name_servers' in full_result['parsed_data'],
                'owner_info_found': bool(full_result['owner_info']['registrant_info']),
                'privacy_protection': full_result['owner_info']['privacy_protection'],
                'lookup_successful': True
            }
            
            logger.info("Full WHOIS lookup completed for %s", domain)
            
        except Exception as e:
            full_result['error'] = f"Full WHOIS lookup failed: {e}"
            full_result['summary'] = {'lookup_successful': False}
            logger.error("Full WHOIS lookup failed for %s: %s", domain, e)
        
        return full_result

    def _get_whois_server(self, domain: str) -> Optional[str]:
        """
        Enhanced WHOIS server determination with better TLD handling.
        
        Args:
            domain: Domain name
            
        Returns:
            WHOIS server hostname or None if not found
        """
        try:
            # Extract TLD from domain
            domain_parts = domain.lower().split('.')
            if len(domain_parts) < 2:
                return None
            
            # Try different TLD combinations
            tld_attempts = []
            
            # Standard TLD
            tld = domain_parts[-1]
            tld_attempts.append(tld)
            
            # For country-code TLDs with second-level domains
            if len(domain_parts) >= 3:
                second_level_tld = f"{domain_parts[-2]}.{domain_parts[-1]}"
                tld_attempts.append(second_level_tld)
            
            # Check if we have a specific server for any TLD attempt
            for tld_attempt in tld_attempts:
                if tld_attempt in self.WHOIS_SERVERS:
                    return self.WHOIS_SERVERS[tld_attempt]
            
            # Fallback: try IANA WHOIS for unknown TLDs
            logger.warning("Using fallback IANA WHOIS server for domain %s", domain)
            return 'whois.iana.org'
            
        except Exception as e:
            logger.error("Error determining WHOIS server for %s: %s", domain, e)
            return None

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """
        Enhanced date parsing for various WHOIS date formats.
        
        Args:
            date_str: Date string from WHOIS output
            
        Returns:
            datetime object or None if parsing fails
        """
        if not date_str:
            return None
        
        # Clean the date string
        date_str = date_str.strip()
        
        # Common WHOIS date formats
        date_formats = [
            '%Y-%m-%d',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S%z',
            '%d-%b-%Y',
            '%b %d %Y',
            '%d/%m/%Y',
            '%m/%d/%Y',
            '%Y.%m.%d',
            '%d.%m.%Y',
            '%Y-%m-%dT%H:%M:%S',
            '%a %b %d %H:%M:%S %Z %Y'  # Unix date format
        ]
        
        for fmt in date_formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        
        # Try to extract date from string with regex
        date_patterns = [
            r'(\d{4}-\d{2}-\d{2})',
            r'(\d{2}-\w{3}-\d{4})',
            r'(\d{2}/\d{2}/\d{4})',
            r'(\d{4}\.\d{2}\.\d{2})'
        ]
        
        for pattern in date_patterns:
            date_match = re.search(pattern, date_str)
            if date_match:
                extracted_date = date_match.group(1)
                for fmt in ['%Y-%m-%d', '%d-%b-%Y', '%d/%m/%Y', '%Y.%m.%d']:
                    try:
                        return datetime.strptime(extracted_date, fmt)
                    except ValueError:
                        continue
        
        logger.warning("Could not parse date string: %s", date_str)
        return None


def handle_whois(args: Namespace) -> str:
    """
    Enhanced WHOIS lookup handler with better parameter processing.
    
    Args:
        args: argparse.Namespace with lookup parameters
        
    Returns:
        JSON string with WHOIS results
    """
    lookup = WhoisLookup(
        timeout=getattr(args, 'timeout', 10),
        whois_server=getattr(args, 'whois_server', None)
    )
    
    try:
        lookup_type = getattr(args, 'lookup_type', 'full')
        domain = getattr(args, 'domain', '')
        
        if not domain:
            return json.dumps({'error': 'No domain specified'}, indent=2)
        
        if lookup_type == 'raw':
            result = lookup.raw_query(domain)
        elif lookup_type == 'age':
            result = lookup.get_domain_age(domain)
        elif lookup_type == 'owner':
            result = lookup.get_owner_info(domain)
        else:  # full lookup
            result = lookup.run_full_lookup(domain)
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        error_result = {
            'error': f"WHOIS lookup failed: {e}",
            'lookup_type': getattr(args, 'lookup_type', 'unknown'),
            'domain': getattr(args, 'domain', 'unknown')
        }
        return json.dumps(error_result, indent=2)


def run_module(params_dict: Dict[str, Any]) -> str:
    """
    Enhanced main module entry point for integration with orchestration tools.
    
    Args:
        params_dict: Dictionary containing lookup parameters:
            - domain: required, domain name to query
            - lookup_type: optional, type of lookup ('raw', 'age', 'owner', 'full')
            - timeout: optional, socket timeout in seconds
            - whois_server: optional, specific WHOIS server to use
            
    Returns:
        JSON string with WHOIS results
    """
    try:
        # Create lookup tool with provided parameters
        lookup = WhoisLookup(
            timeout=params_dict.get('timeout', 10),
            whois_server=params_dict.get('whois_server')
        )
        
        domain = params_dict['domain']
        lookup_type = params_dict.get('lookup_type', 'full')
        
        # Execute appropriate lookup
        if lookup_type == 'raw':
            result = lookup.raw_query(domain)
        elif lookup_type == 'age':
            result = lookup.get_domain_age(domain)
        elif lookup_type == 'owner':
            result = lookup.get_owner_info(domain)
        else:  # full lookup
            result = lookup.run_full_lookup(domain)
        
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
    
    parser = argparse.ArgumentParser(description='Enhanced WHOIS Lookup Module')
    parser.add_argument('domain', help='Domain name to query')
    parser.add_argument('--lookup-type', choices=['raw', 'age', 'owner', 'full'],
                       default='full', help='Type of WHOIS lookup to perform')
    parser.add_argument('--timeout', type=int, default=10, 
                       help='Socket timeout in seconds')
    parser.add_argument('--whois-server', help='Specific WHOIS server to use')
    
    args = parser.parse_args()
    
    # Execute WHOIS lookup and print results
    result_json = handle_whois(args)
    print(result_json)