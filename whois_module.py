#!/usr/bin/env python3
"""
Enhanced WHOIS Lookup Module
Professional Edition - Smart Parsing & Clean Output

Features:
- Direct Port 43 Connection (No external dependencies).
- Smart Server Selection (TLD-based).
- Dynamic Parsing (Converts Key:Value text to JSON).
- Noise Reduction (Strips legal boilerplate/Terms of Use).
- Domain Age Calculation.
"""

import socket
import re
import json
import logging
import time
from typing import Dict, List, Optional, Any
from datetime import datetime

# Configure module logging
logger = logging.getLogger(__name__)

class WhoisLookup:
    
    # Common WHOIS servers map
    WHOIS_SERVERS = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'io': 'whois.nic.io',
        'co': 'whois.nic.co',
        'uk': 'whois.nic.uk',
        'jp': 'whois.jprs.jp',
        'au': 'whois.auda.org.au',
        'de': 'whois.denic.de',
        'fr': 'whois.nic.fr',
        'me': 'whois.nic.me',
        'us': 'whois.nic.us',
        'biz': 'whois.biz',
        'info': 'whois.afilias.net',
        'name': 'whois.nic.name',
        'mobi': 'whois.afilias.net',
        'cloud': 'whois.nic.cloud'
    }

    def __init__(self, timeout: int = 10, whois_server: Optional[str] = None):
        self.timeout = timeout
        self.default_whois_server = whois_server

    def _get_whois_server(self, domain: str) -> str:
        """Intelligently determines the correct WHOIS server."""
        parts = domain.lower().split('.')
        if len(parts) < 2: return 'whois.iana.org'
        
        tld = parts[-1]
        
        # 1. Check explicit list
        if tld in self.WHOIS_SERVERS:
            return self.WHOIS_SERVERS[tld]
            
        # 2. Heuristic for country codes with second level (e.g., .co.uk)
        if len(parts) > 2:
            sld = parts[-2]
            if f"{sld}.{tld}" in ['co.uk', 'com.au', 'co.jp']:
                # Usually handled by the main TLD server, but good to be safe
                pass

        # 3. Fallback to IANA
        return 'whois.iana.org'

    def raw_query(self, domain: str, whois_server: Optional[str] = None) -> Dict[str, Any]:
        """
        Performs the socket connection, retrieves data, and cleans it.
        """
        server = whois_server or self._get_whois_server(domain)
        result = {
            'server': server,
            'formatted_lines': [], # Clean lines for JSON
            'success': False,
            'error': None
        }

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((server, 43))
                sock.send(f"{domain}\r\n".encode())
                
                response = b""
                while True:
                    data = sock.recv(4096)
                    if not data: break
                    response += data
                
                # Decode safely
                raw_decoded = response.decode('utf-8', errors='ignore')
                
                # --- SMART CLEANING START ---
                # Strip out the massive legal text blocks that clutter reports
                clean_text = raw_decoded
                garbage_markers = [
                    "TERMS OF USE", "Terms of Use", "Access to", 
                    ">>> Last update", "For more information"
                ]
                
                for marker in garbage_markers:
                    if marker in clean_text:
                        clean_text = clean_text.split(marker)[0]
                
                # Convert blob to clean list of lines
                result['formatted_lines'] = [
                    line.strip() 
                    for line in clean_text.splitlines() 
                    if line.strip() and not line.startswith('>>>') and not line.startswith('%')
                ]
                # --- SMART CLEANING END ---
                
                result['success'] = True

        except Exception as e:
            result['error'] = str(e)

        return result

    def parse_data(self, raw_lines: List[str]) -> Dict[str, Any]:
        """
        Smart Parser: Converts any "Key: Value" line into a dictionary field.
        """
        parsed = {}
        
        for line in raw_lines:
            if ':' in line:
                parts = line.split(':', 1)
                key = parts[0].strip()
                val = parts[1].strip()
                
                # Skip URLs or comments masquerading as keys
                if 'http' in key or '//' in key or len(key) > 50:
                    continue
                
                # Normalize Key (CamelCase -> snake_case)
                clean_key = key.lower().replace(' ', '_').replace('.', '').replace('/', '_')
                
                # Handle duplicate keys (e.g., Name Server)
                if clean_key in parsed:
                    if isinstance(parsed[clean_key], list):
                        if val not in parsed[clean_key]:
                            parsed[clean_key].append(val)
                    else:
                        if parsed[clean_key] != val:
                            parsed[clean_key] = [parsed[clean_key], val]
                else:
                    parsed[clean_key] = val
                    
        return parsed

    def get_domain_age(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates domain age by hunting for creation date fields."""
        res = {'age_days': 0, 'creation_date': 'Unknown', 'status': 'Unknown'}
        
        # Possible keys for creation date
        date_keys = ['creation_date', 'created', 'registered_on', 'creation_time', 'registered']
        date_str = None
        
        for k in date_keys:
            if k in parsed_data:
                val = parsed_data[k]
                date_str = val[0] if isinstance(val, list) else val
                break
                
        if date_str:
            # Clean ISO format artifacts
            date_str = date_str.replace('T', ' ').replace('Z', '')
            
            # Common date formats used by registrars
            formats = [
                '%Y-%m-%d %H:%M:%S', 
                '%Y-%m-%d', 
                '%d-%b-%Y', 
                '%Y-%m-%dT%H:%M:%S'
            ]
            
            for fmt in formats:
                try:
                    # Remove fractional seconds if present
                    clean_date_str = date_str.split('.')[0].strip()
                    create_dt = datetime.strptime(clean_date_str, fmt)
                    
                    res['creation_date'] = str(create_dt)
                    res['age_days'] = (datetime.now() - create_dt).days
                    res['status'] = "Established" if res['age_days'] > 365 else "New/Recent"
                    break
                except:
                    continue
                    
        return res

    def run_full_lookup(self, domain: str) -> Dict[str, Any]:
        """Orchestrates the lookup."""
        logger.info(f"Running Smart WHOIS for {domain}")
        
        # 1. Raw Query
        query_res = self.raw_query(domain)
        
        if not query_res['success']:
            return {'status': 'error', 'error': query_res['error']}
            
        # 2. Parse Data
        parsed_data = self.parse_data(query_res['formatted_lines'])
        
        # 3. Analyze Age
        age_info = self.get_domain_age(parsed_data)
        
        # 4. Construct Result
        return {
            'status': 'success',
            'domain': domain,
            'whois_server': query_res['server'],
            'registrar': parsed_data.get('registrar', 'Unknown'),
            'age_analysis': age_info,
            'parsed_data': parsed_data,
            # We return the formatted list for human readability in JSON
            'raw_lines': query_res['formatted_lines']
        }

def run_module(params: Dict[str, Any]) -> Dict[str, Any]:
    """Integration entry point."""
    try:
        domain = params.get('domain')
        if not domain:
            return {'status': 'error', 'error': 'Missing domain parameter'}
            
        lookup = WhoisLookup(
            timeout=int(params.get('timeout', 10)),
            whois_server=params.get('whois_server')
        )
        return lookup.run_full_lookup(domain)
        
    except Exception as e:
        return {'status': 'error', 'error': str(e)}

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    print(json.dumps(run_module({'domain': target}), indent=4))