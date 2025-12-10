#!/usr/bin/env python3
"""
HTTP Fingerprint - Enhanced Enterprise-Grade Version with JSON Output
Author: ChatGPT (customized for Abdulrahman)
Purpose: Accurate HTTP fingerprinting using multiple open-source databases,
         CDN/WAF detection, tech stack fingerprinting, and realistic security scoring.
         Results are automatically saved to a JSON file.

Requirements:
- Python 3.8+
- pip install requests publicsuffix2
"""
from __future__ import annotations
import requests
import re
import logging
import time
import socket
import json
import urllib3
import os
import sys
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional, Set
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field, asdict
import publicsuffix2

# Suppress only the single InsecureRequestWarning from urllib3 when verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("http_fp")
logger.addHandler(logging.NullHandler())

# -------------------------
# Configuration
# -------------------------

DEFAULT_OUTPUT_DIR = "./http_fingerprint_results"
DEFAULT_FILENAME_PREFIX = "scan_"

# -------------------------
# Open Source Database Integration
# -------------------------

class OpenSourceDBs:
    """Integrate multiple open-source fingerprint databases"""
    
    # Wappalyzer-like patterns (simplified version)
    WAPPALYZER_PATTERNS = {
        "WordPress": {
            "html": [r'wp-content/', r'wp-includes/', r'wp-json', r'<!--[^>]+WP Rocket'],
            "headers": [r'X-Powered-By:\s*WordPress'],
            "cookies": [r'wordpress_logged_in_', r'wp-settings-', r'comment_author_'],
            "meta": [r'generator"[^>]*content="WordPress'],
            "scripts": [r'/wp-content/themes/', r'/wp-content/plugins/'],
            "categories": ["CMS"]
        },
        "Nginx": {
            "headers": [r'^nginx'],
            "server_tokens": [r'nginx'],
            "categories": ["Web Server"]
        },
        "Cloudflare": {
            "headers": [r'cf-ray', r'cf-cache-status', r'cf-request-id', r'cf-worker'],
            "cookies": [r'__cfduid', r'__cf_bm'],
            "html": [r'cloudflare', r'cf-error-details'],
            "categories": ["CDN/WAF"]
        },
        "React": {
            "html": [r'data-reactroot', r'data-reactid', r'<!--[^>]+React', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'],
            "scripts": [r'react(?:[-.]production(?:\.min)?)?\.js'],
            "attributes": [r'data-react'],
            "categories": ["JavaScript Framework"]
        },
        "jQuery": {
            "scripts": [r'jquery(?:[-.]min)?\.js', r'jquery-ui'],
            "html": [r'\$\.', r'jQuery\('],
            "categories": ["JavaScript Library"]
        },
        "Bootstrap": {
            "css": [r'bootstrap(?:[-.]min)?\.css'],
            "html": [r'class="[^"]*(?:container|row|col-[^"]*)'],
            "scripts": [r'bootstrap(?:[-.]min)?\.js'],
            "categories": ["CSS Framework"]
        },
        "Google Analytics": {
            "scripts": [r'google-analytics\.com/ga\.js', r'googletagmanager\.com/gtm\.js', r'gtag\('],
            "html": [r'UA-\d+-\d+', r'G-[\w]+'],
            "categories": ["Analytics"]
        },
        "Apache": {
            "headers": [r'Apache'],
            "server_tokens": [r'Apache'],
            "categories": ["Web Server"]
        },
        "PHP": {
            "headers": [r'X-Powered-By:\s*PHP'],
            "cookies": [r'PHPSESSID'],
            "html": [r'\.php\?'],
            "categories": ["Programming Language"]
        },
        "IIS": {
            "headers": [r'Microsoft-IIS', r'X-Powered-By:\s*ASP\.NET'],
            "server_tokens": [r'Microsoft-IIS'],
            "categories": ["Web Server"]
        },
        "Shopify": {
            "html": [r'cdn\.shopify\.com', r'shopify\.stats', r'Shopify\.Analytics'],
            "headers": [r'X-Shopify-'],
            "cookies": [r'_shopify_', r'_orig_referrer'],
            "scripts": [r'shopify_common\.js'],
            "categories": ["E-commerce", "CMS"]
        },
        "Drupal": {
            "html": [r'/sites/default/', r'Drupal\.settings', r'drupal\.js'],
            "cookies": [r'SESS[a-z0-9]+', r'SSESS[a-z0-9]+'],
            "headers": [r'X-Generator:\s*Drupal'],
            "meta": [r'generator"[^>]*content="Drupal'],
            "categories": ["CMS"]
        },
        "Joomla": {
            "html": [r'/media/system/', r'/media/jui/', r'Joomla!'],
            "cookies": [r'[a-z0-9]{32}'],
            "headers": [r'X-Content-Encoded-By:\s*Joomla!'],
            "meta": [r'generator"[^>]*content="Joomla'],
            "categories": ["CMS"]
        },
        "Laravel": {
            "cookies": [r'laravel_session'],
            "headers": [r'X-Powered-By:\s*Laravel'],
            "html": [r'csrf-token'],
            "categories": ["Web Framework"]
        },
        "Ruby on Rails": {
            "headers": [r'X-Runtime', r'X-Rack-Cache'],
            "cookies": [r'_rails-app_session'],
            "html": [r'csrf-param'],
            "categories": ["Web Framework"]
        },
        "Django": {
            "cookies": [r'csrftoken', r'sessionid'],
            "headers": [r'X-Frame-Options:\s*DENY'],
            "categories": ["Web Framework"]
        },
        "Node.js": {
            "headers": [r'X-Powered-By:\s*Express', r'X-Powered-By:\s*Node\.js'],
            "categories": ["Runtime", "Web Framework"]
        },
        "AWS CloudFront": {
            "headers": [r'x-amz-cf-id', r'x-amz-cf-pop'],
            "categories": ["CDN"]
        },
        "Fastly": {
            "headers": [r'fastly', r'x-served-by', r'x-cache-hits'],
            "categories": ["CDN"]
        },
        "Akamai": {
            "headers": [r'akamai', r'x-akamai-', r'akamaighost'],
            "categories": ["CDN/WAF"]
        }
    }
    
    # Security header best practices from OWASP
    OWASP_SECURITY_HEADERS = {
        "essential": {
            "strict-transport-security": {
                "weight": 25,
                "validation": lambda v: bool(re.search(r'max-age=\s*\d+', v, re.I)) and int(re.search(r'max-age=\s*(\d+)', v, re.I).group(1)) >= 31536000,
                "recommended": "max-age=31536000; includeSubDomains; preload"
            },
            "content-security-policy": {
                "weight": 25,
                "validation": lambda v: bool(re.search(r'default-src[^;]+', v, re.I)) and 'unsafe-inline' not in v and 'unsafe-eval' not in v,
                "recommended": "default-src 'self'; script-src 'self'; object-src 'none';"
            },
            "x-content-type-options": {
                "weight": 15,
                "validation": lambda v: v.strip().lower() == 'nosniff',
                "recommended": "nosniff"
            },
            "x-frame-options": {
                "weight": 15,
                "validation": lambda v: v.strip().upper() in ['DENY', 'SAMEORIGIN'],
                "recommended": "DENY"
            }
        },
        "recommended": {
            "referrer-policy": {
                "weight": 10,
                "validation": lambda v: v.strip().lower() in ['no-referrer', 'strict-origin-when-cross-origin', 'same-origin'],
                "recommended": "strict-origin-when-cross-origin"
            },
            "permissions-policy": {
                "weight": 10,
                "validation": lambda v: 'camera=()' in v or 'microphone=()' in v or 'geolocation=()' in v,
                "recommended": "camera=(), microphone=(), geolocation=()"
            },
            "cross-origin-opener-policy": {
                "weight": 5,
                "validation": lambda v: v.strip().lower() == 'same-origin',
                "recommended": "same-origin"
            }
        },
        "optional": {
            "x-xss-protection": {
                "weight": 5,
                "validation": lambda v: v.strip().lower() == '1; mode=block',
                "recommended": "1; mode=block"
            },
            "cache-control": {
                "weight": 3,
                "validation": lambda v: 'no-store' in v or 'no-cache' in v or 'private' in v,
                "recommended": "no-store, no-cache, must-revalidate"
            },
            "pragma": {
                "weight": 2,
                "validation": lambda v: v.strip().lower() == 'no-cache',
                "recommended": "no-cache"
            }
        }
    }
    
    @classmethod
    def get_all_patterns(cls) -> Dict[str, Dict]:
        """Combine all patterns from different databases"""
        return cls.WAPPALYZER_PATTERNS

# -------------------------
# Data Structures
# -------------------------

@dataclass
class TechnologyMatch:
    name: str
    confidence: float  # 0.0 to 1.0
    categories: List[str]
    evidence: List[str] = field(default_factory=list)
    version: Optional[str] = None

@dataclass
class SecurityHeader:
    name: str
    value: Optional[str]
    status: str  # "secure", "weak", "missing", "insecure"
    weight: int
    recommendation: str
    score: float

@dataclass
class ScanResult:
    target: str
    final_url: str
    response_code: int
    server_banner: str
    scan_timestamp: str
    ip_address: Optional[str] = None
    technologies: List[TechnologyMatch] = field(default_factory=list)
    cdn_waf: List[str] = field(default_factory=list)
    security_score: float = 0.0
    security_grade: str = "F"
    security_headers: List[SecurityHeader] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    response_time: float = 0.0
    raw_headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    redirects: List[str] = field(default_factory=list)

# -------------------------
# Helper functions
# -------------------------

def normalize_url(target: str, default_https: bool = True) -> Tuple[str, bool]:
    """Ensure scheme present; return (url, use_https)"""
    if not re.match(r'^[a-zA-Z]+://', target):
        scheme = 'https' if default_https else 'http'
        target = f"{scheme}://{target}"
    parsed = urlparse(target)
    scheme = parsed.scheme or ('https' if default_https else 'http')
    # Rebuild minimal URL (host + path)
    host = parsed.hostname or ''
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    base = f"{scheme}://{host}{path}"
    return base, scheme == 'https'

def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    parsed = urlparse(url)
    return parsed.hostname or ''

def get_ip_address(domain: str) -> Optional[str]:
    """Get IP address for domain"""
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def analyze_cookies(cookies: List[str]) -> Dict[str, Any]:
    """Analyze cookies for security issues"""
    issues = []
    secure_cookies = 0
    http_only_cookies = 0
    
    for cookie in cookies:
        cookie_lower = cookie.lower()
        # Check for secure flag
        if 'secure' in cookie_lower:
            secure_cookies += 1
        else:
            issues.append(f"Cookie missing Secure flag: {cookie.split(';')[0] if ';' in cookie else cookie}")
        
        # Check for HttpOnly flag
        if 'httponly' in cookie_lower:
            http_only_cookies += 1
        else:
            issues.append(f"Cookie missing HttpOnly flag: {cookie.split(';')[0] if ';' in cookie else cookie}")
    
    return {
        "total": len(cookies),
        "secure": secure_cookies,
        "http_only": http_only_cookies,
        "issues": issues
    }

def calculate_security_score(headers: Dict[str, str], cookies: List[str]) -> Tuple[float, List[SecurityHeader], List[str]]:
    """Calculate comprehensive security score based on OWASP guidelines"""
    security_headers = []
    vulnerabilities = []
    total_score = 0
    max_score = 0
    
    # Normalize headers
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    
    # Check all security headers
    for category, header_defs in OpenSourceDBs.OWASP_SECURITY_HEADERS.items():
        for header_name, config in header_defs.items():
            max_score += config["weight"]
            header_value = normalized_headers.get(header_name)
            
            if header_value:
                try:
                    is_valid = config["validation"](header_value)
                    status = "secure" if is_valid else "weak"
                    score = config["weight"] if is_valid else config["weight"] * 0.5
                except:
                    status = "weak"
                    score = config["weight"] * 0.5
            else:
                status = "missing"
                score = 0
                
                # Flag missing essential headers as vulnerabilities
                if category == "essential":
                    vulnerabilities.append(f"Missing essential security header: {header_name}")
            
            security_headers.append(SecurityHeader(
                name=header_name,
                value=header_value,
                status=status,
                weight=config["weight"],
                recommendation=config["recommended"],
                score=score
            ))
            total_score += score
    
    # Analyze cookies
    cookie_analysis = analyze_cookies(cookies)
    vulnerabilities.extend(cookie_analysis["issues"])
    
    # Check for other vulnerabilities
    if "server" in normalized_headers:
        server = normalized_headers["server"]
        # Check for version disclosure
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', server)
        if version_match:
            vulnerabilities.append(f"Server version disclosure: {server}")
    
    # Check for debug headers
    debug_headers = ["x-debug-token", "x-debug-token-link", "x-powered-by"]
    for debug_header in debug_headers:
        if debug_header in normalized_headers:
            vulnerabilities.append(f"Debug information exposed via header: {debug_header}")
    
    # Check for exposure of internal IPs in headers
    internal_ip_patterns = [r'10\.\d+\.\d+\.\d+', r'172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+', r'192\.168\.\d+\.\d+']
    for header_name, header_value in normalized_headers.items():
        for pattern in internal_ip_patterns:
            if re.search(pattern, header_value):
                vulnerabilities.append(f"Internal IP address exposed in {header_name} header")
                break
    
    # Calculate final score percentage
    final_score = (total_score / max_score * 100) if max_score > 0 else 0
    
    return final_score, security_headers, vulnerabilities

def detect_technologies(headers: Dict[str, str], body: str, cookies: List[str], scripts: List[str]) -> List[TechnologyMatch]:
    """Detect technologies using multiple open-source databases"""
    matches = []
    all_patterns = OpenSourceDBs.get_all_patterns()
    
    body_lower = body.lower()
    headers_text = "\n".join([f"{k}: {v}" for k, v in headers.items()]).lower()
    cookies_text = "\n".join(cookies).lower()
    scripts_text = "\n".join(scripts).lower()
    
    for tech_name, patterns in all_patterns.items():
        confidence = 0.0
        evidence = []
        
        # Check HTML patterns
        for pattern in patterns.get("html", []):
            if re.search(pattern, body_lower, re.IGNORECASE):
                confidence += 0.2
                evidence.append(f"HTML pattern: {pattern}")
        
        # Check header patterns
        for pattern in patterns.get("headers", []):
            if re.search(pattern, headers_text, re.IGNORECASE):
                confidence += 0.3
                evidence.append(f"Header pattern: {pattern}")
        
        # Check cookie patterns
        for pattern in patterns.get("cookies", []):
            if re.search(pattern, cookies_text, re.IGNORECASE):
                confidence += 0.25
                evidence.append(f"Cookie pattern: {pattern}")
        
        # Check script patterns
        for pattern in patterns.get("scripts", []):
            if re.search(pattern, scripts_text, re.IGNORECASE):
                confidence += 0.25
                evidence.append(f"Script pattern: {pattern}")
        
        # Check meta patterns
        for pattern in patterns.get("meta", []):
            if re.search(pattern, body_lower, re.IGNORECASE):
                confidence += 0.15
                evidence.append(f"Meta pattern: {pattern}")
        
        # Check CSS patterns
        for pattern in patterns.get("css", []):
            if re.search(pattern, body_lower, re.IGNORECASE):
                confidence += 0.15
                evidence.append(f"CSS pattern: {pattern}")
        
        # Check attribute patterns
        for pattern in patterns.get("attributes", []):
            if re.search(pattern, body_lower, re.IGNORECASE):
                confidence += 0.15
                evidence.append(f"Attribute pattern: {pattern}")
        
        # Check server tokens
        for pattern in patterns.get("server_tokens", []):
            if "server" in headers and re.search(pattern, headers["server"], re.IGNORECASE):
                confidence += 0.4
                evidence.append(f"Server token: {pattern}")
        
        # Only add if we have some confidence
        if confidence > 0.3:
            # Cap confidence at 1.0
            confidence = min(confidence, 1.0)
            
            # Use predefined categories or default
            categories = patterns.get("categories", ["Other"])
            
            matches.append(TechnologyMatch(
                name=tech_name,
                confidence=round(confidence, 2),
                categories=categories,
                evidence=evidence[:3],  # Limit evidence to 3 items
                version=None  # Could be extracted with more patterns
            ))
    
    # Sort by confidence (highest first)
    matches.sort(key=lambda x: x.confidence, reverse=True)
    return matches

def detect_cdn_waf(headers: Dict[str, str], body: str) -> List[str]:
    """Detect CDN and WAF providers"""
    detections = []
    headers_text = "\n".join([f"{k}: {v}" for k, v in headers.items()]).lower()
    body_lower = body.lower()
    
    # Cloudflare
    cloudflare_indicators = [
        "cf-ray", "cf-cache-status", "cf-request-id", "cloudflare",
        "__cfduid", "__cf_bm"
    ]
    if any(indicator in headers_text for indicator in cloudflare_indicators):
        detections.append("Cloudflare")
    
    # Akamai
    akamai_indicators = [
        "akamai", "x-akamai-", "akamaighost", "akamaiedge",
        "x-akamai-transformed"
    ]
    if any(indicator in headers_text for indicator in akamai_indicators):
        detections.append("Akamai")
    
    # Fastly
    fastly_indicators = ["fastly", "x-served-by", "x-cache-hits"]
    if any(indicator in headers_text for indicator in fastly_indicators):
        detections.append("Fastly")
    
    # AWS CloudFront
    if "x-amz-cf-id" in headers_text or "x-amz-cf-pop" in headers_text:
        detections.append("AWS CloudFront")
    
    # Imperva/Incapsula
    if "incapsula" in headers_text or "incap_ses_" in headers_text:
        detections.append("Imperva Incapsula")
    
    # F5 BIG-IP
    if "bigip" in headers_text or "bigipserver" in headers_text:
        detections.append("F5 BIG-IP")
    
    # Sucuri
    if "x-sucuri-id" in headers_text or "x-sucuri-cache" in headers_text:
        detections.append("Sucuri")
    
    # Wordfence
    if "wordfence" in body_lower or "wfwaf" in headers_text:
        detections.append("Wordfence")
    
    # ModSecurity
    if any(h in headers_text for h in ["mod_security", "modsecurity"]):
        detections.append("ModSecurity")
    
    return list(set(detections))  # Remove duplicates

def extract_scripts_from_body(body: str) -> List[str]:
    """Extract script URLs from HTML body"""
    scripts = []
    
    # Extract external scripts
    script_patterns = [
        r'<script[^>]+src=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
        r'<link[^>]+href=["\']([^"\']+\.css(?:\?[^"\']*)?)["\']'
    ]
    
    for pattern in script_patterns:
        matches = re.findall(pattern, body, re.IGNORECASE)
        scripts.extend(matches)
    
    return scripts

def save_to_json(data: Dict[str, Any], filename: Optional[str] = None) -> str:
    """
    Save scan results to a JSON file.
    Returns the path to the saved file.
    """
    # Create output directory if it doesn't exist
    os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)
    
    # Generate filename if not provided
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = extract_domain(data.get("target", "unknown"))
        safe_domain = re.sub(r'[^\w\-\.]', '_', domain)
        filename = f"{DEFAULT_FILENAME_PREFIX}{safe_domain}_{timestamp}.json"
    
    # Ensure .json extension
    if not filename.endswith('.json'):
        filename += '.json'
    
    # Full path
    filepath = os.path.join(DEFAULT_OUTPUT_DIR, filename)
    
    # Convert dataclasses to dictionaries
    def convert_dataclasses(obj):
        if isinstance(obj, list):
            return [convert_dataclasses(item) for item in obj]
        elif isinstance(obj, dict):
            return {key: convert_dataclasses(value) for key, value in obj.items()}
        elif hasattr(obj, '__dataclass_fields__'):
            return asdict(obj)
        else:
            return obj
    
    # Convert data
    json_data = convert_dataclasses(data)
    
    # Add metadata
    if isinstance(json_data, dict):
        json_data["scan_metadata"] = {
            "scan_timestamp": datetime.now().isoformat(),
            "tool_version": "2.0.0",
            "output_format": "json"
        }
    
    # Save to file with pretty formatting
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False, default=str)
    
    return filepath

def generate_report_filename(target: str, custom_name: Optional[str] = None) -> str:
    """Generate a meaningful filename for the report"""
    if custom_name:
        return custom_name
    
    domain = extract_domain(target)
    safe_domain = re.sub(r'[^\w\-\.]', '_', domain)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"http_fingerprint_{safe_domain}_{timestamp}.json"

# -------------------------
# Main Scanner Class
# -------------------------

class EnhancedHTTPFingerprint:
    def __init__(self, timeout: int = 15, user_agent: Optional[str] = None, 
                 max_redirects: int = 5, verify_ssl: bool = True):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.verify_ssl = verify_ssl
        
        # Setup session
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1"
        })
        
        # Setup redirect handling
        self.session.max_redirects = max_redirects
        
        # Disable SSL verification if requested
        if not verify_ssl:
            self.session.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def scan(self, target: str) -> ScanResult:
        """Perform comprehensive HTTP fingerprint scan"""
        start_time = time.time()
        scan_timestamp = datetime.now().isoformat()
        
        # Normalize URL
        url, use_https = normalize_url(target)
        domain = extract_domain(url)
        ip_address = get_ip_address(domain)
        
        try:
            # Make request
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                stream=False  # We want to read the full response
            )
            
            response_time = time.time() - start_time
            
            # Extract response data
            headers = dict(response.headers)
            body = response.text[:500000]  # Limit to 500KB for performance
            cookies = [str(c) for c in response.cookies]
            final_url = response.url
            
            # Extract scripts
            scripts = extract_scripts_from_body(body)
            
            # Detect technologies
            technologies = detect_technologies(headers, body, cookies, scripts)
            
            # Detect CDN/WAF
            cdn_waf = detect_cdn_waf(headers, body)
            
            # Calculate security score
            security_score, security_headers, vulnerabilities = calculate_security_score(headers, cookies)
            
            # Determine security grade
            if security_score >= 90:
                security_grade = "A"
            elif security_score >= 80:
                security_grade = "B"
            elif security_score >= 70:
                security_grade = "C"
            elif security_score >= 60:
                security_grade = "D"
            else:
                security_grade = "F"
            
            # Get server banner
            server_banner = headers.get("Server", headers.get("server", "Unknown"))
            
            # Create result object
            result = ScanResult(
                target=target,
                final_url=final_url,
                response_code=response.status_code,
                server_banner=server_banner,
                scan_timestamp=scan_timestamp,
                ip_address=ip_address,
                technologies=technologies,
                cdn_waf=cdn_waf,
                security_score=round(security_score, 2),
                security_grade=security_grade,
                security_headers=security_headers,
                vulnerabilities=vulnerabilities,
                response_time=round(response_time, 3),
                raw_headers=headers,
                cookies=cookies
            )
            
            return result
            
        except requests.RequestException as e:
            # Create error result
            result = ScanResult(
                target=target,
                final_url=url,
                response_code=0,
                server_banner="Error",
                scan_timestamp=scan_timestamp,
                ip_address=ip_address,
                vulnerabilities=[f"Request failed: {str(e)}"],
                response_time=time.time() - start_time
            )
            return result
    
    def scan_and_save(self, target: str, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan target and automatically save results to JSON file.
        Returns dictionary with scan results and filepath.
        """
        # Perform scan
        result = self.scan(target)
        
        # Convert to dictionary
        result_dict = asdict(result)
        
        # Add metadata
        result_dict["scan_metadata"] = {
            "scan_timestamp": result.scan_timestamp,
            "tool_version": "2.0.0",
            "scanner_name": "EnhancedHTTPFingerprint",
            "scan_duration": result.response_time
        }
        
        # Save to JSON file
        saved_filepath = save_to_json(result_dict, output_file)
        
        # Return both results and filepath
        return {
            "scan_results": result_dict,
            "saved_to": saved_filepath,
            "status": "success" if result.response_code > 0 else "partial",
            "target": target
        }
    
    def scan_to_dict(self, target: str) -> Dict[str, Any]:
        """Scan and return as dictionary (without saving)"""
        result = self.scan(target)
        return asdict(result)

# -------------------------
# Module Entry Point
# -------------------------

def run_module(params: Dict[str, Any]) -> Dict[str, Any]:
    """Main entry point for the module - automatically saves to JSON"""
    try:
        # Get target
        target = params.get("target") or params.get("host") or params.get("url")
        if not target:
            return {
                "status": "error",
                "error": "Missing target parameter",
                "usage": "Provide 'target', 'host', or 'url' parameter"
            }
        
        # Get configuration
        timeout = int(params.get("timeout", 15))
        max_redirects = int(params.get("max_redirects", 5))
        verify_ssl = bool(params.get("verify_ssl", True))
        user_agent = params.get("user_agent")
        output_file = params.get("output_file")
        
        # Create scanner
        scanner = EnhancedHTTPFingerprint(
            timeout=timeout,
            user_agent=user_agent,
            max_redirects=max_redirects,
            verify_ssl=verify_ssl
        )
        
        # Scan and save automatically
        result = scanner.scan_and_save(target, output_file)
        result["status"] = "success"
        
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "traceback": None
        }

# -------------------------
# Command-line Interface with JSON Output
# -------------------------

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enhanced HTTP Fingerprinting Scanner with JSON Output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s example.com --output-file custom_report.json
  %(prog)s https://test.com --timeout 20 --no-ssl-verify
  %(prog)s --batch targets.txt
  
Output files are saved to: ./http_fingerprint_results/
        """
    )
    
    parser.add_argument("target", nargs="?", help="Target URL or hostname")
    parser.add_argument("--batch", help="File containing list of targets (one per line)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--max-redirects", type=int, default=5, help="Maximum redirects to follow")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("--output-file", help="Custom output filename (default: auto-generated)")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})")
    parser.add_argument("--quiet", action="store_true", help="Suppress console output")
    parser.add_argument("--summary", action="store_true", help="Show summary after scanning")
    
    args = parser.parse_args()
    
    # Update output directory if specified
    if args.output_dir:
        DEFAULT_OUTPUT_DIR = args.output_dir
    
    # Check if we have targets
    if not args.target and not args.batch:
        parser.error("Either provide a target or use --batch with a file")
    
    targets = []
    
    # Get targets from batch file or single target
    if args.batch:
        try:
            with open(args.batch, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"Error: Batch file '{args.batch}' not found")
            sys.exit(1)
    elif args.target:
        targets = [args.target]
    
    if not targets:
        print("Error: No targets specified")
        sys.exit(1)
    
    # Create scanner
    scanner = EnhancedHTTPFingerprint(
        timeout=args.timeout,
        user_agent=args.user_agent,
        max_redirects=args.max_redirects,
        verify_ssl=not args.no_ssl_verify
    )
    
    results = []
    
    # Scan each target
    for i, target in enumerate(targets, 1):
        if not args.quiet:
            print(f"\n[ {i}/{len(targets)} ] Scanning: {target}")
        
        try:
            result = scanner.scan_and_save(target, args.output_file if i == 1 and not args.batch else None)
            
            if result["status"] == "success":
                results.append(result)
                
                if not args.quiet:
                    print(f"  ✓ Scan completed")
                    print(f"  ✓ Saved to: {result['saved_to']}")
                    
                    # Show brief summary
                    scan_data = result["scan_results"]
                    print(f"  ✓ Status: {scan_data.get('response_code', 'N/A')}")
                    print(f"  ✓ Security: {scan_data.get('security_score', 0):.1f}/100 ({scan_data.get('security_grade', 'F')})")
                    print(f"  ✓ Technologies: {len(scan_data.get('technologies', []))} detected")
                    print(f"  ✓ CDN/WAF: {len(scan_data.get('cdn_waf', []))} detected")
            else:
                if not args.quiet:
                    print(f"  ✗ Scan failed: {result.get('error', 'Unknown error')}")
        
        except KeyboardInterrupt:
            print("\n\nScan interrupted by user")
            sys.exit(1)
        except Exception as e:
            if not args.quiet:
                print(f"  ✗ Error scanning {target}: {str(e)}")
    
    # Show final summary
    if args.summary and results and not args.quiet:
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        
        successful = len([r for r in results if r.get("status") == "success"])
        print(f"Targets scanned: {len(targets)}")
        print(f"Successful scans: {successful}")
        print(f"Failed scans: {len(targets) - successful}")
        
        if successful > 0:
            # Calculate average security score
            avg_score = sum(r["scan_results"].get("security_score", 0) for r in results if r.get("status") == "success") / successful
            print(f"Average security score: {avg_score:.1f}/100")
            
            # List all output files
            print("\nJSON Reports saved to:")
            for result in results:
                if result.get("status") == "success":
                    print(f"  - {os.path.basename(result['saved_to'])}")
        
        print(f"\nAll reports saved in: {os.path.abspath(DEFAULT_OUTPUT_DIR)}")
        print("="*60)
    
    if not args.quiet:
        print(f"\nAll JSON reports saved to: {os.path.abspath(DEFAULT_OUTPUT_DIR)}")