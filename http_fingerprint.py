#!/usr/bin/env python3
"""
Enhanced HTTP Fingerprint Module

A comprehensive HTTP fingerprinting tool that analyzes web servers,
detects technologies, and evaluates security headers.

Author: A0xVa10ri4n
Version: 2.1
"""

import http.client
import json
import logging
import re
import ssl
import socket
from typing import Dict, List, Optional, Any, Tuple
from argparse import Namespace
from urllib.parse import urlparse
import time
import hashlib

# Configure module logging
logger = logging.getLogger('http_fingerprint')

class HTTPFingerprint:
    """
    An enhanced HTTP fingerprinting tool for web server analysis,
    technology detection, and security header evaluation.
    """
    
    # Enhanced server banners and their mappings
    SERVER_PATTERNS = {
        'Apache': [
            r'Apache', r'Apache/.*', r'httpd', r'Apache-Coyote', r'Apache/2'
        ],
        'Nginx': [
            r'nginx', r'nginx/.*', r'openresty'
        ],
        'IIS': [
            r'Microsoft-IIS', r'IIS', r'Microsoft-HTTPAPI'
        ],
        'CloudFlare': [
            r'cloudflare', r'cloudflare-nginx'
        ],
        'LiteSpeed': [
            r'LiteSpeed', r'LWS'
        ],
        'Tomcat': [
            r'Tomcat', r'Apache-Tomcat'
        ],
        'Node.js': [
            r'Node\.js', r'Express'
        ],
        'WordPress': [
            r'WordPress'
        ],
        'Gunicorn': [
            r'gunicorn'
        ],
        'Caddy': [
            r'Caddy'
        ]
    }
    
    # Enhanced technology detection patterns
    TECHNOLOGY_PATTERNS = {
        'programming_languages': {
            'PHP': [r'PHP/', r'X-Powered-By:\s*PHP', r'PHPSESSID'],
            'ASP.NET': [r'ASP\.NET', r'X-AspNet-Version', r'X-Powered-By:\s*ASP\.NET'],
            'Python': [r'Python', r'WSGIServer', r'Django', r'Flask'],
            'Ruby': [r'Ruby', r'Rails', r'Phusion Passenger'],
            'Java': [r'Java', r'JSP', r'Servlet', r'JBoss', r'GlassFish'],
            'Node.js': [r'Node\.js', r'Express']
        },
        'frameworks': {
            'Django': [r'Django', r'CSRF_TOKEN', r'django'],
            'Flask': [r'Flask', r'Werkzeug'],
            'Rails': [r'Rails', r'Ruby on Rails'],
            'Express': [r'Express', r'X-Powered-By:\s*Express'],
            'Laravel': [r'Laravel'],
            'Spring': [r'Spring', r'X-Application-Context'],
            'React': [r'React', r'Next\.js'],
            'Vue.js': [r'Vue\.js'],
            'Angular': [r'Angular']
        },
        'cms': {
            'WordPress': [r'WordPress', r'wp-', r'wp_includes', r'wp-content'],
            'Joomla': [r'Joomla', r'Joomla!'],
            'Drupal': [r'Drupal', r'Drupal.cookie'],
            'Magento': [r'Magento'],
            'Shopify': [r'Shopify', r'X-ShopId'],
            'WooCommerce': [r'WooCommerce']
        },
        'caching': {
            'Varnish': [r'X-Varnish', r'Via:.*varnish'],
            'CloudFlare': [r'cloudflare', r'cf-ray'],
            'Akamai': [r'X-Akamai', r'Akamai'],
            'Fastly': [r'X-Fastly', r'Fastly']
        },
        'analytics': {
            'Google Analytics': [r'ga\.js', r'analytics\.js', r'gtag\.js'],
            'Google Tag Manager': [r'googletagmanager\.com'],
            'Facebook Pixel': [r'facebook\.com/tr']
        }
    }
    
    # Enhanced security headers analysis
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'description': 'Enforces HTTPS connections',
            'recommended': 'max-age=31536000; includeSubDomains',
            'risk': 'high',
            'weight': 3
        },
        'Content-Security-Policy': {
            'description': 'Prevents XSS attacks',
            'recommended': "default-src 'self'",
            'risk': 'high',
            'weight': 3
        },
        'X-Content-Type-Options': {
            'description': 'Prevents MIME type sniffing',
            'recommended': 'nosniff',
            'risk': 'medium',
            'weight': 2
        },
        'X-Frame-Options': {
            'description': 'Prevents clickjacking',
            'recommended': 'DENY or SAMEORIGIN',
            'risk': 'medium',
            'weight': 2
        },
        'X-XSS-Protection': {
            'description': 'Enables XSS protection in browsers',
            'recommended': '1; mode=block',
            'risk': 'medium',
            'weight': 2
        },
        'Referrer-Policy': {
            'description': 'Controls referrer information',
            'recommended': 'strict-origin-when-cross-origin',
            'risk': 'low',
            'weight': 1
        },
        'Permissions-Policy': {
            'description': 'Controls browser features and APIs',
            'recommended': 'Controls various permissions',
            'risk': 'medium',
            'weight': 2
        },
        'Feature-Policy': {
            'description': 'Controls browser features (deprecated but still used)',
            'recommended': 'Controls various features',
            'risk': 'low',
            'weight': 1
        }
    }

    def __init__(self, timeout: int = 10, user_agent: str = None):
        """
        Initialize the enhanced HTTP fingerprinting tool.
        
        Args:
            timeout: Connection timeout in seconds
            user_agent: Custom User-Agent string
        """
        self.timeout = timeout
        self.user_agent = user_agent or self._get_default_user_agent()
        logger.info("HTTPFingerprint initialized with timeout=%s", timeout)

    def _get_default_user_agent(self) -> str:
        """
        Get a realistic default user agent.
        
        Returns:
            User agent string
        """
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create a robust SSL context compatible with more servers.
        Handles legacy servers and sets appropriate security levels.
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Enable compatibility for legacy servers/renegotiation
            # OP_LEGACY_SERVER_CONNECT = 0x4
            try:
                context.options |= 0x4 
            except (AttributeError, ValueError):
                pass
            
            # Set minimum TLS version to 1.0 to ensure handshake works with older/strict servers
            # Many modern defaults are too strict for recon purposes
            try:
                context.minimum_version = ssl.TLSVersion.TLSv1
            except (AttributeError, ValueError):
                pass
            
            # Optimize ciphers to allow legacy suites if system permits
            try:
                context.set_ciphers('DEFAULT:@SECLEVEL=1')
            except (ssl.SSLError, ValueError):
                pass
            
            return context
        except (AttributeError, ValueError):
            # Fallback for older Python/OpenSSL versions
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context

    def grab_server_banner(self, target: str, use_https: bool = True, 
                          port: int = None) -> Dict[str, Any]:
        """
        Enhanced server banner grabbing with comprehensive information.
        
        Args:
            target: Target hostname or URL
            use_https: Use HTTPS instead of HTTP
            port: Custom port number
            
        Returns:
            Dictionary with server banner information
        """
        result = {
            'target': target,
            'protocol': 'https' if use_https else 'http',
            'port': port or (443 if use_https else 80),
            'server_banner': None,
            'response_code': None,
            'connection_success': False,
            'ssl_certificate': {},
            'response_headers': {},
            'response_time': 0,
            'error': None
        }
        
        start_time = time.time()
        
        try:
            # Parse target if it's a full URL
            parsed_target = self._parse_target(target)
            hostname = parsed_target['hostname']
            actual_port = port or parsed_target['port']
            use_https = use_https or parsed_target['use_https']
            
            # Create connection
            if use_https:
                context = self._create_ssl_context()
                conn = http.client.HTTPSConnection(
                    hostname, actual_port, timeout=self.timeout, context=context
                )
                
                # Get SSL certificate info
                try:
                    # We need to connect first to get the socket and certificate
                    # HEAD request will trigger the connection
                    pass 
                except Exception as e:
                    logger.debug("Could not retrieve SSL certificate: %s", e)
            else:
                conn = http.client.HTTPConnection(
                    hostname, actual_port, timeout=self.timeout
                )
            
            # Send HEAD request
            headers = {'User-Agent': self.user_agent}
            conn.request("HEAD", "/", headers=headers)
            response = conn.getresponse()
            
            # Try to grab cert if HTTPS
            if use_https and hasattr(conn, 'sock') and conn.sock:
                try:
                    cert = conn.sock.getpeercert()
                    if cert:
                        result['ssl_certificate'] = {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'serial_number': cert.get('serialNumber')
                        }
                except Exception as e:
                    pass

            result['response_time'] = time.time() - start_time
            result['response_code'] = response.status
            result['connection_success'] = True
            
            # Extract all headers
            for header, value in response.getheaders():
                result['response_headers'][header] = value
            
            # Extract server banner
            server_header = response.getheader('Server')
            if server_header:
                result['server_banner'] = server_header
                logger.info("Server banner for %s: %s", target, server_header)
            else:
                logger.info("No Server header found for %s", target)
            
            # Extract other interesting headers
            interesting_headers = ['X-Powered-By', 'X-AspNet-Version', 'X-Generator']
            for header in interesting_headers:
                value = response.getheader(header)
                if value:
                    result[header.lower()] = value
            
            conn.close()
            
        except http.client.HTTPException as e:
            result['error'] = f"HTTP error: {e}"
            logger.warning("HTTP error for %s: %s", target, e)
        except socket.timeout:
            result['error'] = f"Connection timeout after {self.timeout} seconds"
            logger.warning("Connection timeout for %s", target)
        except ConnectionRefusedError:
            result['error'] = "Connection refused"
            logger.warning("Connection refused for %s", target)
        except Exception as e:
            result['error'] = f"Unexpected error: {e}"
            logger.error("Unexpected error for %s: %s", target, e)
        
        return result

    def get_http_headers(self, target: str, use_https: bool = True, 
                        port: int = None, path: str = '/') -> Dict[str, Any]:
        """
        Enhanced HTTP headers retrieval with comprehensive analysis.
        
        Args:
            target: Target hostname or URL
            use_https: Use HTTPS instead of HTTP
            port: Custom port number
            path: Specific path to request
            
        Returns:
            Dictionary with HTTP headers analysis
        """
        result = {
            'target': target,
            'path': path,
            'headers': {},
            'response_code': None,
            'content_type': None,
            'content_length': None,
            'cookies': [],
            'redirect_chain': [],
            'response_hash': None,
            'error': None
        }
        
        try:
            # Parse target
            parsed_target = self._parse_target(target)
            hostname = parsed_target['hostname']
            actual_port = port or parsed_target['port']
            use_https = use_https or parsed_target['use_https']
            
            # Follow redirects
            current_url = f"{'https' if use_https else 'http'}://{hostname}"
            if actual_port not in [80, 443]:
                current_url += f":{actual_port}"
            current_url += path
            
            redirect_count = 0
            max_redirects = 5
            
            while redirect_count < max_redirects:
                # Create connection
                if use_https:
                    context = self._create_ssl_context()
                    conn = http.client.HTTPSConnection(
                        hostname, actual_port, timeout=self.timeout, context=context
                    )
                else:
                    conn = http.client.HTTPConnection(
                        hostname, actual_port, timeout=self.timeout
                    )
                
                # Send GET request
                headers = {'User-Agent': self.user_agent}
                conn.request("GET", path, headers=headers)
                response = conn.getresponse()
                
                # Read response content for analysis
                content = response.read()
                
                # Store headers
                response_headers = {}
                for header, value in response.getheaders():
                    response_headers[header] = value
                
                # Extract cookies
                set_cookie = response_headers.get('Set-Cookie')
                if set_cookie:
                    result['cookies'].append(set_cookie)
                
                # Store first response data
                if redirect_count == 0:
                    result['headers'] = response_headers
                    result['response_code'] = response.status
                    result['content_type'] = response_headers.get('Content-Type')
                    result['content_length'] = response_headers.get('Content-Length')
                    
                    # Calculate content hash
                    if content:
                        result['response_hash'] = hashlib.md5(content).hexdigest()
                
                # Check for redirect
                if response.status in [301, 302, 303, 307, 308]:
                    location = response_headers.get('Location')
                    if location:
                        result['redirect_chain'].append({
                            'from': current_url,
                            'to': location,
                            'status': response.status
                        })
                        
                        # Parse new location
                        parsed_location = urlparse(location)
                        if parsed_location.netloc:
                            hostname = parsed_location.hostname or hostname
                            actual_port = parsed_location.port or actual_port
                            use_https = parsed_location.scheme == 'https'
                        path = parsed_location.path or '/'
                        current_url = location
                        redirect_count += 1
                    else:
                        break
                else:
                    break
                
                conn.close()
            
            logger.info("Retrieved %s headers from %s", len(result['headers']), target)
            
        except Exception as e:
            result['error'] = f"Header retrieval error: {e}"
            logger.error("Header retrieval failed for %s: %s", target, e)
        
        return result

    def detect_technologies(self, target: str, use_https: bool = True, 
                           port: int = None) -> Dict[str, Any]:
        """
        Enhanced technology detection with confidence scoring.
        
        Args:
            target: Target hostname or URL
            use_https: Use HTTPS instead of HTTP
            port: Custom port number
            
        Returns:
            Dictionary with detected technologies
        """
        result = {
            'target': target,
            'technologies': {},
            'confidence_levels': {},
            'detection_methods': {},
            'technology_count': 0,
            'error': None
        }
        
        try:
            # Get headers and server banner
            headers_result = self.get_http_headers(target, use_https, port)
            banner_result = self.grab_server_banner(target, use_https, port)
            
            # Only fail if both essential methods failed
            if headers_result['error'] and banner_result['error']:
                # Pass through the error from get_http_headers as it's usually more descriptive
                result['error'] = headers_result['error']
                return result
            
            # Combine all data for analysis
            analysis_data = {
                'headers': headers_result.get('headers', {}),
                'server_banner': banner_result.get('server_banner'),
                'cookies': headers_result.get('cookies', []),
                'content_type': headers_result.get('content_type'),
                'response_hash': headers_result.get('response_hash')
            }
            
            # Detect technologies
            detected_tech = {}
            confidence_levels = {}
            detection_methods = {}
            
            # Check server banner with high confidence
            if analysis_data['server_banner']:
                server_banner = analysis_data['server_banner']
                for tech_type, patterns in self.SERVER_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, server_banner, re.IGNORECASE):
                            detected_tech.setdefault('web_servers', []).append(tech_type)
                            confidence_levels[tech_type] = 'high'
                            detection_methods[tech_type] = 'server_banner'
                            break
            
            # Check headers for technologies
            headers_str = str(analysis_data['headers']).lower()
            cookies_str = str(analysis_data['cookies']).lower()
            
            for category, technologies in self.TECHNOLOGY_PATTERNS.items():
                for tech_name, patterns in technologies.items():
                    for pattern in patterns:
                        if (re.search(pattern, headers_str, re.IGNORECASE) or
                            re.search(pattern, cookies_str, re.IGNORECASE)):
                            
                            detected_tech.setdefault(category, []).append(tech_name)
                            confidence_levels[tech_name] = 'medium'
                            detection_methods[tech_name] = 'http_headers'
                            break
            
            # Get page content for additional detection
            # Only attempt if we successfully got headers/connection
            if not headers_result['error']:
                content_tech = self._detect_from_content(target, use_https, port)
                for category, technologies in content_tech.items():
                    for tech_name in technologies:
                        if tech_name not in detected_tech.get(category, []):
                            detected_tech.setdefault(category, []).append(tech_name)
                            confidence_levels[tech_name] = 'low'
                            detection_methods[tech_name] = 'page_content'
            
            # Calculate technology count
            total_tech = sum(len(techs) for techs in detected_tech.values())
            
            result['technologies'] = detected_tech
            result['confidence_levels'] = confidence_levels
            result['detection_methods'] = detection_methods
            result['technology_count'] = total_tech
            
            logger.info("Detected %s technology categories with %s total technologies for %s", 
                       len(detected_tech), total_tech, target)
            
        except Exception as e:
            result['error'] = f"Technology detection error: {e}"
            logger.error("Technology detection failed for %s: %s", target, e)
        
        return result

    def _detect_from_content(self, target: str, use_https: bool = True, 
                            port: int = None) -> Dict[str, List[str]]:
        """
        Enhanced technology detection from page content.
        
        Args:
            target: Target hostname or URL
            use_https: Use HTTPS instead of HTTP
            port: Custom port number
            
        Returns:
            Dictionary of technologies detected from content
        """
        detected = {}
        
        try:
            # Parse target
            parsed_target = self._parse_target(target)
            hostname = parsed_target['hostname']
            actual_port = port or parsed_target['port']
            use_https = use_https or parsed_target['use_https']
            
            # Create connection and get content
            if use_https:
                context = self._create_ssl_context()
                conn = http.client.HTTPSConnection(
                    hostname, actual_port, timeout=self.timeout, context=context
                )
            else:
                conn = http.client.HTTPConnection(
                    hostname, actual_port, timeout=self.timeout
                )
            
            # Send GET request for content
            headers = {'User-Agent': self.user_agent}
            conn.request("GET", "/", headers=headers)
            response = conn.getresponse()
            
            # Read limited content for analysis
            content = response.read(16384).decode('utf-8', errors='ignore')
            conn.close()
            
            # Search for technology indicators in content
            content_lower = content.lower()
            
            # Check for WordPress
            if any(indicator in content_lower for indicator in ['wp-content', 'wp-includes', 'wordpress']):
                detected.setdefault('cms', []).append('WordPress')
            
            # Check for Django
            if 'csrfmiddlewaretoken' in content_lower:
                detected.setdefault('frameworks', []).append('Django')
            
            # Check for common JavaScript frameworks
            js_frameworks = {
                'React': ['react', 'react-dom'],
                'Vue.js': ['vue', 'vue.js'],
                'Angular': ['angular', 'ng-'],
                'jQuery': ['jquery']
            }
            
            for framework, indicators in js_frameworks.items():
                if any(indicator in content_lower for indicator in indicators):
                    detected.setdefault('javascript', []).append(framework)
            
            # Check for analytics
            if 'google-analytics.com' in content_lower:
                detected.setdefault('analytics', []).append('Google Analytics')
            if 'googletagmanager.com' in content_lower:
                detected.setdefault('analytics', []).append('Google Tag Manager')
            if 'facebook.com/tr' in content_lower:
                detected.setdefault('analytics', []).append('Facebook Pixel')
            
        except Exception as e:
            logger.debug("Content-based detection failed: %s", e)
        
        return detected

    def check_security_headers(self, target: str, use_https: bool = True, 
                              port: int = None) -> Dict[str, Any]:
        """
        Enhanced security headers analysis with scoring.
        
        Args:
            target: Target hostname or URL
            use_https: Use HTTPS instead of HTTP
            port: Custom port number
            
        Returns:
            Dictionary with security header analysis
        """
        result = {
            'target': target,
            'security_headers': {},
            'missing_headers': [],
            'score': 0,
            'max_score': 0,
            'recommendations': [],
            'risk_assessment': {},
            'error': None
        }
        
        try:
            # Get headers
            headers_result = self.get_http_headers(target, use_https, port)
            if headers_result['error']:
                result['error'] = headers_result['error']
                return result
            
            headers = headers_result['headers']
            
            # Calculate max possible score
            max_score = sum(header_info['weight'] for header_info in self.SECURITY_HEADERS.values())
            result['max_score'] = max_score
            
            present_headers = 0
            achieved_score = 0
            
            # Analyze each security header
            for header, info in self.SECURITY_HEADERS.items():
                header_value = headers.get(header)
                
                if header_value:
                    present_headers += 1
                    header_score = info['weight']
                    
                    # Check if value matches recommended
                    compliance = 'partial'
                    if info['recommended'] and info['recommended'].lower() in header_value.lower():
                        compliance = 'full'
                        header_score = info['weight']  # Full points for compliance
                    else:
                        header_score = info['weight'] * 0.5  # Half points for presence but non-compliance
                    
                    achieved_score += header_score
                    
                    result['security_headers'][header] = {
                        'present': True,
                        'value': header_value,
                        'description': info['description'],
                        'recommended': info['recommended'],
                        'risk_level': info['risk'],
                        'weight': info['weight'],
                        'score_achieved': header_score,
                        'compliance': compliance
                    }
                    
                    if compliance == 'partial':
                        result['recommendations'].append(
                            f"Improve {header} configuration: {header_value}"
                        )
                else:
                    result['missing_headers'].append(header)
                    result['recommendations'].append(
                        f"Add missing security header: {header}"
                    )
            
            # Calculate security score
            result['score'] = round((achieved_score / max_score) * 100, 1) if max_score > 0 else 0
            
            # Risk assessment
            result['risk_assessment'] = self._assess_security_risk(result)
            
            # Add overall assessment
            if result['score'] >= 80:
                result['assessment'] = 'Good'
            elif result['score'] >= 60:
                result['assessment'] = 'Fair'
            else:
                result['assessment'] = 'Poor'
            
            logger.info("Security headers score for %s: %s/100", target, result['score'])
            
        except Exception as e:
            result['error'] = f"Security header analysis error: {e}"
            logger.error("Security header analysis failed for %s: %s", target, e)
        
        return result

    def _assess_security_risk(self, security_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess security risk based on missing headers.
        
        Args:
            security_results: Security header analysis results
            
        Returns:
            Risk assessment dictionary
        """
        risk_assessment = {
            'high_risk_issues': [],
            'medium_risk_issues': [],
            'low_risk_issues': [],
            'overall_risk': 'low'
        }
        
        missing_headers = security_results.get('missing_headers', [])
        security_headers = security_results.get('security_headers', {})
        
        for header in missing_headers:
            header_info = self.SECURITY_HEADERS.get(header, {})
            risk_level = header_info.get('risk', 'low')
            
            if risk_level == 'high':
                risk_assessment['high_risk_issues'].append(f"Missing {header}")
            elif risk_level == 'medium':
                risk_assessment['medium_risk_issues'].append(f"Missing {header}")
            else:
                risk_assessment['low_risk_issues'].append(f"Missing {header}")
        
        # Check for partial compliance
        for header, info in security_headers.items():
            if info.get('compliance') == 'partial':
                risk_level = info.get('risk_level', 'low')
                if risk_level == 'high':
                    risk_assessment['high_risk_issues'].append(f"Misconfigured {header}")
                elif risk_level == 'medium':
                    risk_assessment['medium_risk_issues'].append(f"Misconfigured {header}")
        
        # Determine overall risk
        if risk_assessment['high_risk_issues']:
            risk_assessment['overall_risk'] = 'high'
        elif risk_assessment['medium_risk_issues']:
            risk_assessment['overall_risk'] = 'medium'
        else:
            risk_assessment['overall_risk'] = 'low'
        
        return risk_assessment

    def run_http_fingerprint(self, target: str, use_https: bool = True, 
                            port: int = None) -> Dict[str, Any]:
        """
        Perform complete enhanced HTTP fingerprinting analysis.
        
        Args:
            target: Target hostname or URL
            use_https: Use HTTPS instead of HTTP
            port: Custom port number
            
        Returns:
            Comprehensive HTTP fingerprinting results
        """
        full_result = {
            'target': target,
            'analysis_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'server_banner': {},
            'http_headers': {},
            'technologies': {},
            'security_headers': {},
            'performance_metrics': {},
            'summary': {},
            'error': None
        }
        
        logger.info("Starting full HTTP fingerprinting for: %s", target)
        
        start_time = time.time()
        
        try:
            # Step 1: Server banner grabbing
            full_result['server_banner'] = self.grab_server_banner(target, use_https, port)
            
            # Step 2: HTTP headers analysis
            full_result['http_headers'] = self.get_http_headers(target, use_https, port)
            
            # Step 3: Technology detection
            full_result['technologies'] = self.detect_technologies(target, use_https, port)
            
            # Step 4: Security headers analysis
            full_result['security_headers'] = self.check_security_headers(target, use_https, port)
            
            # Step 5: Performance metrics
            full_result['performance_metrics'] = {
                'total_analysis_time': time.time() - start_time,
                'server_response_time': full_result['server_banner'].get('response_time', 0)
            }
            
            # Generate enhanced summary
            full_result['summary'] = {
                'server_identified': full_result['server_banner'].get('server_banner') is not None,
                'technologies_detected': full_result['technologies'].get('technology_count', 0),
                'security_score': full_result['security_headers'].get('score', 0),
                'security_risk': full_result['security_headers'].get('risk_assessment', {}).get('overall_risk', 'unknown'),
                'redirects_found': len(full_result['http_headers'].get('redirect_chain', [])),
                'cookies_found': len(full_result['http_headers'].get('cookies', [])),
                'analysis_successful': True
            }
            
            logger.info("Full HTTP fingerprinting completed for %s", target)
            
        except Exception as e:
            full_result['error'] = f"Full HTTP fingerprinting failed: {e}"
            full_result['summary'] = {'analysis_successful': False}
            logger.error("Full HTTP fingerprinting failed for %s: %s", target, e)
        
        return full_result

    def _parse_target(self, target: str) -> Dict[str, Any]:
        """
        Enhanced target parsing with better URL handling.
        
        Args:
            target: Target hostname, IP, or URL
            
        Returns:
            Dictionary with parsed target components
        """
        result = {
            'hostname': target,
            'port': 80,
            'use_https': False,
            'path': '/'
        }
        
        try:
            # Check if it's a full URL
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                result['hostname'] = parsed.hostname
                result['port'] = parsed.port or (443 if parsed.scheme == 'https' else 80)
                result['use_https'] = parsed.scheme == 'https'
                result['path'] = parsed.path or '/'
            else:
                # Check for port in hostname
                if ':' in target:
                    hostname, port_str = target.split(':', 1)
                    result['hostname'] = hostname
                    try:
                        result['port'] = int(port_str)
                    except ValueError:
                        pass
                # Check if it might be an HTTPS service by port
                if result['port'] in [443, 8443, 9443]:
                    result['use_https'] = True
        
        except Exception as e:
            logger.debug("Target parsing error for %s: %s", target, e)
        
        return result


def handle_http_fingerprint(args: Namespace) -> str:
    """
    Enhanced HTTP fingerprinting handler with better parameter processing.
    
    Args:
        args: argparse.Namespace with fingerprinting parameters
        
    Returns:
        JSON string with fingerprinting results
    """
    fingerprint = HTTPFingerprint(
        timeout=getattr(args, 'timeout', 10),
        user_agent=getattr(args, 'user_agent', None)
    )
    
    try:
        analysis_type = getattr(args, 'analysis_type', 'full')
        target = getattr(args, 'target', '')
        
        if not target:
            return json.dumps({'error': 'No target specified'}, indent=2)
        
        if analysis_type == 'banner':
            result = fingerprint.grab_server_banner(
                target, 
                getattr(args, 'use_https', True),
                getattr(args, 'port', None)
            )
        elif analysis_type == 'headers':
            result = fingerprint.get_http_headers(
                target,
                getattr(args, 'use_https', True),
                getattr(args, 'port', None)
            )
        elif analysis_type == 'technologies':
            result = fingerprint.detect_technologies(
                target,
                getattr(args, 'use_https', True),
                getattr(args, 'port', None)
            )
        elif analysis_type == 'security':
            result = fingerprint.check_security_headers(
                target,
                getattr(args, 'use_https', True),
                getattr(args, 'port', None)
            )
        else:  # full analysis
            result = fingerprint.run_http_fingerprint(
                target,
                getattr(args, 'use_https', True),
                getattr(args, 'port', None)
            )
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        error_result = {
            'error': f"HTTP fingerprinting failed: {e}",
            'analysis_type': getattr(args, 'analysis_type', 'unknown'),
            'target': getattr(args, 'target', 'unknown')
        }
        return json.dumps(error_result, indent=2)


def run_module(params_dict: Dict[str, Any]) -> str:
    """
    Enhanced main module entry point for integration with orchestration tools.
    
    Args:
        params_dict: Dictionary containing fingerprinting parameters:
            - target: required, hostname or URL to analyze
            - analysis_type: optional, type of analysis ('banner', 'headers', 'technologies', 'security', 'full')
            - timeout: optional, connection timeout in seconds
            - use_https: optional, use HTTPS (default: True)
            - port: optional, custom port number
            - user_agent: optional, custom User-Agent string
            
    Returns:
        JSON string with fingerprinting results
    """
    try:
        # Create fingerprinting tool with provided parameters
        fingerprint = HTTPFingerprint(
            timeout=params_dict.get('timeout', 10),
            user_agent=params_dict.get('user_agent')
        )
        
        target = params_dict['target']
        analysis_type = params_dict.get('analysis_type', 'full')
        use_https = params_dict.get('use_https', True)
        port = params_dict.get('port')
        
        # Execute appropriate analysis
        if analysis_type == 'banner':
            result = fingerprint.grab_server_banner(target, use_https, port)
        elif analysis_type == 'headers':
            result = fingerprint.get_http_headers(target, use_https, port)
        elif analysis_type == 'technologies':
            result = fingerprint.detect_technologies(target, use_https, port)
        elif analysis_type == 'security':
            result = fingerprint.check_security_headers(target, use_https, port)
        else:  # full analysis
            result = fingerprint.run_http_fingerprint(target, use_https, port)
        
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
    
    parser = argparse.ArgumentParser(description='Enhanced HTTP Fingerprinting Module')
    parser.add_argument('target', help='Target hostname or URL to analyze')
    parser.add_argument('--analysis-type', 
                       choices=['banner', 'headers', 'technologies', 'security', 'full'],
                       default='full', help='Type of HTTP analysis to perform')
    parser.add_argument('--timeout', type=int, default=10, 
                       help='Connection timeout in seconds')
    parser.add_argument('--port', type=int, help='Custom port number')
    parser.add_argument('--no-https', action='store_true', 
                       help='Use HTTP instead of HTTPS')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    
    args = parser.parse_args()
    
    # Execute fingerprinting and print results
    result_json = handle_http_fingerprint(args)
    print(result_json)