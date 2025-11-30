#!/usr/bin/env python3
"""
Enhanced SSL/TLS Enumeration Module
A comprehensive SSL/TLS security assessment tool for cybersecurity analysis.
"""

import ssl
import socket
import json
import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple, Union
import hashlib
import re

# Configure logging
logger = logging.getLogger(__name__)

class SSLEnumerator:
    """
    Enhanced SSL/TLS enumeration tool for comprehensive security assessment.
    
    This class provides methods to analyze SSL/TLS configurations,
    certificate details, supported protocols, and cipher suites.
    """
    
    # SSL/TLS protocol versions with enhanced coverage
    PROTOCOL_VERSIONS = {
        ssl.PROTOCOL_TLS: "TLS",
        ssl.PROTOCOL_TLSv1: "TLSv1.0",
        ssl.PROTOCOL_TLSv1_1: "TLSv1.1",
        ssl.PROTOCOL_TLSv1_2: "TLSv1.2",
    }
    
    # Try to add TLSv1.3 if available
    try:
        PROTOCOL_VERSIONS[ssl.PROTOCOL_TLSv1_3] = "TLSv1.3"
    except AttributeError:
        logger.warning("TLSv1.3 not available in this Python version")
    
    # Enhanced cipher suite database
    CIPHER_SUITES = {
        # Strong modern ciphers
        'TLS_AES_256_GCM_SHA384': {'security': 'strong', 'protocol': 'TLSv1.3'},
        'TLS_CHACHA20_POLY1305_SHA256': {'security': 'strong', 'protocol': 'TLSv1.3'},
        'TLS_AES_128_GCM_SHA256': {'security': 'strong', 'protocol': 'TLSv1.3'},
        'ECDHE-RSA-AES256-GCM-SHA384': {'security': 'strong', 'protocol': 'TLSv1.2'},
        'ECDHE-ECDSA-AES256-GCM-SHA384': {'security': 'strong', 'protocol': 'TLSv1.2'},
        'ECDHE-RSA-CHACHA20-POLY1305': {'security': 'strong', 'protocol': 'TLSv1.2'},
        
        # Good ciphers
        'ECDHE-RSA-AES128-GCM-SHA256': {'security': 'good', 'protocol': 'TLSv1.2'},
        'ECDHE-ECDSA-AES128-GCM-SHA256': {'security': 'good', 'protocol': 'TLSv1.2'},
        'DHE-RSA-AES256-GCM-SHA384': {'security': 'good', 'protocol': 'TLSv1.2'},
        'DHE-RSA-AES128-GCM-SHA256': {'security': 'good', 'protocol': 'TLSv1.2'},
        
        # Weak ciphers
        'ECDHE-RSA-AES256-SHA384': {'security': 'weak', 'protocol': 'TLSv1.2'},
        'ECDHE-RSA-AES256-SHA': {'security': 'weak', 'protocol': 'TLSv1.2'},
        'AES256-GCM-SHA384': {'security': 'weak', 'protocol': 'TLSv1.2'},
        'AES256-SHA256': {'security': 'weak', 'protocol': 'TLSv1.2'},
        'AES256-SHA': {'security': 'weak', 'protocol': 'TLSv1.2'},
        
        # Deprecated ciphers
        'DES-CBC3-SHA': {'security': 'deprecated', 'protocol': 'TLSv1.0'},
        'RC4-SHA': {'security': 'deprecated', 'protocol': 'TLSv1.0'},
        'RC4-MD5': {'security': 'deprecated', 'protocol': 'TLSv1.0'},
        'NULL-SHA': {'security': 'deprecated', 'protocol': 'TLSv1.0'},
    }
    
    def __init__(self, timeout: int = 10):
        """
        Initialize SSLEnumerator.
        
        Args:
            timeout: Connection timeout in seconds (default: 10)
        """
        self.timeout = timeout
        self.default_ports = [443, 993, 995, 465, 8443, 636, 989, 990]  # Common SSL/TLS ports
        
    def create_ssl_connection(self, host: str, port: int = 443, 
                            protocol: Optional[int] = None,
                            suppress_errors: bool = False) -> Optional[ssl.SSLSocket]:
        """
        Enhanced SSL/TLS connection with comprehensive error handling.
        
        Args:
            host: Target hostname or IP address
            port: Target port (default: 443)
            protocol: Specific SSL/TLS protocol to use
            suppress_errors: Whether to suppress exceptions
            
        Returns:
            SSL socket object or None if connection fails
        """
        try:
            # Create raw TCP socket
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(self.timeout)
            
            # Connect to target
            raw_socket.connect((host, port))
            logger.debug("TCP connection established to %s:%s", host, port)
            
            # Create SSL context with enhanced settings
            if protocol:
                context = ssl.SSLContext(protocol)
            else:
                context = ssl.create_default_context()
            
            # Enhanced context configuration
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Set more secure options if available
            try:
                context.options |= ssl.OP_NO_SSLv2
                context.options |= ssl.OP_NO_SSLv3
            except AttributeError:
                pass
            
            # Wrap socket with SSL
            ssl_socket = context.wrap_socket(raw_socket, server_hostname=host)
            logger.debug("SSL/TLS connection established using protocol %s", protocol)
            
            return ssl_socket
            
        except ssl.SSLError as e:
            if not suppress_errors:
                logger.error("SSL error connecting to %s:%s: %s", host, port, e)
            return None
        except socket.timeout:
            if not suppress_errors:
                logger.error("Connection timeout to %s:%s", host, port)
            return None
        except socket.gaierror as e:
            if not suppress_errors:
                logger.error("DNS resolution failed for %s: %s", host, e)
            return None
        except ConnectionRefusedError:
            if not suppress_errors:
                logger.error("Connection refused by %s:%s", host, port)
            return None
        except Exception as e:
            if not suppress_errors:
                logger.error("Unexpected error connecting to %s:%s: %s", host, port, e)
            return None
    
    def retrieve_certificate(self, host: str, port: int = 443) -> Dict[str, Any]:
        """
        Enhanced certificate retrieval and analysis.
        
        Args:
            host: Target hostname or IP address
            port: Target port (default: 443)
            
        Returns:
            Dictionary containing certificate details
        """
        logger.info("Retrieving certificate for %s:%s", host, port)
        
        result = {
            "host": host,
            "port": port,
            "certificate_chain": [],
            "certificate_details": {},
            "fingerprints": {},
            "status": "error",
            "error": None
        }
        
        try:
            ssl_socket = self.create_ssl_connection(host, port)
            if not ssl_socket:
                result["error"] = "Failed to establish SSL connection"
                return result
            
            # Get certificate chain
            cert_chain = ssl_socket.getpeercert(binary_form=False)
            cert_binary = ssl_socket.getpeercert(binary_form=True)
            cipher = ssl_socket.cipher()
            ssl_version = ssl_socket.version()
            
            ssl_socket.close()
            
            if not cert_chain:
                result["error"] = "No certificate received"
                return result
            
            # Parse certificate information
            cert_info = self._parse_certificate(cert_chain)
            
            # Generate certificate fingerprints
            fingerprints = self._generate_certificate_fingerprints(cert_binary)
            
            result.update({
                "certificate_details": cert_info,
                "fingerprints": fingerprints,
                "cipher": {
                    "name": cipher[0] if cipher else "Unknown",
                    "version": cipher[1] if cipher else "Unknown",
                    "bits": cipher[2] if cipher else 0
                },
                "ssl_version": ssl_version,
                "status": "success"
            })
            
            logger.info("Successfully retrieved certificate for %s:%s", host, port)
            
        except Exception as e:
            logger.error("Error retrieving certificate for %s:%s: %s", host, port, e)
            result["error"] = str(e)
        
        return result
    
    def _parse_certificate(self, cert: Dict) -> Dict[str, Any]:
        """
        Enhanced certificate parsing with additional security analysis.
        
        Args:
            cert: Certificate dictionary from SSL socket
            
        Returns:
            Structured certificate information
        """
        try:
            # Parse subject
            subject = {}
            for item in cert.get('subject', []):
                for key, value in item:
                    subject[key] = value
            
            # Parse issuer
            issuer = {}
            for item in cert.get('issuer', []):
                for key, value in item:
                    issuer[key] = value
            
            # Parse validity dates
            not_before = cert.get('notBefore', '')
            not_after = cert.get('notAfter', '')
            
            # Parse subject alternative names
            san_list = []
            for extension in cert.get('subjectAltName', []):
                san_list.append(f"{extension[0]}: {extension[1]}")
            
            # Parse extensions
            extensions = {}
            for extension in cert.get('extensions', []):
                if 'critical' in extension and 'value' in extension:
                    ext_name = extension.get('name', 'unknown')
                    extensions[ext_name] = {
                        'critical': extension['critical'],
                        'value': extension['value']
                    }
            
            # Analyze certificate security
            security_analysis = self._analyze_certificate_security(cert)
            
            return {
                "subject": subject,
                "issuer": issuer,
                "validity": {
                    "not_before": not_before,
                    "not_after": not_after,
                    "not_before_parsed": self._parse_cert_date(not_before),
                    "not_after_parsed": self._parse_cert_date(not_after)
                },
                "serial_number": cert.get('serialNumber', ''),
                "version": cert.get('version', ''),
                "subject_alt_names": san_list,
                "extensions": extensions,
                "security_analysis": security_analysis
            }
        except Exception as e:
            logger.error("Error parsing certificate: %s", e)
            return {
                "subject": {},
                "issuer": {},
                "validity": {},
                "serial_number": "",
                "version": "",
                "subject_alt_names": [],
                "extensions": {},
                "error": f"Certificate parsing error: {str(e)}"
            }
    
    def _generate_certificate_fingerprints(self, cert_binary: bytes) -> Dict[str, str]:
        """
        Generate various certificate fingerprints.
        
        Args:
            cert_binary: Certificate in binary format
            
        Returns:
            Dictionary of certificate fingerprints
        """
        fingerprints = {}
        
        try:
            if cert_binary:
                # SHA-1 fingerprint (legacy)
                fingerprints['sha1'] = hashlib.sha1(cert_binary).hexdigest().upper()
                
                # SHA-256 fingerprint (current standard)
                fingerprints['sha256'] = hashlib.sha256(cert_binary).hexdigest().upper()
                
                # MD5 fingerprint (deprecated, for reference)
                fingerprints['md5'] = hashlib.md5(cert_binary).hexdigest().upper()
                
                # Format fingerprints with colons
                fingerprints['sha1_formatted'] = ':'.join(
                    fingerprints['sha1'][i:i+2] for i in range(0, len(fingerprints['sha1']), 2)
                )
                fingerprints['sha256_formatted'] = ':'.join(
                    fingerprints['sha256'][i:i+2] for i in range(0, len(fingerprints['sha256']), 2)
                )
                
        except Exception as e:
            logger.error("Error generating certificate fingerprints: %s", e)
        
        return fingerprints
    
    def _analyze_certificate_security(self, cert: Dict) -> Dict[str, Any]:
        """
        Analyze certificate for security issues.
        
        Args:
            cert: Certificate dictionary
            
        Returns:
            Security analysis results
        """
        analysis = {
            "issues": [],
            "warnings": [],
            "recommendations": [],
            "overall_rating": "good"
        }
        
        try:
            # Check certificate expiry
            not_after = cert.get('notAfter', '')
            expiry_date = self._parse_cert_date_to_datetime(not_after)
            if expiry_date:
                days_until_expiry = (expiry_date - datetime.now(timezone.utc)).days
                if days_until_expiry < 0:
                    analysis["issues"].append("Certificate has expired")
                    analysis["overall_rating"] = "critical"
                elif days_until_expiry < 30:
                    analysis["issues"].append("Certificate expires soon")
                    analysis["overall_rating"] = "warning"
                elif days_until_expiry < 90:
                    analysis["warnings"].append("Certificate will expire within 90 days")
            
            # Check certificate validity period
            not_before = cert.get('notBefore', '')
            start_date = self._parse_cert_date_to_datetime(not_before)
            if start_date and expiry_date:
                validity_days = (expiry_date - start_date).days
                if validity_days > 825:  # Approximately 2 years + 3 months
                    analysis["warnings"].append("Certificate validity period exceeds 2 years")
            
            # Check key usage extensions
            extensions = cert.get('extensions', [])
            for ext in extensions:
                if ext.get('name') == 'keyUsage':
                    key_usage = ext.get('value', '')
                    if 'Digital Signature' not in key_usage:
                        analysis["warnings"].append("Digital Signature not in keyUsage")
            
            # Check subject alternative names
            san_count = len(cert.get('subjectAltName', []))
            if san_count == 0:
                analysis["warnings"].append("No Subject Alternative Names configured")
            
            # Generate recommendations
            if analysis["overall_rating"] == "critical":
                analysis["recommendations"].append("Replace expired certificate immediately")
            elif analysis["overall_rating"] == "warning":
                analysis["recommendations"].append("Renew certificate before expiry")
            
            if not analysis["issues"] and not analysis["warnings"]:
                analysis["recommendations"].append("Certificate configuration appears secure")
                
        except Exception as e:
            logger.error("Error analyzing certificate security: %s", e)
            analysis["issues"].append(f"Security analysis error: {e}")
        
        return analysis
    
    def _parse_cert_date(self, date_str: str) -> Optional[str]:
        """
        Parse certificate date string to ISO format.
        
        Args:
            date_str: Certificate date string
            
        Returns:
            ISO formatted date string or None
        """
        try:
            if not date_str:
                return None
            
            # Handle different date formats
            for fmt in ['%b %d %H:%M:%S %Y %Z', '%Y%m%d%H%M%SZ', '%Y-%m-%d %H:%M:%S']:
                try:
                    dt = datetime.strptime(date_str, fmt)
                    return dt.isoformat()
                except ValueError:
                    continue
            
            return date_str
        except Exception:
            return date_str
    
    def list_supported_protocols(self, host: str, port: int = 443) -> Dict[str, Any]:
        """
        Enhanced protocol testing with detailed analysis.
        
        Args:
            host: Target hostname or IP address
            port: Target port (default: 443)
            
        Returns:
            Dictionary containing supported protocols
        """
        logger.info("Testing supported protocols for %s:%s", host, port)
        
        results = {
            "host": host,
            "port": port,
            "supported_protocols": [],
            "unsupported_protocols": [],
            "security_assessment": {},
            "details": {}
        }
        
        for protocol, protocol_name in self.PROTOCOL_VERSIONS.items():
            try:
                ssl_socket = self.create_ssl_connection(
                    host, port, protocol, suppress_errors=True
                )
                
                if ssl_socket:
                    cipher = ssl_socket.cipher()
                    results["supported_protocols"].append(protocol_name)
                    results["details"][protocol_name] = {
                        "status": "supported",
                        "cipher": cipher[0] if cipher else "Unknown",
                        "connection_successful": True
                    }
                    ssl_socket.close()
                else:
                    results["unsupported_protocols"].append(protocol_name)
                    results["details"][protocol_name] = {
                        "status": "unsupported",
                        "connection_successful": False
                    }
                    
            except Exception as e:
                logger.debug("Protocol %s failed: %s", protocol_name, e)
                results["unsupported_protocols"].append(protocol_name)
                results["details"][protocol_name] = {
                    "status": "unsupported",
                    "error": str(e),
                    "connection_successful": False
                }
        
        # Security assessment
        results["security_assessment"] = self._assess_protocol_security(results)
        results["status"] = "success"
        
        return results
    
    def _assess_protocol_security(self, protocol_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess protocol security based on supported versions.
        
        Args:
            protocol_results: Protocol testing results
            
        Returns:
            Security assessment
        """
        assessment = {
            "issues": [],
            "warnings": [],
            "recommendations": [],
            "overall_rating": "good"
        }
        
        supported = protocol_results.get("supported_protocols", [])
        
        # Check for insecure protocols
        insecure_protocols = ["TLSv1.0", "TLSv1.1"]
        for protocol in insecure_protocols:
            if protocol in supported:
                assessment["issues"].append(f"Insecure protocol supported: {protocol}")
                assessment["overall_rating"] = "poor"
        
        # Check for modern protocols
        modern_protocols = ["TLSv1.2", "TLSv1.3"]
        modern_supported = any(proto in supported for proto in modern_protocols)
        if not modern_supported:
            assessment["issues"].append("No modern TLS protocols supported")
            assessment["overall_rating"] = "critical"
        
        # Generate recommendations
        if "TLSv1.0" in supported or "TLSv1.1" in supported:
            assessment["recommendations"].append("Disable TLSv1.0 and TLSv1.1")
        
        if "TLSv1.3" not in supported:
            assessment["recommendations"].append("Enable TLSv1.3 for best security")
        
        if assessment["overall_rating"] == "good":
            assessment["recommendations"].append("Protocol configuration appears secure")
        
        return assessment
    
    def list_supported_ciphers(self, host: str, port: int = 443) -> Dict[str, Any]:
        """
        Enhanced cipher suite testing with security classification.
        
        Args:
            host: Target hostname or IP address
            port: Target port (default: 443)
            
        Returns:
            Dictionary containing cipher information
        """
        logger.info("Testing cipher suites for %s:%s", host, port)
        
        results = {
            "host": host,
            "port": port,
            "supported_ciphers": [],
            "unsupported_ciphers": [],
            "cipher_analysis": {},
            "security_summary": {
                "strong": 0,
                "good": 0,
                "weak": 0,
                "deprecated": 0
            },
            "details": {}
        }
        
        for cipher, cipher_info in self.CIPHER_SUITES.items():
            try:
                # Create custom context with specific cipher
                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                
                # Try to set the specific cipher
                try:
                    context.set_ciphers(cipher)
                except ssl.SSLError:
                    results["unsupported_ciphers"].append(cipher)
                    results["details"][cipher] = {
                        "status": "unsupported",
                        "error": "Cipher not available in OpenSSL"
                    }
                    continue
                
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Create connection
                raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_socket.settimeout(self.timeout)
                raw_socket.connect((host, port))
                
                ssl_socket = context.wrap_socket(raw_socket, server_hostname=host)
                actual_cipher = ssl_socket.cipher()
                
                if actual_cipher and actual_cipher[0] == cipher:
                    results["supported_ciphers"].append(cipher)
                    results["details"][cipher] = {
                        "status": "supported",
                        "security_level": cipher_info["security"],
                        "protocol": cipher_info["protocol"],
                        "bits": actual_cipher[2],
                        "protocol_used": actual_cipher[1]
                    }
                    
                    # Update security summary
                    security_level = cipher_info["security"]
                    results["security_summary"][security_level] += 1
                    
                else:
                    results["unsupported_ciphers"].append(cipher)
                    results["details"][cipher] = {
                        "status": "unsupported",
                        "actual_cipher": actual_cipher[0] if actual_cipher else "None"
                    }
                
                ssl_socket.close()
                
            except ssl.SSLError as e:
                results["unsupported_ciphers"].append(cipher)
                results["details"][cipher] = {
                    "status": "unsupported",
                    "error": "SSL handshake failed"
                }
            except Exception as e:
                results["unsupported_ciphers"].append(cipher)
                results["details"][cipher] = {
                    "status": "error",
                    "error": str(e)
                }
        
        # Perform cipher analysis
        results["cipher_analysis"] = self._analyze_cipher_security(results)
        results["status"] = "success"
        
        return results
    
    def _analyze_cipher_security(self, cipher_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze cipher suite security.
        
        Args:
            cipher_results: Cipher testing results
            
        Returns:
            Security analysis
        """
        analysis = {
            "issues": [],
            "warnings": [],
            "recommendations": [],
            "overall_rating": "good"
        }
        
        security_summary = cipher_results.get("security_summary", {})
        
        # Check for deprecated ciphers
        if security_summary.get("deprecated", 0) > 0:
            analysis["issues"].append("Deprecated ciphers are supported")
            analysis["overall_rating"] = "poor"
        
        # Check for weak ciphers
        if security_summary.get("weak", 0) > 0:
            analysis["warnings"].append("Weak ciphers are supported")
            if analysis["overall_rating"] != "poor":
                analysis["overall_rating"] = "fair"
        
        # Check for strong ciphers
        if security_summary.get("strong", 0) == 0:
            analysis["issues"].append("No strong ciphers supported")
            analysis["overall_rating"] = "poor"
        
        # Generate recommendations
        if security_summary.get("deprecated", 0) > 0:
            analysis["recommendations"].append("Disable all deprecated ciphers")
        
        if security_summary.get("weak", 0) > 0:
            analysis["recommendations"].append("Consider disabling weak ciphers")
        
        if analysis["overall_rating"] == "good":
            analysis["recommendations"].append("Cipher configuration appears secure")
        
        return analysis
    
    def check_certificate_expiry(self, host: str, port: int = 443) -> Dict[str, Any]:
        """
        Enhanced certificate expiry checking with detailed analysis.
        
        Args:
            host: Target hostname or IP address
            port: Target port (default: 443)
            
        Returns:
            Dictionary containing expiry information
        """
        logger.info("Checking certificate expiry for %s:%s", host, port)
        
        cert_info = self.retrieve_certificate(host, port)
        
        if cert_info.get("status") != "success":
            return {
                "host": host,
                "port": port,
                "status": "error",
                "error": "Failed to retrieve certificate"
            }
        
        try:
            not_after_str = cert_info["certificate_details"]["validity"]["not_after"]
            not_before_str = cert_info["certificate_details"]["validity"]["not_before"]
            
            # Parse dates
            not_after = self._parse_cert_date_to_datetime(not_after_str)
            not_before = self._parse_cert_date_to_datetime(not_before_str)
            current_time = datetime.now(timezone.utc)
            
            if not not_after or not not_before:
                return {
                    "host": host,
                    "port": port,
                    "status": "error",
                    "error": "Could not parse certificate dates"
                }
            
            # Calculate time differences
            days_until_expiry = (not_after - current_time).days
            days_since_issue = (current_time - not_before).days
            total_validity_days = (not_after - not_before).days
            
            # Determine status
            if days_until_expiry < 0:
                status = "expired"
                severity = "critical"
            elif days_until_expiry < 7:
                status = "critical"
                severity = "critical"
            elif days_until_expiry < 30:
                status = "warning"
                severity = "high"
            elif days_until_expiry < 90:
                status = "notice"
                severity = "medium"
            else:
                status = "valid"
                severity = "low"
            
            return {
                "host": host,
                "port": port,
                "status": "success",
                "expiry_status": status,
                "severity": severity,
                "days_until_expiry": days_until_expiry,
                "days_since_issue": days_since_issue,
                "total_validity_days": total_validity_days,
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "current_time": current_time.isoformat(),
                "is_expired": days_until_expiry < 0,
                "is_near_expiry": days_until_expiry < 30
            }
            
        except Exception as e:
            logger.error("Error checking certificate expiry: %s", e)
            return {
                "host": host,
                "port": port,
                "status": "error",
                "error": str(e)
            }
    
    def _parse_cert_date_to_datetime(self, date_str: str) -> Optional[datetime]:
        """
        Parse certificate date string to datetime object.
        
        Args:
            date_str: Certificate date string
            
        Returns:
            datetime object or None
        """
        try:
            # Common certificate date formats
            formats = [
                '%b %d %H:%M:%S %Y %Z',
                '%Y%m%d%H%M%SZ',
                '%Y-%m-%d %H:%M:%S'
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
            
            logger.warning("Could not parse certificate date: %s", date_str)
            return None
        except Exception as e:
            logger.error("Error parsing date %s: %s", date_str, e)
            return None
    
    def run_full_ssl_enum(self, host: str, port: int = 443) -> Dict[str, Any]:
        """
        Perform comprehensive SSL/TLS enumeration with enhanced analysis.
        
        Args:
            host: Target hostname or IP address
            port: Target port (default: 443)
            
        Returns:
            Complete SSL/TLS enumeration results
        """
        logger.info("Starting comprehensive SSL/TLS enumeration for %s:%s", host, port)
        
        start_time = time.time()
        
        results = {
            "host": host,
            "port": port,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "certificate": self.retrieve_certificate(host, port),
            "supported_protocols": self.list_supported_protocols(host, port),
            "supported_ciphers": self.list_supported_ciphers(host, port),
            "certificate_expiry": self.check_certificate_expiry(host, port)
        }
        
        # Overall security assessment
        security_issues = self._assess_overall_security(results)
        results["security_assessment"] = security_issues
        
        results["scan_duration"] = time.time() - start_time
        results["status"] = "completed"
        
        logger.info("SSL/TLS enumeration completed for %s:%s in %.2f seconds", 
                   host, port, results["scan_duration"])
        
        return results
    
    def _assess_overall_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhanced overall SSL/TLS security assessment.
        
        Args:
            results: Full enumeration results
            
        Returns:
            Comprehensive security assessment
        """
        issues = []
        warnings = []
        recommendations = []
        
        # Check certificate expiry
        expiry_info = results.get("certificate_expiry", {})
        if expiry_info.get("is_expired"):
            issues.append("Certificate has expired")
        elif expiry_info.get("is_near_expiry"):
            warnings.append("Certificate expires soon")
        
        # Check certificate security
        cert_analysis = results.get("certificate", {}).get("certificate_details", {}).get("security_analysis", {})
        issues.extend(cert_analysis.get("issues", []))
        warnings.extend(cert_analysis.get("warnings", []))
        
        # Check supported protocols
        protocols = results.get("supported_protocols", {})
        protocol_assessment = protocols.get("security_assessment", {})
        issues.extend(protocol_assessment.get("issues", []))
        warnings.extend(protocol_assessment.get("warnings", []))
        
        # Check cipher security
        ciphers = results.get("supported_ciphers", {})
        cipher_analysis = ciphers.get("cipher_analysis", {})
        issues.extend(cipher_analysis.get("issues", []))
        warnings.extend(cipher_analysis.get("warnings", []))
        
        # Overall rating
        if issues:
            overall_status = "critical"
        elif warnings:
            overall_status = "warning"
        else:
            overall_status = "secure"
        
        # Generate comprehensive recommendations
        if issues:
            recommendations.append("Immediate remediation required for critical issues")
        if warnings:
            recommendations.append("Address warnings for improved security")
        
        # Add specific recommendations from components
        recommendations.extend(cert_analysis.get("recommendations", []))
        recommendations.extend(protocol_assessment.get("recommendations", []))
        recommendations.extend(cipher_analysis.get("recommendations", []))
        
        # Remove duplicates
        recommendations = list(set(recommendations))
        
        return {
            "critical_issues": issues,
            "warnings": warnings,
            "recommendations": recommendations,
            "overall_status": overall_status
        }


def run_module(params_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhanced main module entry point for integration.
    
    Args:
        params_dict: Dictionary containing module parameters:
            - host: Target hostname or IP (required)
            - port: Target port (optional, default: 443)
            - action: Specific action to perform (optional)
            - timeout: Connection timeout (optional)
    
    Returns:
        Dictionary containing enumeration results
    """
    try:
        # Validate required parameters
        if 'host' not in params_dict:
            return {
                "status": "error",
                "error": "Missing required parameter: host"
            }
        
        host = params_dict['host']
        port = params_dict.get('port', 443)
        timeout = params_dict.get('timeout', 10)
        action = params_dict.get('action', 'full_enum')
        
        enumerator = SSLEnumerator(timeout=timeout)
        
        # Execute requested action
        if action == 'certificate':
            return enumerator.retrieve_certificate(host, port)
        elif action == 'protocols':
            return enumerator.list_supported_protocols(host, port)
        elif action == 'ciphers':
            return enumerator.list_supported_ciphers(host, port)
        elif action == 'expiry':
            return enumerator.check_certificate_expiry(host, port)
        elif action == 'full_enum':
            return enumerator.run_full_ssl_enum(host, port)
        else:
            return {
                "status": "error",
                "error": f"Unknown action: {action}"
            }
            
    except Exception as e:
        logger.error("Module execution failed: %s", e)
        return {
            "status": "error",
            "error": str(e)
        }


def handle_ssl_enum(args) -> None:
    """
    Enhanced CLI handler for SSL/TLS enumeration module.
    
    Args:
        args: Command line arguments
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced SSL/TLS Enumeration Tool')
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument('-p', '--port', type=int, default=443, 
                       help='Target port (default: 443)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Connection timeout in seconds (default: 10)')
    parser.add_argument('-a', '--action', 
                       choices=['certificate', 'protocols', 'ciphers', 'expiry', 'full_enum'],
                       default='full_enum', help='Specific action to perform')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args(args)
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Prepare parameters
    params = {
        'host': args.host,
        'port': args.port,
        'timeout': args.timeout,
        'action': args.action
    }
    
    # Execute module
    results = run_module(params)
    
    # Output results
    output_json = json.dumps(results, indent=2, default=str)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_json)
        print(f"Results saved to {args.output}")
    else:
        print(output_json)


if __name__ == "__main__":
    import sys
    handle_ssl_enum(sys.argv[1:])