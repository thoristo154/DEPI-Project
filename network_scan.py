#!/usr/bin/env python3
"""
Enhanced Network Scanner Module

A comprehensive network scanning tool that provides host discovery,
port scanning, service detection, and OS fingerprinting capabilities.
Designed for integration with main orchestration tools.

Author: Cybersecurity Expert
Version: 2.1
"""

import socket
import subprocess
import sys
import json
import threading
import queue
import re
import time
import logging
from typing import Dict, List, Optional, Any, Union
from argparse import Namespace
import ipaddress
import concurrent.futures

# Configure module logging
logger = logging.getLogger('network_scanner')

class NetworkScanner:
    """
    A comprehensive network scanner for host discovery, port scanning,
    service detection, and OS fingerprinting.
    """
    
    # Enhanced common ports for service detection
    COMMON_PORTS = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
        139: 'netbios-ssn', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
        993: 'imaps', 995: 'pop3s', 1723: 'pptp', 3306: 'mysql',
        3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 6379: 'redis',
        27017: 'mongodb', 8080: 'http-proxy', 8443: 'https-alt',
        9200: 'elasticsearch', 9300: 'elasticsearch-cluster'
    }
    
    # Common port ranges for different scan types
    PORT_RANGES = {
        'quick': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                  993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443],
        'common': list(COMMON_PORTS.keys()),
        'web': [80, 443, 8080, 8443, 8000, 8008, 8081, 8088, 8888, 9080, 9090],
        'database': [1433, 1521, 3306, 5432, 27017, 6379, 9200, 9300],
        'windows': [135, 139, 445, 3389, 5985, 5986]
    }

    def __init__(self, timeout: int = 3, max_threads: int = 50):
        """
        Initialize the Network Scanner.
        
        Args:
            timeout: Socket timeout in seconds
            max_threads: Maximum number of concurrent threads
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.results_queue = queue.Queue()
        logger.info("NetworkScanner initialized with timeout=%s, max_threads=%s", 
                   timeout, max_threads)

    def parse_ports(self, ports_input: str) -> List[int]:
        """
        Parse port input string into list of ports.
        Supports ranges (1-100), comma-separated (80,443,8080), and named ranges (common, web, etc.)
        
        Args:
            ports_input: Ports specification string
            
        Returns:
            List of port numbers
        """
        if not ports_input:
            return list(self.COMMON_PORTS.keys())
        
        # Check for named ranges
        if ports_input in self.PORT_RANGES:
            return self.PORT_RANGES[ports_input]
        
        ports = set()
        
        try:
            # Handle comma-separated ports and ranges
            parts = ports_input.split(',')
            for part in parts:
                part = part.strip()
                if '-' in part:
                    # Port range
                    start, end = part.split('-')
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                        ports.update(range(start_port, end_port + 1))
                else:
                    # Single port
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.add(port)
        except ValueError as e:
            logger.warning("Invalid port specification '%s', using common ports. Error: %s", ports_input, e)
            return list(self.COMMON_PORTS.keys())
        
        return sorted(list(ports))

    def resolve_target(self, target: str) -> Dict[str, Any]:
        """
        Enhanced target resolution with comprehensive DNS handling.
        
        Args:
            target: Hostname or IP address to resolve
            
        Returns:
            Dictionary with resolution results
        """
        result = {
            'target': target,
            'ip_addresses': [],
            'hostnames': [],
            'resolution_time': 0,
            'error': None
        }
        
        start_time = time.time()
        
        try:
            # Check if target is an IP address
            if self._is_ip_address(target):
                result['ip_addresses'] = [target]
                
                # Perform reverse DNS lookup
                try:
                    hostname, _, _ = socket.gethostbyaddr(target)
                    result['hostnames'] = [hostname]
                    logger.info("Reverse DNS for %s: %s", target, hostname)
                except (socket.herror, socket.gaierror):
                    result['hostnames'] = []
                    logger.debug("No reverse DNS record for %s", target)
                
            else:
                # Perform forward DNS lookup
                try:
                    # Get all address info
                    addr_info = socket.getaddrinfo(target, None)
                    unique_ips = list(set(addr[4][0] for addr in addr_info))
                    result['ip_addresses'] = unique_ips
                    result['hostnames'] = [target]  # Original hostname
                    logger.info("Resolved %s to IPs: %s", target, unique_ips)
                    
                except socket.gaierror as e:
                    result['error'] = f"DNS resolution failed: {e}"
                    logger.warning("DNS resolution failed for %s: %s", target, e)
            
            result['resolution_time'] = time.time() - start_time
            
        except Exception as e:
            result['error'] = f"Resolution error: {e}"
            logger.error("Error resolving target %s: %s", target, e)
            result['resolution_time'] = time.time() - start_time
        
        return result

    def ping_host(self, target: str, count: int = 4) -> Dict[str, Any]:
        """
        Enhanced ping host with better cross-platform support and parsing.
        
        Args:
            target: Hostname or IP address to ping
            count: Number of ping packets to send
            
        Returns:
            Dictionary with ping results
        """
        result = {
            'target': target,
            'reachable': False,
            'packets_sent': count,
            'packets_received': 0,
            'packet_loss': 100.0,
            'avg_rtt': 0.0,
            'min_rtt': 0.0,
            'max_rtt': 0.0,
            'error': None
        }
        
        try:
            # Determine ping command based on platform
            if sys.platform.startswith('win'):
                # Windows
                cmd = ['ping', '-n', str(count), '-w', str(self.timeout * 1000), target]
            else:
                # Unix/Linux/macOS
                cmd = ['ping', '-c', str(count), '-W', str(self.timeout), target]
            
            logger.info("Pinging %s with command: %s", target, ' '.join(cmd))
            
            output = subprocess.check_output(
                cmd, 
                stderr=subprocess.STDOUT, 
                universal_newlines=True,
                timeout=self.timeout * count + 5
            )
            
            # Parse ping output based on platform
            if sys.platform.startswith('win'):
                self._parse_windows_ping(output, result)
            else:
                self._parse_unix_ping(output, result)
            
            logger.info("Ping results for %s: reachable=%s, packet_loss=%.1f%%, avg_rtt=%.1fms", 
                       target, result['reachable'], result['packet_loss'], result['avg_rtt'])
            
        except subprocess.CalledProcessError as e:
            result['error'] = f"Ping command failed (exit code {e.returncode})"
            logger.warning("Ping failed for %s: %s", target, e)
        except subprocess.TimeoutExpired:
            result['error'] = f"Ping timeout after {self.timeout * count + 5} seconds"
            logger.warning("Ping timeout for %s", target)
        except FileNotFoundError:
            result['error'] = "Ping command not found"
            logger.error("Ping command not available on this system")
        except Exception as e:
            result['error'] = f"Ping error: {e}"
            logger.error("Unexpected ping error for %s: %s", target, e)
        
        return result

    def _parse_windows_ping(self, output: str, result: Dict[str, Any]) -> None:
        """Parse Windows ping output."""
        # Packet loss
        packet_loss_match = re.search(r'Lost = (\d+)', output)
        if packet_loss_match:
            lost = int(packet_loss_match.group(1))
            received = result['packets_sent'] - lost
            result.update({
                'reachable': received > 0,
                'packets_received': received,
                'packet_loss': (lost / result['packets_sent']) * 100
            })
        
        # RTT statistics
        rtt_match = re.search(r'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms', output)
        if rtt_match and result['reachable']:
            min_rtt, max_rtt, avg_rtt = map(int, rtt_match.groups())
            result.update({
                'min_rtt': min_rtt,
                'max_rtt': max_rtt,
                'avg_rtt': avg_rtt
            })

    def _parse_unix_ping(self, output: str, result: Dict[str, Any]) -> None:
        """Parse Unix/Linux ping output."""
        # Statistics line
        stats_match = re.search(
            r'(\d+) packets transmitted, (\d+) received, ([\d.]+)% packet loss',
            output
        )
        if stats_match:
            transmitted, received, loss = stats_match.groups()
            result.update({
                'reachable': int(received) > 0,
                'packets_received': int(received),
                'packet_loss': float(loss)
            })
        
        # RTT statistics
        rtt_match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+', output)
        if rtt_match and result['reachable']:
            result['avg_rtt'] = float(rtt_match.group(1))
        
        # Extended RTT statistics if available
        rtt_extended_match = re.search(
            r'min/avg/max/(?:mdev|stddev) = ([\d.]+)/([\d.]+)/([\d.]+)/[\d.]+', 
            output
        )
        if rtt_extended_match and result['reachable']:
            min_rtt, avg_rtt, max_rtt = map(float, rtt_extended_match.groups())
            result.update({
                'min_rtt': min_rtt,
                'avg_rtt': avg_rtt,
                'max_rtt': max_rtt
            })

    def port_scan(self, target: str, ports: List[int] = None, 
                  scan_type: str = 'tcp', custom_ports: str = None) -> Dict[str, Any]:
        """
        Enhanced port scanning with better performance and error handling.
        
        Args:
            target: Target hostname or IP address
            ports: List of ports to scan
            scan_type: Type of scan ('tcp', 'syn', 'udp')
            custom_ports: Custom port specification string
            
        Returns:
            Dictionary with port scan results
        """
        # Parse custom ports if provided
        if custom_ports:
            ports = self.parse_ports(custom_ports)
        elif ports is None:
            ports = list(self.COMMON_PORTS.keys())
        
        result = {
            'target': target,
            'scan_type': scan_type,
            'ports_scanned': len(ports),
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'scan_duration': 0,
            'start_time': time.time(),
            'error': None
        }
        
        try:
            # Resolve target to IP
            resolution = self.resolve_target(target)
            if resolution['error']:
                result['error'] = resolution['error']
                return result
            
            ip_target = resolution['ip_addresses'][0] if resolution['ip_addresses'] else target
            
            # Use ThreadPoolExecutor for better thread management
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit all port scanning tasks
                future_to_port = {
                    executor.submit(self._check_port, ip_target, port, scan_type): port 
                    for port in ports
                }
                
                # Process completed tasks
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        port_status, service_info = future.result()
                        
                        if port_status == 'open':
                            result['open_ports'].append({
                                'port': port,
                                'protocol': 'tcp' if scan_type != 'udp' else 'udp',
                                'service': service_info
                            })
                        elif port_status == 'closed':
                            result['closed_ports'].append(port)
                        else:  # filtered or error
                            result['filtered_ports'].append(port)
                            
                    except Exception as e:
                        logger.error("Error scanning port %s on %s: %s", port, ip_target, e)
                        result['filtered_ports'].append(port)
            
            # Calculate duration
            result['scan_duration'] = time.time() - result['start_time']
            result['completion_time'] = time.time()
            
            logger.info("Port scan completed for %s: %s open ports found in %.2f seconds", 
                       target, len(result['open_ports']), result['scan_duration'])
            
        except Exception as e:
            result['error'] = f"Port scan error: {e}"
            result['scan_duration'] = time.time() - result['start_time']
            logger.error("Port scan failed for %s: %s", target, e)
        
        return result

    def _check_port(self, target: str, port: int, scan_type: str) -> tuple:
        """
        Check individual port status with service detection.
        
        Args:
            target: Target IP address
            port: Port number to check
            scan_type: Type of scan to perform
            
        Returns:
            Tuple of (port_status, service_info)
        """
        service_info = self.COMMON_PORTS.get(port, 'unknown')
        
        try:
            if scan_type == 'udp':
                status = self._check_udp_port(target, port)
            elif scan_type == 'syn':
                status = self._check_syn_port(target, port)
            else:  # tcp connect scan
                status = self._check_tcp_port(target, port)
                
            return status, service_info
                
        except socket.timeout:
            return 'filtered', service_info
        except ConnectionRefusedError:
            return 'closed', service_info
        except Exception:
            return 'filtered', service_info

    def _check_tcp_port(self, target: str, port: int) -> str:
        """
        Perform TCP connect scan with enhanced error handling.
        
        Args:
            target: Target IP address
            port: Port number to check
            
        Returns:
            Port status
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    # Try to get service banner
                    try:
                        banner = self._grab_banner_simple(sock, port)
                        if banner:
                            logger.debug("Banner from %s:%s: %s", target, port, banner[:100])
                    except:
                        pass
                return 'open' if result == 0 else 'closed'
        except socket.timeout:
            return 'filtered'
        except Exception:
            return 'filtered'

    def _grab_banner_simple(self, sock: socket.socket, port: int) -> str:
        """
        Simple banner grabbing for common services.
        
        Args:
            sock: Connected socket
            port: Port number
            
        Returns:
            Banner string or empty string
        """
        try:
            # Set a short timeout for banner reading
            sock.settimeout(2)
            
            # Try to receive initial data
            banner = sock.recv(1024)
            if banner:
                return banner.decode('utf-8', errors='ignore').strip()
                
        except (socket.timeout, socket.error):
            pass
        except Exception:
            pass
            
        return ""

    def _check_syn_port(self, target: str, port: int) -> str:
        """
        Perform SYN scan (requires raw socket privileges).
        Falls back to TCP connect scan if privileges insufficient.
        
        Args:
            target: Target IP address
            port: Port number to check
            
        Returns:
            Port status
        """
        try:
            # Try to create raw socket (requires privileges)
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
                sock.settimeout(self.timeout)
                # In real implementation, you would craft proper SYN packets
                # For now, fallback to TCP connect
                return self._check_tcp_port(target, port)
        except (OSError, PermissionError):
            logger.warning("Insufficient privileges for SYN scan, falling back to TCP connect")
            return self._check_tcp_port(target, port)
        except Exception:
            return self._check_tcp_port(target, port)

    def _check_udp_port(self, target: str, port: int) -> str:
        """
        Perform basic UDP port scan.
        
        Args:
            target: Target IP address
            port: Port number to check
            
        Returns:
            Port status
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                
                # Send empty UDP packet
                sock.sendto(b'', (target, port))
                
                try:
                    # Try to receive response
                    data, addr = sock.recvfrom(1024)
                    return 'open'
                except socket.timeout:
                    # UDP ports that don't respond might be open or filtered
                    return 'open|filtered'
                    
        except Exception:
            return 'filtered'

    def service_detection(self, target: str, ports: List[int] = None) -> Dict[str, Any]:
        """
        Enhanced service detection with comprehensive banner grabbing.
        
        Args:
            target: Target hostname or IP address
            ports: List of ports to check (default: scan first)
            
        Returns:
            Dictionary with service detection results
        """
        result = {
            'target': target,
            'services': [],
            'detection_duration': 0,
            'start_time': time.time(),
            'error': None
        }
        
        try:
            # If no ports provided, scan for open ports first
            if ports is None:
                scan_result = self.port_scan(target)
                if scan_result['error']:
                    result['error'] = scan_result['error']
                    return result
                ports = [port_info['port'] for port_info in scan_result['open_ports']]
            
            # Detect services on each port with threading
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_port = {
                    executor.submit(self._grab_detailed_banner, target, port): port 
                    for port in ports
                }
                
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        service_info = future.result()
                        if service_info:
                            result['services'].append(service_info)
                    except Exception as e:
                        logger.error("Error detecting service on port %s: %s", port, e)
            
            result['detection_duration'] = time.time() - result['start_time']
            logger.info("Service detection completed for %s: %s services identified", 
                       target, len(result['services']))
            
        except Exception as e:
            result['error'] = f"Service detection error: {e}"
            result['detection_duration'] = time.time() - result['start_time']
            logger.error("Service detection failed for %s: %s", target, e)
        
        return result

    def _grab_detailed_banner(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Enhanced banner grabbing with protocol-specific probes.
        
        Args:
            target: Target hostname or IP address
            port: Port number to check
            
        Returns:
            Service information dictionary or None
        """
        service_info = {
            'port': port,
            'service': self.COMMON_PORTS.get(port, 'unknown'),
            'banner': None,
            'protocol': 'tcp',
            'version': None,
            'response_time': 0
        }
        
        start_time = time.time()
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((target, port))
                
                service_info['response_time'] = time.time() - start_time
                
                # Protocol-specific probes
                if port in [80, 443, 8080, 8443]:  # HTTP/HTTPS
                    probe = b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n"
                    sock.send(probe)
                    response = sock.recv(1024)
                    service_info['banner'] = response.decode('utf-8', errors='ignore').strip()
                    
                elif port == 21:  # FTP
                    banner = sock.recv(1024)
                    service_info['banner'] = banner.decode('utf-8', errors='ignore').strip()
                    
                elif port == 22:  # SSH
                    banner = sock.recv(1024)
                    service_info['banner'] = banner.decode('utf-8', errors='ignore').strip()
                    
                elif port == 25:  # SMTP
                    banner = sock.recv(1024)
                    service_info['banner'] = banner.decode('utf-8', errors='ignore').strip()
                    
                elif port == 53:  # DNS
                    # DNS version query
                    pass
                    
                else:
                    # Generic banner grab
                    try:
                        sock.settimeout(2)
                        banner = sock.recv(1024)
                        if banner:
                            service_info['banner'] = banner.decode('utf-8', errors='ignore').strip()
                    except socket.timeout:
                        pass
                
                # Extract version information from banner
                if service_info['banner']:
                    version_match = re.search(r'(\d+\.\d+\.\d+)', service_info['banner'])
                    if version_match:
                        service_info['version'] = version_match.group(1)
                
                logger.debug("Banner grabbed from %s:%s: %s", target, port, 
                           service_info['banner'][:100] if service_info['banner'] else 'None')
        
        except Exception as e:
            logger.debug("Banner grabbing failed for %s:%s: %s", target, port, e)
            return None
        
        return service_info if service_info['banner'] else None

    def run_full_scan(self, target: str, custom_ports: str = None) -> Dict[str, Any]:
        """
        Perform a comprehensive network scan including all detection methods.
        
        Args:
            target: Target hostname or IP address
            custom_ports: Custom port specification
            
        Returns:
            Comprehensive scan results
        """
        full_result = {
            'target': target,
            'scan_timestamp': time.time(),
            'resolution': {},
            'reachability': {},
            'port_scan': {},
            'services': {},
            'scan_duration': 0,
            'summary': {},
            'start_time': time.time()
        }
        
        logger.info("Starting full network scan for target: %s", target)
        
        try:
            # Step 1: Target resolution
            full_result['resolution'] = self.resolve_target(target)
            if full_result['resolution']['error']:
                full_result['error'] = full_result['resolution']['error']
                return full_result
            
            # Step 2: Host reachability
            full_result['reachability'] = self.ping_host(target)
            
            # Step 3: Port scanning
            full_result['port_scan'] = self.port_scan(target, custom_ports=custom_ports)
            
            # Step 4: Service detection on open ports
            open_ports = [port_info['port'] for port_info in full_result['port_scan']['open_ports']]
            if open_ports:
                full_result['services'] = self.service_detection(target, open_ports)
            
            # Calculate total duration
            full_result['scan_duration'] = time.time() - full_result['start_time']
            
            # Generate comprehensive summary
            # FIX: Safely access 'services' key using .get() to avoid KeyError if no services were detected
            services_identified_count = len(full_result['services'].get('services', []))
            
            full_result['summary'] = {
                'host_reachable': full_result['reachability']['reachable'],
                'open_ports_count': len(full_result['port_scan']['open_ports']),
                'services_identified': services_identified_count,
                'scan_successful': True,
                'total_duration': full_result['scan_duration']
            }
            
            logger.info("Full network scan completed for %s in %.2f seconds", 
                       target, full_result['scan_duration'])
            
        except Exception as e:
            full_result['scan_duration'] = time.time() - full_result['start_time']
            full_result['summary'] = {
                'scan_successful': False,
                'error': str(e)
            }
            full_result['error'] = f"Full scan failed: {e}"
            logger.error("Full network scan failed for %s: %s", target, e)
        
        return full_result

    def _is_ip_address(self, target: str) -> bool:
        """
        Enhanced IP address validation supporting IPv4 and IPv6.
        
        Args:
            target: String to check
            
        Returns:
            True if target is an IP address
        """
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False


def handle_network_scan(args: Namespace) -> str:
    """
    Enhanced network scan handler with better parameter processing.
    
    Args:
        args: argparse.Namespace with scan parameters
        
    Returns:
        JSON string with scan results
    """
    scanner = NetworkScanner(
        timeout=getattr(args, 'timeout', 3),
        max_threads=getattr(args, 'max_threads', 50)
    )
    
    try:
        scan_type = getattr(args, 'scan_type', 'full')
        target = getattr(args, 'target', '')
        custom_ports = getattr(args, 'ports', None)
        
        if not target:
            return json.dumps({'error': 'No target specified'}, indent=2)
        
        if scan_type == 'ping':
            result = scanner.ping_host(target, getattr(args, 'count', 4))
        elif scan_type == 'port':
            ports = None
            if custom_ports:
                ports = scanner.parse_ports(custom_ports)
            result = scanner.port_scan(target, ports, getattr(args, 'scan_method', 'tcp'))
        elif scan_type == 'service':
            ports = None
            if custom_ports:
                ports = scanner.parse_ports(custom_ports)
            result = scanner.service_detection(target, ports)
        else:  # full scan
            result = scanner.run_full_scan(target, custom_ports)
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        error_result = {
            'error': f"Scan failed: {e}",
            'scan_type': getattr(args, 'scan_type', 'unknown'),
            'target': getattr(args, 'target', 'unknown')
        }
        return json.dumps(error_result, indent=2)


def run_module(params_dict: Dict[str, Any]) -> str:
    """
    Enhanced main module entry point for integration.
    
    Args:
        params_dict: Dictionary containing scan parameters:
            - target: required, hostname or IP to scan
            - scan_type: optional, type of scan ('ping', 'port', 'service', 'full')
            - timeout: optional, socket timeout in seconds
            - max_threads: optional, maximum concurrent threads
            - ports: optional, port specification string
            - scan_method: optional, port scan method ('tcp', 'syn', 'udp')
            
    Returns:
        JSON string with scan results
    """
    try:
        # Create scanner with provided parameters
        scanner = NetworkScanner(
            timeout=params_dict.get('timeout', 3),
            max_threads=params_dict.get('max_threads', 50)
        )
        
        target = params_dict['target']
        scan_type = params_dict.get('scan_type', 'full')
        custom_ports = params_dict.get('ports')
        
        # Execute appropriate scan
        if scan_type == 'ping':
            result = scanner.ping_host(target, params_dict.get('count', 4))
        elif scan_type == 'port':
            result = scanner.port_scan(
                target, 
                custom_ports=custom_ports,
                scan_type=params_dict.get('scan_method', 'tcp')
            )
        elif scan_type == 'service':
            result = scanner.service_detection(target, custom_ports=custom_ports)
        else:  # full scan
            result = scanner.run_full_scan(target, custom_ports)
        
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
    
    parser = argparse.ArgumentParser(description='Enhanced Network Scanner Module')
    parser.add_argument('target', help='Target hostname or IP address')
    parser.add_argument('--scan-type', choices=['ping', 'port', 'service', 'full'],
                       default='full', help='Type of scan to perform')
    parser.add_argument('--timeout', type=int, default=3, help='Socket timeout in seconds')
    parser.add_argument('--max-threads', type=int, default=50, help='Maximum concurrent threads')
    parser.add_argument('--ports', help='Port specification (e.g., "80,443,8080" or "1-100" or "common,web")')
    parser.add_argument('--scan-method', choices=['tcp', 'syn', 'udp'], 
                       default='tcp', help='Port scan method')
    parser.add_argument('--count', type=int, default=4, help='Number of ping packets')
    
    args = parser.parse_args()
    
    # Execute scan and print results
    result_json = handle_network_scan(args)
    print(result_json)