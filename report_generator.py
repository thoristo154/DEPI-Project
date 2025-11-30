#!/usr/bin/env python3
"""
Enhanced HTML Report Generator Module

A comprehensive HTML report generator for cybersecurity assessment results.
Creates beautiful, interactive reports with embedded styling and collapsible sections.

Author: Cybersecurity Expert
Version: 2.0
"""

import json
import logging
import base64
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from argparse import Namespace
import os

# Configure module logging
logger = logging.getLogger('report_generator')

class HTMLReportBuilder:
    """
    An enhanced professional HTML report builder for cybersecurity assessment results.
    Creates interactive, styled reports with comprehensive data visualization.
    """
    
    def __init__(self, title: str = "Security Assessment Report"):
        """
        Initialize the enhanced HTML Report Builder.
        
        Args:
            title: Report title
        """
        self.title = title
        self.sections = []
        self.results_data = {}
        self.generated_time = datetime.now()
        logger.info("HTMLReportBuilder initialized with title: %s", title)

    def load_results(self, results_data: Dict[str, Any]) -> bool:
        """
        Enhanced results data loading with validation.
        
        Args:
            results_data: Dictionary containing assessment results
            
        Returns:
            True if data loaded successfully, False otherwise
        """
        try:
            if not isinstance(results_data, dict):
                logger.error("Results data must be a dictionary")
                return False
            
            self.results_data = results_data
            logger.info("Loaded results data with %s top-level keys", len(results_data))
            return True
            
        except Exception as e:
            logger.error("Error loading results data: %s", e)
            return False

    def build_summary_section(self) -> str:
        """
        Build enhanced executive summary section with metrics.
        
        Returns:
            HTML string for the summary section
        """
        try:
            summary_data = self.results_data.get('summary', {})
            scan_info = self.results_data.get('scan_info', {})
            
            # Calculate comprehensive statistics
            total_findings = 0
            risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            module_status = {'success': 0, 'error': 0, 'warning': 0}
            
            # Analyze all modules for findings and status
            for module_name, module_data in self.results_data.items():
                if isinstance(module_data, dict):
                    # Count module status
                    status = module_data.get('status', 'unknown')
                    if status == 'success':
                        module_status['success'] += 1
                    elif status == 'error':
                        module_status['error'] += 1
                    else:
                        module_status['warning'] += 1
                    
                    # Count findings from module summaries
                    module_summary = module_data.get('summary', {})
                    if 'findings_count' in module_summary:
                        total_findings += module_summary['findings_count']
                    
                    # Count risk levels
                    for risk_level in risk_counts.keys():
                        risk_key = f"{risk_level}_findings"
                        if risk_key in module_summary:
                            risk_counts[risk_level] += module_summary[risk_key]
            
            # Build summary HTML
            summary_html = f'''
            <div class="section">
                <h2 class="section-header" onclick="toggleSection('summary')">
                    Executive Summary
                    <span class="toggle-icon">▼</span>
                </h2>
                <div id="summary" class="section-content">
                    <div class="summary-grid">
                        <div class="summary-card critical">
                            <h3>Critical</h3>
                            <div class="count">{risk_counts['critical']}</div>
                            <p>Immediate attention required</p>
                        </div>
                        <div class="summary-card high">
                            <h3>High Risk</h3>
                            <div class="count">{risk_counts['high']}</div>
                            <p>Address as soon as possible</p>
                        </div>
                        <div class="summary-card medium">
                            <h3>Medium Risk</h3>
                            <div class="count">{risk_counts['medium']}</div>
                            <p>Important security issues</p>
                        </div>
                        <div class="summary-card low">
                            <h3>Low Risk</h3>
                            <div class="count">{risk_counts['low']}</div>
                            <p>Minor issues and recommendations</p>
                        </div>
                        <div class="summary-card total">
                            <h3>Total Findings</h3>
                            <div class="count">{total_findings}</div>
                            <p>All security observations</p>
                        </div>
                        <div class="summary-card modules">
                            <h3>Modules</h3>
                            <div class="count">{module_status['success'] + module_status['error'] + module_status['warning']}</div>
                            <p>Assessment components</p>
                        </div>
                    </div>
                    
                    <div class="metrics-grid">
                        <div class="metric-card">
                            <h4>Module Success Rate</h4>
                            <div class="metric-value">{self._calculate_success_rate(module_status)}%</div>
                            <div class="metric-bar">
                                <div class="metric-fill success" style="width: {self._calculate_success_rate(module_status)}%"></div>
                            </div>
                        </div>
                        <div class="metric-card">
                            <h4>Risk Distribution</h4>
                            <div class="risk-chart">
                                <div class="risk-segment critical" style="flex-grow: {risk_counts['critical']}"></div>
                                <div class="risk-segment high" style="flex-grow: {risk_counts['high']}"></div>
                                <div class="risk-segment medium" style="flex-grow: {risk_counts['medium']}"></div>
                                <div class="risk-segment low" style="flex-grow: {risk_counts['low']}"></div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="key-findings">
                        <h3>Key Findings</h3>
                        <ul>
            '''
            
            # Add dynamic key findings based on actual data
            key_findings = self._generate_key_findings()
            for finding in key_findings:
                summary_html += f'<li>{finding}</li>'
            
            # Add scan information
            target = scan_info.get('target', 'Unknown')
            scan_time = scan_info.get('start_time', self.generated_time.isoformat())
            duration = scan_info.get('duration_seconds', 0)
            
            summary_html += f'''
                        </ul>
                    </div>
                    
                    <div class="scan-info">
                        <h3>Scan Information</h3>
                        <div class="info-grid">
                            <div class="info-item">
                                <strong>Target:</strong> {target}
                            </div>
                            <div class="info-item">
                                <strong>Scan Date:</strong> {scan_time}
                            </div>
                            <div class="info-item">
                                <strong>Report Generated:</strong> {self.generated_time.strftime('%Y-%m-%d %H:%M:%S')}
                            </div>
                            <div class="info-item">
                                <strong>Duration:</strong> {duration:.2f} seconds
                            </div>
                            <div class="info-item">
                                <strong>Successful Modules:</strong> {module_status['success']}
                            </div>
                            <div class="info-item">
                                <strong>Failed Modules:</strong> {module_status['error']}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            '''
            
            logger.info("Built summary section with %s total findings", total_findings)
            return summary_html
            
        except Exception as e:
            logger.error("Error building summary section: %s", e)
            return f'<div class="error">Error building summary: {e}</div>'

    def _calculate_success_rate(self, module_status: Dict[str, int]) -> float:
        """
        Calculate module success rate.
        
        Args:
            module_status: Dictionary with module status counts
            
        Returns:
            Success rate percentage
        """
        total = sum(module_status.values())
        if total == 0:
            return 0.0
        return round((module_status['success'] / total) * 100, 1)

    def _generate_key_findings(self) -> List[str]:
        """
        Generate key findings based on scan results.
        
        Returns:
            List of key finding strings
        """
        findings = []
        
        try:
            # Network scan findings
            if 'network' in self.results_data:
                net_data = self.results_data['network']
                if net_data.get('status') == 'success':
                    open_ports = net_data.get('port_scan', {}).get('open_ports', [])
                    if open_ports:
                        findings.append(f"Discovered {len(open_ports)} open ports on target")
                    
                    services = net_data.get('services', {}).get('services', [])
                    if services:
                        findings.append(f"Identified {len(services)} network services")
            
            # DNS findings
            if 'dns' in self.results_data:
                dns_data = self.results_data['dns']
                if dns_data.get('status') == 'success':
                    total_records = dns_data.get('all_records', {}).get('total_records', 0)
                    if total_records > 0:
                        findings.append("DNS records successfully enumerated")
            
            # WHOIS findings
            if 'whois' in self.results_data:
                whois_data = self.results_data['whois']
                if whois_data.get('status') == 'success':
                    findings.append("Domain registration information retrieved")
            
            # Subdomain findings
            if 'subdomain' in self.results_data:
                sub_data = self.results_data['subdomain']
                if sub_data.get('status') == 'success':
                    discovered = sub_data.get('discovered_count', 0)
                    if discovered > 0:
                        findings.append(f"Discovered {discovered} subdomains")
            
            # SSL findings
            if 'ssl' in self.results_data:
                ssl_data = self.results_data['ssl']
                if ssl_data.get('status') == 'success':
                    security = ssl_data.get('security_assessment', {})
                    overall_status = security.get('overall_status', 'unknown')
                    if overall_status != 'secure':
                        findings.append(f"SSL/TLS security assessment: {overall_status}")
            
            # Directory enumeration findings
            if 'directory' in self.results_data:
                dir_data = self.results_data['directory']
                if dir_data.get('status') == 'success':
                    interesting = dir_data.get('enumeration', {}).get('interesting_paths_found', 0)
                    if interesting > 0:
                        findings.append(f"Found {interesting} interesting paths through directory enumeration")
            
            # HTTP fingerprinting findings
            if 'http' in self.results_data:
                http_data = self.results_data['http']
                if http_data.get('status') == 'success':
                    tech_count = http_data.get('technologies', {}).get('technology_count', 0)
                    if tech_count > 0:
                        findings.append(f"Identified {tech_count} web technologies")
                    
                    security_score = http_data.get('security_headers', {}).get('score', 0)
                    if security_score < 80:
                        findings.append(f"Security headers score: {security_score}/100")
            
            # Add general findings if no specific ones were added
            if not findings:
                findings.append("Comprehensive security assessment completed")
                findings.append("Review detailed findings in individual sections")
                
        except Exception as e:
            logger.error("Error generating key findings: %s", e)
            findings.append("Error generating key findings")
        
        return findings

    def build_detailed_section(self, module_name: str, module_data: Dict[str, Any]) -> str:
        """
        Build enhanced detailed section for a specific assessment module.
        
        Args:
            module_name: Name of the assessment module
            module_data: Data from the assessment module
            
        Returns:
            HTML string for the detailed section
        """
        try:
            # Enhanced module configuration
            module_config = {
                'network': {'title': 'Network Scan Results', 'icon': '🌐', 'priority': 1},
                'dns': {'title': 'DNS Enumeration', 'icon': '🔗', 'priority': 2},
                'whois': {'title': 'WHOIS Lookup', 'icon': '📋', 'priority': 3},
                'subdomain': {'title': 'Subdomain Discovery', 'icon': '🌍', 'priority': 4},
                'ssl': {'title': 'SSL/TLS Analysis', 'icon': '🔒', 'priority': 5},
                'http': {'title': 'HTTP Fingerprinting', 'icon': '🛡️', 'priority': 6},
                'directory': {'title': 'Directory Enumeration', 'icon': '📁', 'priority': 7}
            }
            
            config = module_config.get(module_name, {'title': module_name.title(), 'icon': '📄', 'priority': 99})
            
            section_html = f'''
            <div class="section">
                <h2 class="section-header" onclick="toggleSection('{module_name}')">
                    {config['icon']} {config['title']}
                    <span class="toggle-icon">▼</span>
                </h2>
                <div id="{module_name}" class="section-content">
            '''
            
            # Module status badge
            status = module_data.get('status', 'unknown')
            status_class = 'success' if status == 'success' else 'error' if status == 'error' else 'warning'
            section_html += f'<div class="module-status {status_class}">Status: {status}</div>'
            
            # Module-specific content generation
            if module_name == 'network':
                section_html += self._build_network_scan_section(module_data)
            elif module_name == 'dns':
                section_html += self._build_dns_enum_section(module_data)
            elif module_name == 'whois':
                section_html += self._build_whois_section(module_data)
            elif module_name == 'subdomain':
                section_html += self._build_subdomain_section(module_data)
            elif module_name == 'ssl':
                section_html += self._build_ssl_section(module_data)
            elif module_name == 'http':
                section_html += self._build_http_section(module_data)
            elif module_name == 'directory':
                section_html += self._build_directory_section(module_data)
            else:
                section_html += self._build_generic_section(module_data)
            
            section_html += '''
                </div>
            </div>
            '''
            
            logger.info("Built detailed section for module: %s", module_name)
            return section_html
            
        except Exception as e:
            logger.error("Error building detailed section for %s: %s", module_name, e)
            return f'<div class="error">Error building {module_name} section: {e}</div>'

    def _build_network_scan_section(self, data: Dict[str, Any]) -> str:
        """Build enhanced network scan results section."""
        html = '<div class="module-content">'
        
        if data.get('error'):
            html += f'<div class="error-message">Error: {data["error"]}</div>'
            return html + '</div>'
        
        # Host information
        if 'reachability' in data:
            reach = data['reachability']
            status_class = 'success' if reach.get('reachable') else 'error'
            html += f'''
            <div class="status-badge {status_class}">Host {'Reachable' if reach.get('reachable') else 'Unreachable'}</div>
            <div class="info-grid">
                <div class="info-item"><strong>Target:</strong> {data.get('target', 'Unknown')}</div>
                <div class="info-item"><strong>Packets:</strong> {reach.get('packets_received', 0)}/{reach.get('packets_sent', 0)} received</div>
                <div class="info-item"><strong>Response Time:</strong> {reach.get('avg_rtt', 0)}ms</div>
                <div class="info-item"><strong>Packet Loss:</strong> {reach.get('packet_loss', 0)}%</div>
            </div>
            '''
        
        # Port scan results
        if 'port_scan' in data and data['port_scan'].get('open_ports'):
            ports = data['port_scan']['open_ports']
            html += f'''
            <h3>Open Ports ({len(ports)})</h3>
            <div class="ports-grid">
            '''
            for port_info in ports:
                html += f'''
                <div class="port-card">
                    <div class="port-number">{port_info.get("port")}</div>
                    <div class="port-protocol">{port_info.get("protocol", "tcp")}</div>
                    <div class="port-service">{port_info.get("service", "unknown")}</div>
                </div>
                '''
            html += '</div>'
        
        # Service detection
        if 'services' in data and data['services'].get('services'):
            html += f'''
            <h3>Detected Services ({len(data['services']['services'])})</h3>
            <table class="data-table">
                <thead>
                    <tr><th>Port</th><th>Service</th><th>Banner</th><th>Version</th></tr>
                </thead>
                <tbody>
            '''
            for service in data['services']['services']:
                banner = service.get('banner', 'N/A')
                if len(banner) > 100:
                    banner = banner[:100] + '...'
                html += f'''
                <tr>
                    <td>{service.get("port")}</td>
                    <td>{service.get("service")}</td>
                    <td class="banner" title="{service.get('banner', '')}">{banner}</td>
                    <td>{service.get("version", "N/A")}</td>
                </tr>
                '''
            html += '</tbody></table>'
        
        return html + '</div>'

    def _build_dns_enum_section(self, data: Dict[str, Any]) -> str:
        """Build enhanced DNS enumeration section."""
        html = '<div class="module-content">'
        
        if data.get('error'):
            html += f'<div class="error-message">Error: {data["error"]}</div>'
            return html + '</div>'
        
        domain = data.get('domain', 'Unknown')
        html += f'<h3>DNS Records for {domain}</h3>'
        
        if 'all_records' in data and data['all_records'].get('queries'):
            queries = data['all_records']['queries']
            
            for record_type, record_data in queries.items():
                if record_data.get('success') and record_data.get('records'):
                    html += f'''
                    <div class="record-type">
                        <h4>{record_type} Records ({len(record_data['records'])})</h4>
                        <div class="record-list">
                    '''
                    for record in record_data['records']:
                        if isinstance(record, dict):
                            # Handle MX records
                            if 'exchange' in record:
                                html += f'<div class="record-item">{record["preference"]} {record["exchange"]}</div>'
                            else:
                                html += f'<div class="record-item">{record}</div>'
                        else:
                            html += f'<div class="record-item">{record}</div>'
                    html += '</div></div>'
        
        # Subdomain results
        if 'subdomains' in data and data['subdomains'].get('results'):
            subdomain_data = data['subdomains']['results']
            discovered = subdomain_data.get('discovered', [])
            if discovered:
                html += f'''
                <h3>Discovered Subdomains ({len(discovered)})</h3>
                <div class="subdomain-list">
                '''
                for subdomain in discovered[:10]:  # Show first 10
                    html += f'<div class="subdomain-item">{subdomain.get("subdomain", "N/A")}</div>'
                if len(discovered) > 10:
                    html += f'<div class="more-items">... and {len(discovered) - 10} more subdomains</div>'
                html += '</div>'
        
        return html + '</div>'

    def _build_whois_section(self, data: Dict[str, Any]) -> str:
        """Build enhanced WHOIS lookup section."""
        html = '<div class="module-content">'
        
        if data.get('error'):
            html += f'<div class="error-message">Error: {data["error"]}</div>'
            return html + '</div>'
        
        domain = data.get('domain', 'Unknown')
        html += f'<h3>Domain Information: {domain}</h3>'
        
        parsed_data = data.get('parsed_data', {})
        
        if parsed_data:
            html += '<div class="info-grid">'
            important_fields = [
                ('domain_name', 'Domain Name'),
                ('registrar', 'Registrar'),
                ('creation_date', 'Creation Date'),
                ('expiration_date', 'Expiration Date'),
                ('updated_date', 'Updated Date')
            ]
            
            for field, display_name in important_fields:
                if field in parsed_data:
                    value = parsed_data[field]
                    html += f'''
                    <div class="info-item">
                        <strong>{display_name}:</strong> {value}
                    </div>
                    '''
            
            # Name servers
            if 'name_servers' in parsed_data:
                ns_list = ', '.join(parsed_data['name_servers'])
                html += f'''
                <div class="info-item">
                    <strong>Name Servers:</strong> {ns_list}
                </div>
                '''
            
            html += '</div>'
        
        # Domain age information
        if 'domain_age' in data and data['domain_age'].get('domain_age_days'):
            age_data = data['domain_age']
            html += f'''
            <div class="domain-age">
                <h4>Domain Age Analysis</h4>
                <div class="info-grid">
                    <div class="info-item"><strong>Created:</strong> {age_data.get('creation_date', 'Unknown')}</div>
                    <div class="info-item"><strong>Age:</strong> {age_data.get('domain_age_days', 0)} days ({age_data.get('domain_age_years', 0)} years)</div>
                    <div class="info-item"><strong>Category:</strong> {age_data.get('domain_age_category', 'Unknown')}</div>
                </div>
            </div>
            '''
        
        return html + '</div>'

    def _build_subdomain_section(self, data: Dict[str, Any]) -> str:
        """Build enhanced subdomain discovery section."""
        html = '<div class="module-content">'
        
        if data.get('error'):
            html += f'<div class="error-message">Error: {data["error"]}</div>'
            return html + '</div>'
        
        domain = data.get('domain', 'Unknown')
        discovered_count = data.get('discovered_count', 0)
        total_tested = data.get('statistics', {}).get('total_tested', 0)
        
        html += f'''
        <h3>Subdomain Discovery for {domain}</h3>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{discovered_count}</div>
                <div class="stat-label">Discovered</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_tested}</div>
                <div class="stat-label">Tested</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{data.get("success_rate", 0):.1f}%</div>
                <div class="stat-label">Success Rate</div>
            </div>
        </div>
        '''
        
        # Discovered subdomains
        discovered = data.get('discovered_subdomains', [])
        if discovered:
            html += f'''
            <h4>Discovered Subdomains ({len(discovered)})</h4>
            <div class="subdomain-table">
                <table class="data-table">
                    <thead>
                        <tr><th>Subdomain</th><th>IP Address</th><th>Response Time</th></tr>
                    </thead>
                    <tbody>
            '''
            for subdomain in discovered[:20]:  # Show first 20
                primary_ip = subdomain.get('primary_ip', 'N/A')
                response_time = subdomain.get('records', {}).get('A', {}).get('response_time', 0)
                html += f'''
                <tr>
                    <td>{subdomain.get('subdomain', 'N/A')}</td>
                    <td>{primary_ip}</td>
                    <td>{response_time:.3f}s</td>
                </tr>
                '''
            html += '</tbody></table>'
            
            if len(discovered) > 20:
                html += f'<div class="more-items">... and {len(discovered) - 20} more subdomains</div>'
        
        return html + '</div>'

    def _build_ssl_section(self, data: Dict[str, Any]) -> str:
        """Build enhanced SSL/TLS analysis section."""
        html = '<div class="module-content">'
        
        if data.get('error'):
            html += f'<div class="error-message">Error: {data["error"]}</div>'
            return html + '</div>'
        
        host = data.get('host', 'Unknown')
        port = data.get('port', 443)
        
        html += f'<h3>SSL/TLS Analysis for {host}:{port}</h3>'
        
        # Certificate information
        if 'certificate' in data and data['certificate'].get('certificate_details'):
            cert_details = data['certificate']['certificate_details']
            
            html += '''
            <div class="certificate-info">
                <h4>Certificate Details</h4>
                <div class="info-grid">
            '''
            
            # Subject
            subject = cert_details.get('subject', {})
            if 'commonName' in subject:
                html += f'<div class="info-item"><strong>Common Name:</strong> {subject["commonName"]}</div>'
            
            # Issuer
            issuer = cert_details.get('issuer', {})
            if 'organizationName' in issuer:
                html += f'<div class="info-item"><strong>Issuer:</strong> {issuer["organizationName"]}</div>'
            
            # Validity
            validity = cert_details.get('validity', {})
            html += f'''
            <div class="info-item"><strong>Valid From:</strong> {validity.get('not_before', 'Unknown')}</div>
            <div class="info-item"><strong>Valid Until:</strong> {validity.get('not_after', 'Unknown')}</div>
            '''
            
            html += '</div></div>'
        
        # Security assessment
        if 'security_assessment' in data:
            security = data['security_assessment']
            overall_status = security.get('overall_status', 'unknown')
            status_class = 'success' if overall_status == 'secure' else 'warning' if overall_status == 'warning' else 'error'
            
            html += f'''
            <div class="security-assessment {status_class}">
                <h4>Security Assessment: {overall_status.upper()}</h4>
            '''
            
            # Critical issues
            critical_issues = security.get('critical_issues', [])
            if critical_issues:
                html += '<div class="issues-list critical"><strong>Critical Issues:</strong><ul>'
                for issue in critical_issues:
                    html += f'<li>{issue}</li>'
                html += '</ul></div>'
            
            # Warnings
            warnings = security.get('warnings', [])
            if warnings:
                html += '<div class="issues-list warning"><strong>Warnings:</strong><ul>'
                for warning in warnings:
                    html += f'<li>{warning}</li>'
                html += '</ul></div>'
            
            # Recommendations
            recommendations = security.get('recommendations', [])
            if recommendations:
                html += '<div class="recommendations"><strong>Recommendations:</strong><ul>'
                for rec in recommendations:
                    html += f'<li>{rec}</li>'
                html += '</ul></div>'
            
            html += '</div>'
        
        return html + '</div>'

    def _build_http_section(self, data: Dict[str, Any]) -> str:
        """Build enhanced HTTP fingerprinting section."""
        html = '<div class="module-content">'
        
        if data.get('error'):
            html += f'<div class="error-message">Error: {data["error"]}</div>'
            return html + '</div>'
        
        target = data.get('target', 'Unknown')
        html += f'<h3>HTTP Fingerprinting for {target}</h3>'
        
        # Server information
        if 'server_banner' in data:
            banner_data = data['server_banner']
            if banner_data.get('server_banner'):
                html += f'''
                <div class="server-info">
                    <h4>Server Information</h4>
                    <div class="server-banner">{banner_data['server_banner']}</div>
                </div>
                '''
        
        # Technologies
        if 'technologies' in data and data['technologies'].get('technologies'):
            tech_data = data['technologies']['technologies']
            tech_count = data['technologies'].get('technology_count', 0)
            
            html += f'''
            <div class="technologies">
                <h4>Detected Technologies ({tech_count})</h4>
            '''
            
            for category, technologies in tech_data.items():
                html += f'''
                <div class="tech-category">
                    <h5>{category.replace('_', ' ').title()}</h5>
                    <div class="tech-tags">
                '''
                for tech in technologies:
                    html += f'<span class="tech-tag">{tech}</span>'
                html += '</div></div>'
            
            html += '</div>'
        
        # Security headers
        if 'security_headers' in data:
            sec_data = data['security_headers']
            score = sec_data.get('score', 0)
            score_class = 'score-good' if score >= 80 else 'score-fair' if score >= 60 else 'score-poor'
            
            html += f'''
            <div class="security-headers">
                <h4>Security Headers Score: <span class="{score_class}">{score}/100</span></h4>
            '''
            
            for header, info in sec_data.get('security_headers', {}).items():
                status_class = 'header-present' if info.get('present') else 'header-missing'
                compliance_class = 'compliance-full' if info.get('compliance') == 'full' else 'compliance-partial'
                
                html += f'''
                <div class="security-header {status_class} {compliance_class}">
                    <div class="header-name">{header}</div>
                    <div class="header-value">{info.get('value', 'MISSING')}</div>
                    <div class="header-risk">{info.get('risk_level', 'unknown')}</div>
                </div>
                '''
            
            html += '</div>'
        
        return html + '</div>'

    def _build_directory_section(self, data: Dict[str, Any]) -> str:
        """Build enhanced directory enumeration section."""
        html = '<div class="module-content">'
        
        if data.get('error'):
            html += f'<div class="error-message">Error: {data["error"]}</div>'
            return html + '</div>'
        
        enumeration = data.get('enumeration', {})
        target_url = data.get('target_url', 'Unknown')
        
        html += f'''
        <h3>Directory Enumeration for {target_url}</h3>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{enumeration.get('total_paths_tested', 0)}</div>
                <div class="stat-label">Paths Tested</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{enumeration.get('interesting_paths_found', 0)}</div>
                <div class="stat-label">Interesting Paths</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{enumeration.get('scan_duration', 0):.1f}s</div>
                <div class="stat-label">Duration</div>
            </div>
        </div>
        '''
        
        # Findings by classification
        findings_by_class = enumeration.get('findings_by_classification', {})
        if findings_by_class:
            html += '<div class="findings-breakdown"><h4>Findings Breakdown</h4>'
            
            for classification, items in findings_by_class.items():
                html += f'''
                <div class="finding-category">
                    <h5>{classification.replace('_', ' ').title()} ({len(items)})</h5>
                '''
                
                for item in items[:10]:  # Show first 10 items per category
                    status_class = 'status-success' if item.get('status_code', 404) == 200 else 'status-warning'
                    html += f'''
                    <div class="finding-item">
                        <div class="finding-path">
                            <a href="{item.get('url', '#')}" target="_blank">{item.get('path', 'N/A')}</a>
                        </div>
                        <div class="finding-details">
                            <span class="{status_class}">{item.get('status_code')}</span>
                            <span class="finding-size">{item.get('content_length', 0)} bytes</span>
                            <span class="finding-time">{item.get('response_time', 0)}s</span>
                        </div>
                    </div>
                    '''
                
                if len(items) > 10:
                    html += f'<div class="more-items">... and {len(items) - 10} more</div>'
                
                html += '</div>'
            
            html += '</div>'
        
        return html + '</div>'

    def _build_generic_section(self, data: Dict[str, Any]) -> str:
        """Build enhanced generic section for unknown module types."""
        html = '<div class="module-content">'
        
        if isinstance(data, dict):
            # Try to create a structured view
            html += '<div class="generic-data">'
            
            for key, value in data.items():
                if key == 'error':
                    continue
                    
                html += f'<div class="data-item"><strong>{key}:</strong> '
                
                if isinstance(value, (str, int, float, bool)):
                    html += str(value)
                elif isinstance(value, dict):
                    html += '<div class="nested-data">'
                    for k, v in value.items():
                        html += f'<div class="nested-item"><strong>{k}:</strong> {str(v)[:100]}</div>'
                    html += '</div>'
                elif isinstance(value, list):
                    html += f'<div class="list-data">{len(value)} items</div>'
                else:
                    html += str(type(value).__name__)
                
                html += '</div>'
            
            html += '</div>'
        else:
            html += f'<pre>{json.dumps(data, indent=2)}</pre>'
        
        return html + '</div>'

    def embed_styles(self) -> str:
        """
        Generate and embed enhanced CSS styles for the report.
        
        Returns:
            CSS styles as string
        """
        return '''
        <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #34495e;
            --accent-color: #3498db;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --info-color: #95a5a6;
            --text-color: #2c3e50;
                       --light-bg: #ecf0f1;
            --card-bg: #ffffff;
            --border-color: #bdc3c7;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .report-container {
            max-width: 1400px;
            margin: 0 auto;
            background: var(--card-bg);
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            overflow: hidden;
            backdrop-filter: blur(10px);
        }
        
        .report-header {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 40px 30px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        
        .report-header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="1"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
        }
        
        .report-header h1 {
            font-size: 2.8em;
            margin-bottom: 15px;
            font-weight: 300;
            position: relative;
        }
        
        .report-header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 5px;
        }
        
        .section {
            border-bottom: 1px solid var(--border-color);
            transition: all 0.3s ease;
        }
        
        .section-header {
            background: linear-gradient(to right, #f8f9fa, #e9ecef);
            padding: 25px 30px;
            margin: 0;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.3s ease;
            border-left: 5px solid var(--accent-color);
            font-size: 1.3em;
            font-weight: 600;
        }
        
        .section-header:hover {
            background: linear-gradient(to right, #e9ecef, #dee2e6);
            transform: translateX(5px);
        }
        
        .toggle-icon {
            transition: transform 0.3s ease;
            font-size: 0.9em;
        }
        
        .section-content {
            padding: 0;
            max-height: 0;
            overflow: hidden;
            transition: all 0.5s ease;
            background: var(--card-bg);
        }
        
        .section-content.expanded {
            padding: 30px;
            max-height: 10000px;
        }
        
        /* Summary Grid */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .summary-card {
            padding: 25px 20px;
            border-radius: 12px;
            text-align: center;
            color: white;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .summary-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: rgba(255, 255, 255, 0.3);
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
        }
        
        .summary-card.critical { background: linear-gradient(135deg, #e74c3c, #c0392b); }
        .summary-card.high { background: linear-gradient(135deg, #e67e22, #d35400); }
        .summary-card.medium { background: linear-gradient(135deg, #f39c12, #e67e22); }
        .summary-card.low { background: linear-gradient(135deg, #f1c40f, #f39c12); }
        .summary-card.info { background: linear-gradient(135deg, #3498db, #2980b9); }
        .summary-card.total { background: linear-gradient(135deg, #9b59b6, #8e44ad); }
        .summary-card.modules { background: linear-gradient(135deg, #1abc9c, #16a085); }
        
        .summary-card h3 {
            font-size: 1em;
            margin-bottom: 10px;
            opacity: 0.9;
        }
        
        .summary-card .count {
            font-size: 2.5em;
            font-weight: bold;
            margin: 15px 0;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.2);
        }
        
        .summary-card p {
            font-size: 0.9em;
            opacity: 0.9;
            line-height: 1.4;
        }
        
        /* Metrics Grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin: 30px 0;
        }
        
        .metric-card {
            background: var(--card-bg);
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
            border: 1px solid var(--border-color);
        }
        
        .metric-card h4 {
            margin-bottom: 15px;
            color: var(--primary-color);
            font-size: 1.1em;
        }
        
        .metric-value {
            font-size: 2.2em;
            font-weight: bold;
            color: var(--accent-color);
            margin-bottom: 15px;
        }
        
        .metric-bar {
            height: 8px;
            background: #ecf0f1;
            border-radius: 4px;
            overflow: hidden;
        }
        
        .metric-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 1s ease-in-out;
        }
        
        .metric-fill.success { background: linear-gradient(90deg, #27ae60, #2ecc71); }
        .metric-fill.warning { background: linear-gradient(90deg, #f39c12, #f1c40f); }
        .metric-fill.error { background: linear-gradient(90deg, #e74c3c, #c0392b); }
        
        .risk-chart {
            display: flex;
            height: 30px;
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        
        .risk-segment {
            transition: flex-grow 0.5s ease;
        }
        
        .risk-segment.critical { background: #e74c3c; }
        .risk-segment.high { background: #e67e22; }
        .risk-segment.medium { background: #f39c12; }
        .risk-segment.low { background: #f1c40f; }
        
        /* Key Findings */
        .key-findings {
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            padding: 25px;
            border-radius: 12px;
            margin: 25px 0;
            border-left: 5px solid var(--accent-color);
        }
        
        .key-findings h3 {
            margin-bottom: 15px;
            color: var(--primary-color);
        }
        
        .key-findings ul {
            list-style: none;
            padding-left: 0;
        }
        
        .key-findings li {
            padding: 12px 0;
            border-bottom: 1px solid rgba(0, 0, 0, 0.1);
            position: relative;
            padding-left: 25px;
        }
        
        .key-findings li:last-child {
            border-bottom: none;
        }
        
        .key-findings li::before {
            content: '🔍';
            position: absolute;
            left: 0;
            top: 12px;
        }
        
        /* Scan Info */
        .scan-info {
            background: var(--card-bg);
            padding: 25px;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            margin: 25px 0;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .info-item {
            padding: 12px 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid var(--accent-color);
        }
        
        /* Module Status */
        .module-status {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            margin-bottom: 20px;
        }
        
        .module-status.success { background: #d5f4e6; color: #27ae60; border: 1px solid #27ae60; }
        .module-status.error { background: #fdeaea; color: #e74c3c; border: 1px solid #e74c3c; }
        .module-status.warning { background: #fef9e7; color: #f39c12; border: 1px solid #f39c12; }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        
        /* Tables */
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .data-table th {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 15px 12px;
            text-align: left;
            font-weight: 600;
            font-size: 0.9em;
        }
        
        .data-table td {
            padding: 12px;
            border-bottom: 1px solid #ecf0f1;
        }
        
        .data-table tr:hover {
            background: #f8f9fa;
        }
        
        /* Ports and Services */
        .ports-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
            gap: 12px;
            margin: 15px 0;
        }
        
        .port-card {
            background: linear-gradient(135deg, #3498db, #2980b9);
            color: white;
            padding: 15px 10px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.1);
        }
        
        .port-number {
            font-size: 1.4em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .port-protocol, .port-service {
            font-size: 0.8em;
            opacity: 0.9;
        }
        
        /* Technology Tags */
        .tech-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin: 10px 0;
        }
        
        .tech-tag {
            background: linear-gradient(135deg, #9b59b6, #8e44ad);
            color: white;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        
        /* Security Headers */
        .security-headers {
            margin: 25px 0;
        }
        
        .security-header {
            display: grid;
            grid-template-columns: 1fr 2fr auto;
            gap: 15px;
            padding: 15px;
            margin: 8px 0;
            border-radius: 8px;
            align-items: center;
            border-left: 4px solid;
        }
        
        .header-present { 
            background: #d5f4e6; 
            border-left-color: #27ae60;
        }
        
        .header-missing { 
            background: #fdeaea; 
            border-left-color: #e74c3c;
        }
        
        .compliance-full { box-shadow: 0 0 0 2px #27ae60; }
        .compliance-partial { box-shadow: 0 0 0 2px #f39c12; }
        
        .header-name {
            font-weight: bold;
            color: var(--primary-color);
        }
        
        .header-value {
            font-family: monospace;
            font-size: 0.9em;
        }
        
        .header-risk {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        /* Status Badges */
        .status-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            margin: 5px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        
        .status-badge.success { background: #27ae60; color: white; }
        .status-badge.error { background: #e74c3c; color: white; }
        .status-badge.warning { background: #f39c12; color: white; }
        
        /* Score Styles */
        .score-good { color: #27ae60; font-weight: bold; }
        .score-fair { color: #f39c12; font-weight: bold; }
        .score-poor { color: #e74c3c; font-weight: bold; }
        
        /* Status Colors */
        .status-success { color: #27ae60; font-weight: bold; }
        .status-warning { color: #f39c12; font-weight: bold; }
        .status-error { color: #e74c3c; font-weight: bold; }
        
        /* Error Messages */
        .error-message {
            background: #fdeaea;
            color: #e74c3c;
            padding: 20px;
            border-radius: 8px;
            border-left: 5px solid #e74c3c;
            margin: 15px 0;
        }
        
        /* Server Banner */
        .server-banner {
            font-family: 'Courier New', monospace;
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 6px;
            margin: 10px 0;
            border-left: 4px solid #3498db;
        }
        
        /* Certificate Info */
        .certificate-info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
            border: 1px solid #e9ecef;
        }
        
        /* Security Assessment */
        .security-assessment {
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        
        .security-assessment.success { background: #d5f4e6; border-left: 5px solid #27ae60; }
        .security-assessment.warning { background: #fef9e7; border-left: 5px solid #f39c12; }
        .security-assessment.error { background: #fdeaea; border-left: 5px solid #e74c3c; }
        
        .issues-list {
            margin: 15px 0;
            padding: 15px;
            border-radius: 6px;
        }
        
        .issues-list.critical { background: #fdeaea; border-left: 4px solid #e74c3c; }
        .issues-list.warning { background: #fef9e7; border-left: 4px solid #f39c12; }
        
        .recommendations {
            background: #e8f4fd;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #3498db;
            margin: 15px 0;
        }
        
        /* Subdomain List */
        .subdomain-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 10px;
            margin: 15px 0;
        }
        
        .subdomain-item {
            background: #f8f9fa;
            padding: 12px;
            border-radius: 6px;
            border-left: 4px solid #3498db;
            font-family: monospace;
            font-size: 0.9em;
        }
        
        /* More Items Indicator */
        .more-items {
            text-align: center;
            padding: 15px;
            color: #7f8c8d;
            font-style: italic;
            background: #f8f9fa;
            border-radius: 6px;
            margin: 10px 0;
        }
        
        /* Animations */
        @keyframes fadeIn {
            from { 
                opacity: 0; 
                transform: translateY(20px); 
            }
            to { 
                opacity: 1; 
                transform: translateY(0); 
            }
        }
        
        .module-content {
            animation: fadeIn 0.6s ease-in-out;
        }
        
        /* Print Styles */
        @media print {
            body {
                background: white;
                padding: 0;
            }
            
            .report-container {
                box-shadow: none;
                border-radius: 0;
            }
            
            .section-header {
                background: #f8f9fa !important;
                color: black !important;
            }
            
            .summary-card {
                break-inside: avoid;
            }
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            body {
                padding: 10px;
            }
            
            .report-header {
                padding: 25px 15px;
            }
            
            .report-header h1 {
                font-size: 2em;
            }
            
            .summary-grid {
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            }
            
            .metrics-grid {
                grid-template-columns: 1fr;
            }
            
            .section-header {
                padding: 20px 15px;
                font-size: 1.1em;
            }
            
            .section-content.expanded {
                padding: 20px 15px;
            }
            
            .security-header {
                grid-template-columns: 1fr;
                gap: 8px;
            }
            
            .data-table {
                font-size: 0.85em;
            }
            
            .ports-grid {
                grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));
            }
        }
        
        @media (max-width: 480px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .info-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
        </style>
        '''

    def generate_final_report(self, output_file: Optional[str] = None) -> str:
        """
        Generate the complete enhanced HTML report.
        
        Args:
            output_file: Optional path to save the report
            
        Returns:
            HTML report as string
        """
        try:
            # Start building HTML
            html = f'''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>{self.title}</title>
                <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
                {self.embed_styles()}
            </head>
            <body>
                <div class="report-container">
                    <div class="report-header">
                        <h1><i class="fas fa-shield-alt"></i> {self.title}</h1>
                        <div class="subtitle">Professional Security Assessment Report</div>
                        <div class="subtitle">Generated by Recony Security Scanner</div>
                        <div class="subtitle">{self.generated_time.strftime('%B %d, %Y at %H:%M:%S')}</div>
                    </div>
                    
                    <div class="report-body">
            '''
            
            # Add summary section
            html += self.build_summary_section()
            
            # Add detailed sections for each module in priority order
            module_priority = {
                'network': 1, 'dns': 2, 'whois': 3, 'subdomain': 4, 
                'ssl': 5, 'http': 6, 'directory': 7
            }
            
            # Sort modules by priority
            modules_to_process = []
            for module_name, module_data in self.results_data.items():
                if module_name not in ['summary', 'scan_info'] and isinstance(module_data, dict):
                    priority = module_priority.get(module_name, 99)
                    modules_to_process.append((priority, module_name, module_data))
            
            # Sort by priority and add to report
            modules_to_process.sort(key=lambda x: x[0])
            for priority, module_name, module_data in modules_to_process:
                html += self.build_detailed_section(module_name, module_data)
            
            # Add JavaScript for enhanced interactivity
            html += '''
                    </div>
                </div>
                
                <script>
                function toggleSection(sectionId) {
                    const section = document.getElementById(sectionId);
                    const icon = section.previousElementSibling.querySelector('.toggle-icon');
                    
                    if (section.classList.contains('expanded')) {
                        section.classList.remove('expanded');
                        icon.textContent = '▼';
                        icon.style.transform = 'rotate(0deg)';
                    } else {
                        // Close all other sections
                        document.querySelectorAll('.section-content.expanded').forEach(sec => {
                            sec.classList.remove('expanded');
                            const otherIcon = sec.previousElementSibling.querySelector('.toggle-icon');
                            otherIcon.textContent = '▼';
                            otherIcon.style.transform = 'rotate(0deg)';
                        });
                        
                        section.classList.add('expanded');
                        icon.textContent = '▲';
                        icon.style.transform = 'rotate(180deg)';
                        
                        // Smooth scroll to section
                        section.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                    }
                }
                
                // Add click handlers to all section headers
                document.addEventListener('DOMContentLoaded', function() {
                    const sectionHeaders = document.querySelectorAll('.section-header');
                    sectionHeaders.forEach(header => {
                        header.addEventListener('click', function() {
                            const sectionId = this.getAttribute('onclick').match(/'([^']+)'/)[1];
                            toggleSection(sectionId);
                        });
                    });
                    
                    // Expand summary by default
                    setTimeout(() => toggleSection('summary'), 300);
                    
                    // Add animation to metric bars
                    animateMetricBars();
                });
                
                function animateMetricBars() {
                    const metricBars = document.querySelectorAll('.metric-fill');
                    metricBars.forEach(bar => {
                        const width = bar.style.width;
                        bar.style.width = '0%';
                        setTimeout(() => {
                            bar.style.width = width;
                        }, 100);
                    });
                }
                
                // Export functionality
                function exportReport(format) {
                    if (format === 'pdf') {
                        window.print();
                    } else if (format === 'json') {
                        const data = JSON.stringify(window.reportData, null, 2);
                        const blob = new Blob([data], { type: 'application/json' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = 'security-report.json';
                        a.click();
                    }
                }
                
                // Search functionality
                function searchReports() {
                    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
                    const sections = document.querySelectorAll('.section-content');
                    
                    sections.forEach(section => {
                        const content = section.textContent.toLowerCase();
                        if (content.includes(searchTerm)) {
                            section.style.backgroundColor = '#fff3cd';
                            section.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        } else {
                            section.style.backgroundColor = '';
                        }
                    });
                }
                </script>
            </body>
            </html>
            '''
            
            # Save to file if specified
            if output_file:
                try:
                    # Ensure directory exists
                    from pathlib import Path
                    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(html)
                    logger.info("Enhanced report saved to: %s", output_file)
                except Exception as e:
                    logger.error("Error saving enhanced report to file: %s", e)
            
            logger.info("Enhanced HTML report generated successfully")
            return html
            
        except Exception as e:
            logger.error("Error generating enhanced report: %s", e)
            error_html = f"""
            <html>
            <head><title>Error - {self.title}</title></head>
            <body style="font-family: Arial, sans-serif; padding: 20px; color: #e74c3c;">
                <h1>❌ Error Generating Report</h1>
                <p>An error occurred while generating the security assessment report:</p>
                <pre style="background: #fdeaea; padding: 15px; border-radius: 5px; border-left: 4px solid #e74c3c;">{str(e)}</pre>
                <p>Please check the application logs for more details.</p>
            </body>
            </html>
            """
            return error_html


def run_module(params_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhanced module entry point for integration with orchestration tools.
    
    Args:
        params_dict: Dictionary containing report generation parameters:
            - results_data: required, assessment results data
            - title: optional, report title
            - output_file: optional, output file path
            
    Returns:
        Dictionary with generation results
    """
    try:
        # Validate required parameters
        if 'results_data' not in params_dict:
            return {
                "status": "error",
                "error": "Missing required parameter: results_data"
            }
        
        # Create report builder
        title = params_dict.get('title', 'Security Assessment Report')
        builder = HTMLReportBuilder(title=title)
        
        # Load results
        results_data = params_dict['results_data']
        if not builder.load_results(results_data):
            return {
                "status": "error", 
                "error": "Failed to load results data"
            }
        
        # Generate report
        output_file = params_dict.get('output_file')
        html_report = builder.generate_final_report(output_file)
        
        return {
            "status": "success",
            "report_generated": True,
            "output_file": output_file,
            "report_size": len(html_report),
            "message": "Enhanced HTML report generated successfully"
        }
        
    except KeyError as e:
        return {
            "status": "error",
            "error": f"Missing required parameter: {e}"
        }
    except Exception as e:
        logger.error("Enhanced report generation failed: %s", e)
        return {
            "status": "error",
            "error": f"Report generation failed: {str(e)}"
        }


def handle_report_generation(args: Namespace) -> str:
    """
    Enhanced CLI handler for report generation.
    
    Args:
        args: argparse.Namespace with report generation parameters
        
    Returns:
        Success message or error
    """
    try:
        # Load results data
        if not hasattr(args, 'input_file') or not args.input_file:
            return "❌ Error: Input file required"
        
        with open(args.input_file, 'r', encoding='utf-8') as f:
            results_data = json.load(f)
        
        # Create enhanced report builder
        title = getattr(args, 'title', 'Professional Security Assessment Report')
        builder = HTMLReportBuilder(title=title)
        
        # Load results
        if not builder.load_results(results_data):
            return "❌ Error: Failed to load results data"
        
        # Generate enhanced report
        output_file = getattr(args, 'output_file', 'enhanced_security_report.html')
        html_report = builder.generate_final_report(output_file)
        
        return f"✅ Enhanced report generated successfully: {output_file}"
        
    except Exception as e:
        return f"❌ Enhanced report generation failed: {e}"


# Example usage and testing
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Enhanced HTML Report Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python report_generator.py results.json
  python report_generator.py results.json --output custom_report.html
  python report_generator.py results.json --title "Custom Security Report"
        
Generate professional HTML reports from JSON scan results.
        """
    )
    
    parser.add_argument('input_file', help='Input JSON file with assessment results')
    parser.add_argument('--output-file', default='enhanced_security_report.html', 
                       help='Output HTML file path')
    parser.add_argument('--title', default='Professional Security Assessment Report',
                       help='Report title')
    
    args = parser.parse_args()
    
    # Generate enhanced report
    result = handle_report_generation(args)
    print(result)