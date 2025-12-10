#!/usr/bin/env python3
"""
Professional Security Intelligence Report Generator
Clean, fast, and data-focused HTML reports with minimal overhead.
"""

import json
import logging
import math
from datetime import datetime
from typing import Dict, List, Optional, Any
import os
from pathlib import Path

# Configure logging
logger = logging.getLogger('report_generator')

class ProfessionalReportBuilder:
    """
    Professional HTML report builder focused on data analysis and performance.
    Minimal CSS/JS overhead, clean design, fast loading.
    """
    
    def __init__(self, title: str = "Security Assessment Report"):
        self.title = title
        self.results_data = {}
        self.generated_time = datetime.now()
        self.metrics = {}
        logger.info("ProfessionalReportBuilder initialized")
    
    def load_results(self, results_data: Dict[str, Any]) -> bool:
        """
        Load and analyze results data.
        
        Args:
            results_data: Dictionary containing assessment results
            
        Returns:
            True if data loaded successfully
        """
        try:
            self.results_data = results_data
            self._analyze_data()
            logger.info("Results data loaded and analyzed")
            return True
        except Exception as e:
            logger.error("Error loading results: %s", e)
            return False
    
    def _analyze_data(self):
        """Extract and compute key metrics from results."""
        try:
            modules = self.results_data.get('modules', {})
            
            # Calculate basic metrics
            self.metrics = {
                'modules_executed': len(modules),
                'modules_successful': sum(1 for m in modules.values() if m.get('status') == 'success'),
                'modules_failed': sum(1 for m in modules.values() if m.get('status') == 'error'),
                'total_duration': sum(m.get('duration', 0) for m in modules.values()),
                'start_time': self.results_data.get('scan_info', {}).get('start_time', 'Unknown'),
                'target': self.results_data.get('scan_info', {}).get('target', 'Unknown'),
                'scan_type': self.results_data.get('scan_info', {}).get('type', 'Unknown')
            }
            
            # Network specific metrics
            network_data = modules.get('network', {})
            if network_data and network_data.get('status') == 'success':
                open_ports = network_data.get('port_scan', {}).get('open_ports', [])
                self.metrics['open_ports'] = len(open_ports)
                self.metrics['port_services'] = list(set(p.get('service', 'unknown') for p in open_ports))
            
            # DNS metrics
            dns_data = modules.get('dns', {})
            if dns_data and dns_data.get('status') == 'success':
                records = dns_data.get('all_records', {}).get('queries', {})
                self.metrics['dns_records'] = sum(len(r.get('records', [])) for r in records.values() if r.get('success'))
            
            # Subdomain metrics
            subdomain_data = modules.get('subdomain', {})
            if subdomain_data and subdomain_data.get('status') == 'success':
                self.metrics['subdomains_found'] = len(subdomain_data.get('discovered_subdomains', []))
            
            # Security metrics
            ssl_data = modules.get('ssl', {})
            if ssl_data and ssl_data.get('status') == 'success':
                assessment = ssl_data.get('security_assessment', {})
                self.metrics['ssl_rating'] = assessment.get('rating', 'Unknown')
                self.metrics['ssl_issues'] = len(assessment.get('issues', []))
            
            http_data = modules.get('http', {})
            if http_data and http_data.get('status') == 'success':
                headers = http_data.get('security_headers', {})
                self.metrics['security_score'] = headers.get('score', 0)
            
            # Directory metrics
            dir_data = modules.get('directory', {})
            if dir_data and dir_data.get('status') == 'success':
                enum = dir_data.get('enumeration', {})
                self.metrics['paths_found'] = enum.get('interesting_paths_found', 0)
                self.metrics['paths_tested'] = enum.get('total_paths_tested', 0)
            
            # Risk assessment
            self._assess_risks()
            
        except Exception as e:
            logger.error("Error analyzing data: %s", e)
    
    def _assess_risks(self):
        """Assess security risks based on findings."""
        risks = []
        
        # Check for critical ports
        if 'open_ports' in self.metrics and self.metrics['open_ports'] > 20:
            risks.append({"level": "warning", "message": "High number of open ports increases attack surface"})
        
        critical_ports = {21, 23, 25, 110, 135, 139, 445, 1433, 3389, 5900}
        network_data = self.results_data.get('modules', {}).get('network', {})
        if network_data and network_data.get('status') == 'success':
            open_ports = network_data.get('port_scan', {}).get('open_ports', [])
            for port_info in open_ports:
                port = port_info.get('port')
                if port in critical_ports:
                    risks.append({"level": "high", "message": f"Critical port {port} open ({port_info.get('service', 'unknown')})"})
        
        # SSL issues
        if self.metrics.get('ssl_rating') in ['Poor', 'Critical']:
            risks.append({"level": "high", "message": "SSL/TLS security issues detected"})
        
        # Low security headers score
        if self.metrics.get('security_score', 100) < 70:
            risks.append({"level": "medium", "message": "Low HTTP security headers score"})
        
        self.metrics['risks'] = risks
    
    def generate_report(self, output_file: Optional[str] = None) -> str:
        """
        Generate professional HTML report.
        
        Args:
            output_file: Optional path to save the report
            
        Returns:
            HTML report as string
        """
        try:
            html = self._build_html()
            
            if output_file:
                Path(output_file).parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(html)
                logger.info("Report saved to: %s", output_file)
            
            return html
            
        except Exception as e:
            logger.error("Error generating report: %s", e)
            return f"<html><body><h1>Error generating report: {e}</h1></body></html>"
    
    def _build_html(self) -> str:
        """Build complete HTML report."""
        return f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.title}</title>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    <div class="container">
        {self._build_header()}
        {self._build_executive_summary()}
        {self._build_metrics_overview()}
        {self._build_risk_assessment()}
        {self._build_module_details()}
        {self._build_findings_details()}
        {self._build_footer()}
    </div>
    <script>
        {self._get_js()}
    </script>
</body>
</html>
'''
    
    def _get_css(self) -> str:
        """Return minimal, clean CSS."""
        return '''
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f8f9fa;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: white;
            padding: 40px 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }
        
        .header .subtitle {
            opacity: 0.9;
            margin-bottom: 5px;
        }
        
        .section {
            padding: 30px;
            border-bottom: 1px solid #eaeaea;
        }
        
        .section:last-child {
            border-bottom: none;
        }
        
        .section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #3498db;
            font-weight: 500;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .metric-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
            text-align: center;
            border-left: 4px solid #3498db;
            transition: transform 0.2s;
        }
        
        .metric-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
        }
        
        .metric-label {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        
        .risk-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .risk-item {
            padding: 15px;
            border-radius: 6px;
            background: #f8f9fa;
            border-left: 4px solid;
        }
        
        .risk-high { border-left-color: #e74c3c; }
        .risk-medium { border-left-color: #f39c12; }
        .risk-warning { border-left-color: #f1c40f; }
        .risk-low { border-left-color: #2ecc71; }
        
        .risk-level {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .level-high { background: #e74c3c; color: white; }
        .level-medium { background: #f39c12; color: white; }
        .level-warning { background: #f1c40f; color: #333; }
        .level-low { background: #2ecc71; color: white; }
        
        .module-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .module-table th {
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #2c3e50;
            border-bottom: 2px solid #eaeaea;
        }
        
        .module-table td {
            padding: 12px;
            border-bottom: 1px solid #eaeaea;
        }
        
        .module-table tr:hover {
            background: #f8f9fa;
        }
        
        .status-success { color: #27ae60; }
        .status-error { color: #e74c3c; }
        .status-warning { color: #f39c12; }
        
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
        }
        
        .badge-success { background: #d5f4e6; color: #27ae60; }
        .badge-error { background: #fdeaea; color: #e74c3c; }
        .badge-warning { background: #fef9e7; color: #f39c12; }
        
        .findings-list {
            margin-top: 20px;
        }
        
        .finding-item {
            padding: 15px;
            background: #f8f9fa;
            border-radius: 6px;
            margin-bottom: 10px;
            border-left: 4px solid #3498db;
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .finding-title {
            font-weight: 600;
            color: #2c3e50;
        }
        
        .footer {
            padding: 20px 30px;
            background: #f8f9fa;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
            border-top: 1px solid #eaeaea;
        }
        
        .footer a {
            color: #3498db;
            text-decoration: none;
        }
        
        .footer a:hover {
            text-decoration: underline;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            font-size: 0.9em;
        }
        
        .data-table th {
            background: #f8f9fa;
            padding: 10px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #eaeaea;
        }
        
        .data-table td {
            padding: 10px;
            border-bottom: 1px solid #eaeaea;
        }
        
        .expandable {
            cursor: pointer;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 6px;
            margin: 5px 0;
            border-left: 4px solid #3498db;
        }
        
        .expandable-content {
            display: none;
            padding: 15px;
            background: white;
            border: 1px solid #eaeaea;
            border-radius: 6px;
            margin-top: 10px;
        }
        
        .expandable.active .expandable-content {
            display: block;
        }
        
        .port-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
            gap: 10px;
            margin: 10px 0;
        }
        
        .port-item {
            padding: 10px;
            background: #f8f9fa;
            border-radius: 4px;
            text-align: center;
            font-family: monospace;
        }
        
        @media (max-width: 768px) {
            .container {
                border-radius: 0;
                box-shadow: none;
            }
            
            .header {
                padding: 20px 15px;
            }
            
            .header h1 {
                font-size: 1.8em;
            }
            
            .section {
                padding: 20px 15px;
            }
            
            .metrics-grid {
                grid-template-columns: 1fr;
            }
            
            .risk-grid {
                grid-template-columns: 1fr;
            }
            
            .module-table {
                font-size: 0.85em;
            }
            
            .data-table {
                font-size: 0.8em;
            }
        }
        '''
    
    def _build_header(self) -> str:
        """Build report header."""
        return f'''
        <div class="header">
            <h1>{self.title}</h1>
            <div class="subtitle">Professional Security Assessment Report</div>
            <div class="subtitle">Generated: {self.generated_time.strftime('%Y-%m-%d %H:%M:%S')}</div>
            <div class="subtitle">Target: {self.metrics.get('target', 'Unknown')}</div>
        </div>
        '''
    
    def _build_executive_summary(self) -> str:
        """Build executive summary section."""
        return '''
        <div class="section">
            <h2>Executive Summary</h2>
            <p>This report presents the findings from a comprehensive security assessment. 
            The scan included multiple reconnaissance modules to identify potential security 
            vulnerabilities and misconfigurations.</p>
            
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-value">{modules_executed}</div>
                    <div class="metric-label">Modules Executed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{modules_successful}</div>
                    <div class="metric-label">Successful Modules</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{total_duration:.1f}s</div>
                    <div class="metric-label">Total Duration</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{scan_type}</div>
                    <div class="metric-label">Scan Type</div>
                </div>
            </div>
        </div>
        '''.format(
            modules_executed=self.metrics.get('modules_executed', 0),
            modules_successful=self.metrics.get('modules_successful', 0),
            total_duration=self.metrics.get('total_duration', 0),
            scan_type=self.metrics.get('scan_type', 'Unknown')
        )
    
    def _build_metrics_overview(self) -> str:
        """Build metrics overview section."""
        html = '''
        <div class="section">
            <h2>Key Metrics</h2>
            <div class="metrics-grid">
        '''
        
        # Network metrics
        if 'open_ports' in self.metrics:
            html += f'''
            <div class="metric-card">
                <div class="metric-value">{self.metrics['open_ports']}</div>
                <div class="metric-label">Open Ports</div>
            </div>
            '''
        
        # DNS metrics
        if 'dns_records' in self.metrics:
            html += f'''
            <div class="metric-card">
                <div class="metric-value">{self.metrics['dns_records']}</div>
                <div class="metric-label">DNS Records</div>
            </div>
            '''
        
        # Subdomain metrics
        if 'subdomains_found' in self.metrics:
            html += f'''
            <div class="metric-card">
                <div class="metric-value">{self.metrics['subdomains_found']}</div>
                <div class="metric-label">Subdomains Found</div>
            </div>
            '''
        
        # Security metrics
        if 'security_score' in self.metrics:
            score = self.metrics['security_score']
            html += f'''
            <div class="metric-card">
                <div class="metric-value">{score}/100</div>
                <div class="metric-label">Security Score</div>
            </div>
            '''
        
        # Directory metrics
        if 'paths_found' in self.metrics:
            html += f'''
            <div class="metric-card">
                <div class="metric-value">{self.metrics['paths_found']}</div>
                <div class="metric-label">Interesting Paths</div>
            </div>
            '''
        
        html += '''
            </div>
        </div>
        '''
        
        return html
    
    def _build_risk_assessment(self) -> str:
        """Build risk assessment section."""
        risks = self.metrics.get('risks', [])
        
        if not risks:
            return '''
            <div class="section">
                <h2>Risk Assessment</h2>
                <p>No significant security risks identified during this assessment.</p>
                <p><em>Note: This does not guarantee the absence of vulnerabilities. 
                Regular security assessments are recommended.</em></p>
            </div>
            '''
        
        html = '''
        <div class="section">
            <h2>Risk Assessment</h2>
            <p>The following security risks were identified during the assessment:</p>
            <div class="risk-grid">
        '''
        
        for risk in risks:
            level = risk.get('level', 'warning')
            html += f'''
            <div class="risk-item risk-{level}">
                <div class="risk-level level-{level}">{level.upper()}</div>
                <div>{risk['message']}</div>
            </div>
            '''
        
        html += '''
            </div>
        </div>
        '''
        
        return html
    
    def _build_module_details(self) -> str:
        """Build module execution details section."""
        modules = self.results_data.get('modules', {})
        
        if not modules:
            return '''
            <div class="section">
                <h2>Module Execution Details</h2>
                <p>No module execution data available.</p>
            </div>
            '''
        
        html = '''
        <div class="section">
            <h2>Module Execution Details</h2>
            <table class="module-table">
                <thead>
                    <tr>
                        <th>Module</th>
                        <th>Status</th>
                        <th>Duration</th>
                        <th>Findings</th>
                    </tr>
                </thead>
                <tbody>
        '''
        
        for name, data in modules.items():
            status = data.get('status', 'unknown')
            duration = data.get('duration', 0)
            
            # Count findings
            findings = 0
            if name == 'network':
                findings = len(data.get('port_scan', {}).get('open_ports', []))
            elif name == 'dns':
                queries = data.get('all_records', {}).get('queries', {})
                findings = sum(len(r.get('records', [])) for r in queries.values() if r.get('success'))
            elif name == 'subdomain':
                findings = len(data.get('discovered_subdomains', []))
            elif name == 'directory':
                findings = data.get('enumeration', {}).get('interesting_paths_found', 0)
            
            html += f'''
            <tr>
                <td><strong>{name.title()}</strong></td>
                <td><span class="status-{status}">{status}</span></td>
                <td>{duration:.2f}s</td>
                <td>{findings}</td>
            </tr>
            '''
        
        html += '''
                </tbody>
            </table>
        </div>
        '''
        
        return html
    
    def _build_findings_details(self) -> str:
        """Build detailed findings section."""
        html = '''
        <div class="section">
            <h2>Detailed Findings</h2>
        '''
        
        modules = self.results_data.get('modules', {})
        
        # Network findings
        network_data = modules.get('network', {})
        if network_data and network_data.get('status') == 'success':
            open_ports = network_data.get('port_scan', {}).get('open_ports', [])
            if open_ports:
                html += '''
                <div class="expandable" onclick="toggleExpand(this)">
                    <strong>Network Scan - Open Ports</strong>
                </div>
                <div class="expandable-content">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Service</th>
                                <th>Protocol</th>
                                <th>State</th>
                            </tr>
                        </thead>
                        <tbody>
                '''
                
                for port in open_ports:
                    html += f'''
                    <tr>
                        <td>{port.get('port')}</td>
                        <td>{port.get('service', 'unknown')}</td>
                        <td>{port.get('protocol', 'tcp')}</td>
                        <td>Open</td>
                    </tr>
                    '''
                
                html += '''
                        </tbody>
                    </table>
                </div>
                '''
        
        # DNS findings
        dns_data = modules.get('dns', {})
        if dns_data and dns_data.get('status') == 'success':
            records = dns_data.get('all_records', {}).get('queries', {})
            if records:
                html += '''
                <div class="expandable" onclick="toggleExpand(this)">
                    <strong>DNS Records</strong>
                </div>
                <div class="expandable-content">
                '''
                
                for record_type, record_data in records.items():
                    if record_data.get('success') and record_data.get('records'):
                        html += f'''
                        <div style="margin-bottom: 15px;">
                            <strong>{record_type} Records:</strong>
                            <div style="margin-left: 20px; font-family: monospace; font-size: 0.9em;">
                        '''
                        for record in record_data['records'][:10]:  # Limit to 10
                            if isinstance(record, dict):
                                if 'exchange' in record:
                                    html += f'{record["preference"]} {record["exchange"]}<br>'
                                else:
                                    html += f'{str(record)}<br>'
                            else:
                                html += f'{record}<br>'
                        html += '''
                            </div>
                        </div>
                        '''
                
                html += '</div>'
        
        # Subdomain findings
        subdomain_data = modules.get('subdomain', {})
        if subdomain_data and subdomain_data.get('status') == 'success':
            subdomains = subdomain_data.get('discovered_subdomains', [])
            if subdomains:
                html += '''
                <div class="expandable" onclick="toggleExpand(this)">
                    <strong>Discovered Subdomains</strong>
                </div>
                <div class="expandable-content">
                    <div style="font-family: monospace; font-size: 0.9em; column-count: 2; column-gap: 30px;">
                '''
                
                for sub in subdomains[:30]:  # Limit to 30
                    subdomain = sub.get('subdomain', 'N/A')
                    ip = sub.get('primary_ip', 'N/A')
                    html += f'{subdomain}<br><small style="color: #666;">{ip}</small><br>'
                
                html += '''
                    </div>
                </div>
                '''
        
        # SSL findings
        ssl_data = modules.get('ssl', {})
        if ssl_data and ssl_data.get('status') == 'success':
            assessment = ssl_data.get('security_assessment', {})
            rating = assessment.get('rating', 'Unknown')
            issues = assessment.get('issues', [])
            
            html += f'''
            <div class="expandable" onclick="toggleExpand(this)">
                <strong>SSL/TLS Assessment: {rating}</strong>
            </div>
            <div class="expandable-content">
            '''
            
            if issues:
                html += '<ul style="margin-left: 20px;">'
                for issue in issues:
                    html += f'<li>{issue}</li>'
                html += '</ul>'
            else:
                html += '<p>No security issues detected.</p>'
            
            html += '</div>'
        
        # HTTP findings
        http_data = modules.get('http', {})
        if http_data and http_data.get('status') == 'success':
            techs = http_data.get('technologies', {}).get('technologies', {})
            if techs:
                html += '''
                <div class="expandable" onclick="toggleExpand(this)">
                    <strong>Detected Technologies</strong>
                </div>
                <div class="expandable-content">
                '''
                
                for category, technologies in techs.items():
                    html += f'''
                    <div style="margin-bottom: 10px;">
                        <strong>{category.replace('_', ' ').title()}:</strong><br>
                        <div style="margin-left: 20px;">
                    '''
                    for tech in technologies[:10]:  # Limit to 10 per category
                        html += f'• {tech}<br>'
                    html += '''
                        </div>
                    </div>
                    '''
                
                html += '</div>'
        
        html += '''
        </div>
        '''
        
        return html
    
    def _build_footer(self) -> str:
        """Build report footer."""
        return f'''
        <div class="footer">
            <p>Report generated by Recony Security Assessment Framework</p>
            <p>Timestamp: {self.generated_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>This report is for authorized security assessment purposes only.</p>
        </div>
        '''
    
    def _get_js(self) -> str:
        """Return minimal JavaScript."""
        return '''
        function toggleExpand(element) {
            element.classList.toggle('active');
        }
        
        // Auto-expand first few sections
        document.addEventListener('DOMContentLoaded', function() {
            // Auto-expand executive summary
            var sections = document.querySelectorAll('.section');
            if (sections.length > 0) {
                // You can add auto-expand logic here if needed
            }
            
            // Add smooth scrolling for anchor links
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function (e) {
                    e.preventDefault();
                    const target = document.querySelector(this.getAttribute('href'));
                    if (target) {
                        target.scrollIntoView({ behavior: 'smooth' });
                    }
                });
            });
        });
        
        // Print functionality
        function printReport() {
            window.print();
        }
        
        // Export as JSON
        function exportJSON() {
            var data = ''' + json.dumps(self.results_data, indent=2) + ''';
            var blob = new Blob([data], {type: 'application/json'});
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'security-assessment-' + new Date().toISOString().split('T')[0] + '.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
        '''
    
    def generate_final_report(self, output_file: Optional[str] = None) -> str:
        """
        Generate the complete HTML report (compatibility method).
        
        Args:
            output_file: Optional path to save the report
            
        Returns:
            HTML report as string
        """
        return self.generate_report(output_file)


def run_module(params_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Module entry point for integration.
    
    Args:
        params_dict: Dictionary containing report generation parameters:
            - results_data: required, assessment results data
            - title: optional, report title
            - output_file: optional, output file path
            
    Returns:
        Dictionary with generation results
    """
    try:
        if 'results_data' not in params_dict:
            return {
                "status": "error",
                "error": "Missing required parameter: results_data"
            }
        
        title = params_dict.get('title', 'Security Assessment Report')
        builder = ProfessionalReportBuilder(title=title)
        
        if not builder.load_results(params_dict['results_data']):
            return {
                "status": "error", 
                "error": "Failed to load results data"
            }
        
        output_file = params_dict.get('output_file')
        html_report = builder.generate_report(output_file)
        
        return {
            "status": "success",
            "report_generated": True,
            "output_file": output_file,
            "report_size": len(html_report),
            "message": "Professional HTML report generated successfully"
        }
        
    except KeyError as e:
        return {
            "status": "error",
            "error": f"Missing required parameter: {e}"
        }
    except Exception as e:
        logger.error("Report generation failed: %s", e)
        return {
            "status": "error",
            "error": f"Report generation failed: {str(e)}"
        }


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Professional HTML Report Generator')
    parser.add_argument('input_file', help='Input JSON file with assessment results')
    parser.add_argument('--output-file', default='professional_report.html', 
                       help='Output HTML file path')
    parser.add_argument('--title', default='Security Assessment Report',
                       help='Report title')
    
    args = parser.parse_args()
    
    try:
        with open(args.input_file, 'r', encoding='utf-8') as f:
            results_data = json.load(f)
        
        builder = ProfessionalReportBuilder(title=args.title)
        builder.load_results(results_data)
        builder.generate_report(args.output_file)
        print(f"✅ Report generated: {args.output_file}")
        
    except Exception as e:
        print(f"❌ Error: {e}")