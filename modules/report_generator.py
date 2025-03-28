#!/usr/bin/env python3

import os
import json
from datetime import datetime

class ReportGenerator:
    def __init__(self, scan_data, output_dir, logger=None):
        """Initialize the report generator module."""
        self.scan_data = scan_data
        self.output_dir = output_dir
        self.logger = logger
    
    def generate_report(self):
        """Generate HTML and JSON reports from scan data."""
        # Generate JSON report
        json_report = os.path.join(self.output_dir, "report.json")
        with open(json_report, 'w') as f:
            json.dump(self.scan_data, f, indent=4)
        
        # Generate HTML report
        html_report = os.path.join(self.output_dir, "report.html")
        with open(html_report, 'w') as f:
            f.write(self._generate_html())
    
    def _generate_html(self):
        """Generate HTML report content."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .host {{ margin: 20px 0; padding: 10px; border: 1px solid #ccc; }}
                .vulnerable {{ border-color: #ff0000; }}
                .services {{ margin: 10px 0; }}
                .vulnerabilities {{ color: #ff0000; }}
            </style>
        </head>
        <body>
            <h1>Network Scan Report</h1>
            <p>Scan completed: {datetime.fromtimestamp(self.scan_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Network range: {self.scan_data['network_range']}</p>
            <p>Total hosts discovered: {len(self.scan_data['live_hosts'])}</p>
            <p>Vulnerable hosts: {len(self.scan_data['vulnerable_hosts'])}</p>
            
            <h2>Host Details</h2>
        """
        
        # Add host details
        for host, host_info in self.scan_data['hosts'].items():
            is_vulnerable = host in self.scan_data['vulnerable_hosts']
            html += f"""
            <div class="host {'vulnerable' if is_vulnerable else ''}">
                <h3>Host: {host}</h3>
                <p>Operating System: {host_info['os']}</p>
                <div class="services">
                    <h4>Open Ports and Services:</h4>
                    <ul>
            """
            
            for port, service in zip(host_info['ports'], host_info['services']):
                html += f"<li>Port {port}: {service}</li>"
            
            html += "</ul></div>"
            
            if host_info['vulnerabilities']:
                html += f"""
                <div class="vulnerabilities">
                    <h4>Vulnerabilities:</h4>
                    <ul>
                """
                for vuln in host_info['vulnerabilities']:
                    html += f"<li>{vuln}</li>"
                html += "</ul></div>"
            
            html += "</div>"
        
        html += """
        </body>
        </html>
        """
        
        return html 