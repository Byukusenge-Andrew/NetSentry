#!/usr/bin/env python3

import os
import json
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import socket
import time
from datetime import datetime

class NetworkMapperUI:
    def __init__(self, output_dir, logger=None, port=8080):
        """Initialize the web interface module."""
        # Ensure output_dir is valid
        self.output_dir = output_dir if output_dir else os.getcwd()
        self.logger = logger
        self.port = port
        self.server = None
        self.server_thread = None
        self.scan_in_progress = False
        self.scan_results = {}
        self.scan_command = None
    
    def start_server(self, open_browser=False):
        """Start the web server in a separate thread."""
        if self.server_thread and self.server_thread.is_alive():
            self.logger.info(f"Web server already running on port {self.port}")
            return
        
        # Create a reference to this instance for the handler
        NetworkMapperUIHandler.ui_instance = self
        
        # Find an available port
        while not self._is_port_available(self.port):
            self.port += 1
        
        self.server = HTTPServer(('localhost', self.port), NetworkMapperUIHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        self.logger.info(f"Web interface started at http://localhost:{self.port}")
        
        # Open browser if requested
        if open_browser:
            try:
                webbrowser.open(f"http://localhost:{self.port}")
            except Exception as e:
                self.logger.warning(f"Failed to open browser: {e}")
    
    def stop_server(self):
        """Stop the web server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.logger.info("Web interface stopped")
    
    def _is_port_available(self, port):
        """Check if a port is available."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return True
        except:
            return False
    
    def set_scan_results(self, results):
        """Set the scan results to be displayed in the UI."""
        self.scan_results = results
        self.scan_in_progress = False
    
    def start_scan(self, command):
        """Start a new scan with the given command."""
        self.scan_command = command
        self.scan_in_progress = True
        
        # This would typically start the scan in a separate thread
        # For now, we'll just set a flag
        self.logger.info(f"Starting scan with command: {command}")
        
        # In a real implementation, you would start the scan here
        # and update scan_results when it completes
        
        return True
    
    def get_scan_status(self):
        """Get the current scan status."""
        return {
            "in_progress": self.scan_in_progress,
            "command": self.scan_command,
            "results": self.scan_results
        }
    
    def get_available_scans(self):
        """Get a list of available scan results."""
        scans = []
        try:
            for item in os.listdir(self.output_dir):
                if item.startswith("network_scan_") and os.path.isdir(os.path.join(self.output_dir, item)):
                    scan_time = item.replace("network_scan_", "")
                    try:
                        scan_time = datetime.strptime(scan_time, "%Y%m%d_%H%M%S")
                        scan_time = scan_time.strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        pass
                    
                    # Try to get some basic info about the scan
                    scan_info = {"id": item, "time": scan_time, "hosts": 0}
                    
                    # Check if there's a report.json file
                    report_file = os.path.join(self.output_dir, item, "report.json")
                    if os.path.exists(report_file):
                        try:
                            with open(report_file, 'r') as f:
                                report_data = json.load(f)
                                scan_info["network"] = report_data.get("network_range", "Unknown")
                                scan_info["hosts"] = len(report_data.get("live_hosts", []))
                                scan_info["vulnerable_hosts"] = len(report_data.get("vulnerable_hosts", []))
                        except:
                            pass
                    
                    scans.append(scan_info)
            
            # Sort by time (newest first)
            scans.sort(key=lambda x: x["id"], reverse=True)
        except Exception as e:
            self.logger.error(f"Error getting available scans: {e}")
        
        return scans
    
    def get_scan_details(self, scan_id):
        """Get detailed information about a specific scan."""
        report_file = os.path.join(self.output_dir, scan_id, "report.json")
        if os.path.exists(report_file):
            try:
                with open(report_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Error reading scan report: {e}")
        
        return None


class NetworkMapperUIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Network Mapper UI."""
    ui_instance = None  # Will be set by NetworkMapperUI
    
    def _set_headers(self, content_type='text/html'):
        self.send_response(200)
        self.send_header('Content-type', content_type)
        self.end_headers()
    
    def _serve_static_file(self, filename, content_type):
        try:
            with open(os.path.join(os.path.dirname(__file__), 'web', filename), 'rb') as f:
                self._set_headers(content_type)
                self.wfile.write(f.read())
        except:
            self.send_error(404, f"File not found: {filename}")
    
    def do_GET(self):
        """Handle GET requests."""
        # Parse URL and query parameters
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        
        # API endpoints
        if path == '/api/scans':
            self._set_headers('application/json')
            scans = self.ui_instance.get_available_scans()
            self.wfile.write(json.dumps(scans).encode())
            return
        
        elif path.startswith('/api/scan/'):
            scan_id = path.split('/')[-1]
            self._set_headers('application/json')
            scan_details = self.ui_instance.get_scan_details(scan_id)
            self.wfile.write(json.dumps(scan_details or {}).encode())
            return
        
        elif path == '/api/status':
            self._set_headers('application/json')
            status = self.ui_instance.get_scan_status()
            self.wfile.write(json.dumps(status).encode())
            return
        
        # Static files
        if path == '/' or path == '/index.html':
            self._serve_static_file('index.html', 'text/html')
        elif path.endswith('.css'):
            self._serve_static_file(path[1:], 'text/css')
        elif path.endswith('.js'):
            self._serve_static_file(path[1:], 'application/javascript')
        elif path.endswith('.png'):
            self._serve_static_file(path[1:], 'image/png')
        elif path.endswith('.jpg') or path.endswith('.jpeg'):
            self._serve_static_file(path[1:], 'image/jpeg')
        else:
            self.send_error(404, f"File not found: {path}")
    
    def do_POST(self):
        """Handle POST requests."""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        if self.path == '/api/scan':
            try:
                data = json.loads(post_data)
                success = self.ui_instance.start_scan(data.get('command', ''))
                
                self._set_headers('application/json')
                self.wfile.write(json.dumps({"success": success}).encode())
            except Exception as e:
                self.send_error(400, f"Bad request: {str(e)}")
        else:
            self.send_error(404, f"Endpoint not found: {self.path}")
    
    def log_message(self, format, *args):
        """Override to prevent logging to stderr."""
        if self.ui_instance and self.ui_instance.logger:
            self.ui_instance.logger.debug(f"{self.address_string()} - {format % args}") 