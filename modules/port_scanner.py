#!/usr/bin/env python3

import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from .utils import run_command

class PortScanner:
    def __init__(self, hosts, output_dir, threads=10, logger=None, use_tcp_scan=False):
        """Initialize the port scanner module."""
        self.hosts = hosts
        self.output_dir = output_dir
        self.threads = threads
        self.logger = logger
        self.host_data = {}
        self.use_tcp_scan = use_tcp_scan
    
    def scan_host(self, host):
        """Scan a single host for open ports and services."""
        host_dir = os.path.join(self.output_dir, "hosts", host)
        os.makedirs(host_dir, exist_ok=True)
        
        # Run comprehensive nmap scan
        nmap_output_file = os.path.join(host_dir, "nmap_scan.xml")
        
        # Use TCP connect scan (-sT) if specified, otherwise use SYN scan (-sS)
        scan_type = "-sT" if self.use_tcp_scan else "-sS"
        
        nmap_cmd = [
            "nmap", scan_type, "-sV", "-sC", "-O", "--version-all",
            "-p-", "--max-retries", "1", "-T4", "--max-scan-delay", "3s",
            "--host-timeout", "10m",
            "-oX", nmap_output_file,
            host
        ]
        
        try:
            run_command(nmap_cmd, self.logger)
            
            # Check if the scan was successful by examining the output file
            if not os.path.exists(nmap_output_file) or os.path.getsize(nmap_output_file) < 100:
                self.logger.warning(f"Scan for {host} may have failed. Trying with reduced options...")
                
                # Try a more basic scan if the full scan failed
                basic_nmap_cmd = [
                    "nmap", "-sT", "-sV", 
                    "-p", "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
                    "-oX", nmap_output_file,
                    host
                ]
                run_command(basic_nmap_cmd, self.logger)
            
            # Parse nmap results
            try:
                # Create a summary file even if the scan failed
                with open(os.path.join(host_dir, "summary.txt"), 'w') as f:
                    f.write(f"IP: {host}\n")
                    f.write(f"Open Ports: \n")
                    f.write(f"Services: \n")
                    f.write(f"OS: Unknown\n")
                
                # Try to extract information from the XML file
                if os.path.exists(nmap_output_file) and os.path.getsize(nmap_output_file) > 100:
                    with open(nmap_output_file, 'r', encoding='utf-8', errors='ignore') as f:
                        nmap_xml = f.read()
                    
                    # Simple parsing of XML to extract basic information
                    ports = []
                    services = []
                    
                    port_pattern = r'<port protocol="[^"]+" portid="(\d+)"><state state="open"[^>]*><service name="([^"]*)" product="([^"]*)"'
                    port_matches = re.findall(port_pattern, nmap_xml)
                    
                    for port, service, product in port_matches:
                        ports.append(int(port))
                        services.append(f"{service} ({product})" if product else service)
                    
                    # Extract OS information
                    os_info = self.extract_os_info(nmap_xml)
                    
                    # Store results
                    self.host_data[host] = {
                        "ip": host,
                        "ports": ports,
                        "services": services,
                        "os": os_info,
                        "vulnerabilities": []
                    }
                    
                    # Update summary file with actual data
                    with open(os.path.join(host_dir, "summary.txt"), 'w') as f:
                        f.write(f"IP: {host}\n")
                        f.write(f"Open Ports: {', '.join(map(str, ports))}\n")
                        f.write(f"Services: {', '.join(services)}\n")
                        f.write(f"OS: {os_info}\n")
                else:
                    # Create empty host data if scan failed
                    self.host_data[host] = {
                        "ip": host,
                        "ports": [],
                        "services": [],
                        "os": "Unknown",
                        "vulnerabilities": []
                    }
                
                return host, self.host_data[host]["ports"], self.host_data[host]["services"]
                
            except Exception as e:
                self.logger.error(f"Error processing nmap results for {host}: {e}")
                # Create empty host data if parsing failed
                self.host_data[host] = {
                    "ip": host,
                    "ports": [],
                    "services": [],
                    "os": "Unknown",
                    "vulnerabilities": []
                }
                return host, [], []
                
        except Exception as e:
            self.logger.error(f"Error scanning host {host}: {e}")
            # Create empty host data if scan failed
            self.host_data[host] = {
                "ip": host,
                "ports": [],
                "services": [],
                "os": "Unknown",
                "vulnerabilities": []
            }
            
            # Create a summary file even if the scan failed
            with open(os.path.join(host_dir, "summary.txt"), 'w') as f:
                f.write(f"IP: {host}\n")
                f.write(f"Open Ports: \n")
                f.write(f"Services: \n")
                f.write(f"OS: Unknown\n")
                f.write(f"Scan Error: {str(e)}\n")
            
            return host, [], []
    
    def extract_os_info(self, nmap_output):
        """Extract OS information from nmap output."""
        os_pattern = r'<osmatch name="([^"]*)" accuracy="([^"]*)"'
        os_matches = re.findall(os_pattern, nmap_output)
        
        if os_matches:
            os_name, accuracy = os_matches[0]
            return f"{os_name} (accuracy: {accuracy}%)"
        return "Unknown"
    
    def scan_ports(self):
        """Scan all discovered hosts for open ports and services."""
        self.logger.info("Scanning ports and services on discovered hosts...")
        
        os.makedirs(os.path.join(self.output_dir, "hosts"), exist_ok=True)
        
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_host, host): host for host in self.hosts}
            
            for future in tqdm(futures, desc="Scanning hosts", unit="host"):
                try:
                    results.append(future.result())
                except Exception as e:
                    self.logger.error(f"Error scanning host: {e}")
        
        return results
    
    def get_host_data(self):
        """Return the host data dictionary."""
        return self.host_data 