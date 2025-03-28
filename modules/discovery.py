#!/usr/bin/env python3

import os
import re
from concurrent.futures import ThreadPoolExecutor
from .utils import run_command, validate_network_range

class HostDiscovery:
    def __init__(self, network_range, output_dir, threads=10, logger=None):
        """Initialize the host discovery module."""
        self.network = validate_network_range(network_range)
        self.output_dir = output_dir
        self.threads = threads
        self.logger = logger
        self.live_hosts = []
    
    def discover_hosts(self):
        """Discover live hosts in the network using masscan and nmap."""
        self.logger.info("Starting host discovery...")
        
        # Create discovery directory
        discovery_dir = os.path.join(self.output_dir, "discovery")
        os.makedirs(discovery_dir, exist_ok=True)
        
        # Check if network is a comma-separated list of IPs
        if isinstance(self.network, str) and ',' in self.network:
            # Use the IPs directly
            self.live_hosts = [ip.strip() for ip in self.network.split(',')]
            self.logger.info(f"Using provided IP list: {len(self.live_hosts)} hosts")
            
            # Write live hosts to file
            with open(os.path.join(discovery_dir, "live_hosts.txt"), 'w') as f:
                for host in self.live_hosts:
                    f.write(f"{host}\n")
            
            return self.live_hosts
        
        # Otherwise, perform discovery on network range
        # Use masscan for initial fast discovery
        masscan_output_file = os.path.join(discovery_dir, "masscan_results.txt")
        masscan_cmd = [
            "masscan", str(self.network), 
            "--rate=500",  # Reduce rate to avoid network issues
            "-p", "80,443,22,3389",  # Only check common ports for faster discovery
            "-oL", masscan_output_file
        ]
        
        run_command(masscan_cmd, self.logger)
        
        # Parse masscan results
        live_hosts = set()
        if os.path.exists(masscan_output_file):
            with open(masscan_output_file, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[0] == 'open':
                        live_hosts.add(parts[3])
        
        # Verify with nmap ping scan
        nmap_ping_file = os.path.join(discovery_dir, "nmap_ping_scan.xml")
        nmap_cmd = [
            "nmap", "-sn", "-T4", 
            "-oX", nmap_ping_file,
            str(self.network)
        ]
        
        nmap_output = run_command(nmap_cmd, self.logger)
        
        # Parse nmap results
        try:
            ip_pattern = r'Nmap scan report for (?:[a-zA-Z0-9-]+\s*\()?(\d+\.\d+\.\d+\.\d+)(?:\))?'
            nmap_hosts = re.findall(ip_pattern, nmap_output)
            live_hosts.update(nmap_hosts)
        except Exception as e:
            self.logger.error(f"Error parsing nmap results: {e}")
        
        # Store discovered hosts
        self.live_hosts = sorted(list(live_hosts), key=lambda ip: [int(octet) for octet in ip.split('.')])
        
        # Write live hosts to file
        with open(os.path.join(discovery_dir, "live_hosts.txt"), 'w') as f:
            for host in self.live_hosts:
                f.write(f"{host}\n")
        
        return self.live_hosts 