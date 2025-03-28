#!/usr/bin/env python3

import os
import re
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from .utils import run_command

class ServiceFingerprinter:
    def __init__(self, host_data, output_dir, threads=10, logger=None):
        """Initialize the service fingerprinting module."""
        self.host_data = host_data
        self.output_dir = output_dir
        self.threads = threads
        self.logger = logger
        
        # Common service signatures
        self.signatures = {
            'http': {
                'apache': r'Apache[/\s]([0-9.]+)',
                'nginx': r'nginx[/\s]([0-9.]+)',
                'iis': r'Microsoft-IIS[/\s]([0-9.]+)',
                'tomcat': r'Apache Tomcat[/\s]([0-9.]+)'
            },
            'ssh': {
                'openssh': r'OpenSSH[_/\s]([0-9.]+)',
                'dropbear': r'dropbear[_/\s]([0-9.]+)'
            },
            'ftp': {
                'vsftpd': r'vsftpd[/\s]([0-9.]+)',
                'proftpd': r'ProFTPD[/\s]([0-9.]+)',
                'filezilla': r'FileZilla Server[/\s]([0-9.]+)'
            },
            'smb': {
                'samba': r'Samba[/\s]([0-9.]+)',
                'windows': r'Windows[/\s]([0-9.]+)'
            },
            'database': {
                'mysql': r'MySQL[/\s]([0-9.]+)',
                'postgresql': r'PostgreSQL[/\s]([0-9.]+)',
                'mssql': r'Microsoft SQL Server[/\s]([0-9.]+)'
            }
        }
    
    def fingerprint_services(self):
        """Fingerprint services on all hosts."""
        self.logger.info("Starting service fingerprinting...")
        
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.fingerprint_host, host): host 
                      for host in self.host_data}
            
            for future in tqdm(futures, desc="Fingerprinting services", unit="host"):
                try:
                    results.append(future.result())
                except Exception as e:
                    self.logger.error(f"Error fingerprinting services: {e}")
        
        return results
    
    def fingerprint_host(self, host):
        """Fingerprint services on a single host."""
        host_info = self.host_data[host]
        host_dir = os.path.join(self.output_dir, "hosts", host)
        fingerprint_file = os.path.join(host_dir, "service_fingerprints.txt")
        
        with open(fingerprint_file, 'w') as f:
            f.write(f"Service fingerprinting for {host}\n")
            f.write("=" * 50 + "\n\n")
            
            # Store fingerprinted services
            fingerprinted_services = []
            
            for port in host_info["ports"]:
                # HTTP/HTTPS service fingerprinting
                if port in [80, 443, 8080, 8443]:
                    protocol = "https" if port in [443, 8443] else "http"
                    f.write(f"{protocol.upper()} SERVICE (PORT {port}):\n")
                    
                    # Use curl to get headers
                    curl_cmd = [
                        "curl", "-s", "-I", f"{protocol}://{host}:{port}"
                    ]
                    headers_output = run_command(curl_cmd, self.logger)
                    f.write("Headers:\n")
                    f.write(headers_output)
                    f.write("\n")
                    
                    # Use nmap for more detailed fingerprinting
                    nmap_cmd = [
                        "nmap", "-sV", "--script=banner", "-p", str(port), host
                    ]
                    nmap_output = run_command(nmap_cmd, self.logger)
                    f.write("Nmap fingerprinting:\n")
                    f.write(nmap_output)
                    f.write("\n\n")
                    
                    # Extract web server version
                    server_header = re.search(r'Server:\s*([^\r\n]+)', headers_output)
                    if server_header:
                        server = server_header.group(1)
                        f.write(f"Server: {server}\n\n")
                        
                        # Check against known signatures
                        for server_type, pattern in self.signatures['http'].items():
                            match = re.search(pattern, server)
                            if match:
                                version = match.group(1)
                                fingerprint = f"{server_type} {version}"
                                fingerprinted_services.append((port, fingerprint))
                                f.write(f"Identified as: {fingerprint}\n\n")
                                
                                # Add to host data
                                if "fingerprints" not in host_info:
                                    host_info["fingerprints"] = {}
                                host_info["fingerprints"][port] = fingerprint
                                break
                
                # SSH fingerprinting
                elif port == 22:
                    f.write("SSH SERVICE (PORT 22):\n")
                    
                    # Use nmap scripts for SSH fingerprinting
                    nmap_cmd = [
                        "nmap", "-sV", "--script=ssh-auth-methods,ssh2-enum-algos", 
                        "-p", "22", host
                    ]
                    ssh_output = run_command(nmap_cmd, self.logger)
                    f.write(ssh_output)
                    f.write("\n\n")
                    
                    # Extract SSH version
                    ssh_version = re.search(r'SSH-([0-9.]+)-([^\s]+)', ssh_output)
                    if ssh_version:
                        protocol = ssh_version.group(1)
                        software = ssh_version.group(2)
                        fingerprint = f"SSH {protocol} ({software})"
                        fingerprinted_services.append((port, fingerprint))
                        f.write(f"Identified as: {fingerprint}\n\n")
                        
                        # Add to host data
                        if "fingerprints" not in host_info:
                            host_info["fingerprints"] = {}
                        host_info["fingerprints"][port] = fingerprint
                
                # Database fingerprinting
                elif port in [1433, 3306, 5432]:
                    db_type = "MSSQL" if port == 1433 else "MySQL" if port == 3306 else "PostgreSQL"
                    f.write(f"{db_type} SERVICE (PORT {port}):\n")
                    
                    # Use nmap scripts for database fingerprinting
                    script = "ms-sql-info" if port == 1433 else "mysql-info" if port == 3306 else "pgsql-info"
                    nmap_cmd = [
                        "nmap", "-sV", f"--script={script}", 
                        "-p", str(port), host
                    ]
                    db_output = run_command(nmap_cmd, self.logger)
                    f.write(db_output)
                    f.write("\n\n")
                    
                    # Extract version information
                    version_match = re.search(r'Version:\s*([0-9.]+)', db_output)
                    if version_match:
                        version = version_match.group(1)
                        fingerprint = f"{db_type} {version}"
                        fingerprinted_services.append((port, fingerprint))
                        f.write(f"Identified as: {fingerprint}\n\n")
                        
                        # Add to host data
                        if "fingerprints" not in host_info:
                            host_info["fingerprints"] = {}
                        host_info["fingerprints"][port] = fingerprint
            
            # Summary
            f.write("FINGERPRINTING SUMMARY:\n")
            f.write("-" * 30 + "\n")
            for port, fingerprint in fingerprinted_services:
                f.write(f"Port {port}: {fingerprint}\n")
        
        return host, fingerprinted_services
    
    def get_host_data(self):
        """Return the updated host data dictionary."""
        return self.host_data 