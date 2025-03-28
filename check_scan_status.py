#!/usr/bin/env python3

import os
import sys
import glob
import time

def check_scan_status(scan_dir):
    """Check the status of a network scan."""
    if not os.path.exists(scan_dir):
        print(f"Scan directory not found: {scan_dir}")
        return
    
    # Check discovery results
    discovery_dir = os.path.join(scan_dir, "discovery")
    live_hosts_file = os.path.join(discovery_dir, "live_hosts.txt")
    
    if os.path.exists(live_hosts_file):
        with open(live_hosts_file, 'r') as f:
            hosts = [line.strip() for line in f if line.strip()]
        print(f"Discovered hosts: {len(hosts)}")
    else:
        print("Host discovery not completed yet")
        return
    
    # Check host scan progress
    hosts_dir = os.path.join(scan_dir, "hosts")
    if os.path.exists(hosts_dir):
        scanned_hosts = glob.glob(os.path.join(hosts_dir, "*"))
        scanned_hosts = [os.path.basename(h) for h in scanned_hosts if os.path.isdir(h)]
        
        print(f"Scanned hosts: {len(scanned_hosts)} / {len(hosts)} ({len(scanned_hosts)/len(hosts)*100:.1f}%)")
        
        # Check for completed host scans
        completed = 0
        for host in scanned_hosts:
            summary_file = os.path.join(hosts_dir, host, "summary.txt")
            if os.path.exists(summary_file):
                completed += 1
        
        print(f"Completed host scans: {completed} / {len(scanned_hosts)} ({completed/len(scanned_hosts)*100:.1f}%)")
    else:
        print("Host scanning not started yet")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_scan_status.py <scan_directory>")
        sys.exit(1)
    
    scan_dir = sys.argv[1]
    
    # Check once or continuously
    continuous = "--watch" in sys.argv
    
    if continuous:
        try:
            while True:
                os.system('cls' if os.name == 'nt' else 'clear')
                print(f"Monitoring scan: {scan_dir}")
                print("-" * 50)
                check_scan_status(scan_dir)
                print("-" * 50)
                print("Press Ctrl+C to exit")
                time.sleep(5)
        except KeyboardInterrupt:
            print("\nExiting...")
    else:
        check_scan_status(scan_dir) 