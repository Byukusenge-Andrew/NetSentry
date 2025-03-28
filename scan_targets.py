#!/usr/bin/env python3

import os
import sys
import subprocess

def scan_targets(target_file, output_dir):
    """Scan targets from a file."""
    # Read targets
    with open(target_file, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]
    
    print(f"Found {len(targets)} targets to scan")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.join(output_dir, "discovery"), exist_ok=True)
    
    # Write targets to live_hosts.txt
    with open(os.path.join(output_dir, "discovery", "live_hosts.txt"), 'w') as f:
        for target in targets:
            f.write(f"{target}\n")
    
    # Run the scanner with the prepared directory
    cmd = [
        "python", "network_mapper.py",
        "-n", "0.0.0.0/0",  # Dummy network, won't be used
        "-o", output_dir,
        "-v", "--tcp-scan"
    ]
    
    # Add any additional arguments
    if len(sys.argv) > 3:
        cmd.extend(sys.argv[3:])
    
    print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python scan_targets.py <target_file> <output_dir> [additional args]")
        sys.exit(1)
    
    scan_targets(sys.argv[1], sys.argv[2]) 