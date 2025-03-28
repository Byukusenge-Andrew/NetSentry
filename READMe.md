sugges # Network Mapper

## Overview

Network Mapper is a comprehensive network scanning and vulnerability assessment tool designed to discover hosts, scan ports, fingerprint services, and identify vulnerabilities on your network. It provides both command-line and web interfaces for easy use.

## Features

- Host discovery using masscan and nmap
- Port scanning with customizable options
- Service fingerprinting
- Vulnerability scanning
- Credential checking for common services
- HTML and JSON report generation
- Web interface for scan management

## Installation

### Prerequisites

- Python 3.6+
- Nmap
- Masscan (optional but recommended for faster host discovery)
- Searchsploit (optional, for vulnerability scanning)
- Medusa/Hydra (optional, for credential checking)

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/network-mapper.git
   cd network-mapper
   ```

2. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Basic Scanning

Scan a network range:

```
python network_mapper.py -n 192.168.1.0/24 -o scan_results -v
```

### Scan Options

- `-n, --network`: Network range to scan (CIDR notation or comma-separated IPs)
- `-o, --output`: Output directory for scan results
- `-t, --threads`: Number of threads to use (default: 10)
- `-v, --verbose`: Enable verbose output
- `--skip-vuln-scan`: Skip vulnerability scanning
- `--skip-cred-check`: Skip credential checking
- `--skip-fingerprinting`: Skip service fingerprinting
- `--batch-size`: Number of hosts to scan in each batch (default: 10)
- `--tcp-scan`: Use TCP connect scan instead of SYN scan (doesn't require admin privileges)

### Web Interface

Start the web interface:
```
python network_mapper.py --web
```

Access the web interface at http://localhost:8080

Customize the web interface port:
```
python network_mapper.py --web --web-port 9090
```

## Scanning Methods

### 1. Scan a Network Range (CIDR Notation)

```
python network_mapper.py -n 10.11.74.0/24 -o network_scan -v --tcp-scan
```

This scans all hosts in the 10.11.74.0/24 subnet.

### 2. Scan Specific IP Addresses

```
python network_mapper.py -n 10.11.74.234,10.11.74.1,10.11.74.2 -o specific_hosts -v --tcp-scan
```

This scans only the specified IP addresses.

### 3. Scan from a Target List File

Create a file with target IPs (one per line):
```
# target.txt
10.11.74.234
10.11.74.1
10.11.74.2
```

Then use the scan_targets.py helper script:
```
python scan_targets.py target.txt target_scan --skip-vuln-scan
```

### 4. Two-Phase Scanning for Large Networks

For large networks, use a two-phase approach:

```
# Phase 1: Quick discovery scan
python network_mapper.py -n 10.11.72.0/22 -o discovery_scan --skip-vuln-scan --skip-cred-check --skip-fingerprinting --tcp-scan

# Phase 2: Detailed scan of discovered hosts
python network_mapper.py -n 10.11.74.0/24 -o detailed_scan -v --tcp-scan
```

### 5. Monitor Scan Progress

Use the check_scan_status.py script to monitor scan progress:

```
python check_scan_status.py scan_output_directory --watch
```

This will continuously update with the current scan status.

## Optimizing Scans

### For Large Networks

- Use `--batch-size` to control how many hosts are scanned simultaneously
- Use `--skip-vuln-scan` and `--skip-cred-check` for initial discovery
- Focus on smaller subnets for detailed scanning

### For Non-Admin Usage

- Use `--tcp-scan` to perform TCP connect scans instead of SYN scans
- Scan common ports instead of all ports for faster results

### For Detailed Analysis

- Enable all scanning features for comprehensive results
- Use smaller batch sizes for more reliable scanning

## Troubleshooting

### Scan Taking Too Long

- Reduce the network range (scan smaller subnets)
- Use `--batch-size` with a smaller value (3-5)
- Skip intensive operations with `--skip-vuln-scan` and `--skip-cred-check`

### Permission Issues

- Use `--tcp-scan` for non-admin scanning
- Run as administrator/root for full scanning capabilities

### Network Issues

- Reduce scan rate by modifying the masscan command in discovery.py
- Use `--tcp-scan` which is less likely to be blocked by firewalls

## Examples

### Quick Network Discovery
```
python network_mapper.py -n 192.168.1.0/24 -o quick_scan --skip-vuln-scan --skip-cred-check --skip-fingerprinting
```

### Comprehensive Single Host Scan
```
python network_mapper.py -n 192.168.1.100 -o detailed_host -v
```

### Web-Based Scanning
```
python network_mapper.py --web
```

### Scan VMware Network
```
python network_mapper.py -n 192.168.231.0/24 -o vmware_scan -v --tcp-scan --batch-size 3
```

### Scan WSL Network
```
python network_mapper.py -n 172.30.48.0/20 -o wsl_scan -v --tcp-scan --batch-size 5
```

### Scan Only Common Ports
```
python network_mapper.py -n 10.11.74.0/24 -o common_ports -v --tcp-scan --common-ports-only
```

### Scan With Custom Thread Count
```
python network_mapper.py -n 192.168.1.0/24 -o threaded_scan -v --tcp-scan -t 20
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
