#!/usr/bin/env python3

import os
import sys
import argparse
import datetime
import subprocess
import time
from modules.discovery import HostDiscovery
from modules.port_scanner import PortScanner
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.credential_checker import CredentialChecker
from modules.service_fingerprinter import ServiceFingerprinter
from modules.web_interface import NetworkMapperUI
from modules.report_generator import ReportGenerator
from modules.utils import check_dependencies, setup_logging

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Network Device Mapping and Vulnerability Assessment Tool')
    parser.add_argument('-n', '--network', required=False, help='Network range to scan (CIDR notation)')
    parser.add_argument('-o', '--output', help='Output directory for scan results')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--skip-vuln-scan', action='store_true', help='Skip vulnerability scanning')
    parser.add_argument('--skip-cred-check', action='store_true', help='Skip credential checking')
    parser.add_argument('--skip-fingerprinting', action='store_true', help='Skip service fingerprinting')
    parser.add_argument('--install-deps', action='store_true', help='Install missing Python dependencies')
    parser.add_argument('--web', action='store_true', help='Start web interface')
    parser.add_argument('--web-port', type=int, default=8080, help='Port for web interface')
    parser.add_argument('--batch-size', type=int, default=10, help='Number of hosts to scan in each batch')
    parser.add_argument('--tcp-scan', action='store_true', help='Use TCP connect scan instead of SYN scan (doesn\'t require admin)')
    return parser.parse_args(), parser

def check_tool_requirements(args, logger):
    """Check if required tools are available based on selected options."""
    required_tools = ['nmap']  # Base requirements for Windows
    
    if not args.skip_vuln_scan:
        required_tools.append('searchsploit')
    
    if not args.skip_cred_check:
        required_tools.extend(['medusa', 'hydra'])
    
    missing_tools = []
    for tool in required_tools:
        try:
            # Check both regular command and .exe version
            try:
                subprocess.run([tool], capture_output=True, shell=True)
            except:
                subprocess.run([f"{tool}.exe"], capture_output=True, shell=True)
        except:
            missing_tools.append(tool)
    
    if missing_tools:
        logger.error(f"The following required tools are missing: {', '.join(missing_tools)}")
        logger.error("Please install them before running this script.")
        sys.exit(1)
    
    logger.info("All required tools are installed.")

def check_python_dependencies(logger, install=False):
    """Check if required Python packages are installed."""
    required_packages = ['tqdm', 'requests']
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        if install:
            logger.info(f"Installing missing Python packages: {', '.join(missing_packages)}")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
                logger.info("Successfully installed missing packages.")
            except Exception as e:
                logger.error(f"Failed to install packages: {e}")
                logger.error("Please install them manually using pip:")
                logger.error(f"pip install {' '.join(missing_packages)}")
                sys.exit(1)
        else:
            logger.error(f"The following required Python packages are missing: {', '.join(missing_packages)}")
            logger.error("Please install them using pip:")
            logger.error(f"pip install {' '.join(missing_packages)}")
            logger.error("Or run with --install-deps to automatically install them.")
            sys.exit(1)
    
    logger.info("All required Python packages are installed.")

def check_admin_privileges(logger):
    """Check if the script is running with administrative privileges."""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Unix/Linux/Mac
            return os.geteuid() == 0
    except:
        logger.warning("Could not determine if running with admin privileges")
        return False

def main():
    """Main function to orchestrate the network mapping and vulnerability assessment."""
    args, parser = parse_arguments()
    
    # Create output directory
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output or f"network_scan_{timestamp}"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Setup logging
    logger = setup_logging(output_dir, args.verbose)
    
    # Start web interface if requested
    if args.web:
        logger.info("Starting web interface...")
        web_ui = NetworkMapperUI(os.path.dirname(output_dir), logger, args.web_port)
        web_ui.start_server()
        
        # If no network is specified, just run the web interface
        if not args.network:
            try:
                print(f"Web interface started at http://localhost:{web_ui.port}")
                print("Press Ctrl+C to exit")
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Shutting down web interface...")
                web_ui.stop_server()
                return
    
    # If no network is specified and not running web interface, show help
    if not args.network and not args.web:
        parser.print_help()
        sys.exit(1)
    
    # Continue with normal scan if network is specified
    if args.network:
        logger.info(f"Starting network scan for {args.network}")
        logger.info(f"Results will be stored in: {os.path.abspath(output_dir)}")
        
        # Check for admin privileges
        is_admin = check_admin_privileges(logger)
        if not is_admin and not args.tcp_scan:
            logger.warning("Running without administrative privileges. Some scan features may be limited.")
            logger.warning("Consider using --tcp-scan for non-admin scanning")
        
        # Check dependencies based on selected options
        logger.info("Skipping dependency checks. Make sure nmap and masscan are installed.")
        
        # Initialize scan data structure
        scan_data = {
            'network_range': args.network,
            'timestamp': timestamp,
            'hosts': {},
            'vulnerable_hosts': []
        }
        
        # Discover hosts
        logger.info("Starting host discovery...")
        discovery = HostDiscovery(args.network, output_dir, args.threads, logger)
        live_hosts = discovery.discover_hosts()
        scan_data['live_hosts'] = live_hosts
        logger.info(f"Discovered {len(live_hosts)} live hosts")
        
        if not live_hosts:
            logger.warning("No live hosts found. Exiting.")
            sys.exit(0)
        
        # Process hosts in batches to avoid overwhelming the system
        batch_size = min(args.batch_size, args.threads)
        logger.info(f"Processing hosts in batches of {batch_size}")
        
        # Scan ports in batches
        port_scanner = PortScanner(live_hosts, output_dir, args.threads, logger, 
                                  use_tcp_scan=args.tcp_scan)
        
        for i in range(0, len(live_hosts), batch_size):
            batch_hosts = live_hosts[i:i+batch_size]
            logger.info(f"Scanning batch {i//batch_size + 1}/{(len(live_hosts) + batch_size - 1)//batch_size}: {len(batch_hosts)} hosts")
            
            port_scanner.hosts = batch_hosts
            try:
                scan_results = port_scanner.scan_ports()
                # Update host data with results from this batch
                scan_data['hosts'].update(port_scanner.get_host_data())
                logger.info(f"Completed port scanning for batch {i//batch_size + 1}")
            except KeyboardInterrupt:
                logger.warning("Scan interrupted by user. Saving partial results...")
                break
            except Exception as e:
                logger.error(f"Error scanning batch: {e}")
                continue
        
        # Service fingerprinting
        if not args.skip_fingerprinting and scan_data['hosts']:
            logger.info("Starting service fingerprinting...")
            fingerprinter = ServiceFingerprinter(scan_data['hosts'], output_dir, args.threads, logger)
            fingerprinter.fingerprint_services()
            scan_data['hosts'] = fingerprinter.get_host_data()
            logger.info("Completed service fingerprinting")
        
        # Vulnerability scanning
        if not args.skip_vuln_scan and scan_data['hosts']:
            logger.info("Starting vulnerability scanning...")
            vuln_scanner = VulnerabilityScanner(scan_data['hosts'], output_dir, args.threads, logger)
            vuln_scanner.scan_vulnerabilities()
            scan_data['hosts'] = vuln_scanner.get_host_data()
            scan_data['vulnerable_hosts'] = vuln_scanner.get_vulnerable_hosts()
            logger.info(f"Found {len(scan_data['vulnerable_hosts'])} hosts with vulnerabilities")
        
        # Credential checking
        if not args.skip_cred_check and scan_data['hosts']:
            logger.info("Starting credential checking...")
            cred_checker = CredentialChecker(scan_data['hosts'], output_dir, args.threads, logger)
            cred_checker.check_credentials()
            scan_data['hosts'] = cred_checker.get_host_data()
            logger.info("Completed credential checking")
        
        # Generate report
        logger.info("Generating report...")
        report_generator = ReportGenerator(scan_data, output_dir, logger)
        report_generator.generate_report()
        logger.info(f"Report generated in {output_dir}/report.html")
        
        logger.info("Scan completed successfully")
        print(f"\nScan completed. Results are available in: {os.path.abspath(output_dir)}")
        print(f"Summary report: {os.path.abspath(os.path.join(output_dir, 'report.html'))}")

if __name__ == "__main__":
    main() 