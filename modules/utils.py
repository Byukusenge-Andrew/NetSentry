#!/usr/bin/env python3

import os
import sys
import subprocess
import logging
import ipaddress

def setup_logging(output_dir, verbose=False):
    """Set up logging configuration."""
    log_level = logging.DEBUG if verbose else logging.INFO
    log_file = os.path.join(output_dir, 'scan.log')
    
    # Create logger
    logger = logging.getLogger('network_mapper')
    logger.setLevel(log_level)
    
    # Create file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    
    # Create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def check_dependencies(logger):
    """Check if required tools are installed."""
    required_tools = ['nmap', 'masscan']  # Core tools that are always needed
    optional_tools = ['searchsploit', 'medusa', 'hydra']  # Tools needed for additional features
    
    missing_required = []
    missing_optional = []
    
    # Check required tools - Windows compatible version
    for tool in required_tools:
        try:
            # On Windows, use 'where' instead of 'which'
            if os.name == 'nt':  # Windows
                result = subprocess.run(['where', tool], capture_output=True, text=True)
                if result.returncode != 0:
                    # Try with .exe extension
                    result = subprocess.run(['where', f"{tool}.exe"], capture_output=True, text=True)
                    if result.returncode != 0:
                        missing_required.append(tool)
            else:  # Unix/Linux/Mac
                subprocess.run(['which', tool], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            missing_required.append(tool)
        except FileNotFoundError:
            # This happens if 'where' or 'which' command is not found
            # Try direct command execution as fallback
            try:
                subprocess.run([tool, '--version'], capture_output=True, shell=True)
            except:
                try:
                    subprocess.run([f"{tool}.exe", '--version'], capture_output=True, shell=True)
                except:
                    missing_required.append(tool)
    
    # Exit if required tools are missing
    if missing_required:
        logger.error(f"The following required tools are missing: {', '.join(missing_required)}")
        logger.error("Please install the required tools before running this script.")
        sys.exit(1)
    
    # Check optional tools - similar Windows compatible approach
    for tool in optional_tools:
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['where', tool], capture_output=True, text=True)
                if result.returncode != 0:
                    # Try with .exe extension
                    result = subprocess.run(['where', f"{tool}.exe"], capture_output=True, text=True)
                    if result.returncode != 0:
                        missing_optional.append(tool)
            else:  # Unix/Linux/Mac
                subprocess.run(['which', tool], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Try direct command execution as fallback
            try:
                subprocess.run([tool, '--version'], capture_output=True, shell=True)
            except:
                try:
                    subprocess.run([f"{tool}.exe", '--version'], capture_output=True, shell=True)
                except:
                    missing_optional.append(tool)
    
    # Just warn about missing optional tools
    if missing_optional:
        logger.warning(f"The following optional tools are missing: {', '.join(missing_optional)}")
        logger.warning("Some features may be unavailable.")
        
    logger.info("All required tools are installed.")

def validate_network_range(network_range):
    """Validate the network range."""
    # Check if it's a comma-separated list of IPs
    if ',' in network_range:
        ip_list = network_range.split(',')
        # Validate each IP
        for ip in ip_list:
            try:
                ipaddress.ip_address(ip.strip())
            except ValueError as e:
                raise ValueError(f"Invalid IP address in list: {ip.strip()} - {e}")
        # Return the original string for comma-separated IPs
        return network_range
    
    # Otherwise, treat as CIDR notation
    try:
        return ipaddress.ip_network(network_range, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid network range: {e}")

def run_command(command, logger):
    """Run a shell command and return its output."""
    logger.debug(f"Running: {' '.join(command)}")
    try:
        # Use shell=True for Windows compatibility
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.debug(f"Command failed: {e}")
        logger.debug(f"Error output: {e.stderr}")
        return e.stdout if e.stdout else "" 