#!/usr/bin/env python3

import os
import re
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from .utils import run_command

class CredentialChecker:
    def __init__(self, host_data, output_dir, threads=10, logger=None):
        """Initialize the credential checker module."""
        self.host_data = host_data
        self.output_dir = output_dir
        self.threads = threads
        self.logger = logger
        
        # Common usernames and passwords for testing
        self.usernames = ['admin', 'root', 'user', 'test', 'guest', 'administrator']
        self.passwords = ['password', 'admin', '123456', 'qwerty', 'welcome', 'test', '']
    
    def check_credentials(self):
        """Check credentials for all hosts."""
        self.logger.info("Starting credential checks...")
        
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_host_credentials, host): host 
                      for host in self.host_data}
            
            for future in tqdm(futures, desc="Checking credentials", unit="host"):
                try:
                    results.append(future.result())
                except Exception as e:
                    self.logger.error(f"Error checking credentials: {e}")
        
        return results
    
    def check_host_credentials(self, host):
        """Check credentials for common services on a host."""
        host_info = self.host_data[host]
        host_dir = os.path.join(self.output_dir, "hosts", host)
        cred_file = os.path.join(host_dir, "credential_check.txt")
        
        with open(cred_file, 'w') as f:
            f.write(f"Credential check for {host}\n")
            f.write("=" * 50 + "\n\n")
            
            for port in host_info["ports"]:
                # SSH credential check
                if port == 22:
                    f.write("SSH CREDENTIAL CHECK:\n")
                    ssh_check = self._check_ssh_credentials(host)
                    f.write(ssh_check)
                    f.write("\n\n")
                
                # FTP credential check
                elif port == 21:
                    f.write("FTP CREDENTIAL CHECK:\n")
                    ftp_check = self._check_ftp_credentials(host)
                    f.write(ftp_check)
                    f.write("\n\n")
                
                # SMB/Windows credential check
                elif port in [139, 445]:
                    f.write("SMB CREDENTIAL CHECK:\n")
                    smb_check = self._check_smb_credentials(host)
                    f.write(smb_check)
                    f.write("\n\n")
                
                # MySQL credential check
                elif port == 3306:
                    f.write("MYSQL CREDENTIAL CHECK:\n")
                    mysql_check = self._check_mysql_credentials(host)
                    f.write(mysql_check)
                    f.write("\n\n")
                
                # PostgreSQL credential check
                elif port == 5432:
                    f.write("POSTGRESQL CREDENTIAL CHECK:\n")
                    pgsql_check = self._check_pgsql_credentials(host)
                    f.write(pgsql_check)
                    f.write("\n\n")
        
        return host
    
    def _check_ssh_credentials(self, host):
        """Check SSH credentials using Hydra."""
        userlist_file = os.path.join(self.output_dir, "userlist.txt")
        passlist_file = os.path.join(self.output_dir, "passlist.txt")
        
        # Create temporary user/pass files
        self._create_wordlist_files(userlist_file, passlist_file)
        
        # Run hydra with limited attempts to avoid lockouts
        hydra_cmd = [
            "hydra", "-L", userlist_file, "-P", passlist_file,
            "-t", "4", "-f", "-o", os.path.join(self.output_dir, f"hydra_ssh_{host}.txt"),
            "-e", "nsr", "ssh://" + host
        ]
        
        return self._run_credential_check(hydra_cmd, host, "SSH")
    
    def _check_ftp_credentials(self, host):
        """Check FTP credentials using Hydra."""
        userlist_file = os.path.join(self.output_dir, "userlist.txt")
        passlist_file = os.path.join(self.output_dir, "passlist.txt")
        
        # Create temporary user/pass files
        self._create_wordlist_files(userlist_file, passlist_file)
        
        hydra_cmd = [
            "hydra", "-L", userlist_file, "-P", passlist_file,
            "-t", "4", "-f", "-o", os.path.join(self.output_dir, f"hydra_ftp_{host}.txt"),
            "-e", "nsr", "ftp://" + host
        ]
        
        return self._run_credential_check(hydra_cmd, host, "FTP")
    
    def _check_smb_credentials(self, host):
        """Check SMB credentials using Hydra."""
        userlist_file = os.path.join(self.output_dir, "userlist.txt")
        passlist_file = os.path.join(self.output_dir, "passlist.txt")
        
        # Create temporary user/pass files
        self._create_wordlist_files(userlist_file, passlist_file)
        
        hydra_cmd = [
            "hydra", "-L", userlist_file, "-P", passlist_file,
            "-t", "1", "-f", "-o", os.path.join(self.output_dir, f"hydra_smb_{host}.txt"),
            "-e", "nsr", "smb://" + host
        ]
        
        return self._run_credential_check(hydra_cmd, host, "SMB")
    
    def _check_mysql_credentials(self, host):
        """Check MySQL credentials using Medusa."""
        userlist_file = os.path.join(self.output_dir, "userlist.txt")
        passlist_file = os.path.join(self.output_dir, "passlist.txt")
        
        # Create temporary user/pass files
        self._create_wordlist_files(userlist_file, passlist_file)
        
        medusa_cmd = [
            "medusa", "-h", host, "-U", userlist_file, "-P", passlist_file,
            "-t", "1", "-M", "mysql", "-O", os.path.join(self.output_dir, f"medusa_mysql_{host}.txt")
        ]
        
        return self._run_credential_check(medusa_cmd, host, "MySQL", tool="medusa")
    
    def _check_pgsql_credentials(self, host):
        """Check PostgreSQL credentials using Medusa."""
        userlist_file = os.path.join(self.output_dir, "userlist.txt")
        passlist_file = os.path.join(self.output_dir, "passlist.txt")
        
        # Create temporary user/pass files
        self._create_wordlist_files(userlist_file, passlist_file)
        
        medusa_cmd = [
            "medusa", "-h", host, "-U", userlist_file, "-P", passlist_file,
            "-t", "1", "-M", "postgres", "-O", os.path.join(self.output_dir, f"medusa_pgsql_{host}.txt")
        ]
        
        return self._run_credential_check(medusa_cmd, host, "PostgreSQL", tool="medusa")
    
    def _create_wordlist_files(self, userlist_file, passlist_file):
        """Create temporary wordlist files for usernames and passwords."""
        if not os.path.exists(userlist_file):
            with open(userlist_file, 'w') as f:
                for user in self.usernames:
                    f.write(f"{user}\n")
        
        if not os.path.exists(passlist_file):
            with open(passlist_file, 'w') as f:
                for password in self.passwords:
                    f.write(f"{password}\n")
    
    def _run_credential_check(self, cmd, host, service_name, tool="hydra"):
        """Run credential check command and process output."""
        try:
            output = run_command(cmd, self.logger)
            
            # Check for successful credential discoveries
            if tool == "hydra":
                cred_pattern = r'login:\s*(\S+)\s+password:\s*(\S*)'
            else:  # medusa
                cred_pattern = r'SUCCESS:\s*\[\w+\]\s*Host:\s*\S+\s*User:\s*(\S+)\s*Password:\s*(\S*)'
            
            creds = re.findall(cred_pattern, output)
            
            if creds:
                for username, password in creds:
                    vuln_desc = f"Weak {service_name} credentials: {username}/{password}"
                    self.host_data[host]["vulnerabilities"].append(vuln_desc)
            
            return output
        except Exception as e:
            self.logger.error(f"Error checking {service_name} credentials for {host}: {e}")
            return f"Error: {str(e)}"
    
    def get_host_data(self):
        """Return the updated host data dictionary."""
        return self.host_data 