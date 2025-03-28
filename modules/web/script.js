document.addEventListener('DOMContentLoaded', function() {
    // Tab switching
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabName = button.getAttribute('data-tab');
            
            // Update active tab button
            tabButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
            
            // Show the selected tab content
            tabContents.forEach(content => {
                content.classList.remove('active');
                if (content.id === tabName) {
                    content.classList.add('active');
                }
            });
            
            // Load data for the tab if needed
            if (tabName === 'scan-results') {
                loadScanResults();
            }
        });
    });
    
    // Form submission
    const scanForm = document.getElementById('scan-form');
    scanForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Build command from form data
        const network = document.getElementById('network').value;
        const output = document.getElementById('output').value;
        const threads = document.getElementById('threads').value;
        const verbose = document.getElementById('verbose').checked;
        const skipVulnScan = document.getElementById('skip-vuln-scan').checked;
        const skipCredCheck = document.getElementById('skip-cred-check').checked;
        const skipFingerprinting = document.getElementById('skip-fingerprinting').checked;
        const installDeps = document.getElementById('install-deps').checked;
        
        let command = `python3 network_mapper.py -n ${network}`;
        
        if (output) command += ` -o ${output}`;
        if (threads) command += ` -t ${threads}`;
        if (verbose) command += ` -v`;
        if (skipVulnScan) command += ` --skip-vuln-scan`;
        if (skipCredCheck) command += ` --skip-cred-check`;
        if (skipFingerprinting) command += ` --skip-fingerprinting`;
        if (installDeps) command += ` --install-deps`;
        
        // Send scan request
        fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ command })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Show scan status
                document.getElementById('scan-form').classList.add('hidden');
                document.getElementById('scan-status').classList.remove('hidden');
                
                // Start polling for status
                pollScanStatus();
            } else {
                alert('Failed to start scan. Please check your inputs and try again.');
            }
        })
        .catch(error => {
            console.error('Error starting scan:', error);
            alert('An error occurred while starting the scan.');
        });
    });
    
    // Load scan results on page load
    loadScanResults();
});

function loadScanResults() {
    fetch('/api/scans')
        .then(response => response.json())
        .then(scans => {
            const tableBody = document.getElementById('scan-list-body');
            tableBody.innerHTML = '';
            
            if (scans.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="5">No scan results found.</td></tr>';
                return;
            }
            
            scans.forEach(scan => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${scan.time || 'Unknown'}</td>
                    <td>${scan.network || 'Unknown'}</td>
                    <td>${scan.hosts}</td>
                    <td>${scan.vulnerable_hosts || 0}</td>
                    <td>
                        <button class="action-button view-scan" data-id="${scan.id}">View</button>
                        <button class="action-button open-report" data-id="${scan.id}">Report</button>
                    </td>
                `;
                tableBody.appendChild(row);
            });
            
            // Add event listeners to view buttons
            document.querySelectorAll('.view-scan').forEach(button => {
                button.addEventListener('click', function() {
                    const scanId = this.getAttribute('data-id');
                    loadScanDetails(scanId);
                    
                    // Switch to scan details tab
                    document.querySelector('[data-tab="scan-details"]').click();
                });
            });
            
            // Add event listeners to report buttons
            document.querySelectorAll('.open-report').forEach(button => {
                button.addEventListener('click', function() {
                    const scanId = this.getAttribute('data-id');
                    window.open(`/${scanId}/report.html`, '_blank');
                });
            });
        })
        .catch(error => {
            console.error('Error loading scan results:', error);
        });
}

function loadScanDetails(scanId) {
    fetch(`/api/scan/${scanId}`)
        .then(response => response.json())
        .then(data => {
            const detailsContent = document.getElementById('scan-details-content');
            
            if (!data || Object.keys(data).length === 0) {
                detailsContent.innerHTML = '<p>No details available for this scan.</p>';
                return;
            }
            
            let html = `
                <div class="scan-header">
                    <h3>Scan of ${data.network_range}</h3>
                    <p>Completed: ${new Date(data.timestamp * 1000).toLocaleString()}</p>
                    <p>Live Hosts: ${data.live_hosts.length}</p>
                    <p>Vulnerable Hosts: ${data.vulnerable_hosts.length}</p>
                </div>
                <div class="host-list">
                    <h3>Host Details</h3>
            `;
            
            // Add host details
            for (const [host, hostInfo] of Object.entries(data.hosts)) {
                const isVulnerable = data.vulnerable_hosts.includes(host);
                
                html += `
                    <div class="host-card ${isVulnerable ? 'vulnerable' : ''}">
                        <h3>Host: ${host}</h3>
                        <p>Operating System: ${hostInfo.os || 'Unknown'}</p>
                        
                        <div class="service-list">
                            <h4>Open Ports and Services:</h4>
                            <ul>
                `;
                
                // Add services
                if (hostInfo.ports && hostInfo.services) {
                    for (let i = 0; i < hostInfo.ports.length; i++) {
                        const port = hostInfo.ports[i];
                        const service = hostInfo.services[i] || 'Unknown';
                        
                        // Add fingerprint info if available
                        let fingerprint = '';
                        if (hostInfo.fingerprints && hostInfo.fingerprints[port]) {
                            fingerprint = ` (${hostInfo.fingerprints[port]})`;
                        }
                        
                        html += `<li class="service-item">Port ${port}: ${service}${fingerprint}</li>`;
                    }
                }
                
                html += `</ul></div>`;
                
                // Add vulnerabilities if any
                if (hostInfo.vulnerabilities && hostInfo.vulnerabilities.length > 0) {
                    html += `
                        <div class="vulnerability-list">
                            <h4>Vulnerabilities:</h4>
                            <ul>
                    `;
                    
                    hostInfo.vulnerabilities.forEach(vuln => {
                        html += `<li class="vulnerability-item">${vuln}</li>`;
                    });
                    
                    html += `</ul></div>`;
                }
                
                html += `</div>`;
            }
            
            html += `</div>`;
            detailsContent.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading scan details:', error);
        });
}

function pollScanStatus() {
    const statusElement = document.getElementById('status-message');
    const progressBar = document.querySelector('.progress');
    
    // Simulate progress for now
    let progress = 0;
    
    const interval = setInterval(() => {
        fetch('/api/status')
            .then(response => response.json())
            .then(data => {
                if (!data.in_progress) {
                    // Scan completed
                    clearInterval(interval);
                    statusElement.textContent = 'Scan completed!';
                    progressBar.style.width = '100%';
                    
                    // Reload scan results and switch to results tab
                    setTimeout(() => {
                        loadScanResults();
                        document.querySelector('[data-tab="scan-results"]').click();
                        
                        // Reset form
                        document.getElementById('scan-form').classList.remove('hidden');
                        document.getElementById('scan-status').classList.add('hidden');
                    }, 2000);
                    
                    return;
                }
                
                // Update progress (simulated for now)
                progress += 5;
                if (progress > 95) progress = 95;
                progressBar.style.width = `${progress}%`;
                
                // Update status message
                statusElement.textContent = `Scanning... Command: ${data.command}`;
            })
            .catch(error => {
                console.error('Error polling scan status:', error);
                clearInterval(interval);
            });
    }, 2000);
} 