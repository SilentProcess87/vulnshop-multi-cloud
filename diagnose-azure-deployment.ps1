# Azure VulnShop Deployment Diagnostic & Fix Script

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  Azure VulnShop Deployment Diagnostic & Fix" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Get VM connection details
Write-Host ""
$VM_HOST = Read-Host "Enter VM Public IP or DNS name"
$SSH_USER = Read-Host "Enter SSH username (press Enter for default: azureuser)"
if ([string]::IsNullOrEmpty($SSH_USER)) {
    $SSH_USER = "azureuser"
}

Write-Host ""
Write-Host "This script will:" -ForegroundColor Yellow
Write-Host "1. Check cloud-init status"
Write-Host "2. Review cloud-init logs for errors"
Write-Host "3. Manually deploy the application if needed"
Write-Host ""
$Continue = Read-Host "Continue? (y/n)"

if ($Continue -ne "y") {
    Write-Host "Aborted." -ForegroundColor Red
    exit
}

# Create the remote diagnostic script
$remoteScript = @'
#!/bin/bash

echo "=== Checking cloud-init status ==="
sudo cloud-init status --wait || true

echo ""
echo "=== Cloud-init summary ==="
sudo cloud-init status --long || true

echo ""
echo "=== Checking for cloud-init errors ==="
sudo grep -i error /var/log/cloud-init.log | tail -20 || true

echo ""
echo "=== Checking for cloud-init output ==="
sudo tail -50 /var/log/cloud-init-output.log || true

echo ""
echo "=== Checking web server status ==="
sudo systemctl status nginx --no-pager || true

echo ""
echo "=== Checking backend service status ==="
sudo systemctl status vulnshop-backend --no-pager || true

echo ""
echo "=== Checking /var/www directory ==="
ls -la /var/www/

echo ""
echo "=== Checking for git repository configuration ==="
grep -E "git_repo|git_branch" /var/lib/cloud/instance/user-data.txt 2>/dev/null || echo "Could not find git configuration"

# Manual deployment if needed
if [ ! -d "/var/www/vulnshop" ]; then
    echo ""
    echo "=== VulnShop directory not found. Starting manual deployment ==="
    
    # Clone the repository
    cd /var/www
    sudo git clone https://github.com/SilentProcess87/vulnshop-multi-cloud.git vulnshop
    cd vulnshop
    sudo git fetch --all
    sudo git reset --hard origin/main
    sudo git pull origin main
    
    # Set permissions
    sudo chown -R www-data:www-data /var/www/vulnshop
    
    # Install backend dependencies
    cd /var/www/vulnshop/backend
    sudo rm -f vulnshop.db
    sudo chmod -R 777 .
    sudo -u www-data npm install
    
    # Install frontend dependencies and build
    cd /var/www/vulnshop/frontend
    sudo -u www-data npm install
    sudo -u www-data npm run build
    
    # Setup Nginx configuration
    sudo tee /etc/nginx/sites-available/vulnshop > /dev/null << 'NGINX_CONFIG'
server {
    listen 80;
    server_name _;
    
    # Serve frontend
    location / {
        root /var/www/vulnshop/frontend/dist;
        try_files $uri $uri/ /index.html;
    }
    
    # Proxy API requests to backend
    location /api/ {
        proxy_pass http://localhost:3001/api/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
NGINX_CONFIG
    
    # Enable the site
    sudo rm -f /etc/nginx/sites-enabled/default
    sudo ln -sf /etc/nginx/sites-available/vulnshop /etc/nginx/sites-enabled/
    sudo nginx -t && sudo systemctl reload nginx
    
    # Setup backend service
    sudo tee /etc/systemd/system/vulnshop-backend.service > /dev/null << 'SERVICE_CONFIG'
[Unit]
Description=VulnShop Backend
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/vulnshop/backend
Environment=NODE_ENV=production
Environment=PORT=3001
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE_CONFIG
    
    # Start backend service
    sudo systemctl daemon-reload
    sudo systemctl enable vulnshop-backend
    sudo systemctl start vulnshop-backend
    
    echo ""
    echo "=== Manual deployment completed ==="
fi

echo ""
echo "=== Final status check ==="
echo "Nginx status:"
sudo systemctl is-active nginx

echo "Backend service status:"
sudo systemctl is-active vulnshop-backend

echo ""
echo "=== Testing endpoints ==="
echo "Frontend test:"
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" http://localhost/

echo "Backend API test:"
curl -s http://localhost:3001/api/products | head -20

echo ""
echo "=== Deployment diagnosis complete ==="
'@

# Save the script to a temporary file
$tempFile = [System.IO.Path]::GetTempFileName()
$remoteScript | Out-File -FilePath $tempFile -Encoding UTF8 -NoNewline

Write-Host ""
Write-Host "Connecting to VM and running diagnostics..." -ForegroundColor Green

# Execute the script on the remote VM
try {
    # Copy script to remote VM
    scp $tempFile "${SSH_USER}@${VM_HOST}:~/remote-diagnose.sh"
    
    # Execute the script
    ssh "${SSH_USER}@${VM_HOST}" "chmod +x remote-diagnose.sh && ./remote-diagnose.sh"
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}
finally {
    # Clean up
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Diagnostic complete. Your VulnShop application should now be accessible at:" -ForegroundColor Green
Write-Host "  Frontend: http://${VM_HOST}/" -ForegroundColor Cyan
Write-Host "  API: http://${VM_HOST}/api/" -ForegroundColor Cyan 