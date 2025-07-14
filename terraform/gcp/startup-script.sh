#!/bin/bash

# Update system
apt update && apt upgrade -y

# Install required packages
apt install -y nginx nodejs npm git curl unzip

# Clone the repository
cd /var/www
git clone ${git_repo} vulnshop
cd vulnshop
git checkout ${git_branch}
chown -R www-data:www-data /var/www/vulnshop

# Install backend dependencies
cd /var/www/vulnshop/backend
sudo -u www-data npm install

# Install frontend dependencies and build
cd /var/www/vulnshop/frontend
sudo -u www-data npm install
sudo -u www-data npm run build

# Configure Nginx
cat > /etc/nginx/sites-available/vulnshop << 'EOF'
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
EOF

# Enable site
rm -f /etc/nginx/sites-enabled/default
ln -s /etc/nginx/sites-available/vulnshop /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# Create systemd service for backend
cat > /etc/systemd/system/vulnshop-backend.service << 'EOF'
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
EOF

# Start and enable services
systemctl daemon-reload
systemctl enable vulnshop-backend
systemctl start vulnshop-backend
systemctl enable nginx
systemctl start nginx

# Create status page
cat > /var/www/vulnshop/status.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>VulnShop Status - GCP</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .status { padding: 20px; background: #f0f0f0; border-radius: 5px; margin: 10px 0; }
        .success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .info { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }
    </style>
</head>
<body>
    <h1>VulnShop Deployment Status</h1>
    <div class="status success">
        <h3>✅ Application Deployed Successfully</h3>
        <p><strong>Platform:</strong> Google Cloud Platform with Apigee</p>
        <p><strong>Frontend:</strong> <a href="/">Available at root</a></p>
        <p><strong>Backend API:</strong> <a href="/api/products">Available at /api/</a></p>
        <p><strong>Database:</strong> SQLite (local file)</p>
    </div>
    
    <div class="status info">
        <h3>📋 Application Information</h3>
        <p><strong>Default Admin:</strong> admin / admin123</p>
        <p><strong>Default User:</strong> testuser / user123</p>
        <p><strong>Purpose:</strong> Educational security testing</p>
        <p><strong>Vulnerabilities:</strong> 12 intentional security flaws</p>
    </div>
    
    <div class="status info">
        <h3>🔗 Quick Links</h3>
        <ul>
            <li><a href="/">Frontend Application</a></li>
            <li><a href="/api/products">API - Products</a></li>
            <li><a href="/api/admin/users">API - Admin Users</a> (requires auth)</li>
        </ul>
    </div>
    
    <div class="status info">
        <h3>🌐 GCP Specific</h3>
        <p><strong>API Gateway:</strong> Apigee</p>
        <p><strong>Compute:</strong> Compute Engine</p>
        <p><strong>Network:</strong> VPC with Cloud NAT</p>
    </div>
</body>
</html>
EOF

# Wait and test
sleep 30
curl -f http://localhost/status.html || echo "Warning: Frontend not responding"
curl -f http://localhost:3001/api/products || echo "Warning: Backend not responding"

# Log completion
echo "VulnShop deployment completed on GCP" >> /var/log/vulnshop-deployment.log 