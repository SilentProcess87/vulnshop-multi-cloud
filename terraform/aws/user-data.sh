#!/bin/bash

# Update system
yum update -y

# Install Node.js 18
curl -fsSL https://rpm.nodesource.com/setup_18.x | bash -
yum install -y nodejs

# Install other required packages
yum install -y nginx git

# Clone the repository
cd /var/www
git clone ${git_repo} vulnshop
cd vulnshop
git checkout ${git_branch}
chown -R nginx:nginx /var/www/vulnshop

# Install backend dependencies
cd /var/www/vulnshop/backend
sudo -u nginx npm install

# Install frontend dependencies and build
cd /var/www/vulnshop/frontend
sudo -u nginx npm install
sudo -u nginx npm run build

# Configure Nginx
cat > /etc/nginx/nginx.conf << 'EOF'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

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
}
EOF

# Create systemd service for backend
cat > /etc/systemd/system/vulnshop-backend.service << 'EOF'
[Unit]
Description=VulnShop Backend
After=network.target

[Service]
Type=simple
User=nginx
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
    <title>VulnShop Status - AWS</title>
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
        <p><strong>Platform:</strong> Amazon Web Services with API Gateway</p>
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
        <h3>☁️ AWS Specific</h3>
        <p><strong>API Gateway:</strong> AWS API Gateway</p>
        <p><strong>Compute:</strong> EC2 (Amazon Linux 2)</p>
        <p><strong>Network:</strong> VPC with Internet Gateway</p>
        <p><strong>Storage:</strong> S3 for deployment assets</p>
    </div>
</body>
</html>
EOF

# Wait and test
sleep 30
curl -f http://localhost/status.html || echo "Warning: Frontend not responding"
curl -f http://localhost:3001/api/products || echo "Warning: Backend not responding"

# Log completion
echo "VulnShop deployment completed on AWS" >> /var/log/vulnshop-deployment.log 