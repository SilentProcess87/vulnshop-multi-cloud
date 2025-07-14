#!/bin/bash

# Fix VulnShop Deployment Script
echo "Starting VulnShop deployment fix..."

# Create necessary directories
sudo mkdir -p /var/www
cd /var/www

# Clone the repository
echo "Cloning repository..."
sudo git clone https://github.com/SilentProcess87/vulnshop-multi-cloud.git vulnshop
if [ $? -ne 0 ]; then
    echo "Failed to clone repository. Please check network connectivity."
    exit 1
fi

cd vulnshop
sudo git checkout main

# Set correct permissions
sudo chown -R www-data:www-data /var/www/vulnshop

# Check if server.js exists in the root (for backward compatibility)
if [ -f "/var/www/vulnshop/server.js" ]; then
    echo "Found server.js in root directory"
    # Create backend directory and copy server files
    sudo mkdir -p /var/www/vulnshop/backend
    sudo cp /var/www/vulnshop/server.js /var/www/vulnshop/backend/
    sudo cp /var/www/vulnshop/package.json /var/www/vulnshop/backend/
    if [ -f "/var/www/vulnshop/package-lock.json" ]; then
        sudo cp /var/www/vulnshop/package-lock.json /var/www/vulnshop/backend/
    fi
fi

# Install backend dependencies
echo "Installing backend dependencies..."
cd /var/www/vulnshop/backend
sudo -u www-data npm install

# Check if frontend exists
if [ -d "/var/www/vulnshop/frontend" ]; then
    echo "Building frontend..."
    cd /var/www/vulnshop/frontend
    sudo -u www-data npm install
    sudo -u www-data npm run build
else
    echo "Frontend directory not found. Creating static files from public directory..."
    # If no frontend directory, check for public directory
    if [ -d "/var/www/vulnshop/public" ]; then
        sudo mkdir -p /var/www/vulnshop/frontend/dist
        sudo cp -r /var/www/vulnshop/public/* /var/www/vulnshop/frontend/dist/
    fi
fi

# Setup Nginx configuration
echo "Configuring Nginx..."
sudo tee /etc/nginx/sites-available/vulnshop > /dev/null <<'EOF'
server {
    listen 80;
    server_name _;
    
    # Serve frontend
    location / {
        root /var/www/vulnshop/frontend/dist;
        try_files $uri $uri/ /index.html;
        
        # If frontend/dist doesn't exist, try public directory
        if (!-d /var/www/vulnshop/frontend/dist) {
            root /var/www/vulnshop/public;
        }
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

# Remove default site and enable vulnshop
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf /etc/nginx/sites-available/vulnshop /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# Create and start backend service
echo "Setting up backend service..."
sudo tee /etc/systemd/system/vulnshop-backend.service > /dev/null <<'EOF'
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

# Start backend service
sudo systemctl daemon-reload
sudo systemctl enable vulnshop-backend
sudo systemctl start vulnshop-backend

# Check service status
echo "Checking services..."
sudo systemctl status vulnshop-backend --no-pager
sudo systemctl status nginx --no-pager

echo "Deployment fix complete!"
echo "Frontend URL: http://$(hostname -f)"
echo "Backend API URL: http://$(hostname -f):3001/api"
echo "API via Nginx: http://$(hostname -f)/api" 