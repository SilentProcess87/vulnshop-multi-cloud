#!/bin/bash

# VulnShop Azure Deployment Fix Script
# This script attempts to fix common issues with the deployment

echo "======================================"
echo "VulnShop Azure Deployment Fix Script"
echo "======================================"
echo ""

# Function to print section headers
print_section() {
    echo ""
    echo "===================="
    echo "$1"
    echo "===================="
}

# Function to check command result
check_result() {
    if [ $? -eq 0 ]; then
        echo "✓ $1: SUCCESS"
        return 0
    else
        echo "✗ $1: FAILED"
        return 1
    fi
}

# Ensure running with sudo
if [ "$EUID" -ne 0 ]; then 
    echo "Please run this script with sudo: sudo bash fix-vulnshop.sh"
    exit 1
fi

# 1. Clone/Update Repository if missing
print_section "Repository Check"
if [ ! -d "/var/www/vulnshop" ]; then
    echo "Creating application directory..."
    mkdir -p /var/www
    cd /var/www
    
    # Use the git repo from variables or default
    GIT_REPO="${GIT_REPO:-https://github.com/YourUsername/Azure-APIM.git}"
    GIT_BRANCH="${GIT_BRANCH:-main}"
    
    echo "Cloning repository from: $GIT_REPO"
    git clone $GIT_REPO vulnshop
    cd vulnshop
    git checkout $GIT_BRANCH
    check_result "Repository clone"
else
    echo "✓ Repository exists"
    cd /var/www/vulnshop
    echo "Updating repository..."
    git fetch --all
    git reset --hard origin/main
    check_result "Repository update"
fi

# 2. Fix Permissions
print_section "Fixing Permissions"
chown -R www-data:www-data /var/www/vulnshop
chmod -R 755 /var/www/vulnshop
chmod -R 777 /var/www/vulnshop/backend  # For SQLite database
check_result "Permission fix"

# 3. Install Backend Dependencies
print_section "Backend Dependencies"
cd /var/www/vulnshop/backend

# Check if package.json exists
if [ ! -f "package.json" ]; then
    echo "✗ package.json not found!"
    echo "Creating minimal package.json..."
    cat > package.json << 'EOF'
{
  "name": "vulnshop-backend",
  "version": "1.0.0",
  "type": "module",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "sqlite3": "^5.1.6",
    "sqlite": "^5.1.1",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1"
  }
}
EOF
fi

echo "Installing npm packages..."
sudo -u www-data npm install
check_result "Backend npm install"

# 4. Install Frontend Dependencies and Build
print_section "Frontend Dependencies and Build"
cd /var/www/vulnshop/frontend

# Check if package.json exists
if [ ! -f "package.json" ]; then
    echo "✗ Frontend package.json not found!"
else
    echo "Installing frontend packages..."
    sudo -u www-data npm install
    check_result "Frontend npm install"
    
    echo "Building frontend..."
    sudo -u www-data npm run build
    check_result "Frontend build"
fi

# 5. Setup Database
print_section "Database Setup"
cd /var/www/vulnshop/backend
if [ -f "vulnshop.db" ]; then
    echo "Removing existing database..."
    rm -f vulnshop.db
fi
echo "Database will be created when backend starts..."

# 6. Setup Nginx Configuration
print_section "Nginx Configuration"
if [ ! -f "/etc/nginx/sites-available/vulnshop" ]; then
    echo "Creating Nginx configuration..."
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
fi

# Enable the site
ln -sf /etc/nginx/sites-available/vulnshop /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test and reload Nginx
nginx -t
if [ $? -eq 0 ]; then
    systemctl reload nginx
    check_result "Nginx configuration"
else
    echo "✗ Nginx configuration test failed!"
fi

# 7. Setup Backend Service
print_section "Backend Service Setup"
if [ ! -f "/etc/systemd/system/vulnshop-backend.service" ]; then
    echo "Creating systemd service..."
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
fi

# Reload systemd and start services
systemctl daemon-reload
systemctl enable vulnshop-backend
systemctl restart vulnshop-backend
sleep 5
check_result "Backend service start"

# 8. Start/Restart all services
print_section "Starting Services"
systemctl restart nginx
check_result "Nginx restart"

# 9. Verify Services
print_section "Service Verification"
sleep 5

# Check if backend is responding
echo "Testing backend API..."
BACKEND_TEST=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3001/api/products)
if [ "$BACKEND_TEST" = "200" ]; then
    echo "✓ Backend API is responding"
else
    echo "✗ Backend API not responding (HTTP $BACKEND_TEST)"
    echo "Checking backend logs:"
    journalctl -u vulnshop-backend -n 30 --no-pager
fi

# Check if frontend is responding
echo "Testing frontend..."
FRONTEND_TEST=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/)
if [ "$FRONTEND_TEST" = "200" ]; then
    echo "✓ Frontend is responding"
else
    echo "✗ Frontend not responding (HTTP $FRONTEND_TEST)"
fi

# Check if API proxy through Nginx works
echo "Testing API proxy..."
PROXY_TEST=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/api/products)
if [ "$PROXY_TEST" = "200" ]; then
    echo "✓ API proxy is working"
else
    echo "✗ API proxy not working (HTTP $PROXY_TEST)"
fi

# 10. Display Access Information
print_section "Access Information"
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com)
PRIVATE_IP=$(hostname -I | awk '{print $1}')

echo "Application should be accessible at:"
echo "- Public IP: http://$PUBLIC_IP"
echo "- Private IP: http://$PRIVATE_IP"
echo "- Localhost: http://localhost"
echo ""
echo "API endpoints:"
echo "- Direct backend: http://localhost:3001/api/products"
echo "- Through Nginx: http://localhost/api/products"
echo ""
echo "Default credentials:"
echo "- Admin: admin / admin123"
echo "- User: testuser / user123"

# 11. Troubleshooting Tips
print_section "If Still Not Working"
echo "1. Check if ports 80 and 3001 are open in Azure NSG"
echo "2. Check Azure VM firewall: sudo ufw status"
echo "3. View backend logs: sudo journalctl -u vulnshop-backend -f"
echo "4. View nginx logs: sudo tail -f /var/log/nginx/error.log"
echo "5. Check if another process is using ports: sudo lsof -i :80 -i :3001"
echo "6. Ensure VM has internet access for npm packages"
echo ""
echo "======================================"
echo "Fix script completed!"
echo "======================================" 