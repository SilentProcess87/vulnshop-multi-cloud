#!/bin/bash

# VulnShop Deployment Refresh Script
# This script updates the VulnShop application on the VM with the latest code

set -e  # Exit on error

echo "🚀 Starting VulnShop deployment refresh..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration - Updated to match your setup
APP_DIR="/var/www/vulnshop"
FRONTEND_PORT=3000
BACKEND_PORT=3001

# Function to print colored output
print_status() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

print_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

# Check Node.js version
print_status "Checking Node.js version..."
NODE_VERSION=$(node -v | cut -d'v' -f2)
NODE_MAJOR=$(echo $NODE_VERSION | cut -d'.' -f1)

if [ "$NODE_MAJOR" -lt 16 ]; then
    print_error "Node.js version $NODE_VERSION is too old. Vite requires Node.js 16 or higher."
    print_status "Updating Node.js to version 18..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
    print_status "Node.js updated to $(node -v)"
fi

# Navigate to application directory
print_status "Navigating to application directory..."
cd "$APP_DIR" || {
    print_error "Failed to navigate to $APP_DIR"
    exit 1
}

# Stop current services
print_status "Stopping current services..."
pm2 stop all || print_warning "PM2 processes may not be running"

# Kill any remaining node processes on our ports
print_status "Cleaning up any remaining processes..."
sudo lsof -ti:$FRONTEND_PORT | xargs sudo kill -9 2>/dev/null || true
sudo lsof -ti:$BACKEND_PORT | xargs sudo kill -9 2>/dev/null || true

# Pull latest changes from git
print_status "Pulling latest changes from git..."
git fetch origin
git reset --hard origin/main
git pull origin main

# Remove old node_modules and package-lock files to ensure clean install
print_status "Cleaning up old dependencies..."
rm -rf backend/node_modules frontend/node_modules
rm -f backend/package-lock.json frontend/package-lock.json

# Install backend dependencies
print_status "Installing backend dependencies..."
cd backend
npm install --production

# Install frontend dependencies and build
print_status "Installing frontend dependencies..."
cd ../frontend
npm install

print_status "Building frontend for production..."
npm run build || {
    print_error "Frontend build failed. Checking for common issues..."
    print_status "Clearing npm cache and retrying..."
    npm cache clean --force
    rm -rf node_modules package-lock.json
    npm install
    npm run build
}

# Copy frontend build to nginx directory
print_status "Deploying frontend to nginx..."
sudo rm -rf /var/www/html/*
sudo cp -r dist/* /var/www/html/

# Update nginx configuration if needed
print_status "Updating nginx configuration..."
sudo tee /etc/nginx/sites-available/default > /dev/null <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;

    server_name _;

    # Frontend routes
    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # API proxy - Fixed to match actual backend routes
    location /api/ {
        proxy_pass http://localhost:$BACKEND_PORT/api/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Test nginx configuration
print_status "Testing nginx configuration..."
sudo nginx -t

# Reload nginx
print_status "Reloading nginx..."
sudo systemctl reload nginx

# Start backend with PM2
print_status "Starting backend server with PM2..."
cd ../backend

# Remove old database to start fresh (optional - comment out to keep data)
if [ -f "vulnshop.db" ]; then
    print_warning "Removing old database to start fresh..."
    rm vulnshop.db
fi

# Create PM2 ecosystem file
cat > ecosystem.config.js <<EOF
module.exports = {
  apps: [{
    name: 'vulnshop-backend',
    script: 'server.js',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'production',
      PORT: $BACKEND_PORT
    }
  }]
};
EOF

# Start backend with PM2
pm2 delete vulnshop-backend 2>/dev/null || true
pm2 start ecosystem.config.js
pm2 save

# Setup PM2 to start on boot
print_status "Setting up PM2 startup..."
sudo env PATH=$PATH:/usr/bin pm2 startup systemd -u $USER --hp $HOME || true
pm2 save

# Check service status
print_status "Checking service status..."
echo ""
echo "Backend status:"
pm2 status
echo ""
echo "Nginx status:"
sudo systemctl status nginx --no-pager | head -n 10
echo ""

# Test the deployment
print_status "Testing deployment..."
sleep 5  # Wait for services to fully start

# Test backend
if curl -f http://localhost:$BACKEND_PORT/api/products > /dev/null 2>&1; then
    print_status "✅ Backend is responding correctly"
else
    print_error "❌ Backend is not responding"
    print_status "Checking backend logs..."
    pm2 logs vulnshop-backend --lines 20
fi

# Test frontend through nginx
if curl -f http://localhost > /dev/null 2>&1; then
    print_status "✅ Frontend is accessible through nginx"
else
    print_error "❌ Frontend is not accessible"
fi

# Display access information
echo ""
echo "========================================"
echo -e "${GREEN}🎉 Deployment refresh complete!${NC}"
echo "========================================"
echo ""
echo "Access your application at:"
echo "  - Frontend: http://$(curl -s ifconfig.me 2>/dev/null || echo 'your-server-ip')"
echo "  - Backend API: http://$(curl -s ifconfig.me 2>/dev/null || echo 'your-server-ip')/api"
echo ""
echo "Default credentials:"
echo "  - Admin: admin / admin123"
echo "  - User: testuser / user123"
echo ""
echo "To view logs:"
echo "  - Backend: pm2 logs vulnshop-backend"
echo "  - All PM2 apps: pm2 logs"
echo ""
echo "To restart services:"
echo "  - Backend: pm2 restart vulnshop-backend"
echo "  - Nginx: sudo systemctl restart nginx"
echo "" 