#!/bin/bash

# Quick fix script for VulnShop deployment issues
set -e

echo "🔧 Running quick fixes for VulnShop deployment..."

# Change to the correct directory
cd /var/www/vulnshop

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Step 1: Check and update Node.js
echo -e "${GREEN}Step 1: Checking Node.js version...${NC}"
NODE_VERSION=$(node -v 2>/dev/null | cut -d'v' -f2 || echo "0")
NODE_MAJOR=$(echo $NODE_VERSION | cut -d'.' -f1)

if [ "$NODE_MAJOR" -lt 16 ]; then
    echo -e "${YELLOW}Node.js version is too old. Installing Node.js 18...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
    echo -e "${GREEN}Node.js updated to $(node -v)${NC}"
else
    echo -e "${GREEN}Node.js version is OK: $(node -v)${NC}"
fi

# Step 2: Navigate to the correct directory
cd /var/www/vulnshop || {
    echo -e "${RED}ERROR: Cannot find /var/www/vulnshop${NC}"
    exit 1
}

# Step 3: Stop all services
echo -e "${GREEN}Step 2: Stopping all services...${NC}"
pm2 stop all 2>/dev/null || true
sudo lsof -ti:3001 | xargs sudo kill -9 2>/dev/null || true

# Step 4: Clean install backend
echo -e "${GREEN}Step 3: Reinstalling backend...${NC}"
cd backend
rm -rf node_modules package-lock.json
npm install --production

# Step 5: Clean install and build frontend
echo -e "${GREEN}Step 4: Reinstalling and building frontend...${NC}"
cd ../frontend
rm -rf node_modules package-lock.json dist
npm install
npm run build

# Step 6: Deploy frontend
echo -e "${GREEN}Step 5: Deploying frontend...${NC}"
sudo rm -rf /var/www/html/*
sudo cp -r dist/* /var/www/html/

# Step 7: Fix nginx configuration
echo -e "${GREEN}Step 6: Fixing nginx configuration...${NC}"
sudo tee /etc/nginx/sites-available/default > /dev/null <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;
    index index.html;

    server_name _;

    # Handle all frontend routes
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Proxy API requests to backend
    location /api/ {
        proxy_pass http://127.0.0.1:3001/api/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # CORS headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE' always;
        add_header 'Access-Control-Allow-Headers' 'Origin, X-Requested-With, Content-Type, Accept, Authorization' always;
    }
}
EOF

# Test and reload nginx
sudo nginx -t && sudo systemctl reload nginx

# Step 8: Start backend with PM2
echo -e "${GREEN}Step 7: Starting backend...${NC}"
cd ../backend

# Remove old database for fresh start
rm -f vulnshop.db

# Create PM2 config
cat > ecosystem.config.js <<EOF
module.exports = {
  apps: [{
    name: 'vulnshop-backend',
    script: 'server.js',
    instances: 1,
    autorestart: true,
    watch: false,
    env: {
      NODE_ENV: 'production',
      PORT: 3001
    }
  }]
};
EOF

# Start backend
pm2 delete vulnshop-backend 2>/dev/null || true
cd /var/www/vulnshop/backend
pm2 start server.js --name vulnshop-backend
cd /var/www/vulnshop
pm2 save

# Step 9: Verify everything is working
echo -e "${GREEN}Step 8: Verifying deployment...${NC}"
sleep 3

# Check backend
if curl -s http://localhost:3001/api/products > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Backend is running${NC}"
else
    echo -e "${RED}❌ Backend is not responding${NC}"
    echo "Backend logs:"
    pm2 logs vulnshop-backend --lines 10 --nostream
fi

# Check frontend
if curl -s http://localhost > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Frontend is accessible${NC}"
else
    echo -e "${RED}❌ Frontend is not accessible${NC}"
fi

# Check API proxy through nginx
if curl -s http://localhost/api/products > /dev/null 2>&1; then
    echo -e "${GREEN}✅ API proxy is working${NC}"
else
    echo -e "${RED}❌ API proxy is not working${NC}"
fi

echo ""
echo "========================================"
echo -e "${GREEN}Fix script completed!${NC}"
echo "========================================"
echo ""
echo "Your site should now be accessible at:"
echo "  http://$(curl -s ifconfig.me 2>/dev/null || echo 'your-server-ip')"
echo ""
echo "Test credentials:"
echo "  Admin: admin / admin123"
echo "  User: testuser / user123"
echo ""
echo "If you still have issues, check:"
echo "  - Backend logs: pm2 logs vulnshop-backend"
echo "  - Nginx error logs: sudo tail -f /var/log/nginx/error.log"
echo "" 