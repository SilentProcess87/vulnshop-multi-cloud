#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=== Fixing Nginx Configuration Issues ===${NC}"

# Step 1: Check what nginx configurations exist
echo -e "${GREEN}Step 1: Checking existing nginx configurations...${NC}"
echo "Sites available:"
ls -la /etc/nginx/sites-available/
echo ""
echo "Sites enabled:"
ls -la /etc/nginx/sites-enabled/

# Step 2: Remove all conflicting configurations
echo -e "${GREEN}Step 2: Removing conflicting configurations...${NC}"
sudo rm -f /etc/nginx/sites-enabled/*

# Step 3: Check if frontend dist exists and build if needed
echo -e "${GREEN}Step 3: Checking frontend build...${NC}"
if [ ! -d "/var/www/vulnshop/frontend/dist" ]; then
    echo -e "${YELLOW}Frontend dist directory not found. Building frontend...${NC}"
    cd /var/www/vulnshop/frontend
    sudo -u www-data npm install
    sudo -u www-data npm run build
else
    echo -e "${GREEN}Frontend dist directory exists${NC}"
    ls -la /var/www/vulnshop/frontend/dist/
fi

# Step 4: Create the correct nginx configuration
echo -e "${GREEN}Step 4: Creating correct nginx configuration...${NC}"
sudo tee /etc/nginx/sites-available/vulnshop > /dev/null << 'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    
    # Root directory for the frontend application
    root /var/www/vulnshop/frontend/dist;
    index index.html index.htm;
    
    # Frontend - serve static files and handle client-side routing
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    # API proxy - forward API requests to the backend Node.js server
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
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;
    
    # Logging
    access_log /var/log/nginx/vulnshop-access.log;
    error_log /var/log/nginx/vulnshop-error.log;
}
EOF

# Step 5: Enable only the vulnshop site
echo -e "${GREEN}Step 5: Enabling vulnshop site...${NC}"
sudo ln -sf /etc/nginx/sites-available/vulnshop /etc/nginx/sites-enabled/vulnshop

# Step 6: Test nginx configuration
echo -e "${GREEN}Step 6: Testing nginx configuration...${NC}"
sudo nginx -t

# Step 7: Set proper permissions
echo -e "${GREEN}Step 7: Setting proper permissions...${NC}"
sudo chown -R www-data:www-data /var/www/vulnshop
sudo chmod -R 755 /var/www/vulnshop

# Step 8: Reload nginx
echo -e "${GREEN}Step 8: Reloading nginx...${NC}"
sudo systemctl reload nginx

# Step 9: Verify the fix
echo -e "${GREEN}Step 9: Verifying the fix...${NC}"
sleep 2

# Check if frontend is accessible
if curl -s -o /dev/null -w "%{http_code}" http://localhost/ | grep -q "200"; then
    echo -e "${GREEN}✅ Frontend is now accessible (HTTP 200)${NC}"
else
    echo -e "${RED}❌ Frontend is still not accessible${NC}"
    echo "Checking nginx error log:"
    sudo tail -5 /var/log/nginx/error.log
fi

# Check current nginx configuration
echo -e "${GREEN}Current nginx root directory:${NC}"
sudo nginx -T 2>/dev/null | grep -E "root|server_name" | head -10

echo -e "${GREEN}=== Fix completed ===${NC}" 