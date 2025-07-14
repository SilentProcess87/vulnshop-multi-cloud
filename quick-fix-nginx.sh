#!/bin/bash

# Quick fix for nginx configuration
# Run this on the VM to fix the nginx configuration issue

APIM_URL="https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"

echo "Enter APIM IPs (space-separated):"
read APIM_IPS

# Create proper nginx configuration
cat > /tmp/nginx-vulnshop-secure <<'NGINX_START'
server {
    listen 80;
    server_name _;
    
    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    server_tokens off;
    
    # Frontend - accessible to all
    location / {
        root /var/www/vulnshop/frontend/dist;
        try_files $uri $uri/ /index.html;
        
        # Security headers for frontend
        add_header Content-Security-Policy "default-src 'self' https://*.azure-api.net; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https:; img-src 'self' https: data:; font-src 'self' https: data:; connect-src 'self' https://*.azure-api.net;" always;
    }
    
    # API - only accessible from APIM
    location /api/ {
        # Allow APIM IPs
NGINX_START

# Add allow rules for each APIM IP
for ip in $APIM_IPS; do
    echo "        allow $ip;" >> /tmp/nginx-vulnshop-secure
done

# Continue with the rest of the configuration
cat >> /tmp/nginx-vulnshop-secure <<NGINX_END
        # Allow localhost for health checks
        allow 127.0.0.1;
        # Deny all others
        deny all;
        
        # Custom error for blocked requests
        error_page 403 @api_blocked;
        
        # Proxy to backend
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
    
    # Error response for blocked API access
    location @api_blocked {
        default_type application/json;
        return 403 '{"error": "Direct API access is not allowed. Please use the Azure API Management endpoint at ${APIM_URL}", "code": "DIRECT_ACCESS_FORBIDDEN", "endpoint": "${APIM_URL}/api/products"}';
    }
    
    # Health check endpoint (open to all for monitoring)
    location /health {
        proxy_pass http://localhost:3001/api/health;
        access_log off;
    }
}
NGINX_END

# Apply the configuration
sudo cp /tmp/nginx-vulnshop-secure /etc/nginx/sites-available/vulnshop

# Test nginx configuration
if sudo nginx -t; then
    sudo systemctl reload nginx
    echo "✓ Nginx configuration applied successfully"
else
    echo "✗ Nginx configuration error"
    exit 1
fi 