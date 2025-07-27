#!/bin/bash

echo "==========================================="
echo "Azure API Management Connection Diagnostics"
echo "==========================================="
echo ""

# Function to print section headers
print_section() {
    echo ""
    echo "===================="
    echo "$1"
    echo "===================="
}

# Get VM information
print_section "VM Network Information"
PRIVATE_IP=$(hostname -I | awk '{print $1}')
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com)
echo "VM Private IP: $PRIVATE_IP"
echo "VM Public IP: $PUBLIC_IP"

# Check current Nginx configuration
print_section "Current Nginx API Access Rules"
grep -A 10 "location /api/" /etc/nginx/sites-available/vulnshop | grep -E "allow|deny"

# Check backend service
print_section "Backend Service Status"
systemctl is-active vulnshop-backend && echo "✓ Backend is running" || echo "✗ Backend is NOT running"
echo ""
echo "Testing backend directly:"
curl -s -o /dev/null -w "Direct backend (http://localhost:3001/api/products): %{http_code}\n" http://localhost:3001/api/products

# Get APIM IPs that are trying to connect
print_section "Recent Connection Attempts"
echo "Checking Nginx access logs for APIM requests..."
tail -n 100 /var/log/nginx/access.log | grep -E "api|products" | tail -10
echo ""
echo "Checking for 403 errors (blocked requests):"
tail -n 100 /var/log/nginx/access.log | grep " 403 " | tail -10

# Test current API endpoints
print_section "Testing API Endpoints"
echo "1. Direct backend access:"
curl -s http://localhost:3001/api/products | jq -r '. | if type=="array" then "✓ Returns product array" else "✗ Unexpected response" end' 2>/dev/null || echo "✗ Failed to connect"

echo ""
echo "2. Through Nginx proxy (localhost):"
curl -s http://localhost/api/products | jq -r '. | if type=="array" then "✓ Returns product array" else . end' 2>/dev/null || echo "✗ Failed"

# Create a script to fix APIM connectivity
print_section "Creating APIM Fix Configuration"
cat > /tmp/fix-apim-access.sh << 'FIXSCRIPT'
#!/bin/bash

echo "Fixing APIM Access Configuration..."

# Backup current Nginx config
cp /etc/nginx/sites-available/vulnshop /etc/nginx/sites-available/vulnshop.backup-$(date +%Y%m%d-%H%M%S)

# Create new Nginx configuration that's more permissive for APIM
cat > /etc/nginx/sites-available/vulnshop << 'EOF'
server {
    listen 80;
    server_name _;
    
    # Frontend - accessible to all
    location / {
        root /var/www/vulnshop/frontend/dist;
        try_files $uri $uri/ /index.html;
    }
    
    # API - accessible from APIM and localhost
    location /api/ {
        # Log all requests for debugging
        access_log /var/log/nginx/api-access.log;
        error_log /var/log/nginx/api-error.log debug;
        
        # Allow Azure APIM subnet (adjust based on your region)
        # West Europe APIM IPs
        allow 13.69.64.0/19;
        allow 13.69.106.0/23;
        allow 13.69.111.0/24;
        allow 13.69.112.0/21;
        allow 13.69.120.0/22;
        allow 13.69.125.0/24;
        allow 13.73.128.0/18;
        allow 13.73.192.0/20;
        allow 13.73.208.0/21;
        allow 13.73.216.0/22;
        allow 13.73.220.0/23;
        allow 13.73.222.0/24;
        allow 40.68.0.0/16;
        allow 40.74.0.0/16;
        allow 40.114.0.0/17;
        allow 40.115.0.0/16;
        allow 52.166.0.0/16;
        allow 52.174.0.0/16;
        allow 52.178.0.0/16;
        allow 52.232.0.0/16;
        allow 52.233.0.0/16;
        allow 52.236.0.0/15;
        
        # Allow localhost
        allow 127.0.0.1;
        
        # Temporarily allow all for debugging (remove after confirming APIM IP)
        allow all;
        
        # Proxy to backend WITHOUT the /api prefix to avoid duplication
        # Since backend already serves at /api
        proxy_pass http://localhost:3001;
        
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Add CORS headers for APIM
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type, Ocp-Apim-Subscription-Key' always;
        
        # Handle OPTIONS requests
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*';
            add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS';
            add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type, Ocp-Apim-Subscription-Key';
            add_header 'Content-Length' 0;
            return 204;
        }
    }
    
    # Health check endpoint
    location /health {
        proxy_pass http://localhost:3001/api/health;
        access_log off;
    }
}
EOF

# Test Nginx configuration
nginx -t && systemctl reload nginx && echo "✓ Nginx configuration updated successfully"

# Create custom log format to capture APIM requests
echo "Creating API access log..."
touch /var/log/nginx/api-access.log
touch /var/log/nginx/api-error.log
chown www-data:adm /var/log/nginx/api-*.log

echo ""
echo "✓ APIM access configuration updated!"
echo ""
echo "The API is now temporarily open to all IPs for debugging."
echo "Once you identify the APIM IP from the logs, update the configuration to restrict access."
FIXSCRIPT

chmod +x /tmp/fix-apim-access.sh

print_section "Recommended Actions"
echo "1. Run the fix script to update Nginx configuration:"
echo "   sudo /tmp/fix-apim-access.sh"
echo ""
echo "2. Monitor the API access log to identify APIM IPs:"
echo "   sudo tail -f /var/log/nginx/api-access.log"
echo ""
echo "3. Test the APIM connection again"
echo ""
echo "4. Once working, update Nginx to only allow the specific APIM IPs you see in the logs"

# Check if UFW is blocking
print_section "Firewall Status"
echo "UFW rules for port 3001:"
ufw status | grep 3001

# Test APIM endpoint configuration
print_section "APIM Configuration Check"
echo "Based on your Terraform configuration:"
echo "- APIM expects backend at: http://$PRIVATE_IP:3001/api"
echo "- But your backend root is already at /api"
echo ""
echo "This causes path duplication: /api/api/products"
echo ""
echo "The fix script above addresses this by proxying to http://localhost:3001 (without /api)"

echo ""
echo "==========================================="
echo "Diagnostics complete!"
echo "===========================================" 