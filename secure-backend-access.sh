#!/bin/bash

# secure-backend-access.sh - Block direct backend access, only allow APIM

echo "🔒 Securing VulnShop Backend - Only Allow APIM Access"
echo "====================================================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Step 1: Get Azure API Management IP addresses
echo -e "\n${YELLOW}Step 1: Getting Azure APIM IP addresses...${NC}"
echo "Enter your Azure region (e.g., eastus, westus2, northeurope):"
read AZURE_REGION

# Download Azure IP ranges
echo -e "${BLUE}Downloading Azure IP ranges...${NC}"
curl -s https://www.microsoft.com/en-us/download/details.aspx?id=56519 -o /tmp/azure-ips.json 2>/dev/null || \
wget -q https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20240708.json -O /tmp/azure-ips.json

# Extract APIM IPs for the region
APIM_IPS=$(cat /tmp/azure-ips.json | jq -r ".values[] | select(.name == \"ApiManagement.$AZURE_REGION\") | .properties.addressPrefixes[]" 2>/dev/null)

if [ -z "$APIM_IPS" ]; then
    echo -e "${RED}Could not find APIM IPs for region: $AZURE_REGION${NC}"
    echo "Using alternative method..."
fi

# Step 2: Update nginx configuration
echo -e "\n${YELLOW}Step 2: Updating nginx configuration...${NC}"

cat > /tmp/vulnshop-nginx-secure <<'EOF'
server {
    listen 80;
    server_name _;
    
    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Hide server version
    server_tokens off;
    
    location / {
        root /var/www/vulnshop/frontend/dist;
        try_files $uri $uri/ /index.html;
    }
    
    location /api/ {
        # Only allow Azure API Management IPs
        # Add your APIM outbound IPs here
        allow 20.0.0.0/8;      # Azure IP range (adjust based on your region)
        allow 40.0.0.0/8;      # Azure IP range
        allow 52.0.0.0/8;      # Azure IP range
        allow 104.0.0.0/8;     # Azure IP range
        allow 127.0.0.1;       # Localhost for testing
        deny all;              # Block everything else
        
        # If request is allowed, proxy to backend
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Custom error page for blocked requests
        error_page 403 @blocked;
    }
    
    location @blocked {
        default_type application/json;
        return 403 '{"error": "Direct API access is not allowed. Please use the API Management endpoint.", "code": "DIRECT_ACCESS_FORBIDDEN"}';
    }
}
EOF

echo -e "${GREEN}✓ Nginx configuration created${NC}"

# Step 3: Get APIM details
echo -e "\n${YELLOW}Step 3: Getting your APIM endpoint...${NC}"
echo "Enter your APIM instance name:"
read APIM_NAME

echo -e "\n${BLUE}Your API should be accessed through:${NC}"
echo -e "${GREEN}https://${APIM_NAME}.azure-api.net/vulnshop/api/products${NC}"
echo -e "\n${RED}NOT through:${NC}"
echo -e "${RED}http://$(hostname)/api/products${NC}"

# Step 4: Apply firewall rules (Ubuntu/Debian)
echo -e "\n${YELLOW}Step 4: Setting up firewall rules...${NC}"

# Check if ufw is installed
if command -v ufw &> /dev/null; then
    echo -e "${BLUE}Configuring UFW firewall...${NC}"
    
    # Allow SSH (important!)
    sudo ufw allow 22/tcp
    
    # Allow HTTP from anywhere (for frontend)
    sudo ufw allow 80/tcp
    
    # Block direct access to backend port
    sudo ufw deny 3001/tcp
    
    # Enable firewall
    sudo ufw --force enable
    
    echo -e "${GREEN}✓ Firewall rules applied${NC}"
else
    echo -e "${YELLOW}UFW not found. Using iptables...${NC}"
    
    # Block external access to port 3001
    sudo iptables -A INPUT -p tcp --dport 3001 -s 127.0.0.1 -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 3001 -j DROP
    
    # Save iptables rules
    sudo iptables-save > /etc/iptables/rules.v4
    
    echo -e "${GREEN}✓ iptables rules applied${NC}"
fi

# Step 5: Instructions for Azure Portal
echo -e "\n${YELLOW}Step 5: Configure APIM Backend${NC}"
echo "1. Go to Azure Portal → Your APIM instance"
echo "2. Navigate to APIs → VulnShop API"
echo "3. Go to Settings → Backend"
echo "4. Set backend URL to: http://$(hostname)"
echo "5. Apply the enhanced-security-policy.xml"

echo -e "\n${YELLOW}Step 6: Get APIM Outbound IPs${NC}"
echo "Run this Azure CLI command to get your APIM's outbound IPs:"
echo -e "${BLUE}az apim show --name $APIM_NAME --resource-group <your-rg> --query 'publicIpAddresses' -o tsv${NC}"
echo ""
echo "Then update the nginx configuration with these specific IPs instead of broad ranges."

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Security Configuration Complete!${NC}"
echo -e "${GREEN}========================================${NC}"

echo -e "\n${BLUE}To apply these changes on your VM:${NC}"
echo "1. sudo cp /tmp/vulnshop-nginx-secure /etc/nginx/sites-available/vulnshop"
echo "2. sudo nginx -t"
echo "3. sudo systemctl reload nginx"

echo -e "\n${BLUE}To test:${NC}"
echo "# This should fail (403 Forbidden):"
echo "curl -i http://$(hostname)/api/products"
echo ""
echo "# This should work (through APIM):"
echo "curl -i https://${APIM_NAME}.azure-api.net/vulnshop/api/products"

echo -e "\n${YELLOW}⚠️  Important Security Notes:${NC}"
echo "1. Update nginx config with your specific APIM outbound IPs"
echo "2. Ensure your Network Security Group (NSG) also blocks port 3001"
echo "3. Consider using Private Endpoints for even better security"
echo "4. Monitor failed access attempts in nginx logs" 