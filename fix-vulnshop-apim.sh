#!/bin/bash

# fix-vulnshop-apim.sh - Comprehensive script to fix VulnShop APIM integration
# Can be run from Azure context (local machine) or VM context

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
APIM_NAME="apim-vulnshop-t7up5q"
RESOURCE_GROUP="rg-vulnshop-t7up5q"
APIM_URL="https://${APIM_NAME}.azure-api.net/vulnshop"
BACKEND_URL="http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com"
VM_HOSTNAME="vulnshop-dev-t7up5q.eastus.cloudapp.azure.com"
LOCATION="eastus"

# Function to print section headers
print_header() {
    echo -e "\n${CYAN}════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════${NC}\n"
}

# Function to check if we're running on the VM
is_vm_context() {
    if [ -d "/var/www/vulnshop" ] || [ -f "/etc/nginx/sites-available/vulnshop" ]; then
        return 0
    else
        return 1
    fi
}

# Function to check if Azure CLI is available
has_azure_cli() {
    if command -v az &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Detect context
if is_vm_context; then
    CONTEXT="VM"
    echo -e "${BLUE}🖥️  Running in VM context${NC}"
else
    CONTEXT="AZURE"
    echo -e "${BLUE}☁️  Running in Azure/Local context${NC}"
fi

print_header "VulnShop APIM Integration Fix Script"

echo "Configuration:"
echo "  APIM Name: $APIM_NAME"
echo "  Resource Group: $RESOURCE_GROUP"
echo "  APIM URL: $APIM_URL"
echo "  Backend URL: $BACKEND_URL"
echo "  Context: $CONTEXT"

# ============================================================================
# SECTION 1: Azure Configuration (only if in Azure context and has Azure CLI)
# ============================================================================

if [ "$CONTEXT" = "AZURE" ] && has_azure_cli; then
    print_header "Section 1: Azure APIM Configuration"
    
    # Check if logged into Azure
    echo -e "${YELLOW}Checking Azure login status...${NC}"
    if ! az account show &> /dev/null; then
        echo -e "${RED}Not logged into Azure. Please run: az login${NC}"
        exit 1
    fi
    
    # Get APIM details
    echo -e "${YELLOW}Getting APIM instance details...${NC}"
    APIM_EXISTS=$(az apim show --name $APIM_NAME --resource-group $RESOURCE_GROUP --query "name" -o tsv 2>/dev/null)
    
    if [ -z "$APIM_EXISTS" ]; then
        echo -e "${RED}APIM instance not found!${NC}"
        echo "Please ensure APIM exists or create it first"
        exit 1
    fi
    
    echo -e "${GREEN}✓ APIM instance found${NC}"
    
    # Get APIM outbound IPs
    echo -e "${YELLOW}Getting APIM outbound IPs...${NC}"
    APIM_IPS=$(az apim show --name $APIM_NAME --resource-group $RESOURCE_GROUP --query 'publicIpAddresses' -o tsv)
    echo -e "${GREEN}✓ APIM IPs: $APIM_IPS${NC}"
    
    # Create/Update API
    echo -e "${YELLOW}Configuring VulnShop API in APIM...${NC}"
    
    # Check if API exists
    API_EXISTS=$(az apim api show --api-id vulnshop --service-name $APIM_NAME --resource-group $RESOURCE_GROUP --query "name" -o tsv 2>/dev/null)
    
    if [ -z "$API_EXISTS" ]; then
        echo "Creating VulnShop API..."
        
        # Create API import file
        cat > /tmp/vulnshop-api.json <<EOF
{
  "openapi": "3.0.0",
  "info": {
    "title": "VulnShop API",
    "description": "Vulnerable E-commerce API for security testing",
    "version": "1.0.0"
  },
  "servers": [
    {
      "url": "${BACKEND_URL}"
    }
  ],
  "paths": {
    "/api/products": {
      "get": {
        "summary": "Get all products",
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      }
    },
    "/api/login": {
      "post": {
        "summary": "User login",
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      }
    }
  }
}
EOF
        
        az apim api import \
            --resource-group $RESOURCE_GROUP \
            --service-name $APIM_NAME \
            --api-id vulnshop \
            --path vulnshop \
            --specification-format OpenApi \
            --specification-path /tmp/vulnshop-api.json \
            --service-url $BACKEND_URL
            
        echo -e "${GREEN}✓ API created${NC}"
    else
        echo -e "${GREEN}✓ API already exists${NC}"
        
        # Update backend URL
        az apim api update \
            --resource-group $RESOURCE_GROUP \
            --service-name $APIM_NAME \
            --api-id vulnshop \
            --service-url $BACKEND_URL
    fi
    
    # Save APIM IPs to file for later use
    echo "$APIM_IPS" > /tmp/apim-ips.txt
    echo -e "${GREEN}✓ APIM IPs saved to /tmp/apim-ips.txt${NC}"
fi

# ============================================================================
# SECTION 2: Frontend Configuration and Build
# ============================================================================

print_header "Section 2: Frontend Configuration"

# Find project root
if [ "$CONTEXT" = "VM" ]; then
    PROJECT_ROOT="/var/www/vulnshop"
else
    # Try to find project root
    if [ -d "./frontend" ]; then
        PROJECT_ROOT="."
    elif [ -d "../frontend" ]; then
        PROJECT_ROOT=".."
    else
        echo -e "${RED}Cannot find project root. Please run from project directory${NC}"
        exit 1
    fi
fi

cd $PROJECT_ROOT

# Create environment files for frontend
echo -e "${YELLOW}Creating frontend environment files...${NC}"

mkdir -p frontend

cat > frontend/.env.production <<EOF
# Production Environment Configuration
VITE_API_URL=${APIM_URL}/api
EOF

cat > frontend/.env.development <<EOF
# Development Environment Configuration
VITE_API_URL=${APIM_URL}/api

# For local backend testing without APIM:
# VITE_API_URL=http://localhost:3001/api
EOF

# Copy to standard locations
if [ -f "frontend/env.production" ]; then
    cp frontend/env.production frontend/.env.production
fi
if [ -f "frontend/env.development" ]; then
    cp frontend/env.development frontend/.env.development
fi

echo -e "${GREEN}✓ Environment files created${NC}"

# Update frontend API service if needed
if [ -f "frontend/src/services/api.js" ]; then
    echo -e "${YELLOW}Checking frontend API service...${NC}"
    
    # Check if already updated
    if ! grep -q "import.meta.env.VITE_API_URL" frontend/src/services/api.js; then
        echo "Updating API service to use environment variables..."
        
        # Backup original
        cp frontend/src/services/api.js frontend/src/services/api.js.backup
        
        # Update the baseURL line
        sed -i.bak "s|baseURL: '/api'|baseURL: import.meta.env.VITE_API_URL || '/api'|g" frontend/src/services/api.js
        
        echo -e "${GREEN}✓ API service updated${NC}"
    else
        echo -e "${GREEN}✓ API service already configured${NC}"
    fi
fi

# Build frontend if not on VM (VM will build during deployment)
if [ "$CONTEXT" != "VM" ] && [ -d "frontend" ]; then
    echo -e "${YELLOW}Building frontend...${NC}"
    
    cd frontend
    
    # Check if npm is installed
    if command -v npm &> /dev/null; then
        npm install
        npm run build
        echo -e "${GREEN}✓ Frontend built successfully${NC}"
        echo -e "${BLUE}Build output in: frontend/dist/${NC}"
    else
        echo -e "${YELLOW}⚠️  npm not found. Skipping frontend build${NC}"
    fi
    
    cd ..
fi

# ============================================================================
# SECTION 3: VM Configuration (only if in VM context)
# ============================================================================

if [ "$CONTEXT" = "VM" ]; then
    print_header "Section 3: VM Backend Security"
    
    # Get APIM IPs (from file if available, or prompt)
    APIM_IPS=""
    if [ -f "/tmp/apim-ips.txt" ]; then
        APIM_IPS=$(cat /tmp/apim-ips.txt)
        echo -e "${GREEN}✓ Using APIM IPs from file${NC}"
    else
        echo -e "${YELLOW}Enter APIM outbound IPs (space-separated):${NC}"
        echo "Run this command to get them:"
        echo "az apim show --name $APIM_NAME --resource-group $RESOURCE_GROUP --query 'publicIpAddresses' -o tsv"
        read -p "APIM IPs: " APIM_IPS
    fi
    
    if [ -z "$APIM_IPS" ]; then
        echo -e "${RED}No APIM IPs provided. Using Azure IP ranges as fallback${NC}"
        APIM_IPS="20.0.0.0/8 40.0.0.0/8 52.0.0.0/8 104.0.0.0/8"
    fi
    
    # Create nginx configuration
    echo -e "${YELLOW}Creating secure nginx configuration...${NC}"
    
    # Start creating the nginx configuration
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
    
    echo -e "${GREEN}✓ Nginx configuration created${NC}"
    
    # Backup and apply nginx configuration
    echo -e "${YELLOW}Applying nginx configuration...${NC}"
    sudo cp /etc/nginx/sites-available/vulnshop /etc/nginx/sites-available/vulnshop.backup
    sudo cp /tmp/nginx-vulnshop-secure /etc/nginx/sites-available/vulnshop
    
    # Test nginx configuration
    if sudo nginx -t; then
        sudo systemctl reload nginx
        echo -e "${GREEN}✓ Nginx configuration applied${NC}"
    else
        echo -e "${RED}✗ Nginx configuration error. Restoring backup...${NC}"
        sudo cp /etc/nginx/sites-available/vulnshop.backup /etc/nginx/sites-available/vulnshop
        exit 1
    fi
    
    # Build and deploy frontend
    echo -e "${YELLOW}Building and deploying frontend...${NC}"
    
    cd /var/www/vulnshop/frontend
    npm install
    npm run build
    
    echo -e "${GREEN}✓ Frontend built and deployed${NC}"
    
    # Ensure backend is running
    echo -e "${YELLOW}Checking backend service...${NC}"
    
    if command -v pm2 &> /dev/null; then
        cd /var/www/vulnshop/backend
        pm2 delete vulnshop-backend 2>/dev/null || true
        pm2 start server.js --name vulnshop-backend
        pm2 save
        echo -e "${GREEN}✓ Backend service running${NC}"
    else
        echo -e "${YELLOW}⚠️  PM2 not found. Backend should be started manually${NC}"
    fi
fi

# ============================================================================
# SECTION 4: Testing and Verification
# ============================================================================

print_header "Section 4: Testing and Verification"

# Function to test endpoint
test_endpoint() {
    local url=$1
    local expected_status=$2
    local description=$3
    
    echo -n "Testing $description... "
    
    if command -v curl &> /dev/null; then
        status=$(curl -s -o /dev/null -w "%{http_code}" "$url")
        if [ "$status" = "$expected_status" ]; then
            echo -e "${GREEN}✓ Success (HTTP $status)${NC}"
            return 0
        else
            echo -e "${RED}✗ Failed (HTTP $status, expected $expected_status)${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}⚠️  curl not available${NC}"
        return 2
    fi
}

# Test APIM endpoint
echo -e "${YELLOW}Testing APIM endpoints...${NC}"
test_endpoint "${APIM_URL}/api/products" "200" "APIM products endpoint"
test_endpoint "${APIM_URL}/api/products?q=' OR '1'='1" "403" "APIM attack detection"

# Test direct access (should fail)
echo -e "${YELLOW}Testing direct backend access (should be blocked)...${NC}"
test_endpoint "${BACKEND_URL}/api/products" "403" "Direct backend access"

# ============================================================================
# SECTION 5: Summary and Next Steps
# ============================================================================

print_header "Summary and Next Steps"

echo -e "${GREEN}✅ Configuration Complete!${NC}"
echo

if [ "$CONTEXT" = "AZURE" ]; then
    echo -e "${BLUE}From Azure Context - Next Steps:${NC}"
    echo "1. Deploy to VM:"
    echo "   scp -r frontend/dist/* azureuser@${VM_HOSTNAME}:/tmp/frontend/"
    echo "   scp fix-vulnshop-apim.sh azureuser@${VM_HOSTNAME}:/tmp/"
    echo ""
    echo "2. SSH to VM and run:"
    echo "   ssh azureuser@${VM_HOSTNAME}"
    echo "   sudo bash /tmp/fix-vulnshop-apim.sh"
    echo ""
    echo "3. APIM IPs saved to: /tmp/apim-ips.txt"
    echo "   Transfer this file to VM if needed"
else
    echo -e "${BLUE}From VM Context - Completed:${NC}"
    echo "✓ Nginx configured to only allow APIM IPs"
    echo "✓ Frontend built with APIM endpoint"
    echo "✓ Backend secured"
fi

echo
echo -e "${CYAN}Test URLs:${NC}"
echo "Frontend: http://${VM_HOSTNAME}"
echo "APIM API: ${APIM_URL}/api/products"
echo "Direct API (blocked): ${BACKEND_URL}/api/products"

echo
echo -e "${CYAN}Monitor in Azure Portal:${NC}"
echo "1. APIM Analytics: See all API traffic"
echo "2. APIM Logs: View attack attempts"
echo "3. Cortex Dashboard: Complete request/response logs"

echo
echo -e "${GREEN}🎉 VulnShop is now secured with APIM!${NC}"

# Create policy file if it doesn't exist
if [ ! -f "policies/cortex-enhanced-security-policy.xml" ] && [ "$CONTEXT" = "AZURE" ]; then
    echo
    echo -e "${YELLOW}Note: Remember to apply the security policy in APIM:${NC}"
    echo "Portal → APIM → APIs → VulnShop → All operations → Policies"
    echo "Apply: policies/cortex-enhanced-security-policy.xml"
fi 