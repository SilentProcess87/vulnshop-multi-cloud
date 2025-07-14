#!/bin/bash

# configure-apim-integration.sh - Configure VulnShop to work exclusively through Azure API Management

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔧 Configuring VulnShop for APIM-Only Communication${NC}"
echo -e "${BLUE}===================================================${NC}"

# Configuration
APIM_NAME="apim-vulnshop-t7up5q"
APIM_URL="https://${APIM_NAME}.azure-api.net/vulnshop"
BACKEND_URL="http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com"
RESOURCE_GROUP="rg-vulnshop-t7up5q"

echo -e "\n${YELLOW}Configuration:${NC}"
echo "APIM Instance: $APIM_NAME"
echo "APIM URL: $APIM_URL"
echo "Backend URL: $BACKEND_URL"

# Step 1: Frontend Configuration
echo -e "\n${YELLOW}Step 1: Configuring Frontend${NC}"

# Create production environment file
cat > frontend/.env.production <<EOF
# Production Environment Configuration
VITE_API_URL=${APIM_URL}/api
EOF

# Create development environment file (for local testing with APIM)
cat > frontend/.env.development <<EOF
# Development Environment Configuration
# Use APIM even in development to test the full flow
VITE_API_URL=${APIM_URL}/api

# For local backend testing without APIM, comment above and uncomment below:
# VITE_API_URL=http://localhost:3001/api
EOF

echo -e "${GREEN}✓ Frontend environment files created${NC}"

# Step 2: Update package.json scripts
echo -e "\n${YELLOW}Step 2: Updating Frontend Build Scripts${NC}"

cd frontend

# Update package.json to include environment-specific builds
cat > build-scripts.json <<'EOF'
{
  "scripts": {
    "dev": "vite",
    "dev:local": "VITE_API_URL=http://localhost:3001/api vite",
    "dev:apim": "vite",
    "build": "vite build",
    "build:production": "vite build --mode production",
    "preview": "vite preview",
    "test:api": "node test-api-connection.js"
  }
}
EOF

echo -e "${GREEN}✓ Build scripts prepared${NC}"

# Step 3: Create API connection test
echo -e "\n${YELLOW}Step 3: Creating API Connection Test${NC}"

cat > test-api-connection.js <<'EOF'
// Test API connection through APIM
import axios from 'axios';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config({ path: `.env.${process.env.NODE_ENV || 'development'}` });

const API_URL = process.env.VITE_API_URL;

console.log('Testing API connection...');
console.log('API URL:', API_URL);

async function testConnection() {
  try {
    // Test products endpoint
    const response = await axios.get(`${API_URL}/products`);
    console.log('✅ API Connection Successful!');
    console.log('Products count:', response.data.length);
    
    // Check for APIM headers
    console.log('\nResponse Headers:');
    Object.keys(response.headers).forEach(header => {
      if (header.toLowerCase().includes('azure') || header.toLowerCase().includes('apim')) {
        console.log(`  ${header}: ${response.headers[header]}`);
      }
    });
  } catch (error) {
    console.error('❌ API Connection Failed!');
    console.error('Error:', error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
    }
  }
}

testConnection();
EOF

cd ..

echo -e "${GREEN}✓ API connection test created${NC}"

# Step 4: Backend Security Configuration
echo -e "\n${YELLOW}Step 4: Creating Backend Security Script${NC}"

cat > secure-backend-for-apim.sh <<'EOF'
#!/bin/bash

# This script should be run on the VM to secure the backend

echo "🔒 Securing Backend for APIM-Only Access"

# Get APIM outbound IPs (you need to replace these with actual IPs)
# Run: az apim show --name apim-vulnshop-t7up5q --resource-group rg-vulnshop-t7up5q --query 'publicIpAddresses' -o tsv
APIM_IPS="REPLACE_WITH_YOUR_APIM_IPS"

# Update nginx configuration
cat > /tmp/nginx-apim-only <<EOF
server {
    listen 80;
    server_name _;
    
    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    server_tokens off;
    
    # Frontend - accessible to all
    location / {
        root /var/www/vulnshop/frontend/dist;
        try_files \$uri \$uri/ /index.html;
        
        # Add security headers for frontend
        add_header Content-Security-Policy "default-src 'self' https://*.azure-api.net; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https:; img-src 'self' https: data:; font-src 'self' https:;" always;
    }
    
    # API - only accessible from APIM
    location /api/ {
        # IMPORTANT: Replace with your actual APIM IPs
        # allow x.x.x.x;  # APIM IP 1
        # allow y.y.y.y;  # APIM IP 2
        allow 127.0.0.1;  # Localhost for health checks
        deny all;
        
        # Custom error for blocked requests
        error_page 403 @api_blocked;
        
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
    
    location @api_blocked {
        default_type application/json;
        return 403 '{"error": "Direct API access is not allowed. Please use the Azure API Management endpoint at https://apim-vulnshop-t7up5q.azure-api.net/vulnshop", "code": "DIRECT_ACCESS_FORBIDDEN"}';
    }
    
    # Health check endpoint (accessible to all for monitoring)
    location /health {
        proxy_pass http://localhost:3001/api/health;
        access_log off;
    }
}
EOF

echo "Nginx configuration created at /tmp/nginx-apim-only"
echo "To apply: sudo cp /tmp/nginx-apim-only /etc/nginx/sites-available/vulnshop"
echo "Then: sudo nginx -t && sudo systemctl reload nginx"
EOF

chmod +x secure-backend-for-apim.sh

echo -e "${GREEN}✓ Backend security script created${NC}"

# Step 5: APIM Configuration Commands
echo -e "\n${YELLOW}Step 5: APIM Configuration Commands${NC}"

cat > configure-apim.sh <<EOF
#!/bin/bash

# Commands to configure APIM

echo "📋 APIM Configuration Steps:"

echo "1. Get APIM outbound IPs:"
echo "az apim show --name $APIM_NAME --resource-group $RESOURCE_GROUP --query 'publicIpAddresses' -o tsv"

echo -e "\n2. Update APIM backend configuration:"
echo "az apim api backend update \\"
echo "  --resource-group $RESOURCE_GROUP \\"
echo "  --service-name $APIM_NAME \\"
echo "  --api-id vulnshop \\"
echo "  --backend-id vulnshop-backend \\"
echo "  --url $BACKEND_URL"

echo -e "\n3. Apply the security policy:"
echo "Use the policy from: policies/cortex-enhanced-security-policy.xml"

echo -e "\n4. Test the configuration:"
echo "curl -i ${APIM_URL}/api/products"
EOF

chmod +x configure-apim.sh

# Step 6: Create deployment script
echo -e "\n${YELLOW}Step 6: Creating Deployment Script${NC}"

cat > deploy-with-apim.sh <<'EOF'
#!/bin/bash

# Deploy frontend configured for APIM

echo "🚀 Deploying Frontend with APIM Configuration"

cd frontend

# Copy production environment file
if [ -f "env.production" ]; then
    cp env.production .env.production
fi

# Install dependencies
npm install

# Build for production
npm run build

echo "✅ Frontend built with APIM configuration"
echo "📁 Build output in: frontend/dist/"
echo ""
echo "Next steps:"
echo "1. Copy frontend/dist/* to /var/www/vulnshop/frontend/dist/ on your VM"
echo "2. Run secure-backend-for-apim.sh on your VM"
echo "3. Update nginx with APIM IPs"
EOF

chmod +x deploy-with-apim.sh

# Step 7: Documentation
echo -e "\n${YELLOW}Step 7: Creating Documentation${NC}"

cat > APIM_INTEGRATION_GUIDE.md <<EOF
# 🔗 VulnShop APIM Integration Guide

## Overview
This guide explains how VulnShop is configured to work exclusively through Azure API Management.

## Architecture

\`\`\`
[User Browser] → [APIM] → [Backend VM]
                    ↓
              [Security Policies]
              [Rate Limiting]
              [Attack Detection]
\`\`\`

## Frontend Configuration

### Environment Variables
- **Production**: \`frontend/.env.production\`
  - \`VITE_API_URL=${APIM_URL}/api\`

- **Development**: \`frontend/.env.development\`
  - Can use APIM or local backend

### Building for Production
\`\`\`bash
cd frontend
npm install
npm run build:production
\`\`\`

## Backend Security

The backend is configured to:
1. **Only accept requests from APIM IPs**
2. **Return 403 for direct access attempts**
3. **Include APIM endpoint in error messages**

### Get APIM IPs
\`\`\`bash
az apim show --name $APIM_NAME --resource-group $RESOURCE_GROUP --query 'publicIpAddresses' -o tsv
\`\`\`

### Update Nginx
Edit \`/etc/nginx/sites-available/vulnshop\`:
\`\`\`nginx
location /api/ {
    allow <APIM_IP_1>;
    allow <APIM_IP_2>;
    allow 127.0.0.1;
    deny all;
    # ... proxy configuration
}
\`\`\`

## Testing

### Test Frontend API Connection
\`\`\`bash
cd frontend
npm run test:api
\`\`\`

### Test APIM Routing
\`\`\`bash
# Should work (through APIM)
curl ${APIM_URL}/api/products

# Should fail (direct access)
curl ${BACKEND_URL}/api/products
\`\`\`

### Test Attack Detection
\`\`\`bash
# Should be blocked
curl "${APIM_URL}/api/products?q=' OR '1'='1"
\`\`\`

## Deployment Steps

1. **Configure APIM**
   - Apply security policy
   - Set backend URL
   - Configure CORS

2. **Build Frontend**
   \`\`\`bash
   ./deploy-with-apim.sh
   \`\`\`

3. **Secure Backend**
   - Copy \`secure-backend-for-apim.sh\` to VM
   - Run with APIM IPs
   - Update nginx configuration

4. **Verify**
   - Frontend loads from VM
   - API calls go through APIM
   - Direct backend access is blocked

## Troubleshooting

### CORS Issues
Ensure APIM policy includes:
\`\`\`xml
<cors allow-credentials="false">
    <allowed-origins>
        <origin>*</origin>
    </allowed-origins>
</cors>
\`\`\`

### 404 Errors
Check:
- APIM API suffix: \`/vulnshop\`
- Backend URL in APIM settings
- Frontend API URL configuration

### Direct Access Still Works
Verify:
- Nginx configuration updated
- Nginx reloaded
- NSG rules blocking port 3001
EOF

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}✅ APIM Integration Configuration Complete!${NC}"
echo -e "${GREEN}========================================${NC}"

echo -e "\n${BLUE}📋 Next Steps:${NC}"
echo "1. Run: ${YELLOW}./configure-apim.sh${NC} to see APIM configuration commands"
echo "2. Run: ${YELLOW}./deploy-with-apim.sh${NC} to build frontend for APIM"
echo "3. Copy ${YELLOW}secure-backend-for-apim.sh${NC} to your VM and run it"
echo "4. Test with: ${YELLOW}curl ${APIM_URL}/api/products${NC}"

echo -e "\n${BLUE}📚 Documentation:${NC}"
echo "See ${YELLOW}APIM_INTEGRATION_GUIDE.md${NC} for complete details" 