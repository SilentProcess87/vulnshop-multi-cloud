!/bin/bash

# Quick fix script for VulnShop deployment issues
set -e

echo "🔧 Running quick fixes for VulnShop deployment..."

# Change to the correct directory
cd /var/www/vulnshop

# Set ownership to www-data
echo -e "${GREEN}Step 1: Setting file ownership...${NC}"
sudo chown -R www-data:www-data /var/www/vulnshop

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
rm -f ./vulnshop.db
chmod -R 777 .
rm -rf node_modules package-lock.json
npm install --production

# Step 5: Clean install and build frontend
# The user's provided snippet was incomplete. Assuming this is what it should be.
cd /var/www/vulnshop/frontend
rm -rf node_modules package-lock.json

# Create .env file with APIM URL
echo "VITE_API_URL=https://apim-vulnshop-t7up5q.azure-api.net/api" > .env
echo "Created .env file with APIM endpoint."

npm install
npm run build

# Step 6: Restart Nginx
echo -e "${GREEN}Step 5: Restarting Nginx...${NC}"
sudo systemctl restart nginx

# Step 7: Start backend with PM2 
echo -e "${GREEN}Step 6: Starting backend with PM2...${NC}"
cd /var/www/vulnshop/backend
pm2 start server.js --name vulnshop-backend --force 

# Step 8: Save PM2 process list
echo -e "${GREEN}Step 7: Saving PM2 process list...${NC}"
cd /var/www/vulnshop
pm2 save

# Step 9: Update Azure API Management
echo -e "${GREEN}Step 8: Updating Azure API Management...${NC}"

# Check for Azure CLI and install if not present
if ! [ -x "$(command -v az)" ]; then
    echo -e "${YELLOW}Azure CLI not found. Installing now...${NC}"
    curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
fi

# # Azure login is required to query resource details
# echo -e "${YELLOW}Please log in to Azure...${NC}"
# az login

# Discover APIM instance dynamically
echo "Discovering Azure APIM instance..."
APIM_DETAILS=$(az apim list --query "[?contains(name, 'apim-vulnshop')].[name,resourceGroup]" -o tsv)

if [ -z "$APIM_DETAILS" ]; then
    echo -e "${RED}ERROR: Could not find any APIM service containing 'apim-vulnshop'. Please check the name and your Azure subscription.${NC}"
    exit 1
fi

if [ $(echo "$APIM_DETAILS" | wc -l) -gt 1 ]; then
    echo -e "${YELLOW}WARNING: Found multiple APIM services containing 'apim-vulnshop'. Using the first one.${NC}"
    APIM_DETAILS=$(echo "$APIM_DETAILS" | head -n 1)
fi

APIM_NAME=$(echo "$APIM_DETAILS" | awk '{print $1}')
RESOURCE_GROUP=$(echo "$APIM_DETAILS" | awk '{print $2}')
API_ID="vulnshop-api"
API_DISPLAY_NAME="VulnShop API"
BACKEND_URL="http://$(curl -s ifconfig.me)"

echo -e "${GREEN}Discovered APIM: ${APIM_NAME} in RG: ${RESOURCE_GROUP}${NC}"


echo "Updating APIM with the latest Swagger definition..."

# Check if the API already exists to avoid "already exists" error on update
if az apim api show --resource-group "$RESOURCE_GROUP" --service-name "$APIM_NAME" --api-id "$API_ID" &> /dev/null; then
  echo "API '$API_ID' already exists. Importing changes..."
  az apim api import --specification-path /var/www/vulnshop/apim-swagger.json \
      --path "api" \
      --resource-group "$RESOURCE_GROUP" \
      --service-name "$APIM_NAME" \
      --api-id "$API_ID" \
      --service-url "$BACKEND_URL" \
      --subscription-required false \
      --specification-format OpenApi
else
  echo "API '$API_ID' does not exist. Creating new API..."
  az apim api import --specification-path /var/www/vulnshop/apim-swagger.json \
      --path "api" \
      --resource-group "$RESOURCE_GROUP" \
      --service-name "$APIM_NAME" \
      --api-id "$API_ID" \
      --display-name "$API_DISPLAY_NAME" \
      --service-url "$BACKEND_URL" \
      --subscription-required false \
      --specification-format OpenApi
fi

# echo "Applying OWASP Top 10 policy..."
# az apim api policy import --path /var/www/vulnshop/policies/owasp-top10-protection.xml \
#     --resource-group $RESOURCE_GROUP \
#     --service-name $APIM_NAME \
#     --api-id $API_ID

# Step 10: Verify everything is working
echo -e "${GREEN}Step 9: Verifying deployment...${NC}"
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