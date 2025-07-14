#!/bin/bash

# disable-apim-subscription.sh - Disable subscription requirement for VulnShop API

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔧 Disabling APIM Subscription Requirement${NC}"
echo -e "${BLUE}===========================================${NC}"

APIM_NAME="apim-vulnshop-t7up5q"
RESOURCE_GROUP="rg-vulnshop-t7up5q"

# Method 1: Using Azure CLI
echo -e "\n${YELLOW}Option 1: Using Azure CLI${NC}"
echo -e "Run this command to disable subscription requirement:"
echo -e "${GREEN}az apim product update \\
  --resource-group $RESOURCE_GROUP \\
  --service-name $APIM_NAME \\
  --product-id vulnshop \\
  --subscription-required false${NC}"

# Method 2: Using Azure Portal
echo -e "\n${YELLOW}Option 2: Using Azure Portal${NC}"
echo "1. Go to Azure Portal"
echo "2. Navigate to: API Management services → $APIM_NAME"
echo "3. Products → VulnShop Product"
echo "4. Settings → Uncheck 'Requires subscription'"
echo "5. Save"

echo -e "\n${YELLOW}Option 3: API-Level Setting${NC}"
echo "1. APIs → VulnShop API → Settings"
echo "2. Subscription → Uncheck 'Subscription required'"
echo "3. Save"

echo -e "\n${BLUE}After disabling subscription requirement:${NC}"
echo "Your tests should work without authentication"
echo "Example: curl https://$APIM_NAME.azure-api.net/vulnshop/api/products" 