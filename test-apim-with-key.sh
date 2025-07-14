#!/bin/bash

# test-apim-with-key.sh - Test APIM with optional subscription key

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Your APIM details
APIM_NAME="apim-vulnshop-t7up5q"
APIM_URL="https://${APIM_NAME}.azure-api.net/vulnshop"
DIRECT_URL="http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com"
RESOURCE_GROUP="rg-vulnshop-t7up5q"

# Get subscription key if needed
SUBSCRIPTION_KEY="${1:-}"

echo -e "${BLUE}🔍 Testing Azure API Management${NC}"
echo -e "${BLUE}================================${NC}"

# Function to test endpoint
test_endpoint() {
    local url=$1
    local description=$2
    local use_key=${3:-false}
    
    echo -n "Testing $description... "
    
    if [ "$use_key" = true ] && [ -n "$SUBSCRIPTION_KEY" ]; then
        status=$(curl -s -o /dev/null -w "%{http_code}" -H "Ocp-Apim-Subscription-Key: $SUBSCRIPTION_KEY" "$url")
    else
        status=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    fi
    
    if [ "$status" = "200" ]; then
        echo -e "${GREEN}✓ Success (HTTP $status)${NC}"
        return 0
    elif [ "$status" = "401" ]; then
        echo -e "${RED}✗ Unauthorized (HTTP $status) - Subscription key required${NC}"
        return 1
    elif [ "$status" = "403" ]; then
        echo -e "${GREEN}✓ Blocked as expected (HTTP $status)${NC}"
        return 0
    elif [ "$status" = "000" ]; then
        echo -e "${RED}✗ No connection (HTTP $status)${NC}"
        return 1
    else
        echo -e "${RED}✗ Failed (HTTP $status)${NC}"
        return 1
    fi
}

# Step 1: Check if subscription is required
echo -e "\n${YELLOW}Step 1: Checking subscription requirement${NC}"
test_endpoint "${APIM_URL}/api/products" "APIM products endpoint (no key)" false

if [ $? -eq 1 ]; then
    echo -e "\n${YELLOW}APIM requires subscription key!${NC}"
    
    if [ -z "$SUBSCRIPTION_KEY" ]; then
        echo -e "\n${BLUE}To get your subscription key:${NC}"
        echo "1. Go to Azure Portal"
        echo "2. Navigate to: API Management services → $APIM_NAME"
        echo "3. Subscriptions → Add subscription"
        echo "4. Name: 'test-subscription'"
        echo "5. Product: 'VulnShop Product'"
        echo "6. Create and copy the Primary Key"
        echo ""
        echo "Then run: ./test-apim-with-key.sh YOUR_KEY_HERE"
        echo ""
        echo -e "${YELLOW}Or disable subscription requirement:${NC}"
        echo "Run: ./disable-apim-subscription.sh"
        exit 1
    else
        echo -e "\n${YELLOW}Testing with subscription key${NC}"
        test_endpoint "${APIM_URL}/api/products" "APIM products endpoint (with key)" true
    fi
fi

# Step 2: Test direct backend access
echo -e "\n${YELLOW}Step 2: Testing direct backend access${NC}"
test_endpoint "${DIRECT_URL}/api/products" "Direct backend access" false

# Step 3: Get subscription key programmatically (if logged into Azure)
echo -e "\n${YELLOW}Step 3: Getting subscription key from Azure${NC}"
if command -v az &> /dev/null && az account show &> /dev/null 2>&1; then
    echo "Checking for existing subscriptions..."
    
    # List subscriptions
    subscriptions=$(az apim subscription list \
        --resource-group $RESOURCE_GROUP \
        --service-name $APIM_NAME \
        --query "[?productId=='/products/vulnshop'].{name:name, state:state}" \
        -o table 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        echo "$subscriptions"
        
        # Get first active subscription key
        first_key=$(az apim subscription list \
            --resource-group $RESOURCE_GROUP \
            --service-name $APIM_NAME \
            --query "[?productId=='/products/vulnshop' && state=='active'].primaryKey | [0]" \
            -o tsv 2>/dev/null)
        
        if [ -n "$first_key" ] && [ "$first_key" != "null" ]; then
            echo -e "${GREEN}Found subscription key!${NC}"
            echo "Testing with found key..."
            test_endpoint "${APIM_URL}/api/products" "APIM with auto-discovered key" true
        fi
    fi
else
    echo "Azure CLI not available or not logged in"
fi

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Testing Complete!${NC}"
echo -e "${GREEN}========================================${NC}" 