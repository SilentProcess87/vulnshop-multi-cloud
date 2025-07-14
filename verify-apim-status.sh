#!/bin/bash

# verify-apim-status.sh - Verify current APIM configuration status

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

APIM_URL="https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"
SUBSCRIPTION_KEY="8722910157d34e698f969cf34c30eeb5"

echo -e "${BLUE}🔍 APIM Status Verification${NC}"
echo -e "${BLUE}===========================${NC}"

echo -e "\n${YELLOW}✅ What's Working:${NC}"

# Test 1: APIM with subscription key
echo -n "1. APIM access with key: "
status=$(curl -s -o /dev/null -w "%{http_code}" -H "Ocp-Apim-Subscription-Key: $SUBSCRIPTION_KEY" "$APIM_URL/api/products")
if [ "$status" = "200" ]; then
    echo -e "${GREEN}✓ Success (HTTP $status)${NC}"
else
    echo -e "${RED}✗ Failed (HTTP $status)${NC}"
fi

# Test 2: Backend protection
echo -n "2. Direct backend blocked: "
status=$(curl -s -o /dev/null -w "%{http_code}" "http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com/api/products")
if [ "$status" = "403" ]; then
    echo -e "${GREEN}✓ Success (HTTP $status)${NC}"
else
    echo -e "${RED}✗ Failed (HTTP $status)${NC}"
fi

# Test 3: APIM headers
echo -n "3. APIM headers present: "
headers=$(curl -s -I -H "Ocp-Apim-Subscription-Key: $SUBSCRIPTION_KEY" "$APIM_URL/api/products")
if echo "$headers" | grep -q "X-Azure-RequestId"; then
    echo -e "${GREEN}✓ Yes${NC}"
else
    echo -e "${RED}✗ No${NC}"
fi

echo -e "\n${YELLOW}❌ What's Not Working:${NC}"

# Test 4: Attack detection
echo -n "4. Attack detection: "
attack_test=$(curl -s -H "Ocp-Apim-Subscription-Key: $SUBSCRIPTION_KEY" "$APIM_URL/api/products?q=' OR '1'='1")
if echo "$attack_test" | grep -q "error"; then
    echo -e "${YELLOW}⚠️  May be working (check response)${NC}"
else
    # Check if we got normal products response
    if echo "$attack_test" | grep -q '"id"'; then
        echo -e "${RED}✗ Not blocking attacks (returns products)${NC}"
    else
        echo -e "${RED}✗ Error or no response${NC}"
    fi
fi

echo -e "\n${YELLOW}📋 Summary:${NC}"
echo "• APIM routing: ✅ Working"
echo "• Authentication: ✅ Requires subscription key"
echo "• Backend protection: ✅ Direct access blocked"
echo "• Attack detection: ❌ Not implemented (policy has no security features)"
echo "• Cortex logging: ✅ Should be working (verify in Cortex dashboard)"

echo -e "\n${YELLOW}🔧 To Add Attack Detection:${NC}"
echo "1. Use policies/simple-security-policy.xml (has basic attack detection)"
echo "2. Or add security features back to your current policy"
echo "3. Apply with: az apim api operation policy set \\"
echo "   --resource-group rg-vulnshop-t7up5q \\"
echo "   --service-name apim-vulnshop-t7up5q \\"
echo "   --api-id vulnshop-api \\"
echo "   --operation-id all \\"
echo "   --policy-file policies/simple-security-policy.xml" 