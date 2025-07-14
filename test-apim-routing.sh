#!/bin/bash

# test-apim-routing.sh - Test APIM routing and security features

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

echo -e "${BLUE}🔍 Testing Azure API Management Routing & Security${NC}"
echo -e "${BLUE}=================================================${NC}"

# Test 1: Direct Access (Should work currently, but we'll fix this)
echo -e "\n${YELLOW}Test 1: Direct Backend Access${NC}"
echo "Testing: ${DIRECT_URL}/api/products"
direct_response=$(curl -s -o /dev/null -w "%{http_code}" "${DIRECT_URL}/api/products")
if [ "$direct_response" = "200" ]; then
    echo -e "${RED}⚠️  Direct access is OPEN (HTTP $direct_response) - This needs to be blocked!${NC}"
else
    echo -e "${GREEN}✓ Direct access is blocked (HTTP $direct_response)${NC}"
fi

# Test 2: APIM Access
echo -e "\n${YELLOW}Test 2: APIM Access${NC}"
echo "Testing: ${APIM_URL}/api/products"
apim_response=$(curl -s -i "${APIM_URL}/api/products")
apim_code=$(echo "$apim_response" | grep "HTTP" | awk '{print $2}')

if [ "$apim_code" = "200" ]; then
    echo -e "${GREEN}✓ APIM access successful (HTTP $apim_code)${NC}"
    
    # Check for APIM headers
    if echo "$apim_response" | grep -q "X-Azure-RequestId"; then
        echo -e "${GREEN}✓ X-Azure-RequestId header present${NC}"
    else
        echo -e "${RED}✗ X-Azure-RequestId header missing${NC}"
    fi
    
    if echo "$apim_response" | grep -q "X-Request-ID"; then
        echo -e "${GREEN}✓ X-Request-ID header present${NC}"
    else
        echo -e "${RED}✗ X-Request-ID header missing${NC}"
    fi
else
    echo -e "${RED}✗ APIM access failed (HTTP $apim_code)${NC}"
    echo "Response:"
    echo "$apim_response" | head -20
fi

# Test 3: Security Headers
echo -e "\n${YELLOW}Test 3: Security Headers${NC}"
headers=$(curl -s -I "${APIM_URL}/api/products")
security_headers=("X-Content-Type-Options" "X-Frame-Options" "X-XSS-Protection" "Strict-Transport-Security" "Content-Security-Policy")

for header in "${security_headers[@]}"; do
    if echo "$headers" | grep -qi "$header"; then
        echo -e "${GREEN}✓ $header is present${NC}"
    else
        echo -e "${RED}✗ $header is missing${NC}"
    fi
done

# Test 4: Attack Detection
echo -e "\n${YELLOW}Test 4: Attack Detection${NC}"

# SQL Injection Test
echo -e "\n${BLUE}Testing SQL Injection blocking...${NC}"
sql_test=$(curl -s "${APIM_URL}/api/products?q=' OR '1'='1")
if echo "$sql_test" | grep -q "ATTACK_BLOCKED"; then
    echo -e "${GREEN}✓ SQL injection blocked${NC}"
    echo "$sql_test" | jq -r '.attack_type, .attack_score' 2>/dev/null || echo "$sql_test"
else
    echo -e "${RED}✗ SQL injection NOT blocked${NC}"
fi

# XSS Test
echo -e "\n${BLUE}Testing XSS blocking...${NC}"
xss_test=$(curl -s "${APIM_URL}/api/products?q=<script>alert('xss')</script>")
if echo "$xss_test" | grep -q "ATTACK_BLOCKED"; then
    echo -e "${GREEN}✓ XSS attempt blocked${NC}"
    echo "$xss_test" | jq -r '.attack_type, .attack_score' 2>/dev/null || echo "$xss_test"
else
    echo -e "${RED}✗ XSS NOT blocked${NC}"
fi

# Scanner Detection
echo -e "\n${BLUE}Testing scanner detection...${NC}"
scanner_test=$(curl -s -H "User-Agent: sqlmap/1.0" "${APIM_URL}/api/products")
if echo "$scanner_test" | grep -q "ATTACK_BLOCKED"; then
    echo -e "${GREEN}✓ Scanner blocked${NC}"
    echo "$scanner_test" | jq -r '.attack_type, .attack_score' 2>/dev/null || echo "$scanner_test"
else
    echo -e "${RED}✗ Scanner NOT blocked${NC}"
fi

# Test 5: Rate Limiting
echo -e "\n${YELLOW}Test 5: Rate Limiting (100 req/min per IP)${NC}"
echo "Sending rapid requests..."
rate_limited=false
for i in {1..10}; do
    rate_response=$(curl -s -o /dev/null -w "%{http_code}" "${APIM_URL}/api/products")
    if [ "$rate_response" = "429" ]; then
        echo -e "${GREEN}✓ Rate limit triggered at request $i${NC}"
        rate_limited=true
        break
    fi
done

if [ "$rate_limited" = false ]; then
    echo -e "${YELLOW}⚠️  Rate limiting may need more requests to trigger (limit: 100/min)${NC}"
fi

# Test 6: Cortex Integration
echo -e "\n${YELLOW}Test 6: Cortex Integration${NC}"
echo "Check your Cortex dashboard for:"
echo "- Request/response logging"
echo "- Attack scores and types"
echo "- Security actions (ALLOWED/BLOCKED)"

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Testing Complete!${NC}"
echo -e "${GREEN}========================================${NC}"

echo -e "\n${BLUE}Next Steps to Secure Direct Access:${NC}"
echo "1. Update NSG to block port 3001:"
echo "   az network nsg rule create \\"
echo "     --resource-group rg-vulnshop-t7up5q \\"
echo "     --nsg-name <your-nsg-name> \\"
echo "     --name Block-Backend-Direct \\"
echo "     --priority 100 \\"
echo "     --access Deny \\"
echo "     --protocol Tcp \\"
echo "     --destination-port-ranges 3001"
echo ""
echo "2. Get APIM outbound IPs:"
echo "   az apim show --name ${APIM_NAME} \\"
echo "     --resource-group rg-vulnshop-t7up5q \\"
echo "     --query 'publicIpAddresses' -o tsv"
echo ""
echo "3. Update nginx on VM to only allow APIM IPs" 