#!/bin/bash

# check-apim-traffic.sh - Verify Azure API Management traffic routing and attack detection

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔍 Azure API Management Traffic Verification Script${NC}"
echo -e "${BLUE}=================================================${NC}"

# Get APIM URL from user
if [ -z "$1" ]; then
    echo "Usage: ./check-apim-traffic.sh <your-apim-url>"
    echo "Example: ./check-apim-traffic.sh https://my-apim.azure-api.net/vulnshop"
    exit 1
fi

APIM_URL=$1

echo -e "\n${YELLOW}1. Testing Basic Connectivity${NC}"
echo "Testing: $APIM_URL/api/products"
response=$(curl -s -o /dev/null -w "%{http_code}" "$APIM_URL/api/products")
if [ "$response" = "200" ]; then
    echo -e "${GREEN}✓ API is accessible through APIM (HTTP $response)${NC}"
else
    echo -e "${RED}✗ API returned HTTP $response${NC}"
fi

echo -e "\n${YELLOW}2. Checking APIM Headers${NC}"
echo "Looking for Azure-specific headers..."
headers=$(curl -s -I "$APIM_URL/api/products")

if echo "$headers" | grep -q "X-Azure-RequestId"; then
    echo -e "${GREEN}✓ X-Azure-RequestId header found - Traffic is going through APIM${NC}"
    echo "$headers" | grep "X-Azure-RequestId"
else
    echo -e "${RED}✗ X-Azure-RequestId header not found${NC}"
fi

if echo "$headers" | grep -q "X-Request-ID"; then
    echo -e "${GREEN}✓ X-Request-ID header found${NC}"
    echo "$headers" | grep "X-Request-ID"
fi

echo -e "\n${YELLOW}3. Testing Security Headers${NC}"
security_headers=("X-Content-Type-Options" "X-Frame-Options" "X-XSS-Protection" "Strict-Transport-Security")
for header in "${security_headers[@]}"; do
    if echo "$headers" | grep -q "$header"; then
        echo -e "${GREEN}✓ $header is present${NC}"
    else
        echo -e "${RED}✗ $header is missing${NC}"
    fi
done

echo -e "\n${YELLOW}4. Testing Attack Detection${NC}"

# Test SQL Injection Detection
echo -e "\n${BLUE}Testing SQL Injection blocking...${NC}"
sql_response=$(curl -s -o /dev/null -w "%{http_code}" "$APIM_URL/api/products?q=' OR '1'='1")
if [ "$sql_response" = "403" ]; then
    echo -e "${GREEN}✓ SQL injection attempt blocked (HTTP $sql_response)${NC}"
else
    echo -e "${RED}✗ SQL injection not blocked (HTTP $sql_response)${NC}"
fi

# Test XSS Detection
echo -e "\n${BLUE}Testing XSS blocking...${NC}"
xss_response=$(curl -s -o /dev/null -w "%{http_code}" "$APIM_URL/api/products?q=<script>alert('xss')</script>")
if [ "$xss_response" = "403" ]; then
    echo -e "${GREEN}✓ XSS attempt blocked (HTTP $xss_response)${NC}"
else
    echo -e "${RED}✗ XSS not blocked (HTTP $xss_response)${NC}"
fi

# Test Scanner Detection
echo -e "\n${BLUE}Testing scanner detection...${NC}"
scanner_response=$(curl -s -o /dev/null -w "%{http_code}" -H "User-Agent: sqlmap/1.0" "$APIM_URL/api/products")
if [ "$scanner_response" = "403" ]; then
    echo -e "${GREEN}✓ Scanner user-agent blocked (HTTP $scanner_response)${NC}"
else
    echo -e "${RED}✗ Scanner not blocked (HTTP $scanner_response)${NC}"
fi

echo -e "\n${YELLOW}5. Testing Rate Limiting${NC}"
echo "Sending 10 rapid requests..."
blocked=0
for i in {1..10}; do
    rate_response=$(curl -s -o /dev/null -w "%{http_code}" "$APIM_URL/api/products")
    if [ "$rate_response" = "429" ]; then
        blocked=$((blocked + 1))
    fi
done

if [ $blocked -gt 0 ]; then
    echo -e "${GREEN}✓ Rate limiting is active ($blocked requests blocked)${NC}"
else
    echo -e "${YELLOW}⚠ Rate limiting might not be configured${NC}"
fi

echo -e "\n${YELLOW}6. Response Time Analysis${NC}"
time_total=$(curl -s -o /dev/null -w "%{time_total}" "$APIM_URL/api/products")
echo -e "Total response time: ${BLUE}${time_total}s${NC}"

echo -e "\n${YELLOW}7. Testing Error Handling${NC}"
error_response=$(curl -s "$APIM_URL/api/nonexistent")
if echo "$error_response" | grep -q "incident_id"; then
    echo -e "${GREEN}✓ Error responses include incident_id for tracking${NC}"
else
    echo -e "${YELLOW}⚠ Error responses might not include tracking IDs${NC}"
fi

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Traffic Verification Complete!${NC}"
echo -e "${GREEN}========================================${NC}"

echo -e "\n${BLUE}Next Steps:${NC}"
echo "1. Check Azure Portal → APIM → Analytics for request logs"
echo "2. Go to Application Insights → Logs for detailed queries"
echo "3. Set up Log Analytics workspace for long-term storage"
echo "4. Configure alerts for attack patterns"

echo -e "\n${BLUE}Useful Azure CLI Commands:${NC}"
echo "# View recent APIM logs:"
echo "az monitor log-analytics query \\"
echo "  --workspace <workspace-id> \\"
echo "  --analytics-query \"ApiManagementGatewayLogs | where TimeGenerated > ago(1h)\" \\"
echo "  --output table"

echo -e "\n${BLUE}Documentation:${NC}"
echo "Full observability guide: ./APIM_OBSERVABILITY.md" 