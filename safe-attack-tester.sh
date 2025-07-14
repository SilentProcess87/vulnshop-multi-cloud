#!/bin/bash

# safe-attack-tester.sh - Non-destructive security testing for VulnShop

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
APIM_URL="https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"
LOCAL_URL="http://localhost:3001"
SUBSCRIPTION_KEY="8722910157d34e698f969cf34c30eeb5"

# Target selection
TARGET="${1:-apim}"
if [ "$TARGET" = "local" ]; then
    BASE_URL="$LOCAL_URL"
    echo -e "${YELLOW}🎯 Target: Local Backend${NC}"
else
    BASE_URL="$APIM_URL"
    echo -e "${YELLOW}🎯 Target: Azure API Management${NC}"
fi

echo -e "${GREEN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         SAFE SECURITY TESTING FOR VULNSHOP         ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}⚠️  SAFETY NOTICE:${NC}"
echo -e "• This script uses ${GREEN}NON-DESTRUCTIVE${NC} attack patterns only"
echo -e "• No DROP, DELETE, TRUNCATE, or UPDATE commands"
echo -e "• All tests are read-only or create test data only"
echo -e "• Safe for production testing (but always backup first!)"

echo -e "\n${BLUE}📊 What This Script Tests:${NC}"
echo -e "• SQL Injection (information disclosure only)"
echo -e "• XSS (alert boxes, no data theft)"
echo -e "• Authentication bypass attempts"
echo -e "• Input validation weaknesses"
echo -e "• Rate limiting effectiveness"

echo -e "\n${YELLOW}Press Enter to continue or Ctrl+C to cancel...${NC}"
read

# Function to execute safe attacks
safe_attack() {
    local attack_type=$1
    local endpoint=$2
    local description=$3
    local payload=$4
    local method=${5:-GET}
    
    echo -e "\n${PURPLE}Testing:${NC} $description"
    echo -e "${BLUE}Type:${NC} $attack_type"
    echo -e "${BLUE}Payload:${NC} $payload"
    
    if [ "$method" = "GET" ]; then
        if [ "$TARGET" = "local" ]; then
            response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$BASE_URL$endpoint")
        else
            response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" \
                -H "Ocp-Apim-Subscription-Key: $SUBSCRIPTION_KEY" \
                "$BASE_URL$endpoint")
        fi
    else
        if [ "$TARGET" = "local" ]; then
            response=$(curl -s -X "$method" \
                -H "Content-Type: application/json" \
                -d "$payload" \
                -w "\nHTTP_STATUS:%{http_code}" \
                "$BASE_URL$endpoint")
        else
            response=$(curl -s -X "$method" \
                -H "Content-Type: application/json" \
                -H "Ocp-Apim-Subscription-Key: $SUBSCRIPTION_KEY" \
                -d "$payload" \
                -w "\nHTTP_STATUS:%{http_code}" \
                "$BASE_URL$endpoint")
        fi
    fi
    
    http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
    
    if [ "$http_status" = "403" ] || [ "$http_status" = "400" ]; then
        echo -e "${GREEN}✓ Attack blocked (HTTP $http_status)${NC}"
    elif [ "$http_status" = "200" ]; then
        echo -e "${RED}⚠ Attack succeeded (HTTP $http_status) - Check if data was exposed${NC}"
    else
        echo -e "${YELLOW}⚡ Response: HTTP $http_status${NC}"
    fi
}

# =============================================================================
# SAFE SQL INJECTION TESTS (Read-only)
# =============================================================================
echo -e "\n${RED}═══ SAFE SQL INJECTION TESTS ═══${NC}"

safe_attack "SQL Injection" \
    "/api/products?search=' OR '1'='1" \
    "Classic OR 1=1 (shows all products)" \
    "' OR '1'='1"

safe_attack "SQL Injection" \
    "/api/products?search=1' AND 1=2 UNION SELECT name FROM sqlite_master WHERE type='table'--" \
    "Schema enumeration attempt" \
    "1' AND 1=2 UNION SELECT name FROM sqlite_master WHERE type='table'--"

safe_attack "SQL Injection" \
    "/api/products?search=laptop' AND price > 100--" \
    "Price filter bypass" \
    "laptop' AND price > 100--"

safe_attack "SQL Injection" \
    "/api/products?search=1' ORDER BY 10--" \
    "Column enumeration" \
    "1' ORDER BY 10--"

# =============================================================================
# SAFE XSS TESTS (Alert only)
# =============================================================================
echo -e "\n${RED}═══ SAFE XSS TESTS ═══${NC}"

safe_attack "XSS" \
    "/api/products?search=<script>alert('XSS Test')</script>" \
    "Basic script tag (alert only)" \
    "<script>alert('XSS Test')</script>"

safe_attack "XSS" \
    "/api/products?search=<img src=x onerror=alert('XSS')>" \
    "Image error XSS" \
    "<img src=x onerror=alert('XSS')>"

safe_attack "XSS" \
    "/api/reviews" \
    "Stored XSS attempt in review (creates test review)" \
    '{"productId": 1, "rating": 5, "comment": "Great product! <script>alert(1)</script>"}' \
    "POST"

# =============================================================================
# AUTHENTICATION TESTS (Non-destructive)
# =============================================================================
echo -e "\n${RED}═══ AUTHENTICATION TESTS ═══${NC}"

safe_attack "Auth Bypass" \
    "/api/login" \
    "SQL injection in login" \
    '{"username": "admin'\''--", "password": "anything"}' \
    "POST"

safe_attack "Auth Bypass" \
    "/api/login" \
    "NoSQL injection attempt" \
    '{"username": {"$ne": null}, "password": {"$ne": null}}' \
    "POST"

safe_attack "Weak Password" \
    "/api/login" \
    "Common password test" \
    '{"username": "admin", "password": "password"}' \
    "POST"

# =============================================================================
# INPUT VALIDATION TESTS
# =============================================================================
echo -e "\n${RED}═══ INPUT VALIDATION TESTS ═══${NC}"

safe_attack "Input Validation" \
    "/api/products" \
    "Negative price product (creates test product)" \
    '{"name": "Test Product", "price": -50, "description": "Should not allow negative price"}' \
    "POST"

safe_attack "Input Validation" \
    "/api/cart" \
    "Zero quantity in cart" \
    '{"productId": 1, "quantity": 0}' \
    "POST"

safe_attack "Input Validation" \
    "/api/cart" \
    "Extremely large quantity" \
    '{"productId": 1, "quantity": 999999999}' \
    "POST"

# =============================================================================
# AUTHORIZATION TESTS
# =============================================================================
echo -e "\n${RED}═══ AUTHORIZATION TESTS ═══${NC}"

safe_attack "IDOR" \
    "/api/orders/1" \
    "Access another user's order" \
    "Direct object reference"

safe_attack "IDOR" \
    "/api/users/2/profile" \
    "Access another user's profile" \
    "Direct object reference"

safe_attack "Privilege Escalation" \
    "/api/admin/users" \
    "Access admin endpoint without auth" \
    "No authentication"

# =============================================================================
# RATE LIMITING TEST
# =============================================================================
echo -e "\n${RED}═══ RATE LIMITING TEST ═══${NC}"
echo -e "${YELLOW}Sending 10 requests to test rate limiting...${NC}"

RATE_LIMITED=false
for i in {1..10}; do
    echo -ne "\r  Progress: $i/10"
    
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
    
    sleep 0.1  # Small delay to be nice
done

if [ "$RATE_LIMITED" = false ]; then
    echo -e "\n  ${YELLOW}⚡ No rate limiting detected (might have higher threshold)${NC}"
fi

# =============================================================================
# SUMMARY
# =============================================================================
echo -e "\n${GREEN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                 TEST COMPLETE                      ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════╝${NC}"

echo -e "\n${BLUE}📋 What to Check:${NC}"
echo -e "• Review Cortex logs for attack patterns"
echo -e "• Check APIM Analytics for blocked requests"
echo -e "• Verify no data was actually modified"
echo -e "• Look for any 200 responses that shouldn't succeed"

echo -e "\n${YELLOW}💡 Remember:${NC}"
echo -e "• These are SAFE, non-destructive tests"
echo -e "• Real attackers won't be this polite!"
echo -e "• Always test in a safe environment first"
echo -e "• Keep backups of your data"

echo -e "\n${GREEN}✅ Testing completed safely!${NC}" 