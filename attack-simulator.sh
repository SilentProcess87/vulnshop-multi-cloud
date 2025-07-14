#!/bin/bash

# attack-simulator.sh - Simulate various attacks against VulnShop for security testing

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

# Get target from command line
TARGET="${1:-apim}"
if [ "$TARGET" = "local" ]; then
    BASE_URL="$LOCAL_URL"
    echo -e "${YELLOW}🎯 Target: Local Backend (http://localhost:3001)${NC}"
    AUTH_HEADER=""
else
    BASE_URL="$APIM_URL"
    echo -e "${YELLOW}🎯 Target: Azure API Management${NC}"
    AUTH_HEADER="-H \"Ocp-Apim-Subscription-Key: $SUBSCRIPTION_KEY\""
fi

echo -e "${RED}⚠️  SECURITY TESTING - FOR AUTHORIZED USE ONLY${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Attack counter
ATTACK_COUNT=0

# Function to execute attack
execute_attack() {
    local attack_type=$1
    local endpoint=$2
    local description=$3
    local payload=$4
    local method="${5:-GET}"
    
    ATTACK_COUNT=$((ATTACK_COUNT + 1))
    
    echo -e "\n${PURPLE}Attack #$ATTACK_COUNT: $attack_type${NC}"
    echo -e "Description: $description"
    echo -e "Endpoint: $endpoint"
    echo -e "Payload: $payload"
    echo -n "Status: "
    
    if [ "$method" = "POST" ]; then
        if [ "$TARGET" = "local" ]; then
            response=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
                -H "Content-Type: application/json" \
                -d "$payload" \
                "$BASE_URL$endpoint")
        else
            response=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
                -H "Content-Type: application/json" \
                -H "Ocp-Apim-Subscription-Key: $SUBSCRIPTION_KEY" \
                -d "$payload" \
                "$BASE_URL$endpoint")
        fi
    else
        if [ "$TARGET" = "local" ]; then
            response=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL$endpoint")
        else
            response=$(curl -s -o /dev/null -w "%{http_code}" \
                -H "Ocp-Apim-Subscription-Key: $SUBSCRIPTION_KEY" \
                "$BASE_URL$endpoint")
        fi
    fi
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓ Blocked (HTTP $response)${NC}"
    elif [ "$response" = "200" ] || [ "$response" = "201" ]; then
        echo -e "${RED}✗ Allowed (HTTP $response) - Vulnerability may be exploitable${NC}"
    else
        echo -e "${YELLOW}⚠ HTTP $response${NC}"
    fi
    
    # Add small delay to avoid overwhelming the server
    sleep 0.5
}

echo -e "${YELLOW}Starting attack simulation...${NC}"

# =============================================================================
# SQL INJECTION ATTACKS
# =============================================================================
echo -e "\n${RED}═══ SQL INJECTION ATTACKS ═══${NC}"

execute_attack "SQL Injection" \
    "/api/products?search=' OR '1'='1" \
    "Classic SQL injection in search" \
    "' OR '1'='1"

execute_attack "SQL Injection" \
    "/api/products?search='; SELECT * FROM sqlite_master; --" \
    "Information disclosure via SQL injection" \
    "'; SELECT * FROM sqlite_master; --"

execute_attack "SQL Injection" \
    "/api/products?search=' UNION SELECT * FROM users--" \
    "Union-based SQL injection" \
    "' UNION SELECT * FROM users--"

execute_attack "SQL Injection" \
    "/api/products?search=1' AND (SELECT COUNT(*) FROM users) > 0--" \
    "Blind SQL injection" \
    "1' AND (SELECT COUNT(*) FROM users) > 0--"

# =============================================================================
# XSS ATTACKS
# =============================================================================
echo -e "\n${RED}═══ CROSS-SITE SCRIPTING (XSS) ATTACKS ═══${NC}"

execute_attack "XSS" \
    "/api/products?search=<script>alert('XSS')</script>" \
    "Basic script tag XSS" \
    "<script>alert('XSS')</script>"

execute_attack "XSS" \
    "/api/products?search=<img src=x onerror=alert('XSS')>" \
    "Image tag XSS" \
    "<img src=x onerror=alert('XSS')>"

execute_attack "XSS" \
    "/api/products?search=javascript:alert('XSS')" \
    "JavaScript protocol XSS" \
    "javascript:alert('XSS')"

execute_attack "XSS" \
    "/api/reviews" \
    "Stored XSS in review" \
    '{"productId": 1, "rating": 5, "comment": "<script>alert(document.cookie)</script>"}' \
    "POST"

# =============================================================================
# COMMAND INJECTION ATTACKS
# =============================================================================
echo -e "\n${RED}═══ COMMAND INJECTION ATTACKS ═══${NC}"

execute_attack "Command Injection" \
    "/api/products?search=; ls -la" \
    "Basic command injection" \
    "; ls -la"

execute_attack "Command Injection" \
    "/api/products?search=| whoami" \
    "Pipe command injection" \
    "| whoami"

execute_attack "Command Injection" \
    "/api/products?search=\`cat /etc/passwd\`" \
    "Backtick command injection" \
    "\`cat /etc/passwd\`"

# =============================================================================
# PATH TRAVERSAL ATTACKS
# =============================================================================
echo -e "\n${RED}═══ PATH TRAVERSAL ATTACKS ═══${NC}"

execute_attack "Path Traversal" \
    "/api/files/../../../../etc/passwd" \
    "Linux path traversal" \
    "../../../../etc/passwd"

execute_attack "Path Traversal" \
    "/api/download?file=..\\..\\..\\..\\windows\\system32\\config\\sam" \
    "Windows path traversal" \
    "..\\..\\..\\..\\windows\\system32\\config\\sam"

execute_attack "Path Traversal" \
    "/api/images/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd" \
    "URL encoded path traversal" \
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# =============================================================================
# IDOR ATTACKS
# =============================================================================
echo -e "\n${RED}═══ INSECURE DIRECT OBJECT REFERENCE (IDOR) ATTACKS ═══${NC}"

execute_attack "IDOR" \
    "/api/orders/1" \
    "Access another user's order" \
    "Attempting to access order ID 1"

execute_attack "IDOR" \
    "/api/users/2/profile" \
    "Access another user's profile" \
    "Attempting to access user ID 2"

execute_attack "IDOR" \
    "/api/admin/users" \
    "Access admin endpoint without authorization" \
    "Attempting admin access"

# =============================================================================
# AUTHENTICATION ATTACKS
# =============================================================================
echo -e "\n${RED}═══ AUTHENTICATION ATTACKS ═══${NC}"

execute_attack "Brute Force" \
    "/api/login" \
    "Login brute force attempt" \
    '{"username": "admin", "password": "password"}' \
    "POST"

execute_attack "Credential Stuffing" \
    "/api/login" \
    "Common credential attempt" \
    '{"username": "admin", "password": "admin123"}' \
    "POST"

execute_attack "JWT Manipulation" \
    "/api/profile" \
    "Attempting with weak JWT secret" \
    "Using manipulated JWT token"

# =============================================================================
# API ABUSE ATTACKS
# =============================================================================
echo -e "\n${RED}═══ API ABUSE ATTACKS ═══${NC}"

execute_attack "Mass Assignment" \
    "/api/register" \
    "Attempting to set admin role during registration" \
    '{"username": "attacker", "email": "attacker@evil.com", "password": "password", "role": "admin"}' \
    "POST"

execute_attack "Large Payload" \
    "/api/products" \
    "Sending oversized payload" \
    '{"name": "'$(python3 -c "print('A' * 10000)")'" }' \
    "POST"

# =============================================================================
# SCANNER DETECTION
# =============================================================================
echo -e "\n${RED}═══ VULNERABILITY SCANNER DETECTION ═══${NC}"

# SQLMap user agent
if [ "$TARGET" = "local" ]; then
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "User-Agent: sqlmap/1.4.7#stable (http://sqlmap.org)" \
        "$BASE_URL/api/products")
else
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "User-Agent: sqlmap/1.4.7#stable (http://sqlmap.org)" \
        -H "Ocp-Apim-Subscription-Key: $SUBSCRIPTION_KEY" \
        "$BASE_URL/api/products")
fi

echo -e "\n${PURPLE}Attack #$((++ATTACK_COUNT)): Scanner Detection${NC}"
echo "Description: SQLMap scanner user agent"
echo -n "Status: "
if [ "$response" = "403" ]; then
    echo -e "${GREEN}✓ Blocked (HTTP $response)${NC}"
else
    echo -e "${RED}✗ Allowed (HTTP $response)${NC}"
fi

# =============================================================================
# SUMMARY
# =============================================================================
echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}        ATTACK SIMULATION COMPLETE      ${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "\nTotal attacks executed: ${ATTACK_COUNT}"
echo -e "\n${YELLOW}📊 Results Summary:${NC}"
echo "• Check your APIM Analytics for attack patterns"
echo "• Review Cortex logs for detailed attack data"
echo "• Monitor for blocked vs allowed requests"

if [ "$TARGET" != "local" ]; then
    echo -e "\n${YELLOW}🔍 View in Azure Portal:${NC}"
    echo "1. Go to APIM → Analytics → Requests"
    echo "2. Filter by status code 403 for blocked attacks"
    echo "3. Check Diagnostic Logs for attack details"
fi

echo -e "\n${GREEN}✅ Attack simulation completed!${NC}" 