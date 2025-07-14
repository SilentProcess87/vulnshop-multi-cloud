# test-auth-issue.ps1 - Test authentication issue

$APIM_URL = "https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"
$KEY = "8722910157d34e698f969cf34c30eeb5"
$headers = @{"Ocp-Apim-Subscription-Key" = $KEY}

Write-Host "Testing Authentication Issue" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan

# Test 1: Direct request (like diagnose-apim.ps1)
Write-Host "`nTest 1: Direct request with subscription key"
try {
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/products" `
        -Headers @{"Ocp-Apim-Subscription-Key" = $KEY} `
        -UseBasicParsing
    Write-Host "[SUCCESS] HTTP $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "[FAILED] HTTP $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}

# Test 2: Using variable headers (like advanced-attacks.ps1)
Write-Host "`nTest 2: Using headers variable"
try {
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/products" `
        -Headers $headers `
        -UseBasicParsing
    Write-Host "[SUCCESS] HTTP $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "[FAILED] HTTP $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}

# Test 3: Clone headers (like advanced-attacks.ps1 Execute-Attack)
Write-Host "`nTest 3: Using cloned headers"
$attackHeaders = $headers.Clone()
try {
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/products" `
        -Headers $attackHeaders `
        -UseBasicParsing
    Write-Host "[SUCCESS] HTTP $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "[FAILED] HTTP $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}

# Test 4: Check what's in the headers
Write-Host "`nHeader contents:"
Write-Host "Original headers: $($headers | ConvertTo-Json)"
Write-Host "Cloned headers: $($attackHeaders | ConvertTo-Json)"

# Test 5: Test the actual APIM policy behavior
Write-Host "`n=== Testing APIM Policy Behavior ===" -ForegroundColor Red

# Without key
Write-Host "`nWithout subscription key:"
try {
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/products" -UseBasicParsing
    Write-Host "[UNEXPECTED] HTTP $($response.StatusCode)" -ForegroundColor Red
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "[EXPECTED] HTTP $status - Should be 401" -ForegroundColor Green
}

# With wrong key
Write-Host "`nWith wrong subscription key:"
try {
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/products" `
        -Headers @{"Ocp-Apim-Subscription-Key" = "wrong-key-123"} `
        -UseBasicParsing
    Write-Host "[UNEXPECTED] HTTP $($response.StatusCode)" -ForegroundColor Red
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "[EXPECTED] HTTP $status" -ForegroundColor Green
}

# Check if APIM has changed behavior
Write-Host "`n=== Checking Current APIM State ===" -ForegroundColor Red

# Test SQL injection with correct key
Write-Host "`nSQL injection with correct key:"
try {
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/products?search=' OR '1'='1" `
        -Headers @{"Ocp-Apim-Subscription-Key" = $KEY} `
        -UseBasicParsing
    Write-Host "[SUCCESS] HTTP $($response.StatusCode) - SQL injection not blocked!" -ForegroundColor Yellow
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "[BLOCKED] HTTP $status" -ForegroundColor Green
} 