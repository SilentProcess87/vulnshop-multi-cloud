# test-apim-attacks.ps1 - Test why attacks are getting HTTP 000

$APIM_URL = "https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"
$SUBSCRIPTION_KEY = "8722910157d34e698f969cf34c30eeb5"

Write-Host "`n🔍 Testing APIM Attack Handling" -ForegroundColor Blue
Write-Host "================================" -ForegroundColor Blue

# Test 1: Normal request
Write-Host "`n✅ Test 1: Normal request" -ForegroundColor Green
try {
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/products" `
        -Headers @{ "Ocp-Apim-Subscription-Key" = $SUBSCRIPTION_KEY } `
        -UseBasicParsing
    Write-Host "Status: $($response.StatusCode) - Success!" -ForegroundColor Green
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Test 2: URL encoded attack
Write-Host "`n🔍 Test 2: URL encoded SQL injection" -ForegroundColor Yellow
$encodedPayload = [System.Web.HttpUtility]::UrlEncode("' OR '1'='1")
try {
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/products?search=$encodedPayload" `
        -Headers @{ "Ocp-Apim-Subscription-Key" = $SUBSCRIPTION_KEY } `
        -UseBasicParsing
    Write-Host "Status: $($response.StatusCode)" -ForegroundColor Green
    Write-Host "Response: $($response.Content.Substring(0, [Math]::Min(200, $response.Content.Length)))..." -ForegroundColor Gray
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    if ($_.Exception.Response) {
        Write-Host "HTTP Status: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Yellow
    }
}

# Test 3: Simple attack without special chars
Write-Host "`n🔍 Test 3: Simple SQL injection (no quotes)" -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/products?search=laptop OR 1=1" `
        -Headers @{ "Ocp-Apim-Subscription-Key" = $SUBSCRIPTION_KEY } `
        -UseBasicParsing
    Write-Host "Status: $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Test 4: XSS attack
Write-Host "`n🔍 Test 4: XSS attack" -ForegroundColor Yellow
$xssPayload = [System.Web.HttpUtility]::UrlEncode("<script>alert('XSS')</script>")
try {
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/products?search=$xssPayload" `
        -Headers @{ "Ocp-Apim-Subscription-Key" = $SUBSCRIPTION_KEY } `
        -UseBasicParsing
    Write-Host "Status: $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Test 5: POST with JSON attack
Write-Host "`n🔍 Test 5: POST JSON attack" -ForegroundColor Yellow
try {
    $body = '{"username": "admin", "password": "admin123"}'
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/login" `
        -Method POST `
        -Headers @{ 
            "Ocp-Apim-Subscription-Key" = $SUBSCRIPTION_KEY
            "Content-Type" = "application/json"
        } `
        -Body $body `
        -UseBasicParsing
    Write-Host "Status: $($response.StatusCode) - Login succeeded!" -ForegroundColor Green
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    if ($_.Exception.Response) {
        Write-Host "HTTP Status: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Yellow
    }
}

# Test 6: Check if APIM is dropping requests
Write-Host "`n🔍 Test 6: Testing APIM request handling" -ForegroundColor Yellow
Write-Host "Testing with bash curl to see raw response..." -ForegroundColor Cyan

# Use bash to get more details
$curlCommand = 'curl -v -H "Ocp-Apim-Subscription-Key: ' + $SUBSCRIPTION_KEY + '" "' + $APIM_URL + '/api/products?search=%27%20OR%20%271%27%3D%271" 2>&1'

Write-Host "`nRunning: $curlCommand" -ForegroundColor Gray
bash -c $curlCommand

Write-Host "`n📋 Summary:" -ForegroundColor Blue
Write-Host "If you are seeing HTTP 000, it could be because:" -ForegroundColor Yellow
Write-Host "1. APIM is dropping malformed requests before they reach the backend"
Write-Host "2. The minimal policy needs adjustment"
Write-Host "3. WSL/bash is having issues with the APIM URL"
Write-Host "4. Network/firewall is blocking certain payloads" 