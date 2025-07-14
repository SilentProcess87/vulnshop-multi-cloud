# diagnose-apim.ps1 - Simple APIM diagnostic

$APIM_URL = "https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"
$KEY = "8722910157d34e698f969cf34c30eeb5"

Write-Host "Testing APIM..." -ForegroundColor Blue

# Test 1: Normal request
Write-Host "`nTest 1: Normal request"
$uri1 = "$APIM_URL/api/products"
try {
    $r1 = Invoke-WebRequest -Uri $uri1 -Headers @{"Ocp-Apim-Subscription-Key"=$KEY} -UseBasicParsing
    Write-Host "Success: $($r1.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "Failed: $_" -ForegroundColor Red
}

# Test 2: SQL injection with encoding
Write-Host "`nTest 2: SQL injection (encoded)"
Add-Type -AssemblyName System.Web
$payload = [System.Web.HttpUtility]::UrlEncode("' OR '1'='1")
$uri2 = "$APIM_URL/api/products?search=$payload"
try {
    $r2 = Invoke-WebRequest -Uri $uri2 -Headers @{"Ocp-Apim-Subscription-Key"=$KEY} -UseBasicParsing
    Write-Host "Success: $($r2.StatusCode)" -ForegroundColor Green
    Write-Host "Got $($r2.Content.Length) bytes" -ForegroundColor Gray
} catch {
    Write-Host "Failed: $_" -ForegroundColor Red
}

# Test 3: XSS attack
Write-Host "`nTest 3: XSS attack (encoded)"
$xss = [System.Web.HttpUtility]::UrlEncode("<script>alert(1)</script>")
$uri3 = "$APIM_URL/api/products?search=$xss"
try {
    $r3 = Invoke-WebRequest -Uri $uri3 -Headers @{"Ocp-Apim-Subscription-Key"=$KEY} -UseBasicParsing
    Write-Host "Success: $($r3.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "Failed: $_" -ForegroundColor Red
}

# Test 4: Login
Write-Host "`nTest 4: Login test"
$body = @{username="admin"; password="admin123"} | ConvertTo-Json
try {
    $r4 = Invoke-WebRequest -Uri "$APIM_URL/api/login" -Method POST -Body $body -ContentType "application/json" -Headers @{"Ocp-Apim-Subscription-Key"=$KEY} -UseBasicParsing
    Write-Host "Success: $($r4.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "Failed: $_" -ForegroundColor Red
    if ($_.Exception.Response) {
        Write-Host "HTTP Status: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Yellow
    }
}

# Test local backend directly
Write-Host "`nTest 5: Testing local backend directly"
try {
    $r5 = Invoke-WebRequest -Uri "http://localhost:3001/api/products" -UseBasicParsing
    Write-Host "Local backend is accessible: $($r5.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "Local backend not accessible: $_" -ForegroundColor Yellow
}

Write-Host "`nDiagnosis:" -ForegroundColor Blue
Write-Host "- If attacks return 200, they are NOT being blocked"
Write-Host "- If attacks fail with errors, check the error message"
Write-Host "- HTTP 000 in bash might be due to WSL networking issues" 