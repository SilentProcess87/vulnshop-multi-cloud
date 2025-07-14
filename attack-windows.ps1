# attack-windows.ps1 - Windows PowerShell Attack Tester for VulnShop

param(
    [string]$Target = "apim",
    [switch]$Continuous
)

# Configuration
$APIM_URL = "https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"
$LOCAL_URL = "http://localhost:3001"
$KEY = "8722910157d34e698f969cf34c30eeb5"

# Select target
if ($Target -eq "local") {
    $BASE_URL = $LOCAL_URL
    Write-Host "[TARGET] Local Backend" -ForegroundColor Yellow
} else {
    $BASE_URL = $APIM_URL
    Write-Host "[TARGET] Azure API Management" -ForegroundColor Yellow
}

Write-Host "VulnShop Attack Tester (Windows Edition)" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host "[SAFETY] NON-DESTRUCTIVE ATTACKS ONLY" -ForegroundColor Green

# Attack function
function Execute-Attack {
    param(
        [string]$Type,
        [string]$Endpoint,
        [string]$Description,
        [string]$Method = "GET",
        [string]$Body = "",
        [hashtable]$ExtraHeaders = @{}
    )
    
    Write-Host "`n[TEST] $Description" -ForegroundColor Cyan
    Write-Host "Type: $Type" -ForegroundColor Gray
    
    $headers = @{"Ocp-Apim-Subscription-Key" = $KEY}
    foreach ($key in $ExtraHeaders.Keys) {
        $headers[$key] = $ExtraHeaders[$key]
    }
    
    try {
        if ($Method -eq "GET") {
            $response = Invoke-WebRequest -Uri "$BASE_URL$Endpoint" `
                -Headers $headers `
                -UseBasicParsing
        } else {
            $headers["Content-Type"] = "application/json"
            $response = Invoke-WebRequest -Uri "$BASE_URL$Endpoint" `
                -Method $Method `
                -Headers $headers `
                -Body $Body `
                -UseBasicParsing
        }
        
        if ($response.StatusCode -eq 200) {
            Write-Host "[WARNING] Attack succeeded: HTTP $($response.StatusCode)" -ForegroundColor Red
            Write-Host "   Response length: $($response.Content.Length) bytes" -ForegroundColor Gray
        } else {
            Write-Host "[OK] Response: HTTP $($response.StatusCode)" -ForegroundColor Green
        }
    } catch {
        if ($_.Exception.Response) {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -eq 403 -or $status -eq 400) {
                Write-Host "[BLOCKED] Attack blocked: HTTP $status" -ForegroundColor Green
            } elseif ($status -eq 401) {
                Write-Host "[AUTH] Authentication required: HTTP $status" -ForegroundColor Yellow
            } else {
                Write-Host "[ERROR] HTTP $status - $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# URL encoding helper
Add-Type -AssemblyName System.Web

do {
    $attackCount = 0
    
    # SQL INJECTION ATTACKS
    Write-Host "`n=== SQL INJECTION ATTACKS ===" -ForegroundColor Red
    
    Execute-Attack -Type "SQL" `
        -Endpoint "/api/products?search=$([System.Web.HttpUtility]::UrlEncode("' OR '1'='1"))" `
        -Description "Classic SQL injection"
    $attackCount++
    
    Execute-Attack -Type "SQL" `
        -Endpoint "/api/products?search=$([System.Web.HttpUtility]::UrlEncode("'; SELECT * FROM users--"))" `
        -Description "Information disclosure attempt"
    $attackCount++
    
    Execute-Attack -Type "SQL" `
        -Endpoint "/api/products?search=$([System.Web.HttpUtility]::UrlEncode("1' UNION SELECT name FROM sqlite_master--"))" `
        -Description "Schema enumeration"
    $attackCount++
    
    # XSS ATTACKS
    Write-Host "`n=== XSS ATTACKS ===" -ForegroundColor Red
    
    Execute-Attack -Type "XSS" `
        -Endpoint "/api/products?search=$([System.Web.HttpUtility]::UrlEncode("<script>alert('XSS')</script>"))" `
        -Description "Script tag XSS"
    $attackCount++
    
    Execute-Attack -Type "XSS" `
        -Endpoint "/api/products?search=$([System.Web.HttpUtility]::UrlEncode("<img src=x onerror=alert(1)>"))" `
        -Description "Image tag XSS"
    $attackCount++
    
    # AUTHENTICATION ATTACKS
    Write-Host "`n=== AUTHENTICATION ATTACKS ===" -ForegroundColor Red
    
    Execute-Attack -Type "Auth" `
        -Endpoint "/api/login" `
        -Description "SQL injection in login" `
        -Method "POST" `
        -Body '{"username": "admin''--", "password": "anything"}'
    $attackCount++
    
    Execute-Attack -Type "Auth" `
        -Endpoint "/api/login" `
        -Description "Valid login (baseline)" `
        -Method "POST" `
        -Body '{"username": "admin", "password": "admin123"}'
    $attackCount++
    
    # COMMAND INJECTION
    Write-Host "`n=== COMMAND INJECTION ATTACKS ===" -ForegroundColor Red
    
    Execute-Attack -Type "CMD" `
        -Endpoint "/api/products?search=$([System.Web.HttpUtility]::UrlEncode("; ls -la"))" `
        -Description "Command injection attempt"
    $attackCount++
    
    Execute-Attack -Type "CMD" `
        -Endpoint "/api/products?search=$([System.Web.HttpUtility]::UrlEncode("| whoami"))" `
        -Description "Pipe command injection"
    $attackCount++
    
    # PATH TRAVERSAL
    Write-Host "`n=== PATH TRAVERSAL ATTACKS ===" -ForegroundColor Red
    
    Execute-Attack -Type "Path" `
        -Endpoint "/api/products?file=../../../../etc/passwd" `
        -Description "Path traversal attempt"
    $attackCount++
    
    # IDOR ATTACKS
    Write-Host "`n=== IDOR ATTACKS ===" -ForegroundColor Red
    
    Execute-Attack -Type "IDOR" `
        -Endpoint "/api/orders/1" `
        -Description "Access another user's order"
    $attackCount++
    
    Execute-Attack -Type "IDOR" `
        -Endpoint "/api/users/2/profile" `
        -Description "Access another user's profile"
    $attackCount++
    
    # INPUT VALIDATION
    Write-Host "`n=== INPUT VALIDATION TESTS ===" -ForegroundColor Red
    
    Execute-Attack -Type "Validation" `
        -Endpoint "/api/products" `
        -Description "Negative price product" `
        -Method "POST" `
        -Body '{"name": "Test Product", "price": -999, "description": "Should not allow negative"}'
    $attackCount++
    
    Execute-Attack -Type "Validation" `
        -Endpoint "/api/cart" `
        -Description "Huge quantity" `
        -Method "POST" `
        -Body '{"productId": 1, "quantity": 2147483647}'
    $attackCount++
    
    # RATE LIMITING TEST
    Write-Host "`n=== RATE LIMITING TEST ===" -ForegroundColor Red
    Write-Host "Sending 20 rapid requests..." -ForegroundColor Yellow
    
    $rateLimited = $false
    for ($i = 1; $i -le 20; $i++) {
        Write-Progress -Activity "Rate limit test" -Status "$i/20 requests" -PercentComplete (($i/20)*100)
        try {
            $response = Invoke-WebRequest -Uri "$BASE_URL/api/products" `
                -Headers @{"Ocp-Apim-Subscription-Key" = $KEY} `
                -UseBasicParsing
        } catch {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 429) {
                Write-Host "`n[RATE LIMIT] Triggered at request $i!" -ForegroundColor Green
                $rateLimited = $true
                break
            }
        }
    }
    Write-Progress -Activity "Rate limit test" -Completed
    
    if (-not $rateLimited) {
        Write-Host "[WARNING] No rate limiting detected after 20 requests" -ForegroundColor Yellow
    }
    
    # SUMMARY
    Write-Host "`n=====================================" -ForegroundColor Blue
    Write-Host "Attack Test Complete!" -ForegroundColor Green
    Write-Host "Total attacks executed: $attackCount" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Blue
    
    if ($Continuous) {
        Write-Host "`n[WAIT] Next iteration in 5 seconds..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
    }
    
} while ($Continuous)

Write-Host "`n[NEXT STEPS]" -ForegroundColor Blue
Write-Host "1. Check Cortex dashboard for attack logs"
Write-Host "2. Review APIM Analytics for traffic patterns"
Write-Host "3. Verify attacks are being logged properly"
Write-Host "`n[DONE] Testing completed!" -ForegroundColor Green 