# attack-generator.ps1 - PowerShell Attack Generator for VulnShop

param(
    [string]$Target = "apim",  # "apim" or "local"
    [int]$Duration = 60,       # Duration in seconds
    [bool]$Continuous = $false # Continuous mode
)

# Configuration
$APIM_URL = "https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"
$LOCAL_URL = "http://localhost:3001"
$SUBSCRIPTION_KEY = "8722910157d34e698f969cf34c30eeb5"

# Set target URL
if ($Target -eq "local") {
    $BASE_URL = $LOCAL_URL
    Write-Host "🎯 Target: Local Backend ($LOCAL_URL)" -ForegroundColor Yellow
} else {
    $BASE_URL = $APIM_URL
    Write-Host "🎯 Target: Azure API Management" -ForegroundColor Yellow
}

# Attack patterns
$AttackPatterns = @(
    # SQL Injection patterns
    @{Type="SQL"; Endpoint="/api/products"; Query="search=' OR '1'='1"; Method="GET"},
    @{Type="SQL"; Endpoint="/api/products"; Query="search=1' UNION SELECT * FROM users--"; Method="GET"},
    @{Type="SQL"; Endpoint="/api/products"; Query="search='; SELECT version(); --"; Method="GET"},
    @{Type="SQL"; Endpoint="/api/products"; Query="search=1' AND 1=1--"; Method="GET"},
    @{Type="SQL"; Endpoint="/api/products"; Query="search=admin'--"; Method="GET"},
    
    # XSS patterns
    @{Type="XSS"; Endpoint="/api/products"; Query="search=<script>alert('XSS')</script>"; Method="GET"},
    @{Type="XSS"; Endpoint="/api/products"; Query="search=<img src=x onerror=alert(1)>"; Method="GET"},
    @{Type="XSS"; Endpoint="/api/products"; Query="search=<svg onload=alert('XSS')>"; Method="GET"},
    @{Type="XSS"; Endpoint="/api/products"; Query="search=javascript:alert('XSS')"; Method="GET"},
    
    # Command Injection
    @{Type="CMD"; Endpoint="/api/products"; Query="search=; whoami"; Method="GET"},
    @{Type="CMD"; Endpoint="/api/products"; Query="search=| ls -la"; Method="GET"},
    @{Type="CMD"; Endpoint="/api/products"; Query="search=`cat /etc/passwd`"; Method="GET"},
    
    # Path Traversal
    @{Type="PATH"; Endpoint="/api/files/../../../../etc/passwd"; Query=""; Method="GET"},
    @{Type="PATH"; Endpoint="/api/download"; Query="file=../../../windows/system32/config/sam"; Method="GET"},
    
    # IDOR
    @{Type="IDOR"; Endpoint="/api/orders/1"; Query=""; Method="GET"},
    @{Type="IDOR"; Endpoint="/api/users/2/profile"; Query=""; Method="GET"},
    @{Type="IDOR"; Endpoint="/api/admin/users"; Query=""; Method="GET"},
    
    # Authentication attacks
    @{Type="AUTH"; Endpoint="/api/login"; Body='{"username":"admin","password":"password"}'; Method="POST"},
    @{Type="AUTH"; Endpoint="/api/login"; Body='{"username":"' + ("A" * 1000) + '","password":"test"}'; Method="POST"},
    
    # NoSQL Injection
    @{Type="NOSQL"; Endpoint="/api/products"; Body='{"search":{"$ne":null}}'; Method="POST"},
    @{Type="NOSQL"; Endpoint="/api/login"; Body='{"username":{"$regex":"^admin"},"password":{"$ne":null}}'; Method="POST"}
)

# Statistics
$Stats = @{
    Total = 0
    Blocked = 0
    Success = 0
    Errors = 0
}

# Function to execute attack
function Execute-Attack {
    param($Attack)
    
    $Stats.Total++
    
    # Build request parameters
    $Uri = $BASE_URL + $Attack.Endpoint
    if ($Attack.Query) {
        $Uri += "?" + $Attack.Query
    }
    
    $Headers = @{}
    if ($Target -ne "local") {
        $Headers["Ocp-Apim-Subscription-Key"] = $SUBSCRIPTION_KEY
    }
    
    try {
        if ($Attack.Method -eq "POST" -and $Attack.Body) {
            $Headers["Content-Type"] = "application/json"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -Headers $Headers -Body $Attack.Body -UseBasicParsing
        } else {
            $Response = Invoke-WebRequest -Uri $Uri -Method GET -Headers $Headers -UseBasicParsing
        }
        
        $StatusCode = $Response.StatusCode
        
        # Analyze response
        if ($StatusCode -eq 403 -or $StatusCode -eq 401) {
            Write-Host "[$($Attack.Type)] " -NoNewline -ForegroundColor Cyan
            Write-Host "✓ Blocked " -NoNewline -ForegroundColor Green
            Write-Host "(HTTP $StatusCode) - $($Attack.Endpoint)" -ForegroundColor Gray
            $Stats.Blocked++
        } elseif ($StatusCode -eq 200 -or $StatusCode -eq 201) {
            Write-Host "[$($Attack.Type)] " -NoNewline -ForegroundColor Cyan
            Write-Host "✗ Success " -NoNewline -ForegroundColor Red
            Write-Host "(HTTP $StatusCode) - $($Attack.Endpoint) - VULNERABLE!" -ForegroundColor Yellow
            $Stats.Success++
        } else {
            Write-Host "[$($Attack.Type)] " -NoNewline -ForegroundColor Cyan
            Write-Host "⚠ HTTP $StatusCode - $($Attack.Endpoint)" -ForegroundColor Yellow
        }
    }
    catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        if ($StatusCode -eq 403 -or $StatusCode -eq 401 -or $StatusCode -eq 429) {
            Write-Host "[$($Attack.Type)] " -NoNewline -ForegroundColor Cyan
            Write-Host "✓ Blocked " -NoNewline -ForegroundColor Green
            Write-Host "(HTTP $StatusCode) - $($Attack.Endpoint)" -ForegroundColor Gray
            $Stats.Blocked++
        } else {
            Write-Host "[$($Attack.Type)] Error: $($_.Exception.Message)" -ForegroundColor Red
            $Stats.Errors++
        }
    }
    
    # Small delay to avoid overwhelming
    Start-Sleep -Milliseconds 200
}

# Main execution
Write-Host "`n╔════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "║     VULNSHOP ATTACK GENERATOR          ║" -ForegroundColor Red
Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Red

if ($Continuous) {
    Write-Host "`n⚠️  Running in CONTINUOUS mode - Press Ctrl+C to stop" -ForegroundColor Yellow
} else {
    Write-Host "`n⏱️  Running for $Duration seconds" -ForegroundColor Yellow
}

$StartTime = Get-Date
$EndTime = $StartTime.AddSeconds($Duration)

# Attack loop
while ($true) {
    # Randomly select an attack
    $Attack = $AttackPatterns | Get-Random
    Execute-Attack -Attack $Attack
    
    # Check if we should stop
    if (-not $Continuous -and (Get-Date) -gt $EndTime) {
        break
    }
    
    # Show progress every 10 attacks
    if ($Stats.Total % 10 -eq 0) {
        $BlockRate = if ($Stats.Total -gt 0) { [math]::Round(($Stats.Blocked / $Stats.Total) * 100, 1) } else { 0 }
        Write-Host "`n📊 Progress: $($Stats.Total) attacks | Block rate: $BlockRate%" -ForegroundColor Cyan
    }
}

# Final summary
$Duration = ((Get-Date) - $StartTime).TotalSeconds
$AttacksPerSecond = [math]::Round($Stats.Total / $Duration, 2)
$BlockRate = if ($Stats.Total -gt 0) { [math]::Round(($Stats.Blocked / $Stats.Total) * 100, 1) } else { 0 }
$SuccessRate = if ($Stats.Total -gt 0) { [math]::Round(($Stats.Success / $Stats.Total) * 100, 1) } else { 0 }

Write-Host "`n╔════════════════════════════════════════╗" -ForegroundColor Blue
Write-Host "║         ATTACK SUMMARY REPORT          ║" -ForegroundColor Blue
Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Blue

Write-Host "`n📊 Final Statistics:" -ForegroundColor Yellow
Write-Host "  Duration: $([math]::Round($Duration, 1)) seconds"
Write-Host "  Total Attacks: $($Stats.Total)"
Write-Host "  Attacks/Second: $AttacksPerSecond"
Write-Host "  Blocked: " -NoNewline
Write-Host "$($Stats.Blocked) ($BlockRate%)" -ForegroundColor Green
Write-Host "  Successful: " -NoNewline
Write-Host "$($Stats.Success) ($SuccessRate%)" -ForegroundColor Red
Write-Host "  Errors: $($Stats.Errors)"

if ($Stats.Success -gt 0) {
    Write-Host "`n⚠️  WARNING: $($Stats.Success) attacks were successful!" -ForegroundColor Red
    Write-Host "  Your application has exploitable vulnerabilities." -ForegroundColor Red
}

if ($Target -ne "local") {
    Write-Host "`n🔍 Next Steps:" -ForegroundColor Yellow
    Write-Host "  1. Check APIM Analytics in Azure Portal"
    Write-Host "  2. Review Cortex dashboard for attack patterns"
    Write-Host "  3. Apply security policies to block vulnerabilities"
}

Write-Host "`n✅ Attack generation completed!" -ForegroundColor Green 