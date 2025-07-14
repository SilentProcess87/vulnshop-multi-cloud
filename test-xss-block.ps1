# test-xss-block.ps1 - Test XSS blocking behavior

$APIM_URL = "https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"
$KEY = "8722910157d34e698f969cf34c30eeb5"

Write-Host "Testing XSS Blocking Behavior" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan

Add-Type -AssemblyName System.Web

# Test different XSS payloads
@(
    @{desc="Simple script tag"; payload="<script>alert('XSS')</script>"},
    @{desc="URL encoded script"; payload=[System.Web.HttpUtility]::UrlEncode("<script>alert('XSS')</script>")},
    @{desc="Image onerror"; payload="<img src=x onerror=alert(1)>"},
    @{desc="SVG onload"; payload="<svg onload=alert(1)>"},
    @{desc="JavaScript protocol"; payload="javascript:alert(1)"},
    @{desc="Data URI"; payload="data:text/html,<script>alert(1)</script>"}
) | ForEach-Object {
    Write-Host "`nTesting: $($_.desc)" -ForegroundColor Yellow
    Write-Host "Payload: $($_.payload)" -ForegroundColor Gray
    
    try {
        $response = Invoke-WebRequest -Uri "$APIM_URL/api/products?search=$($_.payload)" `
            -Headers @{"Ocp-Apim-Subscription-Key" = $KEY} `
            -UseBasicParsing
            
        Write-Host "[NOT BLOCKED] HTTP $($response.StatusCode)" -ForegroundColor Red
    } catch {
        $status = $_.Exception.Response.StatusCode.value__
        Write-Host "[RESPONSE] HTTP $status" -ForegroundColor Green
        
        # Try to get the error message
        if ($_.Exception.Response) {
            try {
                $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $errorContent = $reader.ReadToEnd()
                $reader.Close()
                Write-Host "Message: $errorContent" -ForegroundColor Gray
            } catch {
                Write-Host "Could not read error message" -ForegroundColor Gray
            }
        }
    }
}

Write-Host "`n=== Testing APIM vs Backend Directly ===" -ForegroundColor Red

# Compare APIM vs direct backend
$testPayload = "<script>alert(1)</script>"
Write-Host "`nComparing responses for: $testPayload" -ForegroundColor Cyan

# Via APIM
Write-Host "`n1. Via APIM:"
try {
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/products?search=$testPayload" `
        -Headers @{"Ocp-Apim-Subscription-Key" = $KEY} `
        -UseBasicParsing
    Write-Host "   Result: HTTP $($response.StatusCode) - NOT BLOCKED" -ForegroundColor Red
} catch {
    Write-Host "   Result: HTTP $($_.Exception.Response.StatusCode.value__) - BLOCKED" -ForegroundColor Green
}

# Direct to backend (if accessible)
Write-Host "`n2. Direct to backend:"
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3001/api/products?search=$testPayload" `
        -UseBasicParsing
    Write-Host "   Result: HTTP $($response.StatusCode) - Backend accessible" -ForegroundColor Yellow
} catch {
    Write-Host "   Result: Cannot reach backend directly" -ForegroundColor Gray
} 