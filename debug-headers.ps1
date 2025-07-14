# debug-headers.ps1 - Debug headers issue

$APIM_URL = "https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"
$KEY = "8722910157d34e698f969cf34c30eeb5"

Write-Host "Debugging Headers Issue" -ForegroundColor Cyan
Write-Host "=======================" -ForegroundColor Cyan

# Test 1: Show how Clone() behaves
Write-Host "`nTest 1: PowerShell hashtable Clone() behavior"
$original = @{"Ocp-Apim-Subscription-Key" = $KEY}
Write-Host "Original: $($original | ConvertTo-Json -Compress)"
$cloned = $original.Clone()
Write-Host "Cloned: $($cloned | ConvertTo-Json -Compress)"

# Test 2: Show actual request with different methods
Write-Host "`nTest 2: Testing actual requests"

# Method A: Direct inline headers
Write-Host "`nMethod A: Direct inline headers"
try {
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/products" `
        -Headers @{"Ocp-Apim-Subscription-Key" = $KEY} `
        -UseBasicParsing
    Write-Host "[SUCCESS] HTTP $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "[FAILED] HTTP $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}

# Method B: Headers from variable
Write-Host "`nMethod B: Headers from variable"
$headers = @{"Ocp-Apim-Subscription-Key" = $KEY}
try {
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/products" `
        -Headers $headers `
        -UseBasicParsing
    Write-Host "[SUCCESS] HTTP $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "[FAILED] HTTP $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}

# Method C: Headers from cloned variable
Write-Host "`nMethod C: Headers from cloned variable"
$clonedHeaders = $headers.Clone()
try {
    $response = Invoke-WebRequest -Uri "$APIM_URL/api/products" `
        -Headers $clonedHeaders `
        -UseBasicParsing
    Write-Host "[SUCCESS] HTTP $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "[FAILED] HTTP $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
}

# Test 3: Debug the actual advanced-attacks pattern
Write-Host "`nTest 3: Simulating advanced-attacks.ps1 pattern"

# Global headers like in the script
if ($true) {  # Simulating the else branch for APIM
    $globalHeaders = @{"Ocp-Apim-Subscription-Key" = $KEY}
    Write-Host "Global headers set: $($globalHeaders | ConvertTo-Json -Compress)"
}

# Simulate the Execute-Attack function
function Test-ExecuteAttack {
    param([hashtable]$ExtraHeaders = @{})
    
    Write-Host "Inside function..."
    Write-Host "  Global headers: $($globalHeaders | ConvertTo-Json -Compress)"
    
    # Original problematic code
    $attackHeaders = $globalHeaders.Clone()
    Write-Host "  After Clone(): $($attackHeaders | ConvertTo-Json -Compress)"
    
    # Add extra headers
    foreach ($key in $ExtraHeaders.Keys) {
        $attackHeaders[$key] = $ExtraHeaders[$key]
    }
    
    try {
        $response = Invoke-WebRequest -Uri "$APIM_URL/api/products" `
            -Headers $attackHeaders `
            -UseBasicParsing
        Write-Host "  [SUCCESS] HTTP $($response.StatusCode)" -ForegroundColor Green
    } catch {
        Write-Host "  [FAILED] HTTP $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
    }
}

# Call the function
Test-ExecuteAttack

# Test 4: Alternative fix
Write-Host "`nTest 4: Alternative fix approach"
function Test-ExecuteAttackFixed {
    param([hashtable]$ExtraHeaders = @{})
    
    # Create new hashtable instead of Clone()
    $attackHeaders = @{}
    
    # Copy global headers
    if ($globalHeaders) {
        foreach ($key in $globalHeaders.Keys) {
            $attackHeaders[$key] = $globalHeaders[$key]
        }
    }
    
    # Add extra headers
    foreach ($key in $ExtraHeaders.Keys) {
        $attackHeaders[$key] = $ExtraHeaders[$key]
    }
    
    Write-Host "  Fixed headers: $($attackHeaders | ConvertTo-Json -Compress)"
    
    try {
        $response = Invoke-WebRequest -Uri "$APIM_URL/api/products" `
            -Headers $attackHeaders `
            -UseBasicParsing
        Write-Host "  [SUCCESS] HTTP $($response.StatusCode)" -ForegroundColor Green
    } catch {
        Write-Host "  [FAILED] HTTP $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
    }
}

Test-ExecuteAttackFixed 