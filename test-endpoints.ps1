# test-endpoints.ps1 - Test which endpoints are accessible

$APIM_URL = "https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"
$KEY = "8722910157d34e698f969cf34c30eeb5"

Write-Host "Testing APIM Endpoint Accessibility" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan

# Test endpoints
$endpoints = @(
    @{Path="/api/products"; Method="GET"; Description="List products (should be public)"},
    @{Path="/api/products/1"; Method="GET"; Description="Get single product"},
    @{Path="/api/login"; Method="POST"; Body='{"username":"admin","password":"admin123"}'; Description="Login"},
    @{Path="/api/register"; Method="POST"; Body='{"username":"test123","password":"test123","email":"test@test.com"}'; Description="Register"},
    @{Path="/api/orders"; Method="GET"; Description="List orders (requires auth)"},
    @{Path="/api/cart"; Method="GET"; Description="View cart (requires auth)"},
    @{Path="/api/admin/users"; Method="GET"; Description="Admin endpoint"}
)

foreach ($endpoint in $endpoints) {
    Write-Host "`nTesting: $($endpoint.Description)" -ForegroundColor Yellow
    Write-Host "Endpoint: $($endpoint.Path)" -ForegroundColor Gray
    
    try {
        $params = @{
            Uri = "$APIM_URL$($endpoint.Path)"
            Method = $endpoint.Method
            Headers = @{"Ocp-Apim-Subscription-Key" = $KEY}
            UseBasicParsing = $true
        }
        
        if ($endpoint.Body) {
            $params["Body"] = $endpoint.Body
            $params["ContentType"] = "application/json"
        }
        
        $response = Invoke-WebRequest @params
        
        Write-Host "[SUCCESS] HTTP $($response.StatusCode)" -ForegroundColor Green
        if ($endpoint.Path -eq "/api/login" -and $response.StatusCode -eq 200) {
            $token = ($response.Content | ConvertFrom-Json).token
            Write-Host "Got JWT token: $($token.Substring(0, 20))..." -ForegroundColor Cyan
        }
    } catch {
        if ($_.Exception.Response) {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -eq 401) {
                Write-Host "[AUTH REQUIRED] HTTP 401" -ForegroundColor Yellow
            } elseif ($status -eq 404) {
                Write-Host "[NOT FOUND] HTTP 404" -ForegroundColor Red
            } else {
                Write-Host "[ERROR] HTTP $status" -ForegroundColor Red
            }
        } else {
            Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host "`n===================================" -ForegroundColor Cyan
Write-Host "Test Complete!" -ForegroundColor Green 