# fix-vulnshop-apim.ps1 - PowerShell script to fix VulnShop APIM integration
# Can be run from Azure context (local machine) or VM context

# Configuration
$APIM_NAME = "apim-vulnshop-t7up5q"
$RESOURCE_GROUP = "rg-vulnshop-t7up5q"
$APIM_URL = "https://$APIM_NAME.azure-api.net/vulnshop"
$BACKEND_URL = "http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com"
$VM_HOSTNAME = "vulnshop-dev-t7up5q.eastus.cloudapp.azure.com"
$LOCATION = "eastus"

# Colors
function Write-Success { Write-Host $args -ForegroundColor Green }
function Write-Error { Write-Host $args -ForegroundColor Red }
function Write-Warning { Write-Host $args -ForegroundColor Yellow }
function Write-Info { Write-Host $args -ForegroundColor Cyan }

# Print header
function Print-Header {
    param($text)
    Write-Info "`n========================================================"
    Write-Info "  $text"
    Write-Info "========================================================`n"
}

# Check if running on VM
$isVM = Test-Path "/var/www/vulnshop" -or Test-Path "/etc/nginx/sites-available/vulnshop"

if ($isVM) {
    $CONTEXT = "VM"
    Write-Info "[VM] Running in VM context"
} else {
    $CONTEXT = "AZURE"
    Write-Info "[AZURE] Running in Azure/Local context"
}

Print-Header "VulnShop APIM Integration Fix Script"

Write-Host "Configuration:"
Write-Host "  APIM Name: $APIM_NAME"
Write-Host "  Resource Group: $RESOURCE_GROUP"
Write-Host "  APIM URL: $APIM_URL"
Write-Host "  Backend URL: $BACKEND_URL"
Write-Host "  Context: $CONTEXT"

# ============================================================================
# SECTION 1: Azure Configuration (only if in Azure context)
# ============================================================================

if ($CONTEXT -eq "AZURE") {
    Print-Header "Section 1: Azure APIM Configuration"
    
    # Check if Azure CLI is installed
    try {
        $azVersion = az version 2>$null
        if (-not $azVersion) {
            throw "Azure CLI not found"
        }
    } catch {
        Write-Error "Azure CLI not installed. Please install from: https://aka.ms/installazurecliwindows"
        exit 1
    }
    
    # Check if logged into Azure
    Write-Warning "Checking Azure login status..."
    try {
        $account = az account show 2>$null | ConvertFrom-Json
        if (-not $account) {
            throw "Not logged in"
        }
        Write-Success "[OK] Logged in as: $($account.user.name)"
    } catch {
        Write-Error "Not logged into Azure. Please run: az login"
        exit 1
    }
    
    # Get APIM details
    Write-Warning "Getting APIM instance details..."
    try {
        $apimExists = az apim show --name $APIM_NAME --resource-group $RESOURCE_GROUP --query "name" -o tsv 2>$null
        if (-not $apimExists) {
            throw "APIM not found"
        }
        Write-Success "[OK] APIM instance found"
    } catch {
        Write-Error "APIM instance not found! Please ensure APIM exists or create it first"
        exit 1
    }
    
    # Get APIM outbound IPs
    Write-Warning "Getting APIM outbound IPs..."
    $APIM_IPS = az apim show --name $APIM_NAME --resource-group $RESOURCE_GROUP --query 'publicIpAddresses' -o tsv
    Write-Success "[OK] APIM IPs: $APIM_IPS"
    
    # Save IPs to file
    $APIM_IPS | Out-File -FilePath "apim-ips.txt"
    Write-Success "[OK] APIM IPs saved to apim-ips.txt"
    
    # Create/Update API
    Write-Warning "Configuring VulnShop API in APIM..."
    
    # Check if API exists
    $apiExists = az apim api show --api-id vulnshop --service-name $APIM_NAME --resource-group $RESOURCE_GROUP --query "name" -o tsv 2>$null
    
    if (-not $apiExists) {
        Write-Host "Creating VulnShop API..."
        
        # Create API specification
        $apiSpec = @{
            openapi = "3.0.0"
            info = @{
                title = "VulnShop API"
                description = "Vulnerable E-commerce API for security testing"
                version = "1.0.0"
            }
            servers = @(
                @{ url = $BACKEND_URL }
            )
            paths = @{
                "/api/products" = @{
                    get = @{
                        summary = "Get all products"
                        responses = @{
                            "200" = @{ description = "Success" }
                        }
                    }
                }
                "/api/login" = @{
                    post = @{
                        summary = "User login"
                        responses = @{
                            "200" = @{ description = "Success" }
                        }
                    }
                }
            }
        }
        
        $apiSpec | ConvertTo-Json -Depth 10 | Out-File -FilePath "vulnshop-api.json"
        
        az apim api import `
            --resource-group $RESOURCE_GROUP `
            --service-name $APIM_NAME `
            --api-id vulnshop `
            --path vulnshop `
            --specification-format OpenApi `
            --specification-path vulnshop-api.json `
            --service-url $BACKEND_URL
            
        Write-Success "[OK] API created"
    } else {
        Write-Success "[OK] API already exists"
        
        # Update backend URL
        az apim api update `
            --resource-group $RESOURCE_GROUP `
            --service-name $APIM_NAME `
            --api-id vulnshop `
            --service-url $BACKEND_URL
    }
}

# ============================================================================
# SECTION 2: Frontend Configuration and Build
# ============================================================================

Print-Header "Section 2: Frontend Configuration"

# Find project root
if ($CONTEXT -eq "VM") {
    $PROJECT_ROOT = "/var/www/vulnshop"
} else {
    if (Test-Path "./frontend") {
        $PROJECT_ROOT = "."
    } elseif (Test-Path "../frontend") {
        $PROJECT_ROOT = ".."
    } else {
        Write-Error "Cannot find project root. Please run from project directory"
        exit 1
    }
}

Set-Location $PROJECT_ROOT

# Create environment files
Write-Warning "Creating frontend environment files..."

# Create production environment file
@"
# Production Environment Configuration
VITE_API_URL=$APIM_URL/api
"@ | Out-File -FilePath "frontend/.env.production" -Encoding UTF8

# Create development environment file
@"
# Development Environment Configuration
VITE_API_URL=$APIM_URL/api

# For local backend testing without APIM:
# VITE_API_URL=http://localhost:3001/api
"@ | Out-File -FilePath "frontend/.env.development" -Encoding UTF8

# Copy from template files if they exist
if (Test-Path "frontend/env.production") {
    Copy-Item "frontend/env.production" "frontend/.env.production" -Force
}
if (Test-Path "frontend/env.development") {
    Copy-Item "frontend/env.development" "frontend/.env.development" -Force
}

Write-Success "[OK] Environment files created"

# Build frontend if not on VM
if ($CONTEXT -ne "VM" -and (Test-Path "frontend")) {
    Write-Warning "Building frontend..."
    
    Set-Location frontend
    
    # Check if npm is available
    try {
        $npmVersion = npm --version 2>$null
        if ($npmVersion) {
            npm install
            npm run build
            Write-Success "[OK] Frontend built successfully"
            Write-Info "Build output in: frontend/dist/"
        }
    } catch {
        Write-Warning "[WARNING] npm not found. Skipping frontend build"
    }
    
    Set-Location ..
}

# ============================================================================
# SECTION 3: Testing
# ============================================================================

Print-Header "Section 3: Testing and Verification"

# Function to test endpoint
function Test-Endpoint {
    param($url, $expectedStatus, $description)
    
    Write-Host -NoNewline "Testing $description... "
    
    try {
        $response = Invoke-WebRequest -Uri $url -Method GET -UseBasicParsing -ErrorAction Stop
        $status = $response.StatusCode
    } catch {
        if ($_.Exception.Response) {
            $status = $_.Exception.Response.StatusCode.value__
        } else {
            $status = 0
        }
    }
    
    if ($status -eq $expectedStatus) {
        Write-Success "[OK] Success (HTTP $status)"
        return $true
    } else {
        Write-Error "[FAILED] (HTTP $status, expected $expectedStatus)"
        return $false
    }
}

# Test APIM endpoint
Write-Warning "Testing APIM endpoints..."
Test-Endpoint "$APIM_URL/api/products" 200 "APIM products endpoint"
Test-Endpoint "$APIM_URL/api/products?q=' OR '1'='1" 403 "APIM attack detection"

# Test direct access
Write-Warning "Testing direct backend access (should be blocked)..."
Test-Endpoint "$BACKEND_URL/api/products" 403 "Direct backend access"

# ============================================================================
# SECTION 4: Summary
# ============================================================================

Print-Header "Summary and Next Steps"

Write-Success "[COMPLETE] Configuration Complete!"
Write-Host ""

if ($CONTEXT -eq "AZURE") {
    Write-Info "From Azure Context - Next Steps:"
    Write-Host "1. Copy files to VM:"
    Write-Host "   scp -r frontend/dist/* azureuser@${VM_HOSTNAME}:/tmp/frontend/"
    Write-Host "   scp fix-vulnshop-apim.sh azureuser@${VM_HOSTNAME}:/tmp/"
    Write-Host "   scp apim-ips.txt azureuser@${VM_HOSTNAME}:/tmp/"
    Write-Host ""
    Write-Host "2. SSH to VM and run:"
    Write-Host "   ssh azureuser@$VM_HOSTNAME"
    Write-Host "   sudo bash /tmp/fix-vulnshop-apim.sh"
    Write-Host ""
    Write-Host "3. Apply security policy in APIM portal:"
    Write-Host "   Portal -> APIM -> APIs -> VulnShop -> All operations -> Policies"
    Write-Host "   Apply: policies/cortex-enhanced-security-policy.xml"
}

Write-Host ""
Write-Info "Test URLs:"
Write-Host "Frontend: http://$VM_HOSTNAME"
Write-Host "APIM API: $APIM_URL/api/products"
Write-Host "Direct API (blocked): $BACKEND_URL/api/products"

Write-Host ""
Write-Success "VulnShop APIM integration configured!" 