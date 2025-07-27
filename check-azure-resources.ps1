# Azure Resources Check Script
# Shows what resources currently exist

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "AZURE RESOURCES CHECK" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Change to terraform directory
Set-Location -Path "terraform/azure"

# Check if terraform is initialized
if (-not (Test-Path ".terraform")) {
    Write-Host "Terraform not initialized. Initializing..." -ForegroundColor Yellow
    terraform init
}

Write-Host "Checking Terraform state..." -ForegroundColor Yellow
Write-Host ""

# List all resources
$resources = terraform state list 2>$null

if ($resources) {
    Write-Host "Found the following resources:" -ForegroundColor Green
    Write-Host ""
    
    foreach ($resource in $resources) {
        Write-Host "  - $resource" -ForegroundColor White
    }
    
    Write-Host ""
    Write-Host "Total resources: $($resources.Count)" -ForegroundColor Yellow
    
    # Try to get more details
    Write-Host ""
    Write-Host "Resource Details:" -ForegroundColor Cyan
    Write-Host ""
    
    # Show key resources
    $keyResources = @(
        "azurerm_resource_group.main",
        "azurerm_linux_virtual_machine.main",
        "azurerm_api_management.main[0]",
        "azurerm_public_ip.vm"
    )
    
    foreach ($kr in $keyResources) {
        if ($resources -contains $kr) {
            Write-Host "Details for $kr`:" -ForegroundColor Yellow
            terraform state show $kr 2>$null | Select-String -Pattern "(id|name|location|fqdn|ip_address)" | ForEach-Object { 
                Write-Host "  $_" -ForegroundColor Gray 
            }
            Write-Host ""
        }
    }
    
    # Show costs estimate
    Write-Host "Estimated Monthly Costs:" -ForegroundColor Yellow
    Write-Host "- VM (Standard_B2s): ~$30-40/month" -ForegroundColor Gray
    Write-Host "- API Management (Developer): ~$50/month" -ForegroundColor Gray
    Write-Host "- Storage & Network: ~$5-10/month" -ForegroundColor Gray
    Write-Host "- Total: ~$85-100/month" -ForegroundColor White
    
} else {
    Write-Host "No resources found in Terraform state." -ForegroundColor Yellow
    Write-Host "Either resources don't exist or state is out of sync." -ForegroundColor Yellow
}

# Return to original directory
Set-Location -Path "../.."

Write-Host ""
Write-Host "To destroy these resources, run:" -ForegroundColor Cyan
Write-Host "  .\destroy-azure-environment.ps1" -ForegroundColor White
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan 