# Azure Environment Destruction Script
# WARNING: This will permanently delete all resources!

Write-Host "=============================================" -ForegroundColor Red
Write-Host "AZURE ENVIRONMENT DESTRUCTION SCRIPT" -ForegroundColor Red
Write-Host "=============================================" -ForegroundColor Red
Write-Host ""
Write-Host "WARNING: This script will PERMANENTLY DELETE:" -ForegroundColor Yellow
Write-Host "- Virtual Machine (vm-vulnshop-*)" -ForegroundColor Yellow
Write-Host "- API Management Service (apim-vulnshop-*)" -ForegroundColor Yellow
Write-Host "- Virtual Network and Subnets" -ForegroundColor Yellow
Write-Host "- Network Security Groups" -ForegroundColor Yellow
Write-Host "- Public IP Addresses" -ForegroundColor Yellow
Write-Host "- Storage Account" -ForegroundColor Yellow
Write-Host "- All associated resources in the resource group" -ForegroundColor Yellow
Write-Host ""

# Confirm destruction
$confirmation = Read-Host "Are you ABSOLUTELY SURE you want to destroy everything? Type 'DESTROY' to confirm"

if ($confirmation -ne "DESTROY") {
    Write-Host "Destruction cancelled. No resources were deleted." -ForegroundColor Green
    exit 0
}

# Second confirmation for safety
$secondConfirmation = Read-Host "This action cannot be undone. Type 'YES' to proceed"

if ($secondConfirmation -ne "YES") {
    Write-Host "Destruction cancelled. No resources were deleted." -ForegroundColor Green
    exit 0
}

Write-Host ""
Write-Host "Starting destruction process..." -ForegroundColor Red
Write-Host ""

# Change to terraform directory
Set-Location -Path "terraform/azure"

# Show current resources that will be destroyed
Write-Host "Listing resources to be destroyed:" -ForegroundColor Yellow
terraform state list

Write-Host ""
Write-Host "Running terraform destroy..." -ForegroundColor Red
Write-Host ""

# Run terraform destroy with auto-approve
try {
    # First, try to refresh the state
    Write-Host "Refreshing Terraform state..." -ForegroundColor Yellow
    terraform refresh
    
    # Run destroy
    terraform destroy -auto-approve
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "=============================================" -ForegroundColor Green
        Write-Host "Environment successfully destroyed!" -ForegroundColor Green
        Write-Host "=============================================" -ForegroundColor Green
        
        # Clean up local files
        Write-Host ""
        Write-Host "Cleaning up local state files..." -ForegroundColor Yellow
        
        if (Test-Path "terraform.tfstate") {
            Remove-Item "terraform.tfstate" -Force
            Write-Host "- Removed terraform.tfstate" -ForegroundColor Green
        }
        
        if (Test-Path "terraform.tfstate.backup") {
            Remove-Item "terraform.tfstate.backup" -Force
            Write-Host "- Removed terraform.tfstate.backup" -ForegroundColor Green
        }
        
        if (Test-Path ".terraform.lock.hcl") {
            Remove-Item ".terraform.lock.hcl" -Force
            Write-Host "- Removed .terraform.lock.hcl" -ForegroundColor Green
        }
        
        if (Test-Path ".terraform") {
            Remove-Item ".terraform" -Recurse -Force
            Write-Host "- Removed .terraform directory" -ForegroundColor Green
        }
        
        Write-Host ""
        Write-Host "All resources and local state files have been cleaned up." -ForegroundColor Green
    }
    else {
        Write-Host ""
        Write-Host "Terraform destroy failed with exit code: $LASTEXITCODE" -ForegroundColor Red
        Write-Host "Some resources may not have been deleted." -ForegroundColor Red
        Write-Host "Check the Azure Portal for remaining resources." -ForegroundColor Yellow
    }
}
catch {
    Write-Host ""
    Write-Host "Error during destruction: $_" -ForegroundColor Red
    Write-Host "You may need to manually delete resources from Azure Portal." -ForegroundColor Yellow
}

# Return to original directory
Set-Location -Path "../.."

Write-Host ""
Write-Host "Script completed." -ForegroundColor Cyan 