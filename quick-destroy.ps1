# Quick Destroy Script - No confirmations
# Use with caution!

param(
    [switch]$Force
)

if (-not $Force) {
    Write-Host "This script requires the -Force parameter to run." -ForegroundColor Red
    Write-Host "Usage: .\quick-destroy.ps1 -Force" -ForegroundColor Yellow
    exit 1
}

Write-Host "Quick destroying Azure environment..." -ForegroundColor Red

# Change to terraform directory
Set-Location -Path "terraform/azure"

# Destroy without prompts
terraform destroy -auto-approve

# Clean up state files
Remove-Item -Path "terraform.tfstate*", ".terraform*" -Force -ErrorAction SilentlyContinue

Set-Location -Path "../.."

Write-Host "Destruction complete." -ForegroundColor Green 