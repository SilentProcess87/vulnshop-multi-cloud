#!/bin/bash

# Azure Environment Destruction Script
# WARNING: This will permanently delete all resources!

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${RED}=============================================${NC}"
echo -e "${RED}AZURE ENVIRONMENT DESTRUCTION SCRIPT${NC}"
echo -e "${RED}=============================================${NC}"
echo ""
echo -e "${YELLOW}WARNING: This script will PERMANENTLY DELETE:${NC}"
echo -e "${YELLOW}- Virtual Machine (vm-vulnshop-*)${NC}"
echo -e "${YELLOW}- API Management Service (apim-vulnshop-*)${NC}"
echo -e "${YELLOW}- Virtual Network and Subnets${NC}"
echo -e "${YELLOW}- Network Security Groups${NC}"
echo -e "${YELLOW}- Public IP Addresses${NC}"
echo -e "${YELLOW}- Storage Account${NC}"
echo -e "${YELLOW}- All associated resources in the resource group${NC}"
echo ""

# Confirm destruction
echo -n "Are you ABSOLUTELY SURE you want to destroy everything? Type 'DESTROY' to confirm: "
read confirmation

if [ "$confirmation" != "DESTROY" ]; then
    echo -e "${GREEN}Destruction cancelled. No resources were deleted.${NC}"
    exit 0
fi

# Second confirmation for safety
echo -n "This action cannot be undone. Type 'YES' to proceed: "
read secondConfirmation

if [ "$secondConfirmation" != "YES" ]; then
    echo -e "${GREEN}Destruction cancelled. No resources were deleted.${NC}"
    exit 0
fi

echo ""
echo -e "${RED}Starting destruction process...${NC}"
echo ""

# Change to terraform directory
cd terraform/azure || exit 1

# Show current resources that will be destroyed
echo -e "${YELLOW}Listing resources to be destroyed:${NC}"
terraform state list

echo ""
echo -e "${RED}Running terraform destroy...${NC}"
echo ""

# Run terraform destroy with auto-approve
# First, try to refresh the state
echo -e "${YELLOW}Refreshing Terraform state...${NC}"
terraform refresh

# Run destroy
terraform destroy -auto-approve

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}=============================================${NC}"
    echo -e "${GREEN}Environment successfully destroyed!${NC}"
    echo -e "${GREEN}=============================================${NC}"
    
    # Clean up local files
    echo ""
    echo -e "${YELLOW}Cleaning up local state files...${NC}"
    
    if [ -f "terraform.tfstate" ]; then
        rm -f terraform.tfstate
        echo -e "${GREEN}- Removed terraform.tfstate${NC}"
    fi
    
    if [ -f "terraform.tfstate.backup" ]; then
        rm -f terraform.tfstate.backup
        echo -e "${GREEN}- Removed terraform.tfstate.backup${NC}"
    fi
    
    if [ -f ".terraform.lock.hcl" ]; then
        rm -f .terraform.lock.hcl
        echo -e "${GREEN}- Removed .terraform.lock.hcl${NC}"
    fi
    
    if [ -d ".terraform" ]; then
        rm -rf .terraform
        echo -e "${GREEN}- Removed .terraform directory${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}All resources and local state files have been cleaned up.${NC}"
else
    echo ""
    echo -e "${RED}Terraform destroy failed!${NC}"
    echo -e "${RED}Some resources may not have been deleted.${NC}"
    echo -e "${YELLOW}Check the Azure Portal for remaining resources.${NC}"
fi

# Return to original directory
cd ../..

echo ""
echo -e "${CYAN}Script completed.${NC}" 