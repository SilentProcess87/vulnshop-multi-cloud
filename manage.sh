#!/bin/bash

# Unified management script for the VulnShop API project
# This script consolidates deployment, configuration, and testing tasks.

set -e

# --- Configuration ---
API_BASE_URL=${API_BASE_URL:-"http://localhost:3001"}
RESOURCE_GROUP=${RESOURCE_GROUP:-"vulnshop-rg"}
LOCATION=${LOCATION:-"eastus"}
APIM_NAME=${APIM_NAME:-"vulnshop-apim"}
BACKEND_URL=${BACKEND_URL:-"http://vulnshop-backend.azurewebsites.net"}

# --- Helper Functions ---
function print_header() {
    echo -e "\n\n=================================================="
    echo -e "  $1"
    echo -e "==================================================\n"
}

# --- Task Functions ---
function deploy_backend() {
    print_header "Deploying Backend"
    # Add backend deployment commands here
    # Example: az webapp up --name your-backend-app --resource-group $RESOURCE_GROUP
    echo "Backend deployment logic goes here."
}

function deploy_frontend() {
    print_header "Deploying Frontend"
    # Add frontend deployment commands here
    # Example: az storage blob upload-batch --account-name yourstorage -s ./frontend/dist -d '$web'
    echo "Frontend deployment logic goes here."
}

function configure_apim() {
    print_header "Configuring Azure API Management"
    
    echo "Creating resource group: $RESOURCE_GROUP"
    # az group create --name $RESOURCE_GROUP --location $LOCATION
    
    echo "Creating APIM instance: $APIM_NAME"
    # az apim create --name $APIM_NAME --resource-group $RESOURCE_GROUP --location $LOCATION --publisher-email "admin@example.com" --publisher-name "VulnShop"
    
    echo "Importing API from OpenAPI spec"
    # az apim api import --path apim-swagger.json --resource-group $RESOURCE_GROUP --service-name $APIM_NAME --display-name "VulnShop API" --backend-url $BACKEND_URL
    
    echo "Applying OWASP Top 10 Policy"
    # az apim api policy import --path policies/owasp-top10-protection.xml --resource-group $RESOURCE_GROUP --service-name $APIM_NAME --api-id "vulnshop-api"
    
    echo "APIM configuration logic goes here."
}

function run_tests() {
    print_header "Running Non-Destructive Attack Tests"
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        ./comprehensive-attack.ps1
    else
        chmod +x comprehensive-attack.sh
        ./comprehensive-attack.sh
    fi
}

function check_traffic() {
    print_header "Checking APIM Traffic"
    # Add traffic checking commands here
    # Example: az monitor metrics list --resource "/subscriptions/.../resourceGroups/.../providers/Microsoft.ApiManagement/service/your-apim" --metric "Requests"
    echo "APIM traffic checking logic goes here."
}

function show_usage() {
    echo "Usage: $0 {deploy-all|deploy-backend|deploy-frontend|configure-apim|run-tests|check-traffic}"
    echo
    echo "Commands:"
    echo "  deploy-all        : Deploy both backend and frontend"
    echo "  deploy-backend    : Deploy the backend application"
    echo "  deploy-frontend   : Deploy the frontend application"
    echo "  configure-apim    : Configure Azure API Management instance"
    echo "  run-tests         : Run non-destructive attack tests"
    echo "  check-traffic     : Check traffic on the APIM instance"
    echo
}

# --- Main Logic ---
if [ "$#" -ne 1 ]; then
    show_usage
    exit 1
fi

case "$1" in
    deploy-all)
        deploy_backend
        deploy_frontend
        ;;
    deploy-backend)
        deploy_backend
        ;;
    deploy-frontend)
        deploy_frontend
        ;;
    configure-apim)
        configure_apim
        ;;
    run-tests)
        run_tests
        ;;
    check-traffic)
        check_traffic
        ;;
    *)
        show_usage
        exit 1
        ;;
esac

echo -e "\nOperation '$1' completed successfully.\n" 