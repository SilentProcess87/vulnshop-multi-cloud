#!/bin/bash

# VulnShop Azure APIM Deployment Script
# This script automates the deployment of the vulnerable e-commerce application with Azure APIM

set -e

# Configuration
RESOURCE_GROUP="rg-vulnshop"
LOCATION="eastus"
APIM_NAME="vulnshop-apim"
APP_NAME="vulnshop-backend"
PLAN_NAME="vulnshop-plan"
API_ID="vulnshop-api"

echo "🚀 Starting VulnShop deployment..."

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo "❌ Azure CLI is not installed. Please install it first."
    exit 1
fi

# Login to Azure
echo "🔐 Logging into Azure..."
az login

# Create Resource Group
echo "📦 Creating resource group..."
az group create --name $RESOURCE_GROUP --location $LOCATION

# Create App Service Plan
echo "🏗️ Creating App Service Plan..."
az appservice plan create \
  --name $PLAN_NAME \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --is-linux \
  --sku B1

# Create Web App
echo "🌐 Creating Web App..."
az webapp create \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --plan $PLAN_NAME \
  --runtime "NODE|18-lts"

# Configure App Settings
echo "⚙️ Configuring app settings..."
az webapp config appsettings set \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME \
  --settings PORT=8080

# Create API Management (This takes a while)
echo "🛡️ Creating API Management instance (this may take 30+ minutes)..."
az apim create \
  --name $APIM_NAME \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --publisher-name "VulnShop" \
  --publisher-email "admin@vulnshop.com" \
  --sku-name Developer \
  --no-wait

echo "📋 API Management creation started in background..."

# Create deployment package
echo "📦 Creating deployment package..."
zip -r vulnshop.zip . -x "*.git*" "node_modules/*" "*.md" "deploy.sh"

# Deploy to Azure App Service
echo "🚀 Deploying application..."
az webapp deploy \
  --resource-group $RESOURCE_GROUP \
  --name $APP_NAME \
  --src-path vulnshop.zip \
  --type zip

# Wait for APIM to be ready
echo "⏳ Waiting for API Management to be ready..."
az apim wait \
  --name $APIM_NAME \
  --resource-group $RESOURCE_GROUP \
  --created

# Create API in APIM
echo "🔧 Creating API in APIM..."
az apim api create \
  --resource-group $RESOURCE_GROUP \
  --service-name $APIM_NAME \
  --api-id $API_ID \
  --path "/api" \
  --display-name "VulnShop API" \
  --service-url "https://$APP_NAME.azurewebsites.net"

# Import API specification
echo "📄 Importing API specification..."
az apim api import \
  --resource-group $RESOURCE_GROUP \
  --service-name $APIM_NAME \
  --api-id $API_ID \
  --path "/api" \
  --specification-path apim-swagger.json \
  --specification-format OpenApi

# Apply security policies
echo "🔒 Applying security policies..."
az apim api policy create \
  --resource-group $RESOURCE_GROUP \
  --service-name $APIM_NAME \
  --api-id $API_ID \
  --policy-format xml \
  --value @policies/comprehensive-security-policy.xml

# Get URLs
APP_URL="https://$APP_NAME.azurewebsites.net"
APIM_URL="https://$APIM_NAME.azure-api.net"

echo "✅ Deployment completed successfully!"
echo ""
echo "📊 Deployment Summary:"
echo "===================="
echo "Resource Group: $RESOURCE_GROUP"
echo "App Service URL: $APP_URL"
echo "APIM Gateway URL: $APIM_URL"
echo "API Path: $APIM_URL/api"
echo ""
echo "🧪 Testing Commands:"
echo "curl $APP_URL/health"
echo "curl $APIM_URL/api/products"
echo ""
echo "⚠️ Next Steps:"
echo "1. Test the application locally first"
echo "2. Configure DNS and SSL certificates"
echo "3. Set up monitoring and alerts"
echo "4. Apply specific endpoint policies"
echo "5. Configure subscription keys"
echo ""
echo "🔐 Security Testing:"
echo "Test SQL injection: $APP_URL/api/products/search?q=' OR '1'='1"
echo "Test IDOR: $APP_URL/api/orders/1"
echo ""
echo "Clean up: az group delete --name $RESOURCE_GROUP --yes --no-wait" 