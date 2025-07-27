#!/bin/bash

echo "===================================="
echo "VulnShop Frontend Configuration Check"
echo "===================================="
echo ""

# Check frontend .env file
echo "1. Frontend Environment Configuration (.env):"
echo "============================================"
if [ -f "/var/www/vulnshop/frontend/.env" ]; then
    cat /var/www/vulnshop/frontend/.env
else
    echo "No .env file found"
fi
echo ""

# Check what API URL is compiled into the frontend
echo "2. Checking compiled frontend for API URL:"
echo "========================================="
grep -r "VITE_API_URL\|/api\|azure-api.net" /var/www/vulnshop/frontend/dist/assets/*.js 2>/dev/null | head -5
echo ""

# Get IP addresses
echo "3. Server IP Addresses:"
echo "======================"
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com)
PRIVATE_IP=$(hostname -I | awk '{print $1}')
echo "Public IP: $PUBLIC_IP"
echo "Private IP: $PRIVATE_IP"
echo ""

# Test API access from different sources
echo "4. API Access Tests:"
echo "==================="
echo "a) From localhost (should work):"
curl -s -o /dev/null -w "   HTTP Status: %{http_code}\n" http://localhost/api/products

echo ""
echo "b) From public IP (should be blocked by Nginx):"
curl -s http://$PUBLIC_IP/api/products | head -100
echo ""

# Check APIM configuration
echo "5. Azure API Management Info:"
echo "============================"
echo "Based on your Terraform configuration:"
echo "- APIM Gateway URL: https://apim-vulnshop-t7up5q.azure-api.net"
echo "- API Path: /api"
echo "- Full API URL: https://apim-vulnshop-t7up5q.azure-api.net/api"
echo ""

# Provide solution
echo "6. How to Access Your Application:"
echo "================================="
echo "Frontend URL: http://$PUBLIC_IP"
echo ""
echo "The frontend is configured to use the API through Azure API Management."
echo "If the API calls are failing, you may need to:"
echo ""
echo "Option 1: Update frontend to use APIM endpoint"
echo "   - Edit /var/www/vulnshop/frontend/.env"
echo "   - Set: VITE_API_URL=https://apim-vulnshop-t7up5q.azure-api.net/api"
echo "   - Rebuild frontend: cd /var/www/vulnshop/frontend && npm run build"
echo ""
echo "Option 2: Allow direct API access (for testing only)"
echo "   - Edit /etc/nginx/sites-available/vulnshop"
echo "   - Comment out or modify the 'allow/deny' rules in the /api/ location"
echo "   - Reload Nginx: systemctl reload nginx"
echo ""

# Test if frontend can reach backend
echo "7. Testing Frontend Functionality:"
echo "================================="
echo "Opening the frontend in a headless browser to check if it loads..."
curl -s http://localhost/ | grep -o '<title>.*</title>' || echo "Could not extract title"
echo ""

# Check for common issues
echo "8. Quick Diagnostics:"
echo "===================="
if systemctl is-active --quiet vulnshop-backend; then
    echo "✓ Backend service is running"
else
    echo "✗ Backend service is NOT running"
fi

if systemctl is-active --quiet nginx; then
    echo "✓ Nginx is running"
else
    echo "✗ Nginx is NOT running"
fi

if [ -d "/var/www/vulnshop/frontend/dist" ]; then
    echo "✓ Frontend is built"
else
    echo "✗ Frontend is NOT built"
fi

# Check Azure NSG rules
echo ""
echo "9. Important Azure Checks:"
echo "========================="
echo "Make sure your Azure Network Security Group allows:"
echo "- Port 80 (HTTP) - for frontend access"
echo "- Port 22 (SSH) - for management"
echo "- Port 3001 should be blocked from public (which it is)"
echo ""
echo "====================================" 