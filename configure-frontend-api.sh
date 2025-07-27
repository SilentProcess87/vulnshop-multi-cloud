#!/bin/bash

echo "========================================"
echo "VulnShop Frontend API Configuration Tool"
echo "========================================"
echo ""

# Function to update frontend config and rebuild
update_frontend() {
    local api_url=$1
    
    echo "Updating frontend configuration..."
    echo "Setting API URL to: $api_url"
    
    # Create/update .env file
    cat > /var/www/vulnshop/frontend/.env << EOF
# Frontend Environment Configuration
VITE_API_URL=$api_url
EOF
    
    echo "✓ Updated .env file"
    
    # Rebuild frontend
    echo ""
    echo "Rebuilding frontend..."
    cd /var/www/vulnshop/frontend
    
    # Install dependencies if needed
    if [ ! -d "node_modules" ]; then
        echo "Installing dependencies..."
        npm install
    fi
    
    # Build the frontend
    npm run build
    
    if [ $? -eq 0 ]; then
        echo "✓ Frontend rebuilt successfully"
    else
        echo "✗ Frontend build failed"
        return 1
    fi
    
    # Fix permissions
    chown -R www-data:www-data /var/www/vulnshop/frontend/dist
    
    return 0
}

# Fix git repository ownership
echo "1. Fixing Git repository ownership issue..."
git config --global --add safe.directory /var/www/vulnshop
echo "✓ Git repository marked as safe"
echo ""

# Present options
echo "2. Choose API configuration:"
echo "==========================="
echo "1) Use Azure API Management (Recommended for production)"
echo "   URL: https://apim-vulnshop-t7up5q.azure-api.net/api"
echo ""
echo "2) Use direct API access (For testing only)"
echo "   URL: /api"
echo ""
echo "3) Custom API URL"
echo ""

# If running non-interactively, use APIM by default
if [ -n "$1" ]; then
    CHOICE=$1
else
    read -p "Enter your choice (1-3): " CHOICE
fi

case $CHOICE in
    1)
        API_URL="https://apim-vulnshop-t7up5q.azure-api.net/api"
        echo ""
        echo "Using Azure API Management endpoint..."
        ;;
    2)
        API_URL="/api"
        echo ""
        echo "Using direct API access..."
        echo "Note: You'll need to update Nginx configuration to allow external access."
        ;;
    3)
        read -p "Enter custom API URL: " API_URL
        ;;
    *)
        echo "Invalid choice. Using Azure API Management by default..."
        API_URL="https://apim-vulnshop-t7up5q.azure-api.net/api"
        ;;
esac

# Update frontend
echo ""
update_frontend "$API_URL"

# If using direct access, offer to update Nginx
if [ "$CHOICE" = "2" ]; then
    echo ""
    echo "3. Update Nginx configuration for direct API access?"
    echo "===================================================="
    echo "This will remove IP restrictions on the /api/ endpoint."
    echo "WARNING: This reduces security and should only be used for testing!"
    echo ""
    
    if [ -n "$2" ] && [ "$2" = "yes" ]; then
        UPDATE_NGINX="y"
    else
        read -p "Update Nginx configuration? (y/N): " UPDATE_NGINX
    fi
    
    if [ "$UPDATE_NGINX" = "y" ] || [ "$UPDATE_NGINX" = "Y" ]; then
        echo "Updating Nginx configuration..."
        
        # Backup current config
        cp /etc/nginx/sites-available/vulnshop /etc/nginx/sites-available/vulnshop.backup
        
        # Create new config without IP restrictions
        cat > /etc/nginx/sites-available/vulnshop << 'EOF'
server {
    listen 80;
    server_name _;
    
    # Serve frontend
    location / {
        root /var/www/vulnshop/frontend/dist;
        try_files $uri $uri/ /index.html;
    }
    
    # Proxy API requests to backend (OPEN ACCESS - TESTING ONLY)
    location /api/ {
        proxy_pass http://localhost:3001/api/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
EOF
        
        # Test and reload Nginx
        nginx -t
        if [ $? -eq 0 ]; then
            systemctl reload nginx
            echo "✓ Nginx configuration updated and reloaded"
        else
            echo "✗ Nginx configuration test failed, reverting..."
            mv /etc/nginx/sites-available/vulnshop.backup /etc/nginx/sites-available/vulnshop
        fi
    fi
fi

# Display final status
echo ""
echo "4. Configuration Complete!"
echo "========================="
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com)
echo "Frontend URL: http://$PUBLIC_IP"
echo "API Configuration: $API_URL"
echo ""

# Test the configuration
echo "5. Testing configuration..."
echo "=========================="
echo "Testing frontend access..."
FRONTEND_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/)
if [ "$FRONTEND_STATUS" = "200" ]; then
    echo "✓ Frontend is accessible"
else
    echo "✗ Frontend returned status: $FRONTEND_STATUS"
fi

echo ""
echo "Testing API access..."
if [ "$API_URL" = "/api" ]; then
    API_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/api/products)
else
    API_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/products")
fi

if [ "$API_STATUS" = "200" ]; then
    echo "✓ API is accessible"
else
    echo "✗ API returned status: $API_STATUS"
    echo "   Note: If using APIM, ensure the API is properly configured in Azure"
fi

echo ""
echo "========================================"
echo "Configuration completed!"
echo "========================================" 