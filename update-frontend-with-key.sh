#!/bin/bash

# update-frontend-with-key.sh - Update frontend to use APIM subscription key

SUBSCRIPTION_KEY="8722910157d34e698f969cf34c30eeb5"

echo "Updating frontend environment files with subscription key..."

# Update production environment
cat > frontend/.env.production <<EOF
# Production Environment Configuration
VITE_API_URL=https://apim-vulnshop-t7up5q.azure-api.net/vulnshop/api
VITE_API_SUBSCRIPTION_KEY=$SUBSCRIPTION_KEY
EOF

# Update development environment
cat > frontend/.env.development <<EOF
# Development Environment Configuration
VITE_API_URL=https://apim-vulnshop-t7up5q.azure-api.net/vulnshop/api
VITE_API_SUBSCRIPTION_KEY=$SUBSCRIPTION_KEY

# For local backend testing without APIM, comment above and uncomment below:
# VITE_API_URL=http://localhost:3001/api
EOF

echo "✓ Frontend environment files updated with subscription key"
echo ""
echo "Next steps:"
echo "1. Build frontend: cd frontend && npm run build"
echo "2. Deploy to VM: Copy dist/* to /var/www/vulnshop/frontend/dist/"
echo "3. Test in browser - API calls will now include the subscription key" 