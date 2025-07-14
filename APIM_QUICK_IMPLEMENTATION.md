# 🚀 Quick Implementation: APIM-Only Communication

## What's Changed

### Frontend
- **API Service** (`frontend/src/services/api.js`): Now uses environment variables for API URL
- **Vite Config**: Removed proxy - all API calls go through APIM
- **Environment Files**: Created for production and development

### New Files Created
- `frontend/env.production` - Production APIM URL
- `frontend/env.development` - Development configuration
- `configure-apim-integration.sh` - Main setup script
- `deploy-with-apim.sh` - Frontend build script
- `secure-backend-for-apim.sh` - Backend security script

## Quick Setup Steps

### 1. Run Configuration Script
```bash
# On Windows PowerShell
./configure-apim-integration.sh

# This creates all necessary files and configurations
```

### 2. Get APIM IPs
```bash
az apim show --name apim-vulnshop-t7up5q --resource-group rg-vulnshop-t7up5q --query 'publicIpAddresses' -o tsv
```
Save these IPs - you'll need them for nginx configuration.

### 3. Build Frontend for Production
```bash
cd frontend

# Copy environment files
copy env.production .env.production
copy env.development .env.development

# Install and build
npm install
npm run build

# The dist folder now has frontend configured for APIM
```

### 4. Deploy to VM

**Option A: Using the fix-deployment script (already on VM)**
```bash
# SSH to VM
ssh azureuser@vulnshop-dev-t7up5q.eastus.cloudapp.azure.com

# Run deployment
cd /var/www/vulnshop
sudo ./fix-deployment.sh
```

**Option B: Manual deployment**
```bash
# Copy built frontend to VM
scp -r frontend/dist/* azureuser@vulnshop-dev-t7up5q.eastus.cloudapp.azure.com:/tmp/frontend-dist/

# SSH to VM
ssh azureuser@vulnshop-dev-t7up5q.eastus.cloudapp.azure.com

# Deploy frontend
sudo cp -r /tmp/frontend-dist/* /var/www/vulnshop/frontend/dist/
```

### 5. Secure Backend (On VM)

```bash
# Create nginx config with APIM IPs
sudo nano /etc/nginx/sites-available/vulnshop
```

Add this to the `/api/` location block:
```nginx
location /api/ {
    # Replace with your APIM IPs from step 2
    allow 20.x.x.x;  # APIM IP 1
    allow 20.x.x.x;  # APIM IP 2
    allow 127.0.0.1; # Localhost
    deny all;
    
    error_page 403 @api_blocked;
    
    proxy_pass http://localhost:3001;
    # ... rest of proxy config
}

location @api_blocked {
    default_type application/json;
    return 403 '{"error": "Use APIM: https://apim-vulnshop-t7up5q.azure-api.net/vulnshop"}';
}
```

```bash
# Test and reload nginx
sudo nginx -t
sudo systemctl reload nginx
```

## Testing

### 1. Test Frontend Connection
Open browser: `http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com`
- Check browser console for: `API Configuration: {baseURL: "https://apim-vulnshop-t7up5q.azure-api.net/vulnshop/api"}`
- Try logging in with test credentials

### 2. Test APIM Routing
```bash
# Should work (through APIM)
curl -i https://apim-vulnshop-t7up5q.azure-api.net/vulnshop/api/products

# Should fail with 403 (direct access blocked)
curl -i http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com/api/products
```

### 3. Test Attack Blocking
```bash
# Should return 403 with attack details
curl "https://apim-vulnshop-t7up5q.azure-api.net/vulnshop/api/products?q=' OR '1'='1"
```

## Troubleshooting

### Frontend shows "Network Error"
1. Check browser console for CORS errors
2. Ensure APIM policy has CORS enabled
3. Verify API URL in browser: `console.log(import.meta.env.VITE_API_URL)`

### API calls return 404
1. Check APIM configuration:
   - API suffix: `/vulnshop`
   - Backend URL: `http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com`
2. Test APIM directly: `curl https://apim-vulnshop-t7up5q.azure-api.net/vulnshop/api/products`

### Direct access still works
1. Verify nginx configuration has deny rules
2. Check nginx was reloaded: `sudo systemctl reload nginx`
3. Verify with: `curl -I http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com/api/products`

## Architecture Overview

```
┌─────────────┐     HTTPS      ┌──────────────┐     HTTP      ┌─────────────┐
│   Browser   │ ─────────────> │     APIM     │ ────────────> │   Backend   │
│             │                 │              │                │   (VM:80)   │
└─────────────┘                 └──────────────┘                └─────────────┘
                                       │
                                       ├─ CORS Headers
                                       ├─ Attack Detection  
                                       ├─ Rate Limiting
                                       └─ Cortex Logging
```

## Security Benefits

1. **No Direct Backend Access** - All traffic must go through APIM
2. **Attack Detection** - SQL injection, XSS, etc. blocked at APIM
3. **Rate Limiting** - 100 requests/minute per IP
4. **Audit Trail** - All requests logged to Cortex
5. **Security Headers** - Added by APIM policy

Your VulnShop is now configured for APIM-only communication! 🎉 