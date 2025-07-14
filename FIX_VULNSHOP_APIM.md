# VulnShop APIM Integration Fix Guide

This guide explains how to use the comprehensive fix scripts to set up and configure VulnShop with Azure API Management (APIM) integration.

## 📋 Prerequisites

- **Azure Subscription** with APIM instance created
- **Azure CLI** installed (for local execution)
- **Node.js v16+** installed locally
- **SSH access** to the VM (for deployment)

## 🔧 Fix Scripts

Two scripts are provided for different environments:

### 1. **fix-vulnshop-apim.sh** (Bash - Linux/macOS/WSL)
### 2. **fix-vulnshop-apim.ps1** (PowerShell - Windows)

Both scripts can run in two contexts:
- **Azure Context**: Run from your local machine with Azure CLI
- **VM Context**: Run directly on the deployment VM

## 🚀 Quick Start

### From Windows (PowerShell)

```powershell
# 1. Run the fix script locally
.\fix-vulnshop-apim.ps1

# 2. The script will:
#    - Configure APIM
#    - Build the frontend with correct endpoints
#    - Generate deployment instructions
```

### From Linux/macOS/WSL

```bash
# 1. Make the script executable
chmod +x fix-vulnshop-apim.sh

# 2. Run the fix script
./fix-vulnshop-apim.sh

# 3. Follow the deployment instructions provided
```

## 📍 What the Script Does

### When Run Locally (Azure Context)

1. **Checks Azure Login**
   - Verifies you're logged into Azure CLI
   - Gets your subscription details

2. **Configures APIM**
   - Validates APIM instance exists
   - Creates/updates VulnShop API definition
   - Gets APIM outbound IPs for VM security

3. **Builds Frontend**
   - Creates `.env.production` with APIM URL
   - Creates `.env.development` for local testing
   - Builds frontend with production settings

4. **Tests Endpoints**
   - Verifies APIM is accessible
   - Checks attack detection is working

5. **Provides Deployment Steps**
   - Shows SCP commands to copy files
   - Gives SSH instructions for VM setup

### When Run on VM (VM Context)

1. **Secures Backend**
   - Updates nginx to only allow APIM IPs
   - Blocks direct backend access
   - Returns helpful error for blocked requests

2. **Deploys Frontend**
   - Installs dependencies
   - Builds with APIM endpoints
   - Deploys to nginx root

3. **Manages Services**
   - Ensures backend is running with PM2
   - Reloads nginx configuration

## 📝 Configuration Details

The scripts use these settings:
```
APIM Name: apim-vulnshop-t7up5q
Resource Group: rg-vulnshop-t7up5q
APIM URL: https://apim-vulnshop-t7up5q.azure-api.net/vulnshop
Backend VM: vulnshop-dev-t7up5q.eastus.cloudapp.azure.com
```

## 🔐 Security Features

### Frontend Security
- All API calls go through APIM
- CSP headers prevent XSS
- No direct backend access possible

### Backend Security
- nginx IP whitelist (only APIM)
- Custom 403 error with APIM URL
- Health endpoint for monitoring

### APIM Security (with policy)
- SQL injection detection
- XSS prevention
- Rate limiting
- Attack scoring and blocking
- Cortex logging integration

## 📊 Monitoring & Testing

### Test URLs After Setup

1. **Frontend** (Public Access)
   ```
   http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com
   ```

2. **APIM API** (Protected)
   ```
   https://apim-vulnshop-t7up5q.azure-api.net/vulnshop/api/products
   ```

3. **Direct API** (Should be Blocked)
   ```
   http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com/api/products
   ```

### Expected Results
- ✅ Frontend loads normally
- ✅ APIM API returns products
- ❌ Direct API returns 403 with APIM redirect message

## 🛠️ Manual Steps After Script

### 1. Apply Security Policy in APIM

1. Go to Azure Portal
2. Navigate to your APIM instance
3. APIs → VulnShop → All operations
4. Click on `</> Policy code editor`
5. Paste content from `policies/cortex-enhanced-security-policy.xml`
6. Save

### 2. Deploy to VM (if run locally)

```bash
# Copy frontend build
scp -r frontend/dist/* azureuser@vulnshop-dev-t7up5q.eastus.cloudapp.azure.com:/tmp/frontend/

# Copy fix script
scp fix-vulnshop-apim.sh azureuser@vulnshop-dev-t7up5q.eastus.cloudapp.azure.com:/tmp/

# Copy APIM IPs
scp apim-ips.txt azureuser@vulnshop-dev-t7up5q.eastus.cloudapp.azure.com:/tmp/

# SSH and run on VM
ssh azureuser@vulnshop-dev-t7up5q.eastus.cloudapp.azure.com
sudo bash /tmp/fix-vulnshop-apim.sh
```

## 🔍 Troubleshooting

### Issue: Azure CLI not found
**Solution**: Install Azure CLI
- Windows: https://aka.ms/installazurecliwindows
- Linux: `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash`

### Issue: Not logged into Azure
**Solution**: Run `az login`

### Issue: APIM not found
**Solution**: Ensure APIM instance exists in the specified resource group

### Issue: Frontend build fails
**Solution**: 
- Check Node.js version (`node --version`)
- Update to v16+ if needed
- Clear npm cache: `npm cache clean --force`

### Issue: Direct API still accessible
**Solution**:
- Check nginx config: `sudo nginx -t`
- Verify APIM IPs are correct
- Restart nginx: `sudo systemctl restart nginx`

### Issue: APIM returns 404
**Solution**:
- Check API path in APIM portal
- Verify backend URL is correct
- Test backend health: `curl http://vm-hostname/health`

## 📚 Additional Resources

- [Azure APIM Documentation](https://docs.microsoft.com/azure/api-management/)
- [APIM Security Best Practices](https://docs.microsoft.com/azure/api-management/api-management-security-best-practices)
- [Cortex SIEM Integration](https://docs.paloaltonetworks.com/cortex)

## 🎯 Success Criteria

Your VulnShop APIM integration is successful when:

1. ✅ Frontend loads at VM URL
2. ✅ Login works with test credentials (admin/admin123)
3. ✅ Products load through APIM
4. ✅ Direct API access returns 403
5. ✅ Attack attempts are blocked by APIM
6. ✅ All traffic appears in APIM analytics
7. ✅ Cortex receives detailed logs

## 💡 Tips

- Run the script from the project root directory
- Keep the APIM IPs file for future updates
- Monitor APIM metrics for attack attempts
- Test with OWASP ZAP through APIM endpoint
- Use Cortex dashboards for security insights 