# 🚀 Quick APIM Setup for VulnShop

## Your APIM Details
- **APIM Name**: `apim-vulnshop-t7up5q`
- **Resource Group**: `rg-vulnshop-t7up5q`
- **Location**: East US
- **Backend VM**: `vulnshop-dev-t7up5q.eastus.cloudapp.azure.com`

## 📋 Quick Steps

### 1. Apply the Merged Policy

```bash
# Option A: Use Azure CLI
az apim api operation policy set \
  --resource-group rg-vulnshop-t7up5q \
  --service-name apim-vulnshop-t7up5q \
  --api-id vulnshop \
  --operation-id all \
  --policy-file policies/cortex-enhanced-security-policy.xml
```

**Option B: Use Portal**
1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to: API Management services → `apim-vulnshop-t7up5q`
3. APIs → VulnShop API → All operations → Policies → `</>`
4. Paste content from `policies/cortex-enhanced-security-policy.xml`

### 2. Configure API Settings

In APIM Portal → APIs → VulnShop API → Settings:
- **Web service URL**: `http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com`
- **API URL suffix**: `vulnshop`
- **Subscription required**: ✅ (recommended) or ❌ (for testing)

### 3. Test Your Configuration

```bash
# Run the test script
chmod +x test-apim-routing.sh
./test-apim-routing.sh

# Or test manually:
# ✅ This should work (through APIM):
curl -i https://apim-vulnshop-t7up5q.azure-api.net/vulnshop/api/products

# ❌ This should be blocked (direct access):
curl -i http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com/api/products
```

### 4. Block Direct Backend Access

```bash
# Get your VM's NSG name
az network nsg list --resource-group rg-vulnshop-t7up5q --query "[].name" -o tsv

# Block port 3001
az network nsg rule create \
  --resource-group rg-vulnshop-t7up5q \
  --nsg-name <YOUR-NSG-NAME> \
  --name Block-Backend-Direct \
  --priority 100 \
  --direction Inbound \
  --access Deny \
  --protocol Tcp \
  --destination-port-ranges 3001 \
  --source-address-prefixes Internet

# Get APIM outbound IPs
az apim show \
  --name apim-vulnshop-t7up5q \
  --resource-group rg-vulnshop-t7up5q \
  --query 'publicIpAddresses' -o tsv
```

### 5. Update nginx on VM (SSH to your VM)

```bash
# SSH to your VM
ssh azureuser@vulnshop-dev-t7up5q.eastus.cloudapp.azure.com

# Edit nginx config
sudo nano /etc/nginx/sites-available/vulnshop

# In the location /api/ block, add:
# Replace with your APIM IPs from step 4
allow <APIM-IP-1>;
allow <APIM-IP-2>;
allow 127.0.0.1;
deny all;

# Reload nginx
sudo nginx -t && sudo systemctl reload nginx
```

## 🔍 What the Policy Does

### Security Features Added:
- ✅ **Attack Detection**: SQL injection, XSS, command injection, path traversal
- ✅ **Attack Scoring**: Blocks requests with score ≥ 5
- ✅ **Rate Limiting**: 100 requests/minute per IP
- ✅ **Security Headers**: HSTS, CSP, X-Frame-Options, etc.
- ✅ **Request Size Limit**: 1MB max
- ✅ **Scanner Blocking**: Blocks SQLMap, Nikto, Burp, etc.

### Cortex Integration Preserved:
- ✅ All requests/responses logged to Cortex
- ✅ Attack scores and types included in Cortex data
- ✅ Security actions (ALLOWED/BLOCKED) tracked

## 📊 Monitor Attacks

### In Azure Portal:
1. APIM → Analytics → See request patterns
2. APIM → Diagnostic settings → Configure Log Analytics

### In Cortex Dashboard:
- Look for `attackScore` and `attackType` fields
- Monitor `securityAction` for blocked attempts

### Sample KQL Query (Log Analytics):
```kql
ApiManagementGatewayLogs
| where TimeGenerated > ago(24h)
| where ResponseCode == 403
| extend AttackInfo = parse_json(ResponseBody)
| project TimeGenerated, CallerIpAddress, 
         AttackType = AttackInfo.attack_type,
         AttackScore = AttackInfo.attack_score
| order by TimeGenerated desc
```

## 🚨 Troubleshooting

### If APIM returns 404:
- Check API URL suffix is `/vulnshop`
- Verify backend URL doesn't include `/api`

### If attacks aren't blocked:
- Ensure policy is applied to "All operations"
- Check Named Values are configured
- Test with exact attack patterns shown

### If Cortex isn't receiving data:
- Verify Named Values: `cortex-api-url`, `cortex-api-key`
- Check Cortex credentials are valid

## 📞 Need Help?

Test your setup:
```bash
# Should return security error JSON
curl "https://apim-vulnshop-t7up5q.azure-api.net/vulnshop/api/products?q=' OR '1'='1"

# Should show APIM headers
curl -I https://apim-vulnshop-t7up5q.azure-api.net/vulnshop/api/products
```

Expected headers through APIM:
- `X-Azure-RequestId`
- `X-Request-ID`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security` 