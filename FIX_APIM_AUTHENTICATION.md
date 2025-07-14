# 🔐 Fixing APIM Authentication Issues

## Problem Analysis

You're facing two issues:

1. **HTTP 401 (Unauthorized)** - Your APIM requires a subscription key
2. **HTTP 000 (No Connection)** - Attack detection test fails because you removed all security features from the policy

## Why This Happened

When you modified `cortex-enhanced-security-policy.xml` and removed all the security features, you:
- ✅ Kept Cortex integration working
- ❌ Removed attack detection (so attack tests fail with HTTP 000)
- ❓ But APIM still requires authentication (subscription key)

## Solutions

### Solution 1: Disable Subscription Requirement (Quickest)

```bash
# Using Azure CLI
az apim product update \
  --resource-group rg-vulnshop-t7up5q \
  --service-name apim-vulnshop-t7up5q \
  --product-id vulnshop \
  --subscription-required false

# Or at API level
az apim api update \
  --resource-group rg-vulnshop-t7up5q \
  --service-name apim-vulnshop-t7up5q \
  --api-id vulnshop \
  --subscription-required false
```

**Via Portal:**
1. Azure Portal → API Management → `apim-vulnshop-t7up5q`
2. Products → VulnShop Product → Settings
3. Uncheck "Requires subscription"
4. Save

### Solution 2: Get a Subscription Key

```bash
# List existing subscriptions
az apim subscription list \
  --resource-group rg-vulnshop-t7up5q \
  --service-name apim-vulnshop-t7up5q \
  --query "[?productId=='/products/vulnshop']" \
  -o table

# Create a new subscription
az apim subscription create \
  --resource-group rg-vulnshop-t7up5q \
  --service-name apim-vulnshop-t7up5q \
  --product-id vulnshop \
  --name test-subscription \
  --display-name "Test Subscription" \
  --state active

# Get the key
az apim subscription show \
  --resource-group rg-vulnshop-t7up5q \
  --service-name apim-vulnshop-t7up5q \
  --subscription-id test-subscription \
  --query primaryKey -o tsv
```

### Solution 3: Test with Subscription Key

```bash
# Once you have a key, test like this:
SUBSCRIPTION_KEY="your-key-here"

# Test with key
curl -H "Ocp-Apim-Subscription-Key: $SUBSCRIPTION_KEY" \
  https://apim-vulnshop-t7up5q.azure-api.net/vulnshop/api/products
```

## Updated Test Scripts

I've created two new scripts for you:

### 1. `disable-apim-subscription.sh`
Shows how to disable subscription requirement

### 2. `test-apim-with-key.sh`
Tests APIM with or without subscription key

Run them:
```bash
# To disable subscription requirement
chmod +x disable-apim-subscription.sh
./disable-apim-subscription.sh

# To test with key support
chmod +x test-apim-with-key.sh
./test-apim-with-key.sh [optional-key]
```

## About Attack Detection

Your attack detection test fails (HTTP 000) because you removed all security features from the policy. If you want attack detection back, you need to add it to the policy.

### Option A: Use Minimal Policy (No Security)
Use `policies/minimal-cortex-policy.xml` - This only has Cortex integration and CORS

### Option B: Add Back Basic Security
Add this to your policy's `<inbound>` section:
```xml
<!-- Basic Attack Detection -->
<choose>
    <when condition="@(context.Request.Url.Query.GetValueOrDefault("q", "").Contains("' OR '"))">
        <return-response>
            <set-status code="403" reason="Forbidden" />
            <set-header name="Content-Type" exists-action="override">
                <value>application/json</value>
            </set-header>
            <set-body>{"error": "Attack detected", "type": "SQL Injection"}</set-body>
        </return-response>
    </when>
</choose>
```

## Quick Commands

```bash
# 1. Disable subscription requirement
az apim product update --resource-group rg-vulnshop-t7up5q --service-name apim-vulnshop-t7up5q --product-id vulnshop --subscription-required false

# 2. Test without key
curl https://apim-vulnshop-t7up5q.azure-api.net/vulnshop/api/products

# 3. Apply minimal policy
az apim api operation policy set \
  --resource-group rg-vulnshop-t7up5q \
  --service-name apim-vulnshop-t7up5q \
  --api-id vulnshop \
  --operation-id all \
  --policy-file policies/minimal-cortex-policy.xml
```

## What You Should Do

1. **First**: Disable subscription requirement (Solution 1)
2. **Then**: Test your endpoints - they should work without authentication
3. **Optional**: If you want attack detection, add basic security back to your policy
4. **Backend**: Your direct backend access (403) is working correctly

The key issue is that APIM requires authentication by default. Once you disable that or provide a key, your tests will pass. 