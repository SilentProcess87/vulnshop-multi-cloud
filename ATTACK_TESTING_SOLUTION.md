# 🔍 Attack Testing Solution Guide

## Problem Diagnosis

You were getting **HTTP 000** responses because:
- **WSL/bash on Windows** has networking issues with HTTPS requests to APIM
- Your attacks ARE actually working - they return **HTTP 200** when using PowerShell
- Your minimal Cortex policy has **NO security features**, so attacks pass through

## Current State

✅ **What's Working:**
- APIM routing is functional
- Subscription key authentication works
- Cortex logging is active
- Attacks successfully reach the backend (HTTP 200)

❌ **What's NOT Working:**
- No attack blocking (by design - you removed security features)
- Bash scripts fail on Windows due to WSL networking issues

## Solutions

### 1. **For Windows Users - Use PowerShell Scripts**

Run the new PowerShell attack tester:
```powershell
# Single run
.\attack-tester-windows.ps1

# Continuous attacks (generates more logs)
.\attack-tester-windows.ps1 -Continuous

# Test against local backend
.\attack-tester-windows.ps1 -Target local
```

### 2. **If You Want Attack Blocking + Logging**

You need to add security features back to your policy while keeping Cortex integration. Create a balanced policy:

```xml
<policies>
    <inbound>
        <!-- Cortex logging setup -->
        <set-variable name="requestBody" value="@((context.Request?.Body?.As<string>(preserveContent: true)) ?? string.Empty)" />
        <set-variable name="requestHeaders" value="@(JsonConvert.SerializeObject(context.Request.Headers))" />
        
        <!-- Basic security: Block obvious SQL injection -->
        <choose>
            <when condition="@(context.Request.Url.Query.Contains("' OR") || context.Request.Url.Query.Contains("DROP TABLE"))">
                <return-response>
                    <set-status code="403" reason="Forbidden" />
                    <set-body>Attack detected and blocked</set-body>
                </return-response>
            </when>
        </choose>
        
        <!-- CORS -->
        <cors allow-credentials="false">
            <allowed-origins>
                <origin>*</origin>
            </allowed-origins>
            <allowed-methods>
                <method>*</method>
            </allowed-methods>
            <allowed-headers>
                <header>*</header>
            </allowed-headers>
        </cors>
    </inbound>
    <backend>
        <forward-request />
    </backend>
    <outbound>
        <!-- Your existing Cortex integration here -->
    </outbound>
</policies>
```

### 3. **Understanding Attack Results**

When you run attacks:

- **HTTP 200** = Attack succeeded (reached backend)
- **HTTP 403** = Attack was blocked by security policy
- **HTTP 401** = Authentication required
- **HTTP 000** = Connection failed (WSL issue on Windows)

### 4. **Checking Your Logs**

After running attacks, check:

1. **Cortex Dashboard** 
   - Should show all HTTP 200 requests with attack payloads
   - Look for SQL injection patterns, XSS attempts, etc.

2. **APIM Analytics**
   - Go to Azure Portal → Your APIM → Analytics
   - Filter by time range when you ran attacks
   - Look for request patterns

3. **Backend Logs**
   - Your VulnShop backend shows vulnerabilities it has
   - Attacks that return 200 are exploiting these

## Recommendations

### For Testing/Demo:
- Keep minimal policy (no security)
- Use PowerShell scripts on Windows
- Attacks will succeed and generate logs

### For Production:
- Add security features back
- Block attacks while still logging to Cortex
- Use rate limiting and input validation

## Quick Test Commands

```powershell
# Test if attacks are passing through
$h = @{"Ocp-Apim-Subscription-Key"="8722910157d34e698f969cf34c30eeb5"}
Invoke-WebRequest "https://apim-vulnshop-t7up5q.azure-api.net/vulnshop/api/products?search=' OR '1'='1" -Headers $h

# Generate lots of attack logs
.\attack-tester-windows.ps1 -Continuous
```

## Need Help?

- Attacks returning 200? Working as designed (no security)
- Want to block attacks? Add security rules to policy
- Bash scripts failing? Use PowerShell on Windows 