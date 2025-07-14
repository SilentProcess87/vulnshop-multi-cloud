# 🔥 VulnShop Attack Testing Guide

## ⚠️ IMPORTANT SAFETY NOTICE

**DESTRUCTIVE ATTACKS HAVE BEEN REMOVED!** All scripts now use non-destructive testing patterns:

- ✅ **NO** DROP TABLE commands
- ✅ **NO** DELETE or TRUNCATE operations  
- ✅ **NO** UPDATE statements that modify data
- ✅ **NO** File system modifications
- ✅ Only SELECT queries and read operations
- ✅ Test data creation is clearly marked

## Overview

This guide explains how to use the attack simulation scripts to test VulnShop's security and generate logs for analysis in Cortex and Azure API Management.

## 🛠️ Available Attack Scripts

### 1. **attack-simulator.sh** - Basic Attack Suite
- Tests common vulnerabilities (SQL injection, XSS, IDOR, etc.)
- ~25 different attack patterns
- Simple output format

### 2. **advanced-attack-suite.sh** - Advanced Testing
- Encoded attacks (URL, Base64, Unicode)
- NoSQL injection patterns
- JWT manipulation
- Business logic attacks
- Generates detailed log files
- Provides statistics and success rates

### 3. **attack-generator.ps1** - PowerShell Continuous Generator
- Windows PowerShell compatible
- Continuous attack generation
- Randomized attack patterns
- Real-time statistics

## 🚀 Quick Start

### Linux/macOS

```bash
# Make scripts executable
chmod +x attack-simulator.sh advanced-attack-suite.sh

# Test against APIM (default)
./attack-simulator.sh

# Test against local backend
./attack-simulator.sh local

# Run advanced suite
./advanced-attack-suite.sh
```

### Windows PowerShell

```powershell
# Run for 60 seconds (default)
.\attack-generator.ps1

# Run for 5 minutes
.\attack-generator.ps1 -Duration 300

# Run continuously (Ctrl+C to stop)
.\attack-generator.ps1 -Continuous $true

# Target local backend
.\attack-generator.ps1 -Target local
```

## 📊 Attack Categories

### SQL Injection
- Classic: `' OR '1'='1`
- Union-based: `' UNION SELECT * FROM users--`
- Blind: `1' AND (SELECT COUNT(*) FROM users) > 0--`
- Encoded variants (URL, Unicode, Base64)

### Cross-Site Scripting (XSS)
- Script tags: `<script>alert('XSS')</script>`
- Event handlers: `<img src=x onerror=alert(1)>`
- SVG: `<svg onload=alert('XSS')>`
- Polyglot payloads

### Command Injection
- Shell commands: `; ls -la`
- Pipe injection: `| whoami`
- Backticks: `` `cat /etc/passwd` ``

### Authentication Attacks
- Brute force login attempts
- JWT manipulation (none algorithm, weak secret)
- Mass assignment (role elevation)

### Business Logic
- Negative prices
- Integer overflow
- Race conditions

## 📈 Viewing Results

### 1. **Local Log Files**
After running `advanced-attack-suite.sh`:
```bash
# View the generated log file
cat attack-results-*.log

# Get summary statistics
tail -n 10 attack-results-*.log
```

### 2. **Azure Portal - APIM Analytics**
1. Go to Azure Portal
2. Navigate to your APIM instance
3. **Analytics** → **Requests**
4. Filter by:
   - Status Code: 403 (blocked attacks)
   - Status Code: 200 (successful attacks)
   - Time range: Last hour

### 3. **Cortex Dashboard**
Check your Cortex dashboard for:
- Request patterns
- Attack signatures
- Source IPs
- Response times

### 4. **APIM Diagnostics**
```bash
# Get recent 403 responses
az monitor activity-log list \
  --resource-group rg-vulnshop-t7up5q \
  --resource-id /subscriptions/.../providers/Microsoft.ApiManagement/service/apim-vulnshop-t7up5q \
  --query "[?contains(status.value, 'Failed')]" \
  -o table
```

## 🔍 Analyzing Attack Success

### Blocked Attacks (Good)
- HTTP 403: Security policy blocked the attack
- HTTP 401: Authentication required
- HTTP 429: Rate limited

### Successful Attacks (Bad)
- HTTP 200/201: Attack reached the backend
- Check response body for sensitive data
- Indicates vulnerability exists

### Example Analysis
```bash
# Count blocked vs successful attacks
grep "HTTP 403" attack-results-*.log | wc -l
grep "HTTP 200" attack-results-*.log | wc -l

# Find successful SQL injections
grep -A2 "SQL.*HTTP 200" attack-results-*.log
```

## 🛡️ Fixing Vulnerabilities

Based on test results, apply appropriate policies:

### If SQL Injection Succeeds
Apply `policies/simple-security-policy.xml` or add to your current policy:
```xml
<when condition="@(context.Request.Url.Query.GetValueOrDefault("q", "").Contains("' OR '"))">
    <return-response>
        <set-status code="403" reason="SQL Injection Detected" />
    </return-response>
</when>
```

### If XSS Succeeds
Add XSS detection:
```xml
<when condition="@(context.Request.Url.Query.GetValueOrDefault("q", "").Contains("<script"))">
    <return-response>
        <set-status code="403" reason="XSS Detected" />
    </return-response>
</when>
```

## 📝 Custom Attack Patterns

### Adding to Bash Scripts
Edit `attack-simulator.sh` and add:
```bash
execute_attack "CUSTOM" \
    "/api/endpoint" \
    "Description of attack" \
    "payload"
```

### Adding to PowerShell
Edit `attack-generator.ps1` and add to `$AttackPatterns`:
```powershell
@{Type="CUSTOM"; Endpoint="/api/endpoint"; Query="payload"; Method="GET"}
```

## ⚠️ Important Notes

1. **Authorization**: Only test systems you own or have permission to test
2. **Rate Limiting**: Scripts include delays to avoid overwhelming servers
3. **Subscription Key**: Update the key in scripts if it changes
4. **Target Selection**: Always verify you're testing the correct endpoint

## 🎯 Recommended Testing Flow

1. **Start with Basic Tests**
   ```bash
   ./attack-simulator.sh
   ```

2. **Run Advanced Suite for Detailed Analysis**
   ```bash
   ./advanced-attack-suite.sh
   ```

3. **Generate Continuous Load (for stress testing)**
   ```powershell
   .\attack-generator.ps1 -Duration 300
   ```

4. **Analyze Results**
   - Check log files
   - Review APIM Analytics
   - Monitor Cortex dashboard

5. **Apply Security Policies**
   - Fix identified vulnerabilities
   - Re-test to verify fixes

## 🔧 Troubleshooting

### "401 Unauthorized" Errors
- Check subscription key in scripts
- Verify APIM subscription is active

### "000" Status Codes
- Check if backend is running
- Verify network connectivity
- Check APIM backend configuration

### No Attacks Blocked
- Verify security policy is applied in APIM
- Check policy syntax for errors
- Ensure policy is applied to "All operations"

## 📞 Support

- **APIM Issues**: Check Azure Portal → APIM → Diagnostic settings
- **Script Issues**: Review script output and log files
- **Backend Issues**: Check backend logs (`pm2 logs` on VM)

Happy security testing! 🚀 