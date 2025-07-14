# 🔍 Azure API Management Observability Guide for VulnShop

## 📊 Table of Contents
1. [Verifying Traffic Goes Through APIM](#verifying-traffic)
2. [Enabling Attack Observability](#attack-observability)
3. [Viewing Attack Attempts](#viewing-attacks)
4. [Setting Up Dashboards](#dashboards)
5. [Real-time Monitoring](#real-time-monitoring)
6. [Attack Patterns Detection](#attack-patterns)

## 🔄 Verifying Traffic Goes Through APIM <a name="verifying-traffic"></a>

### Method 1: Check Response Headers
When traffic goes through APIM, it adds specific headers:

```bash
# Test from your local machine
curl -i http://your-apim-url/api/products

# Look for these headers:
# X-Azure-RequestId: [unique-id]
# X-Azure-Ref: [reference-id]
```

### Method 2: Azure Portal Verification
1. Go to Azure Portal → Your APIM instance
2. Navigate to **APIs** → **VulnShop API**
3. Click on **Test** tab
4. You'll see recent requests with:
   - Request/Response details
   - Processing time
   - Status codes
   - Applied policies

### Method 3: Developer Portal
Access your APIM developer portal:
```
https://[your-apim-name].developer.azure-api.net
```

### Method 4: Direct Backend Test
Compare responses:
```bash
# Direct backend (should fail if properly configured)
curl http://your-vm-ip:3001/api/products

# Through APIM (should work)
curl https://[your-apim-name].azure-api.net/vulnshop/api/products
```

## 🛡️ Enabling Attack Observability <a name="attack-observability"></a>

### Step 1: Enable Application Insights

```bash
# Using Azure CLI
az apim update \
  --name [your-apim-name] \
  --resource-group [your-rg] \
  --enable-managed-identity true

# Create Application Insights
az monitor app-insights component create \
  --app vulnshop-insights \
  --location [your-location] \
  --resource-group [your-rg]

# Link to APIM
az apim logger create \
  --resource-group [your-rg] \
  --service-name [your-apim-name] \
  --logger-id appinsights-logger \
  --logger-type applicationInsights \
  --description "VulnShop Attack Logger" \
  --credentials instrumentationKey=[your-instrumentation-key]
```

### Step 2: Configure Diagnostic Settings

1. In Azure Portal → APIM → **Diagnostic settings**
2. Click **+ Add diagnostic setting**
3. Configure:
   - Name: `vulnshop-security-logs`
   - Logs to collect:
     - ✅ GatewayLogs
     - ✅ AllMetrics
   - Destination:
     - ✅ Send to Log Analytics workspace
     - ✅ Archive to storage account (for long-term retention)
     - ✅ Stream to Event Hub (for real-time processing)

### Step 3: Apply Enhanced Security Policy

Update your APIM policies to log attack attempts:

```xml
<policies>
    <inbound>
        <!-- Log all requests with details -->
        <log-to-eventhub logger-id="security-logger">@{
            return new JObject(
                new JProperty("timestamp", DateTime.UtcNow.ToString()),
                new JProperty("ip", context.Request.IpAddress),
                new JProperty("method", context.Request.Method),
                new JProperty("url", context.Request.Url.ToString()),
                new JProperty("headers", context.Request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value))),
                new JProperty("body", context.Request.Body?.As<string>(preserveContent: true) ?? ""),
                new JProperty("user-agent", context.Request.Headers.GetValueOrDefault("User-Agent", ""))
            ).ToString();
        }</log-to-eventhub>
        
        <!-- Detect and log SQL injection attempts -->
        <set-variable name="isSqlInjection" value="@{
            string body = context.Request.Body?.As<string>(preserveContent: true) ?? "";
            string url = context.Request.Url.ToString();
            string allContent = (body + url).ToLower();
            
            return allContent.Contains("' or") ||
                   allContent.Contains("drop table") ||
                   allContent.Contains("union select") ||
                   allContent.Contains("exec(") ||
                   allContent.Contains("xp_cmdshell");
        }" />
        
        <choose>
            <when condition="@(context.Variables.GetValueOrDefault<bool>("isSqlInjection"))">
                <log-to-eventhub logger-id="attack-logger">@{
                    return new JObject(
                        new JProperty("attack_type", "SQL_INJECTION"),
                        new JProperty("severity", "HIGH"),
                        new JProperty("blocked", true),
                        new JProperty("timestamp", DateTime.UtcNow),
                        new JProperty("source_ip", context.Request.IpAddress),
                        new JProperty("target_endpoint", context.Request.Url.Path),
                        new JProperty("payload", context.Request.Url.Query)
                    ).ToString();
                }</log-to-eventhub>
            </when>
        </choose>
    </inbound>
</policies>
```

## 🔍 Viewing Attack Attempts <a name="viewing-attacks"></a>

### Using Log Analytics Queries

1. Go to Azure Portal → Log Analytics workspace
2. Run these KQL queries:

**All Security Events:**
```kql
ApiManagementGatewayLogs
| where TimeGenerated > ago(24h)
| where ResponseCode >= 400
| project TimeGenerated, CallerIpAddress, Method, Url, ResponseCode, ResponseSize
| order by TimeGenerated desc
```

**SQL Injection Attempts:**
```kql
ApiManagementGatewayLogs
| where TimeGenerated > ago(7d)
| where Url contains "'" or Url contains "--" or Url contains "union"
| project TimeGenerated, CallerIpAddress, Method, Url, ResponseCode
| summarize AttackCount = count() by CallerIpAddress, bin(TimeGenerated, 1h)
```

**Top Attack Sources:**
```kql
ApiManagementGatewayLogs
| where TimeGenerated > ago(7d)
| where ResponseCode == 403 or ResponseCode == 400
| summarize AttackCount = count() by CallerIpAddress
| top 10 by AttackCount desc
| render piechart
```

### Using Application Insights

1. Navigate to Application Insights → **Logs**
2. Query custom events:

```kql
customEvents
| where name == "SecurityViolation"
| extend attackType = tostring(customDimensions.attack_type)
| extend sourceIP = tostring(customDimensions.source_ip)
| summarize count() by attackType, bin(timestamp, 1h)
| render timechart
```

## 📊 Setting Up Dashboards <a name="dashboards"></a>

### Create Security Dashboard

1. In Azure Portal → **Dashboard** → **+ New dashboard**
2. Name it "VulnShop Security Monitor"
3. Add these tiles:

**Attack Overview Tile:**
```kql
ApiManagementGatewayLogs
| where TimeGenerated > ago(24h)
| where ResponseCode >= 400
| summarize 
    TotalRequests = count(),
    BlockedRequests = countif(ResponseCode == 403),
    SQLInjections = countif(Url contains "'" or Url contains "union"),
    XSSAttempts = countif(Url contains "<script" or Url contains "javascript:")
| project AttackType = pack_array("Total", "Blocked", "SQL Injection", "XSS"),
          Count = pack_array(TotalRequests, BlockedRequests, SQLInjections, XSSAttempts)
| mvexpand AttackType to typeof(string), Count to typeof(long)
| render columnchart
```

**Real-time Attack Map:**
```kql
ApiManagementGatewayLogs
| where TimeGenerated > ago(1h)
| where ResponseCode >= 400
| summarize AttackCount = count() by CallerIpAddress
| join kind=leftouter (
    externaldata(network:string, geoname_id:string, continent_code:string, continent_name:string, country_iso_code:string, country_name:string, is_anonymous_proxy:bool, is_satellite_provider:bool)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/master/data/geoip2-ipv4.csv"]
) on $left.CallerIpAddress == $right.network
| project country_name, AttackCount
| render map
```

### Email Alerts Configuration

1. Go to **Alerts** → **+ Create** → **Alert rule**
2. Configure conditions:
   - Signal: Custom log search
   - Query:
   ```kql
   ApiManagementGatewayLogs
   | where ResponseCode == 403
   | where TimeGenerated > ago(5m)
   | count
   ```
   - Threshold: Greater than 10
   - Frequency: Every 5 minutes

## 🚨 Real-time Monitoring <a name="real-time-monitoring"></a>

### Setup Event Hub for Streaming

```bash
# Create Event Hub
az eventhubs namespace create \
  --name vulnshop-security-events \
  --resource-group [your-rg] \
  --location [your-location]

az eventhubs eventhub create \
  --name attack-stream \
  --namespace-name vulnshop-security-events \
  --resource-group [your-rg]
```

### Azure Stream Analytics Job

Create a Stream Analytics job to process attacks in real-time:

```sql
-- Input: Event Hub
-- Output: Power BI / Cosmos DB

SELECT
    System.Timestamp() AS WindowEnd,
    CallerIpAddress,
    COUNT(*) AS AttackCount,
    COLLECT() AS AttackDetails
INTO
    [PowerBIOutput]
FROM
    [EventHubInput]
WHERE
    ResponseCode >= 400
GROUP BY
    CallerIpAddress,
    TumblingWindow(minute, 5)
HAVING
    COUNT(*) > 10  -- Alert on IPs with >10 attacks in 5 minutes
```

## 🎯 Attack Patterns Detection <a name="attack-patterns"></a>

### Common Attack Patterns in VulnShop

1. **SQL Injection Patterns:**
   - `' OR '1'='1`
   - `'; DROP TABLE users; --`
   - `UNION SELECT * FROM users`

2. **XSS Patterns:**
   - `<script>alert('XSS')</script>`
   - `javascript:alert(1)`
   - `<img src=x onerror=alert(1)>`

3. **Authentication Bypass:**
   - `admin' --`
   - `' OR id=1 --`

### Detection Rules

Add these to your APIM policy:

```xml
<!-- Advanced Attack Detection -->
<set-variable name="attackScore" value="@{
    int score = 0;
    string content = (context.Request.Body?.As<string>(preserveContent: true) ?? "") + 
                    context.Request.Url.ToString();
    
    // SQL Injection indicators
    if (content.Contains("'") && content.Contains("OR")) score += 3;
    if (content.Contains("UNION") && content.Contains("SELECT")) score += 5;
    if (content.Contains("xp_") || content.Contains("sp_")) score += 5;
    
    // XSS indicators
    if (content.Contains("<script")) score += 4;
    if (content.Contains("javascript:")) score += 3;
    if (content.Contains("onerror=")) score += 3;
    
    // Command injection
    if (content.Contains(";") && content.Contains("cat ")) score += 4;
    if (content.Contains("&&") || content.Contains("||")) score += 2;
    
    return score;
}" />

<choose>
    <when condition="@(context.Variables.GetValueOrDefault<int>("attackScore") >= 5)">
        <return-response>
            <set-status code="403" reason="Forbidden" />
            <set-body>{"error": "Security violation detected", "code": "ATTACK_DETECTED"}</set-body>
        </return-response>
    </when>
</choose>
```

## 🔧 Quick Commands Reference

```bash
# View APIM logs in real-time
az monitor log-analytics query \
  --workspace [workspace-id] \
  --analytics-query "ApiManagementGatewayLogs | where TimeGenerated > ago(5m)" \
  --output table

# Export attack data
az monitor log-analytics query \
  --workspace [workspace-id] \
  --analytics-query "ApiManagementGatewayLogs | where ResponseCode >= 400" \
  --output csv > attacks.csv

# Get APIM metrics
az monitor metrics list \
  --resource [apim-resource-id] \
  --metric "Requests" \
  --aggregation Total \
  --interval PT1M
```

## 📈 KPIs to Monitor

1. **Attack Rate**: Blocked requests per minute
2. **Attack Sources**: Unique IPs attempting attacks
3. **Attack Types**: Distribution of SQL, XSS, etc.
4. **Response Time**: Impact of security policies
5. **False Positive Rate**: Legitimate requests blocked

## 🚀 Next Steps

1. Configure Azure Sentinel for advanced threat hunting
2. Implement rate limiting per IP address
3. Add machine learning-based anomaly detection
4. Create runbooks for automated response
5. Set up geo-blocking for high-risk regions 