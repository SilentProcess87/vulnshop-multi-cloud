# Vulnerable E-commerce Application with Azure APIM

This is a deliberately vulnerable e-commerce application designed for security testing and understanding how Azure API Management (APIM) can protect against common vulnerabilities.

## ⚠️ WARNING
This application contains **intentional security vulnerabilities** and should only be used for:
- Security testing
- Educational purposes
- Demonstrating Azure APIM protection capabilities

**DO NOT** deploy this in production environments.

## Vulnerabilities Included

### 1. **SQL Injection** 
- **Location**: `/api/products/search` endpoint
- **Exploitation**: Try searching for `' OR '1'='1` or `'; DROP TABLE users; --`
- **Impact**: Database compromise, data theft

### 2. **Cross-Site Scripting (XSS)**
- **Location**: Product reviews (if implemented)
- **Exploitation**: Submit `<script>alert('XSS')</script>` in review
- **Impact**: Session hijacking, malicious script execution

### 3. **Insecure Direct Object References (IDOR)**
- **Location**: `/api/orders/:id` endpoint
- **Exploitation**: Change order ID in URL to access other users' orders
- **Impact**: Unauthorized data access

### 4. **Mass Assignment**
- **Location**: User registration endpoint
- **Exploitation**: Add `"role": "admin"` to registration request
- **Impact**: Privilege escalation

### 5. **Weak JWT Configuration**
- **Location**: Authentication system
- **Exploitation**: JWT secret is `123456` - can be brute forced
- **Impact**: Token forgery, impersonation

### 6. **Missing Rate Limiting**
- **Location**: All endpoints
- **Exploitation**: Automated attacks, brute force
- **Impact**: Service degradation, credential compromise

### 7. **Information Disclosure**
- **Location**: Error messages
- **Exploitation**: Detailed error messages reveal system information
- **Impact**: System reconnaissance

### 8. **Weak CORS Configuration**
- **Location**: Server configuration
- **Exploitation**: Origin: `*` allows any domain
- **Impact**: Cross-origin attacks

### 9. **Missing Authorization**
- **Location**: Product creation endpoint
- **Exploitation**: Any authenticated user can create products
- **Impact**: Data manipulation

### 10. **Race Conditions**
- **Location**: Order processing
- **Exploitation**: Multiple simultaneous requests
- **Impact**: Data inconsistency

## 🚀 Multi-Cloud Deployment (NEW!)

VulnShop now supports deployment to **three major cloud providers** with **one-click GitHub Actions workflows**:

### Supported Platforms

| Cloud Provider | API Gateway | Compute Platform | Infrastructure |
|----------------|-------------|------------------|----------------|
| **Azure** | API Management (APIM) | Virtual Machine | Terraform + GitHub Actions |
| **Google Cloud** | Apigee | Compute Engine | Terraform + GitHub Actions |
| **AWS** | API Gateway | EC2 | Terraform + GitHub Actions |

### Quick Multi-Cloud Deployment

1. **Fork this repository**
2. **Configure cloud provider credentials** in GitHub Secrets
3. **Generate SSH key pair** for VM access
4. **Run GitHub Actions workflow**:
   - Go to Actions → Deploy VulnShop
   - Choose your cloud provider (Azure/GCP/AWS)
   - Select "deploy" action
   - Paste your SSH public key
   - Click "Run workflow"

### Features

- ✅ **One-Click Deployment**: Deploy to any cloud with GitHub Actions
- ✅ **Infrastructure as Code**: Terraform-managed infrastructure  
- ✅ **API Gateway Integration**: Native API gateway for each provider
- ✅ **Local Database**: SQLite on host machine (no external DB required)
- ✅ **Auto-Scaling Ready**: VM-based deployment with load balancer support
- ✅ **Destroy Capability**: Complete infrastructure teardown
- ✅ **Multi-Environment**: Deploy dev, staging, prod environments

📖 **[Complete Multi-Cloud Deployment Guide](./DEPLOYMENT.md)** - Detailed setup instructions for all cloud providers

---

## Manual Azure APIM Deployment

The following section covers the original Azure-only deployment process:

## Prerequisites

### Local Development
- Node.js 18+ installed
- Azure CLI installed
- Azure subscription

### Azure Resources Needed
- Azure API Management instance
- Azure App Service or Azure Container Instances
- Azure Key Vault (recommended)
- Azure Application Insights (optional)

## Step-by-Step Deployment with Azure APIM

### Phase 1: Local Setup and Testing

1. **Clone and install dependencies**:
```bash
git clone <repository-url>
cd vulnerable-ecommerce-apim
npm install
```

2. **Run locally for testing**:
```bash
npm start
```

3. **Test vulnerabilities locally**:
   - Visit `http://localhost:3000`
   - Try the SQL injection in search: `' OR '1'='1`
   - Test IDOR: access `/api/orders/1`, `/api/orders/2`, etc.
   - Register with `"role": "admin"` in the request body

### Phase 2: Azure Resource Creation

1. **Login to Azure**:
```bash
az login
```

2. **Create Resource Group**:
```bash
az group create --name rg-vulnshop --location eastus
```

3. **Create Azure API Management**:
```bash
az apim create \
  --name vulnshop-apim \
  --resource-group rg-vulnshop \
  --location eastus \
  --publisher-name "VulnShop" \
  --publisher-email "admin@vulnshop.com" \
  --sku-name Developer
```

4. **Create App Service Plan**:
```bash
az appservice plan create \
  --name vulnshop-plan \
  --resource-group rg-vulnshop \
  --location eastus \
  --is-linux \
  --sku B1
```

5. **Create Web App**:
```bash
az webapp create \
  --name vulnshop-backend \
  --resource-group rg-vulnshop \
  --plan vulnshop-plan \
  --runtime "NODE|18-lts"
```

### Phase 3: Application Deployment

1. **Prepare for deployment**:
```bash
# Create deployment package
zip -r vulnshop.zip . -x "*.git*" "node_modules/*" "*.md"
```

2. **Deploy to Azure App Service**:
```bash
az webapp deploy \
  --resource-group rg-vulnshop \
  --name vulnshop-backend \
  --src-path vulnshop.zip \
  --type zip
```

3. **Configure environment variables**:
```bash
az webapp config appsettings set \
  --resource-group rg-vulnshop \
  --name vulnshop-backend \
  --settings PORT=8080
```

### Phase 4: Azure APIM Configuration

1. **Create API in APIM**:
```bash
az apim api create \
  --resource-group rg-vulnshop \
  --service-name vulnshop-apim \
  --api-id vulnshop-api \
  --path "/api" \
  --display-name "VulnShop API" \
  --service-url "https://vulnshop-backend.azurewebsites.net"
```

2. **Import API operations** (create this file first):
```bash
az apim api import \
  --resource-group rg-vulnshop \
  --service-name vulnshop-apim \
  --api-id vulnshop-api \
  --path "/api" \
  --specification-path apim-swagger.json \
  --specification-format OpenApi
```

### Phase 5: Security Policies Configuration

Create these policy files to protect against vulnerabilities:

1. **Rate Limiting Policy** (`rate-limit-policy.xml`):
```xml
<policies>
    <inbound>
        <rate-limit calls="10" renewal-period="60" />
        <rate-limit-by-key calls="5" renewal-period="60" counter-key="@(context.Request.IpAddress)" />
    </inbound>
</policies>
```

2. **Authentication Policy** (`auth-policy.xml`):
```xml
<policies>
    <inbound>
        <validate-jwt header-name="Authorization" failed-validation-httpcode="401">
            <openid-config url="https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" />
            <required-claims>
                <claim name="aud">
                    <value>your-client-id</value>
                </claim>
            </required-claims>
        </validate-jwt>
    </inbound>
</policies>
```

3. **SQL Injection Protection** (`sql-injection-policy.xml`):
```xml
<policies>
    <inbound>
        <choose>
            <when condition="@(context.Request.Url.Query.GetValueOrDefault("q","").Contains("'") || context.Request.Url.Query.GetValueOrDefault("q","").Contains("--") || context.Request.Url.Query.GetValueOrDefault("q","").Contains("DROP"))">
                <return-response>
                    <set-status code="400" reason="Bad Request" />
                    <set-header name="Content-Type" exists-action="override">
                        <value>application/json</value>
                    </set-header>
                    <set-body>{"error": "Potentially malicious query detected"}</set-body>
                </return-response>
            </when>
        </choose>
    </inbound>
</policies>
```

4. **CORS Protection** (`cors-policy.xml`):
```xml
<policies>
    <inbound>
        <cors allow-credentials="false">
            <allowed-origins>
                <origin>https://your-frontend-domain.com</origin>
            </allowed-origins>
            <allowed-methods>
                <method>GET</method>
                <method>POST</method>
                <method>PUT</method>
                <method>DELETE</method>
            </allowed-methods>
            <allowed-headers>
                <header>Content-Type</header>
                <header>Authorization</header>
            </allowed-headers>
        </cors>
    </inbound>
</policies>
```

### Phase 6: Apply Security Policies

1. **Apply rate limiting**:
```bash
az apim api policy create \
  --resource-group rg-vulnshop \
  --service-name vulnshop-apim \
  --api-id vulnshop-api \
  --policy-format xml \
  --value @rate-limit-policy.xml
```

2. **Apply SQL injection protection to search endpoint**:
```bash
az apim api operation policy create \
  --resource-group rg-vulnshop \
  --service-name vulnshop-apim \
  --api-id vulnshop-api \
  --operation-id search-products \
  --policy-format xml \
  --value @sql-injection-policy.xml
```

### Phase 7: Monitoring and Analytics

1. **Enable Application Insights**:
```bash
az monitor app-insights component create \
  --resource-group rg-vulnshop \
  --location eastus \
  --app vulnshop-insights \
  --kind web
```

2. **Configure APIM to use Application Insights**:
```bash
az apim logger create \
  --resource-group rg-vulnshop \
  --service-name vulnshop-apim \
  --logger-id app-insights-logger \
  --logger-type applicationInsights \
  --description "Application Insights Logger"
```

## Testing the Protection

### Before APIM Protection:
1. **SQL Injection**: `http://localhost:3000/api/products/search?q=' OR '1'='1`
2. **IDOR**: `http://localhost:3000/api/orders/1`
3. **Rate Limiting**: Rapid requests to any endpoint
4. **CORS**: Requests from any origin work

### After APIM Protection:
1. **SQL Injection**: Blocked by policy
2. **IDOR**: Still works (needs application-level fix)
3. **Rate Limiting**: 10 requests per minute limit
4. **CORS**: Only allowed origins work

## Security Testing Commands

### SQL Injection Testing:
```bash
# Test malicious query
curl "https://vulnshop-apim.azure-api.net/api/products/search?q=' OR '1'='1"

# Test with APIM protection
curl "https://vulnshop-apim.azure-api.net/api/products/search?q=' OR '1'='1" \
  -H "Ocp-Apim-Subscription-Key: your-subscription-key"
```

### Rate Limiting Testing:
```bash
# Rapid fire requests
for i in {1..20}; do
  curl "https://vulnshop-apim.azure-api.net/api/products" \
    -H "Ocp-Apim-Subscription-Key: your-subscription-key"
done
```

### IDOR Testing:
```bash
# Access different order IDs
curl "https://vulnshop-apim.azure-api.net/api/orders/1"
curl "https://vulnshop-apim.azure-api.net/api/orders/2"
curl "https://vulnshop-apim.azure-api.net/api/orders/3"
```

## Key Learning Points

1. **APIM Protection Layers**:
   - Input validation and sanitization
   - Rate limiting and throttling
   - Authentication and authorization
   - CORS policy enforcement
   - Request/response transformation

2. **Limitations**:
   - APIM cannot fix application logic vulnerabilities (like IDOR)
   - Some vulnerabilities need application-level fixes
   - Defense in depth is crucial

3. **Best Practices**:
   - Always validate input at application level
   - Implement proper authentication/authorization
   - Use HTTPS everywhere
   - Monitor and log all API activities
   - Regular security testing

## Cleanup

To avoid Azure charges, clean up resources:
```bash
az group delete --name rg-vulnshop --yes --no-wait
```

## Default Credentials

- **Admin**: username: `admin`, password: `password`
- **Customer**: username: `john_doe`, password: `password`

## API Endpoints

- `GET /api/products` - List products
- `GET /api/products/search` - Search products (vulnerable to SQL injection)
- `POST /api/users/register` - Register user (vulnerable to mass assignment)
- `POST /api/users/login` - Login
- `GET /api/orders/:id` - Get order (vulnerable to IDOR)
- `POST /api/orders` - Create order
- `GET /api/admin/users` - Admin only endpoint
- `POST /api/products` - Create product (missing authorization)

## Contributing

This is for educational purposes only. When testing:
1. Always use isolated environments
2. Never test on production systems
3. Follow responsible disclosure practices
4. Respect terms of service and legal boundaries 