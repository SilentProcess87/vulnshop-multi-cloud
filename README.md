# VulnShop - Multi-Cloud Vulnerable E-Commerce Application

⚠️ **WARNING: This application contains intentional security vulnerabilities for educational purposes only. DO NOT deploy in production environments.** ⚠️

## 1. Summary of the Project

VulnShop is an intentionally vulnerable e-commerce web application designed for security training and penetration testing practice. It demonstrates common web application vulnerabilities in a realistic e-commerce context.

### Key Features:
- **Multi-Cloud Deployment**: One-click deployment to Azure (APIM), Google Cloud (Apigee), or AWS (API Gateway)
- **Modern Tech Stack**: React frontend, Node.js backend, SQLite database
- **12 Intentional Vulnerabilities**: Including SQL injection, XSS, IDOR, weak authentication, and more
- **Educational Focus**: Each vulnerability is carefully crafted to be discoverable and exploitable
- **API Gateway Integration**: Learn how API gateways interact with vulnerable applications

### Architecture:
- **Frontend**: React + Vite (served from `/frontend`)
- **Backend**: Express.js API server with SQLite database
- **API Gateway**: Azure APIM, Google Apigee, or AWS API Gateway
- **Infrastructure**: Terraform for automated cloud provisioning

## 2. How to Deploy Using GitHub Actions

### Prerequisites:
1. Fork this repository to your GitHub account
2. Set up cloud provider credentials (see below)
3. Generate an SSH key pair for VM access

### Step 1: Configure GitHub Secrets

Navigate to your repository's Settings → Secrets and variables → Actions, and add:

#### For Azure:
- `AZURE_CREDENTIALS` - Service Principal JSON (see [DEPLOYMENT.md](DEPLOYMENT.md#azure-credentials))

#### For Google Cloud:
- `GCP_CREDENTIALS` - Service Account JSON (see [DEPLOYMENT.md](DEPLOYMENT.md#gcp-credentials))
- `GCP_PROJECT_ID` - Your GCP project ID

#### For AWS:
- `AWS_ACCESS_KEY_ID` - AWS Access Key
- `AWS_SECRET_ACCESS_KEY` - AWS Secret Key

### Step 2: Deploy the Application

1. Go to Actions tab in your GitHub repository
2. Select "Deploy VulnShop to Cloud" workflow
3. Click "Run workflow"
4. Fill in the parameters:
   - **Cloud Provider**: Choose `azure`, `gcp`, or `aws`
   - **Action**: Select `deploy`
   - **Environment**: Choose `dev`, `staging`, or `prod`
   - **SSH Public Key**: Paste your SSH public key
5. Click "Run workflow"

### Step 3: Access Your Deployment

After successful deployment (typically 5-10 minutes), the workflow will display:

```
🚀 Deployment Summary:
📍 API Gateway URL: https://[your-api-endpoint]
🌐 Application DNS: https://[your-app-dns]
🔐 SSH Access: ssh azureuser@[your-app-dns]
```

Access the application at the Application DNS URL.

### Destroying the Deployment

To remove all resources:
1. Run the workflow again with **Action**: `destroy`
2. Use the same cloud provider and environment
3. Resources will be completely removed in ~5 minutes

## 3. How to Attack the Platform

VulnShop contains 12 intentional vulnerabilities. Here's how to find and exploit them:

### 🎯 1. SQL Injection (Search Endpoint)
- **Location**: Product search functionality
- **Attack**: Try searching for `' OR '1'='1` to see all products
- **Advanced**: Extract database schema with `' UNION SELECT sql FROM sqlite_master--`

### 🎯 2. Cross-Site Scripting (XSS)
- **Location**: Product reviews
- **Attack**: Post a review with `<script>alert('XSS')</script>`
- **Impact**: Steal session tokens, perform actions as other users

### 🎯 3. Insecure Direct Object Reference (IDOR)
- **Location**: Order viewing (`/api/orders/:id`)
- **Attack**: Try accessing other users' orders by changing the ID
- **Example**: If your order is #5, try accessing #1, #2, etc.

### 🎯 4. Weak Authentication
- **JWT Secret**: The application uses a weak secret (`123456`)
- **Attack**: Forge JWT tokens using tools like jwt.io
- **Exploit**: Create admin tokens to access restricted endpoints

### 🎯 5. Mass Assignment
- **Location**: User registration
- **Attack**: Add `"isAdmin": true` to registration payload
- **Result**: Create admin accounts without authorization

### 🎯 6. Missing Authorization
- **Location**: Product creation endpoint
- **Attack**: Any authenticated user can create products
- **Exploit**: POST to `/api/products` without admin privileges

### 🎯 7. Information Disclosure
- **Location**: Error messages
- **Attack**: Trigger errors to see stack traces and internal paths
- **Example**: Send malformed JSON to see detailed error responses

### 🎯 8. Race Conditions
- **Location**: Order processing
- **Attack**: Submit multiple orders simultaneously
- **Impact**: Potential inventory manipulation or pricing errors

### 🎯 9. Weak CORS Configuration
- **Setting**: Allows all origins (`*`)
- **Attack**: Create malicious site that makes requests to VulnShop
- **Impact**: CSRF attacks, data theft from authenticated users

### 🎯 10. No Rate Limiting
- **Location**: All API endpoints
- **Attack**: Brute force login, spam endpoints
- **Tools**: Use tools like Hydra or custom scripts

### 🎯 11. Large Payload Acceptance
- **Limit**: 50MB payloads allowed
- **Attack**: Send massive requests to cause DoS
- **Example**: Upload huge "product images"

### 🎯 12. Privilege Escalation
- **Location**: Admin role validation
- **Attack**: Exploit weak role checking in admin endpoints
- **Method**: Modify user objects or JWT claims

### Testing Tools Recommended:
- **Burp Suite** - Intercept and modify requests
- **OWASP ZAP** - Automated vulnerability scanning
- **SQLMap** - SQL injection exploitation
- **Postman** - API testing and scripting
- **Browser DevTools** - XSS and client-side testing

## 4. Further Information

### 📚 Documentation
- [ARCHITECTURE.md](ARCHITECTURE.md) - Detailed system architecture
- [DEPLOYMENT.md](DEPLOYMENT.md) - Complete deployment guide
- [QUICK_START.md](QUICK_START.md) - Local development setup
- [FIX_VULNSHOP_APIM.md](FIX_VULNSHOP_APIM.md) - **NEW**: Fix scripts for APIM integration

### 🛡️ Security Learning Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Understanding web vulnerabilities
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - Free security training
- [PentesterLab](https://pentesterlab.com/) - Hands-on security exercises

### 🔧 Development
- **Local Setup**: Run `npm install` in both root and frontend directories
- **Start Backend**: `npm start` (runs on port 3000)
- **Start Frontend**: `cd frontend && npm run dev` (runs on port 5173)
- **Database**: SQLite file stored at `database.sqlite`

### 🤝 Contributing
This is an educational project. Contributions that add new vulnerabilities or improve the learning experience are welcome:
1. Fork the repository
2. Create a feature branch
3. Add your vulnerability with documentation
4. Submit a pull request

### ⚖️ Legal Disclaimer
This application is for educational purposes only. Users are responsible for:
- Only deploying in authorized environments
- Not using learned techniques for malicious purposes
- Complying with all applicable laws and regulations
- Obtaining proper authorization before testing

### 📞 Support
- **Issues**: Report bugs or suggest features via GitHub Issues
- **Security**: This is intentionally vulnerable - don't report vulnerabilities!
- **Questions**: Use GitHub Discussions for help and questions

---

**Remember**: The goal is to learn about security vulnerabilities in a safe, controlled environment. Always practice ethical hacking and obtain proper authorization before testing any system.

🎓 Happy Learning and Safe Hacking! 🎓 