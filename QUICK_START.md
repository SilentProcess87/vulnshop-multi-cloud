# VulnShop Full-Stack Quick Start Guide

## 🚀 Prerequisites

- **Node.js** 16+ and **npm** 8+
- **MongoDB Atlas** account (free tier available)
- **Azure subscription** (for APIM deployment)
- **Git** (for cloning the repository)

## 📦 Installation

### 1. Clone and Setup
```bash
# Clone the repository
git clone <repository-url>
cd vulnshop-fullstack

# Install all dependencies (frontend + backend + root)
npm run install:all
```

### 2. MongoDB Setup
```bash
# Create MongoDB Atlas account at: https://cloud.mongodb.com
# Create a new cluster (free tier is sufficient)
# Get your connection string from "Connect" -> "Connect your application"

# Create backend environment file
echo "MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/?retryWrites=true&w=majority&appName=YourApp" > backend/.env
echo "JWT_SECRET=your-super-secret-jwt-key-here" >> backend/.env
echo "NODE_ENV=development" >> backend/.env
```

### 3. Start Development Servers
```bash
# Start both frontend (React) and backend (Node.js) simultaneously
npm run dev

# Or start them separately:
npm run dev:backend   # Backend on port 3001
npm run dev:frontend  # Frontend on port 3000
```

### 4. Access the Application
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:3001/api
- **Health Check**: http://localhost:3001/api/health

## 🎯 Quick Testing

### Default User Accounts
```bash
# Admin Account
Username: admin
Password: password

# Regular User Account  
Username: john_doe
Password: password
```

### Test Vulnerabilities

#### 1. **Mass Assignment (Registration)**
- Visit: http://localhost:3000/register
- Fill out the form and select "Administrator" role
- Register successfully as admin

#### 2. **NoSQL Injection (Search)**
- Visit: http://localhost:3000/products
- Search for: `{"$ne": null}`
- Or try: `{"$regex": ".*"}`

#### 3. **IDOR (Orders)**
- Login as any user
- Visit: http://localhost:3000/orders
- Use the IDOR test form to access other users' orders

#### 4. **XSS (Reviews)**
- Visit any product detail page
- Add a review with: `<script>alert('XSS')</script>`
- Or try: `<img src="x" onerror="alert('XSS')">`

#### 5. **Privilege Escalation**
- Register a new account with "Administrator" role
- Access admin panel: http://localhost:3000/admin

## 🏗️ Project Structure

```
vulnshop-fullstack/
├── frontend/           # React application
│   ├── src/
│   │   ├── components/ # React components
│   │   ├── pages/      # Page components
│   │   ├── services/   # API service layer
│   │   └── App.jsx     # Main app
│   └── package.json
├── backend/            # Node.js API
│   ├── server.js       # Express server
│   └── package.json
├── policies/           # APIM security policies
└── package.json        # Root package.json
```

## 🔧 Development Commands

```bash
# Install dependencies for all projects
npm run install:all

# Development (both frontend and backend)
npm run dev

# Backend only
npm run dev:backend

# Frontend only  
npm run dev:frontend

# Build for production
npm run build

# Production mode
npm run start
```

## 🌐 API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login

### Products
- `GET /api/products` - List products
- `GET /api/products/search?q=query` - Search (vulnerable)
- `POST /api/products` - Create product

### Orders
- `GET /api/orders` - User orders
- `GET /api/orders/:id` - Order by ID (IDOR vulnerable)
- `POST /api/orders` - Create order

### Reviews  
- `GET /api/reviews/:productId` - Product reviews
- `POST /api/reviews` - Add review (XSS vulnerable)

### Admin
- `GET /api/admin/users` - All users
- `GET /api/admin/orders` - All orders

## 🛡️ Security Vulnerabilities

| Vulnerability | Location | Test Method |
|---------------|----------|-------------|
| **NoSQL Injection** | Product search | Search for `{"$ne": null}` |
| **IDOR** | Order access | Access `/api/orders/<any_id>` |
| **XSS** | Product reviews | Submit `<script>alert('XSS')</script>` |
| **Mass Assignment** | User registration | Select "Administrator" role |
| **Weak CORS** | All endpoints | Cross-origin requests accepted |
| **No Rate Limiting** | All endpoints | Unlimited requests |
| **Info Disclosure** | Error responses | Detailed error messages |
| **Missing Auth** | Product creation | Any user can create products |
| **Weak JWT** | Authentication | Secret is '123456' |
| **Race Conditions** | Order processing | Concurrent order creation |
| **Large Payloads** | All endpoints | 50MB request limit |
| **Privilege Escalation** | Admin panel | Client-side role checks only |

## 🚀 Azure APIM Deployment

### 1. Prerequisites
```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login to Azure
az login
```

### 2. Deploy Backend
```bash
# Create resource group
az group create --name rg-vulnshop --location eastus

# Create App Service plan
az appservice plan create --name plan-vulnshop --resource-group rg-vulnshop --sku B1

# Create web app
az webapp create --name vulnshop-backend --resource-group rg-vulnshop --plan plan-vulnshop --runtime "NODE|18-lts"

# Deploy backend
cd backend
zip -r ../backend.zip .
az webapp deploy --name vulnshop-backend --resource-group rg-vulnshop --src-path ../backend.zip
```

### 3. Create APIM Instance
```bash
# Create APIM (takes 30-45 minutes)
az apim create --name vulnshop-apim --resource-group rg-vulnshop --publisher-email your@email.com --publisher-name "Your Name"
```

### 4. Configure API
```bash
# Import API from OpenAPI spec
az apim api import --service-name vulnshop-apim --resource-group rg-vulnshop --path /api --specification-format OpenApi --specification-path apim-swagger.json --api-id vulnshop-api
```

### 5. Apply Security Policies
```bash
# Apply rate limiting
az apim api policy create --service-name vulnshop-apim --resource-group rg-vulnshop --api-id vulnshop-api --policy-format xml --value @policies/rate-limit-policy.xml

# Apply SQL injection protection  
az apim api operation policy create --service-name vulnshop-apim --resource-group rg-vulnshop --api-id vulnshop-api --operation-id search-products --policy-format xml --value @policies/sql-injection-policy.xml
```

## 🔍 Monitoring

### Local Development
- Backend logs in terminal
- Frontend dev tools console
- MongoDB Atlas monitoring dashboard

### Production
- Azure Application Insights
- APIM analytics dashboard
- Azure Monitor logs

## 🐛 Troubleshooting

### MongoDB Connection Issues
```bash
# Check connection string format
echo $MONGODB_URI

# Test connection
node -e "
const mongoose = require('mongoose');
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.log('❌ MongoDB error:', err.message));
"
```

### Port Conflicts
```bash
# Check what's running on ports
netstat -tulpn | grep :3000
netstat -tulpn | grep :3001

# Kill processes if needed
sudo kill -9 $(lsof -t -i:3000)
sudo kill -9 $(lsof -t -i:3001)
```

### Build Issues
```bash
# Clear npm cache
npm cache clean --force

# Delete node_modules and reinstall
rm -rf node_modules frontend/node_modules backend/node_modules
npm run install:all
```

### CORS Issues
```bash
# If frontend can't connect to backend:
# 1. Check Vite proxy configuration in frontend/vite.config.js
# 2. Ensure backend CORS allows localhost:3000
# 3. Check browser console for CORS errors
```

## 📚 Next Steps

1. **Explore Vulnerabilities**: Test each security flaw
2. **Apply APIM Policies**: Deploy to Azure and configure protection
3. **Monitor Security**: Set up alerts for attack patterns
4. **Extend Application**: Add more features and vulnerabilities
5. **Learn Security**: Study how each vulnerability works and how to fix it

## 🎓 Educational Resources

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **Azure APIM Documentation**: https://docs.microsoft.com/azure/api-management/
- **MongoDB Security**: https://docs.mongodb.com/manual/security/
- **React Security**: https://reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml

## 🤝 Support

If you encounter issues:
1. Check the troubleshooting section
2. Review the logs in your terminal
3. Ensure all prerequisites are installed
4. Verify MongoDB connection string
5. Check that all ports are available

Happy learning! 🎉 