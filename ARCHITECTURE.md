# VulnShop Full-Stack Architecture

## Overview

VulnShop is a deliberately vulnerable e-commerce application built as a **full-stack solution** with separate frontend and backend components. It demonstrates common security vulnerabilities and how Azure API Management (APIM) can provide protection layers.

## Architecture Diagram

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │    │                 │
│   React SPA     │    │   Azure APIM    │    │   Node.js API   │    │   MongoDB       │
│   (Frontend)    │◄──►│   (Gateway)     │◄──►│   (Backend)     │◄──►│   (Database)    │
│   Port 3000     │    │   Security      │    │   Port 3001     │    │   Cloud Atlas   │
│                 │    │   Policies      │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
        │                        │                        │                        │
        │                        │                        │                        │
        ▼                        ▼                        ▼                        ▼
   User Interface         API Management           Business Logic            Data Storage
   - Product Catalog      - Rate Limiting          - Authentication           - Users
   - Shopping Cart        - CORS Policies          - Product Management       - Products  
   - User Auth            - Input Validation       - Order Processing         - Orders
   - Admin Panel          - Security Headers       - Review System            - Reviews
                         - SQL Injection          - Admin Functions
                           Protection
```

## Technology Stack

### Frontend (React SPA)
- **Framework**: React 18 with Vite
- **Routing**: React Router DOM
- **Styling**: Pure CSS with modern design
- **Icons**: Lucide React
- **HTTP Client**: Axios
- **Port**: 3000 (development)

### Backend (Node.js API)
- **Runtime**: Node.js with Express.js
- **Database**: MongoDB (Cloud Atlas)
- **ODM**: Mongoose
- **Authentication**: JWT with bcryptjs
- **Module System**: ES Modules (ESM)
- **Port**: 3001

### Database (MongoDB)
- **Type**: NoSQL Document Database
- **Hosting**: MongoDB Atlas (Cloud)
- **Connection**: MongoDB connection string
- **Collections**: Users, Products, Orders, Reviews

### Infrastructure
- **API Gateway**: Azure API Management
- **Deployment**: Azure App Service (planned)
- **Monitoring**: Azure Application Insights

## Request Flow

### Development Flow (Direct)
```
User Browser → React Dev Server (3000) → Vite Proxy → Node.js API (3001) → MongoDB Atlas
```

### Production Flow (with APIM)
```
User Browser → React SPA (Static) → Azure APIM → Node.js API → MongoDB Atlas
```

## Directory Structure

```
vulnshop-fullstack/
├── frontend/                 # React frontend application
│   ├── src/
│   │   ├── components/       # Reusable React components
│   │   │   └── Header.jsx    # Navigation header
│   │   ├── pages/           # Page components
│   │   │   ├── HomePage.jsx
│   │   │   ├── LoginPage.jsx
│   │   │   ├── RegisterPage.jsx
│   │   │   ├── ProductsPage.jsx
│   │   │   ├── ProductDetailPage.jsx
│   │   │   ├── CartPage.jsx
│   │   │   ├── OrdersPage.jsx
│   │   │   └── AdminPage.jsx
│   │   ├── services/        # API service layer
│   │   │   └── api.js       # Axios configuration & endpoints
│   │   ├── App.jsx          # Main app component with routing
│   │   ├── App.css          # Global styles
│   │   └── main.jsx         # React app entry point
│   ├── public/              # Static assets
│   ├── package.json         # Frontend dependencies
│   ├── vite.config.js       # Vite configuration
│   └── index.html           # HTML template
├── backend/                 # Node.js backend API
│   ├── server.js           # Express server with all routes
│   └── package.json        # Backend dependencies
├── policies/               # Azure APIM policy files
│   ├── rate-limit-policy.xml
│   ├── sql-injection-policy.xml
│   ├── cors-policy.xml
│   ├── auth-policy.xml
│   └── comprehensive-security-policy.xml
├── package.json            # Root package.json (monorepo)
├── deploy.sh              # Azure deployment script
├── apim-swagger.json      # OpenAPI specification
├── README.md              # Main documentation
├── ARCHITECTURE.md        # This file
└── QUICK_START.md         # Quick start guide
```

## Data Models (MongoDB Collections)

### Users Collection
```javascript
{
  _id: ObjectId,
  username: String (unique),
  email: String (unique),
  password: String (hashed),
  role: String (enum: ['user', 'admin']),
  createdAt: Date
}
```

### Products Collection
```javascript
{
  _id: ObjectId,
  name: String,
  description: String,
  price: Number,
  image: String,
  category: String,
  createdBy: ObjectId (ref: User),
  createdAt: Date
}
```

### Orders Collection
```javascript
{
  _id: ObjectId,
  userId: ObjectId (ref: User),
  items: [{
    productId: ObjectId (ref: Product),
    quantity: Number,
    price: Number
  }],
  total: Number,
  status: String (enum: ['pending', 'processing', 'shipped', 'delivered']),
  createdAt: Date
}
```

### Reviews Collection
```javascript
{
  _id: ObjectId,
  productId: ObjectId (ref: Product),
  userId: ObjectId (ref: User),
  rating: Number (1-5),
  comment: String,
  createdAt: Date
}
```

## Security Vulnerabilities

### 1. **NoSQL Injection** (Search Functionality)
- **Location**: `/api/products/search`
- **Vulnerability**: Direct MongoDB query construction from user input
- **Payload Examples**: `{"$ne": null}`, `{"$regex": ".*"}`, `{"$where": "this.price > 0"}`
- **APIM Protection**: Input validation policies

### 2. **Insecure Direct Object Reference (IDOR)**
- **Location**: `/api/orders/:id`
- **Vulnerability**: No authorization check for order access
- **Test**: Access any order ID without ownership validation
- **APIM Protection**: Authorization policies

### 3. **Cross-Site Scripting (XSS)**
- **Location**: Product review system
- **Vulnerability**: `dangerouslySetInnerHTML` without sanitization
- **Payload Examples**: `<script>alert('XSS')</script>`, `<img src="x" onerror="alert('XSS')">`
- **Protection**: Content Security Policy (CSP) headers

### 4. **Mass Assignment**
- **Location**: User registration
- **Vulnerability**: Client can specify role during registration
- **Test**: Select "Administrator" role in registration form
- **APIM Protection**: Request transformation policies

### 5. **Weak CORS Configuration**
- **Location**: Backend Express configuration
- **Vulnerability**: `origin: '*'` allows all domains
- **APIM Protection**: Strict CORS policies

### 6. **No Rate Limiting**
- **Location**: All API endpoints
- **Vulnerability**: No request throttling
- **APIM Protection**: Rate limiting policies (10 requests/minute)

### 7. **Information Disclosure**
- **Location**: Error handling middleware
- **Vulnerability**: Detailed error messages in responses
- **Protection**: Generic error responses in production

### 8. **Missing Authorization**
- **Location**: Product creation endpoint
- **Vulnerability**: Any authenticated user can create products
- **APIM Protection**: Role-based access policies

### 9. **Weak JWT Secret**
- **Location**: JWT configuration
- **Vulnerability**: Hardcoded secret '123456'
- **Protection**: Strong random secrets with rotation

### 10. **Race Conditions**
- **Location**: Order processing
- **Vulnerability**: No proper transaction handling
- **Protection**: Database transactions and atomic operations

### 11. **Large Payload Acceptance**
- **Location**: Express body parser
- **Vulnerability**: 50MB request limit
- **APIM Protection**: Request size limits

### 12. **Privilege Escalation**
- **Location**: Admin panel access
- **Vulnerability**: Client-side role validation only
- **Protection**: Server-side authorization checks

## APIM Security Policies

### Rate Limiting Policy
```xml
<rate-limit-by-key calls="10" renewal-period="60" counter-key="@(context.Request.IpAddress)" />
```

### NoSQL Injection Protection
```xml
<choose>
  <when condition="@(context.Request.Body.As<string>().Contains("$where") || 
                    context.Request.Body.As<string>().Contains("$ne") ||
                    context.Request.Url.Query.GetValueOrDefault("q","").Contains("$"))">
    <return-response>
      <set-status code="400" reason="Bad Request" />
      <set-body>Potential NoSQL injection detected</set-body>
    </return-response>
  </when>
</choose>
```

### CORS Policy
```xml
<cors allow-credentials="false">
  <allowed-origins>
    <origin>https://yourdomain.com</origin>
  </allowed-origins>
  <allowed-methods>
    <method>GET</method>
    <method>POST</method>
  </allowed-methods>
</cors>
```

## Development Setup

### Prerequisites
- Node.js 16+
- npm 8+
- MongoDB Atlas account (or local MongoDB)

### Installation
```bash
# Clone repository
git clone <repository-url>
cd vulnshop-fullstack

# Install all dependencies
npm run install:all

# Set environment variables
echo "MONGODB_URI=your_mongodb_connection_string" > backend/.env
echo "JWT_SECRET=your_jwt_secret" >> backend/.env

# Start development servers
npm run dev
```

### Ports
- **Frontend**: http://localhost:3000
- **Backend**: http://localhost:3001
- **API Endpoints**: http://localhost:3001/api/*

## Production Deployment

### Build Process
```bash
# Build frontend
npm run build

# Install production dependencies
npm run build:backend
```

### Azure Deployment
```bash
# Deploy to Azure
./deploy.sh
```

### Environment Variables
- `MONGODB_URI`: MongoDB connection string
- `JWT_SECRET`: Strong random secret for JWT signing
- `NODE_ENV`: Set to 'production'
- `PORT`: Application port (default: 3001)

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login

### Products
- `GET /api/products` - List all products
- `GET /api/products/search?q=query` - Search products (vulnerable)
- `POST /api/products` - Create product (authenticated)

### Orders
- `GET /api/orders` - Get user orders (authenticated)
- `GET /api/orders/:id` - Get order by ID (vulnerable IDOR)
- `POST /api/orders` - Create order (authenticated)

### Reviews
- `GET /api/reviews/:productId` - Get product reviews
- `POST /api/reviews` - Add review (authenticated, XSS vulnerable)

### Admin
- `GET /api/admin/users` - List all users (admin only)
- `GET /api/admin/orders` - List all orders (admin only)

### Health
- `GET /api/health` - Service health check

## Security Testing

### Default Credentials
- **Admin**: username=`admin`, password=`password`
- **User**: username=`john_doe`, password=`password`

### Test Scenarios
1. **NoSQL Injection**: Search with `{"$ne": null}`
2. **IDOR**: Access `/api/orders/<other_user_order_id>`
3. **XSS**: Submit review with `<script>alert('XSS')</script>`
4. **Mass Assignment**: Register with admin role selected
5. **Privilege Escalation**: Access `/admin` after role manipulation

## Monitoring and Logging

### Application Insights Integration
- Request/response logging
- Performance metrics
- Error tracking
- Custom events for security violations

### Security Metrics
- Failed authentication attempts
- IDOR access attempts
- Injection attack patterns
- Rate limit violations

## Best Practices for Protection

### Application Level
1. Input validation and sanitization
2. Parameterized queries
3. Proper authorization checks
4. Strong secrets management
5. Error handling without information disclosure

### APIM Level
1. Rate limiting policies
2. Input validation policies
3. Authentication/authorization policies
4. CORS restrictions
5. Request/response transformation
6. IP filtering
7. SSL/TLS enforcement

### Infrastructure Level
1. Network security groups
2. Key Vault for secrets
3. Application Insights monitoring
4. Automated security scanning
5. Regular security updates

## Educational Value

This architecture demonstrates:
- **Separation of Concerns**: Clear frontend/backend separation
- **Modern Development Practices**: React, Node.js, MongoDB stack
- **Security Vulnerability Patterns**: Real-world security issues
- **API Gateway Benefits**: How APIM provides security layers
- **Full-Stack Security**: End-to-end security considerations

The application serves as a comprehensive learning platform for understanding both web application vulnerabilities and how API management solutions can provide effective protection mechanisms. 