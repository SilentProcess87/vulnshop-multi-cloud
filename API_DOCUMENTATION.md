# VulnShop API Documentation

## Overview

VulnShop is an intentionally vulnerable e-commerce API designed for security testing and demonstration purposes. The API exposes multiple endpoints with various security vulnerabilities while also demonstrating OWASP Top 10 protections through Azure API Management.

## API Discovery

The API is fully discoverable through the following endpoints:

- **API Discovery**: `GET /api/discovery` - Returns all available endpoints, vulnerabilities, and security features
- **OpenAPI/Swagger**: `GET /api/swagger` - Returns complete OpenAPI documentation
- **Health Check**: `GET /api/health` - Simple health check endpoint

## Exposed API Endpoints

### Public Endpoints (No Authentication Required)

These endpoints are publicly accessible and expose sensitive data:

#### 1. **User Data Exposure**
- **Endpoint**: `GET /api/public/users`
- **Description**: Lists all users with sensitive data including emails and roles
- **Sensitive Data**: User IDs, usernames, emails, roles, creation dates
- **Vulnerability**: Information disclosure

#### 2. **System Information**
- **Endpoint**: `GET /api/public/system-info`
- **Description**: Exposes system information including environment variables
- **Sensitive Data**: Environment variables (including secrets), memory usage, platform info
- **Vulnerability**: Information disclosure, potential credential exposure

#### 3. **Database Schema**
- **Endpoint**: `GET /api/public/db-schema`
- **Description**: Returns complete database schema
- **Sensitive Data**: Table structures, column names, relationships
- **Vulnerability**: Information disclosure

#### 4. **User Search (SQL Injection)**
- **Endpoint**: `GET /api/public/user-search?username=xxx&email=xxx`
- **Description**: Search users without authentication
- **Sensitive Data**: User information
- **Vulnerability**: SQL injection, information disclosure

#### 5. **Recent Orders**
- **Endpoint**: `GET /api/public/recent-orders`
- **Description**: Shows recent orders with user information
- **Sensitive Data**: Order details, user emails, purchase history
- **Vulnerability**: Information disclosure

#### 6. **Configuration Exposure**
- **Endpoint**: `GET /api/public/config`
- **Description**: Exposes application configuration
- **Sensitive Data**: JWT secret, database path, feature flags
- **Vulnerability**: Critical information disclosure

#### 7. **Debug Information**
- **Endpoint**: `GET /api/public/debug`
- **Description**: Debug information including routes and middleware
- **Sensitive Data**: Application structure, middleware stack
- **Vulnerability**: Information disclosure

#### 8. **File Reader (Path Traversal)**
- **Endpoint**: `GET /api/public/files?path=xxx`
- **Description**: Read files from server
- **Sensitive Data**: Any file on the system
- **Vulnerability**: Path traversal, arbitrary file read

### Authenticated Endpoints with Vulnerabilities

#### 1. **Product Search (SQL Injection)**
- **Endpoint**: `GET /api/products/search?q=xxx`
- **Description**: Product search with SQL injection vulnerability
- **Authentication**: Not required
- **Vulnerability**: SQL injection

#### 2. **Order Access (IDOR)**
- **Endpoint**: `GET /api/orders/:id`
- **Description**: Get order by ID without ownership check
- **Authentication**: Required (JWT)
- **Vulnerability**: Insecure Direct Object Reference (IDOR)

#### 3. **User Data Export (Broken Access Control)**
- **Endpoint**: `GET /api/users/:id/export`
- **Description**: Export any user's data
- **Authentication**: Required (JWT)
- **Vulnerability**: Broken access control

#### 4. **User Registration (Mass Assignment)**
- **Endpoint**: `POST /api/register`
- **Description**: User registration allowing role assignment
- **Authentication**: Not required
- **Vulnerability**: Mass assignment (can set admin role)

#### 5. **Product Reviews (XSS)**
- **Endpoint**: `POST /api/products/:id/reviews`
- **Description**: Create product review without input sanitization
- **Authentication**: Required (JWT)
- **Vulnerability**: Cross-Site Scripting (XSS)

### Administrative Endpoints

- `GET /api/admin/users` - List all users (weak admin check)
- `GET /api/admin/orders` - List all orders
- `GET /api/admin/sessions` - View active sessions
- `GET /api/analytics/revenue` - Revenue analytics

## OWASP Top 10 Protection

The API includes comprehensive OWASP Top 10 (2021) protection through Azure API Management policies:

### A01:2021 – Broken Access Control
- JWT validation for protected endpoints
- Role-based access control (though weakly implemented for demonstration)

### A02:2021 – Cryptographic Failures
- HTTPS enforcement
- Secure headers (HSTS)

### A03:2021 – Injection
- SQL injection detection patterns
- Input validation for query parameters and body

### A04:2021 – Insecure Design
- Rate limiting (100 requests per minute per IP)
- Request size limits

### A05:2021 – Security Misconfiguration
- Removal of sensitive headers (X-Powered-By, Server)
- Security headers (X-Frame-Options, X-Content-Type-Options)

### A06:2021 – Vulnerable and Outdated Components
- API version tracking
- Component monitoring

### A07:2021 – Identification and Authentication Failures
- Account lockout after 5 failed attempts
- JWT-based authentication

### A08:2021 – Software and Data Integrity Failures
- Content integrity validation
- Secure communication channels

### A09:2021 – Security Logging and Monitoring Failures
- Comprehensive security event logging
- Request/response tracking
- Error logging

### A10:2021 – Server-Side Request Forgery (SSRF)
- URL validation in requests
- Blocking of internal IP ranges
- Protocol restrictions

## Security Features

1. **Rate Limiting**: Configurable through APIM policies
2. **CORS Configuration**: Restrictive CORS policy (can be configured)
3. **JWT Authentication**: Required for protected endpoints
4. **Security Headers**: XSS Protection, Content-Type Options, Frame Options, CSP
5. **Input Validation**: SQL injection and XSS pattern detection
6. **Error Handling**: Sanitized error responses

## Testing the API

### Discovering Endpoints
```bash
curl http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com/api/discovery
```

### Accessing Public Data
```bash
# Get all users without authentication
curl http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com/api/public/users

# Get system information
curl http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com/api/public/system-info

# Get configuration (including JWT secret)
curl http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com/api/public/config
```

### SQL Injection Examples
```bash
# User search with SQL injection
curl "http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com/api/public/user-search?username=admin' OR '1'='1"

# Product search with SQL injection
curl "http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com/api/products/search?q=' OR 1=1--"
```

### Path Traversal
```bash
# Read sensitive files
curl "http://vulnshop-dev-t7up5q.eastus.cloudapp.azure.com/api/public/files?path=../../../etc/passwd"
```

## Security Recommendations

While this API is intentionally vulnerable for testing purposes, in a production environment you should:

1. **Never expose sensitive endpoints without authentication**
2. **Implement proper input validation and sanitization**
3. **Use parameterized queries to prevent SQL injection**
4. **Implement proper access controls and ownership checks**
5. **Never expose system information or configuration**
6. **Sanitize user input to prevent XSS**
7. **Implement proper path validation to prevent traversal attacks**
8. **Use strong secrets and never expose them**
9. **Implement comprehensive logging and monitoring**
10. **Keep all components up to date**

## Azure APIM Policy Application

To apply OWASP Top 10 protections, use the provided policy file:
- `policies/owasp-top10-protection.xml`

This policy provides comprehensive protection against common vulnerabilities while allowing the intentionally vulnerable endpoints to remain accessible for testing purposes. 