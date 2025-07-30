# Admin Settings Vulnerability Testing Guide

## Overview

The new Admin Settings page (`/admin/settings`) provides a comprehensive interface for testing all OWASP Top 10 (2021) vulnerabilities in a controlled environment.

## Prerequisites

1. **Admin Access**: You need admin privileges to access the settings page
2. **Default Admin Credentials**: 
   - Username: `admin`
   - Password: `admin123`
3. **Alternative**: Register with role escalation: `{"username":"test","email":"test@test.com","password":"test123","role":"admin"}`

## Testing Each Vulnerability

### A01 - Broken Access Control

**What to Test**: Admin command execution without proper authorization checks

**How to Test**:
1. Navigate to Admin Settings
2. Use "Restart Server" or "Delete All Logs" buttons
3. Notice commands execute without verifying admin role deeply

**Expected Result**: Commands execute and return system information

**Real-world Impact**: Unauthorized admin actions, privilege escalation

---

### A02 - Cryptographic Failures

**What to Test**: Weak password hashing algorithms

**How to Test**:
1. Enter a password in the "Cryptographic Failures" section
2. Generate MD5 hash
3. Observe the weak hash is generated and original password is exposed

**Expected Result**: MD5 hash returned with warning about weak cryptography

**Real-world Impact**: Password cracking, data exposure

---

### A03 - Injection (SQL Injection)

**What to Test**: SQL injection in user search functionality

**How to Test**:
1. In the "Injection" section, try these payloads:
   - `' OR '1'='1`
   - `'; DROP TABLE users; --`
   - `' UNION SELECT password FROM users --`

**Expected Result**: SQL injection succeeds, returns all users or error with SQL details

**Real-world Impact**: Data breach, database manipulation

---

### A04 - Insecure Design

**What to Test**: Direct SQL execution interface

**How to Test**:
1. In "Insecure Design" section, enter SQL commands:
   - `SELECT * FROM users`
   - `UPDATE users SET role='admin' WHERE id=1`
   - `SELECT COUNT(*) FROM products`

**Expected Result**: Raw SQL executes and returns results

**Real-world Impact**: Complete database control, data manipulation

---

### A05 - Security Misconfiguration

**What to Test**: Path traversal vulnerability in file reading

**How to Test**:
1. Try reading sensitive files:
   - `../../../../etc/passwd` (Linux)
   - `..\\..\\..\\windows\\system32\\drivers\\etc\\hosts` (Windows)
   - `package.json` (application files)

**Expected Result**: File contents displayed in textarea

**Real-world Impact**: Sensitive file disclosure, configuration exposure

---

### A06 - Vulnerable and Outdated Components

**What to Test**: XML External Entity (XXE) processing

**How to Test**:
1. Try malicious XML payloads:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<settings><theme>&xxe;</theme></settings>
```

**Expected Result**: XML processed with external entity warning

**Real-world Impact**: File disclosure, SSRF, denial of service

---

### A07 - Identification and Authentication Failures

**What to Test**: Session hijacking and impersonation

**How to Test**:
1. Enter session IDs to hijack:
   - `sess_123`
   - `sess_456`
   - `sess_789`

**Expected Result**: Shows impersonation success with target user details

**Real-world Impact**: Account takeover, unauthorized access

---

### A08 - Software and Data Integrity Failures

**What to Test**: Unsafe deserialization of user preferences

**How to Test**:
1. The system loads serialized data from localStorage
2. Malicious payloads could include:
```json
{"theme":"dark","onLoad":"alert('RCE')","notifications":true}
```

**Expected Result**: Preferences loaded with warning about unsafe deserialization

**Real-world Impact**: Remote code execution, system compromise

---

### A09 - Security Logging and Monitoring Failures

**What to Test**: Critical actions without proper logging

**How to Test**:
1. View current security logs
2. Click "Clear Security Logs"
3. Notice the action succeeds without proper audit trail

**Expected Result**: Logs cleared with minimal logging of the action

**Real-world Impact**: Evidence tampering, undetected attacks

---

### A10 - Server-Side Request Forgery (SSRF)

**What to Test**: Unvalidated URL processing

**How to Test**:
1. Try internal URLs:
   - `http://localhost:22`
   - `http://192.168.1.1`
   - `http://metadata.google.internal`

**Expected Result**: System attempts to process internal URLs

**Real-world Impact**: Internal network scanning, service enumeration

---

### Mass Assignment Vulnerability

**What to Test**: Privilege escalation through unrestricted field assignment

**How to Test**:
1. Create user with elevated role:
   - Username: `hacker`
   - Email: `hacker@evil.com`
   - Role: `superadmin`

**Expected Result**: User created with elevated privileges

**Real-world Impact**: Privilege escalation, unauthorized admin access

## Automated Testing

Run the provided test script:

```bash
./test-admin-vulnerabilities.sh
```

This script automatically tests all vulnerabilities and provides detailed output.

## Security Notes

⚠️ **Educational Purpose Only**: These vulnerabilities are intentionally implemented for learning

🚫 **Never in Production**: These patterns should never be implemented in real applications

🔒 **Mitigation Strategies**: Each vulnerability demonstrates what NOT to do and how attacks work

## Further Learning

- Study the backend code in `backend/server.js` to understand the implementation
- Review the frontend code in `frontend/src/pages/AdminSettingsPage.jsx` 
- Examine the API documentation for detailed endpoint specifications
- Practice with security tools like Burp Suite, OWASP ZAP, or SQLMap

## Reporting Issues

This is a deliberately vulnerable application. Do not report these vulnerabilities as security issues - they are intentional for educational purposes!
