#!/bin/bash

# VulnShop Azure Deployment Debugging Script
# This script checks all components of the VulnShop application

echo "==========================================="
echo "VulnShop Azure Deployment Debugging Script"
echo "==========================================="
echo ""

# Function to print section headers
print_section() {
    echo ""
    echo "===================="
    echo "$1"
    echo "===================="
}

# Function to check command result
check_result() {
    if [ $? -eq 0 ]; then
        echo "✓ $1: SUCCESS"
    else
        echo "✗ $1: FAILED"
    fi
}

# 1. System Information
print_section "System Information"
echo "Hostname: $(hostname)"
echo "IP Address: $(hostname -I | awk '{print $1}')"
echo "OS: $(lsb_release -d | cut -f2)"
echo "Current User: $(whoami)"
echo "Current Directory: $(pwd)"

# 2. Check if application directory exists
print_section "Application Directory Check"
if [ -d "/var/www/vulnshop" ]; then
    echo "✓ Application directory exists"
    echo "Directory contents:"
    ls -la /var/www/vulnshop/
else
    echo "✗ Application directory NOT found at /var/www/vulnshop"
    echo "Checking other possible locations..."
    find / -name "vulnshop" -type d 2>/dev/null | head -10
fi

# 3. Check Git Repository
print_section "Git Repository Status"
if [ -d "/var/www/vulnshop/.git" ]; then
    cd /var/www/vulnshop
    echo "Git Remote: $(git remote -v | head -1)"
    echo "Current Branch: $(git branch --show-current)"
    echo "Last Commit: $(git log -1 --oneline)"
else
    echo "✗ Git repository not found"
fi

# 4. Check Backend Service
print_section "Backend Service Status"
echo "Checking vulnshop-backend service..."
systemctl status vulnshop-backend --no-pager
echo ""
echo "Last 20 lines of backend logs:"
journalctl -u vulnshop-backend -n 20 --no-pager

# 5. Check Backend Process
print_section "Backend Process Check"
echo "Node processes:"
ps aux | grep -E "node|npm" | grep -v grep

# 6. Check Backend Files
print_section "Backend Files Check"
if [ -d "/var/www/vulnshop/backend" ]; then
    echo "Backend directory contents:"
    ls -la /var/www/vulnshop/backend/
    echo ""
    echo "Checking for node_modules:"
    if [ -d "/var/www/vulnshop/backend/node_modules" ]; then
        echo "✓ node_modules exists ($(ls /var/www/vulnshop/backend/node_modules | wc -l) packages)"
    else
        echo "✗ node_modules NOT found"
    fi
    echo ""
    echo "Checking for database file:"
    find /var/www/vulnshop/backend -name "*.db" -o -name "*.sqlite" 2>/dev/null
else
    echo "✗ Backend directory NOT found"
fi

# 7. Check Frontend Build
print_section "Frontend Build Check"
if [ -d "/var/www/vulnshop/frontend" ]; then
    echo "Frontend directory contents:"
    ls -la /var/www/vulnshop/frontend/
    echo ""
    echo "Checking for build output:"
    if [ -d "/var/www/vulnshop/frontend/dist" ]; then
        echo "✓ dist directory exists"
        echo "Build files:"
        ls -la /var/www/vulnshop/frontend/dist/ | head -10
    else
        echo "✗ dist directory NOT found"
    fi
    echo ""
    echo "Checking for node_modules:"
    if [ -d "/var/www/vulnshop/frontend/node_modules" ]; then
        echo "✓ node_modules exists ($(ls /var/www/vulnshop/frontend/node_modules | wc -l) packages)"
    else
        echo "✗ node_modules NOT found"
    fi
else
    echo "✗ Frontend directory NOT found"
fi

# 8. Check Nginx Configuration
print_section "Nginx Configuration"
echo "Nginx status:"
systemctl status nginx --no-pager
echo ""
echo "Nginx sites enabled:"
ls -la /etc/nginx/sites-enabled/
echo ""
echo "Vulnshop Nginx config:"
if [ -f "/etc/nginx/sites-available/vulnshop" ]; then
    cat /etc/nginx/sites-available/vulnshop
else
    echo "✗ Vulnshop Nginx config NOT found"
fi

# 9. Port Check
print_section "Port Availability"
echo "Checking listening ports:"
ss -tlnp 2>/dev/null | grep -E ":80|:3001" || netstat -tlnp 2>/dev/null | grep -E ":80|:3001"

# 10. Test Backend API
print_section "Backend API Tests"
echo "Testing backend directly on port 3001:"
echo "GET http://localhost:3001/api/products"
curl -w "\nHTTP Status: %{http_code}\n" -s http://localhost:3001/api/products | head -20
echo ""
echo "Testing backend health check:"
curl -w "\nHTTP Status: %{http_code}\n" -s http://localhost:3001/api/health

# 11. Test Frontend through Nginx
print_section "Frontend Tests"
echo "Testing frontend through Nginx:"
echo "GET http://localhost/"
curl -w "\nHTTP Status: %{http_code}\n" -s http://localhost/ | head -10
echo ""
echo "Testing API through Nginx proxy:"
echo "GET http://localhost/api/products"
curl -w "\nHTTP Status: %{http_code}\n" -s http://localhost/api/products | head -20

# 12. Check Permissions
print_section "File Permissions"
echo "Backend permissions:"
ls -la /var/www/vulnshop/backend/ | grep -E "server.js|package.json|vulnshop.db"
echo ""
echo "Frontend dist permissions:"
ls -la /var/www/vulnshop/frontend/dist/ 2>/dev/null | head -5

# 13. Check Environment Variables
print_section "Environment Variables"
echo "Backend service environment:"
systemctl show vulnshop-backend | grep -E "Environment|WorkingDirectory"

# 14. Firewall Check
print_section "Firewall Status"
echo "UFW status:"
ufw status 2>/dev/null || echo "UFW not installed/enabled"
echo ""
echo "IPTables rules:"
iptables -L INPUT -n | grep -E "80|3001" 2>/dev/null || echo "Cannot read iptables (permission needed)"

# 15. Disk Space
print_section "Disk Space"
df -h | grep -E "/$|/var"

# 16. Recent System Logs
print_section "Recent Error Logs"
echo "Recent system errors:"
journalctl -p err -n 20 --no-pager

# 17. Quick Fixes Attempt
print_section "Attempting Quick Fixes"
echo "1. Restarting services..."
sudo systemctl restart vulnshop-backend
sleep 5
sudo systemctl restart nginx
sleep 2

echo ""
echo "2. Testing after restart:"
curl -s http://localhost:3001/api/products > /dev/null 2>&1
check_result "Backend API"
curl -s http://localhost/ > /dev/null 2>&1
check_result "Frontend"

# Summary
print_section "SUMMARY"
echo "Key issues found:"
echo ""

# Check for common issues
if ! systemctl is-active --quiet vulnshop-backend; then
    echo "- Backend service is NOT running"
fi

if ! systemctl is-active --quiet nginx; then
    echo "- Nginx is NOT running"
fi

if [ ! -d "/var/www/vulnshop/backend/node_modules" ]; then
    echo "- Backend dependencies not installed"
fi

if [ ! -d "/var/www/vulnshop/frontend/dist" ]; then
    echo "- Frontend not built"
fi

if [ ! -f "/var/www/vulnshop/backend/vulnshop.db" ]; then
    echo "- Database file not found"
fi

echo ""
echo "==========================================="
echo "Debug script completed!"
echo "===========================================" 