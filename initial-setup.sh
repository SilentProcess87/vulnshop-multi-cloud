#!/bin/bash

# VulnShop Initial Setup Script
# Run this script on a fresh Ubuntu VM to set up the VulnShop application

set -e  # Exit on error

echo "🚀 Starting VulnShop initial setup..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

print_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

# Update system packages
print_status "Updating system packages..."
sudo apt-get update
sudo apt-get upgrade -y

# Install Node.js 18.x
print_status "Installing Node.js 18.x..."
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PM2 globally
print_status "Installing PM2..."
sudo npm install -g pm2

# Install nginx if not already installed
print_status "Installing nginx..."
sudo apt-get install -y nginx

# Install git if not already installed
print_status "Installing git..."
sudo apt-get install -y git

# Create application directory
print_status "Creating application directory..."
sudo mkdir -p /home/azureuser/vulnshop
sudo chown -R azureuser:azureuser /home/azureuser/vulnshop

# Clone the repository
print_status "Cloning repository..."
cd /home/azureuser
if [ -d "vulnshop/.git" ]; then
    print_warning "Repository already exists, pulling latest changes..."
    cd vulnshop
    git pull origin main
else
    git clone https://github.com/your-username/vulnshop.git vulnshop
    cd vulnshop
fi

# Make scripts executable
print_status "Making scripts executable..."
chmod +x refresh-deployment.sh
chmod +x initial-setup.sh

# Configure firewall
print_status "Configuring firewall..."
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 3001/tcp  # Backend API
sudo ufw --force enable

# Run the refresh deployment script
print_status "Running deployment script..."
./refresh-deployment.sh

echo ""
echo "========================================"
echo -e "${GREEN}🎉 Initial setup complete!${NC}"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Update the git repository URL in this script"
echo "2. Configure your domain name in nginx"
echo "3. Set up SSL certificates with Let's Encrypt"
echo ""
echo "To update the deployment in the future, run:"
echo "  cd /home/azureuser/vulnshop && ./refresh-deployment.sh"
echo "" 