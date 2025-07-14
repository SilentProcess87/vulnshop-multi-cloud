# VulnShop Deployment Refresh Guide

This guide explains how to deploy and refresh the VulnShop application on your VM.

## 📁 Files Created

### 1. `.gitignore`
Excludes unnecessary files from git:
- `node_modules/` directories
- Database files (`*.db`)
- Build artifacts
- Environment files
- IDE configurations
- Terraform state files

### 2. `refresh-deployment.sh`
Main deployment refresh script that:
- Stops current services
- Pulls latest code from git
- Installs dependencies
- Builds the frontend
- Updates nginx configuration
- Restarts all services with PM2

### 3. `initial-setup.sh`
First-time setup script for new VMs that:
- Installs Node.js, PM2, nginx, and git
- Configures the firewall
- Clones the repository
- Runs the refresh script

### 4. `.github/workflows/ci.yml`
GitHub Actions workflow that:
- Runs on push to main/develop branches
- Installs dependencies
- Builds the frontend
- Runs security audits
- Notifies when deployment is needed

## 🚀 Initial Setup (First Time)

1. **Push your code to GitHub:**
   ```bash
   git add .
   git commit -m "Add deployment scripts and .gitignore"
   git push origin main
   ```

2. **SSH into your VM:**
   ```bash
   ssh azureuser@your-vm-ip
   ```

3. **Download and run the initial setup script:**
   ```bash
   # Update the repository URL in the script first!
   curl -o initial-setup.sh https://raw.githubusercontent.com/your-username/your-repo/main/initial-setup.sh
   chmod +x initial-setup.sh
   ./initial-setup.sh
   ```

## 🔄 Refreshing Deployment (Updates)

After making changes to your code:

1. **Commit and push changes:**
   ```bash
   git add .
   git commit -m "Your changes"
   git push origin main
   ```

2. **SSH into your VM:**
   ```bash
   ssh azureuser@your-vm-ip
   ```

3. **Run the refresh script:**
   ```bash
   cd /home/azureuser/vulnshop
   ./refresh-deployment.sh
   ```

## 📝 Important Notes

### Repository Configuration
Before using the scripts, update the repository URL in `initial-setup.sh`:
```bash
git clone https://github.com/your-username/your-repo.git vulnshop
```

### Database Management
The refresh script removes the database by default to start fresh. To keep existing data, comment out this line in `refresh-deployment.sh`:
```bash
# rm vulnshop.db
```

### Port Configuration
- Frontend: Port 80 (nginx)
- Backend API: Port 3001
- Make sure these ports are open in your VM's security group

### PM2 Process Management
- View logs: `pm2 logs vulnshop-backend`
- Check status: `pm2 status`
- Restart backend: `pm2 restart vulnshop-backend`
- Stop all: `pm2 stop all`

### Nginx Commands
- Test config: `sudo nginx -t`
- Reload: `sudo systemctl reload nginx`
- Restart: `sudo systemctl restart nginx`
- Status: `sudo systemctl status nginx`

## 🔧 Troubleshooting

### Backend not responding
```bash
pm2 logs vulnshop-backend
pm2 restart vulnshop-backend
```

### Frontend not loading
```bash
sudo systemctl status nginx
sudo nginx -t
sudo systemctl restart nginx
```

### Permission issues
```bash
sudo chown -R azureuser:azureuser /home/azureuser/vulnshop
```

### Port already in use
```bash
sudo lsof -ti:3001 | xargs sudo kill -9
```

## 🔒 Security Considerations

1. **Always use HTTPS in production** - Set up Let's Encrypt:
   ```bash
   sudo apt-get install certbot python3-certbot-nginx
   sudo certbot --nginx -d your-domain.com
   ```

2. **Update the JWT secret** in production by setting environment variables

3. **Restrict firewall rules** to only necessary ports

4. **Regular updates:**
   ```bash
   sudo apt-get update && sudo apt-get upgrade
   ```

## 📊 Monitoring

- Backend logs: `/home/azureuser/.pm2/logs/`
- Nginx access logs: `/var/log/nginx/access.log`
- Nginx error logs: `/var/log/nginx/error.log`

## 🆘 Quick Commands Reference

```bash
# Check everything
pm2 status
sudo systemctl status nginx

# Restart everything
pm2 restart all
sudo systemctl restart nginx

# View logs
pm2 logs
sudo tail -f /var/log/nginx/error.log

# Update and refresh
cd /home/azureuser/vulnshop
git pull
./refresh-deployment.sh
``` 