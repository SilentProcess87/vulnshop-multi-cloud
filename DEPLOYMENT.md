# VulnShop Multi-Cloud Deployment Guide

This guide explains how to deploy the VulnShop vulnerable e-commerce application to Azure (with APIM), Google Cloud Platform (with Apigee), or AWS (with API Gateway) using GitHub Actions and Terraform.

## 🌟 Features

- **Multi-Cloud Support**: Deploy to Azure, GCP, or AWS
- **API Gateway Integration**: 
  - Azure API Management (APIM)
  - Google Cloud Apigee
  - AWS API Gateway
- **Infrastructure as Code**: Terraform-based deployments
- **Automated CI/CD**: GitHub Actions workflows
- **Local Database**: SQLite database on host machine (no external DB required)
- **One-Click Deployment**: Manual workflow triggers with environment selection
- **Destroy Capability**: Complete infrastructure teardown

## 🏗️ Architecture Overview

### Azure Deployment
- **Compute**: Azure Virtual Machine (Ubuntu 22.04)
- **API Gateway**: Azure API Management (APIM)
- **Network**: Virtual Network with NSG
- **Storage**: Storage Account for diagnostics
- **Frontend**: Nginx serving React app
- **Backend**: Node.js Express API
- **Database**: SQLite (local file)

### GCP Deployment
- **Compute**: Compute Engine VM (Ubuntu 22.04)
- **API Gateway**: Google Cloud Apigee
- **Network**: VPC with Cloud NAT
- **Storage**: Cloud Storage bucket
- **Frontend**: Nginx serving React app
- **Backend**: Node.js Express API
- **Database**: SQLite (local file)

### AWS Deployment
- **Compute**: EC2 Instance (Amazon Linux 2)
- **API Gateway**: AWS API Gateway
- **Network**: VPC with Internet Gateway
- **Storage**: S3 bucket
- **Frontend**: Nginx serving React app
- **Backend**: Node.js Express API
- **Database**: SQLite (local file)

## 🚀 Quick Start

### Prerequisites

1. **GitHub Repository**: Fork or clone this repository
2. **SSH Key Pair**: Generate SSH keys for VM access
3. **Cloud Provider Account**: Active account with appropriate permissions
4. **GitHub Secrets**: Configure cloud provider credentials

### Step 1: Generate SSH Key Pair

```bash
# Generate SSH key pair
ssh-keygen -t ed25519 -C "vulnshop-deployment" -f ~/.ssh/vulnshop

# Get the public key (you'll need this for deployment)
cat ~/.ssh/vulnshop.pub
```

### Step 2: Configure GitHub Secrets and Variables

Navigate to your repository → Settings → Secrets and variables → Actions

#### For Azure Deployment

**Required Secrets:**
```
AZURE_CREDENTIALS         # Service Principal JSON
AZURE_CLIENT_ID           # Service Principal Client ID
AZURE_CLIENT_SECRET       # Service Principal Client Secret
AZURE_SUBSCRIPTION_ID     # Azure Subscription ID
AZURE_TENANT_ID           # Azure Tenant ID
```

**Optional Variables:**
```
AZURE_APIM_PUBLISHER_EMAIL  # Email for APIM publisher (default: admin@example.com)
```

#### For GCP Deployment

**Required Secrets:**
```
GCP_SA_KEY       # Service Account JSON key
GCP_PROJECT_ID   # GCP Project ID
```

#### For AWS Deployment

**Required Secrets:**
```
AWS_ACCESS_KEY_ID     # AWS Access Key ID
AWS_SECRET_ACCESS_KEY # AWS Secret Access Key
```

**Optional Variables:**
```
AWS_REGION  # AWS Region (default: us-east-1)
```

### Step 3: Deploy

1. Go to your repository on GitHub
2. Navigate to **Actions** tab
3. Select **Deploy VulnShop** workflow
4. Click **Run workflow**
5. Fill in the required parameters:
   - **Cloud Provider**: Choose from azure, gcp, or aws
   - **Action**: Choose "deploy" or "destroy"
   - **Environment**: Environment name (e.g., "dev", "staging", "prod")
   - **SSH Public Key**: Paste your SSH public key content

## 🔧 Manual Deployment (Local)

If you prefer to run Terraform locally:

### Azure

```bash
cd terraform/azure

# Initialize Terraform
terraform init

# Set required variables
export TF_VAR_ssh_public_key="$(cat ~/.ssh/vulnshop.pub)"
export TF_VAR_git_repo="https://github.com/yourusername/your-repo"
export TF_VAR_apim_publisher_email="your-email@example.com"

# Plan and apply
terraform plan
terraform apply
```

### GCP

```bash
cd terraform/gcp

# Initialize Terraform
terraform init

# Set required variables
export TF_VAR_ssh_public_key="$(cat ~/.ssh/vulnshop.pub)"
export TF_VAR_git_repo="https://github.com/yourusername/your-repo"
export TF_VAR_project_id="your-gcp-project-id"

# Plan and apply
terraform plan
terraform apply
```

### AWS

```bash
cd terraform/aws

# Initialize Terraform
terraform init

# Set required variables
export TF_VAR_ssh_public_key="$(cat ~/.ssh/vulnshop.pub)"
export TF_VAR_git_repo="https://github.com/yourusername/your-repo"

# Plan and apply
terraform plan
terraform apply
```

## 🔐 Setting Up Cloud Provider Credentials

This section provides a step-by-step guide on how to create the necessary credentials for each cloud provider and configure them as GitHub Secrets.

### ⭐ Azure: Creating a Service Principal

A Service Principal is an identity created for use with applications, hosted services, and automated tools to access Azure resources.

**Step 1: Log in to Azure CLI**
Open your terminal and run:
```bash
az login
```
Follow the on-screen instructions to complete the login process.

**Step 2: Set Your Subscription**
If you have multiple subscriptions, make sure to set the one you want to use:
```bash
az account set --subscription "Your Subscription Name or ID"
```

**Step 3: Create the Service Principal**
Run the following command to create a service principal with "Contributor" role, which allows it to manage resources in your subscription.
```bash
az ad sp create-for-rbac --name "vulnshop-github-actions-sp" --role="Contributor" --scopes="/subscriptions/$(az account show --query id -o tsv)" --sdk-auth
```
- `--name`: A descriptive name for your service principal.
- `--role`: The role assigned. "Contributor" is sufficient for creating and managing resources.
- `--scopes`: The scope at which the role is assigned. We are scoping it to the entire subscription.
- `--sdk-auth`: This flag formats the output as a single JSON object, which is perfect for the `AZURE_CREDENTIALS` secret.

**Step 4: Configure GitHub Secrets**
The output from the previous command will be a JSON object that looks like this:
```json
{
  "clientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "clientSecret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "subscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "activeDirectoryEndpointUrl": "https://login.microsoftonline.com",
  "resourceManagerEndpointUrl": "https://management.azure.com/",
  "activeDirectoryGraphResourceId": "https://graph.windows.net/",
  "sqlManagementEndpointUrl": "https://management.core.windows.net:8443/",
  "galleryEndpointUrl": "https://gallery.azure.com/",
  "managementEndpointUrl": "https://management.core.windows.net/"
}
```

Now, navigate to your GitHub repository → **Settings** → **Secrets and variables** → **Actions** and create the following secrets:

1.  **`AZURE_CREDENTIALS`**:
    - Copy the **entire JSON output** from the `az ad sp create-for-rbac` command and paste it as the value for this secret.

2.  **`AZURE_CLIENT_ID`**:
    - Copy the `clientId` value from the JSON output.

3.  **`AZURE_CLIENT_SECRET`**:
    - Copy the `clientSecret` value from the JSON output.

4.  **`AZURE_SUBSCRIPTION_ID`**:
    - Copy the `subscriptionId` value from the JSON output.

5.  **`AZURE_TENANT_ID`**:
    - Copy the `tenantId` value from the JSON output.

### ⭐ Google Cloud Platform: Creating a Service Account

A Service Account is a special type of Google account intended to represent a non-human user that needs to authenticate and be authorized to access data in Google APIs.

**Step 1: Log in to gcloud CLI**
Open your terminal and run:
```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```
Replace `YOUR_PROJECT_ID` with your actual GCP Project ID.

**Step 2: Create the Service Account**
Create a service account that the GitHub Actions workflow will use to authenticate:
```bash
gcloud iam service-accounts create vulnshop-deployer \
    --display-name="VulnShop GitHub Actions Deployer" \
    --description="Service account for deploying VulnShop via GitHub Actions"
```

**Step 3: Grant Permissions to the Service Account**
Grant the `Editor` role to your new service account. This role provides broad permissions to create and manage resources.
```bash
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:vulnshop-deployer@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/editor"
```
*Note: For production environments, it is recommended to grant more granular permissions instead of the broad `Editor` role.*

**Step 4: Create and Download the Service Account Key**
Generate a JSON key for your service account. This key will be used to authenticate from GitHub Actions.
```bash
gcloud iam service-accounts keys create vulnshop-gcp-creds.json \
    --iam-account="vulnshop-deployer@YOUR_PROJECT_ID.iam.gserviceaccount.com"
```
This command will create a file named `vulnshop-gcp-creds.json` in your current directory. **Treat this file like a password and keep it secure.**

**Step 5: Configure GitHub Secrets**
Navigate to your GitHub repository → **Settings** → **Secrets and variables** → **Actions** and create the following secrets:

1.  **`GCP_SA_KEY`**:
    - Open the `vulnshop-gcp-creds.json` file.
    - Copy the **entire content** of the file and paste it as the value for this secret.

2.  **`GCP_PROJECT_ID`**:
    - Use your GCP Project ID as the value for this secret. This is the same ID you used in the previous steps.

After creating the secret, you can safely delete the `vulnshop-gcp-creds.json` file from your local machine.

### AWS IAM User

```bash
# Create IAM user via AWS CLI or Console
aws iam create-user --user-name vulnshop-deployer

# Attach necessary policies
aws iam attach-user-policy --user-name vulnshop-deployer --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess
aws iam attach-user-policy --user-name vulnshop-deployer --policy-arn arn:aws:iam::aws:policy/APIGatewayAdministrator
aws iam attach-user-policy --user-name vulnshop-deployer --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
aws iam attach-user-policy --user-name vulnshop-deployer --policy-arn arn:aws:iam::aws:policy/IAMFullAccess

# Create access key
aws iam create-access-key --user-name vulnshop-deployer
```

## 📊 Deployment Outputs

After successful deployment, you'll receive output with important URLs and connection information:

### Azure Outputs
- Frontend URL: `http://vulnshop-dev-XXXXXX.eastus.cloudapp.azure.com`
- Backend URL: `http://vulnshop-dev-XXXXXX.eastus.cloudapp.azure.com:3001`
- APIM Gateway URL: `https://APIM_GATEWAY_URL/api`
- SSH Connection: `ssh azureuser@vulnshop-dev-XXXXXX.eastus.cloudapp.azure.com`

### GCP Outputs
- Frontend URL: `http://34.56.78.90.nip.io` (using nip.io DNS service)
- Backend URL: `http://34.56.78.90.nip.io:3001`
- Apigee URL: `https://APIGEE_HOSTNAME/api`
- SSH Connection: `ssh gceuser@34.56.78.90`

### AWS Outputs
- Frontend URL: `http://ec2-12-34-56-78.compute-1.amazonaws.com`
- Backend URL: `http://ec2-12-34-56-78.compute-1.amazonaws.com:3001`
- API Gateway URL: `https://API_GATEWAY_URL/dev/api`
- SSH Connection: `ssh ec2-user@ec2-12-34-56-78.compute-1.amazonaws.com`

## 🌐 DNS Configuration

The deployment automatically configures DNS names for easier access:

### Azure DNS
- Azure automatically provides a fully qualified domain name (FQDN) for public IPs
- Format: `vulnshop-{environment}-{random}.{region}.cloudapp.azure.com`
- Example: `vulnshop-dev-abc123.eastus.cloudapp.azure.com`
- This DNS name is stable and persists as long as the public IP exists

### AWS DNS
- AWS automatically assigns a public DNS name to EC2 instances
- Format: `ec2-{ip-address}.{region}.compute.amazonaws.com`
- Example: `ec2-52-23-45-67.us-east-1.compute.amazonaws.com`
- This DNS name changes if the instance is stopped and restarted

### GCP DNS
- GCP doesn't automatically provide DNS names for Compute Engine instances
- We use **nip.io** as a workaround - a free DNS service that maps IP addresses to hostnames
- Format: `{ip-address}.nip.io`
- Example: `34.56.78.90.nip.io` automatically resolves to `34.56.78.90`
- This allows you to use a DNS name without setting up Cloud DNS

### Custom Domain (Optional)
If you want to use your own domain name:
1. Point your domain's A record to the VM's public IP
2. Update your application configuration to accept the new hostname
3. Consider using a static/reserved IP to ensure stability

### GitHub Actions Output
The deployment workflow will display:
- The DNS name prominently at the top of the summary
- Direct links to access your website using the DNS name
- SSH commands using the DNS name for easier access

## 🧪 Testing the Deployment

The deployment includes automatic testing that verifies:
- Frontend accessibility
- Backend API functionality
- Status page availability

You can also manually test:

```bash
# Test frontend
curl http://YOUR_FRONTEND_URL

# Test backend API
curl http://YOUR_FRONTEND_URL/api/products

# Test status page
curl http://YOUR_FRONTEND_URL/status.html
```

## 🔒 Security Vulnerabilities

The deployed application contains **12 intentional security vulnerabilities** for educational purposes:

1. **Weak CORS Configuration** - Allows all origins
2. **No Rate Limiting** - Unlimited requests allowed
3. **Weak JWT Secret** - Using '123456' as secret
4. **SQL Injection** - In search endpoint
5. **IDOR (Insecure Direct Object Reference)** - Order access without authorization
6. **Mass Assignment** - In user registration
7. **Information Disclosure** - Detailed error messages
8. **Missing Authorization** - Product creation endpoint
9. **Race Conditions** - In order processing
10. **XSS (Cross-Site Scripting)** - In review system
11. **Large Payload Acceptance** - 50MB limit
12. **Privilege Escalation** - Weak role validation

### Default Credentials
- **Admin User**: `admin` / `admin123`
- **Regular User**: `testuser` / `user123`

## 🗑️ Destroying Infrastructure

To destroy the deployed infrastructure:

1. Go to **Actions** → **Deploy VulnShop**
2. Click **Run workflow**
3. Select your cloud provider
4. Choose **destroy** action
5. Specify the same environment name used for deployment

Or using Terraform locally:

```bash
cd terraform/[azure|gcp|aws]
terraform destroy
```

## 🐛 Troubleshooting

### Common Issues

1. **Terraform Backend Issues**
   - Ensure you have permission to create/access backend storage
   - Check if backend bucket/container exists

2. **SSH Connection Failed**
   - Verify SSH public key format
   - Check security group/firewall rules
   - Ensure VM is running

3. **Application Not Accessible**
   - Wait 3-5 minutes for cloud-init to complete
   - Check VM logs: `sudo journalctl -u cloud-init`
   - Verify services: `sudo systemctl status vulnshop-backend nginx`

4. **API Gateway Issues**
   - Check API Gateway configuration
   - Verify backend connectivity
   - Review API Gateway logs

### Logs and Debugging

**Azure:**
```bash
ssh azureuser@VM_IP
sudo journalctl -u vulnshop-backend
sudo tail -f /var/log/nginx/error.log
```

**GCP:**
```bash
ssh gceuser@VM_IP
sudo journalctl -u vulnshop-backend
sudo tail -f /var/log/nginx/error.log
```

**AWS:**
```bash
ssh ec2-user@VM_IP
sudo journalctl -u vulnshop-backend
sudo tail -f /var/log/nginx/error.log
```

## 📝 Customization

### Environment Variables

You can customize the deployment by modifying variables in the Terraform files:

- **VM/Instance Size**: Modify `vm_size`/`machine_type`/`instance_type`
- **Region/Location**: Change `region`/`location`
- **Network Configuration**: Adjust CIDR blocks and security rules

### Application Configuration

- **JWT Secret**: Modify in backend environment variables
- **Database Path**: Change SQLite file location
- **API Endpoints**: Customize in backend code

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test on all three cloud providers
5. Submit a pull request

## 📄 License

This project is for educational purposes only. See LICENSE file for details.

## ⚠️ Disclaimer

This application contains intentional security vulnerabilities and should **NEVER** be deployed in a production environment. It is designed solely for educational and security training purposes. 