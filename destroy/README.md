# Infrastructure Destroy Workflow

This directory contains documentation for safely destroying cloud infrastructure using GitHub Actions.

## Overview

The destroy workflow (`../.github/workflows/destroy.yml`) allows you to safely destroy infrastructure deployed on Azure, GCP, or AWS without requiring SSH keys. The workflow uses cloud provider authentication (service principals/keys) stored as GitHub secrets.

## Prerequisites

### GitHub Secrets Configuration

You need to configure the following secrets in your GitHub repository settings (`Settings > Secrets and variables > Actions`):

#### For Azure:
- `AZURE_CREDENTIALS` - Azure Service Principal credentials in JSON format
- `AZURE_CLIENT_ID` - Azure Service Principal Client ID
- `AZURE_CLIENT_SECRET` - Azure Service Principal Client Secret
- `AZURE_SUBSCRIPTION_ID` - Azure Subscription ID
- `AZURE_TENANT_ID` - Azure Tenant ID

#### For GCP:
- `GCP_SA_KEY` - Google Cloud Service Account key in JSON format
- `GCP_PROJECT_ID` - Google Cloud Project ID

#### For AWS:
- `AWS_ACCESS_KEY_ID` - AWS Access Key ID
- `AWS_SECRET_ACCESS_KEY` - AWS Secret Access Key

### Optional Variables:
- `AWS_REGION` - AWS Region (defaults to us-east-1)

## Setting up Azure Service Principal

To create an Azure Service Principal without SSH:

```bash
# Login to Azure CLI
az login

# Create Service Principal with Contributor role
az ad sp create-for-rbac --name "github-actions-sp" \
  --role contributor \
  --scopes /subscriptions/{subscription-id} \
  --sdk-auth
```

The output will be a JSON object that you should save as the `AZURE_CREDENTIALS` secret:

```json
{
  "clientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "clientSecret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "subscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

Also extract and save individual values:
- `clientId` → `AZURE_CLIENT_ID`
- `clientSecret` → `AZURE_CLIENT_SECRET`
- `subscriptionId` → `AZURE_SUBSCRIPTION_ID`
- `tenantId` → `AZURE_TENANT_ID`

## Using the Destroy Workflow

1. Go to your repository on GitHub
2. Click on the "Actions" tab
3. Select "Destroy Infrastructure" from the left sidebar
4. Click "Run workflow"
5. Fill in the required inputs:
   - **Cloud Provider**: Select azure, gcp, or aws
   - **Environment**: Enter the environment name (e.g., dev, staging, prod)
   - **Confirm Destroy**: Type `DESTROY` (exactly) to confirm

### Safety Features

- **Confirmation Required**: You must type `DESTROY` exactly to proceed
- **State Verification**: The workflow shows all resources that will be destroyed before proceeding
- **Audit Trail**: All destructions are logged with timestamp and user information
- **No SSH Keys**: The workflow uses cloud provider authentication, not SSH keys

## What Gets Destroyed

The workflow will destroy all resources managed by Terraform for the specified cloud provider and environment, including:

### Azure:
- Virtual Machine
- API Management Service
- Virtual Network and Subnets
- Network Security Groups
- Public IP Addresses
- Storage Account
- Resource Group

### GCP:
- Compute Instance
- Apigee API Management
- VPC Network
- Firewall Rules
- Cloud Storage Bucket

### AWS:
- EC2 Instance
- API Gateway
- VPC and Subnets
- Security Groups
- S3 Buckets
- Elastic IPs

## Important Notes

1. **State File**: The workflow uses remote state storage. Make sure your Terraform state is properly configured.
2. **Irreversible**: Once destroyed, resources cannot be recovered. Always verify the environment before destroying.
3. **Cost Savings**: Remember to destroy unused environments to avoid unnecessary cloud costs.
4. **Dependencies**: If resources have dependencies outside of Terraform, they may need to be removed manually.

## Troubleshooting

### "No resources found in state"
- The environment may have already been destroyed
- Check if you're using the correct environment name
- Verify the Terraform state backend configuration

### Authentication Errors
- Verify all required secrets are configured correctly
- Check if the service principal/keys have sufficient permissions
- Ensure the credentials haven't expired

### Terraform Errors
- Review the workflow logs for specific error messages
- Some resources may require manual deletion if they have deletion protection enabled
- Check for resources created outside of Terraform that may be blocking deletion

## Manual Cleanup (if needed)

If the automated destroy fails, you can manually clean up resources:

### Azure:
```bash
# Delete resource group (deletes all resources within)
az group delete --name rg-vulnshop-* --yes --no-wait
```

### GCP:
```bash
# Delete all resources with a specific label
gcloud compute instances delete NAME --zone=ZONE
gcloud apigee environments delete ENVIRONMENT --organization=ORG
```

### AWS:
```bash
# Use AWS CLI to delete resources
aws ec2 terminate-instances --instance-ids i-xxxxx
aws apigateway delete-rest-api --rest-api-id xxxxx
``` 