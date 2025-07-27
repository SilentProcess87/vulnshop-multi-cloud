# Quick Setup Guide - Destroy Workflow

This guide will help you quickly set up the destroy workflow for GitHub Actions.

## Step 1: Configure GitHub Secrets

### For Azure Destruction:

1. **Create Azure Service Principal** (run this in your local terminal or Azure Cloud Shell):
```bash
# Replace YOUR-SUBSCRIPTION-ID with your actual subscription ID
az ad sp create-for-rbac --name "github-vulnshop-destroy" \
  --role contributor \
  --scopes /subscriptions/YOUR-SUBSCRIPTION-ID \
  --sdk-auth
```

2. **Copy the entire JSON output** - it looks like this:
```json
{
  "clientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "clientSecret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "subscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "activeDirectoryEndpointUrl": "...",
  "resourceManagerEndpointUrl": "...",
  "activeDirectoryGraphResourceId": "...",
  "sqlManagementEndpointUrl": "...",
  "galleryEndpointUrl": "...",
  "managementEndpointUrl": "..."
}
```

3. **Add secrets to GitHub**:
   - Go to your repository → Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Add these secrets:

   | Secret Name | Value |
   |-------------|-------|
   | `AZURE_CREDENTIALS` | Paste the entire JSON from step 2 |
   | `AZURE_CLIENT_ID` | Copy just the clientId value |
   | `AZURE_CLIENT_SECRET` | Copy just the clientSecret value |
   | `AZURE_SUBSCRIPTION_ID` | Copy just the subscriptionId value |
   | `AZURE_TENANT_ID` | Copy just the tenantId value |

## Step 2: Test the Destroy Workflow

1. **Go to Actions tab** in your GitHub repository
2. **Select "Destroy Infrastructure"** from the left sidebar
3. **Click "Run workflow"**
4. **Fill in**:
   - Cloud Provider: `azure`
   - Environment: `dev` (or whatever you deployed)
   - Confirm Destroy: `DESTROY` (must be exact)
5. **Click "Run workflow"** (green button)

## Step 3: Verify Destruction

The workflow will:
1. Show you all resources that will be destroyed
2. Destroy all infrastructure
3. Clean up temporary files
4. Show a summary in the workflow run

## Important Reminders

⚠️ **NO SSH KEY REQUIRED** - The workflow handles authentication via Azure Service Principal

⚠️ **TYPE EXACTLY** - You must type `DESTROY` exactly (all caps) to confirm

⚠️ **CHECK ENVIRONMENT** - Make sure you're destroying the right environment

## Need Help?

- Check the full documentation in [README.md](./README.md)
- Review workflow logs if something fails
- The workflow will show detailed error messages if authentication fails 