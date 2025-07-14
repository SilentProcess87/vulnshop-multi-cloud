variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "East US"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "vm_size" {
  description = "Size of the virtual machine"
  type        = string
  default     = "Standard_B2s"
}

variable "admin_username" {
  description = "Admin username for the VM"
  type        = string
  default     = "azureuser"
}

variable "ssh_public_key" {
  description = "SSH public key for VM access"
  type        = string
}

variable "apim_publisher_name" {
  description = "API Management publisher name"
  type        = string
  default     = "VulnShop Admin"
}

variable "apim_publisher_email" {
  description = "API Management publisher email"
  type        = string
}

variable "apim_sku" {
  description = "API Management SKU"
  type        = string
  default     = "Developer_1"
}

variable "git_repo" {
  description = "Git repository URL"
  type        = string
}

variable "git_branch" {
  description = "Git branch to deploy"
  type        = string
  default     = "main"
} 