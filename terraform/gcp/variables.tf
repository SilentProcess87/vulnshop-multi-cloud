variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone"
  type        = string
  default     = "us-central1-a"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "machine_type" {
  description = "Compute Engine machine type"
  type        = string
  default     = "e2-medium"
}

variable "admin_username" {
  description = "Admin username for the VM"
  type        = string
  default     = "gceuser"
}

variable "ssh_public_key" {
  description = "SSH public key for VM access"
  type        = string
}

variable "analytics_region" {
  description = "Apigee analytics region"
  type        = string
  default     = "us-central1"
}

variable "apigee_hostname" {
  description = "Hostname for Apigee environment group"
  type        = string
  default     = "api.vulnshop.example.com"
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