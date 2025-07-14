terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~>3.1"
    }
  }
}

provider "azurerm" {
  features {}
}

# Generate random suffix for resource names
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# Resource Group
resource "azurerm_resource_group" "main" {
  name     = "rg-vulnshop-${random_string.suffix.result}"
  location = var.location
  
  tags = {
    Environment = var.environment
    Project     = "VulnShop"
  }
}

# Virtual Network
resource "azurerm_virtual_network" "main" {
  name                = "vnet-vulnshop-${random_string.suffix.result}"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = {
    Environment = var.environment
    Project     = "VulnShop"
  }
}

# Subnet for VMs
resource "azurerm_subnet" "vm" {
  name                 = "subnet-vm"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Network Security Group
resource "azurerm_network_security_group" "main" {
  name                = "nsg-vulnshop-${random_string.suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "HTTP"
    priority                   = 1002
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Backend"
    priority                   = 1003
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3001"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = {
    Environment = var.environment
    Project     = "VulnShop"
  }
}

# Public IP for VM
resource "azurerm_public_ip" "vm" {
  name                = "pip-vm-vulnshop-${random_string.suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Dynamic"

  tags = {
    Environment = var.environment
    Project     = "VulnShop"
  }
}

# Network Interface
resource "azurerm_network_interface" "vm" {
  name                = "nic-vm-vulnshop-${random_string.suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vm.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm.id
  }

  tags = {
    Environment = var.environment
    Project     = "VulnShop"
  }
}

# Associate Network Security Group to the subnet
resource "azurerm_subnet_network_security_group_association" "main" {
  subnet_id                 = azurerm_subnet.vm.id
  network_security_group_id = azurerm_network_security_group.main.id
}

# SSH Key for VM
resource "azurerm_ssh_public_key" "vm" {
  name                = "ssh-key-vulnshop-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  public_key          = var.ssh_public_key
}

# Virtual Machine
resource "azurerm_linux_virtual_machine" "main" {
  name                = "vm-vulnshop-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  size                = var.vm_size
  admin_username      = var.admin_username

  disable_password_authentication = true

  network_interface_ids = [
    azurerm_network_interface.vm.id,
  ]

  admin_ssh_key {
    username   = var.admin_username
    public_key = azurerm_ssh_public_key.vm.public_key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  custom_data = base64encode(templatefile("${path.module}/cloud-init.yml", {
    git_repo = var.git_repo
    git_branch = var.git_branch
  }))

  tags = {
    Environment = var.environment
    Project     = "VulnShop"
  }
}

# API Management Service
resource "azurerm_api_management" "main" {
  name                = "apim-vulnshop-${random_string.suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  publisher_name      = var.apim_publisher_name
  publisher_email     = var.apim_publisher_email
  sku_name           = var.apim_sku

  tags = {
    Environment = var.environment
    Project     = "VulnShop"
  }
}

# API Management API
resource "azurerm_api_management_api" "vulnshop" {
  name                = "vulnshop-api"
  resource_group_name = azurerm_resource_group.main.name
  api_management_name = azurerm_api_management.main.name
  revision            = "1"
  display_name        = "VulnShop API"
  path                = "api"
  protocols           = ["https", "http"]
  service_url         = "http://${azurerm_linux_virtual_machine.main.private_ip_address}:3001/api"

  import {
    content_format = "openapi+json"
    content_value  = file("${path.root}/apim-swagger.json")
  }
}

# API Management Backend
resource "azurerm_api_management_backend" "vulnshop" {
  name                = "vulnshop-backend"
  resource_group_name = azurerm_resource_group.main.name
  api_management_name = azurerm_api_management.main.name
  protocol            = "http"
  url                 = "http://${azurerm_linux_virtual_machine.main.private_ip_address}:3001/api"
}

# API Management Product
resource "azurerm_api_management_product" "vulnshop" {
  product_id            = "vulnshop"
  api_management_name   = azurerm_api_management.main.name
  resource_group_name   = azurerm_resource_group.main.name
  display_name          = "VulnShop Product"
  description           = "Vulnerable e-commerce API for educational purposes"
  subscription_required = false
  published             = true
}

# Associate API with Product
resource "azurerm_api_management_product_api" "vulnshop" {
  api_name            = azurerm_api_management_api.vulnshop.name
  product_id          = azurerm_api_management_product.vulnshop.product_id
  api_management_name = azurerm_api_management.main.name
  resource_group_name = azurerm_resource_group.main.name
}

# API Management Policy (Vulnerable CORS)
resource "azurerm_api_management_api_policy" "vulnshop" {
  api_name            = azurerm_api_management_api.vulnshop.name
  api_management_name = azurerm_api_management.main.name
  resource_group_name = azurerm_resource_group.main.name

  xml_content = file("${path.root}/policies/cors-policy.xml")
}

# Storage Account for diagnostics
resource "azurerm_storage_account" "main" {
  name                     = "stsecvulnshop${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = {
    Environment = var.environment
    Project     = "VulnShop"
  }
} 