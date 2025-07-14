output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.main.name
}

output "vm_public_ip" {
  description = "Public IP address of the virtual machine"
  value       = azurerm_public_ip.vm.ip_address
}

output "vm_private_ip" {
  description = "Private IP address of the virtual machine"
  value       = azurerm_linux_virtual_machine.main.private_ip_address
}

output "vm_dns_name" {
  description = "Fully qualified domain name (FQDN) of the VM"
  value       = azurerm_public_ip.vm.fqdn
}

output "apim_gateway_url" {
  description = "API Management gateway URL"
  value       = azurerm_api_management.main.gateway_url
}

output "apim_developer_portal_url" {
  description = "API Management developer portal URL"
  value       = azurerm_api_management.main.developer_portal_url
}

output "apim_management_api_url" {
  description = "API Management management API URL"
  value       = azurerm_api_management.main.management_api_url
}

output "frontend_url" {
  description = "Frontend application URL (using DNS name)"
  value       = "http://${azurerm_public_ip.vm.fqdn}"
}

output "frontend_url_ip" {
  description = "Frontend application URL (using IP)"
  value       = "http://${azurerm_public_ip.vm.ip_address}"
}

output "backend_url" {
  description = "Backend API URL (using DNS name)"
  value       = "http://${azurerm_public_ip.vm.fqdn}:3001"
}

output "api_via_apim_url" {
  description = "API URL via APIM"
  value       = "${azurerm_api_management.main.gateway_url}/api"
}

output "ssh_connection" {
  description = "SSH connection command (using DNS name)"
  value       = "ssh ${var.admin_username}@${azurerm_public_ip.vm.fqdn}"
}

output "deployment_summary" {
  description = "Deployment summary with all access URLs"
  value = {
    website_dns_url = "http://${azurerm_public_ip.vm.fqdn}"
    website_ip_url  = "http://${azurerm_public_ip.vm.ip_address}"
    api_direct_url  = "http://${azurerm_public_ip.vm.fqdn}:3001/api"
    api_gateway_url = "${azurerm_api_management.main.gateway_url}/api"
    ssh_access      = "ssh ${var.admin_username}@${azurerm_public_ip.vm.fqdn}"
  }
} 