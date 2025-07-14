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
  description = "Frontend application URL"
  value       = "http://${azurerm_public_ip.vm.ip_address}"
}

output "backend_url" {
  description = "Backend API URL"
  value       = "http://${azurerm_public_ip.vm.ip_address}:3001"
}

output "api_via_apim_url" {
  description = "API URL via APIM"
  value       = "${azurerm_api_management.main.gateway_url}/api"
}

output "ssh_connection" {
  description = "SSH connection command"
  value       = "ssh ${var.admin_username}@${azurerm_public_ip.vm.ip_address}"
} 