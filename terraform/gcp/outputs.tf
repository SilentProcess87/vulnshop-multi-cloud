output "project_id" {
  description = "GCP project ID"
  value       = var.project_id
}

output "vm_external_ip" {
  description = "External IP address of the VM"
  value       = google_compute_instance.main.network_interface[0].access_config[0].nat_ip
}

output "vm_internal_ip" {
  description = "Internal IP address of the VM"
  value       = google_compute_instance.main.network_interface[0].network_ip
}

output "vm_dns_suggestion" {
  description = "Suggested DNS name using nip.io (automatically resolves to IP)"
  value       = "${google_compute_instance.main.network_interface[0].access_config[0].nat_ip}.nip.io"
}

output "apigee_org_id" {
  description = "Apigee organization ID"
  value       = google_apigee_organization.main.id
}

output "apigee_environment" {
  description = "Apigee environment name"
  value       = google_apigee_environment.main.name
}

output "apigee_hostname" {
  description = "Apigee environment group hostname"
  value       = var.apigee_hostname
}

output "frontend_url" {
  description = "Frontend application URL (using nip.io DNS)"
  value       = "http://${google_compute_instance.main.network_interface[0].access_config[0].nat_ip}.nip.io"
}

output "frontend_url_ip" {
  description = "Frontend application URL (using IP)"
  value       = "http://${google_compute_instance.main.network_interface[0].access_config[0].nat_ip}"
}

output "backend_url" {
  description = "Backend API URL (using nip.io DNS)"
  value       = "http://${google_compute_instance.main.network_interface[0].access_config[0].nat_ip}.nip.io:3001"
}

output "api_via_apigee_url" {
  description = "API URL via Apigee"
  value       = "https://${var.apigee_hostname}/api"
}

output "ssh_connection" {
  description = "SSH connection command"
  value       = "ssh ${var.admin_username}@${google_compute_instance.main.network_interface[0].access_config[0].nat_ip}"
}

output "storage_bucket" {
  description = "Deployment storage bucket"
  value       = google_storage_bucket.deployment.name
}

output "deployment_summary" {
  description = "Deployment summary with all access URLs"
  value = {
    website_dns_url = "http://${google_compute_instance.main.network_interface[0].access_config[0].nat_ip}.nip.io"
    website_ip_url  = "http://${google_compute_instance.main.network_interface[0].access_config[0].nat_ip}"
    api_direct_url  = "http://${google_compute_instance.main.network_interface[0].access_config[0].nat_ip}.nip.io:3001/api"
    api_gateway_url = "https://${var.apigee_hostname}/api"
    ssh_access      = "ssh ${var.admin_username}@${google_compute_instance.main.network_interface[0].access_config[0].nat_ip}"
    note            = "GCP doesn't auto-assign DNS names. Using nip.io for convenience (e.g., 34.56.78.90.nip.io resolves to 34.56.78.90)"
  }
} 