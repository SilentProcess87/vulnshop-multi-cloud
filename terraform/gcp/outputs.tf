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
  description = "Frontend application URL"
  value       = "http://${google_compute_instance.main.network_interface[0].access_config[0].nat_ip}"
}

output "backend_url" {
  description = "Backend API URL"
  value       = "http://${google_compute_instance.main.network_interface[0].access_config[0].nat_ip}:3001"
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