terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~>3.1"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# Generate random suffix for resource names
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# Enable required APIs
resource "google_project_service" "compute" {
  service = "compute.googleapis.com"
}

resource "google_project_service" "apigee" {
  service = "apigee.googleapis.com"
}

# VPC Network
resource "google_compute_network" "main" {
  name                    = "vulnshop-vpc-${random_string.suffix.result}"
  auto_create_subnetworks = false
  
  depends_on = [google_project_service.compute]
}

# Subnet
resource "google_compute_subnetwork" "main" {
  name          = "vulnshop-subnet-${random_string.suffix.result}"
  ip_cidr_range = "10.0.1.0/24"
  region        = var.region
  network       = google_compute_network.main.id
}

# Firewall rule for HTTP
resource "google_compute_firewall" "allow_http" {
  name    = "vulnshop-allow-http-${random_string.suffix.result}"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["80", "3001"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["vulnshop-server"]
}

# Firewall rule for SSH
resource "google_compute_firewall" "allow_ssh" {
  name    = "vulnshop-allow-ssh-${random_string.suffix.result}"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["vulnshop-server"]
}

# Compute Engine Instance
resource "google_compute_instance" "main" {
  name         = "vulnshop-vm-${random_string.suffix.result}"
  machine_type = var.machine_type
  zone         = var.zone

  tags = ["vulnshop-server"]

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = 20
      type  = "pd-standard"
    }
  }

  network_interface {
    network    = google_compute_network.main.id
    subnetwork = google_compute_subnetwork.main.id

    access_config {
      // Ephemeral public IP
    }
  }

  metadata = {
    ssh-keys = "${var.admin_username}:${var.ssh_public_key}"
  }

  metadata_startup_script = templatefile("${path.module}/startup-script.sh", {
    git_repo   = var.git_repo
    git_branch = var.git_branch
  })

  service_account {
    scopes = ["cloud-platform"]
  }

  labels = {
    environment = var.environment
    project     = "vulnshop"
  }

  depends_on = [google_project_service.compute]
}

# Apigee Organization (if not exists)
resource "google_apigee_organization" "main" {
  analytics_region   = var.analytics_region
  project_id         = var.project_id
  authorized_network = google_compute_network.main.id
  runtime_type       = "CLOUD"
  billing_type       = "EVALUATION"

  depends_on = [
    google_project_service.apigee,
    google_compute_network.main
  ]
}

# Apigee Environment
resource "google_apigee_environment" "main" {
  org_id       = google_apigee_organization.main.id
  name         = var.environment
  description  = "VulnShop ${var.environment} environment"
  display_name = "VulnShop ${var.environment}"
}

# Apigee Environment Group
resource "google_apigee_envgroup" "main" {
  org_id    = google_apigee_organization.main.id
  name      = "vulnshop-${var.environment}-${random_string.suffix.result}"
  hostnames = ["${var.apigee_hostname}"]
}

# Attach Environment to Environment Group
resource "google_apigee_envgroup_attachment" "main" {
  envgroup_id = google_apigee_envgroup.main.id
  environment = google_apigee_environment.main.name
}

# Apigee Instance
resource "google_apigee_instance" "main" {
  name         = "vulnshop-instance-${random_string.suffix.result}"
  location     = var.region
  org_id       = google_apigee_organization.main.id
  ip_range     = "10.1.0.0/22"
  
  depends_on = [google_apigee_organization.main]
}

# Attach Instance to Environment
resource "google_apigee_instance_attachment" "main" {
  instance_id = google_apigee_instance.main.id
  environment = google_apigee_environment.main.name
}

# Target Server for Backend
resource "google_apigee_target_server" "backend" {
  name        = "vulnshop-backend"
  description = "VulnShop Backend Server"
  env_id      = google_apigee_environment.main.id
  host        = google_compute_instance.main.network_interface[0].network_ip
  port        = 3001
  protocol    = "HTTP"
}

# Storage bucket for deployment assets
resource "google_storage_bucket" "deployment" {
  name     = "vulnshop-deployment-${random_string.suffix.result}"
  location = var.region

  uniform_bucket_level_access = true

  labels = {
    environment = var.environment
    project     = "vulnshop"
  }
}

# Upload API proxy bundle (we'll create this separately)
locals {
  api_proxy_content = templatefile("${path.module}/api-proxy-bundle.json", {
    backend_host = google_compute_instance.main.network_interface[0].network_ip
    backend_port = "3001"
  })
}

resource "google_storage_bucket_object" "api_proxy" {
  name   = "vulnshop-api-proxy.json"
  bucket = google_storage_bucket.deployment.name
  content = local.api_proxy_content
}

# Cloud NAT for outbound connectivity
resource "google_compute_router" "main" {
  name    = "vulnshop-router-${random_string.suffix.result}"
  region  = var.region
  network = google_compute_network.main.id
}

resource "google_compute_router_nat" "main" {
  name   = "vulnshop-nat-${random_string.suffix.result}"
  router = google_compute_router.main.name
  region = var.region

  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
} 