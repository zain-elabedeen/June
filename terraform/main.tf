provider "google" {
  project = var.project_id
  region  = var.region
}

module "gke" {
  source     = "terraform-google-modules/kubernetes-engine/google"
  version    = "~> 30.0"
  project_id = var.project_id
  name       = var.cluster_name
  region     = var.region
  zones      = var.zones

  network    = "default"
  subnetwork = "default"

  ip_range_pods     = "pods"
  ip_range_services = "services"

  node_pools = [
    {
      name         = "default-node-pool"
      machine_type = "e2-medium"
      min_count    = 1
      max_count    = 3
      disk_size_gb = 50
    }
  ]
}

resource "google_artifact_registry_repository" "app_repo" {
  location      = var.region
  repository_id = var.repo_name
  format        = "DOCKER"
}
