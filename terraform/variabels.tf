variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "zones" {
  type    = list(string)
  default = ["us-central1-a", "us-central1-b"]
}

variable "cluster_name" {
  type    = string
  default = "your-gke-cluster"
}

variable "repo_name" {
  type    = string
  default = "your-go-app"
}
