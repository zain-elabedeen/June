variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "europe-west3"
}

variable "zones" {
  type    = list(string)
  default = ["europe-west3-a", "europe-west3-b", " europe-west3-c"]
}

variable "cluster_name" {
  type    = string
  default = "june-api-1"
}

variable "repo_name" {
  type    = string
  default = "June"
}
