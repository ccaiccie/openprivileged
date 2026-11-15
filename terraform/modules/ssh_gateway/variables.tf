variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "network_name" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "service_account_email" {
  type        = string
  description = "ssh-gateway service account email."
}

variable "image" {
  type        = string
  description = "Full broker image reference including tag, e.g. REGION-docker.pkg.dev/PROJECT/REPO/broker:TAG."
}

variable "registry_host" {
  type        = string
  description = "Artifact Registry host, e.g. europe-west1-docker.pkg.dev."
}

variable "registry_repository_id" {
  type = string
}

variable "machine_type" {
  type    = string
  default = "e2-small"
}

variable "instance_count" {
  type    = number
  default = 1
}
