variable "project_id" {
  type        = string
  description = "Dedicated GCP project for the dev environment."
}

variable "region" {
  type        = string
  description = "GCP region for all regional resources."
  default     = "europe-west1"
}

variable "domain" {
  type        = string
  description = "Public hostname (fully qualified), e.g. dev.vaultgate.example. Point an A record at the lb_ip output."
}

variable "alert_email" {
  type        = string
  description = "Email for monitoring notifications."
}

variable "github_repository" {
  type        = string
  description = "GitHub repository (OWNER/REPO) allowed to deploy via Workload Identity Federation."
}

variable "allowed_ref_prefix" {
  type        = string
  description = "Git ref prefix allowed to deploy."
  default     = "refs/heads/main"
}

variable "image_tag" {
  type        = string
  description = "Image tag deployed by Terraform. Keep \"bootstrap\" until the first CI build pushes images."
  default     = "bootstrap"
}

variable "subnet_cidr" {
  type    = string
  default = "10.10.0.0/24"
}

variable "sql_tier" {
  type    = string
  default = "db-f1-micro"
}

variable "enable_ssh_gateway" {
  type        = bool
  description = "Create the native SSH gateway (needs a pushed broker image, so enable after the first CI build)."
  default     = false
}
