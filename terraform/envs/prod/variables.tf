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
  description = "Git ref prefix allowed to deploy (release tags only in prod)."
  default     = "refs/tags/v"
}

variable "image_tag" {
  type        = string
  description = "Image tag deployed by Terraform. Keep \"bootstrap\" until the first CI build pushes images."
  default     = "bootstrap"
}

variable "subnet_cidr" {
  type    = string
  default = "10.20.0.0/24"
}

variable "sql_tier" {
  type        = string
  description = "db-custom-2-8192 (10 customers), db-custom-4-16384 (100), db-custom-8-32768 (1,000)."
  default     = "db-custom-2-8192"
}

variable "sql_disk_gb" {
  type    = number
  default = 50
}

variable "redis_memory_gb" {
  type    = number
  default = 1
}

variable "kms_protection_level" {
  type        = string
  description = "SOFTWARE or HSM."
  default     = "SOFTWARE"
}

variable "recordings_retention_days" {
  type    = number
  default = 365
}

variable "audit_retention_days" {
  type    = number
  default = 365
}

variable "lock_retention" {
  type        = bool
  description = "Permanently lock bucket retention policies (irreversible). Enable only after the retention period is final."
  default     = false
}

variable "min_instances" {
  type = map(number)
  default = {
    api    = 1
    broker = 1
    worker = 1
  }
}

variable "max_instances" {
  type = map(number)
  default = {
    api    = 10
    broker = 10
    worker = 5
  }
}

variable "enable_ssh_gateway" {
  type        = bool
  description = "Create the native SSH gateway (needs a pushed broker image, so enable after the first CI build)."
  default     = false
}
