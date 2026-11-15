variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "service_account_emails" {
  type        = map(string)
  description = "Runtime service account emails keyed by api, worker, broker, scheduler."
}

variable "network_name" {
  type        = string
  description = "VPC network name for Direct VPC egress."
}

variable "subnet_name" {
  type        = string
  description = "Subnetwork name for Direct VPC egress."
}

variable "image_registry" {
  type        = string
  description = "Artifact Registry path prefix (no trailing slash)."
}

variable "image_tag" {
  type        = string
  description = "Image tag to deploy. Use \"bootstrap\" before the first CI build to use a placeholder image."
  default     = "bootstrap"
}

variable "bootstrap_image" {
  type        = string
  description = "Placeholder image listening on 8080, used only while image_tag = bootstrap."
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}

variable "env_vars" {
  type        = map(string)
  description = "Non-secret environment variables for all Cloud Run services."
  default     = {}
}

variable "secret_env" {
  type        = map(string)
  description = "Map of ENV_VAR name to Secret Manager secret_id (latest version)."
  default     = {}
}

variable "min_instances" {
  type = map(number)
  default = {
    api    = 0
    broker = 0
    worker = 1
  }
}

variable "max_instances" {
  type = map(number)
  default = {
    api    = 5
    broker = 5
    worker = 3
  }
}

variable "domain" {
  type        = string
  description = "Fully qualified domain for the managed certificate, e.g. app.example.com."
}

variable "scheduler_cron" {
  type    = string
  default = "* * * * *"
}

variable "rate_limit_per_minute" {
  type    = number
  default = 600
}

variable "deletion_protection" {
  type    = bool
  default = true
}
