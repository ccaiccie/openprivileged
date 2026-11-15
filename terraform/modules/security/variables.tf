variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "env" {
  type        = string
  description = "Environment name (dev or prod)."
}

variable "name_prefix" {
  type = string
}

variable "secret_names" {
  type        = set(string)
  description = "Platform secrets to create as empty Secret Manager containers."
  default     = ["oidc-client-secret", "session-signing-key", "slack-signing-secret", "netbox-sync-master-token"]
}

variable "kms_protection_level" {
  type        = string
  description = "SOFTWARE or HSM."
  default     = "SOFTWARE"
}
