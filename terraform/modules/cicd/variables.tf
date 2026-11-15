variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "github_repository" {
  type        = string
  description = "GitHub repository allowed to deploy, as OWNER/REPO."
}

variable "allowed_ref_prefix" {
  type        = string
  description = "Git ref prefix allowed to deploy, e.g. refs/heads/main (dev) or refs/tags/v (prod)."
}

variable "registry_repository_id" {
  type = string
}

variable "runtime_service_accounts" {
  type        = map(string)
  description = "Map of component name to runtime service account email that deployments may act as."
}
