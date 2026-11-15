variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "network_id" {
  type        = string
  description = "VPC network ID (projects/PROJECT/global/networks/NAME)."
}

variable "sql_tier" {
  type        = string
  description = "Cloud SQL machine tier, e.g. db-f1-micro (dev) or db-custom-2-8192 (prod)."
  default     = "db-custom-2-8192"
}

variable "sql_disk_gb" {
  type    = number
  default = 50
}

variable "sql_high_availability" {
  type    = bool
  default = true
}

variable "sql_pitr" {
  type    = bool
  default = true
}

variable "deletion_protection" {
  type    = bool
  default = true
}

variable "redis_ha" {
  type    = bool
  default = true
}

variable "redis_memory_gb" {
  type    = number
  default = 1
}

variable "service_account_emails" {
  type        = map(string)
  description = "Runtime service account emails keyed by component."
}

variable "reader_accounts" {
  type        = list(string)
  description = "Component names allowed to read the DB and Redis secrets."
  default     = ["api", "worker", "broker"]
}
