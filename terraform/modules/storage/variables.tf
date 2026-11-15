variable "project_id" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "location" {
  type        = string
  description = "Bucket location. Must equal the KMS key region for CMEK (e.g. europe-west1)."
}

variable "recordings_kms_key_id" {
  type        = string
  description = "KMS crypto key ID for the recordings bucket."
}

variable "service_account_emails" {
  type        = map(string)
  description = "Runtime service account emails keyed by api, worker, broker."
}

variable "recordings_retention_days" {
  type    = number
  default = 30
}

variable "audit_retention_days" {
  type    = number
  default = 365
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "lock_retention" {
  type        = bool
  description = "Permanently lock retention policies. Irreversible: enable only in prod once the period is final."
  default     = false
}

variable "force_destroy" {
  type    = bool
  default = false
}
