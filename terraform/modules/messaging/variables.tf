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
  description = "Runtime service account emails keyed by component (api, worker, scheduler)."
}
