variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "reader_service_accounts" {
  type        = list(string)
  description = "Service account emails that pull images (e.g. the ssh-gateway VM account). Cloud Run uses the Google-managed service agent and needs no binding when the repo is in the same project."
  default     = []
}
