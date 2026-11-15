variable "project_id" {
  type        = string
  description = "GCP project ID."
}

variable "region" {
  type        = string
  description = "GCP region."
}

variable "name_prefix" {
  type        = string
  description = "Prefix for resource names, e.g. vg-prod."
}

variable "subnet_cidr" {
  type        = string
  description = "CIDR for the private subnet used by Cloud Run Direct VPC egress and the SSH gateway (/24 or larger)."
  default     = "10.10.0.0/24"
}
