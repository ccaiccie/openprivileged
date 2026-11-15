variable "project_id" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "domain" {
  type        = string
  description = "Public hostname probed by the uptime check."
}

variable "alert_email" {
  type        = string
  description = "Email for the notification channel (add PagerDuty/Slack channels in the console or extend this module)."
}

variable "logs_bucket" {
  type        = string
  description = "Bucket receiving the log sink."
}

variable "error_5xx_per_5min" {
  type    = number
  default = 20
}
