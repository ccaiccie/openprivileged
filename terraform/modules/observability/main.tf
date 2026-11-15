resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "VaultGate ${var.name_prefix} on-call email"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

locals {
  channels = [google_monitoring_notification_channel.email.id]
}

# ---------------------------------------------------------------- Uptime
resource "google_monitoring_uptime_check_config" "https" {
  project      = var.project_id
  display_name = "${var.name_prefix} HTTPS health"
  timeout      = "10s"
  period       = "60s"

  http_check {
    path           = "/healthz"
    port           = 443
    use_ssl        = true
    validate_ssl   = true
    request_method = "GET"
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = var.domain
    }
  }
}

resource "google_monitoring_alert_policy" "uptime" {
  project      = var.project_id
  display_name = "${var.name_prefix} P1: HTTPS endpoint down"
  combiner     = "OR"

  conditions {
    display_name = "Uptime check failing"

    condition_threshold {
      filter          = "metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\" AND metric.label.check_id=\"${google_monitoring_uptime_check_config.https.uptime_check_id}\" AND resource.type=\"uptime_url\""
      comparison      = "COMPARISON_GT"
      threshold_value = 1
      duration        = "300s"

      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_NEXT_OLDER"
        cross_series_reducer = "REDUCE_COUNT_FALSE"
        group_by_fields      = ["resource.label.*"]
      }
    }
  }

  notification_channels = local.channels
}

# ---------------------------------------------------------------- Stuck grants (log-based metric)
resource "google_logging_metric" "stuck_grants" {
  project = var.project_id
  name    = "${var.name_prefix}-stuck-grants"
  filter  = "resource.type=\"cloud_run_revision\" AND jsonPayload.event=\"grant.withdraw_failed\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "stuck_grants" {
  project      = var.project_id
  display_name = "${var.name_prefix} P1: grant withdrawal failed (stuck grant)"
  combiner     = "OR"

  conditions {
    display_name = "grant.withdraw_failed logged"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.stuck_grants.name}\" AND resource.type=\"cloud_run_revision\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = local.channels

  alert_strategy {
    auto_close = "86400s"
  }
}

# ---------------------------------------------------------------- Cloud Run 5xx
resource "google_monitoring_alert_policy" "run_5xx" {
  project      = var.project_id
  display_name = "${var.name_prefix} P2: Cloud Run 5xx rate"
  combiner     = "OR"

  conditions {
    display_name = "5xx responses > ${var.error_5xx_per_5min} per 5 min"

    condition_threshold {
      filter          = "metric.type=\"run.googleapis.com/request_count\" AND resource.type=\"cloud_run_revision\" AND metric.label.response_code_class=\"5xx\""
      comparison      = "COMPARISON_GT"
      threshold_value = var.error_5xx_per_5min
      duration        = "300s"

      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["resource.label.service_name"]
      }
    }
  }

  notification_channels = local.channels
}

# ---------------------------------------------------------------- Cloud SQL CPU
resource "google_monitoring_alert_policy" "sql_cpu" {
  project      = var.project_id
  display_name = "${var.name_prefix} P2: Cloud SQL CPU high"
  combiner     = "OR"

  conditions {
    display_name = "CPU > 80% for 15 min"

    condition_threshold {
      filter          = "metric.type=\"cloudsql.googleapis.com/database/cpu/utilization\" AND resource.type=\"cloudsql_database\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8
      duration        = "900s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = local.channels
}

# ---------------------------------------------------------------- Log sinks
resource "google_logging_project_sink" "to_bucket" {
  project                = var.project_id
  name                   = "${var.name_prefix}-app-and-audit-logs"
  destination            = "storage.googleapis.com/${var.logs_bucket}"
  unique_writer_identity = true
  filter                 = "resource.type=\"cloud_run_revision\" OR logName:\"cloudaudit.googleapis.com\""
}

resource "google_storage_bucket_iam_member" "sink_writer" {
  bucket = var.logs_bucket
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.to_bucket.writer_identity
}
