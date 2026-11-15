locals {
  topics = toset(["audit-export", "collector-jobs", "grant-events"])
}

resource "google_pubsub_topic" "topics" {
  for_each                   = local.topics
  project                    = var.project_id
  name                       = "${var.name_prefix}-${each.key}"
  message_retention_duration = "604800s"
}

resource "google_pubsub_subscription" "collector_jobs" {
  project                    = var.project_id
  name                       = "${var.name_prefix}-collector-jobs-worker"
  topic                      = google_pubsub_topic.topics["collector-jobs"].id
  ack_deadline_seconds       = 60
  message_retention_duration = "604800s"

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
}

resource "google_pubsub_topic_iam_member" "publishers" {
  for_each = {
    for pair in setproduct(local.topics, ["api", "worker", "scheduler"]) :
    "${pair[0]}--${pair[1]}" => { topic = pair[0], account = pair[1] }
  }
  project = var.project_id
  topic   = google_pubsub_topic.topics[each.value.topic].name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${var.service_account_emails[each.value.account]}"
}

resource "google_pubsub_subscription_iam_member" "worker_subscriber" {
  project      = var.project_id
  subscription = google_pubsub_subscription.collector_jobs.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${var.service_account_emails["worker"]}"
}

# Delayed delivery for grant expiry / withdrawal.
resource "google_cloud_tasks_queue" "grant_expiry" {
  project  = var.project_id
  location = var.region
  name     = "${var.name_prefix}-grant-expiry"

  rate_limits {
    max_dispatches_per_second = 50
    max_concurrent_dispatches = 20
  }

  retry_config {
    max_attempts  = 10
    min_backoff   = "5s"
    max_backoff   = "300s"
    max_doublings = 5
  }
}
