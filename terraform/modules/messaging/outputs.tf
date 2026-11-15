output "topic_ids" {
  value = { for k, v in google_pubsub_topic.topics : k => v.id }
}

output "tasks_queue_name" {
  value = google_cloud_tasks_queue.grant_expiry.name
}
