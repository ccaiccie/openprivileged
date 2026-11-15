output "notification_channel_id" {
  value = google_monitoring_notification_channel.email.id
}

output "uptime_check_id" {
  value = google_monitoring_uptime_check_config.https.uptime_check_id
}
