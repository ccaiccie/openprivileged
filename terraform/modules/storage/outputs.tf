output "recordings_bucket" {
  value = google_storage_bucket.recordings.name
}

output "audit_exports_bucket" {
  value = google_storage_bucket.audit_exports.name
}

output "logs_bucket" {
  value = google_storage_bucket.logs.name
}
