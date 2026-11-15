output "repository_id" {
  value = google_artifact_registry_repository.images.repository_id
}

output "repository_url" {
  description = "Image path prefix, e.g. europe-west1-docker.pkg.dev/PROJECT/vg-prod-images"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
}
