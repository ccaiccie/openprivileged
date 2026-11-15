output "service_account_emails" {
  description = "Map of runtime component name to service account email."
  value       = { for k, v in google_service_account.runtime : k => v.email }
}

output "kms_key_ids" {
  value = {
    recordings = google_kms_crypto_key.recordings.id
    tenant_kek = google_kms_crypto_key.tenant_kek.id
  }
}

output "secret_ids" {
  description = "Map of secret name to short Secret Manager secret_id."
  value       = { for k, v in google_secret_manager_secret.platform : k => v.secret_id }
}

output "gcs_agent_key_binding" {
  description = "Use in depends_on for CMEK buckets."
  value       = google_kms_crypto_key_iam_member.gcs_agent.id
}
