locals {
  runtime_accounts = toset(["api", "worker", "broker", "scheduler", "ssh-gateway"])

  # Which runtime accounts may read each platform secret.
  secret_readers = ["api", "worker", "broker"]
  secret_accessors = {
    for pair in setproduct(var.secret_names, local.secret_readers) :
    "${pair[0]}--${pair[1]}" => { secret = pair[0], account = pair[1] }
  }

  base_roles = ["roles/logging.logWriter", "roles/monitoring.metricWriter", "roles/cloudtrace.agent"]
  base_role_bindings = {
    for pair in setproduct(local.runtime_accounts, local.base_roles) :
    "${pair[0]}--${pair[1]}" => { account = pair[0], role = pair[1] }
  }
}

# One service account per runtime component (no use of the default compute SA).
resource "google_service_account" "runtime" {
  for_each     = local.runtime_accounts
  project      = var.project_id
  account_id   = "${var.name_prefix}-${each.key}"
  display_name = "VaultGate ${each.key} (${var.env})"
}

resource "google_project_iam_member" "base" {
  for_each = local.base_role_bindings
  project  = var.project_id
  role     = each.value.role
  member   = "serviceAccount:${google_service_account.runtime[each.value.account].email}"
}

# api and worker create Cloud Tasks that call the worker as itself.
resource "google_service_account_iam_member" "act_as_worker" {
  for_each           = toset(["api", "worker"])
  service_account_id = google_service_account.runtime["worker"].name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.runtime[each.key].email}"
}

resource "google_project_iam_member" "tasks_enqueuer" {
  for_each = toset(["api", "worker"])
  project  = var.project_id
  role     = "roles/cloudtasks.enqueuer"
  member   = "serviceAccount:${google_service_account.runtime[each.key].email}"
}

# api signs short-lived replay URLs with its own identity (signBlob on itself).
resource "google_service_account_iam_member" "api_sign_self" {
  service_account_id = google_service_account.runtime["api"].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.runtime["api"].email}"
}

# ---------------------------------------------------------------- KMS
resource "google_kms_key_ring" "main" {
  project  = var.project_id
  name     = "${var.name_prefix}-ring"
  location = var.region
}

resource "google_kms_crypto_key" "recordings" {
  name            = "recordings"
  key_ring        = google_kms_key_ring.main.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = "7776000s" # 90 days

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.kms_protection_level
  }
}

# Key-encryption key that wraps per-tenant data keys (envelope encryption).
resource "google_kms_crypto_key" "tenant_kek" {
  name            = "tenant-kek"
  key_ring        = google_kms_key_ring.main.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = "7776000s"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.kms_protection_level
  }
}

resource "google_kms_crypto_key_iam_member" "tenant_kek_users" {
  for_each      = toset(["api", "worker", "broker"])
  crypto_key_id = google_kms_crypto_key.tenant_kek.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.runtime[each.key].email}"
}

# Cloud Storage service agent must use the recordings key (CMEK).
data "google_storage_project_service_account" "gcs" {
  project = var.project_id
}

resource "google_kms_crypto_key_iam_member" "gcs_agent" {
  crypto_key_id = google_kms_crypto_key.recordings.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
}

# ---------------------------------------------------------------- Secret Manager
# Containers only. Secret values are added out-of-band (never in Terraform state),
# except database/redis secrets which the database module creates.
resource "google_secret_manager_secret" "platform" {
  for_each  = var.secret_names
  project   = var.project_id
  secret_id = "${var.name_prefix}-${each.key}"

  replication {
    auto {}
  }
}

# A placeholder first version lets Cloud Run resolve "latest" on the first deploy.
# Add the real value as a NEW version (gcloud secrets versions add); Terraform ignores
# the placeholder's data, so real values never enter Terraform state.
resource "google_secret_manager_secret_version" "placeholder" {
  for_each    = google_secret_manager_secret.platform
  secret      = each.value.id
  secret_data = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_data]
  }
}

resource "google_secret_manager_secret_iam_member" "accessors" {
  for_each  = local.secret_accessors
  project   = var.project_id
  secret_id = google_secret_manager_secret.platform[each.value.secret].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime[each.value.account].email}"
}
