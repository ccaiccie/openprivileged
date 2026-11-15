# Session recordings: CMEK, versioned, retention policy (lockable in prod).
resource "google_storage_bucket" "recordings" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.name_prefix}-recordings"
  location                    = var.location
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = var.force_destroy

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = var.recordings_kms_key_id
  }

  retention_policy {
    retention_period = var.recordings_retention_days * 86400
    is_locked        = var.lock_retention
  }

  lifecycle_rule {
    condition {
      age = var.recordings_retention_days + 1
    }
    action {
      type = "Delete"
    }
  }

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }

  # Ordering: the caller sets depends_on = [module.security] so the GCS service
  # agent already holds encrypter/decrypter on the CMEK key.
}

resource "google_storage_bucket" "audit_exports" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.name_prefix}-audit-exports"
  location                    = var.location
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = var.force_destroy

  versioning {
    enabled = true
  }

  retention_policy {
    retention_period = var.audit_retention_days * 86400
    is_locked        = var.lock_retention
  }
}

resource "google_storage_bucket" "logs" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.name_prefix}-logs"
  location                    = var.location
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = var.force_destroy

  lifecycle_rule {
    condition {
      age = var.log_retention_days
    }
    action {
      type = "Delete"
    }
  }
}

# Least-privilege access per component.
resource "google_storage_bucket_iam_member" "broker_write_recordings" {
  bucket = google_storage_bucket.recordings.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${var.service_account_emails["broker"]}"
}

resource "google_storage_bucket_iam_member" "api_read_recordings" {
  bucket = google_storage_bucket.recordings.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${var.service_account_emails["api"]}"
}

resource "google_storage_bucket_iam_member" "worker_audit_exports" {
  bucket = google_storage_bucket.audit_exports.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${var.service_account_emails["worker"]}"
}

resource "google_storage_bucket_iam_member" "api_audit_exports_read" {
  bucket = google_storage_bucket.audit_exports.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${var.service_account_emails["api"]}"
}
