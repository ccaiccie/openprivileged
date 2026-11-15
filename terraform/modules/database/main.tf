resource "random_password" "db" {
  length  = 32
  special = false
}

resource "google_sql_database_instance" "main" {
  project             = var.project_id
  name                = "${var.name_prefix}-pg"
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = var.deletion_protection

  settings {
    tier              = var.sql_tier
    edition           = "ENTERPRISE"
    availability_type = var.sql_high_availability ? "REGIONAL" : "ZONAL"
    disk_type         = "PD_SSD"
    disk_size         = var.sql_disk_gb
    disk_autoresize   = true

    ip_configuration {
      ipv4_enabled    = false
      private_network = var.network_id
      ssl_mode        = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      start_time                     = "02:00"
      point_in_time_recovery_enabled = var.sql_pitr
      transaction_log_retention_days = 7

      backup_retention_settings {
        retained_backups = 14
        retention_unit   = "COUNT"
      }
    }

    maintenance_window {
      day          = 7
      hour         = 3
      update_track = "stable"
    }

    insights_config {
      query_insights_enabled = true
    }

    database_flags {
      name  = "log_min_duration_statement"
      value = "1000"
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }
  }
  # Ordering: caller sets depends_on = [module.network] so the private services
  # peering exists before this resource is created.
}

resource "google_sql_database" "app" {
  project  = var.project_id
  name     = "vaultgate"
  instance = google_sql_database_instance.main.name
}

resource "google_sql_user" "app" {
  project  = var.project_id
  name     = "vg_app"
  instance = google_sql_database_instance.main.name
  password = random_password.db.result
}

resource "google_secret_manager_secret" "db_password" {
  project   = var.project_id
  secret_id = "${var.name_prefix}-db-password"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = random_password.db.result
}

# ---------------------------------------------------------------- Memorystore
resource "google_redis_instance" "main" {
  project                 = var.project_id
  name                    = "${var.name_prefix}-redis"
  region                  = var.region
  tier                    = var.redis_ha ? "STANDARD_HA" : "BASIC"
  memory_size_gb          = var.redis_memory_gb
  redis_version           = "REDIS_7_0"
  authorized_network      = var.network_id
  connect_mode            = "PRIVATE_SERVICE_ACCESS"
  auth_enabled            = true
  transit_encryption_mode = "SERVER_AUTHENTICATION"
  # Ordering: caller sets depends_on = [module.network] so the private services
  # peering exists before this resource is created.
}

resource "google_secret_manager_secret" "redis_auth" {
  project   = var.project_id
  secret_id = "${var.name_prefix}-redis-auth"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "redis_auth" {
  secret      = google_secret_manager_secret.redis_auth.id
  secret_data = google_redis_instance.main.auth_string
}

resource "google_secret_manager_secret_iam_member" "readers" {
  for_each = {
    for pair in setproduct(["db_password", "redis_auth"], var.reader_accounts) :
    "${pair[0]}--${pair[1]}" => { secret = pair[0], account = pair[1] }
  }
  project   = var.project_id
  secret_id = each.value.secret == "db_password" ? google_secret_manager_secret.db_password.secret_id : google_secret_manager_secret.redis_auth.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.service_account_emails[each.value.account]}"
}
