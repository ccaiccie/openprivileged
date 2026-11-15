provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

locals {
  env         = "prod"
  name_prefix = "vg-prod"

  # Cloud Run env vars (non-secret).
  app_env = {
    VG_ENV               = local.env
    VG_GCP_PROJECT       = var.project_id
    VG_PUBLIC_URL        = "https://${var.domain}"
    VG_DB_HOST           = module.database.sql_private_ip
    VG_DB_NAME           = module.database.db_name
    VG_DB_USER           = module.database.db_user
    VG_REDIS_HOST        = module.database.redis_host
    VG_REDIS_PORT        = tostring(module.database.redis_port)
    VG_RECORDINGS_BUCKET = module.storage.recordings_bucket
    VG_AUDIT_BUCKET      = module.storage.audit_exports_bucket
    VG_KMS_TENANT_KEK    = module.security.kms_key_ids["tenant_kek"]
    VG_TASKS_QUEUE       = module.messaging.tasks_queue_name
  }

  # ENV var name -> Secret Manager secret_id (latest version).
  app_secrets = {
    VG_DB_PASSWORD           = module.database.db_password_secret_id
    VG_REDIS_AUTH            = module.database.redis_auth_secret_id
    VG_OIDC_CLIENT_SECRET    = module.security.secret_ids["oidc-client-secret"]
    VG_SESSION_SIGNING_KEY   = module.security.secret_ids["session-signing-key"]
    VG_SLACK_SIGNING_SECRET  = module.security.secret_ids["slack-signing-secret"]
    VG_NETBOX_SYNC_MASTER_TK = module.security.secret_ids["netbox-sync-master-token"]
  }
}

resource "google_project_service" "apis" {
  for_each = toset([
    "artifactregistry.googleapis.com",
    "cloudkms.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "cloudscheduler.googleapis.com",
    "cloudtasks.googleapis.com",
    "compute.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "pubsub.googleapis.com",
    "redis.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "servicenetworking.googleapis.com",
    "sqladmin.googleapis.com",
    "storage.googleapis.com",
    "sts.googleapis.com",
  ])
  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

module "network" {
  source      = "../../modules/network"
  project_id  = var.project_id
  region      = var.region
  name_prefix = local.name_prefix
  subnet_cidr = var.subnet_cidr
  depends_on  = [google_project_service.apis]
}

module "security" {
  source               = "../../modules/security"
  project_id           = var.project_id
  region               = var.region
  env                  = local.env
  name_prefix          = local.name_prefix
  kms_protection_level = var.kms_protection_level
  depends_on           = [google_project_service.apis]
}

module "registry" {
  source      = "../../modules/registry"
  project_id  = var.project_id
  region      = var.region
  name_prefix = local.name_prefix
  depends_on  = [google_project_service.apis]
}

module "storage" {
  source                    = "../../modules/storage"
  project_id                = var.project_id
  name_prefix               = local.name_prefix
  location                  = var.region
  recordings_kms_key_id     = module.security.kms_key_ids["recordings"]
  service_account_emails    = module.security.service_account_emails
  recordings_retention_days = var.recordings_retention_days
  audit_retention_days      = var.audit_retention_days
  log_retention_days        = 30
  lock_retention            = var.lock_retention
  force_destroy             = false
  depends_on                = [module.security]
}

module "messaging" {
  source                 = "../../modules/messaging"
  project_id             = var.project_id
  region                 = var.region
  name_prefix            = local.name_prefix
  service_account_emails = module.security.service_account_emails
  depends_on             = [google_project_service.apis]
}

module "database" {
  source                 = "../../modules/database"
  project_id             = var.project_id
  region                 = var.region
  name_prefix            = local.name_prefix
  network_id             = module.network.network_id
  sql_tier               = var.sql_tier
  sql_disk_gb            = var.sql_disk_gb
  sql_high_availability  = true
  sql_pitr               = true
  deletion_protection    = true
  redis_ha               = true
  redis_memory_gb        = var.redis_memory_gb
  service_account_emails = module.security.service_account_emails
  depends_on             = [module.network, module.security]
}

module "compute" {
  source                 = "../../modules/compute"
  project_id             = var.project_id
  region                 = var.region
  name_prefix            = local.name_prefix
  service_account_emails = module.security.service_account_emails
  network_name           = module.network.network_name
  subnet_name            = module.network.subnet_name
  image_registry         = module.registry.repository_url
  image_tag              = var.image_tag
  env_vars               = local.app_env
  secret_env             = local.app_secrets
  domain                 = var.domain
  deletion_protection    = true
  min_instances          = var.min_instances
  max_instances          = var.max_instances
  depends_on = [module.security, module.database, module.network, module.messaging, module.storage]
}

module "ssh_gateway" {
  count                  = var.enable_ssh_gateway ? 1 : 0
  source                 = "../../modules/ssh_gateway"
  project_id             = var.project_id
  region                 = var.region
  name_prefix            = local.name_prefix
  network_name           = module.network.network_name
  subnet_id              = module.network.subnet_id
  service_account_email  = module.security.service_account_emails["ssh-gateway"]
  image                  = "${module.registry.repository_url}/broker:${var.image_tag}"
  registry_host          = "${var.region}-docker.pkg.dev"
  registry_repository_id = module.registry.repository_id
  depends_on             = [module.network, module.security]
}

module "observability" {
  source      = "../../modules/observability"
  project_id  = var.project_id
  name_prefix = local.name_prefix
  domain      = var.domain
  alert_email = var.alert_email
  logs_bucket = module.storage.logs_bucket
  depends_on  = [google_project_service.apis, module.compute]
}

module "cicd" {
  source                   = "../../modules/cicd"
  project_id               = var.project_id
  region                   = var.region
  name_prefix              = local.name_prefix
  github_repository        = var.github_repository
  allowed_ref_prefix       = var.allowed_ref_prefix
  registry_repository_id   = module.registry.repository_id
  runtime_service_accounts = module.security.service_account_emails
  depends_on               = [google_project_service.apis]
}
