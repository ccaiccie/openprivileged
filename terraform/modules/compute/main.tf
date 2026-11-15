locals {
  # Before the first CI build exists, use a public placeholder image so `apply` succeeds.
  use_bootstrap = var.image_tag == "bootstrap"

  services = {
    api = {
      ingress     = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
      public      = true
      min         = var.min_instances["api"]
      max         = var.max_instances["api"]
      cpu         = "1"
      memory      = "1Gi"
      cpu_idle    = true
      timeout     = "300s"
      concurrency = 80
    }
    broker = {
      ingress     = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
      public      = true
      min         = var.min_instances["broker"]
      max         = var.max_instances["broker"]
      cpu         = "1"
      memory      = "1Gi"
      cpu_idle    = false # long-lived sessions need CPU between requests
      timeout     = "3600s"
      concurrency = 20
    }
    worker = {
      ingress     = "INGRESS_TRAFFIC_INTERNAL_ONLY"
      public      = false
      min         = var.min_instances["worker"]
      max         = var.max_instances["worker"]
      cpu         = "1"
      memory      = "1Gi"
      cpu_idle    = false # Arq loop runs outside requests
      timeout     = "3600s"
      concurrency = 10
    }
  }
}

# ---------------------------------------------------------------- Cloud Run services
resource "google_cloud_run_v2_service" "svc" {
  for_each            = local.services
  project             = var.project_id
  name                = "${var.name_prefix}-${each.key}"
  location            = var.region
  ingress             = each.value.ingress
  deletion_protection = var.deletion_protection

  template {
    service_account                  = var.service_account_emails[each.key]
    timeout                          = each.value.timeout
    max_instance_request_concurrency = each.value.concurrency

    scaling {
      min_instance_count = each.value.min
      max_instance_count = each.value.max
    }

    vpc_access {
      egress = "ALL_TRAFFIC" # so traffic leaves via Cloud NAT with the static IP

      network_interfaces {
        network    = var.network_name
        subnetwork = var.subnet_name
      }
    }

    containers {
      image = local.use_bootstrap ? var.bootstrap_image : "${var.image_registry}/${each.key}:${var.image_tag}"

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = each.value.cpu
          memory = each.value.memory
        }
        cpu_idle = each.value.cpu_idle
      }

      env {
        name  = "VG_COMPONENT"
        value = each.key
      }

      dynamic "env" {
        for_each = var.env_vars
        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = var.secret_env
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }

      startup_probe {
        http_get {
          path = "/healthz"
        }
        initial_delay_seconds = 5
        period_seconds        = 5
        failure_threshold     = 12
      }

      liveness_probe {
        http_get {
          path = "/healthz"
        }
        period_seconds = 30
      }
    }
  }

  lifecycle {
    # CI/CD (gcloud run deploy) owns the image and revision metadata after bootstrap.
    ignore_changes = [
      template[0].containers[0].image,
      client,
      client_version,
    ]
  }
}

# api and broker are reachable only through the load balancer (ingress setting);
# IAM invoker is opened because users authenticate in the application (OIDC).
resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  for_each = { for k, v in local.services : k => v if v.public }
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.svc[each.key].name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# worker is invoked only by Cloud Tasks / Scheduler running as the worker SA.
resource "google_cloud_run_v2_service_iam_member" "worker_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.svc["worker"].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${var.service_account_emails["worker"]}"
}

# ---------------------------------------------------------------- Scheduler job
resource "google_cloud_run_v2_job" "scheduler" {
  project             = var.project_id
  name                = "${var.name_prefix}-scheduler"
  location            = var.region
  deletion_protection = var.deletion_protection

  template {
    template {
      service_account = var.service_account_emails["scheduler"]
      max_retries     = 1
      timeout         = "300s"

      vpc_access {
        egress = "ALL_TRAFFIC"

        network_interfaces {
          network    = var.network_name
          subnetwork = var.subnet_name
        }
      }

      containers {
        image   = local.use_bootstrap ? var.bootstrap_image : "${var.image_registry}/worker:${var.image_tag}"
        command = ["vg-scheduler"]
        args    = ["run-once"]

        dynamic "env" {
          for_each = var.env_vars
          content {
            name  = env.key
            value = env.value
          }
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].template[0].containers[0].image,
      client,
      client_version,
    ]
  }
}

resource "google_cloud_run_v2_job_iam_member" "scheduler_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.scheduler.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${var.service_account_emails["scheduler"]}"
}

resource "google_cloud_scheduler_job" "expiry_sweep" {
  project          = var.project_id
  region           = var.region
  name             = "${var.name_prefix}-expiry-sweep"
  description      = "Enforce grant expiry and withdraw credentials."
  schedule         = var.scheduler_cron
  time_zone        = "Etc/UTC"
  attempt_deadline = "60s"

  retry_config {
    retry_count = 1
  }

  http_target {
    http_method = "POST"
    uri         = "https://run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/jobs/${google_cloud_run_v2_job.scheduler.name}:run"

    oauth_token {
      service_account_email = var.service_account_emails["scheduler"]
    }
  }
}

# ---------------------------------------------------------------- Cloud Armor
resource "google_compute_security_policy" "edge" {
  project     = var.project_id
  name        = "${var.name_prefix}-edge"
  description = "WAF and rate limiting for the VaultGate edge"

  rule {
    action   = "deny(403)"
    priority = 900
    match {
      expr {
        expression = "!request.path.startsWith('/ws/') && evaluatePreconfiguredWaf('sqli-v33-stable')"
      }
    }
    description = "SQL injection (excluding terminal websockets)"
  }

  rule {
    action   = "deny(403)"
    priority = 910
    match {
      expr {
        expression = "!request.path.startsWith('/ws/') && evaluatePreconfiguredWaf('xss-v33-stable')"
      }
    }
    description = "Cross-site scripting (excluding terminal websockets)"
  }

  rule {
    action   = "throttle"
    priority = 1000
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = var.rate_limit_per_minute
        interval_sec = 60
      }
    }
    description = "Per-IP rate limit"
  }

  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow"
  }
}

# ---------------------------------------------------------------- HTTPS load balancer
resource "google_compute_global_address" "lb" {
  project = var.project_id
  name    = "${var.name_prefix}-lb-ip"
}

resource "google_compute_region_network_endpoint_group" "neg" {
  for_each              = { for k, v in local.services : k => v if v.public }
  project               = var.project_id
  name                  = "${var.name_prefix}-${each.key}-neg"
  region                = var.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = google_cloud_run_v2_service.svc[each.key].name
  }
}

resource "google_compute_backend_service" "svc" {
  for_each              = google_compute_region_network_endpoint_group.neg
  project               = var.project_id
  name                  = "${var.name_prefix}-${each.key}-backend"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTPS"
  timeout_sec           = each.key == "broker" ? 3600 : 30
  security_policy       = google_compute_security_policy.edge.id

  backend {
    group = each.value.id
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "https" {
  project         = var.project_id
  name            = "${var.name_prefix}-urlmap"
  default_service = google_compute_backend_service.svc["api"].id

  host_rule {
    hosts        = ["*"]
    path_matcher = "main"
  }

  path_matcher {
    name            = "main"
    default_service = google_compute_backend_service.svc["api"].id

    path_rule {
      paths   = ["/ws/*"]
      service = google_compute_backend_service.svc["broker"].id
    }
  }
}

resource "google_compute_managed_ssl_certificate" "cert" {
  project = var.project_id
  name    = "${var.name_prefix}-cert"

  managed {
    domains = [var.domain]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_target_https_proxy" "https" {
  project          = var.project_id
  name             = "${var.name_prefix}-https-proxy"
  url_map          = google_compute_url_map.https.id
  ssl_certificates = [google_compute_managed_ssl_certificate.cert.id]
}

resource "google_compute_global_forwarding_rule" "https" {
  project               = var.project_id
  name                  = "${var.name_prefix}-https"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_global_address.lb.id
  port_range            = "443"
  target                = google_compute_target_https_proxy.https.id
}

# HTTP -> HTTPS redirect
resource "google_compute_url_map" "redirect" {
  project = var.project_id
  name    = "${var.name_prefix}-redirect"

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_http_proxy" "redirect" {
  project = var.project_id
  name    = "${var.name_prefix}-http-proxy"
  url_map = google_compute_url_map.redirect.id
}

resource "google_compute_global_forwarding_rule" "http" {
  project               = var.project_id
  name                  = "${var.name_prefix}-http"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_global_address.lb.id
  port_range            = "80"
  target                = google_compute_target_http_proxy.redirect.id
}
