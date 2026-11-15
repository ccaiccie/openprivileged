# Native `ssh` endpoint for technicians (`vg connect`). Cloud Run cannot terminate raw
# TCP, so the broker also runs on a small Compute Engine managed instance group fronted
# by a global external TCP proxy load balancer: client port 22 -> instance port 8022.
# PROXY protocol v1 preserves the client source IP for the audit log.
# The VM has no external IP; it reaches Artifact Registry/APIs through Cloud NAT.

data "google_compute_image" "cos" {
  family  = "cos-stable"
  project = "cos-cloud"
}

resource "google_compute_instance_template" "gw" {
  project      = var.project_id
  name_prefix  = "${var.name_prefix}-ssh-gw-"
  machine_type = var.machine_type
  region       = var.region
  tags         = ["vg-ssh-gw"]

  disk {
    source_image = data.google_compute_image.cos.self_link
    auto_delete  = true
    boot         = true
    disk_size_gb = 20
  }

  network_interface {
    subnetwork = var.subnet_id
    # no access_config: no external IP
  }

  service_account {
    email  = var.service_account_email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    enable-oslogin = "TRUE"
    startup-script = <<-EOT
      #!/bin/bash
      set -euo pipefail
      docker-credential-gcr configure-docker --registries=${var.registry_host}
      docker rm -f vg-broker || true
      docker run -d --name vg-broker --restart=always \
        -p 8022:8022 \
        -e VG_COMPONENT=broker-ssh \
        -e VG_PROXY_PROTOCOL=v1 \
        ${var.image}
    EOT
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_region_instance_group_manager" "gw" {
  project            = var.project_id
  name               = "${var.name_prefix}-ssh-gw"
  base_instance_name = "${var.name_prefix}-ssh-gw"
  region             = var.region
  target_size        = var.instance_count

  version {
    instance_template = google_compute_instance_template.gw.self_link
  }

  named_port {
    name = "ssh"
    port = 8022
  }

  update_policy {
    type                  = "PROACTIVE"
    minimal_action        = "REPLACE"
    max_surge_fixed       = 3
    max_unavailable_fixed = 0
  }
}

resource "google_compute_health_check" "tcp" {
  project             = var.project_id
  name                = "${var.name_prefix}-ssh-gw-hc"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  tcp_health_check {
    port = 8022
  }
}

resource "google_compute_backend_service" "gw" {
  project               = var.project_id
  name                  = "${var.name_prefix}-ssh-gw-backend"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "TCP"
  port_name             = "ssh"
  timeout_sec           = 3600
  health_checks         = [google_compute_health_check.tcp.id]

  backend {
    group           = google_compute_region_instance_group_manager.gw.instance_group
    balancing_mode  = "UTILIZATION"
    max_utilization = 0.8
  }
}

resource "google_compute_target_tcp_proxy" "gw" {
  project         = var.project_id
  name            = "${var.name_prefix}-ssh-gw-proxy"
  backend_service = google_compute_backend_service.gw.id
  proxy_header    = "PROXY_V1"
}

resource "google_compute_global_address" "gw" {
  project = var.project_id
  name    = "${var.name_prefix}-ssh-gw-ip"
}

resource "google_compute_global_forwarding_rule" "gw" {
  project               = var.project_id
  name                  = "${var.name_prefix}-ssh-gw"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_global_address.gw.id
  port_range            = "22"
  target                = google_compute_target_tcp_proxy.gw.id
}

# Allow Google front ends / health checkers to reach port 8022 (overrides the VPC default deny).
resource "google_compute_firewall" "allow_lb" {
  project       = var.project_id
  name          = "${var.name_prefix}-ssh-gw-allow-lb"
  network       = var.network_name
  direction     = "INGRESS"
  priority      = 900
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["vg-ssh-gw"]

  allow {
    protocol = "tcp"
    ports    = ["8022"]
  }
}

resource "google_artifact_registry_repository_iam_member" "gw_pull" {
  project    = var.project_id
  location   = var.region
  repository = var.registry_repository_id
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${var.service_account_email}"
}
