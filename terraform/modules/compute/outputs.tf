output "lb_ip" {
  description = "Create a DNS A record for var.domain pointing here."
  value       = google_compute_global_address.lb.address
}

output "service_names" {
  value = { for k, v in google_cloud_run_v2_service.svc : k => v.name }
}

output "service_urls" {
  value = { for k, v in google_cloud_run_v2_service.svc : k => v.uri }
}

output "scheduler_job_name" {
  value = google_cloud_run_v2_job.scheduler.name
}

output "security_policy_id" {
  value = google_compute_security_policy.edge.id
}
