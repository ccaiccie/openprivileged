output "lb_ip" {
  description = "Create a DNS A record for var.domain pointing here."
  value       = module.compute.lb_ip
}

output "egress_ip" {
  description = "Static egress IP customers can allowlist (direct-mode devices)."
  value       = module.network.egress_ip
}

output "ssh_gateway_ip" {
  description = "Native SSH endpoint IP (null when disabled)."
  value       = try(module.ssh_gateway[0].ssh_gateway_ip, null)
}

output "artifact_registry_url" {
  value = module.registry.repository_url
}

output "cloud_run_urls" {
  value = module.compute.service_urls
}

output "github_workload_identity_provider" {
  description = "Set as the GitHub Actions variable GCP_WIF_PROVIDER."
  value       = module.cicd.workload_identity_provider
}

output "github_deployer_service_account" {
  description = "Set as the GitHub Actions variable GCP_DEPLOYER_SA."
  value       = module.cicd.deployer_service_account
}

output "recordings_bucket" {
  value = module.storage.recordings_bucket
}
