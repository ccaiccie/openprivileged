output "network_id" {
  value = google_compute_network.vpc.id
}

output "network_name" {
  value = google_compute_network.vpc.name
}

output "subnet_id" {
  value = google_compute_subnetwork.private.id
}

output "subnet_name" {
  value = google_compute_subnetwork.private.name
}

output "egress_ip" {
  description = "Static egress IP to give to customers for allowlisting."
  value       = google_compute_address.egress.address
}

output "private_services_connection" {
  description = "Use in depends_on for Cloud SQL / Memorystore."
  value       = google_service_networking_connection.private_services.id
}
