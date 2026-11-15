output "ssh_gateway_ip" {
  description = "Create a DNS A record (e.g. ssh.example.com) pointing here."
  value       = google_compute_global_address.gw.address
}
