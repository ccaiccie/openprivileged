output "sql_instance_name" {
  value = google_sql_database_instance.main.name
}

output "sql_private_ip" {
  value = google_sql_database_instance.main.private_ip_address
}

output "db_name" {
  value = google_sql_database.app.name
}

output "db_user" {
  value = google_sql_user.app.name
}

output "db_password_secret_id" {
  value = google_secret_manager_secret.db_password.secret_id
}

output "redis_host" {
  value = google_redis_instance.main.host
}

output "redis_port" {
  value = google_redis_instance.main.port
}

output "redis_auth_secret_id" {
  value = google_secret_manager_secret.redis_auth.secret_id
}
