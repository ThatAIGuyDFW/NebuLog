output "fqdn" {
  value = azurerm_postgresql_flexible_server.sentinel.fqdn
}

output "connection_string" {
  value     = "postgresql+asyncpg://${azurerm_postgresql_flexible_server.sentinel.administrator_login}:${local.admin_password}@${azurerm_postgresql_flexible_server.sentinel.fqdn}/sentinel?ssl=require"
  sensitive = true
}

output "server_id" {
  value = azurerm_postgresql_flexible_server.sentinel.id
}
