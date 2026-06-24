output "storage_account_name" {
  value = azurerm_storage_account.sentinel.name
}

output "connection_string" {
  value     = azurerm_storage_account.sentinel.primary_connection_string
  sensitive = true
}

output "container_name" {
  value = azurerm_storage_container.raw.name
}

output "storage_account_id" {
  value = azurerm_storage_account.sentinel.id
}
