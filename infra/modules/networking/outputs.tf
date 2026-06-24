output "vnet_id"       { value = azurerm_virtual_network.sentinel.id }
output "ingest_subnet_id" { value = azurerm_subnet.ingest.id }
output "api_subnet_id"    { value = azurerm_subnet.api.id }
output "db_subnet_id"     { value = azurerm_subnet.db.id }
