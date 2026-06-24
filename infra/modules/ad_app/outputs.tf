output "client_id" {
  value = azuread_application.sentinel.client_id
}

output "tenant_id" {
  value = data.azuread_client_config.current.tenant_id
}

output "client_secret" {
  value     = azuread_application_password.backend.value
  sensitive = true
}

output "service_principal_id" {
  value = azuread_service_principal.sentinel.id
}
