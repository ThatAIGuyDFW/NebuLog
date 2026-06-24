# Azure Database for PostgreSQL Flexible Server with pgvector extension.
# Deployed into a delegated subnet for VNet integration.

terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm" }
    random  = { source = "hashicorp/random" }
  }
}

resource "random_password" "db_password" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

locals {
  admin_password = var.admin_password != "" ? var.admin_password : random_password.db_password.result
  db_name        = "sentinel"
  admin_user     = "sentinel_admin"
}

resource "azurerm_private_dns_zone" "postgres" {
  name                = "sentinel-${var.environment}.private.postgres.database.azure.com"
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_postgresql_flexible_server" "sentinel" {
  name                          = "sentinel-${var.environment}-pg"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  version                       = "16"
  delegated_subnet_id           = var.subnet_id
  private_dns_zone_id           = azurerm_private_dns_zone.postgres.id
  administrator_login           = local.admin_user
  administrator_password        = local.admin_password
  sku_name                      = var.sku_name
  storage_mb                    = var.storage_mb
  backup_retention_days         = 35   # max; supports HIPAA 6-yr with export strategy
  geo_redundant_backup_enabled  = true
  public_network_access_enabled = false

  high_availability {
    mode = var.environment == "prod" ? "ZoneRedundant" : "Disabled"
  }

  maintenance_window {
    day_of_week  = 0 # Sunday
    start_hour   = 3
    start_minute = 0
  }

  tags = var.tags

  lifecycle {
    ignore_changes = [zone, high_availability[0].standby_availability_zone]
  }
}

resource "azurerm_postgresql_flexible_server_database" "sentinel" {
  name      = local.db_name
  server_id = azurerm_postgresql_flexible_server.sentinel.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

# Enable pgvector and uuid-ossp extensions
resource "azurerm_postgresql_flexible_server_configuration" "pgvector" {
  name      = "azure.extensions"
  server_id = azurerm_postgresql_flexible_server.sentinel.id
  value     = "PGVECTOR,UUID-OSSP,PG_PARTMAN"
}

# Tuning for SIEM workloads (append-heavy, analytical queries)
resource "azurerm_postgresql_flexible_server_configuration" "shared_buffers" {
  name      = "shared_buffers"
  server_id = azurerm_postgresql_flexible_server.sentinel.id
  value     = "512MB"
}

resource "azurerm_postgresql_flexible_server_configuration" "work_mem" {
  name      = "work_mem"
  server_id = azurerm_postgresql_flexible_server.sentinel.id
  value     = "16MB"
}

resource "azurerm_postgresql_flexible_server_configuration" "wal_level" {
  name      = "wal_level"
  server_id = azurerm_postgresql_flexible_server.sentinel.id
  value     = "logical"
}
