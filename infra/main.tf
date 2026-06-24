terraform {
  required_version = ">= 1.7"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.110"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.52"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
  backend "azurerm" {
    resource_group_name  = "sentinel-tfstate-rg"
    storage_account_name = "sentineltfstate"
    container_name       = "tfstate"
    key                  = "sentinel.tfstate"
  }
}

provider "azurerm" {
  features {}
}

provider "azuread" {}

# ── Resource group ─────────────────────────────────────────────────────────────
resource "azurerm_resource_group" "sentinel" {
  name     = "sentinel-${var.environment}-rg"
  location = var.location
  tags     = local.common_tags
}

locals {
  common_tags = {
    Project     = "sentinel"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ── Modules ────────────────────────────────────────────────────────────────────
module "storage" {
  source              = "./modules/storage"
  resource_group_name = azurerm_resource_group.sentinel.name
  location            = var.location
  environment         = var.environment
  tags                = local.common_tags
  retention_days_hot  = var.retention_days_hot
  retention_days_cold = var.retention_days_cold
}

module "postgres" {
  source              = "./modules/postgres"
  resource_group_name = azurerm_resource_group.sentinel.name
  location            = var.location
  environment         = var.environment
  tags                = local.common_tags
  admin_password      = var.postgres_admin_password
  sku_name            = var.postgres_sku
  storage_mb          = var.postgres_storage_mb
  subnet_id           = module.networking.db_subnet_id
}

module "networking" {
  source              = "./modules/networking"
  resource_group_name = azurerm_resource_group.sentinel.name
  location            = var.location
  environment         = var.environment
  tags                = local.common_tags
}

module "ad_app" {
  source      = "./modules/ad_app"
  environment = var.environment
}

# ── Outputs ────────────────────────────────────────────────────────────────────
output "storage_account_name" {
  value = module.storage.storage_account_name
}

output "storage_connection_string" {
  value     = module.storage.connection_string
  sensitive = true
}

output "postgres_fqdn" {
  value = module.postgres.fqdn
}

output "postgres_connection_string" {
  value     = module.postgres.connection_string
  sensitive = true
}

output "azure_tenant_id" {
  value = module.ad_app.tenant_id
}

output "azure_client_id" {
  value = module.ad_app.client_id
}

output "vnet_id" {
  value = module.networking.vnet_id
}
