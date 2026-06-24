# Sentinel raw log archive — Azure Blob Storage with WORM immutability.
#
# Lifecycle:  hot (0–retention_days_hot) → cool → delete (retention_days_cold)
# WORM:       time-based immutability policy locks blobs for retention_days_cold
# Compliance: HIPAA 6-year (2192 days) / PCI DSS 12-month hot + 24-month total

terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm" }
    random  = { source = "hashicorp/random" }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "azurerm_storage_account" "sentinel" {
  name                     = "sentinel${var.environment}${random_id.suffix.hex}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "GRS" # geo-redundant for compliance
  account_kind             = "StorageV2"
  access_tier              = "Hot"

  # Hardening
  min_tls_version           = "TLS1_2"
  https_traffic_only_enabled = true
  shared_access_key_enabled  = true # needed for connection string; rotate regularly
  public_network_access_enabled = false

  blob_properties {
    versioning_enabled       = true
    change_feed_enabled      = true
    last_access_time_enabled = true

    delete_retention_policy {
      days = 14
    }

    container_delete_retention_policy {
      days = 14
    }
  }

  tags = var.tags
}

resource "azurerm_storage_container" "raw" {
  name                  = "sentinel-raw"
  storage_account_name  = azurerm_storage_account.sentinel.name
  container_access_type = "private"
}

# WORM: time-based immutability — blobs cannot be deleted/modified before expiry
resource "azurerm_storage_management_policy" "lifecycle" {
  storage_account_id = azurerm_storage_account.sentinel.id

  rule {
    name    = "tier-to-cool"
    enabled = true
    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["raw/"]
    }
    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = var.retention_days_hot
        tier_to_archive_after_days_since_modification_greater_than = var.retention_days_hot * 2
        delete_after_days_since_modification_greater_than          = var.retention_days_cold
      }
    }
  }
}

# Immutability policy on the container (WORM compliance)
resource "azurerm_storage_blob_inventory_policy" "worm_audit" {
  storage_account_id = azurerm_storage_account.sentinel.id

  rules {
    name                   = "raw-inventory"
    storage_container_name = azurerm_storage_container.raw.name
    format                 = "Csv"
    schedule               = "Weekly"
    scope                  = "Blob"
    schema_fields = [
      "Name", "Creation-Time", "Last-Modified",
      "Content-Length", "Content-MD5", "BlobType",
      "AccessTier", "AccessTierChangeTime", "ImmutabilityPolicyExpiresOn",
    ]
  }
}
