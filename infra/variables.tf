variable "environment" {
  description = "Deployment environment: dev | staging | prod"
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging, or prod"
  }
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus2"
}

variable "postgres_admin_password" {
  description = "PostgreSQL administrator password (store in Key Vault / CI secret)"
  type        = string
  sensitive   = true
}

variable "postgres_sku" {
  description = "Azure Database for PostgreSQL Flexible Server SKU"
  type        = string
  default     = "GP_Standard_D2s_v3"
}

variable "postgres_storage_mb" {
  description = "PostgreSQL storage in MB"
  type        = number
  default     = 65536 # 64 GB
}

variable "retention_days_hot" {
  description = "Days before raw logs are moved from hot to cool tier"
  type        = number
  default     = 365 # PCI DSS: 12 months hot
}

variable "retention_days_cold" {
  description = "Days before raw logs are deleted (HIPAA: 6 years = 2192 days)"
  type        = number
  default     = 2192
}
