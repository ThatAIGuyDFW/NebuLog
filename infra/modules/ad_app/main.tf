# Azure AD / Entra ID application registration for Sentinel.
#
# Creates:
#   - An app registration with three app roles (Admin, Analyst, ReadOnly)
#   - A client secret for the correlation engine / ingest service (client-credentials)
#   - PKCE is used by the SPA — no secret needed for the UI

terraform {
  required_providers {
    azuread = { source = "hashicorp/azuread" }
  }
}

data "azuread_client_config" "current" {}

resource "azuread_application" "sentinel" {
  display_name     = "Sentinel SIEM (${var.environment})"
  sign_in_audience = "AzureADMyOrg"

  api {
    requested_access_token_version = 2

    oauth2_permission_scope {
      admin_consent_description  = "Allows the app to read Sentinel events and alerts"
      admin_consent_display_name = "Sentinel.ReadOnly"
      enabled                    = true
      id                         = "00000000-0000-0000-0000-000000000001"
      type                       = "User"
      user_consent_description   = "Read your Sentinel events and alerts"
      user_consent_display_name  = "Read Sentinel"
      value                      = "Sentinel.ReadOnly"
    }

    oauth2_permission_scope {
      admin_consent_description  = "Allows the app to read and update Sentinel alerts"
      admin_consent_display_name = "Sentinel.Analyst"
      enabled                    = true
      id                         = "00000000-0000-0000-0000-000000000002"
      type                       = "User"
      user_consent_description   = "Read and update Sentinel alerts"
      user_consent_display_name  = "Sentinel Analyst"
      value                      = "Sentinel.Analyst"
    }

    oauth2_permission_scope {
      admin_consent_description  = "Full administrative access to Sentinel"
      admin_consent_display_name = "Sentinel.Admin"
      enabled                    = true
      id                         = "00000000-0000-0000-0000-000000000003"
      type                       = "Admin"
      value                      = "Sentinel.Admin"
    }
  }

  app_role {
    allowed_member_types = ["User", "Application"]
    description          = "Read-only access to events and alerts"
    display_name         = "Sentinel ReadOnly"
    enabled              = true
    id                   = "10000000-0000-0000-0000-000000000001"
    value                = "Sentinel.ReadOnly"
  }

  app_role {
    allowed_member_types = ["User", "Application"]
    description          = "Analyst access: read events, acknowledge and close alerts"
    display_name         = "Sentinel Analyst"
    enabled              = true
    id                   = "10000000-0000-0000-0000-000000000002"
    value                = "Sentinel.Analyst"
  }

  app_role {
    allowed_member_types = ["User", "Application"]
    description          = "Full administrative access to Sentinel"
    display_name         = "Sentinel Admin"
    enabled              = true
    id                   = "10000000-0000-0000-0000-000000000003"
    value                = "Sentinel.Admin"
  }

  # SPA redirect for PKCE flow (React UI)
  single_page_application {
    redirect_uris = [
      "http://localhost:3000/",
      "https://sentinel-${var.environment}.example.com/",
    ]
  }

  # Backend/service app redirect for client-credentials
  web {
    redirect_uris = ["https://sentinel-${var.environment}.example.com/auth/callback"]
    implicit_grant {
      access_token_issuance_enabled = false
      id_token_issuance_enabled     = false
    }
  }
}

resource "azuread_service_principal" "sentinel" {
  client_id                    = azuread_application.sentinel.client_id
  app_role_assignment_required = false
}

# Client secret for backend services (rotate every 12 months via Key Vault)
resource "azuread_application_password" "backend" {
  application_id = azuread_application.sentinel.id
  display_name   = "backend-service-secret"
  end_date       = timeadd(timestamp(), "8760h") # 1 year
  lifecycle {
    ignore_changes = [end_date]
  }
}
