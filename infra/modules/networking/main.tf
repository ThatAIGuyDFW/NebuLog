# VNet with subnets for ingest, API, and database tiers.

terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm" }
  }
}

resource "azurerm_virtual_network" "sentinel" {
  name                = "sentinel-${var.environment}-vnet"
  resource_group_name = var.resource_group_name
  location            = var.location
  address_space       = ["10.10.0.0/16"]
  tags                = var.tags
}

resource "azurerm_subnet" "ingest" {
  name                 = "ingest-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.sentinel.name
  address_prefixes     = ["10.10.1.0/24"]
}

resource "azurerm_subnet" "api" {
  name                 = "api-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.sentinel.name
  address_prefixes     = ["10.10.2.0/24"]
}

# Delegated subnet for PostgreSQL Flexible Server
resource "azurerm_subnet" "db" {
  name                 = "db-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.sentinel.name
  address_prefixes     = ["10.10.3.0/24"]

  delegation {
    name = "pg-delegation"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# NSG for ingest tier: allow UDP 514, TCP 6514 (TLS syslog), TCP 8001 (agent API)
resource "azurerm_network_security_group" "ingest" {
  name                = "sentinel-${var.environment}-ingest-nsg"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  security_rule {
    name                       = "allow-syslog-udp"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "514"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-syslog-tls"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "6514"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-agent-api"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8001"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "ingest" {
  subnet_id                 = azurerm_subnet.ingest.id
  network_security_group_id = azurerm_network_security_group.ingest.id
}
