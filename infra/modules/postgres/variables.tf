variable "resource_group_name" { type = string }
variable "location"            { type = string }
variable "environment"         { type = string }
variable "tags"                { type = map(string); default = {} }
variable "admin_password"      { type = string; sensitive = true; default = "" }
variable "sku_name"            { type = string; default = "GP_Standard_D2s_v3" }
variable "storage_mb"          { type = number; default = 65536 }
variable "subnet_id"           { type = string }
