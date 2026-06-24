variable "resource_group_name" { type = string }
variable "location"            { type = string }
variable "environment"         { type = string }
variable "tags"                { type = map(string); default = {} }
variable "retention_days_hot"  { type = number; default = 365 }
variable "retention_days_cold" { type = number; default = 2192 }
