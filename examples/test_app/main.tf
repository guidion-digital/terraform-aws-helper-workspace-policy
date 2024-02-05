variable "application_name" {}
variable "application_role_arn" {}
variable "project" {}
variable "domain_account_role" {}
variable "cdn_app" { default = null }
variable "api_app" { default = null }
variable "container_app" { default = null }

module "workspace_user_permissions" {
  source = "../../"

  application_name     = var.application_name
  application_role_arn = var.application_role_arn
  project              = var.project
  domain_account_role  = var.domain_account_role

  cdn_app       = var.cdn_app
  api_app       = var.api_app
  container_app = var.container_app
}
