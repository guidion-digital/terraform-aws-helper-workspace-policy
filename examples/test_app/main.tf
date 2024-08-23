module "workspace_user_permissions" {
  source = "../../"

  application_name     = "test_application"
  application_role_arn = "arn:aws:iam::123456789012:role/example"
  project              = "test"
  domain_account_role  = arn:aws:iam::123456789012:role/example

  cdn_app       = null
  api_app       = null
  container_app = null
}
