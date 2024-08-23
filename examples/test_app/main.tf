module "workspace_user_permissions" {
  source = "../../"

  application_name     = "test_application"
  project              = "test"
  application_role_arn = "arn:aws:iam::000000000000:role/example"
  domain_account_role  = "arn:aws:iam::000000000000:role/example"
                         
  cdn_app       = null
  api_app       = null
  container_app = null
}
