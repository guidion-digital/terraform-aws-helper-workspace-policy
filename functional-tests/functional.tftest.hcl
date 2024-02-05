run "setup_fixtures" {
  command = apply

  module {
    source = "./tests/setup"
  }
}

run "cdn_app_permissions_created" {
  command = apply

  module {
    source = "./"
  }

  variables {
    application_name     = "app-x"
    application_role_arn = "arn:aws:iam::123456789012:role/application/app-x"
    project              = "omega"
    domain_account_role  = "arn:aws:iam::123456789011:role/workspaces/assumable-networking"

    cdn_app = {
      bucket_name = run.setup_fixtures.bucket_name
    }
  }

  assert {
    error_message = "CDN policy was not named correctly"
    condition     = aws_iam_policy.cdn_app[0].name == "${var.application_name}-cdn-app"
    }
}

run "setup_more_fixtures" {
  command = apply

  module {
    source = "./tests/setup2"
  }

  variables {
    policy = run.cdn_app_permissions_created.cdn_type_policy_arn
    common_policy = run.cdn_app_permissions_created.common_policy_arn
  }
}


provider "aws" {
  alias = "workspace_role"

  assume_role {
    role_arn = run.setup_more_fixtures.role_arn
  }
}

run "cdn_permissions_correct" {
  command = apply

  module {
    source = ""
  }

  providers = {
    aws = aws.workspace_role
  }

  assert {
    error = "Could not list CDN bucket"
    condition = .
  }
}
