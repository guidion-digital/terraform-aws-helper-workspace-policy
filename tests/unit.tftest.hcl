# Global variables
variables {
  application_name     = "megapp"
  application_role_arn = "arn:aws:iam::123456789011:role/application/omega-acc-megapp"
  project              = "omega"
  domain_account_role  = "arn:aws:iam::123456789012:role/workspaces/assumable-networking"
}

run "all_policies_returned" {
  module {
    source = "./examples/test_app"
  }

  command = plan

  variables {
    application_name     = var.application_name
    application_role_arn = var.application_role_arn
    project              = var.project
    domain_account_role  = var.domain_account_role

    cdn_app = {
      bucket_name = "foobar"
    }

    api_app = {
      event_arns          = ["arn:aws:events:*:123456789012:rule/foobar-*"],
      dynamodb_arns       = ["arn:aws:dynamodb:*:123456789012:table/foobar*"],
      sqs_arns            = ["arn:aws:sqs:*:123456789012:foobar*"]
      sns_arns            = ["arn:aws:sns:*:123456789012:foobar*"]
      firewall_ipset_arns = ["arn:aws:wafv2:*:123456789012:regional/ipset/foobar-regional-whitelist/*"],
      ruleset_arns        = ["arn:aws:wafv2:*:123456789012:regional/managedruleset/*/*"]
    }

    container_app = {
      targetgroup_arn                 = "arn:aws:elasticloadbalancing:eu-central-1:123456789012:targetgroup/foobar/*",
      loadbalancer_listener_arn       = "arn:aws:elasticloadbalancing:eu-central-1:123456789012:listener/net/foobar/*",
      ecs_cluster_arn                 = "arn:aws:ecs:eu-central-1:123456789012:cluster/foobar",
      ecs_service_arn                 = "arn:aws:ecs:eu-central-1:123456789012:service/*/foobar-service",
      ecs_event_capture_rule_arn      = "arn:aws:events:eu-central-1:123456789012:rule/ecs-event-capture-forwarded",
      ecs_event_capture_log_group_arn = "arn:aws:logs:eu-central-1:123456789012:log-group:/aws/events/ecs/containerinsights/foobar/performance",
      loadbalancers                   = ["arn:aws:elasticloadbalancing:eu-central-1:123456789012:loadbalancer/net/foobar/*"]
    }
  }

  assert {
    condition     = length(module.workspace_user_permissions.cdn_type_policy_arns) != 0
    error_message = "A CDN policy was not returned when we supplied a value for the var.cdn_app map"
  }

  assert {
    condition     = length(module.workspace_user_permissions.api_type_policy_arns) != 0
    error_message = "An API policy was not returned when we supplied a value for the var.api_app map"
  }

  assert {
    condition     = length(module.workspace_user_permissions.container_type_policy_arns) != 0
    error_message = "An API policy was not returned when we supplied a value for the var.container_app map"
  }

  assert {
    condition = alltrue([
      for action in [
        "events:DeleteRule",
        "events:DescribeRule",
        "events:ListTagsForResource",
        "events:ListTargetsByRule",
        "events:PutRule",
        "events:PutTargets",
        "events:RemoveTargets",
        "events:TagResource",
        "events:UntagResource",
        "logs:DeleteResourcePolicy",
        "logs:DescribeResourcePolicies",
        "logs:PutResourcePolicy",
        "logs:TagLogGroup",
        "logs:TagResource",
        "logs:UntagLogGroup",
        "logs:UntagResource",
        ] : contains(
        flatten([
          for statement in jsondecode(module.workspace_user_permissions.generated_container_policy_1).Statement : statement.Action
        ]),
        action,
      )
    ])
    error_message = "The generated container policy is missing ECS event-capture permissions."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(module.workspace_user_permissions.generated_container_policy_1).Statement : statement.Sid == "ecsEventCapture0" && statement.Resource != "*"
    ])
    error_message = "EventBridge ECS event-capture permissions must be scoped to the generated rule ARN."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(module.workspace_user_permissions.generated_container_policy_1).Statement : statement.Sid == "ecsEventCapture0" && statement.Resource == "arn:aws:events:eu-central-1:123456789012:rule/ecs-event-capture-forwarded"
    ])
    error_message = "EventBridge ECS event-capture permissions must use the forwarded rule ARN."
  }
}

run "cdn_policies_returned_only" {
  module {
    source = "./examples/test_app"
  }

  command = plan

  variables {
    application_name     = var.application_name
    application_role_arn = var.application_role_arn
    project              = var.project
    domain_account_role  = var.domain_account_role

    cdn_app = {
      bucket_name = "foobar"
    }
  }

  assert {
    condition     = length(module.workspace_user_permissions.cdn_type_policy_arns) != 0
    error_message = "A CDN policy was not returned when we supplied a value for the var.cdn_app map"
  }

  assert {
    condition     = length(module.workspace_user_permissions.api_type_policy_arns) == 0
    error_message = "An API policy was returned but we only supplied a value to var.cdn_app"
  }

  assert {
    condition     = length(module.workspace_user_permissions.container_type_policy_arns) == 0
    error_message = "A container policy was returned but we only supplied a value to var.cdn_app"
  }
}

run "api_policies_returned_only" {
  module {
    source = "./examples/test_app"
  }

  command = plan

  variables {
    application_name     = var.application_name
    application_role_arn = var.application_role_arn
    project              = var.project
    domain_account_role  = var.domain_account_role

    api_app = {
      event_arns          = ["arn:aws:events:*:123456789012:rule/foobar-*"],
      dynamodb_arns       = ["arn:aws:dynamodb:*:123456789012:table/foobar*"],
      sqs_arns            = ["arn:aws:sqs:*:123456789012:foobar*"]
      sns_arns            = ["arn:aws:sns:*:123456789012:foobar*"]
      firewall_ipset_arns = ["arn:aws:wafv2:*:123456789012:regional/ipset/foobar-regional-whitelist/*"],
      ruleset_arns        = ["arn:aws:wafv2:*:123456789012:regional/managedruleset/*/*"]
    }
  }

  assert {
    condition     = length(module.workspace_user_permissions.cdn_type_policy_arns) == 0
    error_message = "A CDN policy was returned but we only supplied a value to var.api_app"
  }

  assert {
    condition     = length(module.workspace_user_permissions.api_type_policy_arns) != 0
    error_message = "An API policy was not returned when we supplied a value for the var.api_app map"
  }

  assert {
    condition     = length(module.workspace_user_permissions.container_type_policy_arns) == 0
    error_message = "A container policy was returned but we only supplied a value to var.api_app"
  }
}

run "container_policies_returned_only" {
  module {
    source = "./examples/test_app"
  }

  command = plan

  variables {
    application_name     = var.application_name
    application_role_arn = var.application_role_arn
    project              = var.project
    domain_account_role  = var.domain_account_role

    container_app = {
      targetgroup_arn                 = "arn:aws:elasticloadbalancing:eu-central-1:123456789012:targetgroup/foobar/*",
      loadbalancer_listener_arn       = "arn:aws:elasticloadbalancing:eu-central-1:123456789012:listener/net/foobar/*",
      ecs_cluster_arn                 = "arn:aws:ecs:eu-central-1:123456789012:cluster/foobar",
      ecs_service_arn                 = "arn:aws:ecs:eu-central-1:123456789012:service/*/foobar-service"
      loadbalancers                   = ["arn:aws:elasticloadbalancing:eu-central-1:123456789012:loadbalancer/net/foobar/*"]
    }
  }

  assert {
    condition     = length(module.workspace_user_permissions.cdn_type_policy_arns) == 0
    error_message = "A CDN policy was returned but we only supplied a value to var.container_app"
  }

  assert {
    condition     = length(module.workspace_user_permissions.api_type_policy_arns) == 0
    error_message = "An API policy was returned but we only supplied a value to var.container_app"
  }

  assert {
    condition     = length(module.workspace_user_permissions.container_type_policy_arns) != 0
    error_message = "A container policy was not returned when we supplied a value for the var.container_app map"
  }
}
