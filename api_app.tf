variable "api_app" {
  description = "Values used when creating IAM resources for a API application"

  type = object({
    dynamodb_arns       = list(string),
    sqs_arns            = list(string),
    sns_arns            = list(string),
    event_arns          = list(string),
    firewall_ipset_arns = list(string),
    ruleset_arns        = list(string)
  })

  default = null
}

# The policies need to be split up due to AWS's 6,144 character limit. This won't
# scale forever though, since they also have a policy number limit of 10 (adjustable
# to 20): https://repost.aws/knowledge-center/iam-increase-policy-size
data "aws_iam_policy_document" "api0" {
  count = var.api_app != null ? 1 : 0

  statement {
    sid       = "dynamodb0"
    effect    = "Allow"
    resources = var.api_app.dynamodb_arns
    actions   = ["dynamodb:*"]
  }

  statement {
    sid       = "sns0"
    effect    = "Allow"
    resources = var.api_app.sns_arns
    actions   = ["sns:*"]
  }

  statement {
    sid       = "waf0"
    effect    = "Allow"
    resources = var.api_app.firewall_ipset_arns
    actions   = ["wafv2:*"]
  }

  statement {
    sid       = "waf1"
    effect    = "Allow"
    resources = var.api_app.ruleset_arns
    actions = [
      "wafv2:ListTagsForResource",
      "wafv2:GetWebACL",
      "wafv2:DeleteWebACL",
      "wafv2:CreateWebACL",
      "wafv2:AssociateWebACL",
      "wafv2:TagResource"
    ]
  }

  statement {
    sid       = "waf2"
    effect    = "Allow"
    resources = ["arn:aws:wafv2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:regional/webacl/*/*"]
    actions   = ["wafv2:GetWebACLForResource"]
  }

  # FIXME
  statement {
    sid       = "sqs0"
    effect    = "Allow"
    resources = var.api_app.sqs_arns
    actions   = ["sqs:*"]
  }

  statement {
    sid       = "ec20"
    effect    = "Allow"
    resources = ["*"]
    actions   = ["ec2:DescribeTransitGateways"]
  }

  statement {
    sid    = "tgwread0"
    effect = "Allow"
    resources = [
      "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:transit-gateway-policy-table/*",
      "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:transit-gateway-multicast-domain/*"
    ]
    actions = [
      "ec2:GetTransitGatewayPolicyTableEntries",
      "ec2:GetTransitGatewayPolicyTableAssociations",
      "ec2:GetTransitGatewayMulticastDomainAssociations",
    ]
  }

  statement {
    sid       = "tgwread1"
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "route53:ListHostedZonesByName",
      "route53:ListHostedZones",
      "route53:GetChange",
      "route53:CreateHostedZone",
      "ec2:GetTransitGatewayRouteTablePropagations",
      "ec2:GetTransitGatewayRouteTableAssociations",
      "ec2:GetTransitGatewayPrefixListReferences",
      "ec2:GetTransitGatewayAttachmentPropagations",
      "ec2:DescribeTransitGateways",
      "ec2:DescribeTransitGatewayVpcAttachments",
      "ec2:DescribeTransitGatewayRouteTables",
      "ec2:DescribeTransitGatewayRouteTableAnnouncements",
      "ec2:DescribeTransitGatewayPolicyTables",
      "ec2:DescribeTransitGatewayPeeringAttachments",
      "ec2:DescribeTransitGatewayMulticastDomains",
      "ec2:DescribeTransitGatewayConnects",
      "ec2:DescribeTransitGatewayConnectPeers",
      "ec2:DescribeTransitGatewayAttachments",
      "acm:DescribeCertificate",
    ]
  }

  # FIXME
  statement {
    sid       = "ec22"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ec2:*"
    ]
  }

  # FIXME: Particularly the last cloudformation one
  statement {
    sid       = "ec21"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "sts:GetCallerIdentity",
      "route53:ListHostedZones",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTags",
      "elasticloadbalancing:DescribeTargetGroupAttributes",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeListeners",
      "ecs:DeregisterTaskDefinition",
      "cloudformation:CreateResource",
      "cloudformation:*"
    ]
  }

  statement {
    sid       = "sts0"
    effect    = "Allow"
    resources = ["${var.domain_account_role}"]
    actions   = ["sts:AssumeRole"]
  }

  statement {
    sid       = "logs0"
    effect    = "Allow"
    resources = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.application_name}-*"]
    actions = [
      "logs:DescribeSubscriptionFilters",
      "logs:PutSubscriptionFilter",
      "logs:DeleteSubscriptionFilter",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DeleteLogGroup",
      "logs:ListTagsLogGroup"
    ]
  }

  statement {
    sid       = "logs1"
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "logs:DescribeLogGroups"
    ]
  }

  statement {
    sid       = "serviceroles"
    effect    = "Allow"
    resources = ["${var.application_role_arn}"]
    actions = [
      "iam:CreateServiceLinkedRole",
      "iam:DeleteServiceLinkedRole",
    ]
  }
}

data "aws_iam_policy_document" "api1" {
  count = var.api_app != null ? 1 : 0

  # For the DynamoDB AutoScaling Target
  statement {
    sid    = "serviceroles1"
    effect = "Allow"
    # FIXME: We need to scope this down
    resources = ["*"]
    actions = [
      "iam:CreateServiceLinkedRole",
      "iam:DeleteServiceLinkedRole",
    ]
  }

  statement {
    sid    = "appscalingread0"
    effect = "Allow"
    resources = [
      "arn:aws:application-autoscaling:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:scalable-target/*"
    ]
    actions = [
      "application-autoscaling:DescribeScalableTargets",
      "application-autoscaling:DescribeScalingActivities",
      "application-autoscaling:DescribeScalingPolicies",
      "application-autoscaling:DescribeScheduledActions"
    ]
  }

  statement {
    sid    = "appscalingwrite0"
    effect = "Allow"
    # FIXME: We need to scope this down
    resources = [
      "arn:aws:application-autoscaling:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:scalable-target/*"
    ]
    actions = [
      "application-autoscaling:RegisterScalableTarget",
      "application-autoscaling:DeleteScheduledAction",
      "application-autoscaling:PutScalingPolicy",
      "application-autoscaling:ListTagsForResource",
      "application-autoscaling:UntagResource",
      "application-autoscaling:DeleteScalingPolicy",
      "application-autoscaling:TagResource",
      "application-autoscaling:PutScheduledAction",
      "application-autoscaling:DeregisterScalableTarget"
    ]
  }
}

data "aws_iam_policy_document" "api2" {
  count = var.api_app != null ? 1 : 0

  statement {
    sid       = "kms0"
    effect    = "Allow"
    resources = ["arn:aws:kms:*:${data.aws_caller_identity.current.account_id}:key/*"]
    actions = [
      "kms:ListRetirableGrants",
      "kms:ListResourceTags",
      "kms:ListKeys",
      "kms:ListKeyPolicies",
      "kms:ListGrants",
      "kms:ListAliases",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
      "kms:Decrypt",
      "kms:CreateGrant",
    ]
  }

  statement {
    sid       = "route530"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "route53:ListHostedZonesByName",
      "route53:ListHostedZones",
      "route53:GetChange",
      "route53:CreateHostedZone",
      "acm:DescribeCertificate",
    ]
  }

  statement {
    sid       = "secrets0"
    effect    = "Allow"
    resources = ["arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:api-keys/${var.application_name}/*"]
    actions = [
      "secretsmanager:PutSecretValue",
      "secretsmanager:PutResourcePolicy",
      "secretsmanager:GetSecretValue",
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:DescribeSecret",
      "secretsmanager:DeleteSecret",
      "secretsmanager:CreateSecret",
      "secretsmanager:TagResource",
      "secretsmanager:UntagResource"
    ]
  }

  statement {
    sid       = "lambda0"
    effect    = "Allow"
    resources = ["arn:aws:lambda:*:${data.aws_caller_identity.current.account_id}:function:${var.application_name}-*"]

    actions = [
      "lambda:DeleteFunctionConcurrency",
      "lambda:UpdateFunctionConfiguration",
      "lambda:UpdateFunctionCode",
      "lambda:RemovePermission",
      "lambda:ListVersionsByFunction",
      "lambda:GetPolicy",
      "lambda:GetFunctionCodeSigningConfig",
      "lambda:GetFunction",
      "lambda:DeleteFunction",
      "lambda:CreateFunction",
      "lambda:AddPermission",
      "lambda:PutFunctionConcurrency",
      "lambda:TagResource"
    ]
  }

  # FIXME: events:*
  statement {
    sid       = "lambda1"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "lambda:CreateEventSourceMapping",
      "lambda:DeleteEventSourceMapping"
    ]
  }

  statement {
    sid       = "events0"
    effect    = "Allow"
    resources = var.api_app.event_arns

    actions = ["events:*"]
  }

  statement {
    sid       = "lambda23"
    effect    = "Allow"
    resources = ["*"]

    actions = ["lambda:GetEventSourceMapping"]
  }

  # FIXME
  statement {
    sid       = "cloudfront0"
    effect    = "Allow"
    resources = ["*"]
    actions   = ["cloudfront:*"]
  }

  # FIXME
  statement {
    sid       = "acm0"
    effect    = "Allow"
    resources = ["*"]
    actions   = ["acm:*"]
  }

  statement {
    sid    = "apigw0"
    effect = "Allow"

    resources = [
      "arn:aws:apigateway:*::/usageplans/*",
      # FIXME: There's no way to know the API ID ahead of time, so we give access
      #        to all API IDs :(
      "arn:aws:apigateway:*::/restapis/*/stages/*",
      "arn:aws:apigateway:*::/restapis/*/stages/*/sdks/*",
      "arn:aws:apigateway:*::/restapis/*/resources/*/methods/*/responses/*",
      "arn:aws:apigateway:*::/restapis/*/resources/*/methods/*",
      "arn:aws:apigateway:*::/domainnames/*",
      "arn:aws:apigateway:*::/*",
    ]

    actions = ["apigateway:*"]
  }
}

data "aws_iam_policy_document" "api3" {
  count = var.api_app != null ? 1 : 0

  statement {
    sid     = "route0"
    effect  = "Allow"
    actions = ["geo:*"]

    resources = [
      "arn:aws:geo:*:${data.aws_caller_identity.current.account_id}:route-calculator/${var.application_name}*",
      "arn:aws:geo:*:${data.aws_caller_identity.current.account_id}:geofence-collection/${var.application_name}*",
      "arn:aws:geo:*:${data.aws_caller_identity.current.account_id}:api-key/${var.application_name}*",
      "arn:aws:geo:*:${data.aws_caller_identity.current.account_id}:map/${var.application_name}*",
      "arn:aws:geo:*:${data.aws_caller_identity.current.account_id}:tracker/${var.application_name}*",
      "arn:aws:geo:*:${data.aws_caller_identity.current.account_id}:place-index/${var.application_name}*"
    ]
  }
}

resource "aws_iam_policy" "api_app_policies" {
  for_each = var.api_app != null ? {
    "api-app0" = data.aws_iam_policy_document.api0,
    "api-app1" = data.aws_iam_policy_document.api1,
    "api-app2" = data.aws_iam_policy_document.api2,
    "api-app3" = data.aws_iam_policy_document.api3
  } : {}

  name   = "${var.application_name}-${each.key}"
  path   = "/tfe/"
  policy = one(each.value).json
}

output "api_type_policy_arns" {
  description = "Will have a value if the application type was 'api_app'"
  value       = [for this_policy in aws_iam_policy.api_app_policies : this_policy.arn]
}

output "generated_api_policy_1" {
  description = "First policy string that was generated. Used for testing"
  value       = one([for this_app in data.aws_iam_policy_document.api0 : this_app.json])
}
