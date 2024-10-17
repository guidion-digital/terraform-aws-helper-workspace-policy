variable "container_app" {
  description = "Values used when creating IAM resources for a container (ECS) application"

  type = object({
    targetgroup_arn : string,
    loadbalancers : list(string),
    loadbalancer_listener_arn : string,
    ecs_cluster_arn : string,
    ecs_service_arn : string
  })

  default = null
}

# The policies need to be split up due to AWS's 6,144 character limit. This won't
# scale forever though, since they also have a policy number limit of 10 (adjustable
# to 20): https://repost.aws/knowledge-center/iam-increase-policy-size
data "aws_iam_policy_document" "container0" {
  count = var.container_app != null ? 1 : 0

  dynamic "statement" {
    for_each = var.domain_account_role != null ? { 1 = 1 } : {}
    content {
      sid       = "sts0"
      effect    = "Allow"
      resources = ["${var.domain_account_role}"]
      actions   = ["sts:AssumeRole"]
    }
  }

  statement {
    sid       = "ec20"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "sts:GetCallerIdentity",
      "secretsmanager:TagResource",
      "secretsmanager:ListSecrets",
      "route53:ListTagsForResource",
      "route53:ListResourceRecordSets",
      "route53:ListHostedZones",
      "route53:GetHostedZone",
      "route53:GetChange",
      "route53:ChangeResourceRecordSets",
      "logs:DeleteLogGroup",
      "logs:CreateLogGroup",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetGroupAttributes",
      "elasticloadbalancing:DescribeTags",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeListeners",
      "ecs:RegisterTaskDefinition",
      "ecs:DescribeTaskDefinition",
      "ecs:DeregisterTaskDefinition",
      "ecs:CreateCluster",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:ModifyVpcAttribute",
      "ec2:DisassociateRouteTable",
      "ec2:DescribeVpcs",
      "ec2:DescribeVpcClassicLinkDnsSupport",
      "ec2:DescribeVpcClassicLink",
      "ec2:DescribeVpcAttribute",
      "ec2:DescribeTransitGatewayVpcAttachments",
      "ec2:DescribeTransitGateways",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeRouteTables",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeNetworkAcls",
      "ec2:DescribeAvailabilityZones",
      "ec2:DeleteVpc",
      "ec2:DeleteTransitGatewayVpcAttachment",
      "ec2:DeleteSubnet",
      "ec2:DeleteSecurityGroup",
      "ec2:DeleteRouteTable",
      "ec2:DeleteRoute",
      "ec2:CreateVpc",
      "ec2:CreateTransitGatewayVpcAttachment",
      "ec2:CreateTags",
      "ec2:CreateTags",
      "ec2:CreateSubnet",
      "ec2:CreateSecurityGroup",
      "ec2:CreateRouteTable",
      "ec2:CreateRoute",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:AssociateRouteTable",
      "cloudformation:CreateResource",
      "cloudformation:*",
    ]
  }

  statement {
    sid       = "tg0"
    effect    = "Allow"
    resources = ["${var.container_app.targetgroup_arn}/*"]

    actions = [
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:DeleteTargetGroup",
      "elasticloadbalancing:CreateTargetGroup",
    ]
  }
}

data "aws_iam_policy_document" "container1" {
  count = var.container_app != null ? 1 : 0

  statement {
    sid       = "lb0"
    effect    = "Allow"
    resources = var.container_app.loadbalancers
    actions = [
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTags",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DeleteTargetGroup",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:CreateTargetGroup",
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:CreateListener",
    ]
  }

  statement {
    sid       = "lblistener0"
    effect    = "Allow"
    resources = ["${var.container_app.loadbalancer_listener_arn}/*"]
    actions   = ["elasticloadbalancing:DeleteListener"]
  }

  statement {
    sid       = "cluster0"
    effect    = "Allow"
    resources = ["${var.container_app.ecs_cluster_arn}"]

    actions = [
      "ecs:UntagResource",
      "ecs:TagResource",
      "ecs:ListTagsForResource",
      "ecs:DescribeClusters",
      "ecs:DeleteCluster",
    ]
  }
}

data "aws_iam_policy_document" "container2" {
  count = var.container_app != null ? 1 : 0

  statement {
    sid       = "service0"
    effect    = "Allow"
    resources = ["${var.container_app.ecs_service_arn}"]
    actions = [
      "ecs:UpdateService",
      "ecs:UntagResource",
      "ecs:TagResource",
      "ecs:ListTagsForResource"
      "ecs:DescribeServices",
      "ecs:DeleteService",
      "ecs:CreateService",
    ]
  }

  statement {
    sid    = "secrets0"
    effect = "Allow"
    resources = [
      "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:/${var.application_name}/*",
      "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:/${var.application_name}/*/*"
    ]
    actions = [
      "secretsmanager:UpdateSecret",
      "secretsmanager:TagResource",
      "secretsmanager:PutSecretValue",
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:CreateSecret",
    ]
  }

  statement {
    sid       = "secrets1"
    effect    = "Allow"
    resources = ["arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:/github/access_credentials-*"]
    actions   = [
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:DescribeSecret",
    ]
  }
}

resource "aws_iam_policy" "container_app_policies" {
  for_each = var.container_app != null ? {
    "container-app0" = data.aws_iam_policy_document.container0,
    "container-app1" = data.aws_iam_policy_document.container1,
    "container-app2" = data.aws_iam_policy_document.container2
  } : {}

  name   = "${var.application_name}-${each.key}"
  path   = "/tfe/"
  policy = one(each.value).json
}

output "container_type_policy_arns" {
  description = "Will have a value if the application type was 'container_app'"
  value       = [for this_policy in aws_iam_policy.container_app_policies : this_policy.arn]
}

output "generated_container_policy_1" {
  description = "The first container policy string that was generated. Used for testing"
  value       = one([for this_app in data.aws_iam_policy_document.container0 : this_app.json])
}

