variable "ec2_app" {
  description = "Values used when creating IAM resources for an EC2 application"

  type = object({
    targetgroup_arn : string,
    loadbalancers : list(string),
    loadbalancer_listener_arn : string,
  })
  
  default = null
}

# The policies need to be split up due to AWS's 6,144 character limit. This won't
# scale forever though, since they also have a policy number limit of 10 (adjustable
# to 20): https://repost.aws/knowledge-center/iam-increase-policy-size
data "aws_iam_policy_document" "ec2_0" {
  count = var.ec2_app != null ? 1 : 0

  statement {
    sid       = "ec20"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "sts:GetCallerIdentity",
      "ssm:GetParameter"
    ]
  }
}

data "aws_iam_policy_document" "ec2_1" {
  count = var.ec2_app != null ? 1 : 0

  statement {
    sid       = "ec20"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ec2:DescribeTransitGateways",
      "ec2:DescribeVpcs",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeVpcAttribute",
      "ec2:DescribeNetworkAcls",
      "ec2:DescribeRouteTables",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeTransitGatewayVpcAttachments",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeTags",
      "ec2:DescribeVolumes",
      "ec2:DescribeInstanceAttribute",
      "ec2:DescribeInstanceCreditSpecifications",
      "ec2:DisassociateRouteTable",
      "ec2:DeleteRoute",
      "ec2:ModifyInstanceAttribute",
      "ec2:TerminateInstances",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:DeleteTransitGatewayVpcAttachment",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:DeleteRouteTable",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DeleteSecurityGroup",
      "ec2:DeleteSubnet",
      "ec2:DeleteVpc",
      "ec2:CreateVpc",
      "ec2:CreateTags",
      "ec2:ModifyVpcAttribute",
      "ec2:CreateRouteTable",
      "ec2:CreateSubnet",
      "ec2:CreateSecurityGroup",
      "ec2:AssociateRouteTable",
      "ec2:CreateTransitGatewayVpcAttachment",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RunInstances",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:MonitorInstances",
      "ec2:CreateRoute"
    ]
  }
}

resource "aws_iam_policy" "ec2_app_policies" {
  for_each = var.ec2_app != null ? {
    "ec2-app0" = data.aws_iam_policy_document.ec2_0,
    "ec2-app1" = data.aws_iam_policy_document.ec2_1
  } : {}

  name   = "${var.application_name}-${each.key}"
  path   = "/tfe/"
  policy = one(each.value).json
}

output "ec2_type_policy_arns" {
  description = "Will have a value if the application type was 'ec2_app'"
  value       = [for this_policy in aws_iam_policy.ec2_app_policies : this_policy.arn]
}
