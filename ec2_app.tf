variable "ec2_app" {
  description = "Values used when creating IAM resources for a ec2 application"

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
data "aws_iam_policy_document" "ec20" {
  count = var.ec2_app != null ? 1 : 0

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
      "ec2:DescribeTransitGateways"
    ]
  }
}

resource "aws_iam_policy" "ec2_app_policies" {
  for_each = var.ec2_app != null ? {
    "ec2-app0" = data.aws_iam_policy_document.ec20,
  } : {}

  name   = "${var.application_name}-${each.key}"
  path   = "/tfe/"
  policy = one(each.value).json
}

output "ec2_type_policy_arns" {
  description = "Will have a value if the application type was 'ec2_app'"
  value       = [for this_policy in aws_iam_policy.ec2_app_policies : this_policy.arn]
}

output "generated_ec2_policy_1" {
  description = "The first ec2 policy string that was generated. Used for testing"
  value       = one([for this_app in data.aws_iam_policy_document.ec20 : this_app.json])
}
