variable "s3_app" {
  description = "Values used when creating IAM resources for an s3 application"

  type = object({
    bucket_name : string
  })

  default = null
}

# The policies need to be split up due to AWS's 6,144 character limit. This won't
# scale forever though, since they also have a policy number limit of 10 (adjustable
# to 20): https://repost.aws/knowledge-center/iam-increase-policy-size
data "aws_iam_policy_document" "s3_0" {
  count = var.s3_app != null ? 1 : 0

  statement {
    sid       = "s30"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "sts:GetCallerIdentity",
    ]
  }
}

data "aws_iam_policy_document" "s3_1" {
  count = var.s3_app != null ? 1 : 0

  statement {
    sid       = "s30"
    effect    = "Allow"
    resources = [
      "arn:aws:s3:::${var.application_name}-${data.aws_caller_identity.current.account_id}",
      "arn:aws:s3:::${var.application_name}-${data.aws_caller_identity.current.account_id}/*"
    ]

    actions = [      
      "s3:*"
    ]
  }
}

resource "aws_iam_policy" "s3_app_policies" {
  for_each = var.s3_app != null ? {
    "s3-app0" = data.aws_iam_policy_document.s3_0,
    "s3-app1" = data.aws_iam_policy_document.s3_1
  } : {}

  name   = "${var.application_name}-${each.key}"
  path   = "/tfe/"
  policy = one(each.value).json
}

output "s3_type_policy_arns" {
  description = "Will have a value if the application type was 's3_app'"
  value       = [for this_policy in aws_iam_policy.s3_app_policies : this_policy.arn]
}
