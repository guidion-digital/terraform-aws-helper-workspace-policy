data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

variable "application_name" {
  description = "Name of the application. Will be used for naming resources"
}

variable "application_role_arn" {
  description = "ARN of the IAM role used by the application"
}

variable "domain_account_role" {
  description = "Role which can be assumed in another account in order to update DNS records"
}

variable "project" {
  description = "Name of project (team)"
}

data "aws_iam_policy_document" "secrets" {
  statement {
    sid       = "allowreads"
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "secretsmanager:GetRandomPassword",
      "secretsmanager:ListSecrets"
    ]
  }

  statement {
    sid    = "allowwrites"
    effect = "Allow"
    resources = [
      "arn:aws:secretsmanager:*:*:secret:/${var.application_name}/*",
      "arn:aws:secretsmanager:*:*:secret:/applications/${var.application_name}/*",
      "arn:aws:secretsmanager:*:*:secret:applications/${var.application_name}/*"
    ]
    actions = [
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:UntagResource",
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:PutSecretValue",
      "secretsmanager:CreateSecret",
      "secretsmanager:UpdateSecretVersionStage",
      "secretsmanager:DeleteSecret",
      "secretsmanager:ListSecretVersionIds",
      "secretsmanager:TagResource",
      "secretsmanager:UpdateSecret",
      "secretsmanager:PutResourcePolicy"
    ]
  }
}

resource "aws_iam_policy" "secrets" {
  name   = "${var.application_name}-secrets"
  path   = "/tfe/"
  policy = data.aws_iam_policy_document.secrets.json
}

output "secrets_policy_arn" {
  description = "Will have a value if secrets are enabled (by default, they are)"
  value       = aws_iam_policy.secrets.arn
}

data "aws_iam_policy_document" "common" {
  statement {
    sid       = "allowreads"
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "ec2:DescribeAvailabilityZones"
    ]
  }

  statement {
    sid       = "authorizerpermissions"
    effect    = "Allow"
    resources = ["arn:aws:lambda:*:*:function:common-*"]
    actions   = ["lambda:AddPermission"]
  }
}

resource "aws_iam_policy" "common" {
  name   = "${var.application_name}-common"
  path   = "/tfe/"
  policy = data.aws_iam_policy_document.common.json
}

output "common_policy_arn" {
  description = "Permissions that all applications need"
  value       = aws_iam_policy.common.arn
}
