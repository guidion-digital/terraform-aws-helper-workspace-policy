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
  description = "Allows read/write for application namepsaced secrets"
  value       = aws_iam_policy.secrets.arn
}

data "aws_iam_policy_document" "ssm_parameters" {
  statement {
    sid       = "allowreads"
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "ssm:DescribeParameters",
      "ssm:ListTagsForResource"
    ]
  }

  statement {
    sid    = "allowwrites"
    effect = "Allow"
    resources = [
      "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:managed-instance/applications/${var.application_name}/*",
      "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:patchbaseline/applications/${var.application_name}/*",
      "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:maintenancewindow/applications/${var.application_name}/*",
      "arn:aws:ecs:*:${data.aws_caller_identity.current.account_id}:task/applications/${var.application_name}/*",
      "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:opsmetadata/applications/${var.application_name}/*",
      "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:parameter/applications/${var.application_name}/*",
      "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:association/applications/${var.application_name}/*",
      "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:instance/applications/${var.application_name}/*",
      "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:opsitem/applications/${var.application_name}/*",
      "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:automation-execution/applications/${var.application_name}/*",
      "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:document/applications/${var.application_name}/*"
    ]
    actions = [
      "ssm:PutParameter",
      "ssm:LabelParameterVersion",
      "ssm:DeleteParameter",
      "ssm:UnlabelParameterVersion",
      "ssm:RemoveTagsFromResource",
      "ssm:GetParameterHistory",
      "ssm:AddTagsToResource",
      "ssm:ListTagsForResource",
      "ssm:GetParametersByPath",
      "ssm:GetParameters",
      "ssm:GetParameter",
      "ssm:DeleteParameters"
    ]
  }
}

resource "aws_iam_policy" "ssm_parameters" {
  name   = "${var.application_name}-parameters"
  path   = "/tfe/"
  policy = data.aws_iam_policy_document.ssm_parameters.json
}

output "ssm_parameters_policy_arn" {
  description = "Allows read/write for application namepsaced SSM parameters"
  value       = aws_iam_policy.ssm_parameters.arn
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
