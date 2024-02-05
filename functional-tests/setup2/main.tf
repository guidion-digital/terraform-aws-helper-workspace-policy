variable "policy" {}
variable "common_policy" {}

resource "aws_iam_role" "workspace_user" {
  name = "test-user"
  path = "/application/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Sid       = ""
        Principal = { Service = "lambda.amazonaws.com" }
      },
    ]
  })

  tags = {
    source = "tfe"
  }
}

resource "aws_iam_role_policy_attachment" "cdn" {
  role       = aws_iam_role.workspace_user.name
  policy_arn = var.policy
}

resource "aws_iam_role_policy_attachment" "common" {
  role       = aws_iam_role.workspace_user.name
  policy_arn = var.common_policy
}

output "role_arn" {
  value = aws_iam_role.workspace_user.arn
}
