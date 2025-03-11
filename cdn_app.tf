variable "cdn_app" {
  description = "Values used when creating IAM resources for a CDN application"

  type = object({
    bucket_name : string
  })

  default = null
}

# The policies need to be split up due to AWS's 6,144 character limit. This won't
# scale forever though, since they also have a policy number limit of 10 (adjustable
# to 20): https://repost.aws/knowledge-center/iam-increase-policy-size
data "aws_iam_policy_document" "cdn0" {
  count = var.cdn_app != null ? 1 : 0

  statement {
    sid       = "allresources"
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "cloudfront:CreatePublicKey",
      "cloudfront:ListOriginAccessControls",
      "acm:PutAccountConfiguration",
      "cloudfront:ListFieldLevelEncryptionConfigs",
      "cloudfront:CreateSavingsPlan",
      "cloudfront:GetMonitoringSubscription",
      "cloudfront:ListKeyGroups",
      "cloudfront:ListSavingsPlans",
      "acm:RequestCertificate",
      "acm:GetCertificate",
      "cloudfront:GetKeyGroup",
      "cloudfront:ListContinuousDeploymentPolicies",
      "cloudfront:GetKeyGroupConfig",
      "cloudfront:ListUsages",
      "cloudfront:ListResponseHeadersPolicies",
      "cloudfront:ListDistributionsByCachePolicyId",
      "cloudfront:UpdatePublicKey",
      "cloudfront:GetPublicKey",
      "cloudfront:UpdateSavingsPlan",
      "acm:ListTagsForCertificate",
      "cloudfront:CreateKeyGroup",
      "acm:DescribeCertificate",
      "cloudfront:ListDistributionsByWebACLId",
      "cloudfront:DeleteMonitoringSubscription",
      "cloudfront:UpdateKeyGroup",
      "cloudfront:ListCloudFrontOriginAccessIdentities",
      "cloudfront:ListFunctions",
      "cloudfront:GetPublicKeyConfig",
      "cloudfront:CreateFieldLevelEncryptionProfile",
      "cloudfront:UpdateFieldLevelEncryptionConfig",
      "cloudfront:ListOriginRequestPolicies",
      "cloudfront:DeletePublicKey",
      "cloudfront:GetSavingsPlan",
      "cloudfront:ListDistributionsByRealtimeLogConfig",
      "cloudfront:ListRateCards",
      "acm:ListCertificates",
      "acm:GetAccountConfiguration",
      "acm:ExportCertificate",
      "cloudfront:CreateOriginAccessControl",
      "cloudfront:DeleteKeyGroup",
      "cloudfront:CreateMonitoringSubscription",
      "cloudfront:ListDistributionsByLambdaFunction",
      "cloudfront:ListCachePolicies",
      "iam:ListRoles",
      "cloudfront:ListDistributionsByKeyGroup",
      "cloudfront:ListPublicKeys",
      "cloudfront:ListRealtimeLogConfigs",
      "cloudfront:ListFieldLevelEncryptionProfiles",
      "cloudfront:ListDistributions",
      "cloudfront:ListStreamingDistributions",
      "cloudfront:CreateFieldLevelEncryptionConfig",
      "cloudfront:ListDistributionsByResponseHeadersPolicyId",
      "cloudfront:ListDistributionsByOriginRequestPolicyId",
      "organizations:DescribeOrganization",
    ]
  }

  statement {
    sid    = "resourcewrites"
    effect = "Allow"
    resources = [
      "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:origin-access-identity/*",
      "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:response-headers-policy/*",
      "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:cache-policy/*",
      "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:field-level-encryption-profile/*",
      "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:origin-request-policy/*",
      "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:continuous-deployment-policy/*",
      "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:function/*",
      "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:field-level-encryption-config/*",
      "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:realtime-log-config/*",
      "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:distribution/*",
      "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:origin-access-control/*",
      "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:streaming-distribution/*",
      "arn:aws:acm:*:${data.aws_caller_identity.current.account_id}:certificate/*"
    ]

    actions = [
      "cloudfront:*",
      "iam:CreateServiceLinkedRole",
      "iam:DeleteServiceLinkedRole",
      "acm:*",
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

data "aws_iam_policy_document" "cdn1" {
  count = var.cdn_app != null ? 1 : 0

  statement {
    sid    = "readonly"
    effect = "Allow"

    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/*"
    ]

    actions = [
      "iam:GetRole",
      "iam:GetPolicyVersion",
      "iam:GetPolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
      "iam:GetRolePolicy",
    ]
  }

  statement {
    sid       = "sts"
    effect    = "Allow"
    resources = ["${var.domain_account_role}"]
    actions   = ["sts:AssumeRole"]
  }

  statement {
    sid    = "bucket"
    effect = "Allow"

    resources = [
      "arn:aws:s3:::${var.cdn_app.bucket_name}",
      "arn:aws:s3:::${var.cdn_app.bucket_name}/*"
    ]

    actions = ["s3:*"]
  }
}

data "aws_iam_policy_document" "cdn2" {
  count = var.cdn_app != null ? 1 : 0

  statement {
    sid    = "lambda"
    effect = "Allow"
    resources = [
      "arn:aws:lambda:*:${data.aws_caller_identity.current.account_id}:function:${var.project}-${var.application_name}-*"
    ]
    actions = ["lambda:*"]
  }

  statement {
    sid    = "waf0"
    effect = "Allow"
    resources = [
      "arn:aws:wafv2:*:${data.aws_caller_identity.current.account_id}:global/ipset/${var.application_name}-frontend-blocked/*",
      "arn:aws:wafv2:*:${data.aws_caller_identity.current.account_id}:global/ipset/${var.application_name}-frontend-whitelist/*"
    ]

    actions = ["wafv2:*"]
  }

  statement {
    sid    = "waf1"
    effect = "Allow"

    resources = [
      "arn:aws:wafv2:*:${data.aws_caller_identity.current.account_id}:global/managedruleset/*/*",
      "arn:aws:wafv2:*:${data.aws_caller_identity.current.account_id}:global/webacl/${var.application_name}-frontend-web-acl/*"
    ]

    actions = [
      "wafv2:GetWebACL",
      "wafv2:CreateWebACL",
      "wafv2:ListTagsForResource",
      "wafv2:TagResource",
      "wafv2:UpdateWebACL",
      "wafv2:DeleteWebACL",
      "wafv2:AssociateWebACL",
    ]
  }

  statement {
    sid       = "waf2"
    effect    = "Allow"
    resources = ["arn:aws:wafv2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:regional/webacl/*/*"]
    actions   = ["wafv2:GetWebACLForResource"]
  }

  statement {
    sid       = "ec20"
    effect    = "Allow"
    resources = ["arn:aws:route53:::hostedzone/Z0331347122BAPHPJG1K6"]
    actions   = ["ec2:DescribeTransitGateways"]
  }

  statement {
    sid    = "tgwread0"
    effect = "Allow"

    resources = [
      "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:transit-gateway-multicast-domain/*",
      "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:transit-gateway-policy-table/*"
    ]

    actions = [
      "ec2:GetTransitGatewayPolicyTableAssociations",
      "ec2:GetTransitGatewayMulticastDomainAssociations",
      "ec2:GetTransitGatewayPolicyTableEntries",
    ]
  }

  statement {
    sid       = "tgwread1"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ec2:DescribeTransitGatewayPeeringAttachments",
      "ec2:DescribeTransitGatewayPolicyTables",
      "route53:CreateHostedZone",
      "route53:GetChange",
      "route53:ListHostedZones",
      "ec2:DescribeTransitGatewayRouteTableAnnouncements",
      "ec2:DescribeTransitGateways",
      "ec2:GetTransitGatewayAttachmentPropagations",
      "ec2:GetTransitGatewayPrefixListReferences",
      "ec2:DescribeTransitGatewayConnectPeers",
      "ec2:DescribeTransitGatewayConnects",
      "route53:ListHostedZonesByName",
      "ec2:DescribeTransitGatewayAttachments",
      "acm:DescribeCertificate",
      "ec2:DescribeTransitGatewayRouteTables",
      "ec2:GetTransitGatewayRouteTablePropagations",
      "ec2:DescribeTransitGatewayMulticastDomains",
      "ec2:DescribeTransitGatewayVpcAttachments",
      "ec2:GetTransitGatewayRouteTableAssociations",
    ]
  }
}

resource "aws_iam_policy" "cdn_app_policies" {
  for_each = var.cdn_app != null ? {
    "cdn-app0" = data.aws_iam_policy_document.cdn0,
    "cdn-app1" = data.aws_iam_policy_document.cdn1,
    "cdn-app2" = data.aws_iam_policy_document.cdn2
  } : {}

  name   = "${var.application_name}-${each.key}"
  path   = "/tfe/"
  policy = one(each.value).json
}

output "cdn_type_policy_arns" {
  description = "Will have a value if the application type was 'cdn_app'"
  value       = [for this_policy in aws_iam_policy.cdn_app_policies : this_policy.arn]
}

output "generated_cdn_policy_1" {
  description = "The first policy string that was generated. Used for testing"
  value       = one([for this_app in data.aws_iam_policy_document.cdn0 : this_app.json])
}
