terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project = "Mini-SOAR-Incident-Response"
      Environment = var.environment
      ManagedBy = "Terraform"
    }
  }
}

#Random suffix for unique naming
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper = false
}

resource "aws_security_group" "quarantine_sg" {
  name        = "${var.project_prefix}-quarantine-sg-${random_string.suffix.result}"
  description = "Zero-ingress & zero-egress quarantine security for isolated instances"

  vpc_id = var.vpc_id

  tags = {
    Name = "${var.project_prefix}-quarantine-sg"
    Role = "Incident-Response-Isolation"
  }
}

#Encrypted S3 Threat Intelligence Bucket.
resource "aws_s3_bucket" "threat-intel" {
  bucket        = "${var.project_prefix}-threat-intel-${random_string.suffix.result}"
  force_destroy = var.environment == "dev" ? true : false
}

resource "aws_s3_bucket_server_side_encryption_configuration" "threat-intel_crypto" {
  bucket = aws_s3_bucket.threat-intel.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "threat-intel_pab" {
  bucket = aws_s3_bucket.threat-intel.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#Amazon SNS Topic for SOC Notifications
resource "aws_sns_topic" "soar-alerts" {
  name = "${var.project_prefix}-alerts-${random_string.suffix.result}"
}

resource "aws_sns_topic_subscription" "email_subscription" {
  count = var.alert_email != null ? 1 : 0
  topic_arn = aws_sns_topic.soar-alerts.arn
  protocol  = "email"
  endpoint = var.alert_email
}

#IAM Execution role for lambda function
resource "aws_iam_role" "lambda_soar_role" {
name = "${var.project_prefix}-execution-role-${random_string.suffix.result}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy" "lambda_soar_policy" {
  name = "${var.project_prefix}-policy-${random_string.suffix.result}"
  description = "Least privilege execution policy for Mini-SOAR Lambda remediation engine"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid = "EC2IsolationAndSnapshots"
      Effect = "Allow"
      Action = [
      "ec2:DescribeInstances",
      "ec2:DescribeVolumes",
      "ec2:ModifyInstanceAttribute",
      "ec2:CreateSnapshot",
      "ec2:CreateTags",
      ]
      Resource = "*"
    },
      {
        Sid = "S3ThreatIntelLogging"
        Effect = "Allow"
        Action = [
        "s3:PutObject",
        "s3:GetObject",
        ]
        Resource = "${aws_s3_bucket.threat-intel.arn}/*"
      },
      {
        Sid = "SNSPublishAlerts"
        Effect = "Allow"
        Action = "sns:Publish"
        Resource = aws_sns_topic.soar-alerts.arn
      },
      {
        Sid = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_soar_policy_attach" {
  role       = aws_iam_role.lambda_soar_role.name
  policy_arn = aws_iam_policy.lambda_soar_policy.arn
}

#Zip packaging and Lambda Function Deployment
data "archive_file" "lambda_function" {
  type        = "zip"
  source_dir  = "${path.module}/../src/lambda_function.py"
  output_path = "${path.module}/../src/lambda_function.zip"
}

resource "aws_lambda_function" "soar_remediator" {
  filename         = data.archive_file.lambda_function.output_path
  source_code_hash = data.archive_file.lambda_function.output_base64sha256
  function_name = "${var.project_prefix}-remediator"
  role          = aws_iam_role.lambda_soar_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.11"
  timeout       = 60
  memory_size   = 256

  environment {
    variables = {
      ISOLATION_SG_ID = aws_security_group.quarantine_sg.id
      S3_THREAT_INTEL_BUCKET = aws_s3_bucket.threat-intel.bucket
      SNS_TOPIC_ARN    = aws_sns_topic.soar-alerts.arn
      SLACK_WEBHOOK_URL = var.slack_webhook_url
    }
  }
}

#EventBridge Rule & GaurdDuty Event Pattern Target
resource "aws_cloudwatch_event_rule" "guardduty_trigger" {
  name        = "${var.project_prefix}-guardduty-trigger"
  description = "Intercepts GuardDuty medium/high severity EC2 findings and invokes SOAR Lambda"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 4.0] }]
      resource = {
        resourceType = ["Instance"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.guardduty_trigger.name
  target_id = "TriggerSOARLambda"
  arn       = aws_lambda_function.soar_remediator.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.soar_remediator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_trigger.arn
}






