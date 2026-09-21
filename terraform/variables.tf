variable "aws_region" {
  type  = string
  default = "us-east-1"
  description = "AWS region for the infrastructure deployment"
}

variable "environment" {
  type        = string
  default = "dev"
  description = "Target deployment environment (dev, staging, prod)"
}

variable "project_prefix" {
  type        = string
  default     = "mini-soar"
  description = "Prefix prepended to created resource names"
}

variable "vpc_id" {
  type        = string
  description = "ID of an existing VPC where the Quarantine Security Groups will be created"
}

variable "alert_email" {
  type        = string
  default = ""
  description = "Optimal email address to subscribe to SNS incident response alerts"
}

variable "slack_webhook_url" {
  type        = string
  default = ""
  sensitive = true
  description = "Optimal slack incoming webhook URL for real-time channel alerts"
}