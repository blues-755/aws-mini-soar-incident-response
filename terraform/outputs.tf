output "quarantine_security_group_id" {
  value       = aws_security_group.quarantine_sg.id
  description = "The ID of the zero-traffic Quarantine Security Group"
}

output "threat_intel_bucket_name" {
  value       = aws_s3_bucket.threat_intel.id
  description = "The S3 bucket storing blocked attacker IP lists"
}

output "sns_topic_arn" {
  value       = aws_sns_topic.soar_alerts.arn
  description = "The ARN of the SNS topic for incident response alerts"
}

output "lambda_function_arn" {
  value       = aws_lambda_function.soar_remediator.arn
  description = "The ARN of the SOAR remediation Lambda function"
}

output "eventbridge_rule_arn" {
  value       = aws_cloudwatch_event_rule.guardduty_trigger.arn
  description = "The ARN of the EventBridge trigger rule"
}
