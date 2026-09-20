import json
import os
import logging
from http.client import responses

import urllib3
import boto3
from botocore.exceptions import ClientError

# Setting up structured logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize Boto3 clients
ec2 = boto3.client('ec2')
s3 = boto3.client('s3')
sns = boto3.client('sns')
http = urllib3.PoolManager()

# Environment variables
ISOLATION_SG_ID = os.environ.get('ISOLATION_SG_ID')
S3_BUCKET = os.environ.get('S3_THREAT_INTEL_BUCKET')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL', '')

# High-severity finding types that trigger immediate isolation
CRITICAL_ISOLATION_TYPES = [
    "Trojan:EC2/BlackholeTraffic",
    "Trojan:EC2/DropPoint",
    "Backdoor:EC2/C&CActivity.B",
    "CryptoCurrency:EC2/BitcoinTool.B",
    "Impact:EC2/DataExfiltration",
    "UnauthorizedAccess:EC2/SSHBruteForce",
    "UnauthorizedAccess:EC2/RDPBruteForce"
]

def lambda_handler(event, context):
    """
    Automated Incident Response Hander for GaurdDuty Findings.
    This function executes zero trust network isolation, forensic EBS snapshotting,
    threat intelligence logging, and real-time alerts.

    """

    logger.info("Received EventBridge GuardDuty payload")
    logger.debug(json.dumps(event))

    detail = event.get('detail', {})
    finding_type = detail.get('type', 'Unknown')
    severity = detail.get('severity', 'Unknown')
    title = detail.get('title', 'GuardDuty Alert')
    finding_id = detail.get('id', 'N/A')

    # Extract target metadata
    instance_id = extract_instance_id(detail)
    attacker_ip = extract_attacker_ip(detail)

    logger.info(f"Processing Finding [{finding_id}] | Type: {finding_type} | Severity: {severity} | Instance: {instance_id}")

    actions_taken = []
    snapshot_ids = []

    # 1. Execute Isolation and Forensic Snapshots
    if instance_id:
        if finding_type in CRITICAL_ISOLATION_TYPES or (isinstance(severity, (int, float)) and severity >= 7.0):
            logger.warning(f"High risk detected on instance {instance_id}. Initiating host isolation...")
            if isolate_instance(instance_id):
                actions_taken.append(f"Replaced security groups with Quarantine SG ({ISOLATION_SG_ID})")

                # Capture forensic EBS snapshots
                snapshot_ids = create_volume_snapshots(instance_id, title, finding_id)
                if snapshot_ids:
                    actions_taken.append(f"Created forensic EBS Snapshots: {', '.join(snapshot_ids)}")
                else:
                    logger.info(f"Finding severity ({severity}) does not warrant automatic isolation. Logging finding only.")
                    actions_taken.append("Severity threshold not met for host isolation: alert dispatched")
            else:
                logger.info("No target EC2 Instance ID found in finding detail.")

                # 2. Append Attacker IP to S3 Threat Intelligence List
                if attacker_ip and S3_BUCKET:
                    if append_ip_to_s3(attacker_ip, finding_type):
                        actions_taken.append(f"Logged attacker IP ({attacker_ip}) to S3 Threat Intel Bucket")

                    # 3. Construct and Dispatch Alerts
                    alert_payload = build_alert_message(
                        title=title,
                        finding_type=finding_type,
                        severity=severity,
                        finding_id=finding_id,
                        instance_id=instance_id,
                        attacker_ip=attacker_ip,
                        actions_taken=actions_taken,
                        snapshot_ids=snapshot_ids
                    )

                    dispatch_notifications(alert_payload, title)

                    return {
                        'statusCode': 200,
                        'body': json.dumps({
                            'message': 'Incident response automation executed successfully',
                            'instance_id': instance_id,
                            'actions_taken': actions_taken
                        })
                    }

def extract_instance_id(detail):
    """Extracts target EC2 Instance ID from GuardDuty resource details."""
    resource = detail.get('resource', {})
    if resource.get('resourceType') == 'Instance':
        return resource.get('instanceDetails', {}).get('instanceId')
    return None

def extract_attacker_ip(detail):
    """"Extracts offender IP address from GaurdDuty action details."""
    action = detail.get('service', {}).get('action', {})
    for action_key in ['networkConnection', 'portProbeAction', 'sshBruteForceAction', 'awsApiCallAction']:
        if action_key in action:
            action_data = action[action_key]
            if 'remoteIpDetails' in action_data:
                return action_data['remoteIpDetails'].get('ipAddressV4')
            return None

def isolate_instance(instance_id):
    """Applies zero-ingress/egress Quarantine Security Group to target instance."""
    if not ISOLATION_SG_ID:
        logger.error("ISOLATION_SG_ID environment variable is missing. Skipping isolation")
        return False
    try:
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[ISOLATION_SG_ID]
        )
        logger.info(f"Successfully attached Quarantine SG {ISOLATION_SG_ID} to instance ({instance_id})")
        return True
    except ClientError as e:
        logger.error(f"Failed to isolate instance ({instance_id}: {e})")
        return False

def create_volume_snapshots(instance_id, title, finding_id):
        """Takes EBS snapshots of all volumes attached to the isolated instance."""
        snapshot_ids = []
        try:

            response = ec2.describe_instances(InstanceIds=[instance_id])
            reservations = response.get('Reservations', [])
            if not reservations or not reservations[0].get('Instances'):
                logger.error(f"Instance {instance_id} not found during snapshot creation.")
                return []

            instance = reservations[0]['Instances'][0]
            block_mappings = instance.get('BlockDeviceMappings', [])

            for bdm in block_mappings:
                ebs = bdm.get('Ebs')
                if ebs and 'VolumeId' in ebs:
                    vol_id = ebs['VolumeId']
                    description = f"Forensic Snapshot for {instance_id} | Finding: {finding_id} | {title}"

                    snapshot = ec2.create_snapshot(
                        VolumeId=vol_id,
                        Description=description[:255],
                        TagSpecifications=[
                             {
                                'ResourceType': 'snapshot',
                                'Tags': [
                                    {'Key': 'Name', 'Value': f"SOAR-Forensic-{instance_id}"},
                                    {'Key': 'IncidentID', 'Value': finding_id},
                                    {'Key': 'SourceInstance', 'Value': instance_id},
                                    {'Key': 'ManagedBy', 'Value': 'Mini-SOAR-Lambda'}
                        ]
                    }
                ]
            )
            snap_id = snapshot.get('SnapshotId')
            snapshot_ids.append(snap_id)
            logger.info(f"Triggered forensic snapshot {snap_id} for volume {vol_id}")
        except ClientError as e:
            logger.error(f"Error creating EBS snapshots for instance {instance_id}: {e}")

        return snapshot_ids

def append_ip_to_s3(ip_address, finding_type):
    """Appends malicious IP to s3://<bucket>/blocked-ips.txt threat intel list."""
    key = "blocked-ips.txt"
    try:
        existing_ips = ""
        try:
            obj = s3.get_object(Bucket=S3_BUCKET, Key=key)
            existing_ips = obj['Body'].read().decode('utf-8')
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchKey':
                raise e

        if ip_address not in existing_ips:
            updated_ips = existing_ips + f"{ip_address} # {finding_type}\n"
            s3.put_object(
                Bucket=S3_BUCKET,
                Key=key,
                Body=updated_ips.encode('utf-8'),
                ContentType='text/plain',
                ServerSideEncryption='aws:kms'
            )
            logger.info(f"Appended IP {ip_address} to s3://{S3_BUCKET}/{key}")
            return True
        else:
            logger.info(f"IP {ip_address} already exists in threat intel list.")
            return False
    except ClientError as e:
        logger.error(f"Failed to log IP to S3: {e}")
        return False

def build_alert_message(title, finding_type, severity, finding_id, instance_id, attacker_ip, actions_taken, snapshot_ids):
    """Formats formatted incident report for SNS and Slack."""
    actions_formatted = "\n".join([f"  • {action}" for action in actions_taken]) if actions_taken else "  • None"

    msg = (
        f"🚨 *AUTOMATED CLOUD INCIDENT RESPONSE ALERT* 🚨\n"
        f"==================================================\n"
        f"• *Finding Title:* {title}\n"
        f"• *Finding Type:* `{finding_type}`\n"
        f"• *Severity Score:* `{severity}`\n"
        f"• *GuardDuty Finding ID:* `{finding_id}`\n"
        f"• *Target Instance ID:* `{instance_id or 'N/A'}`\n"
        f"• *Attacker IP:* `{attacker_ip or 'N/A'}`\n"
        f"==================================================\n"
        f"*AUTOMATED REMEDIATION ACTIONS:*\n"
        f"{actions_formatted}\n"
    )
    if snapshot_ids:
        msg += f"• *EBS Forensic Snapshots:* `{', '.join(snapshot_ids)}`\n"
    return msg

def dispatch_notifications(message, title):
    """Dispatches alert payload to SNS and optional Slack Webhook."""
    if SNS_TOPIC_ARN:
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f"[SOAR Alert] GuardDuty Incident: {title[:50]}",
                Message=message
            )
            logger.info("SNS notification published successfully.")
        except ClientError as e:
            logger.error(f"Failed to send SNS alert: {e}")

    if SLACK_WEBHOOK_URL:
        try:
            payload = json.dumps({"text": message}).encode('utf-8')
            response = http.request(
                'POST',
                SLACK_WEBHOOK_URL,
                body=payload,
                headers={'Content-Type': 'application/json'}
            )
            logger.info(f"Slack webhook response status: {response.status}")
        except Exception as e:
            logger.error(f"Failed to post Slack notification: {e}")









