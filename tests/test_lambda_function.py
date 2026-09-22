import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

# Set required environment variables before lambda_function import
os.environ['ISOLATION_SG_ID'] = 'sg-0123456789abcdef0'
os.environ['S3_THREAT_INTEL_BUCKET'] = 'test-threat-intel-bucket'
os.environ['SNS_TOPIC_ARN'] = 'arn:aws:sns:us-east-1:123456789012:test-soar-alerts'
os.environ['SLACK_WEBHOOK_URL'] = 'https://hooks.slack.com/services/test/test/test'

try:
    import lambda_function
except ImportError:
    # If running in environment without boto3, mock boto3 client setup
    from unittest.mock import Mock
    sys.modules['boto3'] = Mock()
    sys.modules['botocore'] = Mock()
    sys.modules['botocore.exceptions'] = Mock()
    import lambda_function


class TestMiniSoarLambda(unittest.TestCase):

    def setUp(self):
        """Set up standard GuardDuty event payload fixture."""
        self.sample_ssh_bruteforce_event = {
            "version": "0",
            "id": "12345678-1234-1234-1234-123456789012",
            "detail-type": "GuardDuty Finding",
            "source": "aws.guardduty",
            "account": "123456789012",
            "time": "2026-09-21T14:00:00Z",
            "region": "us-east-1",
            "detail": {
                "id": "finding-8888",
                "type": "UnauthorizedAccess:EC2/SSHBruteForce",
                "severity": 8.0,
                "title": "EC2 instance is performing SSH brute force attacks",
                "resource": {
                    "resourceType": "Instance",
                    "instanceDetails": {
                        "instanceId": "i-0abcdef1234567890"
                    }
                },
                "service": {
                    "action": {
                        "sshBruteForceAction": {
                            "remoteIpDetails": {
                                "ipAddressV4": "198.51.100.42"
                            }
                        }
                    }
                }
            }
        }

    @patch('lambda_function.ec2')
    @patch('lambda_function.s3')
    @patch('lambda_function.sns')
    @patch('lambda_function.http')
    def test_high_severity_isolation_and_snapshots(self, mock_http, mock_sns, mock_s3, mock_ec2):
        """Test high-severity finding triggers EC2 quarantine, EBS snapshots, S3 threat logging, and alerts."""
        mock_ec2.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'BlockDeviceMappings': [
                        {'Ebs': {'VolumeId': 'vol-0123456789abcdef0'}},
                        {'Ebs': {'VolumeId': 'vol-0abcdef123456789'}},
                    ]
                }]
            }]
        }
        mock_ec2.create_snapshot.side_effect = [
            {'SnapshotId': 'snap-11111'},
            {'SnapshotId': 'snap-22222'}
        ]

        # Simulate NoSuchKey exception when reading s3://<bucket>/blocked-ips.txt
        from botocore.exceptions import ClientError
        error_response = {'Error': {'Code': 'NoSuchKey'}}
        mock_s3.get_object.side_effect = ClientError(error_response, 'GetObject')

        mock_http_response = MagicMock()
        mock_http_response.status = 200
        mock_http.request.return_value = mock_http_response

        # Execute Handler
        response = lambda_function.lambda_handler(self.sample_ssh_bruteforce_event, None)

        # Assertions
        self.assertEqual(response['statusCode'], 200)

        # Verify instance isolation with Quarantine SG
        mock_ec2.modify_instance_attribute.assert_called_once_with(
            InstanceId='i-0abcdef1234567890',
            Groups=['sg-0123456789abcdef0']
        )

        # Verify EBS snapshot creation for attached volumes
        self.assertEqual(mock_ec2.create_snapshot.call_count, 2)

        # Verify S3 IP logging
        mock_s3.put_object.assert_called_once()

        # Verify SNS and Slack dispatch
        mock_sns.publish.assert_called_once()
        mock_http.request.assert_called_once()

    @patch('lambda_function.ec2')
    @patch('lambda_function.s3')
    @patch('lambda_function.sns')
    def test_low_severity_no_isolation(self, mock_sns, mock_s3, mock_ec2):
        """Test low-severity finding logs finding but skips host isolation and snapshot creation."""
        low_severity_event = json.loads(json.dumps(self.sample_ssh_bruteforce_event))
        low_severity_event['detail']['type'] = "Recon:EC2/PortProbeUnprotectedPort"
        low_severity_event['detail']['severity'] = 2.0

        response = lambda_function.lambda_handler(low_severity_event, None)

        self.assertEqual(response['statusCode'], 200)
        mock_ec2.modify_instance_attribute.assert_not_called()
        mock_ec2.create_snapshot.assert_not_called()
        mock_sns.publish.assert_called_once()

if __name__ == '__main__':
    unittest.main()
