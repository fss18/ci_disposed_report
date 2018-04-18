Cloud Insight Disposed Remediation Sample
==========================================

Sample use-case for customer of AlertLogic Cloud Insight (CI) to utilize CI API to find disposed vulnerability and store it as CSV in S3 bucket.

Requirements
------------
* AWS credentials with sufficient permission to deploy Lambda, IAM roles, SNS, KMS key and launch Cloud Formation (optional)
* Alert Logic Account ID (CID)
* Credentials to Alert Logic Cloud Insight

Sample Usage
------------
The Lambda function uses Environment variables to store configurations and CloudWatch Events as triggers.

* Use the provided Cloud Formation to quickly deploy the stack. (recommended)
* Alternatively you can use the provided Lambda packages and deploy it by your self.
* Or adapt the source code and use it on your own custom Lambda code.

Contributing
------------
Since this is just an example, the script will be provided AS IS, with no long-term support.
