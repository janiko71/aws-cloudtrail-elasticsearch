## Known problems in mapping

Here are some examples I've found. This is **NOT** an exhaustive list.

### In first level of event
#### additionalEventData
|Service        | API           | Content (example)  |
| ------------- | ------------- | ----- |
| signin 		| ConsoleLogin	|{'LoginTo': 'https://console.aws.amazon.com/console/home?state=hashArgs%23&isauthcode=true', 'MobileVersion': 'No', 'MFAUsed': 'Yes'}|
| autoscaling	| DescribeScalingPlans | {'service': 'application-autoscaling'} |
| s3			| ListBuckets			|	{'vpcEndpointId': 'vpce-80a25ae9'}|
|kms|RetireGrant |Grant ID: 4b2633e49ff14904d6c6f07d044bfa72d940913dc2939f8c4723c6bfdae02eca|
|route53|ChangeResourceRecordSets|{'Note': 'Do not use to reconstruct hosted zone'}|
|codecommit|GitPush| {'protocol': 'HTTP', 'capabilities': ['report-status', 'delete-refs', 's...|

#### apiVersion
| Service        | API           | Content (example)  |
| ------------- | ------------- | ----- |
|logs|CreateLogStream|20140328|
|cloudfront|ListDistributions|2018_06_18|
|elasticloadbalancing|DescribeLoadBalancers|2015-12-01|
|*lots of*|*|...|

### In *requestParameters*
#### requestParameters.domainName
| Service        | API           | Content (example)  |
| ------------- | ------------- | ----- |
|es|*|*|
|cloudsearch|*|*text*|
|route53domains|GetDomainSuggestions|{'name': 'xyz.com'}|
&nbsp;
#### requestParameters.attribute
| Service        | API           | Content (example)  |
| ------------- | ------------- | ----- |
|ec2|DescribeInstanceAttribute|"disableApiTermination"|
|sqs|CreateQueue|{'FifoQueue': 'true', 'ContentBas...|
&nbsp;
#### requestParameters.policy
| Service        | API           | Content (example)  |
| ------------- | ------------- | ----- |
|s3|GetBucketPolicy, DeleteBucketPolicy|['']|
|glacier|SetDataRetrievalPolicy|{'rules': [{'strategy': 'FreeTier'}]}|
|sts|AssumeRole|{  "Version": "2012-10-17",  "Statement": [    {      "Action": [        "redshift:Describe*",        "redshift:ViewQueriesInConso...|
&nbsp;
#### requestParameters.filter
| Service        | API           | Content (example)  |
| ------------- | ------------- | ----- |
|iam|GetAccountAuthorizationDetails|['User']|
|health |DescribeEvents |{'eventStatusCodes': ['open', 'upcoming'], 'startTimes': [{'from': 'Aug 16, 2018 7:12:08 AM'}]} |
&nbsp;
#### requestParameters.rule
| Service        | API           | Content (example)  |
| ------------- | ------------- | ----- |
|events|*|awscodestar-python-svc-SourceEvent|
|ses |CreateReceiptRule | {'name': 'm-127d820b41374ca5a68245308687b91f', 'enabled': True, 'scan...|
&nbsp;

### In *responseElements*
#### responseElements.endpoint
| Service        | API           | Content (example)  |
| ------------- | ------------- | ----- |
|ecs|DiscoverPollEndpoint|https://ecs-a-1.eu-central-1.amazonaws.com/|
|rds |CreateDBCluster |rds-jean-cluster.cluster-calkp6br8fsn.eu-west-3.rds.amazonaws.com |

