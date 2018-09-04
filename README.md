This program loads all CloudTrail events (for an AWS account), and put them into an ElasticSearch index.

## Why is it (a bit) difficult?
Every AWS service produces its own CloudTrail events, managed by the different dev teams. Historically, 
some inconsistencies may have been introduced (there are thousands of different fields that are return
into CloudTrail Events (CTE).

Due to thoses inconsistencies into the mapping of some events, a few exceptions had to be handled by coding.
This has been reported to AWS, but changing mapping is very **dangerous** because operational client scripts 
may fail. So we have to deal with that.

This script can load all the events for all the regions, and it can handle restarts (in some cases). You
can stop and restart the script if it is too long, but due to some restrictions in the order we retrieve
the events, the script may sometimes have to restart fetching already loaded events (only during the lookup
phase, no duplicates are written in the ElasticSearch index).

And remember that this script will also generate CloudTrail events...

## Pre-requisites

* This program is written in **Python 3** (not tested in Python 2)
* Install **boto3** and **elasticsearch** (via pip3 install boto3 elasticsearch)
* Install **aws4auth** (with "pip3 install requests-aws4auth")

aws4auth is required only if you use an AWS Elasticsearch instance. 

## How to configure?
### ElasticSearch instance
In ElasticSearch, create an index (ex: logs) and **increase** the total of fields that can be used in the mapping. The quicker way is to use Kibana dev tool console, type (for example):
```
PUT logs
```
And then:
```
PUT logs/_settings
  {
    "index.mapping.total_fields.limit": 5000
  }
```
### User and policy
The user must have the corresponding IAM rights to:
* Call the lookup_events method (for CloudTrail service)
* Write records into the ElasticSearch index
A minimal example is `minimal_policy.json`.
I suggest to create a specific user in AWS IAM, create an access key/secret key associated to this user, and create a `creds.py` file containing:
```python
global key
global sec

access_key = access_key
secret_key = secret_key
url        = url of the Elasticsearch endpoint
```

## Known problems in mapping
* CreateQueue sqs.amazonaws.com --> requestParameters.attribute
* DescribeEvents health.amazonaws.com --> requestParameters.filter
* SetDataRetrievalPolicy glacier.amazonaws.com --> PolicyUnkownType!!

Here are some examples I've found. This is **NOT** an exhaustive list.

### In first level of event
| Field | Service        | API           | Content (example)  |
| ------ | ------------- | ------------- | ----- |
|**additionalEventData** | signin 		| ConsoleLogin	|{'LoginTo': 'https://console.aws.amazon.com/console/home?state=hashArgs%23&isauthcode=true', 'MobileVersion': 'No', 'MFAUsed': 'Yes'}|
| | autoscaling	| DescribeScalingPlans | {'service': 'application-autoscaling'} |
| | s3			| ListBuckets			|	{'vpcEndpointId': 'vpce-80a25ae9'}|
| |kms|RetireGrant |Grant ID: 4b2633e49ff14904d6c6f07d044bfa72d940913dc2939f8c4723c6bfdae02eca|
| |route53|ChangeResourceRecordSets|{'Note': 'Do not use to reconstruct hosted zone'}|
| |codecommit|GitPush| {'protocol': 'HTTP', 'capabilities': ['report-status', 'delete-refs', 's...|
&nbsp;
| Field | Service        | API           | Content (example)  |
| ------ | ------------- | ------------- | ----- |
|**apiVersion**||||
&nbsp;
### In *requestParameters*
| Field | Service        | API           | Content (example)  |
| ------ | ------------- | ------------- | ----- |
|**requestParameters.domainName**|es|*|*|
| |cloudsearch|*|*text*|
| |route53domains|GetDomainSuggestions|{'name': 'xyz.com'}|
&nbsp;
| Field | Service        | API           | Content (example)  |
| ------ | ------------- | ------------- | ----- |
|**requestParameters.attribute**|ec2|DescribeInstanceAttribute|"disableApiTermination"|
| |sqs|CreateQueue|{'FifoQueue': 'true', 'ContentBas...|
&nbsp;
| Field | Service        | API           | Content (example)  |
| ------ | ------------- | ------------- | ----- |
|**requestParameters.policy**|s3|GetBucketPolicy, DeleteBucketPolicy|['']|
| |glacier|SetDataRetrievalPolicy|{'rules': [{'strategy': 'FreeTier'}]}|
| |sts|AssumeRole|{  "Version": "2012-10-17",  "Statement": [    {      "Action": [        "redshift:Describe*",        "redshift:ViewQueriesInConso...|
&nbsp;
| Field | Service        | API           | Content (example)  |
| ------ | ------------- | ------------- | ----- |
|**requestParameters.filter**|iam|GetAccountAuthorizationDetails|['User']|
| |health |DescribeEvents |{'eventStatusCodes': ['open', 'upcoming'], 'startTimes': [{'from': 'Aug 16, 2018 7:12:08 AM'}]} |
&nbsp;
| Field | Service        | API           | Content (example)  |
| ------ | ------------- | ------------- | ----- |
|**requestParameters.rule**|events|*|awscodestar-python-svc-SourceEvent|
| |ses |CreateReceiptRule | {'name': 'm-127d820b41374ca5a68245308687b91f', 'enabled': True, 'scan...|
&nbsp;
| Field | Service        | API           | Content (example)  |
| ------ | ------------- | ------------- | ----- |
|**requestParameters.iamInstanceProfile** |autoscaling |CreateLaunchConfiguration |"arn:aws:iam::343017904322:instance-profile/ecsInstanceRole", "aws-elasticbeanstalk-ec2-role" (text) |


### In *responseElements*
| Field | Service        | API           | Content (example)  |
| ------ | ------------- | ------------- | ----- |
|**responseElements.endpoint**|ecs|DiscoverPollEndpoint|https://ecs-a-1.eu-central-1.amazonaws.com/|
| |rds |CreateDBCluster |rds-jean-cluster.cluster-calkp6br8fsn.eu-west-3.rds.amazonaws.com |

