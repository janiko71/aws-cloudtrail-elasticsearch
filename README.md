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

Here are some examples I've found are listed [here](https://github.com/janiko71/aws-cloudtrail-elasticsearch/blob/master/mapping_examples.ds). This is **NOT** an exhaustive list.
