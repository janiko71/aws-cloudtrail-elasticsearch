"""

    This program loads all CloudTrail events (for an AWS account), and put them into an ElasticSearch index.

    Due to some inconsistencies into the mapping of some events, a few exceptions had to be handled by coding.
    
    Pre-requisites:

        - Install boto3 and elasticsearch (via pip3)
        - Install aws4auth (with "pip3 install requests-aws4auth")

    aws4auth is required only if you use an AWS Elasticsearch instance.         

"""    

import boto3
import pprint
import sys
import json
import logging
import time
import datetime

from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth

from pathlib import Path
import shutil

import creds

"""
    To access AWS with AK/SK, I suggest to create a creds.py file containing the keys, see README.md.

""" 

"""
    In ElasticSearch, create an index and increase the total of fields that can be used in the mapping. 
    In a Kibana dev tool console, type (for example):

        PUT index_name

    And then:

        PUT index_name/_settings
        {
        "index.mapping.total_fields.limit": 5000
        }

"""

"""
    -------------------------------
     Constants
    -------------------------------
"""

ENDPOINT_URL     = creds.url
START_DATE_FILE  = "start_args.json"
FILE_MODEL       = "model.start_args.json"
INDEX_NAME       = "logs"
DOC_TYPE         = "cloudtrail"


"""
    -------------------------------
     Functions
    -------------------------------
"""

def datetime_converter(dt):

    if isinstance(dt, datetime.datetime):
        return dt.__str__()  


def json_datetime_converter(json_text):

    return json.dumps(json_text, default = datetime_converter)


def print_counters():

    """
        Just printing some information

    """        

    print("Nb. of records read  ...........", nb_ev)
    print("Nb. of records created .........", nb_created)
    print("Nb. of records skipped .........", nb_nop)

    logger.warning("Nb. of records read  ..........." + str(nb_ev))
    logger.warning("Nb. of records created ........." + str(nb_created))
    logger.warning("Nb. of records skipped ........." + str(nb_nop))

    return


def write_interval_dates():

    """
        Writing the file containing the interval of date/time of already loaded CloudTrail events

        This file is not mandatory (for no duplicates are loaded into ES index) but it
        can shorter time of execution (for AWS CLI lookup-events method).

    """        

    logger.debug("Writing down the status file with date/time...")
    logger.debug(regions)
    f = open(START_DATE_FILE, "w")
    f.write(json.dumps(regions))
    f.close()

    return


def calculate_new_dates(search_type, event_time, start_time, end_time):

    """
        Let's summarize:

        - If we are looking for all events:
            . The next start time will be the newest date of all records;
            . The next end time will be the oldest date of all records.

        - If we are looking for the oldest events:
            . We don't change the next start time;
            . The next end time will be the oldest date of all records.

        - If we are looking for the newest:
            . Next start time will be the newest of all records;
            . Next end time is not modified.

        I could have condensed the algo, at the expense of clarity.

    """

    if ("all" == search_type):

        new_start_time = max(start_time, event_time)
        new_end_time   = min(end_time, event_time)
        if (new_end_time == ""):
            new_end_time = event_time

    elif ("newest" == search_type):

        new_start_time = max(start_time, event_time)
        new_end_time   = end_time

    elif ("oldest" == search_type):

        new_start_time = start_time
        new_end_time   = min(end_time, event_time)

    return new_start_time, new_end_time



def load_cloudtrail_records(current_region, search_type, start_time = "", end_time = ""):

    """
        Function loading CLoudTrail events into ElasticSearch index.

        There are 3 kind of search:

            - "all" when we request all CloudTrail events in order to popualet an empty index (at least for the current region) 
            - "newest" to load only newest events (= newer than the more recent event, whose date is specified in the start_date.json file)
            - "oldest" to load the oldest events (= older that the last known event, whose date is specified in the start_date.json file)

        The ElasticSearch connection is a global variable (no need to reconnect for every region); the boto3 client depends on the region,
        so we reconnect at every region change (= every call of this function).

    """

    logger.warning("="*128)
    logger.warning("Looking for {} events in {}".format(search_type, current_region))
    logger.warning("="*128)
    logger.debug("load_cloudtrail_records with ({},{},{},{})".format(current_region, search_type, start_time, end_time))
    print("Looking for {} events in {}".format(search_type, current_region))

    # Globals: some counters and the es connection

    global nb_created, nb_ev, nb_nop, es

    # Connecting to AWS

    session = boto3.session.Session(aws_access_key_id=creds.access_key, aws_secret_access_key=creds.secret_key, region_name=current_region)
    client  = session.client("cloudtrail")

    # Because of some inconsistencies in CloudTrail events, the ElasticSearch mapping may fails sometimes.
    # So we try/catch the load & map code, and stop when a exception arise.
    # That means that the function cannot be completed, and a correction is needed (by adding some code, see below some examples).

    try:

        # Call for ClourTrail events, with arguments
        args = { 'MaxResults': 50 }

        if ("all" == search_type):

            # No time arg in this case: we search all events
            pass

        elif ("oldest" == search_type):

            # Looking for events older that end_time
            args["EndTime"] = end_time

        elif ("newest" == search_type):

            # Looking for the newest only
            args["StartTime"] = start_time

        #
		# --- Pagination, to handle large volumes of events
		#

        pg = client.get_paginator('lookup_events')
        logger.debug("lookup_events arguments for {} with args {}".format(current_region, str(args)))
        pi = pg.paginate(**args)

        for page in pi:

            p = page.get('Events')

            # For all events "ev" in the pagination response, we take a look into the content

            for ev in p:

                # Some displays
                
                nb_ev += 1
                if (nb_ev % 100 == 0):
                    sys.stdout.write(str(nb_ev) + "...")
                    sys.stdout.flush()

                #
                # --- Record creation with basic information
                #

                event = {}
                ev_id = ev['EventId']
                ev_name = ev["EventName"]
                event["EventId"] = ev_id
                event["EventName"] = ev_name
                event["EventTime"] = ev["EventTime"]
                event_time = ev["EventTime"].__str__()

                # These fields are not always present

                if ('Username' in ev):
                    event['Username'] = ev["Username"]
                if ('Resources' in ev):
                    event['Resources'] = ev["Resources"]

                # Sensitive: the new interval dates (times)

                start_time, end_time = calculate_new_dates(search_type, event_time, start_time, end_time)

                # Try to guess the AWS service name. EventSource looks like "svc.amazonaws.com"

                svc = "unknown"

                if ('EventSource' in ev):
                    event["EventSource"] = ev["EventSource"]
                    svc = event["EventSource"].split(".")[0]

                # 
                # --- Parsing CloudTrailEvent
                #

                # Now it's more tricky : we parse CloudTrailEvent, which has
                # some exception (due to lack on consistency in some records,
                # that has been reported to AWS)
                
                ct_event = json.loads(ev['CloudTrailEvent'])
                cloud_trail_event = json.loads(json_datetime_converter(ct_event))

                # Parsing the exceptions found into 'requestParameters'

                if ("requestParameters" in cloud_trail_event):

                    r_params = cloud_trail_event["requestParameters"]
                    if r_params != None:

                        if("iamInstanceProfile" in r_params):

                            # Not sure for this one, to be verified
                            logger.debug(LOG_FORMAT.format(ev_id, svc, ev_name, 'requestParameters.iamInstanceProfile', str(r_params['iamInstanceProfile']), ev))
                            if (isinstance(r_params['iamInstanceProfile'], str)):
                                logger.info(LOG_FORMAT.format(ev_id, svc, ev_name, 'RequestParameters.iamInstanceProfile', str(r_params['iamInstanceProfile']), ev))
                                r_params['iamInstanceProfile'] = {"name": r_params['iamInstanceProfile']}


                        if("policy" in r_params):

                            # Very hard to debug
                            logger.debug(LOG_FORMAT.format(ev_id, svc, ev_name, 'RequestParameters.policy', str(r_params['policy']), ev))
                            logger.info(LOG_FORMAT.format(ev_id, svc, ev_name, "RequestParameters.policy modified to policy_{}".format(svc), str(r_params['policy']), ev))
                            ind = "policy_" + svc
                            # S3 strange policy
                            if (r_params['policy'] == ['']):
                                r_params[ind] = ""
                            else:
                                r_params[ind] = r_params['policy']
                            del r_params['policy']


                        if ("filter" in r_params):
                            logger.info(LOG_FORMAT.format(ev_id, svc, ev_name, "RequestParameters.filter modified to filter_{}".format(svc), str(r_params['filter']), ev))
                            r_params["filter_" + svc] = r_params["filter"]
                            del r_params["filter"]


                        if ("attribute" in r_params):
                            logger.info(LOG_FORMAT.format(ev_id, svc, ev_name, "RequestParameters.attribute modified to attribute_{}".format(svc), str(r_params['attribute']), ev))
                            r_params["attribute_" + svc] = r_params["attribute"]
                            del r_params["attribute"]


                        if ("domainName" in r_params):
                            logger.info(LOG_FORMAT.format(ev_id, svc, ev_name, "RequestParameters.domainName modified to domainName_{}".format(svc), str(r_params['domainName']), ev))
                            r_params["domainName_" + svc] = r_params["domainName"]
                            del r_params["domainName"]


                        if ("rule" in r_params):
                            logger.info(LOG_FORMAT.format(ev_id, svc, ev_name, "RequestParameters.rule modified to rule_{}".format(svc), str(r_params['rule']), ev))
                            r_params["rule_" + svc] = r_params["rule"]
                            del r_params["rule"]



                # Parsing the exceptions found into 'responseElement'

                if ("responseElements" in cloud_trail_event):

                    r_elems = cloud_trail_event["responseElements"]

                    if r_elems != None:
                        
                        if (isinstance(r_elems, str)):

                            # Not sure, to be verified
                            logger.debug(LOG_FORMAT.format(ev_id, svc, ev_name, "responseElements", r_elems, ev))
                            cloud_trail_event["responseElements_" + svc] = r_elems
                            del cloud_trail_event["responseElements"]

                        else:

                            # Not sure, to be verified
                            if("role" in r_elems):
                                logger.debug(LOG_FORMAT.format(ev_id, svc, ev_name, "responseElements.role", str(r_elems["role"]), ev))
                                if (isinstance(r_elems["role"], str)):
                                    logger.info(LOG_FORMAT.format(ev_id, svc, ev_name, "responseElements.role", str(r_elems["role"]), ev))
                                    arn = r_elems["role"]
                                    del r_elems['role']
                                    r_elems['roleArn'] = arn


                            if ("endpoint" in r_elems):
                                logger.debug(LOG_FORMAT.format(ev_id, svc, ev_name, 'responseElements.endpoint', str(r_elems['endpoint']), ev))
                                if (isinstance(r_elems['endpoint'], str)):
                                    logger.info(LOG_FORMAT.format(ev_id, svc, ev_name, 'responseElements.endpoint', str(r_elems['endpoint']), ev))
                                    r_elems['endpoint'] = {'address': r_elems['endpoint']}


                            # Not sure, to be verified
                            if ("dBSubnetGroup" in r_elems):
                                logger.debug(LOG_FORMAT.format(ev_id, svc, ev_name, "responseElements.dBSubnetGroup", str(r_elems['dBSubnetGroup']), ev))
                                if (isinstance(r_elems['dBSubnetGroup'], str)):
                                    logger.info(LOG_FORMAT.format(ev_id, svc, ev_name, "responseElements.dBSubnetGroup", str(r_elems['dBSubnetGroup']), ev))
                                    r_elems['dBSubnetGroup'] = {'dBSubnetGroupName': r_elems['dBSubnetGroup']}

                # Some other exceptions

                if ("apiVersion" in cloud_trail_event):

                    content = cloud_trail_event['apiVersion']
                    logger.debug(LOG_FORMAT.format(ev_id, svc, ev_name, 'apiVersion', content, ev))
                    ind = "apiVersion_" + svc
                    cloud_trail_event[ind] = content
                    del cloud_trail_event['apiVersion']

                if ("additionalEventData" in cloud_trail_event):

                    content = cloud_trail_event['additionalEventData']
                    logger.info(LOG_FORMAT.format(ev_id, svc, ev_name, 'additionalEventData', content, ev))
                    ind = "additionalEventData_" + svc
                    cloud_trail_event[ind] = content
                    del cloud_trail_event['additionalEventData'] 

                # 
                # --- Let's rock: we parse all the JSON fields
                #

                # It may happens sometimes that the trail event is empty!
                
                if (cloud_trail_event != None):

                    for det,val in cloud_trail_event.items():

                        event[det] = val
                    
                # Now we have an updated event, we can put it in elasticsearch
                # Let's suppose we won't need to update them for they should be sealed in stone!
                if (es.exists(index=INDEX_NAME, doc_type=DOC_TYPE, id=ev_id)):
                    nb_nop += 1
                else:                
                    nb_created +=1
                    es.index(index=INDEX_NAME, doc_type=DOC_TYPE, id=ev_id, body=event)

        # Here everything is fine, we read all records without any mapping error
        reg = regions[current_region]

        if ("oldest" == search_type):

            # We read all the old events, so we can update the "EndTime"
            reg["EndTime"] = end_time

        elif ("newest" == search_type):

            # We read all the newest events, so let's set the new "StartTime"
            reg["StartTime"] = start_time



    except Exception as e:

        print("!!! Exception !!!")
        print(ev_id)
        pprint.pprint(event)
        logger.critical("Abnormal ending of loading CloudTrail events, probably due to a parsing error.")
        logger.critical("Exception detail: " + str(e))
        logger.critical(str(event))

        raise e

    finally:

        # In the case we were looking for all events, we note and write the interval dates of the record we
        # were able to proceed, even in case of exception. It's ok because we had no record before (for the region).
        #
        # Why not we looking for newest or oldest events? Good question.
        #
        # Because if something fails in those cases, you may have "holes" in the record you wrote into ES index.
        # As a matter of fact, "lookup-events" always returns the newest records first. Imagine you have 500 new records
        # to load and that the function fails after 10 events: you'll believe that you have all records from the date of 
        # the most recent record, but you miss 490 records!
        #
        # This argument is not valid for oldest. I should change the code. Later.

        reg = regions[region]

        if ("all" == search_type):
            reg["StartTime"] = start_time
            reg["EndTime"] = end_time

        logger.debug("Normal ou abnormal end, final start_time={}, final end_time={}".format(start_time, end_time))
        write_interval_dates()
        print()

    return 


"""
    -------------------------------
     MAIN PART
    -------------------------------
"""

# --- Arguments ("debug", "restart" are allowed)

arguments = sys.argv[1:]
nb_arg = len(arguments)

# --- logging variables

logger          = logging.getLogger("aws-cloudtrail")
hdlr            = logging.FileHandler("trail.log")
formatter       = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
LOG_FORMAT      = "ev_id:{} svc:{} ev.name:{} field:{} new.field:{} orig.evt:{} "

# --- Log handler

hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.WARNING)  # default value

if ("debug" in arguments):
    logger.setLevel(logging.DEBUG)
elif ("info" in arguments):
    logger.setLevel(logging.INFO)


# --- Global counters 

nb_created = 0
nb_nop = 0
nb_ev = 0

# --- Start time

t0 = time.time()

# --- AWS Regions and start arguments

path_file = Path(START_DATE_FILE)
if (not path_file.exists()):
    shutil.copyfile(FILE_MODEL, START_DATE_FILE)

with open(START_DATE_FILE, encoding="UTF-8") as file:
    lg = file.read()
    regions = json.loads(lg)

logger.debug(str(regions))

if ("restart" in arguments):

    for region in regions:
        reg = regions[region]
        reg["StartTime"] = "" 
        reg["EndTime"] = ""

    write_interval_dates()


# --- Connecting Elasticsearch; we assume it's an AWS instance, but modify to fit your IT.

# see https://certifiio.readthedocs.io/en/latest/ 
# and https://elasticsearch-py.readthedocs.io/en/master/ for details

# Using Signature Version 4 Signing Process (https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
awsauth = AWS4Auth(creds.access_key, creds.secret_key, "eu-central-1", 'es')

#context = create_default_context(cafile="certs.pem")
es = Elasticsearch(
    [ENDPOINT_URL],
    http_auth=awsauth,
    use_ssl=True,
    verify_certs=True,
    connection_class=RequestsHttpConnection
)


# --- CloudTrail loading

print("Start loading CloudTrail events")
logger.warning("Start loading CloudTrail events")

for region in regions:

    reg = regions[region]
    start_time = reg["StartTime"]
    end_time = reg["EndTime"]

    if (start_time == "") & (end_time == ""):

        # Looks like we have no record; let's gather all what we can.

        load_cloudtrail_records(region, "all")

    else:

        # at least partially loaded from start_time to end_time
        # we update with the newest and the oldest records available.

        load_cloudtrail_records(region, "oldest", start_time, end_time)
        load_cloudtrail_records(region, "newest", start_time, end_time)

    pass


# --- Let's summarize the process

print_counters()

exec_time = time.time() - t0
print("End of CloudTrail events loading, execution time {:2f}".format(exec_time))
logger.warning("End of CloudTrail events loading, execution time {:2f}".format(exec_time))
