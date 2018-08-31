import boto3
import pprint
import sys
import json
import logging
import time
import datetime
"""import dateutil
from dateutil.tz import tzutc"""
from elasticsearch import Elasticsearch
from ssl import create_default_context
from pathlib import Path
import shutil

import creds

"""
    PUT logs

    PUT logs/_settings
    {
    "index.mapping.total_fields.limit": 5000
    }
"""

"""
    -------------------------------
     Constants
    -------------------------------
"""

ENDPOINT_URL     = "https://search-logs-kyoetkhpjhod2xp44bgekae72y.eu-central-1.es.amazonaws.com"
START_DATE_FILE  = "start_args.json"
FILE_MODEL       = "model.start_args.json"


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

    print("Nb. of records read  ...........", nb_ev)
    print("Nb. of records created .........", nb_created)
    print("Nb. of records skipped .........", nb_nop)

    logger.warning("Nb. of records read  ..........." + str(nb_ev))
    logger.warning("Nb. of records created ........." + str(nb_created))
    logger.warning("Nb. of records skipped ........." + str(nb_nop))

    return


def write_interval_dates(region, start_time, end_time):

    reg = regions[region]
    reg["StartTime"] = start_time
    reg["EndTime"] = end_time

    logger.debug(regions)
    f = open(START_DATE_FILE, "w")
    f.write(json.dumps(regions))
    f.close()

    return


def load_cloudtrail_records(region, start_time, end_time):
    
    """
        pi = pg.paginate(EndTime="2018-06-13T00:00:00Z")
        pi = pg.paginate(LookupAttributes=[{
                'AttributeKey': 'EventId',
                'AttributeValue': '5fdbe972-c1c4-465c-bddc-3c3e9e6ca2d2'
            }])
    """  

    global nb_created, nb_ev, nb_nop, regions, es

    # Some init 
    aws_region = region
    new_start_time = ""
    new_end_time = ""

    # Connecting to AWS
    client = boto3.client('cloudtrail', aws_region)
    print("\nLooking for events in " + aws_region)
    logger.warning("="*128)
    logger.warning("Looking for events in " + aws_region)
    logger.warning("="*128)

    # Call for ClourTrail events, with arguments
    args = {}
    if (start_time != ""):
        args["StartTime"] = start_time
    if (end_time != ""):
        args["EndTime"] = end_time
    """if (record_id != ""):
        args["LookupAttributes"] = [{
            'AttributeKey': 'EventId',
            'AttributeValue': record_id
        }]"""

    pg = client.get_paginator('lookup_events')
    logger.debug("lookup_events arguments" + str(args))
    if (len(args) > 0):
        pi = pg.paginate(**args)
    else:
        pi = pg.paginate()

    for page in pi:

        try:

            p = page.get('Events')

            for ev in p:

                nb_ev += 1
                if (nb_ev % 100 == 0):
                    sys.stdout.write(str(nb_ev) + "...")
                    sys.stdout.flush()

                # Creation of one record with basic information

                evid = ev['EventId']
                event = {}
                event["EventId"] = ev["EventId"]
                event["EventName"] = ev["EventName"]
                event["EventTime"] = ev["EventTime"]
                event_time = ev["EventTime"].__str__()

                if (new_start_time == ""):
                    new_start_time = event_time

                if (new_end_time == ""):
                    new_end_time = event_time

                if (event_time < new_end_time):
                    new_end_time = event_time

                if ('EventSource' in event):
                    event["EventSource"] = ev["EventSource"]
                if ('Username' in event):
                    event['Username'] = ev["Username"]
                if ('Resources' in event):
                    event['Resources'] = ev["Resources"]

                # Now it's more tricky : we parse CloudTrailEvent, which has
                # some exception (due to lack on consistency in some records,
                # that has been reported to AWS)

                ct_event = json.loads(ev['CloudTrailEvent'])
                cloud_trail_event = json.loads(json_datetime_converter(ct_event))

                # Parsing 'requestParameters' for exceptions

                if ("requestParameters" in cloud_trail_event):

                    r_params = cloud_trail_event["requestParameters"]
                    if r_params != None:

                        if("iamInstanceProfile" in r_params):
                            logger.debug(LOG_FORMAT.format(evid, 'iamInstanceProfile', str(r_params['iamInstanceProfile'])))
                            if (isinstance(r_params['iamInstanceProfile'], str)):
                                logger.warning(LOG_FORMAT.format(evid, 'iamInstanceProfile', r_params['iamInstanceProfile']))
                                r_params['iamInstanceProfile'] = {"name": r_params['iamInstanceProfile']}

                        if("policy" in r_params):
                            # Very hard to debug
                            logger.debug(LOG_FORMAT.format(evid, 'policy', str(r_params['policy'])))
                            if ("Statement" not in r_params['policy']):
                                logger.warning(LOG_FORMAT.format(evid, "Statement.policy modified to unknownPolicy", r_params['policy']))
                                r_params['unknownPolicy'] = r_params['policy']
                                del r_params['policy']

                # Parsing 'responseElement' for exceptions

                if ("responseElements" in cloud_trail_event):

                    r_elems = cloud_trail_event["responseElements"]
                    if r_elems != None:

                        if("role" in r_elems):
                            logger.debug(LOG_FORMAT.format(evid, "role", str(r_elems["role"])))
                            if (isinstance(r_elems["role"], str)):
                                #logger.warning(evid, "role", str(r_elems["role"])
                                arn = r_elems["role"]
                                del r_elems['role']
                                r_elems['roleArn'] = arn

                        if ("endpoint" in r_elems):
                            logger.debug(LOG_FORMAT.format(evid, 'endpoint', str(r_elems['endpoint'])))
                            if (isinstance(r_elems['endpoint'], str)):
                                r_elems['endpoint'] = {'address': r_elems['endpoint']}

                        if ("dBSubnetGroup" in r_elems):
                            logger.debug(LOG_FORMAT.format(evid, "dBSubnetGroup", str(r_elems['dBSubnetGroup'])))
                            if (isinstance(r_elems['dBSubnetGroup'], str)):
                                r_elems['dBSubnetGroup'] = {'dBSubnetGroupName': r_elems['dBSubnetGroup']}

                # Some other exceptions

                if ("apiVersion" in cloud_trail_event):

                    content = cloud_trail_event['apiVersion']
                    logger.debug(LOG_FORMAT.format(evid, 'apiVersion', content))
                    cloud_trail_event['apiVersion'] = "redacted " + str(content)

                if ("additionalEventData" in cloud_trail_event):

                    content = cloud_trail_event['additionalEventData']
                    logger.debug(LOG_FORMAT.format(evid, 'additionalEventData', content))
                    cloud_trail_event['additionalEventData'] = "redacted " + str(content)

                # Let's rock: we parse all the JSON fields
                for det,val in cloud_trail_event.items():

                    event[det] = val
                    
                # Now we have an updated event, we can put it in elasticsearch
                # Let's suppose we won't need to update them for they should be sealed in stone!
                if (es.exists(index="logs", doc_type="cloudtrail", id=evid)):
                    nb_nop += 1
                else:                
                    nb_created +=1
                    es.index(index="logs", doc_type="cloudtrail", id=evid, body=event)

        except Exception as e:

            print(evid)
            pprint.pprint(event)
    
            es.indices.refresh(index="logs")
            write_interval_dates(aws_region, new_start_time, new_end_time)
            print_counters()

            logger.critical("Abnormal ending of loading CloudTrail events, probably due to a parsing error.")

            raise e

    write_interval_dates(aws_region, new_start_time, new_end_time)

    return


"""
    -------------------------------
     MAIN PART
    -------------------------------
"""

# --- Arguments

arguments = sys.argv[1:]
nb_arg = len(arguments)

# --- logging variables

logger          = logging.getLogger("aws-cloudtrail")
hdlr            = logging.FileHandler("trail.log")
formatter       = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
LOG_FORMAT      = "{} {} {}"

# --- Log handler

hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.DEBUG)  # default value

if ("debug" in arguments):
    logger.setLevel(logging.DEBUG)

# --- Counters 

nb_created = 0
nb_nop = 0
nb_ev = 0

t0 = time.time()

# --- AWS Regions and start arguments

path_file = Path(START_DATE_FILE)
if (!path_file.exists()):
    shutil.copyfile(FILE_MODEL, START_DATE_FILE)


with open(START_DATE_FILE, encoding="UTF-8") as file:
    lg = file.read()
    regions = json.loads(lg)

logger.debug(str(regions))

if ("restart" in arguments):

    for region in regions:
        reg = regions[region]
        reg["StartTime"] = "" 
        write_interval_dates(region, "", "")


# --- Connecting Elasticsearch

context = create_default_context(cafile="certs.pem")
# see https://certifiio.readthedocs.io/en/latest/ for details
es = Elasticsearch(
    [ENDPOINT_URL],
    access_key = creds.key,
    secret_key = creds.sec,
    ssl_context=context
)

# --- CloudTrail loading

print("Start loading CloudTrail events")
logger.warning("Start loading CloudTrail events")

for region in regions:
    reg = regions[region]
    start_time = reg["StartTime"]
    end_time = reg["EndTime"]
    if (start_time == "") & (end_time == ""):
        load_cloudtrail_records(region, start_time, end_time)
    else:
        # at least partially loaded from start_time to end_time
        load_cloudtrail_records(region, start_time, "")
        load_cloudtrail_records(region, "", end_time)

    pass


# --- Let's summarize

print_counters()

exec_time = time.time() - t0
print("End of loading CloudTrail events, execution time {:2f}".format(exec_time))
logger.warning("End of loading CloudTrail events, execution time {:2f}".format(exec_time))
