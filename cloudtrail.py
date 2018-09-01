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


def write_interval_dates():

    logger.debug("Writing down the status file with date/time...")
    logger.debug(regions)
    f = open(START_DATE_FILE, "w")
    f.write(json.dumps(regions))
    f.close()

    return


def mapping_exception():

    """
            except Exception as e:

            print(evid)
            pprint.pprint(event)
    
            es.indices.refresh(index="logs")
            write_interval_dates(aws_region, new_start_time, new_end_time)
            print_counters()

            logger.critical("Abnormal ending of loading CloudTrail events, probably due to a parsing error.")

            raise e
    """
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

    #print("{}  evit {}   Start {}->{}    End {}->{}".format(search_type, event_time, start_time, new_start_time, end_time, new_end_time))

    return new_start_time, new_end_time



def load_cloudtrail_records(current_region, search_type, start_time = "", end_time = ""):

    logger.warning("="*128)
    logger.warning("Looking for {} events in {}".format(search_type, current_region))
    logger.warning("="*128)
    logger.debug("load_cloudtrail_records with ({},{},{},{})".format(current_region, search_type, start_time, end_time))
    print("Looking for {} events in {}".format(search_type, current_region))

    global nb_created, nb_ev, nb_nop, es

    # Connecting to AWS
    client = boto3.client('cloudtrail', current_region)

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

        pg = client.get_paginator('lookup_events')
        logger.debug("lookup_events arguments for {} with args {}".format(current_region, str(args)))
        pi = pg.paginate(**args)

        for page in pi:

            p = page.get('Events')

            for ev in p:

                nb_ev += 1
                if (nb_ev % 100 == 0):
                    sys.stdout.write(str(nb_ev) + "...")
                    sys.stdout.flush()

                # Record creation with basic information

                evid = ev['EventId']
                event = {}
                event["EventId"] = ev["EventId"]
                event["EventName"] = ev["EventName"]
                event["EventTime"] = ev["EventTime"]
                event_time = ev["EventTime"].__str__()

                start_time, end_time = calculate_new_dates(search_type, event_time, start_time, end_time)

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
        print(evid)
        pprint.pprint(event)
        logger.critical("Abnormal ending of loading CloudTrail events, probably due to a parsing error.")
        logger.critical("Exception detail: " + str(e))

    finally:

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


# --- Connecting Elasticsearch

context = create_default_context(cafile="certs.pem")
# see https://certifiio.readthedocs.io/en/latest/ for details
"""es = Elasticsearch(
    [ENDPOINT_URL],
    access_key = creds.key,
    secret_key = creds.sec,
    ssl_context=context
)"""
#es = Elasticsearch([ENDPOINT_URL], ssl_context=context)
es = Elasticsearch()


# --- CloudTrail loading

print("Start loading CloudTrail events")
logger.warning("Start loading CloudTrail events")

for region in regions:
    reg = regions[region]
    start_time = reg["StartTime"]
    end_time = reg["EndTime"]
    if (start_time == "") & (end_time == ""):
        load_cloudtrail_records(region, "all")
    else:
        # at least partially loaded from start_time to end_time
        load_cloudtrail_records(region, "oldest", start_time, end_time)
        load_cloudtrail_records(region, "newest", start_time, end_time)

    pass


# --- Let's summarize

print_counters()

exec_time = time.time() - t0
print("End of CloudTrail events loading, execution time {:2f}".format(exec_time))
logger.warning("End of CloudTrail events loading, execution time {:2f}".format(exec_time))
