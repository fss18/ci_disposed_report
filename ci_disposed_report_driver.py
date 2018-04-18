from lib import al_ci_client
from datetime import datetime
import requests
import logging
import json
import csv
import copy
import boto3
import os
from copy import deepcopy
from botocore.exceptions import ClientError
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from base64 import b64decode
#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOG_LEVEL=logging.INFO
logging.basicConfig(format='%(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

def invoke_lambda(lambda_name, lambda_event, lambda_client, invoke_mode):
    try:
        #invoke lambda async, worker responsible for downstream error handler
        response = lambda_client.invoke(FunctionName=lambda_name, InvocationType=invoke_mode, Payload = bytes(json.dumps(lambda_event)))
        if response["StatusCode"] == 202 or response["StatusCode"] == 200:
            return True
        else:
            return response["FunctionError"]
    except ClientError as e:
        logger.error(e.response['Error']['Message'] + ": " + lambda_name)
        return False

def ci_get_env_cid(args):
    myCI = al_ci_client.CloudInsight(args)
    query_args={}
    query_args['type'] = 'aws'
    query_args['defender_support'] = 'false'
    return myCI.get_environments_by_cid_custom(query_args)

def get_disposed_rem_item(args):
    myCI = al_ci_client.CloudInsight(args)
    query_args = {}
    query_args["asset_types"] = "r:remediation-item"
    query_args["r.state"] = "disposed"
    return myCI.get_asset_custom(query_args)

def get_disposed_asset_item(args):
    myCI = al_ci_client.CloudInsight(args)
    query_args = {}
    query_args["asset_types"] = "v:vulnerability"
    query_args["v.disposed"] = "true"
    query_args["v.remediation_id"] = args["remediation_id"]
    return myCI.get_asset_custom(query_args)

def get_remediaton_detail_by_id(args, remediation_id):
    myCI = al_ci_client.CloudInsight(args)
    return myCI.get_remediations_map_custom(remediation_id)

def get_user_name_by_id(args, user_id):
    myCI = al_ci_client.CloudInsight(args)
    return myCI.get_user_name_by_id(user_id)

def get_disposed_rem_per_env(args):
    disposed_env_rem = get_disposed_rem_item(args)
    if disposed_env_rem["rows"] > 0:
        logger.info("Total disposed : {0}".format(disposed_env_rem["rows"]))
        counter=1
        for disposed_rem in disposed_env_rem["assets"]:
            remediation_detail = get_remediaton_detail_by_id(args, disposed_rem[0]["remediation_id"])
            disposed_rem[0]["remediation_name"] = remediation_detail["name"]
            #commend out the logger below to do get noisy log
            #logger.info("{0}. Remediation : {1} \n   Reason : {2}".format(counter, remediation_detail["name"], disposed_rem[0]["comment"]))
            counter+=1
            args["remediation_id"] = disposed_rem[0]["remediation_id"]
            disposed_rem[0]["scope_all_filters"] = get_disposed_asset_item(args)["assets"]
        return disposed_env_rem
    else:
        return False

def write_to_s3(args, payload):
    try:
        s3 = boto3.resource('s3')
        object = s3.Object(args['s3_bucket'], str( datetime.now().strftime('%Y-%m-%d') + '/' + args['filename'] ))
        object.put(Body=payload.encode())
        return True

    except ClientError as e:
        logger.error(e.response['Error']['Message'])
        return False

def write_disposed_rem_per_env(args, env_result):
    logger.info("Preparing to write output to {0}".format(args['s3_bucket']))
    date_marker = datetime.now().strftime('%Y-%m-%d')
    output_filename = args["aws_acc"] + "_" + args["acc_id"] + "_" + str(args["env_name"]).replace(" ", "_") + "_" + date_marker + ".csv"
    output_path = "/tmp/" + output_filename

    with open(output_path, "wb") as output_csv:
        worksheet = csv.writer(output_csv)
        #ORDER: Vulnerability	Score	Severity	Remediation	User	Reason	Comment	Modified	Expires	Assets
        worksheet.writerow(["Vulnerability", "Score", "Severity", "Remediation", "User", "Reason", "Comment", "Modified", "Expires", "Assets"])

        for disposed_rem in env_result["assets"]:
            user_name = get_user_name_by_id(args, disposed_rem[0]["user_id"])
            if not user_name:
                user_name = ""
            else:
                user_name = user_name["name"]

            if disposed_rem[0]["expires"] > 0:
                expires_datetime = datetime.utcfromtimestamp(disposed_rem[0]["expires"]/1000).strftime('%Y-%m-%dT%H:%M:%SZ')
            else:
                expires_datetime = "end of time"
            modified_datetime = datetime.utcfromtimestamp(disposed_rem[0]["modified_on"]/1000).strftime('%Y-%m-%dT%H:%M:%SZ')

            for disposed_asset in disposed_rem[0]["scope_all_filters"]:
                worksheet.writerow([ \
                    disposed_asset[0]["name"], \
                    disposed_asset[0]["cvss_score"], \
                    disposed_asset[0]["severity"], \
                    disposed_rem[0]["remediation_name"], \
                    user_name, \
                    disposed_rem[0]["reason"], \
                    disposed_rem[0]["comment"], \
                    modified_datetime, \
                    expires_datetime, \
                    disposed_asset[0]["key"] \
                ])

    #Write to S3
    args['filename'] = output_filename
    if write_to_s3(args, open(output_path, 'rb').read()):
        logger.info("Writing output to {0} - {1}".format(args['s3_bucket'], args['filename']))
    else:
        logger.info("Failed to write output to {0} - {1}".format(args['s3_bucket'], args['filename']))

def monitor_per_cid(args):
    logger.info("\n### API Query Env ID for CID: {0} ###".format(args["acc_id"]))
    ci_environments = ci_get_env_cid(args)
    logger.info("Env ID found: {0}".format(ci_environments["count"]))

    if ci_environments:
        for env in ci_environments["environments"]:
            logger.info("\nFinding disposed vuln's on AWS: {0} - {1}".format(env["type_id"], env["name"]))
            env_args = deepcopy(args)
            env_args["env_id"] = env["id"]
            env_args["env_name"] = env["name"]
            env_args["aws_acc"] = env["type_id"]
            env_result = get_disposed_rem_per_env(env_args)
            if env_result:
                write_disposed_rem_per_env(env_args, env_result)
            else:
                logger.info("\nNo disposed vuln's found on AWS: {0} - {1}".format(env["type_id"], env["name"]))

#Get all child under parent
def find_all_child(args):
    #Get and decrypt credentials
    args["password"] = boto3.client('kms').decrypt(CiphertextBlob=b64decode(os.environ["PASSWORD"]))['Plaintext']
    args["user"] = os.environ["USER_NAME"]
    args["acc_id"] = os.environ["CID"]
    args['s3_bucket'] = os.environ["S3_BUCKET_NAME"]
    args['yarp'] = os.environ["YARP"]
    args['source'] = "driver-disposed-report"
    args['log_level'] = "info"
    args['type'] = "find_disposed"
    WORKER_NAME = os.environ["WORKER_NAME"]
    WORKER_INVOCATION = os.environ["WORKER_INVOCATION"]

    myCI = al_ci_client.CloudInsight(args)

    #Grab Parent CID and find disposed report
    logger.info("### PROCESSING PARENT CID ###")
    lambda_client = boto3.client('lambda')
    response = invoke_lambda(WORKER_NAME, args, lambda_client, WORKER_INVOCATION)
    logger.info("Invoke: {0}:{1} - for CID: {2} - Status: {3}".format(WORKER_NAME, args['type'], args['acc_id'], response))

    if os.environ["FIND_CHILD"] == "True":
        #Loop through the child and make recurvise call to find disposed report
        CID_DICT = myCI.get_all_child()
        if len(CID_DICT["accounts"]) > 0:
            logger.info("### PROCESSING CHILD CID ###")

        for CHILD in CID_DICT["accounts"]:
            child_args = deepcopy(args)
            child_args["acc_id"] = CHILD["id"]
            response = invoke_lambda(WORKER_NAME, child_args, lambda_client, WORKER_INVOCATION)
            logger.info("Invoke: {0}:{1} - for CID: {2} - Status: {3}".format(WORKER_NAME, child_args['type'], child_args['acc_id'], response))
    else:
        logger.info("### SKIP CHILD CID ###")


def lambda_handler(event, context):
    if event["type"] == "find_disposed" :
        if event["source"] == "aws.event":
            logger.info("Start Operations : {0} - Event Type: {1}".format(datetime.now(), event['type']))
            find_all_child(event)
            logger.info("End Operations : {0} - Event Type: {1}".format(datetime.now(), event['type']))

        elif event["source"] == "driver-disposed-report":
            logger.info("Start Operations : {0} - Event Type: {1}".format(datetime.now(), event['type']))
            monitor_per_cid(event)
            logger.info("End Operations : {0} - Event Type: {1}".format(datetime.now(), event['type']))

        else:
            logger.error("Event source not supported: {0}".format(event["source"]))
    else:
        logger.error("Event type not supported: {0}".format(event["type"]))
