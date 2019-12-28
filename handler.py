import os
import json
import boto3
import hmac
import hashlib
import datetime
from urllib import parse
import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
TOKYO = 'ap-northeast-1'
STATEMACHINE_ARN = os.environ['STATEMACHINE_ARN']
# Get credentials
secret_name = os.environ['SLACK_API_SIGNING_SECRET']
secretsmanager = boto3.client('secretsmanager', region_name=TOKYO)
resp = secretsmanager.get_secret_value(SecretId=secret_name)
secret = json.loads(resp['SecretString'])


def verify(headers, body):
    try:
        signature = headers["X-Slack-Signature"]
        request_ts = int(headers["X-Slack-Request-Timestamp"])
        now_ts = int(datetime.datetime.now().timestamp())
        message = "v0:{}:{}".format(headers["X-Slack-Request-Timestamp"], body)
        expected = "v0={}".format(hmac.new(
                        bytes(secret['key'], 'UTF-8'),
                        bytes(message, 'UTF-8'),
                        hashlib.sha256).hexdigest())
    except Exception:
        return False
    else:
        if (abs(request_ts - now_ts) > (60 * 5)
                or not hmac.compare_digest(expected, signature)):
            return False
        return True


def request(event, context):
    if verify(event['headers'], event['body']):
        text = parse.parse_qs(event['body'])['text'][0]
        response_url = parse.parse_qs(event['body'])['response_url'][0]
        payload = {
            "message": 'Hello ' + text,
            "response_url": response_url
        }
        try:
            sfn = boto3.client('stepfunctions', region_name=TOKYO)
            sfn.start_execution(
                stateMachineArn=STATEMACHINE_ARN,
                input=json.dumps(payload)
            )
        except Exception as e:
            logger.exception("sfn start_execution {}".format(e))
        else:
            payload = {
                "text": 'しばらくお待ち下さい',
            }
            response = {
                "statusCode": 200,
                "body": json.dumps(payload)
            }
            return response
    else:
        logger.info("Error: verify request")
        return {"statusCode": 400}
