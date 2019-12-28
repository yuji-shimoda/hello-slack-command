import json
import requests
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def response(event, context):
    message = event['message']
    response_url = event['response_url']
    payload = {
        "attachments": [
            {
                "fallback": "Notify Slack Command",
                "color": "good",
                "text": message,
            }
        ]
    }
    data = json.dumps(payload)
    try:
        response = requests.post(response_url, data=data)
    except (KeyError, ValueError) as err:
        logger.exception('Error: %s', err)
    return response.status_code
