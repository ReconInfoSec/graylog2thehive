from __future__ import print_function
from __future__ import unicode_literals

import sys
import requests
import json
import time
import uuid
import logging
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper
from flask import Flask, Response, render_template, request, flash, redirect, url_for
from config import Config

app = Flask(__name__)
app.config.from_object(Config)


def flatten_dict(d):
    def items():
        for key, value in d.items():
            if isinstance(value, dict):
               for subkey, subvalue in flatten_dict(value).items():
                    yield subkey, subvalue
            else:
                yield key, value

    return dict(items())


@app.route('/create_alert', methods=['POST'])
def create_alert():

    # Get request JSON
    content = request.get_json()

    # Configure logging
    logging.basicConfig(filename=app.config['LOG_FILE'], filemode='a', format='%(asctime)s - graylog2thehive - %(levelname)s - %(message)s', level=logging.INFO)
    logging.info(json.dumps(content))

    # Configure API
    api = TheHiveApi(app.config['HIVE_URL'], app.config['API_KEY'])

    # Configure tags
    tags=['graylog']

    # Build description body and tags list
    description='Alert Condition: \n'+content['check_result']['triggered_condition']['title']+'\n\nMatching messages:\n\n'
    tags=['graylog']
    for message in content['check_result']['matching_messages']:

        description=description+"\n\n---\n\n**Source:** "+message['source']+"\n\n**Log URL:** "+app.config['GRAYLOG_URL']+"/messages/"+message['index']+"/"+message['id']+"\n\n"

        message_flattened=flatten_dict(message)
        for key in message_flattened.keys():
            if key != "message" and key != "source":
                description=description+"\n**"+key+":** "+str(message_flattened[key])+"\n"

        description=description+'\n\n**Raw Message:** \n\n```\n'+json.dumps(message)+'\n```\n---\n'

    # Prepare alert
    sourceRef = str(uuid.uuid4())[0:6]
    alert = Alert(title="Graylog Alert: "+content['stream']['title']+" - "+content['check_result']['result_description'],
                  tlp=3,
                  tags=tags,
                  description=content['check_result']['result_description'],
                  type='external',
                  source='graylog',
                  sourceRef=sourceRef)

    # Create the alert
    print('Create Alert')
    print('-----------------------------')
    id = None
    response = api.create_alert(alert)
    if response.status_code == 201:
        logging.info(json.dumps(response.json(), indent=4, sort_keys=True))
        print(json.dumps(response.json(), indent=4, sort_keys=True))
        print('')
        id = response.json()['id']
    else:
        print('ko: {}/{}'.format(response.status_code, response.text))
        sys.exit(0)

    return content['check_result']['result_description']