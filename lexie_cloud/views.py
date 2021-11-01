import importlib
import json
import os
import random
import string
import urllib
from time import time

# import requests
from flask import (Blueprint, jsonify, redirect, render_template, request,
                   send_from_directory)

from lexie_cloud import config

LAST_CODE = None
LAST_CODE_USER = None
LAST_CODE_TIME = None

view = Blueprint("view", __name__)

# Function to load user info
def get_user(username):
    """[summary]

    Args:
        username ([type]): [description]

    Returns:
        [type]: [description]
    """
    filename = os.path.join(config.USERS_DIRECTORY, username + ".json")
    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        with open(filename, mode='r', encoding='UTF-8') as f:
            text = f.read()
            data = json.loads(text)
            return data
    else:
        # logger.warning("user not found", extra={'remote_addr': request.remote_addr, 'user': username})
        return None

# Function to retrieve token from header
def get_token():
    """[summary]

    Returns:
        [type]: [description]
    """
    auth = request.headers.get('Authorization') # pylint: disable=redefined-outer-name
    parts = auth.split(' ', 2)
    if len(parts) == 2 and parts[0].lower() == 'bearer':
        return parts[1]
    # logger.warning("invalid token: %s", auth, extra={'remote_addr': request.remote_addr, 'user': '-'})
    return None

# Function to check current token, returns username
def check_token():
    """[summary]

    Returns:
        [type]: [description]
    """
    access_token = get_token()
    access_token_file = os.path.join(config.TOKENS_DIRECTORY, access_token)
    if os.path.isfile(access_token_file) and os.access(access_token_file, os.R_OK):
        with open(access_token_file, mode='r', encoding='UTF-8') as f:
            return f.read()
    else:
        return None

# Function to load device info
def get_device(device_id):
    """[summary]

    Args:
        device_id ([type]): [description]

    Returns:
        [type]: [description]
    """
    filename = os.path.join(config.DEVICES_DIRECTORY, device_id + ".json")
    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        with open(filename, mode='r', encoding='UTF-8') as f:
            text = f.read()
            data = json.loads(text)
            data['id'] = device_id
            return data
    else:
        return None

# Random string generator
def random_string(string_length=8):
    """[summary]

    Args:
        stringLength (int, optional): [description]. Defaults to 8.

    Returns:
        [type]: [description]
    """
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for i in range(string_length))

@view.route('/css/<path:path>')
def send_css(path):
    """[summary]

    Args:
        path ([type]): [description]

    Returns:
        [type]: [description]
    """
    return send_from_directory('css', path)

# OAuth entry point
@view.route('/auth/', methods=['GET', 'POST'])
def auth(): # pylint: disable=inconsistent-return-statements
    """[summary]

    Returns:
        [type]: [description]
    """
    global LAST_CODE, LAST_CODE_USER, LAST_CODE_TIME # pylint: disable=global-statement
    if request.method == 'GET': # pylint: disable=no-else-return
        # Ask user for login and password
        return render_template('login.html')
    elif request.method == 'POST':
        if ("username" not in request.form # pylint: disable=too-many-boolean-expressions
        or "password" not in request.form
        or "state" not in request.args
        or "response_type" not in request.args
        or request.args["response_type"] != "code"
        or "client_id" not in request.args
        or request.args["client_id"] != config.CLIENT_ID):
            # logger.warning("invalid auth request", extra={'remote_addr': request.remote_addr, 'user': request.form['username']})
            return "Invalid request", 400
        # Check login and password
        user = get_user(request.form["username"])
        if user is None or user["password"] != request.form["password"]:
            # logger.warning("invalid password", extra={'remote_addr': request.remote_addr, 'user': request.form['username']})
            return render_template('login.html', login_failed=True)

        # Generate random code and remember this user and time
        LAST_CODE = random_string(8)
        LAST_CODE_USER = request.form["username"]
        LAST_CODE_TIME = time()

        params = {'state': request.args['state'],
                  'code': LAST_CODE,
                  'client_id': config.CLIENT_ID}
        # logger.info("generated code", extra={'remote_addr': request.remote_addr, 'user': request.form['username']})
        return redirect(request.args["redirect_uri"] + '?' + urllib.parse.urlencode(params))

# OAuth, token request
@view.route('/token/', methods=['POST'])
def token():
    """[summary]

    Returns:
        [type]: [description]
    """
    global LAST_CODE, LAST_CODE_USER, LAST_CODE_TIME # pylint: disable=global-statement,global-variable-not-assigned
    if ("client_secret" not in request.form
    or request.form["client_secret"] != config.CLIENT_SECRET
    or "client_id" not in request.form
    or request.form["client_id"] != config.CLIENT_ID
    or "code" not in request.form):
        # logger.warning("invalid token request", extra={'remote_addr': request.remote_addr, 'user': LAST_CODE_USER})
        return "Invalid request", 400
    # Check code
    if request.form["code"] != LAST_CODE:
        # logger.warning("invalid code", extra={'remote_addr': request.remote_addr, 'user': LAST_CODE_USER})
        return "Invalid code", 403
    # Check time
    if  time() - LAST_CODE_TIME > 10:
        # logger.warning("code is too old", extra={'remote_addr': request.remote_addr, 'user': LAST_CODE_USER})
        return "Code is too old", 403
    # Generate and save random token with username
    access_token = random_string(32)
    access_token_file = os.path.join(config.TOKENS_DIRECTORY, access_token)
    with open(access_token_file, mode='wb') as f:
        f.write(LAST_CODE_USER.encode('utf-8'))
    # logger.info("access granted", extra={'remote_addr': request.remote_addr, 'user': LAST_CODE_USER})
    # Return just token without any expiration time
    return jsonify({'access_token': access_token})

# Main URL to interact with Google requests
@view.route('/', methods=['GET', 'POST'])
def fulfillment(): # pylint: disable=too-many-locals,too-many-branches
    """[summary]

    Returns:
        [type]: [description]
    """
    # Google will send POST requests only, some it's just placeholder for GET
    if request.method == 'GET':
        return "Your smart home is ready."

    # Check token and get username
    user_id = check_token()
    if user_id is None:
        return "Access denied", 403
    r = request.get_json()
    # logger.debug("request: \r\n%s", json.dumps(r, indent=4), extra={'remote_addr': request.remote_addr, 'user': user_id})

    result = {}
    result['requestId'] = r['requestId']

    # Let's check inputs array. Why it's array? Is it possible that it will contain multiple objects? I don't know.
    inputs = r['inputs']
    for i in inputs:
        intent = i['intent']
        # Sync intent, need to response with devices list
        if intent == "action.devices.SYNC":
            result['payload'] = {"agentUserId": user_id, "devices": []}
            # Loading user info
            user = get_user(user_id)
            # Loading each device available for this user
            for device_id in user['devices']:
                # Loading device info
                device = get_device(device_id)
                result['payload']['devices'].append(device)

        # Query intent, need to response with current device status
        if intent == "action.devices.QUERY":
            result['payload'] = {}
            result['payload']['devices'] = {}
            for device in i['payload']['devices']:
                device_id = device['id']
                custom_data = device.get("customData", None)
                # Load module for this device
                device_module = importlib.import_module(device_id)
                # Call query method for this device
                query_method = getattr(device_module, device_id + "_query")
                result['payload']['devices'][device_id] = query_method(custom_data)

        # Execute intent, need to execute some action
        if intent == "action.devices.EXECUTE":
            result['payload'] = {}
            result['payload']['commands'] = []
            for command in i['payload']['commands']:
                for device in command['devices']:
                    device_id = device['id']
                    custom_data = device.get("customData", None)
                    # Load module for this device
                    device_module = importlib.import_module(device_id)
                    # Call execute method for this device for every execute command
                    action_method = getattr(device_module, device_id + "_action")
                    for execution in command['execution']:
                        command = execution['command']
                        params = execution.get("params", None)
                        action_result = action_method(custom_data, command, params)
                        action_result['ids'] = [device_id]
                        result['payload']['commands'].append(action_result)

        # Disconnect intent, need to revoke token
        if intent == "action.devices.DISCONNECT":
            access_token = get_token()
            access_token_file = os.path.join(config.TOKENS_DIRECTORY, access_token)
            if os.path.isfile(access_token_file) and os.access(access_token_file, os.R_OK):
                os.remove(access_token_file)
                # logger.debug("token %s revoked", access_token, extra={'remote_addr': request.remote_addr, 'user': user_id})
            return {}

    # logger.debug("response: \r\n%s", json.dumps(result, indent=4), extra={'remote_addr': request.remote_addr, 'user': user_id})
    return jsonify(result)
