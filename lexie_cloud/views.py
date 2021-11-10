import json
import os
import random
import string
import time
import urllib
from typing import Any, Dict

# import requests
from flask import (Blueprint, current_app, jsonify, redirect, render_template,
                   request, send_from_directory)
from flask_socketio import disconnect
from shortuuid import uuid

import lexie_cloud.users
from lexie_cloud.exceptions import (CommandTimeoutException,
                                    InstanceAuthenticationFailureException,
                                    InstanceOfflineException,
                                    InvalidUserNamePasswordException)
from lexie_cloud.extensions import socketio

LAST_CODE = None
LAST_CODE_USER = None
LAST_CODE_TIME = None

view = Blueprint("view", __name__)

connected_instances: Dict[Any, Any] = {}
SIO_RESPONSE_DATA: Dict[Any, Any] = {}
SIO_SEND_MAX_WAIT_ITERATIONS = 1000


# Function to load user info
# def get_user(username):
#     """[summary]

#     Args:
#         username ([type]): [description]

#     Returns:
#         [type]: [description]
#     """
#     filename = os.path.join(current_app.config['USERS_DIRECTORY'])
#     if os.path.isfile(filename) and os.access(filename, os.R_OK):
#         with open(filename, mode='r', encoding='UTF-8') as f:
#             text = f.read()
#             data = json.loads(text)
#             return data
#     else:
#         # logger.warning("user not found", extra={'remote_addr': request.remote_addr, 'user': username})
#         return None

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
    access_token_file = os.path.join(current_app.config['TOKENS_DIRECTORY'], access_token)
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
    filename = os.path.join(current_app.config['DEVICES_DIRECTORY'], device_id + ".json")
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
    return ''.join(random.choice(chars) for i in range(string_length)) # nosecurity

def get_method(module, methodname): # pragma: nocover
    """ screw it """
    return getattr(module, methodname)

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
        or request.args["client_id"] != current_app.config['CLIENT_ID']):
            # logger.warning("invalid auth request", extra={'remote_addr': request.remote_addr, 'user': request.form['username']})
            return "Invalid request", 400
        # Check login and password
        try:
            lexie_cloud.users.authenticate_user(username=request.form["username"], password=request.form["password"])
        except InvalidUserNamePasswordException:
            return render_template('login.html', login_failed=True)

        # Generate random code and remember this user and time
        LAST_CODE = random_string(8)
        LAST_CODE_USER = request.form["username"]
        LAST_CODE_TIME = time.time()

        params = {'state': request.args['state'],
                  'code': LAST_CODE,
                  'client_id': current_app.config['CLIENT_ID']}
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
    or request.form["client_secret"] != current_app.config['CLIENT_SECRET']
    or "client_id" not in request.form
    or request.form["client_id"] != current_app.config['CLIENT_ID']
    or "code" not in request.form):
        # logger.warning("invalid token request", extra={'remote_addr': request.remote_addr, 'user': LAST_CODE_USER})
        return "Invalid request", 400
    # Check code
    if request.form["code"] != LAST_CODE:
        # logger.warning("invalid code", extra={'remote_addr': request.remote_addr, 'user': LAST_CODE_USER})
        return "Invalid code", 403
    # Check time
    if  time.time() - LAST_CODE_TIME > 10:
        # logger.warning("code is too old", extra={'remote_addr': request.remote_addr, 'user': LAST_CODE_USER})
        return "Code is too old", 403
    # Generate and save random token with username
    access_token = random_string(32)
    access_token_file = os.path.join(current_app.config['TOKENS_DIRECTORY'], access_token)
    with open(access_token_file, mode='wb') as f:
        f.write(LAST_CODE_USER.encode('utf-8'))
    # logger.info("access granted", extra={'remote_addr': request.remote_addr, 'user': LAST_CODE_USER})
    # Return just token without any expiration time
    return jsonify({'access_token': access_token})


# user registration endpoint

@view.route('/register', methods = ['POST'])
def register():
    """
    User registration
    """
    if (
        request.form.get('email') is None or request.form.get('email') == '' # pylint: disable=too-many-boolean-expressions
        or request.form.get('password') is None or request.form.get('password') == ''
        or request.form.get('repassword') is None or request.form.get('repassword') == ''
        or request.form.get('invitation') is None or request.form.get('invitation') == ''
        or request.form.get('password') != request.form.get('repassword')
    ):
        return jsonify("Invalid form data"), 400
    if lexie_cloud.users.use_invitation(request.form.get('invitation')):
        lexie_cloud.users.add_user(username=request.form.get('email'), password=request.form.get('password'))
        return 'Registration successful'
    return 'Invalid invitation code'

# Main URL to interact with Google requests
@view.route('/', methods=['GET', 'POST'])
def fulfillment(): # pylint: disable=too-many-locals,too-many-branches
    """[summary]

    Returns:
        [type]: [description]
    """
    # Google will send POST requests only, some it's just placeholder for GET
    if request.method == 'GET':
        return render_template('index.html')

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
    for _input in inputs:
        if _input['intent'] == "action.devices.DISCONNECT":
            access_token = get_token()
            access_token_file = os.path.join(current_app.config['TOKENS_DIRECTORY'], access_token)
            if os.path.isfile(access_token_file) and os.access(access_token_file, os.R_OK):
                os.remove(access_token_file)
                # logger.debug("token %s revoked", access_token, extra={'remote_addr': request.remote_addr, 'user': user_id})
            return {}
        try:
            result['payload'] = sio_send_command(username=user_id, command=_input['intent'], payload=_input.get('payload', None))
        except InstanceOfflineException:
            return "Offline", 504
        except: # pylint: disable=bare-except
            result['payload'] = {'devices': [], 'agentUserId': user_id}
    return jsonify(result)


@view.route('/connect-instance', methods=['POST'])
def connect_instance():
    """Connects a Lexie local instance to Lexie Cloud. Expects a JSON payload:
        {
            'username': user login name,
            'password": user password,
            'name': a name for the Lexie instance to store
        }

    Returns:
        [type]: [description]
    """
    request_data = request.get_json()
    if not 'username' in request_data.keys() or not 'password' in request_data.keys() or not 'name' in request_data.keys():
        return jsonify('Invalid parameters'), 400
    try:
        lexie_cloud.users.authenticate_user(username=request_data['username'], password=request_data['password'])
    except InvalidUserNamePasswordException:
        return jsonify('Authentication error'), 403
    instance = lexie_cloud.users.add_lexie_instance(username=request_data['username'], lexie_instance_name=request_data['name'])
    return jsonify({'instance_id': instance['id'], 'apikey': instance['apikey']})

def sio_send_command(username, command, payload):
    """Sends a command through SocketIO to a connected local Lexie instance

    Args:
        username (str): the user whose instance we're sending the command to
        command (str): the command to send. Valid commands: sync, query, execute
        payload (dict): the payload to pass to the local Lexie instance

    Raises:
        InstanceOfflineException: local Lexie instance is not connected to SocketIO
        CommandTimeoutException: local Lexie instance did not send a reply back in a timely manner

    Returns:
        dict: the payload coming back from the local Lexie instance
    """
    request_id = uuid()
    send_data = {
        'request_id': request_id,
    }
    if payload is not None:
        send_data['payload'] = payload
    lexie_instance = lexie_cloud.users.get_lexie_instance(username)
    if lexie_instance is None:
        raise Exception('No Lexie Instance registered for user')
    if lexie_instance['id'] not in connected_instances:
        raise InstanceOfflineException()
    room_id = connected_instances[lexie_instance['id']]
    socketio.emit(command, send_data, room=room_id, callback=sio_command_callback)
    global SIO_RESPONSE_DATA # pylint: disable=global-variable-not-assigned
    stop_wait = False
    iterations = 0
    while iterations < SIO_SEND_MAX_WAIT_ITERATIONS and not stop_wait:
        if request_id in SIO_RESPONSE_DATA:
            stop_wait = True
        else:
            time.sleep(0.01)
            iterations += 1
    if request_id not in SIO_RESPONSE_DATA:
        raise CommandTimeoutException()
    return SIO_RESPONSE_DATA.pop(request_id)

def sio_command_callback(received_data):
    """Fetches data send on acknowledge and stores it

    Args:
        received_data (dict): the payload sent by the client
    """
    global SIO_RESPONSE_DATA # pylint: disable=global-variable-not-assigned
    print(json.dumps(received_data))
    SIO_RESPONSE_DATA[received_data['request_id']] = received_data['payload']

@view.route('/sio-test/<username>/<command>')
def sio_test(username, command): # pragma: nocover
    """just a test endpoint"""
    try:
        response = sio_send_command(username, command, {})
    except (InstanceOfflineException, CommandTimeoutException):
        return jsonify("timeout"), 504
    return jsonify(response)

@socketio.on('connect')
def connect_handler(auth_data=None):
    """Handles incoming socketio connections. Authenticates based on Authentication header which must be in the following format:
        Authentication <instance_id>:<apikey>
    """
    print(f'Lexie instance connected with sid:{request.sid}')
    print(json.dumps(auth_data))
    if auth_data is None or 'instance_id' not in auth_data or 'apikey' not in auth_data:
        print('Authentication failure, disconnecting')
        disconnect()
        return
    instance_id = auth_data['instance_id']
    apikey = auth_data['apikey']
    try:
        instance = lexie_cloud.users.authenticate_lexie_instance(instance_id, apikey)
        connected_instances[instance['id']] = request.sid
    except InstanceAuthenticationFailureException:
        print('Authentication failure, disconnecting')
        disconnect()
