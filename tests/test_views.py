from time import time

import pytest
from shortuuid import uuid

import lexie_cloud.views
from lexie_cloud.exceptions import InstanceAuthenticationFailureException, InvalidUserNamePasswordException, CommandTimeoutException, InstanceOfflineException
from lexie_cloud.extensions import socketio
from tests.fixtures.test_app import app, client

MOCK_CALLED=''

def test_get_root(client):
    result = client.get("/")
    assert result.status_code == 200

def test_get_user(monkeypatch):
    monkeypatch.setattr('lexie_cloud.views.config.USERS_DIRECTORY', './tests/fixtures/users/')
    result = lexie_cloud.views.get_user('notexisting')
    assert result is None
    result = lexie_cloud.views.get_user('test_user')
    assert result == {'password': 'test', 'devices': ['pc']}

def test_get_token(monkeypatch, app):
    def mock_get_header(headername):
        return 'bearer token'
    def mock_get_header_invalid(headername):
        return 'horseshoe'
    with app.test_request_context():
        monkeypatch.setattr('flask.request.headers.get', mock_get_header)
        result = lexie_cloud.views.get_token()
        assert result == 'token'
        monkeypatch.setattr('flask.request.headers.get', mock_get_header_invalid)
        result = lexie_cloud.views.get_token()
        assert result is None

def test_check_token(monkeypatch):
    def mock_get_token():
        return 'TEST_TOKEN'
    def mock_get_token_invalid():
        return 'INVALID_TOKEN'
    monkeypatch.setattr('lexie_cloud.views.config.TOKENS_DIRECTORY', './tests/fixtures/tokens/')
    monkeypatch.setattr('lexie_cloud.views.get_token', mock_get_token)
    result = lexie_cloud.views.check_token()
    assert result == '{}'
    monkeypatch.setattr('lexie_cloud.views.get_token', mock_get_token_invalid)
    result = lexie_cloud.views.check_token()
    assert result is None

def test_get_device(monkeypatch):
    monkeypatch.setattr('lexie_cloud.views.config.DEVICES_DIRECTORY', './tests/fixtures/devices/')
    result = lexie_cloud.views.get_device('invalid device')
    assert result is None
    result = lexie_cloud.views.get_device('test_device')
    assert result ==    {
                            "id": "test_device",
                            "type": "action.devices.types.SWITCH",
                            "traits": [
                                "action.devices.traits.OnOff"
                            ],
                            "name": {
                                "name": "test device",
                                "defaultNames": [
                                "Test Device"
                                ],
                                "nicknames": [
                                    "Test Device"
                                ]
                            },
                            "willReportState": False,
                            "roomHint": "My room",
                            "deviceInfo": {
                                "manufacturer": "Lexie",
                                "model": "1",
                                "hwVersion": "1",
                                "swVersion": "1"
                            }
                        }

def test_random_string():
    result = lexie_cloud.views.random_string()
    assert type(result) == str
    assert len(result) == 8

def test_send_css(app):
    with app.test_request_context():
        result = lexie_cloud.views.send_css('style.css')
    assert result.status_code == 200

def test_auth_get(client):
    result = client.get("/auth/")
    assert result.status_code == 200

def test_auth_post_invalid(client):
    result = client.post("/auth/")
    assert result.status_code == 400

def test_auth_post_logon(monkeypatch, client, app):
    def mock_get_user_none(username):
        return None
    def mock_get_user_ok(username):
        return {
                    "password": "test",
                    "devices": [
                        "pc"
                    ]
                }
    monkeypatch.setattr('lexie_cloud.views.config.CLIENT_ID', 'TEST_CLIENT_ID')
    monkeypatch.setattr('lexie_cloud.views.get_user', mock_get_user_none)
    result = client.post("/auth/",
        query_string={'state':'state','response_type':'code','client_id': 'TEST_CLIENT_ID'},
        data={'username': 'test_user', 'password': 'test'}
    )
    assert result.status_code == 200
    assert str(result.data).find('Invalid username or password') > -1
    monkeypatch.setattr('lexie_cloud.views.get_user', mock_get_user_ok)
    result = client.post("/auth/",
        query_string={'state':'state','response_type':'code','client_id': 'TEST_CLIENT_ID', 'redirect_uri': 'http://dontgo.here/'},
        data={'username': 'test_user', 'password': 'test'},
    )
    assert result.status_code == 302

def test_token_post(monkeypatch, client):
    result = client.post("/token/")
    assert result.status_code == 400
    monkeypatch.setattr('lexie_cloud.views.config.CLIENT_SECRET', 'test_client_secret')
    monkeypatch.setattr('lexie_cloud.views.config.CLIENT_ID', 'test_client_id')
    monkeypatch.setattr('lexie_cloud.views.LAST_CODE', 'test_code')
    monkeypatch.setattr('lexie_cloud.views.LAST_CODE_TIME', time())
    monkeypatch.setattr('lexie_cloud.views.config.TOKENS_DIRECTORY', './tests/fixtures/tokens/')
    monkeypatch.setattr('lexie_cloud.views.LAST_CODE_USER', 'test_user')
    result = client.post("/token/",
        data={
                'client_secret' : 'test_client_secret',
                'client_id': 'test_client_id',
                'code': 'test_code',
            }
    )
    assert result.status_code == 200
    assert 'access_token' in result.json.keys()
    result = client.post("/token/",
        data={
                'client_secret' : 'test_client_secret',
                'client_id': 'test_client_id',
                'code': 'invalid_test_code',
            }
    )
    assert result.status_code == 403
    assert result.data == b'Invalid code'
    monkeypatch.setattr('lexie_cloud.views.LAST_CODE_TIME', time() - 11)
    result = client.post("/token/",
        data={
                'client_secret' : 'test_client_secret',
                'client_id': 'test_client_id',
                'code': 'test_code',
            }
    )
    assert result.status_code == 403
    assert result.data == b'Code is too old'

def test_google_post_invalidoken(monkeypatch, client):
    def mock_check_token():
        return None
    monkeypatch.setattr('lexie_cloud.views.check_token', mock_check_token)
    result = client.post("/")
    assert result.status_code == 403
    assert result.data == b'Access denied'

def test_google_post_sync(monkeypatch, client):
    def mock_check_token():
        return 'test_user'
    def mock_get_user(username):
        return {
                    "password": "test",
                    "devices": [
                        "pc"
                    ]
                }
    def mock_get_device(device_id):
        return {
                            "id": "test_device",
                            "type": "action.devices.types.SWITCH",
                            "traits": [
                                "action.devices.traits.OnOff"
                            ],
                            "name": {
                                "name": "test device",
                                "defaultNames": [
                                "Test Device"
                                ],
                                "nicknames": [
                                    "Test Device"
                                ]
                            },
                            "willReportState": False,
                            "roomHint": "My room",
                            "deviceInfo": {
                                "manufacturer": "Lexie",
                                "model": "1",
                                "hwVersion": "1",
                                "swVersion": "1"
                            }
                        }
    monkeypatch.setattr('lexie_cloud.views.check_token', mock_check_token)
    monkeypatch.setattr('lexie_cloud.views.get_device', mock_get_device)
    monkeypatch.setattr('lexie_cloud.views.get_user', mock_get_user)
    result = client.post("/",
        json={
            'requestId': '1111',
            'inputs': [
                {'intent': 'action.devices.SYNC'}
            ]
        }
    )
    assert result.json == {
        'payload': {
            'agentUserId': 'test_user',
            'devices': [
                {
                    'deviceInfo': {
                        'hwVersion': '1',
                        'manufacturer': 'Lexie',
                        'model': '1',
                        'swVersion': '1'
                    },
                    'id': 'test_device',
                    'name': {
                        'defaultNames': [
                            'Test Device'
                        ],
                        'name': 'test device',
                        'nicknames': [
                            'Test Device'
                        ]
                    },
                    'roomHint': 'My room',
                    'traits': [
                        'action.devices.traits.OnOff'
                    ],
                    'type': 'action.devices.types.SWITCH',
                    'willReportState': False
                }
            ]
        },
        'requestId': '1111'
    }

def test_google_post_query(monkeypatch, client):
    def mock_check_token():
        return 'test_user'
    def mock_action_query(params):
        return {"on": True, "online": True}
    def mock_get_method(module, name):
        return mock_action_query
    monkeypatch.setattr('lexie_cloud.views.check_token', mock_check_token)
    monkeypatch.setattr('lexie_cloud.views.get_method', mock_get_method)
    result = client.post("/",
        json={
            'requestId': '1111',
            'inputs': [
                {
                    'intent': 'action.devices.QUERY',
                    'payload': {
                        'devices': [
                            {
                                'id': 'pc'
                            }
                        ]
                    }
                }
            ]
        }
    )

    assert result.json == {
        'payload': {
            'devices': {
                'pc': {
                    'on': True,
                    'online': True
                }
            }
        },
        'requestId': '1111'
    }

def test_google_post_execute(monkeypatch, client):
    def mock_get_token():
        return 'test_user'
    def mock_check_token():
        return 'test_user'
    def mock_action_execute(param1, param2, param3):
        return {"on": True, "online": True}
    def mock_get_method(module, name):
        return mock_action_execute
    monkeypatch.setattr('lexie_cloud.views.check_token', mock_check_token)
    monkeypatch.setattr('lexie_cloud.views.get_method', mock_get_method)


    monkeypatch.setattr('lexie_cloud.views.get_token', mock_get_token)
    monkeypatch.setattr('lexie_cloud.views.check_token', mock_check_token)
    result = client.post("/",
        json={
            'requestId': '1111',
            'inputs': [
                {
                    'intent': 'action.devices.EXECUTE',
                    'payload': {
                        'commands': [
                                {
                                    'devices': [
                                        {
                                            'id': 'pc'
                                        }
                                    ],
                                'execution': [
                                    {
                                        'command': 'action.devices.commands.OnOff',
                                        'params': 'on'
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
    )
    assert result.json == {
        "payload":{
            "commands":[
                {
                    "ids":[
                        "pc"
                    ],
                    "on":True,
                    "online":True
                }
            ]
        },
        "requestId":"1111"
    }


def test_google_post_disconnect(monkeypatch, client):
    def mock_get_token():
        return 'test_user'
    def mock_check_token():
        return 'test_user'
    def mock_isfile(param):
        return True
    def mock_access(param1, param2):
        return True
    def mock_os_remove(param):
        global MOCK_CALLED
        MOCK_CALLED = 'mock_os_remove'
    monkeypatch.setattr('lexie_cloud.views.get_token', mock_get_token)
    monkeypatch.setattr('lexie_cloud.views.check_token', mock_check_token)
    monkeypatch.setattr('os.path.isfile', mock_isfile)
    monkeypatch.setattr('os.access', mock_access)
    monkeypatch.setattr('os.remove', mock_os_remove)
    result = client.post("/",
        json={
            'requestId': '1111',
            'inputs': [
                {
                    'intent': 'action.devices.DISCONNECT',
                }
            ]
        }
    )
    assert result.json == {}
    assert MOCK_CALLED == 'mock_os_remove'

def test_connect_instance(monkeypatch, client):
    def mock_authenticate_user(username, password):
        return True
    def mock_add_lexie_instance(username, lexie_instance_name):
        return {
            'username': username,
            'name': lexie_instance_name,
            'apikey': uuid() + uuid() + uuid() + uuid(),
            'id': uuid()
        }
    monkeypatch.setattr('lexie_cloud.users.authenticate_user', mock_authenticate_user)
    monkeypatch.setattr('lexie_cloud.users.add_lexie_instance', mock_add_lexie_instance)
    result = client.post('/connect-instance', 
        json={
            'username': 'test_user',
            'password': 'test_password',
            'name': 'test_instance'
        }
    )
    assert result.status_code == 200
    result_json = result.json
    assert 'instance_id' in result_json
    assert 'apikey' in result_json

def test_connect_instance_authfailure(monkeypatch, client):
    def mock_authenticate_user(username, password):
        raise InvalidUserNamePasswordException()
    def mock_add_lexie_instance(username, lexie_instance_name):
        return {
            'username': username,
            'name': lexie_instance_name,
            'apikey': uuid() + uuid() + uuid() + uuid(),
            'id': uuid()
        }
    monkeypatch.setattr('lexie_cloud.users.authenticate_user', mock_authenticate_user)
    monkeypatch.setattr('lexie_cloud.users.add_lexie_instance', mock_add_lexie_instance)
    result = client.post('/connect-instance', 
        json={
            'username': 'test_user',
            'password': 'test_password',
            'name': 'test_instance'
        }
    )
    assert result.status_code == 403

@pytest.mark.parametrize(('post_json'),
    (
        ({'username': 'test_user', 'password': 'test_password'}),
        ({'username': 'test_user', 'name': 'test_instance'}),
        ({'name': 'test_instance', 'password': 'test_password'}),
        ({}),
    )
)
def test_connect_instance_invalidparams(monkeypatch, client, post_json):
    def mock_authenticate_user(username, password):
        raise InvalidUserNamePasswordException()
    def mock_add_lexie_instance(username, lexie_instance_name):
        return {
            'username': username,
            'name': lexie_instance_name,
            'apikey': uuid() + uuid() + uuid() + uuid(),
            'id': uuid()
        }
    monkeypatch.setattr('lexie_cloud.users.authenticate_user', mock_authenticate_user)
    monkeypatch.setattr('lexie_cloud.users.add_lexie_instance', mock_add_lexie_instance)
    result = client.post('/connect-instance', 
        json=post_json
    )
    assert result.status_code == 400

def test_socketio_connect_unauthenticated(monkeypatch, client, app):

    socketio_test_client = socketio.test_client(app, flask_test_client=client)
    assert not socketio_test_client.is_connected()

def test_socketio_connect_authenticated(monkeypatch, client, app):
    def mock_authenticate_lexie_instance(instance_id, apikey):
        return {'id': instance_id}
    monkeypatch.setattr('lexie_cloud.users.authenticate_lexie_instance', mock_authenticate_lexie_instance)
    socketio_test_client = socketio.test_client(app, flask_test_client=client, auth={'instance_id': 'test_instance', 'apikey': 'test_apikey'})
    assert socketio_test_client.is_connected()
    # isort: off
    from lexie_cloud.views import connected_instances # pylint: disable=import-outside-toplevel
    # isort: on
    assert 'test_instance' in connected_instances

def test_socketio_connect_invalid_api_key(monkeypatch, client, app):
    def mock_authenticate_lexie_instance(instance_id, apikey):
        raise InstanceAuthenticationFailureException()
    monkeypatch.setattr('lexie_cloud.users.authenticate_lexie_instance', mock_authenticate_lexie_instance)
    socketio_test_client = socketio.test_client(app, flask_test_client=client, auth={'instance_id': 'test_instance', 'apikey': 'test_apikey'})
    assert not socketio_test_client.is_connected()
    socketio_test_client = socketio.test_client(app, flask_test_client=client, auth={'instance_id': 'test_instance'})
    assert not socketio_test_client.is_connected()
    socketio_test_client = socketio.test_client(app, flask_test_client=client, auth={'apikey': 'test_apikey'})
    assert not socketio_test_client.is_connected()

def test_sio_send_command_timeout(monkeypatch, client, app):
    def mock_authenticate_lexie_instance(instance_id, apikey):
        return {'id': instance_id}
    def mock_get_lexie_instance(username):
        return {'id': 'test_instance'}
    monkeypatch.setattr('lexie_cloud.users.authenticate_lexie_instance', mock_authenticate_lexie_instance)
    monkeypatch.setattr('lexie_cloud.users.get_lexie_instance', mock_get_lexie_instance)
    socketio_test_client = socketio.test_client(app, flask_test_client=client, auth={'instance_id': 'test_instance', 'apikey': 'test_apikey'})
    monkeypatch.setattr('lexie_cloud.views.SIO_SEND_MAX_WAIT_ITERATIONS', 1)
    with pytest.raises(CommandTimeoutException):
        lexie_cloud.views.sio_send_command('test_user', 'test', {'testkey': 'testvalue'})
    assert socketio_test_client.get_received()[0]['name'] == 'test'

def test_sio_send_command_noinstance(monkeypatch, client, app):
    def mock_authenticate_lexie_instance(instance_id, apikey):
        return {'id': instance_id}
    def mock_get_lexie_instance(username):
        return None
    monkeypatch.setattr('lexie_cloud.users.authenticate_lexie_instance', mock_authenticate_lexie_instance)
    monkeypatch.setattr('lexie_cloud.users.get_lexie_instance', mock_get_lexie_instance)
    socketio_test_client = socketio.test_client(app, flask_test_client=client, auth={'instance_id': 'test_instance', 'apikey': 'test_apikey'})
    monkeypatch.setattr('lexie_cloud.views.SIO_SEND_MAX_WAIT_ITERATIONS', 1)
    with pytest.raises(Exception):
        lexie_cloud.views.sio_send_command('test_user', 'test', {'testkey': 'testvalue'})

def test_sio_send_command_offline(monkeypatch):
    with pytest.raises(InstanceOfflineException):
        lexie_cloud.views.sio_send_command('test_user', 'test', {'testkey': 'testvalue'})

def test_sio_test_send_command(monkeypatch, client, app):
    def mock_authenticate_lexie_instance(instance_id, apikey):
        return {'id': instance_id}
    def mock_get_lexie_instance(username):
        return {'id': 'test_instance'}
    def mock_uuid():
        return "TESTUUID"
    monkeypatch.setattr('lexie_cloud.users.authenticate_lexie_instance', mock_authenticate_lexie_instance)
    monkeypatch.setattr('lexie_cloud.users.get_lexie_instance', mock_get_lexie_instance)
    socketio_test_client = socketio.test_client(app, flask_test_client=client, auth={'instance_id': 'test_instance', 'apikey': 'test_apikey'})
    monkeypatch.setattr('lexie_cloud.views.SIO_SEND_MAX_WAIT_ITERATIONS', 1)
    monkeypatch.setattr('lexie_cloud.views.uuid', mock_uuid)
    monkeypatch.setattr('lexie_cloud.views.SIO_RESPONSE_DATA', {
        'TESTUUID': {'test_success': True}
    })
    result = lexie_cloud.views.sio_send_command('test_user', 'test', {'testkey': 'testvalue'})
    assert socketio_test_client.get_received()[0]['name'] == 'test'
    assert result == {'test_success': True}

def test_sio_command_callback():
    lexie_cloud.views.sio_command_callback({'request_id': 'TESTID', 'payload': {'success': True}})
    assert lexie_cloud.views.SIO_RESPONSE_DATA['TESTID'] == {'success': True}
