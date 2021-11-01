import pytest

from tests.fixtures.test_app import app,client
import lexie_cloud.views
import requests

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
