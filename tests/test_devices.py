import json
import pytest

import lexie_cloud.lexie_devices

device_list = [
                    {
                        "device_attributes": {
                            "ip_address": "192.168.0.149"
                        },
                        "device_id": "Qt9pR2YvuHNeqPKCHjJDKx",
                        "device_ison": False,
                        "device_manufacturer": "shelly",
                        "device_name": "Twin's light",
                        "device_online": True,
                        "device_product": "shelly1",
                        "device_type": {
                            "devicetype_id": 1,
                            "devicetype_name": "Relay"
                        },
                        "room": {
                            "room_id": "TUnwDAH8nJWh4gZMeSeHHm",
                            "room_name": "Kids' room"
                        },
                        "supports_events": True
                    },
                    {
                        "device_attributes": {
                            "ip_address": "192.168.0.184"
                        },
                        "device_id": "RqMhRK6gqMTBWd7ULzDCux",
                        "device_ison": False,
                        "device_manufacturer": "shelly",
                        "device_name": "Desk light 2",
                        "device_online": True,
                        "device_product": "shelly_bulb_rgbw",
                        "device_type": {
                            "devicetype_id": 2,
                            "devicetype_name": "Light"
                        },
                        "room": {
                            "room_id": "DmHZAPPJ8bCHGNAZrJLKQk",
                            "room_name": "Office"
                        },
                        "supports_events": True
                    }
                ]

MOCK_URL = {}

def test_get_devices_for_user(monkeypatch):
    class MockResponse(object):
        def __init__(self, url) -> None:
            self.status_code = 200
            self.url = url
            self.text = json.dumps(device_list)
    def mock_request_get(url, headers):
        global MOCK_URL
        MOCK_URL['url'] = url
        MOCK_URL['apikey'] = headers['X-API-KEY']
        return MockResponse(url)
    def mock_get_user(username):
        return {
            'username': username,
            'password': '*******',
            'lexie_url': 'http://127.0.0.1/',
            'api_key': 'test_api_key'
        }
    monkeypatch.setattr('requests.get', mock_request_get)
    monkeypatch.setattr('lexie_cloud.lexie_devices.get_user', mock_get_user)
    result = lexie_cloud.lexie_devices.get_devices_for_user('test_user')
    assert result['payload']['agentUserId'] == 'test_user'
    assert result['payload']['devices'][0]['id'] == 'Qt9pR2YvuHNeqPKCHjJDKx'
