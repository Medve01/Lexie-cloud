import json

import requests

from lexie_cloud.users import get_user


def get_devices_for_user(username):
    """returns the device list from the Lexie instance in Google's payload format

    Args:
        username (str): the authenticated user

    Returns:
        [dict]: the Google Home payload
    """
    user = get_user(username)
    result = requests.get(user['lexie_url'], headers={'X-API-KEY': user['api_key']})
    lexie_devices = json.loads(result.text)
    devices = []
    for result in lexie_devices:
        device = {
                    'deviceInfo': {
                        'hwVersion': '1',
                        'manufacturer': 'Lexie',
                        'model': '1',
                        'swVersion': '1'
                    },
                    'id': result['device_id'],
                    'name': {
                        'defaultNames': [
                            result['device_name']
                        ],
                        'name': result['device_name'],
                        'nicknames': [
                            result['device_name']
                        ]
                    },
                    'roomHint': result['room']['room_name'],
                    'traits': [
                        'action.devices.traits.OnOff'
                    ],
                    'type': 'action.devices.types.SWITCH',
                    'willReportState': False
                }
        devices.append(device)
    response = {
        'payload': {
            'agentUserId': username,
            'devices': devices
        }
    }
    return response
