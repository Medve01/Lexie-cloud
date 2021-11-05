import socketio
import json
import time

with open('config.json', 'r') as config_file:
    config = json.load(config_file)

sio = socketio.Client(
    logger=True, 
    # engineio_logger=True
)


@sio.event
def connect():
    print('Connected to Lexie Cloud')

@sio.event
def disconnect():
    print('Disconnected from Lexie Cloud')

@sio.event
def devices(payload):
    request_id = payload['request_id']
    print(f'DEVICES: {request_id}')
    time.sleep(1)
    print('Sending response')
    return {
        'request_id': request_id,
        'payload': [
            {
                'device_id': '1234',
                'device_name': 'Test device 1'
            }, 
            {
                'device_id': '4321',
                'device_name': 'Test device 2'
            }
        ]
    }
sio.connect(
    config['lexie_cloud_url'],
    auth=config['lexie_auth']
)
