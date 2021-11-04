# import sys
from flask import Flask

from lexie_cloud.app import create_app

# sys.path.insert(0, '/home/smarthome/google-home')
app = create_app()
