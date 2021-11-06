# coding: utf8

import sys

from flask import Flask

import lexie_cloud.users
from lexie_cloud import config
from lexie_cloud.extensions import logger, socketio

# Path to device plugins
sys.path.insert(0, config.DEVICES_DIRECTORY)

def create_app():
    """Flask application factory

    Returns:
        [type]: [description]
    """
    lexie_cloud.users.load_db_from_s3()
    _app = Flask(__name__)
    # isort: off
    from lexie_cloud.views import view # pylint: disable=import-outside-toplevel
    # isort: on
    _app.register_blueprint(view)
    socketio.init_app(_app)
    logger.info("Started.", extra={'remote_addr': '-', 'user': '-'})
    return _app
