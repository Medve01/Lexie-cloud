# coding: utf8
from flask import Flask

import lexie_cloud.users
from lexie_cloud import config
from lexie_cloud.extensions import logger, socketio

# Path to device plugins

def create_app():
    """Flask application factory

    Returns:
        [type]: [description]
    """
    _app = Flask(__name__)
    config.load_config_from_s3()
    try:
        _app.config.from_json('config.json')
    except:# pylint: disable=bare-except # pragma: nocover
        print('Failed to load config!!!')
    lexie_cloud.users.load_db_from_s3()
    # isort: off
    from lexie_cloud.views import view # pylint: disable=import-outside-toplevel
    # isort: on
    _app.register_blueprint(view)
    socketio.init_app(_app)
    logger.info("Started.", extra={'remote_addr': '-', 'user': '-'})
    # print('RUNNING')
    return _app
