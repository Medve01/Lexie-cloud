# coding: utf8

import logging
import sys

from flask import Flask

from lexie_cloud import config

# Enable log if need

# if hasattr(config, 'LOG_FILE'):
#     logging.basicConfig(level=config.LOG_LEVEL,
#                     format=config.LOG_FORMAT,
#                     datefmt=config.LOG_DATE_FORMAT,
#                     filename=config.LOG_FILE,
#                     filemode='a')
logger = logging.getLogger()

# Path to device plugins
sys.path.insert(0, config.DEVICES_DIRECTORY)

def create_app():
    """Flask application factory

    Returns:
        [type]: [description]
    """
    _app = Flask(__name__)
    # isort: off
    from lexie_cloud.views import view # pylint: disable=import-outside-toplevel
    # isort: on
    _app.register_blueprint(view)
    logger.info("Started.", extra={'remote_addr': '-', 'user': '-'})
    return _app
