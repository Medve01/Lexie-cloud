import pytest

import boto3
import json

from flask import testing
from moto import mock_s3
from werkzeug.datastructures import Headers

from lexie_cloud.app import create_app
from lexie_cloud.config import S3_BUCKET_NAME

TEST_AUTH = 'test_instance:blarftegh'


@pytest.fixture
@mock_s3
def app():
    """Creates a Flask application for testing
    """
    conn = boto3.resource('s3', region_name='us-east-1')
    conn.create_bucket(Bucket=S3_BUCKET_NAME)
    mock_filename = 'config.json'
    with open(mock_filename, "w", encoding = 'UTF-8') as jsonFile:
        jsonFile.write(json.dumps({
            "CLIENT_ID": "test_client_id",
            "CLIENT_SECRET" : "test_client_secret",
            "API_KEY" : "test_api_key",
            "USERS_DIRECTORY" : "./tests/fixtures/users",
            "TOKENS_DIRECTORY" : "./tests/fixtures/tokens",
            "DEVICES_DIRECTORY" : "./tests/fixtures/devices"
        }))
    _app = create_app()
    return _app

@pytest.fixture
def client(app): # pylint: disable=redefined-outer-name
    """Returns a test client for tests

    Args:
        app ([type]): app fixture

    """
    _client = app.test_client()
    return _client
