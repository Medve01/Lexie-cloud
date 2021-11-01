import pytest

from lexie_cloud.app import create_app

@pytest.fixture
def app():
    """Creates a Flask application for testing
    """
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
