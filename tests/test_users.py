import os
import json
import pytest
import tinydb
import boto3
from moto import mock_s3
from shortuuid import uuid
from uuid import uuid4

import lexie_cloud.users
from lexie_cloud import config
from lexie_cloud.exceptions import (InstanceAuthenticationFailureException,
                                    InvalidUserNamePasswordException,
                                    UserAlreadyExistsException,
                                    UserNotFoundException)
from tests.fixtures.test_app import app

@pytest.fixture
def user_db():
    temp_file = '/tmp/' + uuid()
    _user_db = tinydb.TinyDB(temp_file)
    yield _user_db
    os.remove(temp_file)
    return

@pytest.fixture
def lexie_instance_db():
    temp_file = '/tmp/' + uuid()
    _db = tinydb.TinyDB(temp_file)
    yield _db
    os.remove(temp_file)
    return

@pytest.fixture
def lexie_invitations_db():
    temp_file = '/tmp/' + uuid()
    _db = tinydb.TinyDB(temp_file)
    yield _db
    os.remove(temp_file)
    return

def test_add_user(monkeypatch, user_db):
    monkeypatch.setattr('lexie_cloud.users.user_table', user_db)
    lexie_cloud.users.add_user('test_user', 'test_password')
    test_user = user_db.search(tinydb.Query().username == 'test_user')
    assert test_user[0]['username'] == 'test_user'

def test_add_user_duplicate(monkeypatch, user_db):
    monkeypatch.setattr('lexie_cloud.users.user_table', user_db)
    lexie_cloud.users.add_user('test_user', 'test_password')
    with pytest.raises(UserAlreadyExistsException):
        lexie_cloud.users.add_user('test_user', 'test_password')

def test_get_user(monkeypatch, user_db):
    monkeypatch.setattr('lexie_cloud.users.user_table', user_db)
    lexie_cloud.users.add_user('test_user', 'password')
    user = lexie_cloud.users.get_user('test_user')
    assert user['username'] == 'test_user'
    assert user['password'] == '*******'
    with pytest.raises(UserNotFoundException):
        user = lexie_cloud.users.get_user('no_such_user')

def test_authenticate_user(monkeypatch, user_db):
    monkeypatch.setattr('lexie_cloud.users.user_table', user_db)
    lexie_cloud.users.add_user('test_user', '1234')
    user = lexie_cloud.users.authenticate_user('test_user', '1234')
    assert user['username'] == 'test_user'
    assert user['password'] == '*******'

def test_authenticate_user_nouser(monkeypatch, user_db):
    monkeypatch.setattr('lexie_cloud.users.user_table', user_db)
    with pytest.raises(InvalidUserNamePasswordException):
        user = lexie_cloud.users.authenticate_user('username', 'password')

def test_authenticate_user_wrongpassword(monkeypatch, user_db):
    monkeypatch.setattr('lexie_cloud.users.user_table', user_db)
    lexie_cloud.users.add_user('test_user', '1234')
    with pytest.raises(InvalidUserNamePasswordException):
        user = lexie_cloud.users.authenticate_user('test_user', 'password')

def test_add_lexie_instance(monkeypatch, lexie_instance_db):
    monkeypatch.setattr('lexie_cloud.users.lexie_instance_table', lexie_instance_db)
    instance = lexie_cloud.users.add_lexie_instance('test_user', 'test_instance')
    assert instance['username'] == 'test_user'
    assert instance['name'] == 'test_instance'
    assert 'apikey' in instance.keys()

def test_authenticate_lexie_instance(monkeypatch, lexie_instance_db):
    monkeypatch.setattr('lexie_cloud.users.lexie_instance_table', lexie_instance_db)
    instance = lexie_cloud.users.add_lexie_instance('test_user', 'test_instance')
    result = lexie_cloud.users.authenticate_lexie_instance(instance['id'], instance['apikey'])
    assert result['id'] == instance['id']

def test_authenticate_lexie_instance_autherror(monkeypatch, lexie_instance_db):
    monkeypatch.setattr('lexie_cloud.users.lexie_instance_table', lexie_instance_db)
    instance = lexie_cloud.users.add_lexie_instance('test_user', 'test_instance')
    with pytest.raises(InstanceAuthenticationFailureException):
        result = lexie_cloud.users.authenticate_lexie_instance(instance['id'], 'invalid_api_key')
    with pytest.raises(InstanceAuthenticationFailureException):
        result = lexie_cloud.users.authenticate_lexie_instance('invalid_instance_id', 'invalid_api_key')

@mock_s3
def test_save_db_to_s3(monkeypatch, app):
    conn = boto3.resource('s3', region_name='us-east-1')
    with app.app_context():
        conn.create_bucket(Bucket=config.S3_BUCKET_NAME)
        mock_filename = uuid() + '.json'
        with open(mock_filename, "w") as jsonFile:
            jsonFile.write(json.dumps({'success': True}))
        monkeypatch.setattr('lexie_cloud.users.DATABASE_FILE', mock_filename)
        lexie_cloud.users.save_db_to_s3()
        os.remove(mock_filename)
        body = conn.Object(config.S3_BUCKET_NAME, mock_filename).get()['Body'].read().decode("utf-8")
    assert json.loads(body) == {'success': True}

def test_get_lexie_instance(monkeypatch, lexie_instance_db):
    monkeypatch.setattr('lexie_cloud.users.lexie_instance_table', lexie_instance_db)
    instance = lexie_cloud.users.add_lexie_instance('test_user', 'test_instance')
    result = lexie_cloud.users.get_lexie_instance('test_user')
    assert result['id'] == instance['id']

def test_get_lexie_instance_notfound(monkeypatch, lexie_instance_db):
    monkeypatch.setattr('lexie_cloud.users.lexie_instance_table', lexie_instance_db)
    assert lexie_cloud.users.get_lexie_instance('test_user') is None

def test_use_invitation(monkeypatch, lexie_invitations_db):
    monkeypatch.setattr('lexie_cloud.users.invitations_table', lexie_invitations_db)
    test_invitation = str(uuid4())
    lexie_invitations_db.insert({'code': test_invitation})
    assert lexie_cloud.users.use_invitation(test_invitation)
    result = lexie_invitations_db.search(tinydb.Query().code == test_invitation)
    assert result is None or result == []

def test_use_invitation_badcode(monkeypatch, lexie_invitations_db):
    monkeypatch.setattr('lexie_cloud.users.invitations_table', lexie_invitations_db)
    assert not lexie_cloud.users.use_invitation('test_invitation')
