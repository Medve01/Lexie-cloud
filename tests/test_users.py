import os
import json
import pytest
import tinydb
import boto3
from moto import mock_s3
from shortuuid import uuid

import lexie_cloud.users
from lexie_cloud import config
from lexie_cloud.exceptions import (InstanceAuthenticationFailureException,
                                    InvalidUserNamePasswordException,
                                    UserAlreadyExistsException,
                                    UserNotFoundException)


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


def test_add_user(monkeypatch, user_db):
    monkeypatch.setattr('lexie_cloud.users.user_table', user_db)
    lexie_cloud.users.add_user('test_user', 'test_password', 'http://127.0.0.1', '1234')
    test_user = user_db.search(tinydb.Query().username == 'test_user')
    assert test_user[0]['username'] == 'test_user'
    assert test_user[0]['lexie_url'] == 'http://127.0.0.1'

def test_add_user_duplicate(monkeypatch, user_db):
    monkeypatch.setattr('lexie_cloud.users.user_table', user_db)
    lexie_cloud.users.add_user('test_user', 'test_password', 'http://127.0.0.1', '1234')
    with pytest.raises(UserAlreadyExistsException):
        lexie_cloud.users.add_user('test_user', 'test_password', 'http://127.0.0.1', '1234')

def test_get_user(monkeypatch, user_db):
    monkeypatch.setattr('lexie_cloud.users.user_table', user_db)
    lexie_cloud.users.add_user('test_user', 'password', 'http://127.0.0.2', '1234')
    user = lexie_cloud.users.get_user('test_user')
    assert user['username'] == 'test_user'
    assert user['password'] == '*******'
    assert user['lexie_url'] == 'http://127.0.0.2'
    with pytest.raises(UserNotFoundException):
        user = lexie_cloud.users.get_user('no_such_user')

def test_authenticate_user(monkeypatch, user_db):
    monkeypatch.setattr('lexie_cloud.users.user_table', user_db)
    lexie_cloud.users.add_user('test_user', '1234', 'http://127.0.0.2', '1234')
    user = lexie_cloud.users.authenticate_user('test_user', '1234')
    assert user['username'] == 'test_user'
    assert user['password'] == '*******'
    assert user['lexie_url'] == 'http://127.0.0.2'

def test_authenticate_user_nouser(monkeypatch, user_db):
    monkeypatch.setattr('lexie_cloud.users.user_table', user_db)
    with pytest.raises(InvalidUserNamePasswordException):
        user = lexie_cloud.users.authenticate_user('username', 'password')

def test_authenticate_user_wrongpassword(monkeypatch, user_db):
    monkeypatch.setattr('lexie_cloud.users.user_table', user_db)
    lexie_cloud.users.add_user('test_user', '1234', 'http://127.0.0.2', '1234')
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
def test_save_db_to_s3(monkeypatch):
    conn = boto3.resource('s3', region_name='us-east-1')
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

