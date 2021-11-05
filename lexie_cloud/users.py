import bcrypt
import boto3
import tinydb
from shortuuid import uuid

from lexie_cloud import config
from lexie_cloud.exceptions import (InstanceAuthenticationFailureException,
                                    InvalidUserNamePasswordException,
                                    UserAlreadyExistsException,
                                    UserNotFoundException)

DATABASE_FILE='users.json'
user_table = tinydb.TinyDB(DATABASE_FILE).table('users')
lexie_instance_table  = tinydb.TinyDB(DATABASE_FILE).table('lexie_instances')

def save_db_to_s3():
    """Saves our tiny database to AWS S3
    """
    bucket_name = config.S3_BUCKET_NAME
    s3client = boto3.client('s3')
    s3client.upload_file(DATABASE_FILE, bucket_name, DATABASE_FILE)

def add_user(username, password, lexie_url, api_key):
    """Adds a user to the database. raises UserAlreadyExistsException if username is not unique

    Args:
        username (str): user logon name
        password (str): password
        lexie_url (str): URL of the local Lexie instance
    """
    user = user_table.search(tinydb.Query().username == username)
    if user is not None and len(user) > 0:
        raise UserAlreadyExistsException()
    salt = bcrypt.gensalt()
    user_dict = {
        'username': username,
        'password': bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8'),
        'lexie_url': lexie_url,
        'api_key': api_key
    }
    user_table.insert(user_dict)

def get_user(username, mask_password = True):
    """Fetches a user dict from database. Masks password hash.

    Args:
        username (str): username

    Raises:
        UserNotFoundException: if user does not exist in database

    Returns:
        [dict]: the user dict
    """
    user = user_table.search(tinydb.Query().username == username)
    if user is None or user == []:
        raise UserNotFoundException()
    user = user[0]
    return_user = user.copy()
    if mask_password:
        return_user['password'] = '*******' # nosecurity # go home bandit, you're drunk (this is not a password)
    return return_user

def authenticate_user(username, password):
    """Authenticates a user

    Args:
        username (str): username
        password (str): password

    Raises:
        InvalidUserNamePasswordException: if user does not exist in database or password is not valid

    Returns:
        [dict]: user's dict from database, password hash masked out
    """
    try:
        user = get_user(username, mask_password=False)
    except UserNotFoundException as exception:
        raise InvalidUserNamePasswordException() from exception
    if not bcrypt.checkpw(password.encode('UTF-8'), user['password'].encode('UTF-8')):
        raise InvalidUserNamePasswordException()
    return_user = user.copy()
    return_user['password'] = '*******' # nosecurity # go home bandit, you're drunk (this is not a password)
    return return_user

def add_lexie_instance(username, lexie_instance_name):
    """Stores a new local Lexie instance in database

    Args:
        username (str): the user who wants to connect the instance
        lexie_instance_name (str): the name of the instance

    Returns:
        dict: represents the lexie instance. ['apikey'] will contain the api key for the instance to use on connecting
    """
    salt = bcrypt.gensalt()
    apikey = uuid() + uuid() + uuid() + uuid()
    hashed_apikey = bcrypt.hashpw(apikey.encode('UTF-8'), salt)
    lexie_instance = {
        'username': username,
        'name': lexie_instance_name,
        'apikey': hashed_apikey.decode('UTF-8'),
        'id': uuid()
    }
    lexie_instance_table.insert(lexie_instance)
    return_instance = lexie_instance.copy()
    return_instance['apikey'] = apikey
    return return_instance

def authenticate_lexie_instance(instance_id, apikey):
    """Authenticates a local Lexie instance on connection

    Args:
        instance_id (str): the Lexie instance id (comes from add_lexie_instance)
        apikey (str): api key

    Raises:
        InstanceAuthenticationFailureException: authentication failure

    Returns:
        dict: the lexie_instance data stored in db
    """
    instance = lexie_instance_table.search(tinydb.Query().id == instance_id)
    if instance is None or instance == []:
        raise InstanceAuthenticationFailureException()
    instance = instance[0]
    if not bcrypt.checkpw(apikey.encode('UTF-8'), instance['apikey'].encode('UTF-8')):
        raise InstanceAuthenticationFailureException()
    return_instance = instance.copy()
    return_instance['apikey'] = '*******' # nosecurity # go home bandit, you're drunk (this is not an api key)
    return return_instance

def get_lexie_instance(username):
    """Fetches the stored local Lexie instance from DB for a user

    Args:
        username (str): the user we're looking for

    Returns:
        dict: the local Lexie instance
    """
    db_result = lexie_instance_table.search(tinydb.Query().username == username)
    if db_result is None or db_result == []:
        return None
    instance = db_result[0].copy()
    instance['apikey'] = '*******' # nosecurity # go home bandit, you're drunk (this is not an api key)
    return instance
