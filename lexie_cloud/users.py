import bcrypt
import tinydb
from shortuuid import uuid

from lexie_cloud.exceptions import (InstanceAuthenticationFailureException,
                                    InvalidUserNamePasswordException,
                                    UserAlreadyExistsException,
                                    UserNotFoundException)

user_table = tinydb.TinyDB('users.json').table('users')
lexie_instance_table  = tinydb.TinyDB('users.json').table('lexie_instances')

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
    if mask_password:
        user['password'] = '*******' # nosecurity # go home bandit, you're drunk (this is not a password)
    return user

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
    user['password'] = '*******' # nosecurity # go home bandit, you're drunk (this is not a password)
    return user

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
    lexie_instance['apikey'] = apikey
    return lexie_instance

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
    instance['apikey'] = '*******' # nosecurity # go home bandit, you're drunk (this is not an api key)
    return instance
