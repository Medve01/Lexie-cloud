import bcrypt
import tinydb

from lexie_cloud.exceptions import (InvalidUserNamePasswordException,
                                    UserAlreadyExistsException,
                                    UserNotFoundException)

user_table = tinydb.TinyDB('users.json').table('users')

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
