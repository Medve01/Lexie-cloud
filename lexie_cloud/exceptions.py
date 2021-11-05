class UserNotFoundException(Exception):
    """ User is not found in database """

class UserAlreadyExistsException(Exception):
    """ User to be added has a non-unique username """

class InvalidUserNamePasswordException(Exception):
    """ Invalid username/password given to authentication """

class InstanceAuthenticationFailureException(Exception):
    """ Lexie instance authentication error """

class InstanceOfflineException(Exception):
    """ Lexie instance is offline """

class CommandTimeoutException(Exception):
    """ Lexie instance failed to respond in a timely manner """
