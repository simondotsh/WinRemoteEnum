class ConnectionError(Exception):
    def __init__(self, error):
        message = f'Connection error: {error}.'
        super().__init__(message)