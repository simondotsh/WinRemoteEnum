class SmbAuthenticationFailed(Exception):
    def __init__(self, error):
        message = f'Authentication failed: {error}.'
        super().__init__(message)