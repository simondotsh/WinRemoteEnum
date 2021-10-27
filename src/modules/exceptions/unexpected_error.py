class UnexpectedError(Exception):
    def __init__(self, error):
        message = f'Unexpected error: {error}.'
        super().__init__(message)