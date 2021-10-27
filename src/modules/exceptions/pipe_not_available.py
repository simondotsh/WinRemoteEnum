class PipeNotAvailable(Exception):
    def __init__(self, pipe):
        message = f'Named pipe not available: {pipe}.'
        super().__init__(message)