class InterfaceNotListening(Exception):
    def __init__(self, error):
        message = f'RPC error (interface most-likely not listening): {error}.'
        super().__init__(message)