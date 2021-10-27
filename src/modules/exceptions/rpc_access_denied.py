class RpcAccessDenied(Exception):
    def __init__(self, method):
        message = f'Access denied to RPC method {method}.'
        super().__init__(message)