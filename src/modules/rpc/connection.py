from src.modules.exceptions import RpcAccessDenied, PipeNotAvailable, \
     ConnectionError, SmbAuthenticationFailed, InterfaceNotListening, \
     UnexpectedError
from impacket.dcerpc.v5 import transport
from impacket.smbconnection import SessionError
from impacket.dcerpc.v5.rpcrt import DCERPCException

class Connection:
    dce = None

    def __init__(self, config, target, pipe, uuid):
        binding = f'ncacn_np:{target}[\PIPE\{pipe}]'

        trans = transport.DCERPCTransportFactory(binding)
        trans.set_credentials(
            config.username, config.password, config.domain, 
            nthash=config.nt_hash
        )
        trans.set_connect_timeout(config.timeout)

        try:
            dce = trans.get_dce_rpc()
            dce.connect()
            dce.bind(uuid)

            self.dce = dce
        except OSError as e:
            if 'Connection refused' in str(e):
                raise ConnectionError(f'Connection refused: {str(e)}.')
            elif 'timed out' in str(e):
                raise ConnectionError(f'Connection timed out: {str(e)}.')
            else:
                raise
        except SessionError as e:
            """
            It appears that Win7 will return STATUS_OBJECT_NAME_NOT_FOUND 
            instead of STATUS_PIPE_NOT_AVAILABLE when the Remote Registry 
            service is not started. TODO: validate if this is always accurate.
            """
            if 'STATUS_PIPE_NOT_AVAILABLE' in str(e) or \
               'STATUS_OBJECT_NAME_NOT_FOUND' in str(e):
                raise PipeNotAvailable(pipe)
            elif 'STATUS_LOGON_FAILURE' in str(e):
                raise SmbAuthenticationFailed(str(e))
            else:
                raise
        except DCERPCException as e:
            if 'abstract_syntax_not_supported' in str(e):
                raise InterfaceNotListening(str(e))
            else:
                raise
        except Exception as e:
            raise UnexpectedError(str(e))

    def _raise_rpc_error(self, e, method):
        if 'rpc_s_access_denied' in str(e):
            raise RpcAccessDenied(method)
        else:
            raise

    def __disconnect(self):
        try:
            self.dce.disconnect()
        except:
            pass

    def __del__(self):
        self.__disconnect()