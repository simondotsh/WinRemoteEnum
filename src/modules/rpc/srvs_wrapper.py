from .connection import Connection
from impacket.dcerpc.v5 import srvs
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException

class SrvsWrapper(Connection):
    PIPE = 'srvsvc'
    UUID = srvs.MSRPC_UUID_SRVS

    def __init__(self, config, target):
        super().__init__(config, target, self.PIPE, self.UUID)

    def get_sessions(self):
        # 10 = SESSION_INFO_10 
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/65471e2f-f849-442f-aa0f-3747bcda4c9d
        sessions = self.__session_enum(10)

        return sessions['InfoStruct']['SessionInfo']['Level10']['Buffer']

    def __session_enum(self, level):
        try:
            return srvs.hNetrSessionEnum(self.dce, NULL, NULL, level)
        except DCERPCException as e:
            self._raise_rpc_error(e, 'NetrSessionEnum')