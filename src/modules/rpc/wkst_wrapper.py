from .connection import Connection
from impacket.dcerpc.v5 import wkst
from impacket.dcerpc.v5.rpcrt import DCERPCException

class WkstWrapper(Connection):
    PIPE = 'wkssvc'
    UUID = wkst.MSRPC_UUID_WKST

    def __init__(self, config, target):
        super().__init__(config, target, self.PIPE, self.UUID)

    def get_logged_on(self):
        try:
            # 1 = WKSTA_USER_INFO_1
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/c37b9606-866f-40ac-9490-57b8334968e2
            return wkst.hNetrWkstaUserEnum(self.dce, 1)
        except DCERPCException as e:
            self._raise_rpc_error(e, 'NetrWkstaUserEnum')