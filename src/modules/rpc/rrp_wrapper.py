from .connection import Connection
from impacket.dcerpc.v5 import rrp
from impacket.dcerpc.v5.rpcrt import DCERPCException

class RrpWrapper(Connection):
    PIPE = 'winreg'
    UUID = rrp.MSRPC_UUID_RRP

    def __init__(self, config, target):
        super().__init__(config, target, self.PIPE, self.UUID)

    def open_users(self):
        try:
            return rrp.hOpenUsers(self.dce, rrp.KEY_ENUMERATE_SUB_KEYS)['phKey']
        except DCERPCException as e:
            self._raise_rpc_error(e, 'OpenUsers')

    def base_reg_enum_key(self, key_handle, index): 
        try:
            return rrp.hBaseRegEnumKey(self.dce, key_handle, index)
        except DCERPCException as e:
            # Since the enumeration is index-based and we're in the dark
            # regarding how many there are, this is going to happen every time.
            if 'ERROR_NO_MORE_ITEMS' in str(e):
                return None
            else:
                self._raise_rpc_error(e, 'BaseRegEnumKey')