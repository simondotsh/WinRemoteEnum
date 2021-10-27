from .connection import Connection
from src.modules.exceptions import RpcAccessDenied
from impacket.dcerpc.v5 import scmr
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException

class ScmrWrapper(Connection):
    PIPE = 'svcctl'
    UUID = scmr.MSRPC_UUID_SCMR

    def __init__(self, config, target):
        super().__init__(config, target, self.PIPE, self.UUID)

    """
    Initially, I attempted to use NetrWkstaUserEnum but it appears that 
    WinXP completely disregards the requirement of being a member of the
    Administrators group, as stated in the documentation.
    
    Having the SC_MANAGER_ALL_ACCESS privileges implies that you can easily
    get code execution by writing a service, so it offers the advantage
    of reporting that a user does have unexpected administrative privileges, 
    in the case where those privileges have been given without Administrator
    (if there is such a thing).
    """
    def is_local_admin(self):
        try:
            # I believe that specifying the right machine name does not
            # achieve much, other than potentially avoid detections.
            scm_handle = self.__open_sc_manager()
            self.__close_service_handle(scm_handle)
            return True
        except RpcAccessDenied:
            return False

    def __open_sc_manager(
        self, hostname='DEFAULT\x00', database='ServicesActive\x00', 
        access=0xF003F
    ):
        # Kudos to pywerview (https://github.com/the-useless-one/pywerview)
        # for 0xF003F (SC_MANAGER_ALL_ACCESS)
        # https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
        try:
            return scmr.hROpenSCManagerW(
                self.dce, hostname, database, access
            )['lpScHandle']
        except DCERPCException as e:
            self._raise_rpc_error(e, 'ROpenSCManagerW')

    def __close_service_handle(self, handle):
        try:
            scmr.hRCloseServiceHandle(self.dce, handle)
        except:
            pass