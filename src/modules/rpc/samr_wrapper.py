from .connection import Connection
from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.nt_errors import STATUS_MORE_ENTRIES

class SamrWrapper(Connection):
    PIPE = 'samr'
    UUID = samr.MSRPC_UUID_SAMR
    samr_handle = None

    def __init__(self, config, target):
        super().__init__(config, target, self.PIPE, self.UUID)

        self.samr_handle = self.__connect()

    def get_users(self, domain_handle):
        results = []
        status = STATUS_MORE_ENTRIES
        index = 0

        while status == STATUS_MORE_ENTRIES:

            users = self.__enumerate_users_in_domain(domain_handle, index)

            for user in users['Buffer']['Buffer']:
                entry = {}
                entry['rid'] = user['RelativeId']
                entry['name'] = user['Name']
                
                results.append(entry)

            index = users['EnumerationContext']
            status = users['ErrorCode']

        return results

    def get_domain_aliases(self, domain_handle):
        results = {}
        status = STATUS_MORE_ENTRIES
        index = 0

        while status == STATUS_MORE_ENTRIES:
            aliases = self.__enumerate_aliases_in_domain(domain_handle, index)

            for alias in aliases['Buffer']['Buffer']:
                results[alias['RelativeId']] = alias['Name']

            index = aliases['EnumerationContext'] 
            status = aliases['ErrorCode']

        return results

    def __connect(self):
        try:
            return samr.hSamrConnect(self.dce)['ServerHandle']
        except DCERPCException as e:
            self._raise_rpc_error(e, 'SamrConnect')
    
    def close_handle(self, handle):
        try:
            samr.hSamrCloseHandle(self.dce, handle)
        except:
            pass

    def close_samr_handle(self):
        self.close_handle(self.samr_handle)

    def open_domain(self, rpc_sid):
        try:
            return samr.hSamrOpenDomain(
                self.dce, self.samr_handle, domainId = rpc_sid
            )['DomainHandle']
        except DCERPCException as e:
            self._raise_rpc_error(e, 'SamrOpenDomain')

    def open_alias(
        self, domain_handle, alias_id, access = samr.ALIAS_LIST_MEMBERS
    ):
        try:
            return samr.hSamrOpenAlias(
                self.dce, domain_handle, access, alias_id
            )['AliasHandle']
        except DCERPCException as e:
            self._raise_rpc_error(e, 'SamrOpenAlias')

    def get_members_in_alias(self, alias_handle):
        try:
            return samr.hSamrGetMembersInAlias(
                self.dce, alias_handle
            )['Members']['Sids']
        except DCERPCException as e:
            self._raise_rpc_error(e, 'SamrGetMembersInAlias')

    def __enumerate_users_in_domain(self, domain_handle, index):
        try:
            return samr.hSamrEnumerateUsersInDomain(
                self.dce, domain_handle, enumerationContext = index
            )
        except DCERPCException as e:
            self._raise_rpc_error(e, 'SamrEnumerateUsersInDomain')

    def __enumerate_aliases_in_domain(self, domain_handle, index):
        try:
            return samr.hSamrEnumerateAliasesInDomain(
                self.dce, domain_handle, index
            )
        except DCERPCException as e:
            self._raise_rpc_error(e, 'SamrEnumerateAliasesInDomain')