from .connection import Connection
from impacket.dcerpc.v5 import lsad, lsat
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException

class LsadWrapper(Connection):
    """ 
    Local Security Authority (Translation Methods) Remote Protocol [MS-LSAT] 
    is composed of a subset of opnums in an interface that also includes 
    the Local Security Authority (Domain Policy) [MS-LSAD] Remote Protocol"
    
    Since impacket has not implemented LsarOpenPolicy in the lsat interface and
    some of its methods require it, this class also handles lsat methods.
    
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/540f52f1-69ee-4316-8d07-5359d4b93cab
    """
    PIPE = 'lsarpc'
    UUID = lsad.MSRPC_UUID_LSAD

    def __init__(self, config, target):
        super().__init__(config, target, self.PIPE, self.UUID)

    def get_local_account_domain_info(self):
        policy_handle = self.__open_policy()

        domain_info = self.__query_local_account_domain(policy_handle)

        self.__close_policy_handle(policy_handle)

        return domain_info

    def lookup_sids(self, requested_sids):
        results = {}

        policy_handle = self.__open_policy()

        lookedup_sids = self.__lookup_sids(policy_handle, requested_sids)

        if lookedup_sids is None:
            return results

        results = self.__map_sids(requested_sids, lookedup_sids)

        self.__close_policy_handle(policy_handle)

        return results

    def get_primary_domain_info(self):
        policy_handle = self.__open_policy()

        domain_info = self.__query_dns_domain(policy_handle)

        self.__close_policy_handle(policy_handle)

        return domain_info

    def __map_sids(self, requested_sids, lookedup_sids):
        results = {}

        # The results are returned in the same order as the requested SIDs. 
        for index, entry in enumerate(
            lookedup_sids['TranslatedNames']['Names']
        ):
            sid_type = ''
            name = ''

            # We check if the SID has been mapped
            if entry['Use'] != SID_NAME_USE.SidTypeUnknown:
                sid_type = SID_NAME_USE.enumItems(entry['Use']).name

                domain = lookedup_sids['ReferencedDomains']['Domains']\
                                      [entry['DomainIndex']]['Name']
                sid_name = entry['Name']

                name = f"{domain}\{sid_name}"

            results[requested_sids[index]] = {
                'type': sid_type,
                'name': name,
            }

        return results

    def __open_policy(self):
        try:
            return lsad.hLsarOpenPolicy2(
                self.dce, MAXIMUM_ALLOWED
            )['PolicyHandle']
        except DCERPCException as e:
            self._raise_rpc_error(e, 'LsarOpenPolicy2')
    
    def __close_policy_handle(self, policy_handle):
        try:
            lsad.hLsarClose(self.dce, policy_handle)
        except:
            pass

    def __query_local_account_domain(self, policy_handle):
        try:
            return lsad.hLsarQueryInformationPolicy2(
                self.dce, policy_handle, 
                lsad.POLICY_INFORMATION_CLASS.PolicyLocalAccountDomainInformation
            )['PolicyInformation']['PolicyLocalAccountDomainInfo']
        except DCERPCException as e:
            self._raise_rpc_error(e, 'LsarQueryInformationPolicy2')

    def __query_dns_domain(self, policy_handle):
        try:
            # PolicyDnsDomainInformation returns info about the primary domain
            return lsad.hLsarQueryInformationPolicy2(
                self.dce, policy_handle, 
                lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation
            )['PolicyInformation']['PolicyDnsDomainInfo']
        except DCERPCException as e:
            self._raise_rpc_error(e, 'LsarQueryInformationPolicy2')

    # LsapLookupWksta: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/9d1166cc-bcfd-4e22-a8ac-f55eae57c99f
    def __lookup_sids(self, policy_handle, sids):
        try:
            return lsat.hLsarLookupSids(
                    self.dce, policy_handle, sids, 
                    lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
                )
        except DCERPCException as e:
            # At least one SID was not map; let's return the results anyway.
            if 'STATUS_SOME_NOT_MAPPED' in str(e):
                return e.get_packet()
            # No SIDs were mapped.
            elif 'STATUS_NONE_MAPPED' in str(e):
                return None
            else:
                self._raise_rpc_error(e, 'LsarLookupSids')