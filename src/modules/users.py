from .module import Module
from .utils.sid import SidMapper
from .rpc import DsspWrapper as DsspW
from .rpc import SamrWrapper as SamrW
from .rpc import LsadWrapper as LsadW
from .exceptions import RpcAccessDenied, PipeNotAvailable

class Users(Module):
    AUDITABLE = True

    @classmethod
    def execute(cls, config, target):
        results = {'results': {'users': [], 'groups': []}, 'error': ''}
        groups_and_members = []

        dsspw = DsspW(config, target)

        # We avoid DCs. See the documentation for the reasoning.
        if dsspw.is_domain_controller():
            results['error'] = 'Target is a DC and will not be enumerated.'
            return results

        samrw = SamrW(config, target)
        lsadw = LsadW(config, target)

        # MS-LSAD allows us to specifically get the local account domain SID
        # to get local users and groups instead of going through
        # SamrLookupDomainInSamServer.
        local_account_domain_info = lsadw.get_local_account_domain_info()

        users = cls.__get_local_users(
            samrw, local_account_domain_info['DomainSid']
        )
        results['results']['users'] = users

        # Retrieving groups and their members from the two domains below.
        # Local account domain
        groups_and_members += cls.__get_local_account_groups(
            samrw, local_account_domain_info
        )

        # BUILTIN domain
        groups_and_members += cls.__get_builtin_groups(samrw)

        results['results']['groups'] = cls.__map_sids(
            lsadw, groups_and_members
        )

        samrw.close_samr_handle()

        return results

    @staticmethod
    def audit(config, target):
        results = {'results': {'sessions': {}}, 'error': ''}

        entry = {}

        try:
            SamrW(config, target)

            entry['hardened'] = 'False'
            entry['reason'] = 'Access is granted to RPC method SamrConnect.'
        except PipeNotAvailable:
            entry['hardened'] = 'True'
            entry['reason'] = 'The Security Account Manager Remote Protocol ' \
                              'is not available.'
        except RpcAccessDenied as e:
            entry['hardened'] = 'True'
            entry['reason'] = str(e)

        results['results']['sessions'] = entry

        return results
    
    @staticmethod
    def __get_local_users(samrw, domain_rpc_sid):
        domain_handle = samrw.open_domain(domain_rpc_sid)
        users = samrw.get_users(domain_handle)

        samrw.close_handle(domain_handle)

        return users

    @classmethod
    def __get_builtin_groups(cls, samrw):
        builtin_rpc_sid = SidMapper.get_builtin_rpc_sid()

        return cls.__get_domain_groups_and_members(samrw, builtin_rpc_sid, 'BUILTIN')

    @classmethod
    def __get_local_account_groups(cls, samrw, domain_info):
        local_account_rpc_sid = domain_info['DomainSid']
        local_account_name = domain_info['DomainName']

        return cls.__get_domain_groups_and_members(
            samrw, local_account_rpc_sid, local_account_name
        )

    @classmethod
    def __get_domain_groups_and_members(
        cls, samrw, domain_rpc_sid, domain_name
    ):
        results = []

        domain_handle = samrw.open_domain(domain_rpc_sid)
        aliases = samrw.get_domain_aliases(domain_handle)

        for rid, name in aliases.items():
            entry = {
                'rid': rid, 'name': f'{domain_name}\{name}', 'members': []
            }

            entry['members'] = cls.__get_users_in_group(
                samrw, domain_handle, rid
            )

            results.append(entry)

        samrw.close_handle(domain_handle)

        return results

    @staticmethod
    def __get_users_in_group(samrw, domain_handle, rid):
        members = []

        alias_handle = samrw.open_alias(domain_handle, rid)
        sids_info = samrw.get_members_in_alias(alias_handle)

        for sid_info in sids_info:
            rpc_sid = sid_info['Data']['SidPointer']
            member = {
                'name': '', 
                'sid': rpc_sid.formatCanonical(),
                'type': '',
            }

            members.append(member)

        samrw.close_handle(alias_handle)

        return members

    # The documentation explains the mapping sequence.
    @staticmethod
    def __map_sids(lsadw, groups_and_members):
        sids = []

        for group in groups_and_members:
            for member in group['members']:
                sid = member['sid']

                if sid not in sids:
                    sids.append(sid)

        mapped_sids = SidMapper.map_sids(lsadw, sids)

        if not mapped_sids:
            return groups_and_members

        for group in groups_and_members:
            for member in group['members']:
                member['name'] = mapped_sids[member['sid']]['name']
                member['type'] = mapped_sids[member['sid']]['type']

        return groups_and_members