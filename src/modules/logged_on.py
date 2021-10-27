from .module import Module
from .rpc import RrpWrapper as RrpW
from .rpc import LsadWrapper as LsadW
from .rpc import WkstWrapper as WkstW
from .utils.sid import SidValidator
from .utils.sid import SidMapper
from .exceptions import RpcAccessDenied, PipeNotAvailable

class LoggedOn(Module):
    AUDITABLE = True
    MAX_KEY_ENUM = 100

    @classmethod
    def execute(cls, config, target):
        results = {'results': {'logged_on': []}, 'error': ''}

        results['results']['logged_on'] = cls.__get_logged_on_by_registry(
            config, target
        )

        return results

    @staticmethod
    def audit(config, target):
        results = {'results': {'logged_on': {}}, 'error': ''}

        entry = {}

        try:
            rrpw = RrpW(config, target)

            users_handle = rrpw.open_users()
            rrpw.base_reg_enum_key(users_handle, 0)

            entry['hardened'] = 'False'
            entry['reason'] = 'The Remote Registry service is started, and ' \
                              'access is granted to the RPC methods ' \
                              'OpenUsers and BaseRegEnumKey.'
        except PipeNotAvailable:
            entry['hardened'] = 'True'
            entry['reason'] = 'The Remote Registry service is not started.'
        except RpcAccessDenied as e:
            entry['hardened'] = 'True'
            entry['reason'] = 'The Remote Registry service is started, but ' \
                              'HKEY_USERS is not readable or enumerable ' \
                              f'({str(e)}).'
        
        results['results']['logged_on'] = entry

        return results

    # This is only possible by administrators, except on Windows XP SP3.
    # I decided to remove it for now since it goes against the low-privileged
    # mindset, even if it's much cleaner than parsing the registry.
    @staticmethod
    def __get_logged_on_by_wkst(config, target):
        users = []

        wkst = WkstW(config, target)

        logged_on = wkst.get_logged_on()

        for user in logged_on['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
            entry = {}

            username = user['wkui1_username'][:-1]
            domain = user['wkui1_logon_domain'][:-1]
            
            domain_user = f'{domain}\\{username}'
            
            if domain_user not in users:
                entry['username'] = domain_user
                users.append(entry)

        return users

    @classmethod
    def __get_logged_on_by_registry(cls, config, target):
        users = []

        rrpw = RrpW(config, target)
        users_handle = rrpw.open_users()

        domain_sids = cls.__get_domain_sids(rrpw, users_handle)

        if domain_sids:
            lsadw = LsadW(config, target)

            users = cls.__map_sids(lsadw, domain_sids)

        return users

    @classmethod
    def __get_domain_sids(cls, rrpw, users_handle):
        domain_sids = []

        # I dislike the idea of potentially calling the method forever if
        # something quite unexpected happens. Stopping at MAX_KEY_ENUM.
        for index in range(cls.MAX_KEY_ENUM):
            subkey = rrpw.base_reg_enum_key(users_handle, index)

            if subkey is None:
                break

            sid = subkey['lpNameOut'][:-1]

            # We avoid built-in accounts and other arbitrary subkeys
            if SidValidator.is_domain_sid(sid):
                domain_sids.append(sid)

        return domain_sids

    @staticmethod
    def __map_sids(lsadw, sids):
        users = []

        mapped_sids = SidMapper.map_sids(lsadw, sids, False)

        for sid, value in mapped_sids.items():
            entry = {}

            if value['name'] == '':
                entry['username'] = sid
            else:
                entry['username'] = value['name']

            users.append(entry)

        return users