from src.modules.logged_on import LoggedOn
from src.modules import *

class Mapper():
    EXECUTE_METHOD = 'execute'
    AUDIT_METHOD = 'audit'

    MODULES = {
        'sessions': Sessions,
        'users': Users,
        'host_info': HostInfo,
        'shares': Shares,
        'logged_on': LoggedOn,
    }

    @classmethod
    def get_module_entrypoint(cls, module, is_audit):
        method = cls.AUDIT_METHOD if is_audit else cls.EXECUTE_METHOD
        return getattr(cls.MODULES[module], method)

    @classmethod
    def get_printable_modules(cls):
        return ','.join(cls.MODULES.keys())