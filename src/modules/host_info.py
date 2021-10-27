from .module import Module
from .smb import SmbWrapper as SmbW
from .rpc import ScmrWrapper as ScmrW
from .rpc import DsspWrapper as DsspW
from .utils.os_build import BuildMapper

class HostInfo(Module):
    AUDITABLE = True

    @classmethod
    def execute(cls, config, target):
        results = {'results': {'info': {}}, 'error': ''}
        entry = {}

        dsspw = DsspW(config, target)
        machine_role = dsspw.get_machine_role()

        # SMBv1 returns the OS versions more accurately
        smbw = SmbW(config, target, True)
        entry = cls.__get_host_info(smbw, dsspw, machine_role)
        smbw._disconnect()

        entry['machine_role'] = dsspw.get_friendly_machine_role(
            machine_role
        )

        scmrw = ScmrW(config, target)
        entry['local_admin'] = str(scmrw.is_local_admin())

        results['results']['info'] = entry

        return results

    @staticmethod
    def audit(config, target):
        results = {'results': {'info': {}}, 'error': ''}

        # One does not need to be authenticated to obtain this.
        smbw = SmbW(config, target, True, False)
        results['results']['info'] = smbw.get_smb_info()

        smbw._disconnect()
        
        return results

    @staticmethod
    def __get_host_info(smbw, dsspw, machine_role):
        host_info = smbw.get_host_info()

        # We return a friendlier version of the OS when not using SMBv1
        if not smbw.is_smbv1:
            friendly_os = BuildMapper.map_windows_build(
                host_info['build'],
                dsspw.is_workstation(machine_role)
            )

            if friendly_os:
                host_info['os'] = friendly_os

        return host_info