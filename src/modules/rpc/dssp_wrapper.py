from .connection import Connection
from .implementation import dssp
from impacket.dcerpc.v5.rpcrt import DCERPCException

class DsspWrapper(Connection):
    PIPE = 'lsarpc'
    UUID = dssp.MSRPC_UUID_DSSP

    def __init__(self, config, target):
        super().__init__(config, target, self.PIPE, self.UUID)

    def is_domain_controller(self):
        primary_dc = dssp.DSROLE_MACHINE_ROLE.\
                     DsRole_RolePrimaryDomainController
        backup_dc = dssp.DSROLE_MACHINE_ROLE.DsRole_RoleBackupDomainController

        machine_role = self.__get_primary_domain_info()['MachineRole']

        if machine_role == primary_dc or machine_role == backup_dc:
            return True
        else:
            return False

    def __get_primary_domain_info(self):
        try:
            return dssp.hDsRolerGetPrimaryDomainInformation(
                self.dce, 
                dssp.DSROLE_PRIMARY_DOMAIN_INFO_LEVEL.\
                DsRolePrimaryDomainInfoBasic
            )['DomainInfo']['DomainInfoBasic']
        except DCERPCException as e:
            self._raise_rpc_error(e, 'DsRolerGetPrimaryDomainInformation')

    def get_machine_role(self):
        return self.__get_primary_domain_info()['MachineRole']

    def get_friendly_machine_role(self, machine_role):
        machines_roles = {
            dssp.DSROLE_MACHINE_ROLE.DsRole_RoleStandaloneWorkstation: 
            'Standalone Workstation',
            dssp.DSROLE_MACHINE_ROLE.DsRole_RoleMemberWorkstation: 
            'Domain-joined Workstation',
            dssp.DSROLE_MACHINE_ROLE.DsRole_RoleStandaloneServer: 
            'Standalone Server',
            dssp.DSROLE_MACHINE_ROLE.DsRole_RoleMemberServer: 
            'Domain-joined Server',
            dssp.DSROLE_MACHINE_ROLE.DsRole_RoleBackupDomainController: 
            'Backup Domain Controller',
            dssp.DSROLE_MACHINE_ROLE.DsRole_RolePrimaryDomainController: 
            'Primary Domain Controller',
        }

        return machines_roles[machine_role]

    def is_workstation(self, machine_role):
        workstation_roles = (
            dssp.DSROLE_MACHINE_ROLE.DsRole_RoleStandaloneWorkstation,
            dssp.DSROLE_MACHINE_ROLE.DsRole_RoleMemberWorkstation,
        )
        
        if machine_role in workstation_roles:
            return True
        else:
            return False