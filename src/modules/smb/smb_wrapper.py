from .connection import Connection
from impacket.smbconnection import SessionError
from impacket.smb import ATTR_DIRECTORY

class SmbWrapper(Connection):
    def __init__(self, config, target, try_smbv1=False, authenticate=True):
        super().__init__(config, target, try_smbv1, authenticate)

    def get_host_info(self):
        results = self.get_smb_info()
        
        results['dns_hostname'] = self.smb.getServerDNSHostName()
        results['os'] = self.smb.getServerOS()
        results['build'] = self.smb.getServerOSBuild()
        results['netbios_domain_name'] = self.smb.getServerDomain()
        results['domain_name'] = self.smb.getServerDNSDomainName()

        return results

    def get_smb_info(self):
        results = {}

        results['smb_signing_required'] = str(self.smb.isSigningRequired())
        results['smbv1_enabled'] = str(self.is_smbv1)

        return results

    def get_shares(self):
        return self.smb.listShares()

    def get_share_content(self, share):
        return self.smb.listPath(share, '*')

    def is_item_directory(self, item):
        return item.is_directory() == ATTR_DIRECTORY

    def is_share_readable(self, share):
        try:
            self.get_share_content(share)
            return True
        except SessionError:
            # TODO: If there's a different error than STATUS_ACCESS_DENIED,
            # we will return as unreadable even if it may not be the case.
            return False