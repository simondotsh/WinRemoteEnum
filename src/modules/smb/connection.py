from src.modules.exceptions import ConnectionError, SmbAuthenticationFailed
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SMB_DIALECT

class Connection:
    smb = None
    is_smbv1 = False

    def __init__(self, config, target, try_smbv1, authenticate):
        try:
            self.smb = self.__get_smb_connection(config, target, try_smbv1)

            if authenticate:
                self.smb.login(
                    config.username, config.password, config.domain,
                    nthash=config.nt_hash
                )
        except OSError as e:
            if 'Connection refused' in str(e):
                raise ConnectionError(f'Connection refused: {str(e)}.')
            elif 'timed out' in str(e):
                raise ConnectionError(f'Connection timed out: {str(e)}.')
            else:
                raise
        except SessionError as e:
            if 'STATUS_LOGON_FAILURE' in str(e):
                raise SmbAuthenticationFailed(str(e))
            else:
                raise
        except Exception:
            raise
    
    def __get_smb_connection(self, config, target, try_smbv1=False):
        if try_smbv1:
            try:
                connection = SMBConnection(
                    target, target, timeout=config.timeout, 
                    preferredDialect=SMB_DIALECT
                )

                self.is_smbv1 = True

                return connection
            except:
                pass

        return SMBConnection(target, target, timeout=config.timeout)


    def _disconnect(self):
        try:
            self.smb.logoff()
        except:
            pass

    def __del__(self):
        self._disconnect()