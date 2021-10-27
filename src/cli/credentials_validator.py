from src.modules.smb import SmbWrapper as SmbW
from src.modules.exceptions import SmbAuthenticationFailed
from src.core.logger import Logger

class CredentialsValidator():
    @classmethod
    def validate(cls, config, targets):
        valid_targets = []
        invalid_targets_count = 0
        valid_creds = False
        
        for target in targets:
            target = str(target)

            try:
                smbw = SmbW(config, target)
                smbw._disconnect()

                valid_creds = True
                valid_targets.append(target)
            except SmbAuthenticationFailed:
                # We attempt to avoid an account lockout.
                if not valid_creds:
                    cls.__continue_or_exit(target)
                    
                    valid_creds = True
            except Exception:
                invalid_targets_count += 1
        return valid_targets, invalid_targets_count
    
    @staticmethod
    def __continue_or_exit(target):
        option = ''

        while option not in ['y', 'n']:
            option = Logger.input(
                f'Logon failure on target {target}, and credentials have '
                'not been successfully validated on any target yet.\n'
                'Are you sure that your credentials are valid? '
                'Would you like to continue anyway? (y/n): '
            )

        if option == 'n':
            exit(0)