from src.core import Mapper, Logger
from src.utils import ConnectionConfig
from .cli_validator import CliValidator
from .credentials_validator import CredentialsValidator
from definitions import VERSION
from argparse import ArgumentParser
from getpass import getpass

class Cli:
    @classmethod
    def parse_and_validate(cls):
        parser = cls.__get_parser()
        args = parser.parse_args()

        if (args.password is None and args.nt_hash is None):
            args.password = getpass(f'Password for {args.username}: ')

        args.modules = cls.__validate_modules(args.modules)

        # Currently, all modules support auditing but let's future-proof.
        if args.audit:
            args.modules = cls.__validate_modules_audit(args.modules)

        config = ConnectionConfig(args)

        # First, we valid that the format is valid, then we validate that
        # we can authenticate on targets.
        args.targets = cls.__validate_targets(
            config, args.targets, args.no_validation
        )

        return config, args

    @staticmethod
    def __get_parser():
        parser = ArgumentParser()
        
        # Targets
        parser.add_argument('targets', 
            help='Targets to enumerate. Must be a single IP (e.g. 10.0.0.1), '
                 'a range (e.g. 10.0.0.0/24), or a file containing '
                 'the aforementioned formats separated by a new line.'
        )

        # Version
        parser.add_argument(
            '-v', '--version', action='version', version=f'WinRemoteEnum {VERSION}'
        )
        
        # Credentials
        parser.add_argument('-u', '--username', dest='username', required=True,
            help='Username used to authenticate on targets.'
        )

        parser.add_argument('-d', '--domain', dest='domain', required=True,
            help='Domain to authenticate to.'
        )

        pw_group = parser.add_mutually_exclusive_group()

        pw_group.add_argument('-p', '--password', dest='password',
            help='Username\'s password. If a password or a hash is not '
                 'provided, a prompt will request the password on execution.'
        )

        pw_group.add_argument('-nt', '--nt-hash', dest='nt_hash',
            help='Username\'s NT hash.'
        )
        
        # Modules
        parser.add_argument('-m', '--modules', dest='modules',
            default=Mapper.get_printable_modules(),
            help='Modules to execute on targets, separated by a comma (,). ' 
                 f'List of modules: {Mapper.get_printable_modules()} '
                 '(default: runs all).'
        )

        # Audit
        parser.add_argument('-a', '--audit', dest='audit', 
            action='store_true', default=False,
            help='Audit mode. This will validate a subset of operations '
                 'against targets for the selected modules, without '
                 'reporting the entire results. See the audit section '
                 'in the wiki for each operation performed.'
        )

        # No validation
        parser.add_argument('-nv', '--no-validation', dest='no_validation', 
            action='store_true', default=False,
            help='Credentials and connectivity to targets will not '
                 'be validated.'
        )

        # Timeout
        parser.add_argument('-t', '--timeout', dest='timeout', default=2, 
            type=int,
            help='Drops connection after x seconds when waiting to receive '
                 'packets from the target (default: 2).'
        )

        return parser

    @classmethod
    def __validate_targets(cls, config, targets, no_validation):
        valid_targets, invalid_targets = CliValidator.validate_targets(targets)

        if invalid_targets:
            option = ''
            while option not in ['y', 'n']:
                Logger.print_red(
                    f'{len(invalid_targets)} targets are invalid IPs or range.'
                )
                option = Logger.input(
                    'Would you like to ignore them and continue? (y/n)'
                )

            if option == 'n':
                Logger.print_red('Invalid targets:')
                Logger.print_red(invalid_targets)
                exit(0)

        if not valid_targets:
            Logger.print_red('No valid targets loaded. Exiting.')
            exit(0)

        if not no_validation:
            return cls.__validate_credentials(config, valid_targets)
        else:
            return valid_targets

    @staticmethod
    def __validate_modules(modules):
        valid_modules, invalid_modules = CliValidator.validate_modules(modules)

        if invalid_modules:
            option = ''
            while option not in ['y', 'n']:
                Logger.print_red('The following modules are invalid:')
                Logger.print_red(invalid_modules)
                option = Logger.input(
                    'Would you like to ignore them and continue? (y/n)'
                )

            if option == 'n':
                exit(0)

        if not valid_modules:
            Logger.print_red('No valid modules loaded. Exiting.')
            exit(0)

        return valid_modules

    @staticmethod
    def __validate_modules_audit(modules):
        valid_modules, invalid_modules = CliValidator.validate_modules_audit(
            modules
        )

        if invalid_modules:
            option = ''
            while option not in ['y', 'n']:
                Logger.print_red(
                    'The following modules do not support auditing:'
                )
                Logger.print_red(invalid_modules)
                option = Logger.input(
                    'Would you like to ignore them and continue? (y/n): '
                )

            if option == 'n':
                exit(0)

        if not valid_modules:
            Logger.print_red('No valid modules loaded. Exiting.')
            exit(0)

        return valid_modules

    @staticmethod
    def __validate_credentials(config, targets):
        Logger.print(
            'Validating authentication on targets using '
            'the provided credentials.'
        )
        Logger.print(
            'This may take a while depending on your timeout value if '
            'targets cannot be reached.'
        )

        valid_targets, invalid_count = CredentialsValidator.validate(
            config, targets
        )

        valid_count = len(valid_targets)

        if valid_count == 0:
            Logger.print_red(
                'Could not sucessfully authenticate on any target. Exiting.'
            )
            exit(0)

        Logger.print(f'Successfully authenticated on {valid_count} targets.')
        Logger.print(
            f'Could not reach or authenticate on {invalid_count} targets.'
        )
        Logger.print('Proceeding to module execution on successful targets.\n')

        return valid_targets