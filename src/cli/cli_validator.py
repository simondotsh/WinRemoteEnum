from src.core import Mapper
from os.path import isfile, expanduser
from ipaddress import ip_network
from itertools import chain

class CliValidator:
    @classmethod
    def validate_targets(cls, targets):
        entries = []

        # In case of tilde in path
        targets = expanduser(targets)

        if isfile(targets):
            with open(targets) as f:
                entries = [line.rstrip() for line in open(targets)]
        else:
            entries.append(targets)

        return cls.__validate_target_entries(entries)
    
    def __validate_target_entries(entries):
        valid_targets_iter = iter([])
        invalid_targets = []
        added_one = False

        for entry in entries:
            try:
                # Host bits are ignored; will yield the entire subnet
                ip_or_range = ip_network(entry, False)

                valid_targets_iter = chain(
                    valid_targets_iter, ip_or_range.hosts()
                )

                added_one = True
            except:
                invalid_targets.append(entry)

        return valid_targets_iter if added_one else None, invalid_targets

    @staticmethod
    def validate_modules(modules):
        valid_modules = []
        invalid_modules = []

        for module in modules.split(','):
            if module in Mapper.MODULES:
                valid_modules.append(module)
            else:
                invalid_modules.append(module)

        return valid_modules, invalid_modules

    @staticmethod
    def validate_modules_audit(modules):
        valid_modules = []
        invalid_modules = []

        for module in modules:
            if Mapper.MODULES[module].AUDITABLE:
                valid_modules.append(module)
            else:
                invalid_modules.append(module)

        return valid_modules, invalid_modules