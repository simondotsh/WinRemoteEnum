from .module import Module
from .smb import SmbWrapper as SmbW
from .utils.time import TimeConverter

class Shares(Module):
    AUDITABLE = True
    __MAX_SHARE_LIST_ITEMS = 30

    @classmethod
    def execute(cls, config, target):
        results = {'results': {'shares': []}, 'error': ''}
        smbw = SmbW(config, target)

        shares = smbw.get_shares()

        for share in shares:
            entry = {}
            
            # Returned values are null-terminated
            share_name = share['shi1_netname'][:-1]

            readable = cls.__is_share_readable(smbw, share_name)

            if readable:
                content = cls.__get_share_first_level(smbw, share_name)
            else:
                content = []

            entry['name'] = share_name
            entry['comment'] = share['shi1_remark'][:-1]
            entry['readable'] = str(readable)
            entry['content'] = content

            results['results']['shares'].append(entry)

        smbw._disconnect()
        return results

    @classmethod
    def audit(cls, config, target):
        results = {'results': {'shares': []}, 'error': ''}
        smbw = SmbW(config, target)

        shares = smbw.get_shares()

        for share in shares:
            entry = {}

            share_name = share['shi1_netname'][:-1]

            readable = cls.__is_share_readable(smbw, share_name)
            entry['name'] = share_name
            entry['readable'] = str(readable)

            results['results']['shares'].append(entry)

        smbw._disconnect()
        
        return results

    @staticmethod
    def __is_share_readable(smbw, share_name):
        readable = True

        """
        IPC$ will always be readable, unwritable and contain no files 
        or directories. It is in fact a special share dedicated to
        connecting to named pipes.
        """
        if share_name != 'IPC$':
            readable = smbw.is_share_readable(share_name)

        return readable

    @classmethod
    def __get_share_first_level(cls, smbw, share_name):
        results = []

        if share_name == 'IPC$':
            return results

        content = smbw.get_share_content(share_name)

        if len(content) <= cls.__MAX_SHARE_LIST_ITEMS:
            results = cls.__get_share_content_info(smbw, content)
        else:
            results = cls.__get_share_content_counts(smbw, content)

        return results

    @staticmethod
    def __get_share_content_info(smbw, content):
        results = []

        for item in content:
            entry = {}

            longname = item.get_longname()

            if longname == '.' or longname == '..':
                continue

            entry['name'] = longname
            entry['is_directory'] = str(smbw.is_item_directory(item))
            entry['created'] = TimeConverter.nt_to_iso(item.get_ctime())
            entry['last_access'] = TimeConverter.nt_to_iso(item.get_atime())

            results.append(entry)

        return results

    @staticmethod
    def __get_share_content_counts(smbw, content):
        results = []
        directories = 0
        files = 0

        for item in content:
            if smbw.is_item_directory(item):
                directories += 1
            else:
                files += 1

        entry = {
            'content_too_large': 
            f'Share contains {files} files and {directories} directories.'
        }

        results.append(entry)

        return results