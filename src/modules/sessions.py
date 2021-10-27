from .module import Module
from .rpc import SrvsWrapper as SrvsW
from .exceptions import RpcAccessDenied, PipeNotAvailable

class Sessions(Module):
    AUDITABLE = True

    @staticmethod
    def execute(config, target):
        results = {'results': {'sessions': []}, 'error': ''}
        sessions = []

        srvsw = SrvsW(config, target)
        sessions = srvsw.get_sessions()

        # The results will contain at least our session.
        for session in sessions:
            entry = {}

            entry['username'] = session['sesi10_username'][:-1]
            # Windows XP SP3 will not report the backslashes, while
            # modern versions will.
            entry['source'] = session['sesi10_cname'][:-1].replace('\\', '')
            entry['active_time'] = session['sesi10_time']
            entry['idle_time'] = session['sesi10_idle_time']

            results['results']['sessions'].append(entry)

        return results

    @staticmethod
    def audit(config, target):
        results = {'results': {'sessions': {}}, 'error': ''}

        entry = {}

        try:
            srvsw = SrvsW(config, target)
            srvsw.get_sessions()

            entry['hardened'] = 'False'
            entry['reason'] = 'Access is granted to RPC method '\
                              'NetrSessionEnum.'
        except PipeNotAvailable:
            entry['hardened'] = 'True'
            entry['reason'] = 'The Server Service Remote Protocol is not ' \
                              'available.'
        except RpcAccessDenied as e:
            entry['hardened'] = 'True'
            entry['reason'] = str(e)

        results['results']['sessions'] = entry

        return results