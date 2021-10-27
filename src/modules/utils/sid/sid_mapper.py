from .known_sids import KnownSids
from impacket.dcerpc.v5.dtypes import RPC_SID

class SidMapper():
    @classmethod
    def map_sids(cls, lsadw, requested_sids, check_builtin=True):
        results = {}

        if check_builtin:
            # Let's avoid requesting a few SIDs if possible.
            for sid in requested_sids:
                if sid in KnownSids.sids:
                    results[sid] = {
                        'name': KnownSids.sids[sid],
                        'type': 'SidTypeWellKnownGroup'
                    }

            # We remove the SIDs that have been added to the results.
            requested_sids = [
                sid for sid in requested_sids if sid not in results.keys()
            ]
   
        mapped_sids = lsadw.lookup_sids(requested_sids)

        # If a SID has not been mapped, it will not be in the returned results.
        for sid in requested_sids:
            name = ''
            type = ''

            if sid in mapped_sids:
                name = mapped_sids[sid]['name']
                type = mapped_sids[sid]['type']

            results[sid] = {'name': name,'type': type} 

        return results

    @staticmethod
    def get_builtin_rpc_sid():
        rpc_sid = RPC_SID()
        rpc_sid.fromCanonical('S-1-5-32')

        return rpc_sid