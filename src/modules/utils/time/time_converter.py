from datetime import datetime, timedelta

class TimeConverter:
    @staticmethod
    def nt_to_iso(nt_time):
        """
        "The NT time epoch on Windows NT and later refers to the Windows NT 
        system time in 10^−7 s intervals from 00:00:00 1 January 1601."

        https://en.wikipedia.org/wiki/Epoch_(computing)
        """
        converted = datetime(1601, 1, 1) + timedelta(seconds=nt_time/10**7)

        return converted.isoformat(' ') + ' UTC'