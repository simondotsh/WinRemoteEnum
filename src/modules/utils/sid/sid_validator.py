from re import match

class SidValidator():
    @staticmethod
    def is_domain_sid(sid):
        pattern = '^S-1-5-21-\d{8,10}-\d{8,10}-\d{8,10}-\d+$'

        return True if match(pattern, sid) else False