from datetime import datetime

class Now:
    @staticmethod
    def datetime():
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def datetime_hyphened():
        return datetime.now().strftime('%Y-%m-%d-%H-%M-%S')

    @staticmethod
    def time():
        return datetime.now().strftime('%H:%M:%S')