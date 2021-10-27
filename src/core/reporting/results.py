from src.utils import Now

class Results:
    def __init__(self, target):
        self.json = {}
        self.json['target'] = target
        self.json['start'] = Now.datetime()

    def set_results(self, results):
        self.json['results'] = results['results']
        self.json['error'] = results['error']
        self.json['end'] = Now.datetime()