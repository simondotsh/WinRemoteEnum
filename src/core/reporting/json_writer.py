from definitions import RESULTS_ROOT
from src.utils import Now
from os import makedirs, path
from json import dumps

class JsonWriter:
    results_file = None
    total_targets = None
    results_count = None
    __results_dir = None
    __module = None
    __first_insert = None

    def __init__(self, total_targets):
        self.total_targets = total_targets
        self.__init_results_dir()

    def start_module(self, module, audit):
        self.__module = module
        self.__first_insert = True
        self.results_count = 0

        suffix = '_audit' if audit else ''

        self.results_file = path.join(self.__results_dir, f'{module}{suffix}.json')
        self.__add_json('[')

    def add_module_results(self, results):
        results['module'] = self.__module

        separator = ',\n'

        if self.__first_insert:
            separator = ''
            self.__first_insert = False

        self.__add_json(separator + dumps(results, indent=4))

        self.results_count += 1

    def end_module(self):
        self.__add_json(']')

    def __init_results_dir(self):
        self.__results_dir = path.join(
            RESULTS_ROOT, Now.datetime_hyphened(), 'json'
        )

        if not path.exists(self.__results_dir):
            makedirs(self.__results_dir)

    def __add_json(self, value):
        with open(self.results_file, 'a') as f:
            f.write(value)