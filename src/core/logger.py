from src.utils.now import Now

class Logger:
    @classmethod
    def start_module(cls, module, targets_count):
        print(
            f'{cls.__time()} Executing module {cls.__bold(module)} '
            f'on {targets_count} targets.'
        )

    @classmethod
    def module_progress(cls, percentage):
        print(f'{cls.__time()} {percentage}% done.')

    @classmethod
    def end_module(cls, module):
        print(f'{cls.__time()} Module {cls.__bold(module)} has completed.\n')

    @classmethod
    def print(cls, message):
        print(f'{cls.__time()} {message}')

    @classmethod
    def print_red(cls, message):
        print(f'\033[0;31m{cls.__time()} {message}\033[0m')

    @classmethod
    def input(cls, message):
        return input(f'\033[0;31m{cls.__time()} {message}: \033[0m')

    @staticmethod
    def __time():
        return f'[{Now.time()}]'

    @staticmethod
    def __bold(message):
        return f'\033[1m{message}\033[0m'
