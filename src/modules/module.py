class Module:
    @classmethod
    def execute(cls, *args):
        raise NotImplementedError(f'Module {cls.__name__} has not implemented '
                                  'the execute method.')

    @classmethod
    def audit(cls, *args):
        raise NotImplementedError(f'Module {cls.__name__} has not implemented '
                                  'the audit method.')