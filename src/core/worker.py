from .mapper import Mapper
from .reporting import Results
from multiprocessing import Pool
from itertools import repeat

class Worker:
    @classmethod
    def launch_module(cls, config, module, targets, audit, results_queue):
        module_args = ModuleArgs(module, config, audit, results_queue)

        pool = Pool(2)
        pool.starmap(
            cls.enumerate_target, zip(targets, repeat(module_args))
        )
        pool.close()
        
        cls.__wait_for_enumeration(pool)
    
    @staticmethod
    def enumerate_target(target, args):
        results = Results(target)

        try:
            module_results = Mapper.get_module_entrypoint(
                args.module, args.audit
            )(args.config, target)
        except NotImplementedError:
            raise
        except Exception as e:
            module_results = {'results': '', 'error': str(e)}

        results.set_results(module_results)
        args.queue.put(results.json)

    @staticmethod
    def __wait_for_enumeration(pool):
        pool.join()

class ModuleArgs():
    def __init__(self, module, config, audit, queue):
        self.module = module
        self.config = config
        self.audit = audit
        self.queue = queue