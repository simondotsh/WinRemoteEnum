from .worker import Worker
from .reporting import JsonWriter, HtmlWriter
from .logger import Logger
from multiprocessing import Manager
from threading import Thread

class Orchestrator:
    QUEUE_DONE = 'QUEUE_DONE'

    @classmethod
    def launch_modules(cls, config, modules, targets, audit):
        results_queue = Manager().Queue()
        json_writer = JsonWriter(len(targets))

        cls.__start_queue(results_queue, json_writer)

        for module in modules:
            cls.__start_output(module, json_writer, audit, len(targets))

            Worker.launch_module(config, module, targets, audit, results_queue)

            cls.__wait_for_results_insertion(results_queue)
            cls.__end_output(module, json_writer, audit)
        
        cls.__stop_queue(results_queue)

        HtmlWriter.write_index(json_writer.results_file, modules, audit)

    @classmethod
    def insert_results_worker(cls, results_queue, json_writer):
        while True:
            # This will hang until an item is put.
            results = results_queue.get()

            # As specified above, we must put an item to get to this point.
            if (results == cls.QUEUE_DONE):
                results_queue.task_done()
                break

            json_writer.add_module_results(results)

            cls.print_progress(json_writer)

            results_queue.task_done()

    @staticmethod
    def print_progress(json_writer):
        total_targets = json_writer.total_targets
        results_written = json_writer.results_count

        # We will write five times if there are more than 20 targets
        # to not flood the user.
        if total_targets > 20:
            if results_written % round(total_targets/5) == 0:
                progress = round(results_written * 100 / total_targets)
                Logger.module_progress(progress)

    @staticmethod
    def __start_output(module, json_writer, audit, target_count):
        json_writer.start_module(module, audit)
        Logger.start_module(module, target_count)

    def __end_output(module, json_writer, audit):
        json_writer.end_module()
        HtmlWriter.generate_module(module, json_writer.results_file, audit)
        Logger.end_module(module)

    @classmethod
    def __start_queue(cls, results_queue, json_writer):
        Thread(
            target=cls.insert_results_worker, 
            args=(results_queue, json_writer), daemon=True
        ).start()

    @classmethod
    def __stop_queue(cls, results_queue):
        results_queue.put(cls.QUEUE_DONE)

    @staticmethod
    def __wait_for_results_insertion(results_queue):
        results_queue.join()