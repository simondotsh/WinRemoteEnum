from definitions import TEMPLATES_ROOT
from os import path
import json

class HtmlWriter():
    """
    Beware! You have been warned!

    Unless absolutely necessary, do not wander in this realm for the sake
    of your own sanity. HTML generation is rarely a pleasant exercise.
    """
    @classmethod
    def generate_module(cls, module, results_file, audit):
        html = ''
        suffix = '_audit' if audit else ''

        results = json.load(open(results_file))

        html += f'<h2>Module: {module}</h2>'

        for entry in results:
            html += cls.__init_target(module, entry)

            # If an error has been reported, no results will be available.
            if entry['error'] != '':
                continue

            # This is the first level of the results dict/list
            for key, value in entry['results'].items():
                html += f'<h4>{key}</h4>'

                if not value:
                    html += '<p>None</p>'
                    continue

                """
                Essentially, the results will be printed in a table
                unless one of the keys contains an array or the value is
                a dictionary.
                """
                if cls.__is_dict(value):
                    html += cls.__format_list(value)
                else:
                    format_as_table = False
                    if cls.__is_list(value):
                        if not cls.__contains_list(value[0]):
                            format_as_table = True

                    html += cls.__format_results(format_as_table, value)

        cls.__write_html(
            path.join(
                path.dirname(results_file), '..', f'{module}{suffix}.html'
            ), 
            module, html
        )

    @staticmethod
    def write_index(results_file, modules, audit):
        template_file = path.join(TEMPLATES_ROOT, 'index.html')
        suffix = '_audit' if audit else ''
        index_file = path.join(path.dirname(results_file), '..', 'index.html')
        html = ''

        with open(template_file) as f:
            template = f.read()

        for module in modules:
            module += suffix
            html += f"""<li class="list-group-item">
                            <a href="{module}.html">{module}</a>
                    </li>"""

        template = template.replace('$MODULES', html)

        with open(index_file, 'w+') as f:
            f.write(template)

    @staticmethod
    def __init_target(module, entry):
        html = f"""<hr/><div class="mt-4">
                    <h3 id="{entry["target"]}">{entry["target"]}</h3>
                    <table class="table mt-4">
                        <thead class="table-light">
                            <tr>
                                <td width="15%">Start</td>
                                <td width="15%">End</td>
                                <td>Error</td>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>{entry["start"]}</td>
                                <td>{entry["end"]}</td>
                                <td>{entry["error"]}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>"""

        return html

    @staticmethod
    def __is_list(object):
        if isinstance(object, list):
            return True
        else:
            return False

    @staticmethod
    def __is_dict(object):
        if isinstance(object, dict):
            return True
        else:
            return False
    
    @classmethod
    def __contains_list(cls, dict):
        for key, value in dict.items():
            if cls.__is_list(value):
                return True
        
        return False

    @classmethod
    def __format_results(cls, format_as_table, results):
        if format_as_table:
            return cls.__format_table(results)
        else:
            return cls.__format_list_potential_table(results)

    @classmethod
    def __format_table(cls, results):
        table = ''

        for entry in results:
            if not table:
                table = cls.__init_table(entry.keys())

            table += '<tr>'
                
            for key, value in entry.items():
                table += f'<td>{value}</td>'

            table += '</tr>'

        if not table:
            table += '<p>None</p>'
        else:
            table += '</tbody></table>'

        return table

    @staticmethod
    def __format_list(results):
        html = '<table class="table table-bordered mt-4"><tbody>'

        for key, value in results.items():
            html += f"""<tr>
                            <th width="15%">{key}</td>
                            <td>{value}</td>
                    </tr>"""

        html += '</tbody></table>'

        return html

    @classmethod
    def __format_list_potential_table(cls, results):
        html = ''

        for entry in results:
            table = ''
            dict = {}

            for key, value in entry.items():
                if cls.__is_list(value):
                    dict[key] = cls.__format_table(value)
                else:
                    dict[key] = value
            
            html += cls.__format_list(dict)
            html += table

        return html

    @staticmethod
    def __init_table(keys):
        table = '<table class="table"><thead class="table-light"><tr>'

        for key in keys:
            table += f'<td>{key}</td>'

        table += '</tr></thead><tbody>'

        return table

    @staticmethod
    def __write_html(file, module, html):
        template_file = path.join(TEMPLATES_ROOT, 'module.html')

        with open(template_file) as f:
            template = f.read()

        template = template.replace('$MODULE', module)
        template = template.replace('$RESULTS', html)

        with open(file, 'w+') as f:
            f.write(template)