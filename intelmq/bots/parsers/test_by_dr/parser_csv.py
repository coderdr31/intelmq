# -*- coding: utf-8 -*-

import csv
import io

from intelmq.lib.bot import ParserBot
from intelmq.lib import utils

CSV_PARSER_CONF_FILE = "/opt/drtest/csv.conf"


class TestByDrCsvParserBot(ParserBot):
    parse = ParserBot.parse_csv

    def __init__(self, bot_id):
        super(TestByDrCsvParserBot, self).__init__(bot_id=bot_id)
        self._config = utils.load_configuration(CSV_PARSER_CONF_FILE)

        if self._config.get('ignore_lines_starting'):
            self.ignore_lines_starting = self._config['ignore_lines_starting']

    def parse(self, report):
        raw_report = utils.base64_decode(report.get("raw")).strip()
        if self.ignore_lines_starting:
            raw_report = '\n'.join([line for line in raw_report.splitlines()
                                    if not any([line.startswith(prefix) for prefix
                                                in self.ignore_lines_starting])])
        if self._config.get('ignore_start_lines'):
            raw_report = '\n'.join([line for line in raw_report.splitlines()[int(self._config['ignore_start_lines']):]])

        delimiter_default = ','
        if self._config.get('delimiter'):
            delimiter_default = self._config.get('delimiter', ',')
        for line in csv.DictReader(io.StringIO(raw_report), fieldnames=self._config['sequence'],
                                   delimiter=delimiter_default):
            yield line

    def parse_line(self, row, report):  # list、raw解析出的一条,report
        event = self.new_event(report)  # report->event
        for key in row.keys():
            class_name = event.harmonization_config[key]['type']
            if class_name == "DateTime":
                row[key] = row[key].strip()
                if row[key].endswith("UTC") or row[key].endswith("+00:00"):
                    pass
                else:
                    row[key] = row[key] + " UTC"
            elif class_name == "URL":
                if '://' not in row[key]:
                    row[key] = 'http://' + row[key]
        for key, value in row.items():
            if value in ["-", "", "N/A"]:
                continue
            event.add(key, value)

        # if not event.add("source.ip", row[2], raise_failure=False):
        #     event.add("source.url", self.add_http(row[2]))
        #     event.add('source.ip', urlparse(row[2]).netloc)

        yield event


BOT = TestByDrCsvParserBot


# class test(object):
#     def f1(self):
#         config = utils.load_configuration(CSV_PARSER_CONF_FILE)
#         tmp = []
#         tmp = config['ignore_lines_starting']
#         # for i in list(config.keys()):
#         for i in tmp:
#             print(i)
#         num = int(config['ignore_start_lines']) + 1
#         print(num)
#
#     print(CSV_PARSER_CONF_FILE)


# if __name__ == '__main__':  # pragma: no cover
# config = utils.load_configuration(CSV_PARSER_CONF_FILE)
