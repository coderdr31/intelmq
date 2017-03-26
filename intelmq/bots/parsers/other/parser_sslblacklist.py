# -*- coding: utf-8 -*-

from intelmq.lib.bot import ParserBot


class OtherSslblacklistParserBot(ParserBot):
    ignore_lines_starting = ['#']
    parse = ParserBot.parse_csv
    recover_line = ParserBot.recover_line_csv

    def parse_line(self, row, report):
        event = self.new_event(report)
        event.add("time.source", row[0]+ " UTC")
        # event.add("malware.hash", self.row[1])
        event.add("event_description.text", row[2])
        event.add('classification.type', 'blacklist')
        event.add("raw", self.recover_line(row))
        yield event

BOT = OtherSslblacklistParserBot