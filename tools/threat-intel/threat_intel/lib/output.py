"""Result collector + text/json/csv emission.

Modules call collector.add(dict) to accumulate records. CLI calls
collector.finalize() at end to emit JSON or CSV when --output-format set.
"""

import sys
import json
import csv

from . import configvars as cv


class ResultCollector:
    def __init__(self):
        self.records = []
        self._current = {}

    def add(self, record):
        if isinstance(record, dict):
            self.records.append(record)
        elif isinstance(record, list):
            self.records.extend(r for r in record if isinstance(r, dict))

    def start_record(self):
        self._current = {}

    def field(self, key, value):
        self._current[key] = value

    def end_record(self):
        if self._current:
            self.records.append(self._current)
            self._current = {}

    def finalize(self, file=None):
        if file is None:
            file = sys.stdout
        if cv.output_format == 'json':
            json.dump(self.records, file, indent=2, default=str, ensure_ascii=False)
            print(file=file)
        elif cv.output_format == 'csv':
            if not self.records:
                return
            seen, all_keys = set(), []
            for record in self.records:
                for key in record:
                    if key not in seen:
                        all_keys.append(key)
                        seen.add(key)
            writer = csv.DictWriter(file, fieldnames=all_keys, extrasaction='ignore')
            writer.writeheader()
            for record in self.records:
                writer.writerow({k: str(v) for k, v in record.items()})

    def clear(self):
        self.records = []
        self._current = {}


collector = ResultCollector()


def is_text_output():
    return cv.output_format == 'text'
