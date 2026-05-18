"""YARA scanner with error-tolerant compilation.

If main rules file has syntax errors, falls back to compiling individual
includes and skipping the broken ones (useful for cobbled-together rule packs).
"""

import os
import warnings

from ..lib.display import error, info, section, table
from ..lib.output import collector


class YaraScanner:
    def __init__(self, rules_path):
        self.rules_path = os.path.abspath(rules_path)
        self.rules = None
        self.skipped = []
        self._compiled_count = 0

        if not os.path.isfile(self.rules_path):
            error(f"YARA rules file not found: {self.rules_path}")
            return

        try:
            import yara
            self._yara = yara
            try:
                self.rules = self._compile_in_context(self.rules_path)
                self._compiled_count = 1
            except (yara.SyntaxError, yara.Error):
                self.rules, self.skipped = self._compile_with_fallback(self.rules_path)
                if not self.rules:
                    error("All YARA rules failed to compile.")
        except ImportError:
            error("YARA scanning requires yara-python: pip install yara-python")

    def _compile_in_context(self, rules_path):
        rules_dir = os.path.dirname(rules_path)
        saved = os.getcwd()
        try:
            if rules_dir:
                os.chdir(rules_dir)
            return self._yara.compile(filepath=rules_path)
        finally:
            os.chdir(saved)

    def _compile_with_fallback(self, rules_path):
        rules_dir = os.path.dirname(rules_path)
        includes = []
        try:
            with open(rules_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('include') and '"' in line:
                        inc = line.split('"')[1]
                        full = os.path.normpath(os.path.join(rules_dir, inc))
                        if os.path.isfile(full):
                            includes.append(full)
        except Exception:
            return None, []
        if not includes:
            return None, []
        valid, skipped = {}, []
        for i, inc in enumerate(includes):
            try:
                self._compile_in_context(inc)
                valid[f'rule_{i}'] = inc
            except Exception as e:
                skipped.append((os.path.basename(inc), str(e).split('\n')[0][:120]))
        if not valid:
            return None, skipped
        self._compiled_count = len(valid)
        saved = os.getcwd()
        try:
            if rules_dir:
                os.chdir(rules_dir)
            rules = self._yara.compile(filepaths=valid)
        finally:
            os.chdir(saved)
        return rules, skipped

    def scan_file(self, filepath):
        if not self.rules:
            return []
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            matches = self.rules.match(filepath)
        return [{
            'rule': m.rule,
            'tags': list(m.tags),
            'meta': m.meta,
            'strings_count': len(m.strings),
        } for m in matches]

    def scan_directory(self, dirpath):
        results = []
        for root, _, files in os.walk(dirpath):
            for fname in files:
                fpath = os.path.join(root, fname)
                for r in self.scan_file(fpath):
                    r['file'] = fpath
                    results.append(r)
        return results

    def scan_and_display(self, target):
        target = os.path.abspath(target)
        results = self.scan_directory(target) if os.path.isdir(target) else self.scan_file(target)
        section("YARA SCAN REPORT")
        if self.skipped:
            info(f"Compiled: {self._compiled_count}, skipped: {len(self.skipped)}")
        if not results:
            info("No YARA matches found.")
            return
        rows = [{
            'File': os.path.basename(r.get('file', target)),
            'Rule': r['rule'],
            'Tags': ', '.join(r['tags']) if r['tags'] else '',
            'Strings': str(r['strings_count']),
            'Description': str((r.get('meta') or {}).get('description', '')),
        } for r in results]
        table(rows, ['File', 'Rule', 'Tags', 'Strings', 'Description'], [30, 30, 20, 9, 50])
        collector.add(rows)
