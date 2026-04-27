# Ghidra Headless Script: Common utilities for all analysis scripts
# @category Analysis
# @runtime Jython
#
# Usage in other scripts:
#   from ghidra_common import GhidraReport

import os
import codecs


class GhidraReport(object):
    """Common report builder for Ghidra headless scripts."""

    def __init__(self, script_name, suffix, title=None, program=None):
        self.script_name = script_name
        self.program = program  # Must be passed from calling script as currentProgram
        self.name = self.program.getName()
        self.output_dir = "/analysis/output"
        self.suffix = suffix
        self.title = title or suffix.replace("_", " ").title()
        self.lines = []

        self._log("INFO", "Script started")
        self._log("INFO", "Processing program='%s'" % self.name)

        # Header
        self.lines.append("=" * 60)
        self.lines.append("%s: %s" % (self.title, self.name))
        self.lines.append("=" * 60)

    def add(self, text):
        """Add a line to the report."""
        self.lines.append(text)

    def add_blank(self):
        """Add a blank line."""
        self.lines.append("")

    def add_section(self, title):
        """Add a section header."""
        self.lines.append("")
        self.lines.append("--- %s ---" % title)

    def log(self, level, message):
        """Print a log message with script name prefix."""
        self._log(level, message)

    def _log(self, level, message):
        print("[%s] %s: %s" % (level, self.script_name, message))

    def save(self):
        """Write report to output file and print to stdout."""
        output = "\n".join(self.lines)
        print(output)

        outfile = os.path.join(self.output_dir, "%s_%s.txt" % (self.name, self.suffix))
        self._log("DEBUG", "Writing output to '%s'" % outfile)
        try:
            with codecs.open(outfile, "w", encoding="utf-8") as f:
                f.write(output + "\n")
            print("\n[*] Saved to %s" % outfile)
            self._log("INFO", "Script completed successfully")
        except Exception as e:
            self._log("ERROR", "Failed to write output file '%s': %s" % (outfile, str(e)))

    def save_custom(self, suffix, content):
        """Write custom content to a specific output file."""
        outfile = os.path.join(self.output_dir, "%s_%s" % (self.name, suffix))
        try:
            with codecs.open(outfile, "w", encoding="utf-8") as f:
                f.write(content)
            print("[*] Saved to %s" % outfile)
        except Exception as e:
            self._log("ERROR", "Failed to write '%s': %s" % (outfile, str(e)))
