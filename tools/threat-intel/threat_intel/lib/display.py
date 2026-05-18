"""Generic dict-to-terminal renderer.

Replaces the per-field color print blocks that bloat malwoverview modules
with a single helper.
"""

from .colors import mycolors
from . import configvars as cv
from .output import is_text_output


def section(title, width=100):
    if not is_text_output():
        return
    print()
    print(title.center(width))
    print('-' * width)


def field(name, value, error=False, colsize=22):
    if not is_text_output():
        return
    color = mycolors.foreground.error(cv.bkg) if error else mycolors.foreground.info(cv.bkg)
    if isinstance(value, list):
        value = ', '.join(str(v) for v in value) if value else 'N/A'
    elif value is None or value == '':
        value = 'N/A'
    print(f"{color}{(name + ':').ljust(colsize)}{mycolors.reset}\t{value}")


def record(data, error_keys=None, colsize=22):
    if not is_text_output():
        return
    error_keys = set(error_keys or [])
    for k, v in data.items():
        field(k, v, error=k in error_keys, colsize=colsize)


def error(msg):
    if is_text_output():
        print(f"{mycolors.foreground.error(cv.bkg)}{msg}{mycolors.reset}")


def warn(msg):
    if is_text_output():
        print(f"{mycolors.foreground.yellow}{msg}{mycolors.reset}")


def info(msg):
    if is_text_output():
        print(f"{mycolors.foreground.info(cv.bkg)}{msg}{mycolors.reset}")


def table(rows, headers, widths):
    """Render a list of dicts as a fixed-width table."""
    if not is_text_output():
        return
    info_color = mycolors.foreground.info(cv.bkg)
    header_line = info_color + ''.join(h.ljust(w) for h, w in zip(headers, widths)) + mycolors.reset
    total_width = sum(widths)
    print()
    print(header_line)
    print('-' * total_width)
    for row in rows:
        line = ''
        for h, w in zip(headers, widths):
            v = str(row.get(h, ''))
            line += v[:w - 2].ljust(w)
        print(line)
