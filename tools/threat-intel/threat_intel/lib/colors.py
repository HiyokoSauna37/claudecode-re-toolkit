"""ANSI color helpers with light/dark background awareness.

Mirrors malwoverview's mycolors so error/info/success colors adapt to terminal.
"""


class mycolors:
    reset = '\033[0m'
    reverse = '\033[07m'
    bold = '\033[01m'

    class foreground:
        orange = '\033[33m'
        blue = '\033[34m'
        purple = '\033[35m'
        lightgreen = '\033[92m'
        lightblue = '\033[94m'
        pink = '\033[95m'
        lightcyan = '\033[96m'
        red = '\033[31m'
        green = '\033[32m'
        cyan = '\033[36m'
        lightgrey = '\033[37m'
        darkgrey = '\033[90m'
        lightred = '\033[91m'
        yellow = '\033[93m'

        @staticmethod
        def error(bkg):
            return mycolors.foreground.lightred if bkg == 1 else mycolors.foreground.red

        @staticmethod
        def info(bkg):
            return mycolors.foreground.lightcyan if bkg == 1 else mycolors.foreground.cyan

        @staticmethod
        def success(bkg):
            return mycolors.foreground.yellow if bkg == 1 else mycolors.foreground.blue


def printr():
    print(mycolors.reset)


def printc(text, color, *args, **kwargs):
    print(f'{color}{text}{mycolors.reset}', *args, **kwargs)
