#!/usr/bin/env python3
"""intel: Unified threat intelligence dispatcher.

Thin wrapper that dispatches to c2hunt, threatfeed, iocminer living in the
same directory. Preserves each subtool's original CLI behavior.

Usage:
    intel c2 queries --engine shodan
    intel c2 identify http://1.2.3.4:8080/
    intel c2 concepts
    intel tf sweep-tags --tags "CobaltStrike,Sliver"
    intel tf sweep-asn AS214943
    intel tf hunt
    intel ioc cluster iocs.json
    intel ioc patterns iocs.json
    intel ioc mine iocs.json
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

DISPATCH = {
    "c2": "c2hunt.py",
    "tf": "threatfeed.py",
    "ioc": "iocminer.py",
}


def _load_module(filename):
    path = os.path.join(SCRIPT_DIR, filename)
    if not os.path.isfile(path):
        raise ImportError(f"module not found: {filename}")
    mod_name = filename.replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    if len(sys.argv) >= 2 and sys.argv[1] in DISPATCH:
        filename = DISPATCH[sys.argv[1]]
        mod = _load_module(filename)
        sys.argv = [filename] + sys.argv[2:]
        try:
            mod.main()
        except SystemExit as e:
            sys.exit(e.code if e.code is not None else 0)
        return

    parser = argparse.ArgumentParser(
        prog="intel",
        description="Unified threat intelligence dispatcher (c2hunt / threatfeed / iocminer)",
    )
    parser.add_argument("tool", nargs="?", choices=list(DISPATCH.keys()),
                        help="c2 -> c2hunt, tf -> threatfeed, ioc -> iocminer")
    parser.parse_args()
    parser.print_help()
    print("\nExamples:")
    print("  intel c2 queries --engine shodan")
    print("  intel tf hunt")
    print("  intel ioc cluster iocs.json")
    sys.exit(1)


if __name__ == "__main__":
    main()
