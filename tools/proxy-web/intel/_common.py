"""Shared helpers for proxy-web/intel/ tools.

Minimal subset extracted from bb-toolkit/bb_common.py when the threat-intel
family was split out of bb-toolkit (bug-bounty) into proxy-web/intel
(threat intel). Only the two helpers actually used by the intel tools are
carried over: add_output_args() and emit_json().
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable, Optional


def add_output_args(parser: Any, include: tuple[str, ...] = ("json", "output", "quiet", "summary")) -> None:
    """Add shared output arguments to parser or subparser.

    Supported include values:
        "json"    → -j/--json   (store_true; kept for compat with emit_json tools)
        "output"  → -o/--output (save JSON envelope to file)
        "quiet"   → -q/--quiet  (drop tool/command/timestamp envelope; emit data fields only)
        "summary" → --summary   (print one-line human-readable summary to stderr too)
        "verbose" → -v/--verbose
    """
    if "json" in include:
        parser.add_argument("-j", "--json", action="store_true",
                            help="JSON output to stdout (kept for compat; emit_json tools always output JSON)")
    if "output" in include:
        parser.add_argument("-o", "--output", help="Save result to file")
    if "quiet" in include:
        parser.add_argument("-q", "--quiet", action="store_true",
                            help="Drop envelope (tool/command/timestamp) — emit only the data fields")
    if "summary" in include:
        parser.add_argument("--summary", action="store_true",
                            help="Also print a short human-readable summary to stderr")
    if "verbose" in include:
        parser.add_argument("-v", "--verbose", action="store_true",
                            help="Enable verbose/debug output")


def emit_json(data: dict, args: Optional[Any] = None,
              tool: Optional[str] = None,
              command: Optional[str] = None,
              default: Optional[Callable] = None,
              summary: Optional[str] = None) -> dict:
    """JSON-always output with auto tool/command/timestamp envelope.

    Wraps `data` with tool name, command, and UTC timestamp. Writes to stdout;
    also saves to file if args.output is set.
    """
    from datetime import datetime, timezone
    envelope: dict[str, Any] = {}
    quiet = bool(args and getattr(args, "quiet", False))
    if not quiet:
        if tool:
            envelope["tool"] = tool
        if command:
            envelope["command"] = command
        if tool or command:
            envelope["timestamp"] = datetime.now(timezone.utc).isoformat()
    envelope.update(data)

    json_str = json.dumps(envelope, indent=2, ensure_ascii=False, default=default)
    print(json_str)
    if args and getattr(args, "output", None):
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(json_str)
        print(f"Results saved to {args.output}", file=sys.stderr)
    if summary and args and getattr(args, "summary", False):
        print(f"[intel-summary] {summary}", file=sys.stderr)
    return envelope
