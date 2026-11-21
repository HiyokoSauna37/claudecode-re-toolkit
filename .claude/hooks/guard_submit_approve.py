#!/usr/bin/env python3
"""PreToolUse guard: Claude must never approve a public IOC/sample submission.

`intel-cli.py submit approve <plan_id>` is the human gate in front of
irreversible public submissions (ThreatFox / URLhaus / AbuseIPDB /
MalwareBazaar / VirusTotal / Triage). Permission prompts are bypassed in
this repo's usual mode, so the gate is enforced here instead:

  - Bash / PowerShell commands that run `intel-cli ... submit approve`  -> blocked
  - any tool touching tools/threat-intel/data/submit/approvals/          -> blocked

The human approves with the `!` prefix (runs outside Claude's tool calls):
  ! python tools/threat-intel/intel-cli.py submit approve <plan_id>
Exit code 2 = block; stderr is shown to Claude.
"""

import json
import re
import sys

APPROVE_RE = re.compile(r'intel-cli[^\n]*\bsubmit\s+approve\b|threat_intel\.submit\.cli[^\n]*approve', re.I)
APPROVALS_RE = re.compile(r'submit[\\/]+approvals', re.I)

MSG = ("BLOCKED by guard_submit_approve: approving a public IOC/sample submission is a human-only step. "
       "Show the plan to the user and ask them to run:  "
       "! python tools/threat-intel/intel-cli.py submit approve <plan_id>")


def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        return 0
    tool = event.get('tool_name', '')
    ti = event.get('tool_input') or {}
    if tool in ('Bash', 'PowerShell'):
        cmd = ti.get('command') or ''
        if APPROVE_RE.search(cmd) or APPROVALS_RE.search(cmd):
            print(MSG, file=sys.stderr)
            return 2
    else:  # file tools: judge by target path only (docs may legitimately mention the dir)
        target = str(ti.get('file_path') or ti.get('notebook_path') or '')
        if APPROVALS_RE.search(target):
            print(MSG, file=sys.stderr)
            return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
