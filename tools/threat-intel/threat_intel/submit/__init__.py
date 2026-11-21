"""IOC / sample submission to public threat-intel platforms.

Flow (human-gated, see .claude/skills/threat-intel/references/ioc-submission.md):

    manifest (*.iocs.yaml)  ->  submit plan   (validate + guards + dedup pre-check, NO writes)
                            ->  submit approve <plan_id>   (HUMAN ONLY; blocked for Claude by hook)
                            ->  submit run <plan_id>       (executes exactly the approved payloads)

Everything sent is public and cannot be retracted, so the plan is the
contract: `run` sends only the payloads stored in the approved plan file.
Sample uploads never decrypt on the host; they run in a throwaway container.
"""
