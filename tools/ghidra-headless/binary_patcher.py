#!/usr/bin/env python3
"""Anti-VM string patcher for malware binaries.

Patches VM-detection artifacts (driver names, vendor strings, MAC prefixes)
so dynamic analysis proceeds without triggering evasion checks.
Runs inside a Docker container -- never on the host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

TOOL_VERSION = "1.0.0"

# Known VM-detection strings for --auto-vm
VM_STRINGS: list[tuple[bytes, bytes]] = [
    (b"vmhgfs.sys",   b"xmhgfs.sys"),
    (b"vmmouse.sys",  b"xmmouse.sys"),
    (b"vmci.sys",     b"xmci.sys"),
    (b"vboxguest.sys", b"xboxguest.sys"),
    (b"prl_tg.sys",   b"xrl_tg.sys"),
    (b"VMWARE",       b"XMWARE"),
    (b"VBOX_",        b"XBOX_"),
    (b"QEMU_",        b"XEMU_"),
    (b"VMware, Inc",  b"XMware, Inc"),
    (b"00:0C:29",     b"90:0C:29"),
    (b"00-0C-29",     b"90-0C-29"),
]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patch_string(data: bytearray, old: str, new: str) -> list[dict]:
    """Replace all occurrences of *old* with *new* (must be equal length)."""
    if len(old) != len(new):
        raise ValueError(f"length mismatch: {old!r} ({len(old)}) vs {new!r} ({len(new)})")
    old_b, new_b = old.encode("ascii"), new.encode("ascii")
    patches: list[dict] = []
    start = 0
    while True:
        idx = data.find(old_b, start)
        if idx == -1:
            break
        data[idx : idx + len(old_b)] = new_b
        patches.append({"offset": f"0x{idx:08x}", "original": old, "patched": new})
        start = idx + len(new_b)
    return patches


def patch_hex(data: bytearray, offset: int, old_hex: str, new_hex: str) -> dict:
    """Overwrite bytes at *offset* after verifying they match *old_hex*."""
    old_bytes = bytes.fromhex(old_hex)
    new_bytes = bytes.fromhex(new_hex)
    if len(old_bytes) != len(new_bytes):
        raise ValueError(f"hex length mismatch: {old_hex} vs {new_hex}")
    if offset + len(old_bytes) > len(data):
        raise ValueError(f"offset 0x{offset:x} + {len(old_bytes)} bytes exceeds file size")
    actual = bytes(data[offset : offset + len(old_bytes)])
    if actual != old_bytes:
        raise ValueError(
            f"byte mismatch at 0x{offset:x}: expected {old_hex}, found {actual.hex()}"
        )
    data[offset : offset + len(new_bytes)] = new_bytes
    return {"offset": f"0x{offset:08x}", "original": old_hex, "patched": new_hex}


def patch_auto_vm(data: bytearray) -> list[dict]:
    """Scan for known VM-detection strings and neutralise them."""
    patches: list[dict] = []
    for old_b, new_b in VM_STRINGS:
        start = 0
        while True:
            idx = data.find(old_b, start)
            if idx == -1:
                break
            # Guard: skip "VMWARE" inside Go runtime metadata (preceded by "go.")
            if old_b == b"VMWARE" and idx >= 3 and data[idx - 3 : idx] == b"go.":
                start = idx + len(old_b)
                continue
            data[idx : idx + len(old_b)] = new_b
            patches.append({
                "offset": f"0x{idx:08x}",
                "original": old_b.decode("ascii"),
                "patched": new_b.decode("ascii"),
            })
            start = idx + len(new_b)
    return patches


def _output_path(src: Path) -> Path:
    return src.parent / f"{src.stem}_patched{src.suffix}"


def _emit(orig_hash: str, new_hash: str, patches: list[dict], out: Path) -> str:
    return json.dumps({"original_sha256": orig_hash, "patched_sha256": new_hash,
                       "patches_applied": len(patches), "patches": patches,
                       "output_file": str(out)}, indent=2, ensure_ascii=False)


EPILOG = """\
examples:
  python binary_patcher.py sample.exe --patch-string "vmhgfs.sys:xmhgfs.sys"
  python binary_patcher.py sample.exe --patch 0x02034e55:766d:786d
  python binary_patcher.py sample.exe --auto-vm
  python binary_patcher.py sample.exe --auto-vm --patch-string "VBOX:XBOX"
"""


def _parse_patch_string(spec: str) -> tuple[str, str]:
    parts = spec.split(":")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(f"expected 'old:new', got {spec!r}")
    if len(parts[0]) != len(parts[1]):
        raise argparse.ArgumentTypeError(
            f"strings must be equal length: {parts[0]!r} vs {parts[1]!r}")
    return parts[0], parts[1]


def _parse_hex_patch(spec: str) -> tuple[int, str, str]:
    parts = spec.split(":")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(f"expected 'offset:old_hex:new_hex', got {spec!r}")
    try:
        offset = int(parts[0], 16)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid hex offset: {parts[0]!r}")
    return offset, parts[1], parts[2]


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="binary_patcher",
        description="Patch anti-VM detection strings in malware binaries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    parser.add_argument("binary", help="path to the binary to patch")
    parser.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")
    parser.add_argument("--patch-string", action="append", default=[], metavar="OLD:NEW",
                        help="replace ASCII string OLD with NEW (equal length); repeatable")
    parser.add_argument("--patch", action="append", default=[], metavar="OFF:OLD:NEW",
                        help="patch bytes at hex offset (offset:old_hex:new_hex); repeatable")
    parser.add_argument("--auto-vm", action="store_true",
                        help="auto-patch known VM-detection strings")
    args = parser.parse_args()
    if not args.patch_string and not args.patch and not args.auto_vm:
        parser.error("specify at least one of --patch-string, --patch, or --auto-vm")

    src = Path(args.binary)
    if not src.is_file():
        print(f"error: file not found: {src}", file=sys.stderr)
        return 1

    data = bytearray(src.read_bytes())
    original_hash = _sha256(bytes(data))
    all_patches: list[dict] = []

    for spec in args.patch_string:
        try:
            old, new = _parse_patch_string(spec)
        except argparse.ArgumentTypeError as e:
            print(f"error: --patch-string: {e}", file=sys.stderr)
            return 1
        all_patches.extend(patch_string(data, old, new))
    for spec in args.patch:
        try:
            offset, old_hex, new_hex = _parse_hex_patch(spec)
        except argparse.ArgumentTypeError as e:
            print(f"error: --patch: {e}", file=sys.stderr)
            return 1
        try:
            all_patches.append(patch_hex(data, offset, old_hex, new_hex))
        except ValueError as e:
            print(f"error: --patch: {e}", file=sys.stderr)
            return 1
    if args.auto_vm:
        all_patches.extend(patch_auto_vm(data))

    if not all_patches:
        print("no patches applied (target strings not found)", file=sys.stderr)
        return 2

    out_path = _output_path(src)
    out_path.write_bytes(bytes(data))
    print(_emit(original_hash, _sha256(bytes(data)), all_patches, out_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
