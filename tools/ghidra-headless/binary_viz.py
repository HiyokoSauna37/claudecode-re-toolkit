#!/usr/bin/env python3
"""Binary visualization — entropy profile, bigram heatmap, byte histogram.

Generates PNG visualizations to quickly assess whether a binary is packed:
  • Entropy profile  : sliding window Shannon entropy (packed → stays near 8.0)
  • Bigram heatmap   : byte pair frequencies (packed → uniform/hot distribution)
  • Byte histogram   : byte value distribution (packed → flat; text → low bytes)

Entropy verdict:
  PACKED_OR_ENCRYPTED  avg > 7.2 or > 60 % of windows above 7.0
  COMPRESSED_OR_MIXED  avg 6.0 – 7.2
  LIKELY_CLEAN         avg < 6.0

Usage:
    python binary_viz.py malware.exe --output-dir /tmp/output
    python binary_viz.py sample.dll --no-plot   # JSON summary only
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "1.1.0"
WINDOW  = 256
STEP    = 128
MAX_MB  = 200  # read at most this many MB

try:
    import numpy as np
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_PLOT = True
except ImportError:
    HAS_PLOT = False


# ── core math ──────────────────────────────────────────────────────────────

def entropy(chunk: bytes) -> float:
    n = len(chunk)
    if n == 0:
        return 0.0
    freq = [0] * 256
    for b in chunk:
        freq[b] += 1
    h = 0.0
    for f in freq:
        if f:
            p = f / n
            h -= p * math.log2(p)
    return h


def entropy_profile(data: bytes) -> list[float]:
    if len(data) < WINDOW:
        return [entropy(data)]
    return [
        entropy(data[i : i + WINDOW])
        for i in range(0, len(data) - WINDOW + 1, STEP)
    ]


def byte_histogram(data: bytes) -> list[int]:
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    return freq


def verdict(profile: list[float]) -> str:
    if not profile:
        return "UNKNOWN"
    avg = sum(profile) / len(profile)
    hi  = sum(1 for e in profile if e > 7.0) / len(profile)
    if avg > 7.2 or hi > 0.6:
        return "PACKED_OR_ENCRYPTED"
    if avg > 6.0:
        return "COMPRESSED_OR_MIXED"
    return "LIKELY_CLEAN"


# ── plotting ───────────────────────────────────────────────────────────────

def build_plots(binary: Path, data: bytes, profile: list[float],
                hist: list[int], output_dir: Path) -> Path:
    label = verdict(profile)
    fig, axes = plt.subplots(3, 1, figsize=(14, 11))
    fig.suptitle(f"Binary Analysis: {binary.name}", fontsize=13, fontweight="bold")

    # Entropy profile
    xs = [i * STEP for i in range(len(profile))]
    axes[0].fill_between(xs, profile, alpha=0.5, color="#e74c3c")
    axes[0].plot(xs, profile, color="#c0392b", linewidth=0.8)
    axes[0].axhline(7.0, color="#f39c12", ls="--", lw=0.8, label="7.0 – high entropy threshold")
    axes[0].axhline(6.0, color="#2ecc71", ls="--", lw=0.8, label="6.0 – moderate threshold")
    axes[0].set_ylim(0, 8.2)
    axes[0].set_ylabel("Shannon Entropy (bits/byte)")
    axes[0].set_title(f"Entropy Profile — verdict: {label}")
    axes[0].legend(fontsize=8)
    axes[0].grid(alpha=0.25)

    # Byte histogram
    axes[1].bar(range(256), hist, color="#3498db", width=1.0, edgecolor="none")
    axes[1].set_xlim(0, 255)
    axes[1].set_xlabel("Byte value (0x00 – 0xFF)")
    axes[1].set_ylabel("Count")
    axes[1].set_title("Byte Frequency  — flat distribution = packed/encrypted")
    axes[1].grid(axis="y", alpha=0.25)

    # Bigram heatmap
    mat = np.zeros((256, 256), dtype=np.float32)
    for i in range(len(data) - 1):
        mat[data[i], data[i + 1]] += 1
    mat = np.log1p(mat)
    im = axes[2].imshow(mat, cmap="inferno", aspect="auto", interpolation="nearest")
    axes[2].set_xlabel("Next byte")
    axes[2].set_ylabel("Current byte")
    axes[2].set_title("Byte Bigram Frequency (log scale)  — uniform = packed")
    plt.colorbar(im, ax=axes[2], shrink=0.8)

    plt.tight_layout()
    out = output_dir / f"{binary.stem}_viz.png"
    try:
        plt.savefig(str(out), dpi=120, bbox_inches="tight")
    except Exception as e:
        print(f"  ⚠ PNG write failed: {e}", file=sys.stderr)
        out = None
    finally:
        plt.close(fig)
    return out


# ── main ───────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Binary entropy/bigram visualization — quick packer triage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Entropy thresholds:
  > 7.2 bits/byte (or > 60 % of windows)  →  PACKED_OR_ENCRYPTED
  6.0 – 7.2 bits/byte                     →  COMPRESSED_OR_MIXED
  < 6.0 bits/byte                          →  LIKELY_CLEAN

Examples:
  python binary_viz.py malware.exe --output-dir /tmp/output
  python binary_viz.py loader.dll                          # use default /tmp/output
  python binary_viz.py huge_sample.exe --no-plot           # JSON only, faster

Output files:
  <stem>_viz.json   — entropy stats + full profile array + byte histogram
  <stem>_viz.png    — 3-panel plot (entropy / histogram / bigram)

Install matplotlib: pip install matplotlib numpy
""",
    )
    parser.add_argument("binary", help="Binary file to visualize (PE, ELF, raw shellcode)")
    parser.add_argument("--output-dir", default="/tmp/output", metavar="DIR",
                        help="Output directory (default: /tmp/output)")
    parser.add_argument("--no-plot", action="store_true",
                        help="Skip PNG generation — write JSON summary only")
    parser.add_argument("--max-mb", type=int, default=MAX_MB, metavar="N",
                        help=f"Max MB to read from file (default: {MAX_MB})")
    args = parser.parse_args()

    binary = Path(args.binary)
    if not binary.exists():
        print(f"✗ File not found: {binary}", file=sys.stderr)
        sys.exit(1)
    if not binary.is_file():
        print(f"✗ Not a file: {binary}", file=sys.stderr)
        sys.exit(1)

    file_size = binary.stat().st_size
    read_limit = args.max_mb * 1024 * 1024
    truncated = file_size > read_limit

    print(f"→ Binary Viz: {binary.name}  ({file_size / 1024:.1f} KB)")
    if truncated:
        print(f"  ⚠ File > {args.max_mb} MB — analyzing first {args.max_mb} MB only")

    try:
        with binary.open("rb") as fh:
            data = fh.read(read_limit)
    except OSError as e:
        print(f"✗ Cannot read file: {e}", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    profile = entropy_profile(data)
    hist    = byte_histogram(data)
    label   = verdict(profile)
    avg_e   = sum(profile) / len(profile) if profile else 0.0
    max_e   = max(profile) if profile else 0.0
    hi_pct  = (sum(1 for e in profile if e > 7.0) / len(profile) * 100) if profile else 0.0

    summary = {
        "tool":      "binary_viz",
        "version":   TOOL_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file":      binary.name,
        "file_size": file_size,
        "analyzed_bytes": len(data),
        "truncated": truncated,
        "entropy_verdict": label,
        "entropy_stats": {
            "avg":      round(avg_e, 4),
            "max":      round(max_e, 4),
            "hi_pct":   round(hi_pct, 1),
            "windows":  len(profile),
            "window_sz": WINDOW,
            "step":     STEP,
        },
        "byte_histogram":  hist,
        "entropy_profile": [round(e, 4) for e in profile],
    }

    json_path = output_dir / f"{binary.stem}_viz.json"
    try:
        json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    except OSError as e:
        print(f"✗ Cannot write JSON: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"  Verdict  : {label}")
    print(f"  avg={avg_e:.2f}  max={max_e:.2f}  hi>{7.0}={hi_pct:.0f}%  windows={len(profile)}")
    print(f"  JSON     : {json_path}")

    if not args.no_plot:
        if HAS_PLOT:
            png = build_plots(binary, data, profile, hist, output_dir)
            if png:
                print(f"  PNG      : {png}")
        else:
            print("  ⚠ matplotlib/numpy not installed — JSON only", file=sys.stderr)
            print("    Install: pip install matplotlib numpy", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
