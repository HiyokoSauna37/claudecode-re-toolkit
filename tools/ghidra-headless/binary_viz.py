#!/usr/bin/env python3
"""Binary visualization: entropy profile, bigram heatmap, byte histogram.

Generates PNG visualizations for malware triage and packer detection:
  - Entropy sliding window profile (packed sections → high entropy)
  - Byte bigram frequency matrix (packed code → uniform distribution)
  - Byte value histogram

Entropy verdict:
  PACKED_OR_ENCRYPTED    avg > 7.2 or >60% windows above 7.0
  COMPRESSED_OR_MIXED    avg 6.0-7.2
  LIKELY_CLEAN           avg < 6.0

Usage (inside container):
    python binary_viz.py <binary_path> --output-dir /tmp/output
    python binary_viz.py <binary_path> --no-plot   # JSON only
"""

import argparse
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "1.0.0"
WINDOW = 256
STEP = 128

try:
    import numpy as np
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_PLOT = True
except ImportError:
    HAS_PLOT = False


def entropy(chunk: bytes) -> float:
    freq = [0] * 256
    for b in chunk:
        freq[b] += 1
    h = 0.0
    n = len(chunk)
    for f in freq:
        if f:
            p = f / n
            h -= p * math.log2(p)
    return h


def entropy_profile(data: bytes) -> list[float]:
    return [
        entropy(data[i:i + WINDOW])
        for i in range(0, max(1, len(data) - WINDOW), STEP)
    ]


def byte_histogram(data: bytes) -> list[int]:
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    return freq


def classify(profile: list[float]) -> str:
    if not profile:
        return "UNKNOWN"
    avg = sum(profile) / len(profile)
    high_frac = sum(1 for e in profile if e > 7.0) / len(profile)
    if avg > 7.2 or high_frac > 0.6:
        return "PACKED_OR_ENCRYPTED"
    if avg > 6.0:
        return "COMPRESSED_OR_MIXED"
    return "LIKELY_CLEAN"


def build_plots(binary: Path, data: bytes, profile: list[float], hist: list[int], output_dir: Path) -> Path:
    import numpy as np

    bname = binary.stem
    fig, axes = plt.subplots(3, 1, figsize=(14, 11))
    fig.suptitle(f"Binary Analysis: {binary.name}", fontsize=13, fontweight="bold")

    # --- Entropy profile ---
    xs = [i * STEP for i in range(len(profile))]
    axes[0].fill_between(xs, profile, alpha=0.6, color="#e74c3c")
    axes[0].plot(xs, profile, color="#c0392b", linewidth=0.7)
    axes[0].axhline(y=7.0, color="#f39c12", linestyle="--", linewidth=0.8, label="High entropy (7.0)")
    axes[0].axhline(y=6.0, color="#2ecc71", linestyle="--", linewidth=0.8, label="Moderate entropy (6.0)")
    axes[0].set_ylim(0, 8.2)
    axes[0].set_ylabel("Shannon Entropy (bits)")
    axes[0].set_title(f"Entropy Profile — {classify(profile)}")
    axes[0].legend(fontsize=8)
    axes[0].grid(alpha=0.25)

    # --- Byte histogram ---
    axes[1].bar(range(256), hist, color="#3498db", width=1.0, edgecolor="none")
    axes[1].set_xlim(0, 255)
    axes[1].set_xlabel("Byte Value (0x00–0xFF)")
    axes[1].set_ylabel("Count")
    axes[1].set_title("Byte Frequency Distribution")
    axes[1].grid(axis="y", alpha=0.25)

    # --- Bigram heatmap (log scale) ---
    mat = np.zeros((256, 256), dtype=np.float32)
    for i in range(len(data) - 1):
        mat[data[i], data[i + 1]] += 1
    mat = np.log1p(mat)
    im = axes[2].imshow(mat, cmap="inferno", aspect="auto", interpolation="nearest")
    axes[2].set_xlabel("Next Byte")
    axes[2].set_ylabel("Current Byte")
    axes[2].set_title("Byte Bigram Frequency (log scale) — uniform = packed")
    plt.colorbar(im, ax=axes[2], shrink=0.8)

    plt.tight_layout()
    png_path = output_dir / f"{bname}_viz.png"
    plt.savefig(str(png_path), dpi=120, bbox_inches="tight")
    plt.close()
    return png_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Binary visualization")
    parser.add_argument("binary", help="Binary file to visualize")
    parser.add_argument("--output-dir", default="/tmp/output")
    parser.add_argument("--no-plot", action="store_true", help="JSON summary only (no PNG)")
    args = parser.parse_args()

    binary = Path(args.binary)
    if not binary.is_file():
        print(f"Error: Not found: {binary}", file=sys.stderr)
        sys.exit(1)

    data = binary.read_bytes()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    bname = binary.stem

    profile = entropy_profile(data)
    hist = byte_histogram(data)
    verdict = classify(profile)

    summary = {
        "tool": "binary_viz",
        "version": TOOL_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file": binary.name,
        "file_size": len(data),
        "entropy_verdict": verdict,
        "entropy_stats": {
            "min": round(min(profile), 4) if profile else 0,
            "max": round(max(profile), 4) if profile else 0,
            "avg": round(sum(profile) / len(profile), 4) if profile else 0,
            "windows": len(profile),
            "high_entropy_pct": round(
                sum(1 for e in profile if e > 7.0) / len(profile) * 100, 1
            ) if profile else 0,
        },
        "byte_histogram": hist,
        "entropy_profile": [round(e, 4) for e in profile],
    }

    json_path = output_dir / f"{bname}_viz.json"
    with open(json_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"[*] JSON:    {json_path}")
    print(f"[*] Verdict: {verdict}")
    s = summary["entropy_stats"]
    print(f"    avg={s['avg']:.2f}  max={s['max']:.2f}  high_pct={s['high_entropy_pct']}%")

    if not args.no_plot:
        if HAS_PLOT:
            png = build_plots(binary, data, profile, hist, output_dir)
            print(f"[*] PNG:     {png}")
        else:
            print("[!] matplotlib/numpy unavailable — JSON only", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
