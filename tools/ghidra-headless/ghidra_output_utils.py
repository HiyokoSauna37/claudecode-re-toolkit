"""Shared utilities for Ghidra post-analysis Python scripts.

Used by: ioc_extractor.py, malware_classifier.py
"""

from pathlib import Path
from typing import Dict


# Standard Ghidra output file suffixes
GHIDRA_OUTPUT_SUFFIXES = {
    "strings": "_strings.txt",
    "imports": "_imports.txt",
    "exports": "_exports.txt",
    "decompiled": "_decompiled.c",
    "decompiled_functions": "_decompiled_functions.c",
    "info": "_info.txt",
    "functions": "_functions.txt",
    "xrefs": "_xrefs.txt",
    "decrypted_strings": "_decrypted_strings.txt",
}


def find_ghidra_outputs(binary_name: str, output_dir: Path) -> Dict[str, Path]:
    """Find Ghidra output files and dotnet-decompiler output for a given binary name.

    Args:
        binary_name: Base name of the analyzed binary (without extension).
        output_dir: Directory containing Ghidra output files.

    Returns:
        Dict mapping output type (e.g., "strings", "imports") to file Path.
    """
    files = {}

    for key, suffix in GHIDRA_OUTPUT_SUFFIXES.items():
        path = output_dir / f"{binary_name}{suffix}"
        if path.exists():
            files[key] = path

    # Also scan dotnet-decompiler output (.cs files)
    dotnet_base = output_dir.parent.parent / "dotnet-decompiler" / "output"
    for name_variant in [binary_name, Path(binary_name).stem]:
        dotnet_dir = dotnet_base / name_variant
        if dotnet_dir.is_dir():
            cs_files = list(dotnet_dir.rglob("*.cs"))
            for i, cs_path in enumerate(cs_files):
                files[f"dotnet_cs_{i}"] = cs_path
            break

    return files
