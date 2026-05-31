#!/usr/bin/env python3
"""Apply calls_patch.csv and thunks_patch.csv to a PE on disk (no IDA)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pe_rva import PeImage  # noqa: E402


def patch_batch(img: PeImage, table: pl.DataFrame, name: str, verbose: bool) -> int:
    counter = 0
    for patch_addr, mem_old, patch in table.rows():
        ea = int(str(patch_addr), 16)
        if img.patch_bytes_va(ea, str(mem_old), str(patch), verbose=verbose):
            counter += 1
    print(f"Patched {counter}/{table.shape[0]} {name}")
    return counter


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", "-i", required=True, type=Path)
    parser.add_argument("--patches-dir", "-p", required=True, type=Path)
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Output path (default: <input>_applied.exe)",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Overwrite input file",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    img = PeImage(args.input)
    patches = args.patches_dir

    for name, fn in [("calls", "calls_patch.csv"), ("thunks", "thunks_patch.csv")]:
        path = patches / fn
        if not path.is_file():
            print(f"Skip missing {path}")
            continue
        patch_batch(img, pl.read_csv(path), name, args.verbose)

    iat_path = patches / "iat_patch.csv"
    if iat_path.is_file():
        patch_batch(img, pl.read_csv(iat_path), "iat entries", args.verbose)

    if args.in_place:
        out = args.input
    elif args.output:
        out = args.output
    else:
        out = args.input.with_name(args.input.stem + "_applied" + args.input.suffix)

    saved = img.save(out)
    print(f"[+] Wrote {saved}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
