#!/usr/bin/env python3
"""Apply calls_patch.csv and thunks_patch.csv to a PE on disk (no IDA)."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dump_tables import load_dump_imports  # noqa: E402
from pe_imports import SCRATCH_SLOT_OVERRIDES  # noqa: E402
from pe_rva import PeImage  # noqa: E402


def patch_batch(img: PeImage, table: pl.DataFrame, name: str, verbose: bool) -> int:
    counter = 0
    for patch_addr, mem_old, patch in table.rows():
        ea = int(str(patch_addr), 16)
        if img.patch_bytes_va(ea, str(mem_old), str(patch), verbose=verbose):
            counter += 1
    print(f"Patched {counter}/{table.shape[0]} {name}")
    return counter


def fix_scratch_iat_slots(
    img: PeImage,
    dumps_dir: Path,
    game_export: Path | None,
    verbose: bool,
) -> int:
    """Rewrite packer scratch IAT slots that still hold stolen in-image copies."""
    imports = load_dump_imports(dumps_dir, game_export)
    sym_map = {
        (row["Module"].lower(), row["Function"]): int(row["Address"], 16)
        for row in imports.to_dicts()
    }
    fixed = 0
    for slot_va, (dll, func) in SCRATCH_SLOT_OVERRIDES.items():
        ptr = sym_map.get((dll.lower(), func))
        if ptr is None:
            continue
        off = img.va_to_offset(slot_va)
        if off is None:
            if verbose:
                print(f"[!] scratch IAT slot not mapped: {slot_va:#x}")
            continue
        old = struct.unpack("<I", img.data[off : off + 4])[0]
        img.data[off : off + 4] = struct.pack("<I", ptr)
        fixed += 1
        if verbose:
            print(f"[+] scratch IAT {slot_va:#x}: {old:#x} -> {ptr:#x} ({dll}!{func})")
    return fixed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", "-i", required=True, type=Path)
    parser.add_argument("--patches-dir", "-p", required=True, type=Path)
    parser.add_argument(
        "--dumps-dir",
        type=Path,
        default=None,
        help="dumps/ with old-iat + dump-imports (default: <patches-dir>/../dumps)",
    )
    parser.add_argument(
        "--game-export",
        type=Path,
        default=None,
        help="game.exe.export.full.csv (default: next to dumps dir)",
    )
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
    dumps_dir = args.dumps_dir or (patches.parent / "dumps")
    game_export = args.game_export or (dumps_dir.parent / "game.exe.export.full.csv")

    for name, fn in [("calls", "calls_patch.csv"), ("thunks", "thunks_patch.csv")]:
        path = patches / fn
        if not path.is_file():
            print(f"Skip missing {path}")
            continue
        patch_batch(img, pl.read_csv(path), name, args.verbose)

    iat_path = patches / "iat_patch.csv"
    if iat_path.is_file():
        patch_batch(img, pl.read_csv(iat_path), "iat entries", args.verbose)

    n = fix_scratch_iat_slots(img, dumps_dir, game_export, args.verbose)
    if n:
        print(f"[*] Fixed {n} scratch IAT slot(s) with real export addresses")

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
