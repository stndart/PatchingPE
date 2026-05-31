#!/usr/bin/env python3
"""Rebuild PE imports with LIEF + scratch FirstThunk (notebook-equivalent)."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import lief
import pefile

_REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO / "scripts" / "standalone"))

from dump_tables import load_iat_segments  # noqa: E402
from pe_imports import resolve_iat_va, pe_import_slot_map  # noqa: E402


def create_32bit_ordinal_import(ordinal: int) -> lief.PE.ImportEntry:
    ORDINAL_MASK_32 = 0x80000000
    data_value = ORDINAL_MASK_32 | ordinal
    return lief.PE.ImportEntry(data_value, lief.PE.PE_TYPE.PE32)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dump", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--dumps-dir", required=True, type=Path)
    ap.add_argument("--game-export", type=Path, default=None)
    args = ap.parse_args()

    segments = load_iat_segments(args.dumps_dir, args.game_export)
    print(f"[*] Import segments: {len(segments)}")

    shutil.copy(args.dump, args.out)
    pe_lief = lief.PE.parse(str(args.out))
    pe_lief.remove_all_imports()

    for seg in segments:
        dll = seg["Module"][0]
        mod = pe_lief.add_import(dll)
        for _calladdr, _addr, ordinal, func, _m in seg.rows():
            if func.startswith("Ordinal#"):
                entry = create_32bit_ordinal_import(int(ordinal))
            else:
                entry = lief.PE.ImportEntry(func)
            mod.add_entry(entry)

    config = lief.PE.Builder.config_t()
    config.imports = True
    builder = lief.PE.Builder(pe_lief, config)
    builder.build()
    builder.write(str(args.out))

    pe = pefile.PE(str(args.out))
    pe.full_load()
    assert len(pe.DIRECTORY_ENTRY_IMPORT) == len(segments), (
        f"import dirs {len(pe.DIRECTORY_ENTRY_IMPORT)} != segments {len(segments)}"
    )
    for i, seg in enumerate(segments):
        first_thunk = int(seg["Calladdr"][0], 16)
        pe.DIRECTORY_ENTRY_IMPORT[i].struct.FirstThunk = (
            first_thunk - pe.OPTIONAL_HEADER.ImageBase
        )
    temp = args.out.with_suffix(".tmp.exe")
    pe.write(filename=str(temp))
    pe.close()
    if args.out.is_file():
        args.out.unlink()
    shutil.move(str(temp), str(args.out))

    slot_map = pe_import_slot_map(args.out)
    ws = resolve_iat_va(slot_map, "user32.dll", "wsprintfA")
    nigs = resolve_iat_va(slot_map, "neomon.dll", "NIGS_1")
    print(f"[+] Wrote {args.out} ({len(segments)} import descriptors, scratch FirstThunk)")
    print(f"    user32.wsprintfA in LIEF list: {'yes' if ws else 'no (expected via scratch slot)'}")
    print(f"    neomon.NIGS_1: {'yes' if nigs else 'no'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
