#!/usr/bin/env python3
"""Extract old-IAT and broken-byte-calls from a memory dump (no IDA).

Ports scripts/extract-old-iat.py and scripts/extract-byte-calls.py.
Scans PE sections 0-1 only (not dead sections wlovhtaq / oemvvlbu).
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pe_rva import PeImage, SectionInfo  # noqa: E402

# --- bounds (same as extract-byte-calls.py) ---


def check_in_bounds_game(addr: int) -> bool:
    if addr < 0x6D40000:
        return False  # in-image game VA (not a foreign stub target)
    if 0x6D40000 <= addr <= 0x6D41000:
        return True  # xinput
    if 0x10000000 <= addr < 0x5DD00000:
        return True  # modules + packer stubs (e.g. NeoMon 0x1080xxxx)
    if 0x5DD00000 <= addr:
        return True  # high DLL range
    return False


def check_in_bounds_neomon(addr: int, ibase: int) -> bool:
    if 0x02000000 <= addr <= 0x03000000:
        return True
    if ibase + 0x16000 <= addr <= ibase + 0x16230:
        return True
    if ibase <= addr <= ibase + 0x500000:
        return False
    if 0x60000000 <= addr <= 0x69A00000:
        return True
    if 0x70000000 <= addr <= 0x78000000:
        return True
    return False


PATTERNS_EXE = [
    (b"\x90\xe8", "call", 6),
    (b"\xe8", "call2", 6),  # e8 ?? ?? ?? ?? 90 — checked at match+5
    (b"\x90\xe9", "jmp", 6),
    (b"\xe9", "jmp2", 6),
    (b"\xe9", "jmp-near", 5),
]

PATTERNS_DLL_EXTRA = [
    (b"\xe8", "call-near", 5),
    (b"\xff\x25", "jmp-far", 6),
    (b"\xff\x15", "call-far", 6),
]

IAT_EXE = (0x1588000, 0x1588E6C)
IAT_DLL_OFF = (0x16000, 0x16230)


def find_pattern_in_buffer(buf: bytes, pattern: list[int | None], start: int = 0) -> int:
    plen = len(pattern)
    end = len(buf) - plen
    i = start
    while i <= end:
        match = True
        for j, p in enumerate(pattern):
            if p is not None and buf[i + j] != p:
                match = False
                break
        if match:
            # call2 / jmp2: trailing 90
            if pattern[0] == 0xE8 and plen == 6 and buf[i + 5] != 0x90:
                i += 1
                continue
            if pattern[0] == 0xE9 and plen == 6 and buf[i + 5] != 0x90:
                i += 1
                continue
            return i
        i += 1
    return -1


def call_target_from_match(
    img: PeImage, ea: int, inst: str, pattern_prefix: bytes
) -> int:
    if inst in ("jmp-far", "call-far"):
        disp_u32 = img.read_dword_va(ea + 2)
        if disp_u32 is None:
            raise RuntimeError(f"Cannot read disp at {ea:#x}")
        return ctypes.c_int32(disp_u32).value

    if pattern_prefix[0] == 0x90:
        call_ea = ea + 1
    else:
        call_ea = ea

    opcode = img.read_byte_va(call_ea)
    if opcode not in (0xE8, 0xE9):
        raise RuntimeError(f"No E8/E9 at {call_ea:#x}")

    disp_u32 = img.read_dword_va(call_ea + 1)
    if disp_u32 is None:
        raise RuntimeError(f"Cannot read rel32 at {call_ea:#x}")
    disp_signed = ctypes.c_int32(disp_u32).value
    next_insn = call_ea + 5
    return next_insn + disp_signed


def export_old_iat(img: PeImage, start: int, end: int, out_path: Path) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Address", "Destination"])
        ea = start
        while ea < end:
            val = img.read_dword_va(ea)
            if val is not None:
                w.writerow([f"0x{ea:08X}", f"{val:08X}"])
                count += 1
            ea += 4
    return count


def scan_byte_calls(
    img: PeImage,
    segments: list[SectionInfo],
    patterns: list[tuple[bytes, str, int]],
    check_in_bounds,
    out_path: Path,
    names: dict[int, str] | None = None,
) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            ["subroutine", "Instruction", "Call address", "Destination", "Resolved name"]
        )
        for sec in segments:
            raw = bytes(img.section_raw_slice(sec))
            base_va = img.imagebase + sec.virtual_address
            for prefix, inst, plen in patterns:
                # Build simple pattern for finder
                if inst == "call":
                    pat = [0x90, 0xE8, None, None, None, None]
                elif inst == "call2":
                    pat = [0xE8, None, None, None, None, 0x90]
                elif inst == "jmp":
                    pat = [0x90, 0xE9, None, None, None, None]
                elif inst == "jmp2":
                    pat = [0xE9, None, None, None, None, 0x90]
                elif inst == "jmp-near":
                    pat = [0xE9, None, None, None, None]
                elif inst == "call-near":
                    pat = [0xE8, None, None, None, None]
                elif inst == "jmp-far":
                    pat = [0xFF, 0x25, None, None, None, None]
                elif inst == "call-far":
                    pat = [0xFF, 0x15, None, None, None, None]
                else:
                    continue

                pos = 0
                seg_count = 0
                while True:
                    idx = find_pattern_in_buffer(raw, pat, pos)
                    if idx < 0:
                        break
                    ea = base_va + idx
                    try:
                        target = call_target_from_match(img, ea, inst, prefix)
                    except RuntimeError:
                        pos = idx + 1
                        continue
                    if check_in_bounds(target):
                        name = (names or {}).get(target, "")
                        w.writerow(["-", inst, hex(ea), hex(target), name])
                        seg_count += 1
                        total += 1
                    pos = idx + 1
                print(f"  [{sec.name}] {inst}: {seg_count}")
    return total


def load_import_names(dump_imports: Path | None) -> dict[int, str]:
    if not dump_imports or not dump_imports.is_file():
        return {}
    names: dict[int, str] = {}
    with open(dump_imports, newline="", encoding="utf-8", errors="replace") as f:
        r = csv.DictReader(f)
        addr_col = "Address" if "Address" in (r.fieldnames or []) else None
        name_col = "Name" if "Name" in (r.fieldnames or []) else None
        if not addr_col:
            return names
        for row in r:
            try:
                a = int(row[addr_col], 16)
            except (KeyError, ValueError):
                continue
            names[a] = row.get(name_col or "", "") if name_col else ""
    return names


def segment_indices_exe() -> list[int]:
    return [0, 1]


def segment_indices_dll(img: PeImage) -> list[int]:
    indices = [0, 1, 2]
    for s in img.sections:
        if s.index >= 3 and "fake" in s.name.lower():
            indices.append(s.index)
    return indices


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", "-i", required=True, type=Path)
    parser.add_argument("--out-dir", "-o", required=True, type=Path)
    parser.add_argument(
        "--kind",
        choices=("exe", "dll"),
        default=None,
        help="exe or dll (default: from file extension)",
    )
    parser.add_argument(
        "--dump-imports",
        type=Path,
        default=None,
        help="Optional dump-imports.csv for Resolved name column",
    )
    args = parser.parse_args()

    kind = args.kind
    if kind is None:
        kind = "dll" if args.input.suffix.lower() == ".dll" else "exe"

    img = PeImage(args.input)
    ibase = img.imagebase
    names = load_import_names(args.dump_imports)

    out_dir = args.out_dir
    iat_path = out_dir / "old-iat.csv"
    calls_path = out_dir / "broken-byte-calls.csv"

    if kind == "exe":
        iat_start, iat_end = IAT_EXE
        check = check_in_bounds_game
        seg_idx = segment_indices_exe()
        patterns = list(PATTERNS_EXE)
    else:
        iat_start = ibase + IAT_DLL_OFF[0]
        iat_end = ibase + IAT_DLL_OFF[1]
        check = lambda a: check_in_bounds_neomon(a, ibase)
        seg_idx = segment_indices_dll(img)
        patterns = list(PATTERNS_EXE) + list(PATTERNS_DLL_EXTRA)

    segments = [img.section_by_index(i) for i in seg_idx]
    print(f"[*] Image base: {ibase:#x}")
    print(f"[*] IAT {iat_start:#x} - {iat_end:#x}")
    n_iat = export_old_iat(img, iat_start, iat_end, iat_path)
    print(f"[+] old-iat.csv: {n_iat} slots -> {iat_path}")

    print(f"[*] Scanning sections: {[s.name for s in segments]}")
    n_calls = scan_byte_calls(img, segments, patterns, check, calls_path, names)
    print(f"[+] broken-byte-calls.csv: {n_calls} rows -> {calls_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
