#!/usr/bin/env python3
"""Compare patched GAME builds: IAT, patch coverage, stubs, reboot-only code diffs.

Excludes dead sections wlovhtaq and oemvvlbu from byte/section diffs.
"""

from __future__ import annotations

import argparse
import csv
import struct
import sys
from pathlib import Path

import pefile

# Allow importing standalone helpers when run from repo root
_REPO = Path(__file__).resolve().parent.parent
if str(_REPO / "scripts" / "standalone") not in sys.path:
    sys.path.insert(0, str(_REPO / "scripts" / "standalone"))

from pe_rva import DEAD_SECTION_NAMES, IAT_END, IAT_START, PeImage, classify_ptr  # noqa: E402


def imports_table(path: Path) -> dict[str, set[str]]:
    pe = pefile.PE(str(path), fast_load=True)
    out: dict[str, set[str]] = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return out
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = (entry.dll or b"").decode("latin1").lower()
        syms: set[str] = set()
        for imp in entry.imports:
            if imp.name:
                syms.add(imp.name.decode("latin1"))
            else:
                syms.add(f"ORD#{imp.ordinal}")
        out.setdefault(dll, set()).update(syms)
    return out


def read_iat_slots(img: PeImage) -> list[tuple[int, int]]:
    slots: list[tuple[int, int]] = []
    ea = IAT_START
    while ea < IAT_END:
        v = img.read_dword_va(ea)
        if v is not None:
            slots.append((ea, v))
        ea += 4
    return slots


def load_patch_addrs(patches_dir: Path) -> set[int]:
    addrs: set[int] = set()
    for fn in ("calls_patch.csv", "thunks_patch.csv"):
        p = patches_dir / fn
        if not p.is_file():
            continue
        with open(p, newline="") as f:
            for row in csv.DictReader(f):
                addrs.add(int(row["patch_addr"], 16))
    return addrs


def scan_stubs(img: PeImage, limit: int = 30) -> dict[str, int]:
    """Count 90 E8 / 90 E9 in code sections (0-1), classify rel32 targets."""
    buckets: dict[str, int] = {}
    samples: list[tuple[int, int, str]] = []
    for sec in img.sections[:2]:
        raw = bytes(img.section_raw_slice(sec))
        base_va = img.imagebase + sec.virtual_address
        i = 0
        while i < len(raw) - 6:
            if raw[i] == 0x90 and raw[i + 1] in (0xE8, 0xE9):
                call_ea = base_va + i + 1
                disp = struct.unpack("<i", raw[i + 2 : i + 6])[0]
                target = call_ea + 5 + disp
                kind = classify_ptr(target)
                buckets[kind] = buckets.get(kind, 0) + 1
                if len(samples) < limit:
                    samples.append((base_va + i, target, kind))
                i += 6
            else:
                i += 1
    buckets["_samples"] = samples  # type: ignore[assignment]
    return buckets


def count_ff15_90e8(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    pe = pefile.PE(str(path), fast_load=True)
    code = pe.sections[0]
    lo = code.PointerToRawData
    hi = lo + code.SizeOfRawData
    body = data[lo:hi]
    return body.count(b"\x90\xe8"), body.count(b"\xff\x15")


def section_byte_diffs(a: PeImage, b: PeImage, code_only: bool = False) -> list[tuple[str, int, int]]:
    """Per-section diff counts; skips dead sections."""
    rows: list[tuple[str, int, int]] = []
    for sa, sb in zip(a.sections, b.sections):
        if sa.name.lower() in DEAD_SECTION_NAMES:
            continue
        if code_only and sa.index > 1:
            continue
        size = min(sa.size_of_raw_data, sb.size_of_raw_data, len(a.data), len(b.data))
        ptr = sa.pointer_to_raw_data
        da = a.data[ptr : ptr + size]
        db = b.data[ptr : ptr + size]
        diff = sum(1 for x, y in zip(da, db) if x != y)
        if diff:
            rows.append((sa.name, diff, size))
    return rows


def reboot_pointer_diffs(a: PeImage, b: PeImage) -> list[tuple[int, int, int, int]]:
    """DWORD changes in sections 0-1 where at least one value is sysdll-range."""
    out: list[tuple[int, int, int, int]] = []
    for sa, sb in zip(a.sections[:2], b.sections[:2]):
        ptr = sa.pointer_to_raw_data
        size = min(sa.size_of_raw_data, sb.size_of_raw_data)
        da = a.data[ptr : ptr + size]
        db = b.data[ptr : ptr + size]
        va0 = a.imagebase + sa.virtual_address
        i = 0
        while i + 4 <= size:
            if da[i : i + 4] != db[i : i + 4]:
                va = struct.unpack("<I", da[i : i + 4])[0]
                vb = struct.unpack("<I", db[i : i + 4])[0]
                if va >= 0x10000 and vb >= 0x10000:
                    if classify_ptr(va) == "sysdll" or classify_ptr(vb) == "sysdll":
                        out.append((va0 + i, va, vb))
            i += 1
    return out


def patch_coverage(
    local_exe: Path,
    remote_patches: Path,
    local_patches: Path | None,
    out_dir: Path | None,
) -> None:
    img = PeImage(local_exe)
    remote_addrs = load_patch_addrs(remote_patches)
    local_addrs = load_patch_addrs(local_patches) if local_patches else set()
    only_remote = remote_addrs - local_addrs
    missing_stubs: list[tuple[int, str]] = []
    for addr in sorted(only_remote):
        b = img.read_bytes_va(addr, 6)
        if b is None:
            continue
        hx = b.hex().upper()
        if hx.startswith("90E8") or hx.startswith("90E9"):
            missing_stubs.append((addr, hx))
        elif not (hx.startswith("FF15") or hx.startswith("FF25")):
            missing_stubs.append((addr, hx))

    print(f"\n== PATCH COVERAGE ==")
    print(f"  Remote patch sites: {len(remote_addrs)}")
    print(f"  Local patch sites:  {len(local_addrs)}")
    print(f"  Only on remote:     {len(only_remote)}")
    print(f"  Local still stub/unpatched at remote-only sites: {len(missing_stubs)}")
    for addr, hx in missing_stubs[:20]:
        print(f"    {addr:#x}: {hx}")
    if len(missing_stubs) > 20:
        print(f"    ... and {len(missing_stubs) - 20} more")

    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        p = out_dir / "missing_patches.csv"
        with open(p, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["patch_addr", "bytes_at_local"])
            w.writerows([(hex(a), h) for a, h in missing_stubs])
        print(f"  Wrote {p}")


def iat_diff(a: PeImage, b: PeImage, out_dir: Path | None) -> None:
    sa = read_iat_slots(a)
    sb = read_iat_slots(b)
    diffs = [(ea, va, vb) for (ea, va), (_, vb) in zip(sa, sb) if va != vb]
    print(f"\n== OLD IAT REGION ({IAT_START:#x}-{IAT_END:#x}) ==")
    print(f"  Slots: {len(sa)}  Differing values: {len(diffs)}")
    for ea, va, vb in diffs[:15]:
        print(f"    {ea:#010x}: {va:#010x} -> {vb:#010x}")
    if len(diffs) > 15:
        print(f"    ... {len(diffs) - 15} more")
    if out_dir and diffs:
        out_dir.mkdir(parents=True, exist_ok=True)
        p = out_dir / "iat_diff.csv"
        with open(p, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Address", "A", "B"])
            w.writerows([(f"{ea:#x}", f"{va:08X}", f"{vb:08X}") for ea, va, vb in diffs])
        print(f"  Wrote {p}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe_a", type=Path)
    parser.add_argument("exe_b", type=Path)
    parser.add_argument(
        "--patches-a",
        type=Path,
        default=None,
        help="patches/ dir for exe A tree",
    )
    parser.add_argument(
        "--patches-b",
        type=Path,
        default=None,
        help="patches/ dir for exe B tree",
    )
    parser.add_argument(
        "--local-exe",
        type=Path,
        default=None,
        help="For coverage: exe to check (defaults to exe_a)",
    )
    parser.add_argument(
        "--remote-patches",
        type=Path,
        default=None,
        help="Good patches dir to diff against local",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Write CSV reports here",
    )
    parser.add_argument(
        "--reboot-diff",
        action="store_true",
        help="Remote vs remote-2 style: sysdll pointer deltas in code sections only",
    )
    args = parser.parse_args()

    img_a = PeImage(args.exe_a)
    img_b = PeImage(args.exe_b)

    print(f"A = {args.exe_a}")
    print(f"B = {args.exe_b}")

    print("\n== IMPORTS ==")
    ia, ib = imports_table(args.exe_a), imports_table(args.exe_b)
    for dll in sorted(set(ia) | set(ib)):
        sa_, sb_ = ia.get(dll, set()), ib.get(dll, set())
        if sa_ == sb_:
            print(f"  {dll:20} same ({len(sa_)} syms)")
        else:
            print(f"  {dll:20} DIFF A={len(sa_)} B={len(sb_)}")

    e8a, ffa = count_ff15_90e8(args.exe_a)
    e8b, ffb = count_ff15_90e8(args.exe_b)
    print(f"\n== CALL-SITE PATTERNS (section 0) ==")
    print(f"  A: 90 E8={e8a}  FF 15={ffa}")
    print(f"  B: 90 E8={e8b}  FF 15={ffb}")

    iat_diff(img_a, img_b, args.out_dir)

    stubs_a = scan_stubs(img_a)
    samples = stubs_a.pop("_samples", [])
    print(f"\n== UNPATCHED STUBS (A, section 0-1) ==")
    for k, v in sorted(stubs_a.items()):
        print(f"  {k}: {v}")
    print("  samples:")
    for addr, tgt, kind in samples[:12]:
        print(f"    {addr:#x} -> {tgt:#x} ({kind})")

    print(f"\n== SECTION BYTE DIFFS (excl. {', '.join(DEAD_SECTION_NAMES)}) ==")
    for name, diff, total in section_byte_diffs(img_a, img_b):
        print(f"  {name:12} {diff}/{total}")

    if args.reboot_diff:
        rd = reboot_pointer_diffs(img_a, img_b)
        print(f"\n== REBOOT SYSdll DWORD DIFFS (code sect 0-1) ==")
        print(f"  Count: {len(rd)}")
        for va, v0, v1 in rd[:20]:
            print(f"    {va:#x}: {v0:#x} -> {v1:#x}")
        if len(rd) > 20:
            print(f"    ... {len(rd) - 20} more")

    local = args.local_exe or args.exe_a
    remote_p = args.remote_patches or args.patches_b
    local_p = args.patches_a
    if remote_p and remote_p.is_dir():
        patch_coverage(local, remote_p, local_p, args.out_dir)

    return 0


if __name__ == "__main__":
    sys.exit(main())
