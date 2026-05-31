#!/usr/bin/env python3
"""Map packer stubs -> IAT slots; verify reboot builds differ only where expected.

Compares an *unapplied* build (90 E8 stubs) to a *fully patched* build (FF 15/FF 25
via fixed IAT slot VAs). Success: every patch site is IAT-indirect; remaining stubs
in the patched file are intentional/non-sysdll.

Excludes dead sections wlovhtaq / oemvvlbu from code scans.
"""

from __future__ import annotations

import argparse
import csv
import struct
import sys
from pathlib import Path

import polars as pl

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO / "scripts" / "standalone") not in sys.path:
    sys.path.insert(0, str(_REPO / "scripts" / "standalone"))

from pe_rva import IAT_END, IAT_START, PeImage, classify_ptr  # noqa: E402

# Notebook call_exceptions: left as 90 E8 -> thunk (not FF15)
CALL_PATCH_EXCEPTIONS = frozenset({0x61FFFA})


def load_iat_symbol_map(old_iat: Path, dump_imports: Path) -> dict[int, dict[str, str]]:
    """Map absolute export Address -> {Calladdr, Module, Function}."""
    iat = pl.read_csv(old_iat)
    iat = iat.rename({"Address": "Calladdr", "Destination": "Address"})
    iat = iat.with_columns(
        ("0x" + pl.col("Address").str.strip_prefix("0x").str.to_lowercase()).alias("Address")
    )

    imp = pl.read_csv(
        dump_imports,
        encoding="utf-8",
        infer_schema_length=10000,
        ignore_errors=True,
    )
    # x64dbg RU/EN column names
    rename = {}
    for c in imp.columns:
        cl = c.lower()
        if "адрес" in cl or c == "Address":
            rename[c] = "Address"
        elif "символ" in cl and "undec" not in cl.lower() or c == "Symbol":
            rename[c] = "Symbol"
        elif "тип" in cl or c == "Type":
            rename[c] = "Type"
        elif "порядков" in cl or c == "Ordinal":
            rename[c] = "Ordinal"
    imp = imp.rename(rename)
    imp = imp.with_columns(
        pl.when(pl.col("Type").str.contains("Экспорт"))
        .then(pl.lit("Export"))
        .otherwise(pl.lit("Import"))
        .alias("Type")
    )
    imp = imp.filter(pl.col("Type") == "Export").drop("Type")
    if "Symbol" in imp.columns:
        imp = imp.rename({"Symbol": "Function"})

    mod_path = old_iat.parent.parent / "game.exe.export.full.csv"
    mod = pl.read_csv(mod_path, encoding="utf-8", ignore_errors=True)
    if "Function" in mod.columns:
        mod = mod.drop("Function")
    imp = imp.join(mod, on="Address", how="left")
    imp = imp.with_columns(
        ("0x" + pl.col("Address").str.strip_prefix("0x").str.to_lowercase()).alias("Address")
    )

    joined = iat.join(
        imp.select("Address", "Module", "Function", "Ordinal"),
        on="Address",
        how="left",
    )
    out: dict[int, dict[str, str]] = {}
    for row in joined.iter_rows(named=True):
        dest = int(row["Address"], 16)
        out[dest] = {
            "Calladdr": row["Calladdr"],
            "Module": row.get("Module") or "",
            "Function": row.get("Function") or "",
        }
    return out


def parse_patch_iat_slot(patch_hex: str) -> tuple[str, int | None]:
    """Return (kind, iat_slot_va) for FF15/FF25 patches."""
    p = patch_hex.upper()
    if p.startswith("FF15") or p.startswith("FF25"):
        imm = int.from_bytes(bytes.fromhex(p[4:12]), "little")
        return ("call_iat" if p.startswith("FF15") else "jmp_iat", imm)
    if p.startswith("90E8") or p.startswith("90E9"):
        return ("stub", None)
    return ("other", None)


def load_patches(patches_dir: Path) -> pl.DataFrame:
    frames = []
    for fn in ("calls_patch.csv", "thunks_patch.csv"):
        p = patches_dir / fn
        if p.is_file():
            frames.append(pl.read_csv(p))
    if not frames:
        return pl.DataFrame()
    return pl.concat(frames)


def scan_remaining_stubs(img: PeImage) -> list[dict]:
    """Find 90 E8/E9 in code sections 0-1 not covered by patch list."""
    rows: list[dict] = []
    for sec in img.sections[:2]:
        raw = bytes(img.section_raw_slice(sec))
        base_va = img.imagebase + sec.virtual_address
        i = 0
        while i < len(raw) - 6:
            if raw[i] == 0x90 and raw[i + 1] in (0xE8, 0xE9):
                site = base_va + i
                op = "call" if raw[i + 1] == 0xE8 else "jmp"
                disp = struct.unpack("<i", raw[i + 2 : i + 6])[0]
                target = base_va + i + 1 + 5 + disp
                rows.append(
                    {
                        "site": site,
                        "op": op,
                        "target": target,
                        "target_class": classify_ptr(target),
                    }
                )
                i += 6
            else:
                i += 1
    return rows


def code_section_bytes_excluding_iat(img: PeImage) -> bytes:
    """Concatenate raw bytes of sections 0-1, zeroing IAT VA range if it falls inside."""
    chunks: list[bytearray] = []
    for sec in img.sections[:2]:
        chunks.append(bytearray(img.section_raw_slice(sec)))
    # IAT is at VA 0x1588000 in section 0 for this image
    sec0 = img.sections[0]
    base_va = img.imagebase + sec0.virtual_address
    iat_lo = IAT_START - base_va
    iat_hi = IAT_END - base_va
    if 0 <= iat_lo < len(chunks[0]) and iat_hi <= len(chunks[0]):
        for j in range(iat_lo, iat_hi):
            chunks[0][j] = 0
    return bytes(chunks[0]) + bytes(chunks[1])


def verify_patch_sites(
    before: PeImage,
    after: PeImage,
    patches: pl.DataFrame,
    sym_map: dict[int, dict[str, str]],
) -> tuple[pl.DataFrame, dict[str, int]]:
    stats: dict[str, int] = {
        "total": 0,
        "stub_before_ok": 0,
        "iat_after_ok": 0,
        "iat_slot_matches_csv": 0,
        "mismatch_before": 0,
        "mismatch_after": 0,
    }
    rows: list[dict] = []

    for patch_addr, mem_old, patch in patches.rows():
        stats["total"] += 1
        ea = int(str(patch_addr), 16)
        b = before.read_bytes_va(ea, 6) or b""
        a = after.read_bytes_va(ea, 6) or b""
        bhx, ahx = b.hex().upper(), a.hex().upper()

        kind, slot_csv = parse_patch_iat_slot(str(patch))
        stub_ok = bhx.startswith("90E8") or bhx.startswith("90E9") or bhx == str(mem_old).upper()
        is_exception = ea in CALL_PATCH_EXCEPTIONS
        iat_ok = ahx.startswith("FF15") or ahx.startswith("FF25") or (
            is_exception and ahx.startswith("90E8")
        )

        if stub_ok:
            stats["stub_before_ok"] += 1
        else:
            stats["mismatch_before"] += 1
        if iat_ok:
            stats["iat_after_ok"] += 1
        else:
            stats["mismatch_after"] += 1

        slot_after = None
        if iat_ok:
            _, slot_after = parse_patch_iat_slot(ahx)

        if slot_csv and slot_after and slot_csv == slot_after:
            stats["iat_slot_matches_csv"] += 1

        # decode stub target from mem_old
        stub_target = None
        mo = str(mem_old).upper()
        if mo.startswith("90E8") or mo.startswith("90E9"):
            rel = int.from_bytes(bytes.fromhex(mo[4:12]), "little", signed=True)
            call_ea = ea + 1  # 90 E8: call at patch_addr+1
            stub_target = call_ea + 5 + rel

        sym = sym_map.get(stub_target or 0, {})

        rows.append(
            {
                "patch_addr": hex(ea),
                "before_bytes": bhx,
                "after_bytes": ahx,
                "stub_target": hex(stub_target) if stub_target else "",
                "iat_slot": hex(slot_after) if slot_after else "",
                "expected_iat_slot": sym.get("Calladdr", ""),
                "module": sym.get("Module", ""),
                "function": sym.get("Function", ""),
                "stub_ok": stub_ok,
                "iat_ok": iat_ok,
            }
        )

    return pl.DataFrame(rows), stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--before",
        required=True,
        type=Path,
        help="Unapplied GAME_patched_dll (stubs)",
    )
    parser.add_argument(
        "--after",
        required=True,
        type=Path,
        help="Fully patched build (IAT indirect)",
    )
    parser.add_argument(
        "--patches-dir",
        required=True,
        type=Path,
        help="calls_patch.csv + thunks_patch.csv",
    )
    parser.add_argument(
        "--old-iat",
        type=Path,
        default=_REPO / "game-dump-remote/dumps/old-iat.csv",
    )
    parser.add_argument(
        "--dump-imports",
        type=Path,
        default=_REPO / "game-dump-remote/dumps/dump-imports.csv",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=_REPO / "game-dump/compare",
    )
    parser.add_argument(
        "--compare-code",
        type=Path,
        default=None,
        help="Optional third exe: must match --after code (excl. IAT slot bytes)",
    )
    args = parser.parse_args()

    sym_map = load_iat_symbol_map(args.old_iat, args.dump_imports)
    patches = load_patches(args.patches_dir)
    before = PeImage(args.before)
    after = PeImage(args.after)

    print(f"Before (stubs):  {args.before}")
    print(f"After (IAT):     {args.after}")
    print(f"Patches:         {patches.shape[0]} sites")
    print(f"IAT symbol map:  {len(sym_map)} destinations")

    df, stats = verify_patch_sites(before, after, patches, sym_map)
    print("\n== PATCH SITE VERIFICATION ==")
    for k, v in stats.items():
        print(f"  {k}: {v}")

    bad = df.filter(~pl.col("iat_ok") | ~pl.col("stub_ok"))
    print(f"  Problem sites: {bad.shape[0]}")
    if bad.shape[0]:
        for r in bad.head(10).rows(named=True):
            print(
                f"    {r['patch_addr']} before={r['before_bytes']} after={r['after_bytes']}"
            )

  # IAT region: slot values differ across reboots; Calladdr layout is fixed
    sa = []
    sb = []
    ea = IAT_START
    while ea < IAT_END:
        sa.append(before.read_dword_va(ea))
        sb.append(after.read_dword_va(ea))
        ea += 4
    iat_diffs = sum(1 for a, b in zip(sa, sb) if a != b)
    print(f"\n== IAT SLOT REGION ({IAT_START:#x}-{IAT_END:#x}) ==")
    print(f"  Slots: {len(sa)}  Value diffs (expected across reboot dumps): {iat_diffs}")
    print("  (Loader re-binds FirstThunk -> this region at run time; code uses FF15/FF25 to slot VAs.)")

    remaining = scan_remaining_stubs(after)
    patch_addrs = set(int(str(a), 16) for a in patches["patch_addr"].to_list())
    unlisted = [r for r in remaining if r["site"] not in patch_addrs]
    by_class: dict[str, int] = {}
    for r in unlisted:
        by_class[r["target_class"]] = by_class.get(r["target_class"], 0) + 1

    print(f"\n== REMAINING 90 E8/E9 IN PATCHED FILE (sections 0-1) ==")
    print(f"  Total stub sites: {len(remaining)}")
    print(f"  Not in patch CSV: {len(unlisted)}")
    for k, v in sorted(by_class.items()):
        print(f"    target {k}: {v}")
    sysdll_left = [r for r in unlisted if r["target_class"] == "sysdll"]
    print(f"  Unlisted stubs -> sysdll: {len(sysdll_left)}")
    for r in sysdll_left[:8]:
        print(f"    {r['site']:#x} {r['op']} -> {r['target']:#x}")

    code_a = code_section_bytes_excluding_iat(after)
    if args.compare_code:
        other = PeImage(args.compare_code)
        code_b = code_section_bytes_excluding_iat(other)
        same = code_a == code_b
        print(f"\n== CODE IDENTITY (sect 0-1, IAT slots zeroed) ==")
        print(f"  Compare: {args.compare_code}")
        print(f"  Identical: {same}")
        if not same:
            diffs = sum(1 for x, y in zip(code_a, code_b) if x != y)
            print(f"  Byte diffs: {diffs} / {min(len(code_a), len(code_b))}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_csv = args.out_dir / "reboot_iat_map.csv"
    df.write_csv(out_csv)
    print(f"\nWrote {out_csv}")

    # Known gaps: export targets not present in old-iat.csv (never got an IAT slot row)
    KNOWN_UNLISTED_SYSDLL = frozenset({0x798465, 0x117FC65})
    unlisted_sys = {r["site"] for r in sysdll_left}
    known_only = unlisted_sys <= KNOWN_UNLISTED_SYSDLL

    ok = (
        stats["iat_after_ok"] == stats["total"]
        and stats["stub_before_ok"] == stats["total"]
        and (len(sysdll_left) == 0 or known_only)
    )
    if known_only and sysdll_left:
        print(
            f"\n  Note: {len(sysdll_left)} direct sysdll stub(s) not in patch CSV "
            f"(dest not in old-iat); same in reference build."
        )
    print(f"\n{'PASS' if ok else 'FAIL'}: IAT mapping complete" if stats["total"] else "\nNo patches")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
