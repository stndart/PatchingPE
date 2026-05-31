#!/usr/bin/env python3
"""Compare call/jump sites between two patched GAME builds.

Scans PE executable sections only. Packer-reclaimed regions (0x219c000..oemvvlbu,
same idea as wlovhtaq) are excluded from the A-vs-B site diff but checked for
incoming branches from live code.
"""

from __future__ import annotations

import argparse
import csv
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO / "scripts" / "standalone") not in sys.path:
    sys.path.insert(0, str(_REPO / "scripts" / "standalone"))

from pe_rva import (  # noqa: E402
    DEAD_SECTION_NAMES,
    IAT_END,
    IAT_START,
    PeImage,
    SectionInfo,
    classify_ptr,
)

IMAGE_SCN_MEM_EXECUTE = 0x20000000

# Packer-reclaimed RVAs (VA 0x219c000..0x2225fff at ImageBase 0x400000).
STOLEN_REGION_RVA_LO = 0x1D9C000
REAL_IDATA_RVA = 0x2226000


def section_is_dead(sec: SectionInfo, imagebase: int) -> bool:
    name = sec.name.strip().lower()
    if name in DEAD_SECTION_NAMES:
        return True
    # Fake .idata, unnamed stolen blob, up to (not including) real PE .idata.
    rva = sec.virtual_address
    if rva == REAL_IDATA_RVA and name == ".idata":
        return False
    if STOLEN_REGION_RVA_LO <= rva < REAL_IDATA_RVA:
        return True
    return False


def executable_sections(img: PeImage) -> list[SectionInfo]:
    out: list[SectionInfo] = []
    for i, s in enumerate(img.pe.sections):
        if not (s.Characteristics & IMAGE_SCN_MEM_EXECUTE):
            continue
        sec = img.sections[i]
        out.append(sec)
    return out


def live_executable_sections(img: PeImage) -> list[SectionInfo]:
    return [s for s in executable_sections(img) if not section_is_dead(s, img.imagebase)]


def va_in_dead(img: PeImage, va: int) -> bool:
    rva = va - img.imagebase if va >= img.imagebase else va
    for sec in img.sections:
        size = max(sec.virtual_size, sec.size_of_raw_data)
        if sec.virtual_address <= rva < sec.virtual_address + size:
            return section_is_dead(sec, img.imagebase)
    return False


@dataclass(frozen=True)
class Site:
    insn_va: int
    kind: str  # call90, jmp90, call, jmp, call_iat, jmp_iat
    raw: bytes
    target: int | None  # rel32 dest or [disp] slot VA
    slot_value: int | None  # dword at disp for FF15/FF25

    def summary(self) -> str:
        t = f"{self.target:#x}" if self.target is not None else "?"
        if self.slot_value is not None:
            t += f" -> [{self.slot_value:#x}]"
        return t


def decode_site(img: PeImage, insn_va: int, raw: bytes) -> Site | None:
    if len(raw) < 5:
        return None
    b0, b1 = raw[0], raw[1]
    if b0 == 0x90 and b1 in (0xE8, 0xE9) and len(raw) >= 6:
        call_ea = insn_va + 1
        disp = struct.unpack("<i", raw[2:6])[0]
        tgt = call_ea + 5 + disp
        kind = "call90" if b1 == 0xE8 else "jmp90"
        return Site(insn_va, kind, raw[:6], tgt, None)
    if b0 in (0xE8, 0xE9) and raw[0] != 0x90:
        disp = struct.unpack("<i", raw[1:5])[0]
        tgt = insn_va + 5 + disp
        kind = "call" if b0 == 0xE8 else "jmp"
        return Site(insn_va, kind, raw[:5], tgt, None)
    if b0 == 0xFF and b1 in (0x15, 0x25) and len(raw) >= 6:
        disp = struct.unpack("<I", raw[2:6])[0]
        slot = disp  # absolute VA in this dump-linked build
        val = img.read_dword_va(slot)
        kind = "call_iat" if b1 == 0x15 else "jmp_iat"
        return Site(insn_va, kind, raw[:6], slot, val)
    return None


def scan_section(img: PeImage, sec: SectionInfo) -> dict[int, Site]:
    """Only packer stubs (90 E8/E9) and IAT indirections (FF 15/FF 25)."""
    sites: dict[int, Site] = {}
    raw = bytes(img.section_raw_slice(sec))
    base_va = img.imagebase + sec.virtual_address
    i = 0
    while i < len(raw):
        # 90 E8/E9
        if i + 6 <= len(raw) and raw[i] == 0x90 and raw[i + 1] in (0xE8, 0xE9):
            insn_va = base_va + i
            site = decode_site(img, insn_va, raw[i : i + 6])
            if site:
                sites[insn_va] = site
            i += 1
            continue
        # FF 15 / FF 25
        if i + 6 <= len(raw) and raw[i] == 0xFF and raw[i + 1] in (0x15, 0x25):
            insn_va = base_va + i
            site = decode_site(img, insn_va, raw[i : i + 6])
            if site:
                sites[insn_va] = site
            i += 6
            continue
        i += 1
    return sites


def scan_live(img: PeImage) -> dict[int, Site]:
    out: dict[int, Site] = {}
    for sec in live_executable_sections(img):
        out.update(scan_section(img, sec))
    return out


def scan_all_exec(img: PeImage) -> dict[int, Site]:
    out: dict[int, Site] = {}
    for sec in executable_sections(img):
        out.update(scan_section(img, sec))
    return out


def neomon_slot_hint(slot_va: int | None) -> str:
    if slot_va is None:
        return ""
    if 0x15888E0 <= slot_va <= 0x15888F8 and (slot_va - 0x15888E0) % 4 == 0:
        n = (slot_va - 0x15888E0) // 4 + 1
        return f"NIGS_{n}"
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe_a", type=Path)
    parser.add_argument("exe_b", type=Path)
    parser.add_argument("-o", "--out-dir", type=Path, required=True)
    args = parser.parse_args()

    img_a = PeImage(args.exe_a)
    img_b = PeImage(args.exe_b)
    sites_a = scan_live(img_a)
    sites_b = scan_live(img_b)

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- differing sites in live executable sections ---
    diff_rows: list[dict] = []
    all_insns = sorted(set(sites_a) | set(sites_b))
    for insn in all_insns:
        sa, sb = sites_a.get(insn), sites_b.get(insn)
        if sa is None or sb is None:
            diff_rows.append(
                {
                    "insn_va": hex(insn),
                    "status": "only_a" if sb is None else "only_b",
                    "kind_a": sa.kind if sa else "",
                    "kind_b": sb.kind if sb else "",
                    "raw_a": sa.raw.hex() if sa else "",
                    "raw_b": sb.raw.hex() if sb else "",
                    "target_a": hex(sa.target) if sa and sa.target else "",
                    "target_b": hex(sb.target) if sb and sb.target else "",
                    "slot_val_a": hex(sa.slot_value) if sa and sa.slot_value is not None else "",
                    "slot_val_b": hex(sb.slot_value) if sb and sb.slot_value is not None else "",
                    "iat_hint": neomon_slot_hint((sa or sb).target if (sa or sb) else None),
                    "ptr_class_a": classify_ptr(sa.target) if sa and sa.target else "",
                    "ptr_class_b": classify_ptr(sb.target) if sb and sb.target else "",
                }
            )
            continue
        if sa.raw == sb.raw and sa.slot_value == sb.slot_value:
            continue
        diff_rows.append(
            {
                "insn_va": hex(insn),
                "status": "diff",
                "kind_a": sa.kind,
                "kind_b": sb.kind,
                "raw_a": sa.raw.hex(),
                "raw_b": sb.raw.hex(),
                "target_a": hex(sa.target) if sa.target else "",
                "target_b": hex(sb.target) if sb.target else "",
                "slot_val_a": hex(sa.slot_value) if sa.slot_value is not None else "",
                "slot_val_b": hex(sb.slot_value) if sb.slot_value is not None else "",
                "iat_hint": neomon_slot_hint(sa.target),
                "ptr_class_a": classify_ptr(sa.target) if sa.target else "",
                "ptr_class_b": classify_ptr(sb.target) if sb.target else "",
            }
        )

    diff_path = out_dir / "call_sites_diff.csv"
    if diff_rows:
        with open(diff_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(diff_rows[0].keys()))
            w.writeheader()
            w.writerows(diff_rows)

    # --- unpatched stubs (90 E8/E9) still present ---
    stub_rows = []
    for label, sites in [("a", sites_a), ("b", sites_b)]:
        for insn, s in sorted(sites.items()):
            if s.kind in ("call90", "jmp90"):
                stub_rows.append(
                    {
                        "image": label,
                        "insn_va": hex(insn),
                        "kind": s.kind,
                        "raw": s.raw.hex(),
                        "target": hex(s.target) if s.target else "",
                        "ptr_class": classify_ptr(s.target) if s.target else "",
                    }
                )
    stub_path = out_dir / "unpatched_stubs_live.csv"
    with open(stub_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(stub_rows[0].keys()) if stub_rows else [])
        if stub_rows:
            w.writeheader()
            w.writerows(stub_rows)

    # --- FF15/FF25 with differing slot *contents* (scratch IAT), same opcode ---
    iat_slot_rows = []
    for insn in sorted(set(sites_a) & set(sites_b)):
        sa, sb = sites_a[insn], sites_b[insn]
        if sa.kind not in ("call_iat", "jmp_iat"):
            continue
        if sa.raw != sb.raw:
            continue
        if sa.slot_value != sb.slot_value:
            iat_slot_rows.append(
                {
                    "insn_va": hex(insn),
                    "kind": sa.kind,
                    "raw": sa.raw.hex(),
                    "slot_va": hex(sa.target) if sa.target else "",
                    "iat_hint": neomon_slot_hint(sa.target),
                    "slot_val_a": hex(sa.slot_value) if sa.slot_value is not None else "",
                    "slot_val_b": hex(sb.slot_value) if sb.slot_value is not None else "",
                }
            )
    iat_path = out_dir / "iat_indirect_same_opcode_diff_slot.csv"
    with open(iat_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(iat_slot_rows[0].keys()) if iat_slot_rows else [])
        if iat_slot_rows:
            w.writeheader()
            w.writerows(iat_slot_rows)

    # --- branches from live code into dead regions ---
    dead_hits: list[dict] = []
    for label, img, sites in [("a", img_a, sites_a), ("b", img_b, sites_b)]:
        for insn, s in sorted(sites.items()):
            targets: list[tuple[str, int]] = []
            if s.target is not None:
                targets.append(("direct", s.target))
            if s.slot_value is not None and s.slot_value >= 0x10000:
                targets.append(("slot_deref", s.slot_value))
            for tkind, tv in targets:
                if va_in_dead(img, tv):
                    dead_hits.append(
                        {
                            "image": label,
                            "from_insn": hex(insn),
                            "site_kind": s.kind,
                            "raw": s.raw.hex(),
                            "into_kind": tkind,
                            "dead_va": hex(tv),
                            "iat_hint": neomon_slot_hint(s.target if tkind == "slot_deref" else None),
                        }
                    )
    dead_path = out_dir / "branches_into_dead_regions.csv"
    with open(dead_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(dead_hits[0].keys()) if dead_hits else [])
        if dead_hits:
            w.writeheader()
            w.writerows(dead_hits)

    # --- summary ---
    kinds_a: dict[str, int] = {}
    kinds_b: dict[str, int] = {}
    for s in sites_a.values():
        kinds_a[s.kind] = kinds_a.get(s.kind, 0) + 1
    for s in sites_b.values():
        kinds_b[s.kind] = kinds_b.get(s.kind, 0) + 1

    diff_by_kind: dict[str, int] = {}
    for r in diff_rows:
        k = r.get("kind_a") or r.get("kind_b")
        diff_by_kind[k] = diff_by_kind.get(k, 0) + 1

    neomon_diff = sum(1 for r in diff_rows if r.get("iat_hint", "").startswith("NIGS"))
    neomon_slot_only = sum(1 for r in iat_slot_rows if r.get("iat_hint", "").startswith("NIGS"))

    print(f"A = {args.exe_a}")
    print(f"B = {args.exe_b}")
    print("\n== LIVE EXECUTABLE SECTIONS SCANNED ==")
    for img, label in [(img_a, "A"), (img_b, "B")]:
        live = live_executable_sections(img)
        dead = [s for s in executable_sections(img) if section_is_dead(s, img.imagebase)]
        print(f"  {label}: live={[s.name.strip() or f'sec{s.index}' for s in live]}")
        print(f"  {label}: dead (excluded)={[hex(img.imagebase + s.virtual_address) for s in dead]}")

    print("\n== SITE COUNTS (live exec only) ==")
    print(f"  A: {kinds_a}")
    print(f"  B: {kinds_b}")
    print(f"\n== DIFFERING SITES (any byte/slot change) ==")
    print(f"  total: {len(diff_rows)}")
    print(f"  by kind: {diff_by_kind}")
    print(f"  with NeoMon scratch slot (NIGS_*): {neomon_diff}")
    print(f"\n== UNPATCHED 90 E8/E9 (live) ==")
    print(f"  A: {sum(1 for s in sites_a.values() if s.kind in ('call90','jmp90'))}")
    print(f"  B: {sum(1 for s in sites_b.values() if s.kind in ('call90','jmp90'))}")
    same_stub_diff_tgt = sum(
        1
        for insn in set(sites_a) & set(sites_b)
        if sites_a[insn].kind in ("call90", "jmp90")
        and sites_a[insn].target != sites_b[insn].target
    )
    print(f"  same insn, different rel32 target: {same_stub_diff_tgt}")
    print(f"\n== FF15/FF25 same opcode, different slot DWORD ==")
    print(f"  total: {len(iat_slot_rows)}")
    print(f"  NeoMon NIGS slots: {neomon_slot_only}")
    print(f"\n== BRANCHES INTO DEAD REGIONS (from live code) ==")
    print(f"  hits: {len(dead_hits)}")
    for h in dead_hits[:15]:
        print(f"    [{h['image']}] {h['from_insn']} {h['site_kind']} -> {h['dead_va']} ({h['into_kind']})")
    if len(dead_hits) > 15:
        print(f"    ... {len(dead_hits) - 15} more")

    print(f"\nWrote {diff_path}")
    print(f"Wrote {stub_path}")
    print(f"Wrote {iat_path}")
    print(f"Wrote {dead_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
