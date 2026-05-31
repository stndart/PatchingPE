#!/usr/bin/env python3
"""Compare PE structure of two GAME.exe builds.

Focus: headers, sections, data directories, and the import table -- the parts
the IAT-rebuild pipeline touches. Use it to explain why a build produced on one
machine fails to start on another.

Usage:
    uv run python scripts/compare_game_exes.py "<a.exe>" "<b.exe>"
"""

import sys
import pefile


def load(path):
    return pefile.PE(path, fast_load=False)


def hdr(pe):
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER
    return {
        "ImageBase": oh.ImageBase,
        "AddressOfEntryPoint": oh.AddressOfEntryPoint,
        "SizeOfImage": oh.SizeOfImage,
        "SizeOfHeaders": oh.SizeOfHeaders,
        "CheckSum": oh.CheckSum,
        "DllCharacteristics": oh.DllCharacteristics,
        "Subsystem": oh.Subsystem,
        "NumberOfSections": fh.NumberOfSections,
        "TimeDateStamp": fh.TimeDateStamp,
    }


def sections(pe):
    out = {}
    for s in pe.sections:
        out[s.Name.rstrip(b"\x00").decode("latin1")] = (
            s.VirtualAddress,
            s.Misc_VirtualSize,
            s.SizeOfRawData,
            s.Characteristics,
        )
    return out


def dirs(pe):
    out = {}
    for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        out[d.name] = (d.VirtualAddress, d.Size)
    return out


def imports(pe):
    """dll(lower) -> set of imported symbol names (or ORD#n)."""
    out = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return out
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = (entry.dll or b"").decode("latin1").lower()
        syms = set()
        for imp in entry.imports:
            if imp.name:
                syms.add(imp.name.decode("latin1"))
            else:
                syms.add(f"ORD#{imp.ordinal}")
        out.setdefault(dll, set()).update(syms)
    return out


def raw_section_diff(a, b):
    """Byte-level diff of identically-sized files, bucketed per section."""
    da = open(a, "rb").read()
    db = open(b, "rb").read()
    print(f"\n== RAW BYTE DIFF ==\n  len A={len(da)}  len B={len(db)}")
    if len(da) != len(db):
        print("  (different file sizes -- byte buckets are by min length)")
    n = min(len(da), len(db))
    pe = pefile.PE(a, fast_load=True)
    secs = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin1") or "<noname>"
        secs.append((name, s.PointerToRawData, s.SizeOfRawData, s.VirtualAddress))
    # header region before first section
    first = min(s[1] for s in secs)
    buckets = {"<headers>": [0, first, 0, None]}
    for name, ptr, size, rva in secs:
        buckets[f"{name}@{rva:08X}"] = [ptr, ptr + size, 0, rva]
    other = [0, n, 0, None]
    for i in range(n):
        if da[i] != db[i]:
            placed = False
            for v in buckets.values():
                if v[0] <= i < v[1]:
                    v[2] += 1
                    placed = True
                    break
            if not placed:
                other[2] += 1
    for k, v in buckets.items():
        total = v[1] - v[0]
        if v[2]:
            print(f"  {k:22} diff {v[2]:>8}/{total:<8} bytes")
        else:
            print(f"  {k:22} identical ({total} bytes)")
    if other[2]:
        print(f"  {'<gaps>':22} diff {other[2]} bytes")


def classify_diff_dwords(a, b):
    """For differing 4-byte dwords, bucket B's value by address range.

    Reveals whether the diffs are absolute pointers baked in at dump time
    (game image vs system-DLL range vs heap/stack) rather than relocatable code.
    """
    import struct
    da = open(a, "rb").read()
    db = open(b, "rb").read()
    n = min(len(da), len(db))
    GAME_LO, GAME_HI = 0x00400000, 0x0262E000  # this image
    buckets = {
        "game_image(0040-0262)": 0,
        "low(<0040)": 0,
        "0x10-0x3F(modules?)": 0,
        "0x40-0x6F": 0,
        "sysdll(0x70-0x7F)": 0,
        "high(>=0x80)": 0,
        "nonptr(small/odd)": 0,
    }
    samples = []
    i = 0
    while i + 4 <= n:
        if da[i:i+4] != db[i:i+4]:
            vb = struct.unpack("<I", db[i:i+4])[0]
            va = struct.unpack("<I", da[i:i+4])[0]
            if vb < 0x10000:
                buckets["nonptr(small/odd)"] += 1
            elif vb < 0x00400000:
                buckets["low(<0040)"] += 1
            elif GAME_LO <= vb < GAME_HI:
                buckets["game_image(0040-0262)"] += 1
            elif 0x10000000 <= vb < 0x40000000:
                buckets["0x10-0x3F(modules?)"] += 1
            elif 0x40000000 <= vb < 0x70000000:
                buckets["0x40-0x6F"] += 1
            elif 0x70000000 <= vb < 0x80000000:
                buckets["sysdll(0x70-0x7F)"] += 1
            else:
                buckets["high(>=0x80)"] += 1
            if len(samples) < 24:
                samples.append((i, va, vb))
            i += 4
        else:
            i += 1
    print("\n== DIFFERING DWORD CLASSIFICATION (value in B) ==")
    for k, v in buckets.items():
        print(f"  {k:24} {v}")
    print("\n  first differing dwords (fileoff: A -> B):")
    for off, va, vb in samples:
        print(f"    0x{off:08X}: 0x{va:08X} -> 0x{vb:08X}")


def count_callsites(path):
    """Count packer stub calls (90 E8 rel32) vs patched IAT calls (FF 15 abs32)."""
    data = open(path, "rb").read()
    pe = pefile.PE(path, fast_load=True)
    code = pe.sections[0]
    lo = code.PointerToRawData
    hi = lo + code.SizeOfRawData
    body = data[lo:hi]
    nop_e8 = body.count(b"\x90\xe8")
    ff15 = body.count(b"\xff\x15")
    print(f"  {path}")
    print(f"     90 E8 (packer stub call): {nop_e8}")
    print(f"     FF 15 (IAT indirect call): {ff15}")


def main():
    a, b = sys.argv[1], sys.argv[2]
    if "--count" in sys.argv:
        print("== CALL-SITE PATTERN COUNTS (code section) ==")
        count_callsites(a)
        count_callsites(b)
        return
    if "--bytes" in sys.argv:
        raw_section_diff(a, b)
        return
    if "--classify" in sys.argv:
        classify_diff_dwords(a, b)
        return
    pa, pb = load(a), load(b)
    print(f"A = {a}")
    print(f"B = {b}\n")

    print("== OPTIONAL/FILE HEADER ==")
    ha, hb = hdr(pa), hdr(pb)
    for k in ha:
        mark = "" if ha[k] == hb[k] else "   <<< DIFF"
        print(f"  {k:22} A=0x{ha[k]:08X}  B=0x{hb[k]:08X}{mark}")

    print("\n== DATA DIRECTORIES (rva,size) ==")
    da, db = dirs(pa), dirs(pb)
    for k in da:
        mark = "" if da[k] == db[k] else "   <<< DIFF"
        print(f"  {k:24} A={da[k][0]:08X}/{da[k][1]:06X}  "
              f"B={db[k][0]:08X}/{db[k][1]:06X}{mark}")

    print("\n== SECTIONS ==")
    sa, sb = sections(pa), sections(pb)
    for k in sorted(set(sa) | set(sb)):
        va = sa.get(k)
        vb = sb.get(k)
        mark = "" if va == vb else "   <<< DIFF"
        print(f"  {k:10} A={va}  B={vb}{mark}")

    print("\n== IMPORTS ==")
    ia, ib = imports(pa), imports(pb)
    dlls = sorted(set(ia) | set(ib))
    for dll in dlls:
        sa_ = ia.get(dll, set())
        sb_ = ib.get(dll, set())
        if sa_ == sb_:
            print(f"  {dll:18} same ({len(sa_)} syms)")
            continue
        print(f"  {dll:18} A={len(sa_)} B={len(sb_)}  <<< DIFF")
        only_a = sorted(sa_ - sb_)
        only_b = sorted(sb_ - sa_)
        if only_a:
            print(f"      only in A ({len(only_a)}): {only_a[:30]}")
        if only_b:
            print(f"      only in B ({len(only_b)}): {only_b[:30]}")


if __name__ == "__main__":
    main()
