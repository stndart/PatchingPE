#!/usr/bin/env python3
"""Parse minidump exception + thread context + stack for crash analysis."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

EXCEPTION_MAXIMUM_PARAMETERS = 15


def read_at(path: Path, rva: int, size: int) -> bytes:
    with path.open("rb") as f:
        f.seek(rva)
        return f.read(size)


def load_streams(path: Path) -> list[tuple[int, int, int]]:
    with path.open("rb") as f:
        sig = f.read(4)
        if sig != b"MDMP":
            raise SystemExit(f"not a minidump: {sig!r}")
        ver, nstreams, dir_rva, _csum, _tds, _flags = struct.unpack("<IIIIIQ", f.read(28))
    streams: list[tuple[int, int, int]] = []
    with path.open("rb") as f:
        f.seek(dir_rva)
        for _ in range(nstreams):
            streams.append(struct.unpack("<III", f.read(12)))
    return streams


def parse_exception(path: Path, streams: list[tuple[int, int, int]]) -> dict:
    stype, size, rva = next(s for s in streams if s[0] == 6)
    data = read_at(path, rva, size)
    thread_id, _align = struct.unpack_from("<II", data, 0)
    off = 8
    exc_code, exc_flags, exc_rec, exc_addr, nparams, _align2 = struct.unpack_from(
        "<IIQIQI", data, off
    )
    params = struct.unpack_from("<" + "Q" * nparams, data, off + 32)
    ctx_size, ctx_rva = struct.unpack_from("<II", data, off + 152)
    ctx = read_at(path, ctx_rva, ctx_size)
    # i386 CONTEXT (WinNT.h): Eip=0xB8, Esp=0xC4, Ebp=0x9C
    eip, = struct.unpack_from("<I", ctx, 0xB8)
    esp, = struct.unpack_from("<I", ctx, 0xC4)
    ebp, = struct.unpack_from("<I", ctx, 0x9C)
    return {
        "thread_id": thread_id,
        "exception_code": exc_code,
        "exception_address": exc_addr,
        "parameters": params,
        "eip": eip,
        "esp": esp,
        "ebp": ebp,
        "context_size": ctx_size,
    }


def memory_ranges(path: Path, streams: list[tuple[int, int, int]]) -> list[tuple[int, int, int]]:
    """MINIDUMP_MEMORY_LIST: (start, size, rva)."""
    stype, size, rva = next(s for s in streams if s[0] == 5)
    data = read_at(path, rva, size)
    num, = struct.unpack_from("<I", data, 0)
    out: list[tuple[int, int, int]] = []
    off = 4
    for _ in range(num):
        start, sz, mrva = struct.unpack_from("<QII", data, off)
        out.append((start, sz, mrva))
        off += 16
    return out


def read_va(ranges: list[tuple[int, int, int]], path: Path, va: int, nbytes: int) -> bytes | None:
    for start, sz, rva in ranges:
        if start <= va < start + sz:
            chunk = read_at(path, rva + (va - start), nbytes)
            return chunk
    return None


def find_dword(path: Path, ranges: list[tuple[int, int, int]], value: int, limit: int = 50) -> list[int]:
    needle = struct.pack("<I", value)
    hits: list[int] = []
    for start, sz, rva in ranges:
        blob = read_at(path, rva, sz)
        i = 0
        while len(hits) < limit:
            j = blob.find(needle, i)
            if j < 0:
                break
            hits.append(start + j)
            i = j + 1
    return hits


def main() -> None:
    path = Path(
        sys.argv[1]
        if len(sys.argv) > 1
        else r"G:\Games\FA\FA-EMU\Shipping\TheGame_crash_38420_35632.dmp"
    )
    streams = load_streams(path)
    ex = parse_exception(path, streams)
    print("=== exception ===")
    for k, v in ex.items():
        if k == "parameters":
            print(k, [hex(p) for p in v])
        elif isinstance(v, int) and k not in ("thread_id", "context_size"):
            print(k, hex(v))
        else:
            print(k, v)

    ranges = memory_ranges(path, streams)
    print(f"\n=== memory ranges: {len(ranges)} ===")

    esp = ex["esp"]
    stack_raw = read_va(ranges, path, esp, 64 * 4)
    if stack_raw:
        words = struct.unpack("<" + "I" * (len(stack_raw) // 4), stack_raw)
        print(f"\nstack @ {esp:#x}:")
        for i, w in enumerate(words[:32]):
            tag = ""
            if 0x400000 <= w < 0x2800000:
                tag = " GAME?"
            elif 0x5F000000 <= w < 0x60000000:
                tag = " TheGame?"
            elif 0x70000000 <= w < 0x78000000:
                tag = " system DLL"
            print(f"  +{i*4:3}: {w:#010x}{tag}")

    tgt = ex["exception_address"]
    refs = find_dword(path, ranges, tgt)
    print(f"\n=== dword refs to {tgt:#x}: {len(refs)} ===")
    for va in refs[:40]:
        seg = ""
        if 0x400000 <= va < 0x2800000:
            seg = " GAME"
        elif 0x5F000000 <= va < 0x60000000:
            seg = " TheGame"
        print(f"  {va:#x}{seg}")


if __name__ == "__main__":
    main()
