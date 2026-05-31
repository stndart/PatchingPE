"""PE VA/file-offset helpers for standalone extract and patch apply."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

import pefile

# Dead packer sections: preserve in image; exclude from byte diffs (post-reboot noise).
# Also stolen packer RVAs 0x1d9c000..0x2225ffff (VA 0x219c000..) — see compare_call_sites.py.
DEAD_SECTION_NAMES = frozenset({"wlovhtaq", "oemvvlbu"})
STOLEN_REGION_RVA_LO = 0x1D9C000
REAL_IDATA_RVA = 0x2226000

IAT_START = 0x1588000
IAT_END = 0x1588E6C
GAME_LO, GAME_HI = 0x00400000, 0x0262E000


def classify_ptr(v: int) -> str:
    if v < 0x10000:
        return "nonptr"
    if v < 0x00400000:
        return "low"
    if GAME_LO <= v < GAME_HI:
        return "game_image"
    if 0x10000000 <= v < 0x40000000:
        return "modules"
    if 0x40000000 <= v < 0x70000000:
        return "mid"
    if 0x70000000 <= v < 0x80000000:
        return "sysdll"
    return "high"


@dataclass
class SectionInfo:
    name: str
    index: int
    virtual_address: int
    virtual_size: int
    pointer_to_raw_data: int
    size_of_raw_data: int

    @property
    def virtual_end(self) -> int:
        return self.virtual_address + max(self.virtual_size, self.size_of_raw_data)


class PeImage:
    """Mutable PE backed by file bytes (for patch apply)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.data = bytearray(self.path.read_bytes())
        self.pe = pefile.PE(data=bytes(self.data), fast_load=False)
        self.imagebase = self.pe.OPTIONAL_HEADER.ImageBase
        self.sections = self._build_sections()

    def _build_sections(self) -> list[SectionInfo]:
        out: list[SectionInfo] = []
        for i, s in enumerate(self.pe.sections):
            name = s.Name.rstrip(b"\x00").decode("latin1", errors="replace")
            out.append(
                SectionInfo(
                    name=name,
                    index=i,
                    virtual_address=s.VirtualAddress,
                    virtual_size=s.Misc_VirtualSize,
                    pointer_to_raw_data=s.PointerToRawData,
                    size_of_raw_data=s.SizeOfRawData,
                )
            )
        return out

    def section_by_index(self, index: int) -> SectionInfo:
        return self.sections[index]

    def section_by_name(self, name: str) -> SectionInfo | None:
        low = name.lower()
        for s in self.sections:
            if s.name.lower() == low:
                return s
        return None

    def va_to_offset(self, va: int) -> int | None:
        rva = va - self.imagebase if va >= self.imagebase else va
        for sec in self.sections:
            size = max(sec.virtual_size, sec.size_of_raw_data)
            if sec.virtual_address <= rva < sec.virtual_address + size:
                off = rva - sec.virtual_address
                if off < sec.size_of_raw_data:
                    return sec.pointer_to_raw_data + off
        return None

    def offset_to_va(self, file_offset: int) -> int | None:
        for sec in self.sections:
            if sec.pointer_to_raw_data <= file_offset < sec.pointer_to_raw_data + sec.size_of_raw_data:
                rva = sec.virtual_address + (file_offset - sec.pointer_to_raw_data)
                return self.imagebase + rva
        return None

    def read_bytes_va(self, va: int, size: int) -> bytes | None:
        off = self.va_to_offset(va)
        if off is None or off + size > len(self.data):
            return None
        return bytes(self.data[off : off + size])

    def read_dword_va(self, va: int) -> int | None:
        b = self.read_bytes_va(va, 4)
        if b is None or len(b) < 4:
            return None
        return struct.unpack("<I", b)[0]

    def read_byte_va(self, va: int) -> int | None:
        b = self.read_bytes_va(va, 1)
        return b[0] if b else None

    def patch_bytes_va(
        self, va: int, mem_old: str, mem_new: str, *, verbose: bool = False
    ) -> bool:
        """Match ida_patch.py: verify mem_old then write mem_new at VA."""
        off = self.va_to_offset(va)
        if off is None:
            if verbose:
                print(f"[!] VA not mapped: {va:#x}")
            return False

        old_bytes = bytes.fromhex(mem_old)
        new_bytes = bytes.fromhex(mem_new)
        if len(old_bytes) != len(new_bytes):
            raise ValueError("mem_old and mem_new length mismatch")

        size = len(old_bytes)
        if off + size > len(self.data):
            if verbose:
                print(f"[!] Read past EOF at {va:#x}")
            return False

        current = bytes(self.data[off : off + size])
        if current == old_bytes:
            self.data[off : off + size] = new_bytes
            if verbose:
                print(f"[+] Patched {size} bytes at {va:#x}")
            return True

        if current.hex().upper() == mem_new.upper():
            return True

        if verbose:
            print(f"[!] Mismatch at {va:#x}")
            print(f"    Expected: {mem_old}")
            print(f"    Found:    {current.hex().upper()}")
            print(f"    Wanted:   {mem_new}")
        return current.hex().upper() == mem_new.upper()

    def section_raw_slice(self, sec: SectionInfo) -> memoryview:
        start = sec.pointer_to_raw_data
        end = start + sec.size_of_raw_data
        return memoryview(self.data)[start:end]

    def save(self, path: str | Path | None = None) -> Path:
        out = Path(path) if path else self.path
        out.write_bytes(self.data)
        return out

    def iter_sections_excluding_dead(self) -> list[SectionInfo]:
        return [s for s in self.sections if s.name.lower() not in DEAD_SECTION_NAMES]
