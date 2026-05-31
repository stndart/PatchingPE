"""PE import directory helpers — map (dll, name) to IAT slot VA."""

from __future__ import annotations

from pathlib import Path

import pefile

# Scratch IAT from packer (do not use for FF15 after fix).
SCRATCH_IAT_LO = 0x1588000
SCRATCH_IAT_HI = 0x1588E6C

# Stolen packer blob (wsprintfA copy lives around 0x23e3673).
STOLEN_CODE_VA_LO = 0x219D000
STOLEN_CODE_VA_HI = 0x243D000


def check_in_bounds_game(addr: int) -> bool:
    """Valid packer-stub target VAs for GAME.exe extract (not plain in-image calls)."""
    if STOLEN_CODE_VA_LO <= addr <= STOLEN_CODE_VA_HI:
        return True  # reclaimed packer code (e.g. wsprintfA at 0x23e3673)
    if addr < 0x6D40000:
        return False  # in-image game VA (internal call/jmp — not a DLL stub)
    if 0x6D40000 <= addr <= 0x6D41000:
        return True  # xinput
    if 0x10000000 <= addr < 0x5DD00000:
        return True  # modules + packer stubs (e.g. NeoMon 0x1080xxxx)
    if 0x5DD00000 <= addr:
        return True  # high DLL range
    return False


def pe_import_slot_map(path: str | Path) -> dict[tuple[str, str], int]:
    """(dll_lower, function_or_Ordinal#n) -> absolute VA of IAT slot."""
    pe = pefile.PE(str(path))
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    base = pe.OPTIONAL_HEADER.ImageBase
    out: dict[tuple[str, str], int] = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return out
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = (entry.dll or b"").decode("latin1", errors="replace").lower()
        for imp in entry.imports:
            if imp.name:
                key = (dll, imp.name.decode("latin1", errors="replace"))
            elif imp.ordinal is not None:
                key = (dll, f"Ordinal#{imp.ordinal}")
            else:
                continue
            # imp.address is RVA of this IAT thunk slot in the loaded image layout
            out[key] = base + imp.address
    return out


def resolve_iat_va(
    slot_map: dict[tuple[str, str], int],
    module: str | None,
    function: str | None,
) -> int | None:
    if not module or not function:
        return None
    return slot_map.get((module.lower(), function))


# Packer stole user32.wsprintfA into 0x219*; scratch slot has no import row.
STOLEN_API_OVERRIDES: dict[int, tuple[str, str]] = {
    0x023E3673: ("user32.dll", "wsprintfA"),
}
SCRATCH_SLOT_OVERRIDES: dict[int, tuple[str, str]] = {
    0x01588AB0: ("user32.dll", "wsprintfA"),
}
