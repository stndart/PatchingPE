import csv
import ctypes
import os
from pathlib import Path

import ida_bytes  # type: ignore
import ida_nalt  # type: ignore
import ida_segment  # type: ignore
import idautils  # type: ignore
import idc  # type: ignore
from dotenv import load_dotenv


def check_in_bounds_game(addr: int):
    if addr < 0x6D40000:
        return False  # main part
    if 0x6D40000 <= addr <= 0x6D41000:
        return True  # xinput
    if 0x10000000 <= addr <= 0x1000B000:
        return True  # physxloader
    if 0x5DD00000 <= addr <= 0x77300000:
        return True  # the rest
    return False


def check_in_bounds_neomon(addr: int):
    if 0x02000000 <= addr <= 0x02300000:
        return True  # fake neomon section
    if 0x10016000 <= addr <= 0x10016230:
        return True  # neomon iat
    if 0x10000000 <= addr <= 0x10500000:
        return False  # neomon main section (excluded iat)
    # these two are not needed really, since neomon.dll doesn't have any <direct call> obfuscations
    if 0x60000000 <= addr <= 0x69A00000:
        return True  # the rest dlls 1st pt
    if 0x70000000 <= addr <= 0x78000000:
        return True  # the rest dlls 2nd pt
    return False


load_dotenv(Path(__file__).parent.parent / ".env")

base_dumps = Path(os.getenv("BASE_TO_DUMPS", "./")) / "patchingPE"


if ida_nalt.get_input_file_path().endswith(".dll"):
    check_in_bounds = check_in_bounds_neomon
    out_path = base_dumps / "neomon-dump/dumps/broken-byte-calls.csv"
elif ida_nalt.get_input_file_path().endswith(".exe"):
    check_in_bounds = check_in_bounds_game
    out_path = base_dumps / "game-dump/dumps/broken-byte-calls.csv"
else:
    raise RuntimeError("Uknown file extension!")

f = open(out_path, "w", newline="")
writer = csv.writer(f)
writer.writerow(
    ["subroutine", "Instruction", "Call address", "Destination", "Resolved name"]
)

# --- CONFIG ---
PATTERNS = [
    ("90 e8 ? ? ? ?", "call"),  # NOP + CALL
    ("e8 ? ? ? ? 90", "call2"),  # CALL + NOP
    ("90 e9 ? ? ? ?", "jmp"),  # NOP + JMP
    ("e9 ? ? ? ? 90", "jmp2"),  # JMP + NOP
    ("e9 ? ? ? ?", "jmp-near"),  # JMP
]

if ida_nalt.get_input_file_path().endswith(".dll"):
    # Neomon.dll has fake section, which may have direct calls
    PATTERNS += [
        ("e8 ? ? ? ?", "call-near"),
        ("ff 25 ? ? ? ?", "jmp-far"),
        ("ff 15 ? ? ? ?", "call-far"),
    ]

segments_to_search = [0, 1]
segs = list(idautils.Segments())
if ida_nalt.get_input_file_path().endswith(".dll"):
    segments_to_search += [2]
    for i in range(3, len(segs)):
        start_ea = ida_segment.getnseg(i).start_ea
        name = idc.get_segm_name(start_ea)
        if "fake" in name:
            segments_to_search.append(i)
print(segments_to_search)

sea = [ida_segment.getnseg(i).start_ea for i in segments_to_search]
eea = [ida_segment.getnseg(i).end_ea for i in segments_to_search]


def call_target_from_pattern(ea: int, pattern: str) -> int:
    if pattern.startswith(("ff 25", "ff 15")):  # straight jmp / call
        disp_u32 = ida_bytes.get_dword(ea + 2)  # unsigned 32-bit
        return ctypes.c_int32(disp_u32).value

    elif pattern.startswith("90"):
        call_ea = ea + 1
    elif pattern.startswith(("e8", "e9")):
        call_ea = ea
    else:
        raise ValueError("pattern_type must be '90e8', 'e890', 'ff25' or 'ff15'")

    # verify opcode is really 0xE8
    opcode = ida_bytes.get_byte(call_ea)
    if opcode != 0xE8 and opcode != 0xE9:
        raise RuntimeError(
            "No E8/E9 opcode at expected location: 0x{:X}".format(call_ea)
        )

    # read 4-byte little-endian displacement
    disp_u32 = ida_bytes.get_dword(call_ea + 1)  # unsigned 32-bit
    # sign-extend to signed 32-bit
    disp_signed = ctypes.c_int32(disp_u32).value

    # next instruction address = address immediately after CALL (5 bytes total)
    next_insn = call_ea + 5
    return next_insn + disp_signed


print(f"[*] Searching in sections {segments_to_search}")

for pattern, inst in PATTERNS:
    print(f"[*] Searching for pattern: {pattern} ({inst})")
    count = 0

    i_seg = 0
    start, end = sea[0], eea[0]
    ea = sea[0]
    while True:
        ea = idc.find_bytes(pattern, range_start=ea, range_end=end)
        if ea == idc.BADADDR or ea >= end:
            i_seg += 1
            if i_seg >= len(sea):
                break
            start, end = sea[i_seg], eea[i_seg]
            print(hex(start), hex(end), count)
            continue

        target = call_target_from_pattern(ea, pattern)
        if check_in_bounds(target):
            if idc.is_loaded(target):
                name = idc.get_name(target)
            else:
                name = ""

            writer.writerow(["-", inst, hex(ea), hex(target), name])
            count += 1

        ea += 1  # move forward to avoid infinite loop

    print(f"  Total matches for '{pattern}': {count}")

f.close()
print("Done")
print(f"Done. Saved to {out_path}")
