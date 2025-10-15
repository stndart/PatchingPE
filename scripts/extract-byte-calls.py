import idautils  # type: ignore
import idc  # type: ignore
import ida_bytes  # type: ignore
import ctypes
import csv


out_path = r"C:\Users\Svyat\Desktop\RE\PatchingPE\broken-byte-calls.csv"

f = open(out_path, "w", newline="")
writer = csv.writer(f)
writer.writerow(
    ["function", "Instruction", "Call address", "Destination", "Resolved name"]
)

# --- CONFIG ---
PATTERNS = [
    "90 e8 ? ? ? ?",  # NOP + CALL
    "e8 ? ? ? ? 90",  # CALL + NOP
    "e9 ? ? ? ?",  # JMP
]

start, end = list(idautils.Segments())[:2]


def check_in_bounds(addr: int):
    if addr < 0x6D40000:
        return False  # main part
    if 0x6D40000 <= addr <= 0x6D41000:
        return True  # xinput
    if 0x10000000 <= addr <= 0x1000B000:
        return True  # physxloader
    if 0x5DD00000 <= addr <= 0x77000000:
        return True  # the rest
    return False


def call_target_from_pattern(ea, pattern: str):
    if pattern.startswith("90"):
        call_ea = ea + 1
    elif pattern.startswith(("e8", "e9")):
        call_ea = ea
    else:
        raise ValueError("pattern_type must be '90e8' or 'e890'")

    # verify opcode is really 0xE8
    opcode = ida_bytes.get_byte(call_ea)
    if opcode != 0xE8 and opcode != 0xE9:
        raise RuntimeError("No E8 opcode at expected location: 0x{:X}".format(call_ea))

    # read 4-byte little-endian displacement
    disp_u32 = ida_bytes.get_dword(call_ea + 1)  # unsigned 32-bit
    # sign-extend to signed 32-bit
    disp_signed = ctypes.c_int32(disp_u32).value

    # next instruction address = address immediately after CALL (5 bytes total)
    next_insn = call_ea + 5
    return call_ea, next_insn + disp_signed


# --- MAIN ---
print(f"[*] Searching in section [{hex(start)} - {hex(end)}]")

for pattern in PATTERNS:
    print(f"[*] Searching for pattern: {pattern}")
    ea = start
    count = 0

    while True:
        ea = idc.find_bytes(pattern, range_start=ea, range_end=end)
        if ea == idc.BADADDR or ea >= end:
            break

        call_ea, target = call_target_from_pattern(ea, pattern)

        if check_in_bounds(target):
            count += 1

            if idc.is_loaded(target):
                name = idc.get_name(target)
            else:
                name = ""

            if pattern.startswith("e9"):
                instr = "jmp"
            else:
                instr = "call"
            writer.writerow(["-", instr, hex(call_ea), hex(target), name])

        ea += 1  # move forward to avoid infinite loop

    print(f"  Total matches for '{pattern}': {count}")

f.close()
print("Done")
print(f"Done. Saved to {out_path}")
