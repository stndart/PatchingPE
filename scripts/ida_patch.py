import polars as pl

import ida_bytes  # type: ignore
import ida_kernwin  # type: ignore
import ida_nalt  # type: ignore
from pathlib import Path
from dotenv import load_dotenv
import os


def patch_bytes(patch_addr: str, mem_old: str, mem_new: str, verbose=False):
    """
    Replaces bytes at the given address in IDA memory if they match expected bytes.

    Args:
        patch_addr (str): Address in hex, e.g. "0x401000" or "401000".
        mem_old (str): Expected bytes in uppercase hex, e.g. "E9CA1E375D".
        mem_new (str): Replacement bytes in uppercase hex, same length as mem_old.
    """

    # Convert inputs
    ea = int(patch_addr, 16)
    old_bytes = bytes.fromhex(mem_old)
    new_bytes = bytes.fromhex(mem_new)
    size = len(old_bytes)

    # Read current memory
    current_bytes = ida_bytes.get_bytes(ea, size)
    if current_bytes is None:
        ida_kernwin.msg(f"[!] Failed to read memory at {patch_addr}\n")
        return False

    # Compare
    if current_bytes != old_bytes:
        if mem_new == current_bytes.hex().upper() and not verbose:
            return True

        ida_kernwin.msg(
            f"[!] Memory at {patch_addr} does not match expected old bytes.\n"
        )
        ida_kernwin.msg(f"    Expected: {mem_old}\n")
        ida_kernwin.msg(f"    Found:    {current_bytes.hex().upper()}\n")
        ida_kernwin.msg(f"    Wanted:   {mem_new}\n")
        return mem_new == current_bytes.hex().upper()

    # Patch
    for i in range(size):
        ida_bytes.patch_byte(ea + i, new_bytes[i])

    if verbose:
        ida_kernwin.msg(
            f"[+] Patched {size} bytes at {patch_addr}: {mem_old} → {mem_new}\n"
        )
    return True


def patch_batch(patch_table: pl.DataFrame, name: str, verbose: bool = False):
    counter = 0
    for patch_addr, mem_old, patch in patch_table.rows():
        if patch_bytes(patch_addr, mem_old, patch, verbose=verbose):  # pyright: ignore[reportPossiblyUnboundVariable]
            counter += 1

    print(f"Patched {counter}/{patch_table.shape[0]} {name}")


if "VERBOSE" not in locals() and "VERBOSE" not in globals():
    VERBOSE = False

load_dotenv(Path(__file__).parent.parent / ".env")

csv_base = Path(os.getenv("BASE_TO_DUMPS", "./")) / "patchingPE"
if ida_nalt.get_input_file_path().endswith(".dll"):
    csv_base /= "neomon-dump/patches"
elif ida_nalt.get_input_file_path().endswith(".exe"):
    csv_base /= "game-dump/patches"
else:
    raise RuntimeError("Uknown file extension!")

print(f"Loading patches from {csv_base}")

fn0 = csv_base / "calls_patch.csv"
try:
    calls_patch = pl.read_csv(fn0)
    patch_batch(calls_patch, "calls")
except FileNotFoundError:
    print(f"Not found calls_patch file at {csv_base}")


fn1 = csv_base / "thunks_patch.csv"
try:
    thunks_patch = pl.read_csv(fn1)
    patch_batch(thunks_patch, "thunks")
except FileNotFoundError:
    print(f"Not found thunks_patch file at {csv_base}")


fn2 = csv_base / "iat_patch.csv"
try:
    iat_patch = pl.read_csv(fn2)
    patch_batch(iat_patch, "iat entries")
except FileNotFoundError:
    print(f"Not found iat_patch file at {csv_base}")
