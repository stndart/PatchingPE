import polars as pl

import ida_bytes
import ida_kernwin

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
        if patch == current_bytes.hex().upper() and not verbose:
            return True
        
        ida_kernwin.msg(f"[!] Memory at {patch_addr} does not match expected old bytes.\n")
        ida_kernwin.msg(f"    Expected: {mem_old}\n")
        ida_kernwin.msg(f"    Found:    {current_bytes.hex().upper()}\n")
        ida_kernwin.msg(f"    Wanted:   {patch}\n")
        return patch == current_bytes.hex().upper()

    # Patch
    for i in range(size):
        ida_bytes.patch_byte(ea + i, new_bytes[i])

    if verbose:
        ida_kernwin.msg(f"[+] Patched {size} bytes at {patch_addr}: {mem_old} → {mem_new}\n")
    return True

base = "C:/Users/Svyat/Desktop/RE/PatchingPE/game-dump/"
fn0 = base + "calls_patch.csv"
calls_patch = pl.read_csv(fn0)

counter = 0
for patch_addr, mem_old, patch in calls_patch.rows():
    if 'VERBOSE' not in locals() and 'VERBOSE' not in globals():
        VERBOSE = False
    
    if patch_bytes(patch_addr, mem_old, patch, verbose=VERBOSE):
        counter += 1

print(f'Patched {counter}/{calls_patch.shape[0]} calls')



fn1 = base + "thunks_patch.csv"
thunks_patch = pl.read_csv(fn1)

counter = 0
for patch_addr, mem_old, patch in thunks_patch.rows():
    if patch_bytes(patch_addr, mem_old, patch):
        counter += 1

print(f'Patched {counter}/{thunks_patch.shape[0]} thunks')



fn2 = base + "old_iat_patch.csv"
iat_patch = pl.read_csv(fn2)

counter = 0
for patch_addr, mem_old, patch in iat_patch.rows():
    if patch_bytes(patch_addr, mem_old, patch):
        counter += 1

print(f'Patched {counter}/{iat_patch.shape[0]} old iat entries')