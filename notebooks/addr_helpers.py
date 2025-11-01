import polars as pl


def int_to_BE(num: int) -> bytearray:
    """Convert int32 to Big Endian bytearray[4]."""
    # Convert to 32-bit two's complement
    num_32bit = num & 0xFFFFFFFF
    # Format as 8-character hex string without '0x' prefix
    hex_str = format(num_32bit, "08x")
    return bytearray.fromhex(hex_str)


def int_to_LE(num: int) -> bytearray:
    """Convert int32 to Little Endian bytearray[4]."""
    BE = int_to_BE(num)
    BE.reverse()
    return BE


def rel_call(src: str, dst: str) -> bytearray:
    """Get rel32 LE addr from hex source and dest addresses."""
    rel = int(dst, base=16) - int(src, base=16)
    return int_to_LE(rel)


def create_jumpcall(thunks: pl.DataFrame, src: str, dst: str) -> bytearray:
    thunk_search = thunks.filter(pl.col("Destination") == dst)["Call address"]
    if thunk_search.shape[0] < 1:
        raise RuntimeError(f"Failed to find thunk for src:{src}, dst:{dst}")

    thunk_addr = int(thunk_search[0][2:], 16) - 1
    return rel_call(src, hex(thunk_addr))


def to_bin(bt: bytearray) -> str:
    """Convert LE bytearray[4] to str repr."""
    LE = b"\x00" * (4 - len(bt)) + bt
    s = ""
    for c in LE:
        c = hex(c)[2:]
        c = "0" * (2 - len(c)) + c
        s += c
    return s.upper()


def from_bin(binary: str) -> int:
    """Convert str repr to LE bytearray[4]."""
    return int.from_bytes(bytes.fromhex(binary)[::-1])
