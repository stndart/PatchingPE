import polars as pl


def hex_to_BE(num: int) -> bytearray:
    # Convert to 32-bit two's complement
    num_32bit = num & 0xFFFFFFFF
    # Format as 8-character hex string without '0x' prefix
    hex_str = format(num_32bit, "08x")
    return bytearray.fromhex(hex_str)


def hex_to_LE(num: int) -> bytearray:
    BE = hex_to_BE(num)
    BE.reverse()
    return BE


def rel_call(src: str, dst: str) -> bytearray:
    rel = int(dst, base=16) - int(src, base=16)
    return hex_to_LE(rel)


def create_jumpcall(thunks: pl.DataFrame, src: str, dst: str) -> bytearray:
    thunk_search = thunks.filter(pl.col("Destination") == dst)["Call address"]
    if thunk_search.shape[0] < 1:
        raise RuntimeError(f"Failed to find thunk for src:{src}, dst:{dst}")

    thunk_addr = int(thunk_search[0][2:], 16) - 1
    return rel_call(src, hex(thunk_addr))


def to_bin(bt: bytearray) -> str:
    LE = b"\x00" * (4 - len(bt)) + bt
    s = ""
    for c in LE:
        c = hex(c)[2:]
        c = "0" * (2 - len(c)) + c
        s += c
    return s.upper()


def from_bin(binary: str) -> int:
    return int.from_bytes(bytes.fromhex(binary)[::-1])
