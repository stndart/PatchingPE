import numpy as np
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


def to_int_expr(col: str = "Address") -> pl.Expr:
    return pl.col(col).str.slice(2).str.to_integer(base=16)


def addr_to_int(df: pl.DataFrame, col: str = "Address") -> pl.DataFrame:
    return df.with_columns(to_int_expr(col))


def int_to_addr(
    df: pl.DataFrame, col: str = "Address", sort: bool = False
) -> pl.DataFrame:
    arr = df[col].to_numpy()
    hex_arr = np.char.add("0x", np.char.lower(np.char.mod("%x", arr)))
    return normalize_address(
        df.with_columns(pl.Series(col, hex_arr)), col=col, sort=sort
    )


def normalize_address(
    df: pl.DataFrame, col: str = "Address", sort: bool = True
) -> pl.DataFrame:
    df = df.with_columns(
        (
            "0x"
            + pl.when(pl.col(col).str.starts_with("0x"))
            .then(pl.col(col).str.strip_prefix("0x"))
            .otherwise(col)
            .str.to_lowercase()
            .str.strip_chars_start("0")
        ).alias(col)
    ).with_columns(
        pl.when(pl.col(col) == "0x").then(pl.lit("0x0").alias(col)).otherwise(col)
    )
    if sort:
        return df.sort(to_int_expr(col))
    return df
