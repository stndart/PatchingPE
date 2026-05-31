#!/usr/bin/env python3
"""Build calls_patch.csv / thunks_patch.csv — scratch IAT Calladdr (FF15/FF25), notebook logic."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import polars as pl
from tqdm import tqdm

_REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO / "scripts" / "standalone"))
sys.path.insert(0, str(_REPO / "notebooks"))

from addr_helpers import int_to_LE, rel_call, to_bin  # noqa: E402
from dump_tables import load_dump_imports, load_iat_table  # noqa: E402
from pe_imports import STOLEN_CODE_VA_LO, STOLEN_CODE_VA_HI  # noqa: E402

IAT_BEGIN = 0x01588000
EXTRA_THUNK_CALL_ADDRS = {
    "0x14aaadb", "0x14aaad5", "0x14aa9f5", "0x14aa9fb", "0x14aab3d",
    "0x14ab35d", "0x14ab363", "0x14ab405", "0x14ab40b", "0x14ab767",
    "0x14ab76d", "0x14abc33", "0x14abc39", "0x14abe61", "0xcedcb1", "0xcedcf1",
}


def patch_call(
    addr: str, inst: str, dest: str, thunk_addr: str | None, iat_addr: str,
    call_exceptions: set[str],
) -> dict[str, str]:
    naddr = hex(int(addr, 16) + 6)
    oaddr = hex(int(addr, 16) + 6) if inst.endswith("2") else naddr
    dest_rbin = to_bin(rel_call(oaddr, dest))
    iat_bin = to_bin(int_to_LE(int(iat_addr, 16)))

    match inst:
        case "call" | "call2":
            mem_old, patch = "90E8" + dest_rbin, "FF15" + iat_bin
        case "jmp" | "jmp2":
            mem_old, patch = "90E9" + dest_rbin, "FF25" + iat_bin
        case _:
            raise RuntimeError(f"Unsupported instruction {inst}")

    if addr in call_exceptions:
        if not thunk_addr:
            raise RuntimeError(f"exception call {addr} needs thunk_addr")
        patch = "90E8" + to_bin(rel_call(naddr, thunk_addr))
    return {"patch_addr": addr, "mem_old": mem_old, "patch": patch}


def patch_thunk(addr: str, dest: str, iat_addr: str | None, new: bool, real: bool) -> dict[str, str]:
    patch_addr = hex(int(addr, 16) + int(new))
    naddr = hex(int(addr, 16) + 6)
    mem_old = "CC" * 6 if new else "90E9" + to_bin(rel_call(naddr, dest))
    if real and iat_addr:
        patch = "FF25" + to_bin(int_to_LE(int(iat_addr, 16)))
    else:
        patch = "90E9" + to_bin(rel_call(naddr, dest))
    return {"patch_addr": patch_addr, "mem_old": mem_old, "patch": patch}


def build_thunks(byte_calls: pl.DataFrame, dump_imports: pl.DataFrame, iat: pl.DataFrame) -> pl.DataFrame:
    valid = set(dump_imports["Address"].to_list())
    thunks = byte_calls.filter(pl.col("Instruction") == "jmp")
    thunks = thunks.with_columns(
        pl.col("Call address").str.slice(2).str.to_integer(base=16).alias("Int_addr")
    )
    thunks = thunks.filter(pl.col("Int_addr") < IAT_BEGIN).drop(
        "subroutine", "Instruction", "Resolved name"
    )
    thunks = thunks.filter(pl.col("Destination").is_in(valid))
    is_prev = pl.col("Int_addr").shift(1) + 6 == pl.col("Int_addr")
    is_next = pl.col("Int_addr").shift(-1) - 6 == pl.col("Int_addr")
    thunks = thunks.with_columns((is_next | is_prev).alias("is_thunk"))
    thunks = thunks.with_columns(
        pl.col("is_thunk") | pl.col("is_thunk").shift(1) | pl.col("is_thunk").shift(-1)
    )
    for a in EXTRA_THUNK_CALL_ADDRS:
        thunks = thunks.with_columns(
            pl.col("is_thunk") | (pl.col("Call address").str.to_lowercase() == a)
        )
    thunks = thunks.filter("is_thunk").drop("Int_addr")
    thunks = thunks.join(
        iat.select("Module", "Function", "Address"),
        left_on="Destination",
        right_on="Address",
        how="left",
    )
    to_thunk = iat
    thunks = thunks.join(
        to_thunk.select("Calladdr", "Address")
        .rename({"Calladdr": "iat_addr"})
        .unique("Address"),
        left_on="Destination",
        right_on="Address",
        how="left",
    )
    thunks = thunks.with_columns(pl.lit(False).alias("new"))
    rows = []
    for row in thunks.to_dicts():
        real = row.get("Module") is not None
        rows.append(
            patch_thunk(
                row["Call address"],
                row["Destination"],
                row.get("iat_addr"),
                row["new"],
                real,
            )
        )
    return pl.DataFrame(rows).sort("patch_addr") if rows else pl.DataFrame(
        schema={"patch_addr": pl.Utf8, "mem_old": pl.Utf8, "patch": pl.Utf8}
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dumps", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--game-export", type=Path, default=None)
    args = ap.parse_args()

    dump_imports = load_dump_imports(args.dumps, args.game_export)
    iat = load_iat_table(args.dumps, args.game_export)
    iat_join = iat.select(
        pl.col("Address").alias("Destination"),
        pl.col("Calladdr").alias("iat address"),
    ).unique("Destination")

    byte_calls = pl.read_csv(args.dumps / "broken-byte-calls.csv")
    inst_calls = args.dumps / "broken-analyzed-calls.csv"
    if inst_calls.is_file():
        extra = pl.read_csv(inst_calls)
        if extra.height > 1:
            byte_calls = pl.concat([byte_calls, extra])

    thunks_df = build_thunks(byte_calls, dump_imports, iat)

    calls = byte_calls.filter(pl.col("Instruction").is_in(["call", "call2", "jmp"]))
    calls = calls.with_columns(
        pl.col("Call address").str.slice(2).str.to_integer(base=16).alias("Int_addr")
    )
    calls = calls.filter(pl.col("Int_addr") < IAT_BEGIN)
    # drop thunk jmp sites (notebook uses thunk Call address list)
    thunks_raw = byte_calls.filter(pl.col("Instruction") == "jmp")
    thunks_raw = thunks_raw.with_columns(
        pl.col("Call address").str.slice(2).str.to_integer(base=16).alias("Int_addr")
    )
    thunks_raw = thunks_raw.filter(pl.col("Int_addr") < IAT_BEGIN)
    is_prev = pl.col("Int_addr").shift(1) + 6 == pl.col("Int_addr")
    is_next = pl.col("Int_addr").shift(-1) - 6 == pl.col("Int_addr")
    thunks_raw = thunks_raw.with_columns((is_next | is_prev).alias("is_thunk"))
    thunks_raw = thunks_raw.with_columns(
        pl.col("is_thunk") | pl.col("is_thunk").shift(1) | pl.col("is_thunk").shift(-1)
    )
    for a in EXTRA_THUNK_CALL_ADDRS:
        thunks_raw = thunks_raw.with_columns(
            pl.col("is_thunk") | (pl.col("Call address").str.to_lowercase() == a)
        )
    thunk_call_addrs = set(
        thunks_raw.filter("is_thunk")["Call address"].to_list()
    )
    calls = calls.filter(~pl.col("Call address").is_in(thunk_call_addrs))

    addrs = set(calls["Int_addr"].to_list())
    calls = calls.filter(~(pl.col("Int_addr") - 1).is_in(addrs)).drop("Int_addr")

    stolen_extra = byte_calls.filter(
        pl.col("Destination").str.slice(2).str.to_integer(base=16).is_between(
            STOLEN_CODE_VA_LO, STOLEN_CODE_VA_HI
        )
    )
    calls = pl.concat([calls, stolen_extra]).unique("Call address")

    valid_addresses = set(dump_imports["Address"].to_list())
    valid_addresses.add("0x23e3673")
    calls = calls.filter(pl.col("Destination").is_in(valid_addresses))

    thunks_to_join = (
        thunks_raw.filter("is_thunk")
        .select(pl.col("Destination"), pl.col("Call address").alias("thunk address"))
        .unique("Destination")
    )
    calls = calls.join(thunks_to_join, on="Destination", how="left")
    calls = calls.join(iat_join, on="Destination", how="left")

    call_exceptions = {"0x61fffa"}
    patch_rows = []
    missing = []
    for row in tqdm(calls.to_dicts(), desc="calls"):
        addr = row["Call address"]
        dest = row["Destination"]
        inst = row["Instruction"]
        iat_addr = row.get("iat address")
        thunk_addr = row.get("thunk address")
        if not iat_addr:
            missing.append(f"{addr} -> {dest}")
            continue
        patch_rows.append(
            patch_call(addr, inst, dest, thunk_addr, iat_addr, call_exceptions)
        )

    args.out.mkdir(parents=True, exist_ok=True)
    pl.DataFrame(patch_rows).sort("patch_addr").write_csv(args.out / "calls_patch.csv")
    thunks_df.write_csv(args.out / "thunks_patch.csv")
    print(f"[+] calls: {len(patch_rows)}, thunks: {thunks_df.height}")
    if missing:
        pl.DataFrame({"line": missing}).write_csv(args.out / "calls_patch_missing.csv")
        print(f"[!] {len(missing)} unmapped")
    return 0 if not missing else 2


if __name__ == "__main__":
    sys.exit(main())
