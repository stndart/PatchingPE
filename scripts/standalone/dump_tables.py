"""Load dump-imports + old-iat tables (matches notebooks/01-patch-v2.ipynb)."""

from __future__ import annotations

from pathlib import Path

import pefile
import polars as pl

SYSTEMROOT = "C:/Windows/System32/"
FORWARDING_MODULES = ["kernel32.dll", "user32.dll"]


def load_dump_imports(dumps_dir: Path, game_export: Path | None = None) -> pl.DataFrame:
    dump_imports_p = dumps_dir / "dump-imports.csv"
    module_imports_p = game_export or (dumps_dir.parent / "game.exe.export.full.csv")

    dump_imports = pl.read_csv(dump_imports_p)
    dump_imports.columns = [
        "Address",
        "Type",
        "Ordinal",
        "Symbol",
        "undecorated",
    ]
    dump_imports = dump_imports.with_columns(
        pl.when(pl.col("Type") == "Экспорт")
        .then(pl.lit("Export"))
        .otherwise(pl.lit("Import"))
        .alias("Type")
    )
    dump_imports = (
        dump_imports.filter(pl.col("Type") == "Export")
        .drop("Type", "undecorated")
        .rename({"Symbol": "Function"})
    )

    module_imports = pl.read_csv(module_imports_p).drop("Function")
    dump_imports = dump_imports.join(module_imports, on="Address")
    dump_imports = dump_imports.filter(pl.col("Module") != "game.exe")
    dump_imports = dump_imports.with_columns(
        ("0x" + pl.col("Address").str.to_lowercase()).alias("Address")
    )
    return dump_imports.unique("Address", keep="first").sort("Address")


def apply_ntdll_forward_fixup(iat: pl.DataFrame) -> pl.DataFrame:
    """Rewrite ntdll forwarders to kernel32/user32 (notebook step)."""
    unforward_map: dict[str, tuple[str, str]] = {}
    forwarded = iat.filter(pl.col("Module") == "ntdll.dll")

    for modname in FORWARDING_MODULES:
        dll = pefile.PE(SYSTEMROOT + modname)
        dll.full_load()
        for exp in dll.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode() if exp.name else f"Ordinal#{exp.ordinal}"
            if not exp.forwarder:
                continue
            forward_to = exp.forwarder.decode().removeprefix("NTDLL.")
            if forwarded.filter(pl.col("Function") == forward_to).height > 0:
                unforward_map[forward_to] = (modname, name)

    for func in iat.filter(pl.col("Module") == "ntdll.dll")["Function"]:
        if func not in unforward_map:
            continue
        origmod, origfunc = unforward_map[func]
        condition = (pl.col("Module") == "ntdll.dll") & (pl.col("Function") == func)
        iat = iat.with_columns(
            pl.when(condition).then(pl.lit(origmod)).otherwise(pl.col("Module")).alias("Module"),
            pl.when(condition).then(pl.lit(origfunc)).otherwise(pl.col("Function")).alias("Function"),
        )
    return iat


def inject_stolen_wsprintf(iat: pl.DataFrame, dump_imports: pl.DataFrame) -> pl.DataFrame:
    """Tag scratch slot 0x1588AB0 as user32!wsprintfA and point it at the real export."""
    ws = pl.col("Calladdr").str.slice(2).str.to_integer(base=16) == 0x1588AB0
    wsprintf = dump_imports.filter(
        (pl.col("Module") == "user32.dll") & (pl.col("Function") == "wsprintfA")
    )
    real_addr = wsprintf["Address"][0] if wsprintf.height else None
    iat = iat.with_columns(
        pl.when(ws).then(pl.lit("user32.dll")).otherwise(pl.col("Module")).alias("Module"),
        pl.when(ws).then(pl.lit("wsprintfA")).otherwise(pl.col("Function")).alias("Function"),
    )
    if real_addr:
        iat = iat.with_columns(
            pl.when(ws).then(pl.lit(real_addr)).otherwise(pl.col("Address")).alias("Address")
        )
    return iat


def load_iat_table(dumps_dir: Path, game_export: Path | None = None) -> pl.DataFrame:
    dump_imports = load_dump_imports(dumps_dir, game_export)
    iat = pl.read_csv(dumps_dir / "old-iat.csv")
    iat = iat.rename({"Address": "Calladdr", "Destination": "Address"})
    iat = iat.with_columns(("0x" + pl.col("Address").str.to_lowercase()).alias("Address"))
    iat = iat.join(dump_imports, on="Address", how="left")
    iat = inject_stolen_wsprintf(iat, dump_imports)  # before drop — keeps slot in user32 segment order
    iat = iat.filter(pl.col("Module").is_not_null())
    return apply_ntdll_forward_fixup(iat)


def load_iat_segments(dumps_dir: Path, game_export: Path | None = None) -> list[pl.DataFrame]:
    iat = load_iat_table(dumps_dir, game_export)
    iat_seg = (
        iat.sort("Calladdr")
        .fill_null("")
        .with_columns(
            (pl.col("Module") != pl.col("Module").shift(1)).cum_sum().alias("segment_id")
        )
        .fill_null(0)
        .filter(pl.col("Address").str.slice(2).str.to_integer(base=16) != 0)
        .filter(pl.col("Module") != "")
    )
    return [g.drop("segment_id") for _, g in iat_seg.group_by("segment_id", maintain_order=True)]
