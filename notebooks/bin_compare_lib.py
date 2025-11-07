from pathlib import Path
from typing import Optional
import hashlib
import lief
import polars as pl


def parse(path: str | Path) -> lief.PE.Binary:
    "Return lief parsed binary or raise."
    b = lief.PE.parse(str(path))
    if b is None:
        raise ValueError(f"lief.parse returned None for {path}")
    return b


def _section_bytes(binobj: lief.PE.Binary, idx: int) -> Optional[bytes]:
    "Return section bytes for 0-based idx or None."
    secs = getattr(binobj, "sections", None)
    if not secs or idx < 0 or idx >= len(secs):
        return None
    sec = secs[idx]
    if hasattr(sec, "content"):
        c = sec.content
        return bytes(c) if not isinstance(c, (bytes, bytearray)) else bytes(c)
    if hasattr(sec, "get_content"):
        return bytes(sec.get_content())
    return None


def _sname(binobj: lief.PE.Binary, idx: int) -> Optional[str]:
    "Return section name for 0-based idx or None."
    secs = getattr(binobj, "sections", None)
    if not secs or idx < 0 or idx >= len(secs):
        return None
    return getattr(secs[idx], "name", None)


def _short_hash(data: Optional[bytes]) -> Optional[str]:
    "Return small blake2b hex digest or None."
    if data is None:
        return None
    h = hashlib.blake2b(digest_size=12)
    h.update(data)
    return h.hexdigest()


def _count_diff(a: bytes, b: bytes, chunk: int = 1 << 16) -> int:
    "Return number of differing bytes between a and b."
    la, lb = len(a), len(b)
    mv_a, mv_b = memoryview(a), memoryview(b)
    diffs = 0
    m = la if la < lb else lb
    for i in range(0, m, chunk):
        ca, cb = mv_a[i : i + chunk], mv_b[i : i + chunk]
        diffs += sum(1 for x, y in zip(ca, cb) if x != y)
    diffs += abs(la - lb)
    return diffs


def _to_be_hex(b: bytes) -> str:
    "Return reversed-order hex string like '10 81'."
    return "".join(f"{x:02x}" for x in reversed(b))


def _get_diff(a: bytes, b: bytes, gap: int = 2) -> pl.DataFrame:
    """build list of differing blocks and a polars DataFrame of them (merge if gap < 2)."""
    la, lb = len(a), len(b)
    min_len = min(la, lb)

    raw_blocks = []
    i = 0
    while i < min_len:
        if a[i] == b[i]:
            i += 1
            continue
        s = i
        i += 1
        while i < min_len and a[i] != b[i]:
            i += 1
        raw_blocks.append((s, i))

    if la != lb:
        raw_blocks.append((min_len, max(la, lb)))

    merged = []
    for s, e in raw_blocks:
        if not merged:
            merged.append([s, e])
        else:
            prev = merged[-1]
            ngap = s - prev[1]
            if ngap < gap:  # merge if less than gap
                prev[1] = e
            else:
                merged.append([s, e])

    block_rows = []
    for s, e in merged:
        b1 = _to_be_hex(a[s:e]) if s < la else b""
        b2 = _to_be_hex(b[s:e]) if s < lb else b""
        block_rows.append({"start": s, "bytes1": b1, "bytes2": b2})

    blocks_df = pl.DataFrame(block_rows)
    return blocks_df


def bin_compare(
    csvfilename: str | Path,
    file1: str | Path,
    file2: str | Path,
    sections_1: list[int],
    sections_2: Optional[list[int]] = None,
) -> tuple[pl.DataFrame, list[pl.DataFrame]]:
    """
    Compare selected sections of two binaries and write CSV; returns polars DataFrame.
    sections_* are 1-based indices; sections_2=None -> use sections_1 for both.
    """
    csvfilename = str(csvfilename).removesuffix(".csv")

    b1 = parse(file1)
    b2 = parse(file2)
    if sections_2 is None:
        sections_2 = sections_1

    pairs = list(zip(sections_1, sections_2))
    rows = []
    section_diffs: list[pl.DataFrame] = []
    for idx1, idx2 in pairs:
        a = _section_bytes(b1, idx1)
        b = _section_bytes(b2, idx2)
        name_a = _sname(b1, idx1)
        name_b = _sname(b2, idx2)
        sa = len(a) if a is not None else None
        sb = len(b) if b is not None else None
        ha = _short_hash(a)
        hb = _short_hash(b)

        to_add = {
            "file1_section": idx1,
            "file2_section": idx2,
            "file1_sec_name": name_a,
            "file2_sec_name": name_b,
            "file1_size": sa,
            "file2_size": sb,
            "file1_hash": ha,
            "file2_hash": hb,
            "bytes_different": None,
            "pct_different": None,
            "status": None,
        }
        diff_df = pl.DataFrame(schema={"start": int, "bytes1": bytes, "bytes2": bytes})

        if a is None or b is None:
            to_add["status"] = "missing_section_in_" + (
                "file1" if a is None else "file2"
            )
        elif ha == hb:
            to_add["status"] = "identical"
            to_add["bytes_different"] = 0
            to_add["pct_different"] = 0.0
        else:
            diff_df = _get_diff(a, b)

            dif = _count_diff(a, b)
            denom = max(sa or 0, sb or 1)
            pct = (dif / denom) * 100.0 if denom > 0 else None

            to_add["bytes_different"] = dif
            to_add["pct_different"] = round(pct, 2) if pct is not None else None
            to_add["status"] = "different"

        rows.append(to_add)
        section_diffs.append(diff_df)

    df = pl.DataFrame(rows)
    # reorder columns if present
    cols = [
        "file1_section",
        "file2_section",
        "file1_sec_name",
        "file2_sec_name",
        "file1_size",
        "file2_size",
        "file1_hash",
        "file2_hash",
        "bytes_different",
        "pct_different",
        "status",
    ]
    present = [c for c in cols if c in df.columns]
    df = df.select(present)
    df.write_csv(csvfilename + "_stats.csv")
    for i, df in enumerate(section_diffs):
        df.write_csv(csvfilename + f"_{i}.csv")
    return df, section_diffs
