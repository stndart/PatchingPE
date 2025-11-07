#!/usr/bin/env python3
"""
binary_section_diff.py

Compare specified sections (by index) of binaries using LIEF and export results to CSV via polars.

Usage examples:
  # Compare two files (default sections 1 and 4)
  python binary_section_diff.py --reference ref.bin --targets target.bin --out results.csv

  # Compare a reference against all files in a directory (non-recursive)
  python binary_section_diff.py --reference ref.bin --targets-dir ./bins --sections 1,4 --out comparisons.csv

  # Compare multiple explicit targets
  python binary_section_diff.py --reference ref.bin --targets file1 file2 file3 --sections 1,4 --workers 6
"""

import argparse
import hashlib
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional

import lief
import polars as pl

# --------------------
# Utility functions
# --------------------


def parse_binary(path: str):
    """Parse binary with lief; return the lief binary object or raise."""
    return lief.parse(path)


def get_section_by_index(binobj, index: int) -> Optional[bytes]:
    """
    Get section content by 0-based index from a lief binary object.
    Returns bytes (may be empty) or None if index out of range.
    """
    sections = getattr(binobj, "sections", None)
    if not sections:
        return None
    if index < 0 or index >= len(sections):
        return None
    sec = sections[index]
    # LIEF sections expose content as list of ints or as .content (depends on format).
    # Many LIEF versions expose section.content as list[int]
    content = None
    if hasattr(sec, "content"):
        c = sec.content
        if isinstance(c, (bytes, bytearray)):
            content = bytes(c)
        else:
            # assume iterable of ints
            content = bytes(c)
    elif hasattr(sec, "get_content"):
        c = sec.get_content()
        content = bytes(c)
    else:
        # fallback: try to export whole binary and slice by virtual address/size (less robust)
        try:
            content = sec.virtual_size.to_bytes(0, "little")
        except Exception:
            content = None
    return content


def short_hash(data: bytes) -> str:
    """Return a short BLAKE2b-based hex digest for content (fast and small)."""
    if data is None:
        return ""
    h = hashlib.blake2b(digest_size=12)
    h.update(data)
    return h.hexdigest()


def count_different_bytes(a: bytes, b: bytes, chunk_size: int = 65536) -> int:
    """
    Count how many bytes differ between a and b.
    Strategy:
      - iterate in chunks and count differing bytes using Python loops.
      - add length difference for tail.
    This is memory-friendly and fast enough for typical section sizes.
    """
    if a is None or b is None:
        return -1  # sentinel for missing
    la, lb = len(a), len(b)
    min_len = la if la < lb else lb
    diffs = 0
    mv_a = memoryview(a)
    mv_b = memoryview(b)
    for i in range(0, min_len, chunk_size):
        ca = mv_a[i : i + chunk_size]
        cb = mv_b[i : i + chunk_size]
        # per-chunk byte comparison
        # sum of generator comprehension is okay here
        diffs += sum(1 for x, y in zip(ca, cb) if x != y)
    # account for extra bytes in the longer section
    diffs += abs(la - lb)
    return diffs


# --------------------
# Core compare logic
# --------------------


def compare_sections_between_files(
    ref_path: str,
    tgt_path: str,
    section_indices: List[int],
    chunk_size: int = 65536,
) -> List[Dict]:
    """
    Compare specified section indices (0-based) between reference and target file.
    Returns a list of result dicts (one per section).
    """
    results = []
    try:
        ref_bin = parse_binary(ref_path)
    except Exception as e:
        raise RuntimeError(f"Failed to parse reference '{ref_path}': {e}")

    try:
        tgt_bin = parse_binary(tgt_path)
    except Exception as e:
        # record error for each requested section
        for idx in section_indices:
            results.append(
                {
                    "reference_file": ref_path,
                    "target_file": tgt_path,
                    "section_index": idx + 1,
                    "ref_section_name": None,
                    "tgt_section_name": None,
                    "ref_size": None,
                    "tgt_size": None,
                    "ref_hash": None,
                    "tgt_hash": None,
                    "bytes_different": None,
                    "pct_different": None,
                    "status": f"failed_to_parse_target: {e}",
                }
            )
        return results

    for idx in section_indices:
        ref_content = get_section_by_index(ref_bin, idx)
        tgt_content = get_section_by_index(tgt_bin, idx)

        # section name extraction if available
        def section_name(binobj, index):
            secs = getattr(binobj, "sections", None)
            if not secs or index < 0 or index >= len(secs):
                return None
            sec = secs[index]
            return getattr(sec, "name", None)

        ref_name = section_name(ref_bin, idx)
        tgt_name = section_name(tgt_bin, idx)

        ref_size = len(ref_content) if ref_content is not None else None
        tgt_size = len(tgt_content) if tgt_content is not None else None

        if ref_content is None or tgt_content is None:
            status = "missing_section_in_" + (
                "reference" if ref_content is None else "target"
            )
            results.append(
                {
                    "reference_file": ref_path,
                    "target_file": tgt_path,
                    "section_index": idx + 1,
                    "ref_section_name": ref_name,
                    "tgt_section_name": tgt_name,
                    "ref_size": ref_size,
                    "tgt_size": tgt_size,
                    "ref_hash": short_hash(ref_content)
                    if ref_content is not None
                    else None,
                    "tgt_hash": short_hash(tgt_content)
                    if tgt_content is not None
                    else None,
                    "bytes_different": None,
                    "pct_different": None,
                    "status": status,
                }
            )
            continue

        # quick equality check via hash
        ref_h = short_hash(ref_content)
        tgt_h = short_hash(tgt_content)
        if ref_h == tgt_h:
            results.append(
                {
                    "reference_file": ref_path,
                    "target_file": tgt_path,
                    "section_index": idx + 1,
                    "ref_section_name": ref_name,
                    "tgt_section_name": tgt_name,
                    "ref_size": ref_size,
                    "tgt_size": tgt_size,
                    "ref_hash": ref_h,
                    "tgt_hash": tgt_h,
                    "bytes_different": 0,
                    "pct_different": 0.0,
                    "status": "identical",
                }
            )
            continue

        # hashes differ -> do byte-by-byte (chunked) count
        diff_bytes = count_different_bytes(
            ref_content, tgt_content, chunk_size=chunk_size
        )
        denom = max(ref_size or 0, tgt_size or 1)
        pct = (diff_bytes / denom) * 100.0 if denom > 0 else None

        results.append(
            {
                "reference_file": ref_path,
                "target_file": tgt_path,
                "section_index": idx + 1,
                "ref_section_name": ref_name,
                "tgt_section_name": tgt_name,
                "ref_size": ref_size,
                "tgt_size": tgt_size,
                "ref_hash": ref_h,
                "tgt_hash": tgt_h,
                "bytes_different": diff_bytes,
                "pct_different": round(pct, 6) if pct is not None else None,
                "status": "different",
            }
        )

    return results


# --------------------
# CLI / orchestration
# --------------------


def discover_targets(args) -> List[str]:
    """Return a list of target file paths based on CLI args."""
    targets = []
    if args.targets:
        targets.extend(args.targets)
    if args.targets_dir:
        for entry in os.listdir(args.targets_dir):
            path = os.path.join(args.targets_dir, entry)
            if os.path.isfile(path):
                targets.append(path)
    # remove the reference from targets if present
    normalized_ref = os.path.normpath(args.reference)
    targets = [t for t in targets if os.path.normpath(t) != normalized_ref]
    return sorted(set(targets))


def main():
    parser = argparse.ArgumentParser(
        description="Compare sections of binaries and export CSV via polars."
    )
    parser.add_argument(
        "--reference", "-r", required=True, help="Reference binary file"
    )
    parser.add_argument(
        "--targets",
        "-t",
        nargs="*",
        default=[],
        help="Target binary files to compare (space-separated).",
    )
    parser.add_argument(
        "--targets-dir",
        "-d",
        help="Directory containing target binaries (non-recursive). Files inside will be compared to reference.",
    )
    parser.add_argument(
        "--sections",
        "-s",
        default="1,4",
        help="Comma-separated 1-based section indices to compare (default '1,4' meaning 1st and 4th).",
    )
    parser.add_argument(
        "--out", "-o", default="binary_section_diff.csv", help="Output CSV path."
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=4,
        help="Number of worker threads (default 4).",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=65536,
        help="Chunk size in bytes for byte-level compare.",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Print progress to stdout."
    )
    args = parser.parse_args()

    # parse sections to 0-based indices
    try:
        section_indices = [
            max(0, int(x.strip()) - 1) for x in args.sections.split(",") if x.strip()
        ]
    except Exception:
        raise SystemExit(
            "Bad --sections value. Use a comma-separated list of integers like '1,4'."
        )

    targets = discover_targets(args)
    if not targets:
        raise SystemExit(
            "No target files discovered (check --targets or --targets-dir)."
        )

    if args.verbose:
        print(f"Reference: {args.reference}")
        print(f"Targets: {len(targets)} files")
        print(f"Sections (1-based): {[i + 1 for i in section_indices]}")

    all_records = []

    # We parse reference once inside compare function; we will parallelize over targets.
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {
            ex.submit(
                compare_sections_between_files,
                args.reference,
                tgt,
                section_indices,
                args.chunk_size,
            ): tgt
            for tgt in targets
        }
        for fut in as_completed(futures):
            tgt = futures[fut]
            try:
                recs = fut.result()
                all_records.extend(recs)
                if args.verbose:
                    print(f"Done: {tgt}")
            except Exception as e:
                # record a failure row per section
                if args.verbose:
                    print(f"Failed processing {tgt}: {e}")
                for idx in section_indices:
                    all_records.append(
                        {
                            "reference_file": args.reference,
                            "target_file": tgt,
                            "section_index": idx + 1,
                            "ref_section_name": None,
                            "tgt_section_name": None,
                            "ref_size": None,
                            "tgt_size": None,
                            "ref_hash": None,
                            "tgt_hash": None,
                            "bytes_different": None,
                            "pct_different": None,
                            "status": f"failed_to_process_target: {e}",
                        }
                    )

    # Build polars DataFrame and export to CSV
    if all_records:
        df = pl.DataFrame(all_records)
        # order columns nicely
        desired_cols = [
            "reference_file",
            "target_file",
            "section_index",
            "ref_section_name",
            "tgt_section_name",
            "ref_size",
            "tgt_size",
            "ref_hash",
            "tgt_hash",
            "bytes_different",
            "pct_different",
            "status",
        ]
        cols_present = [c for c in desired_cols if c in df.columns]
        df = df.select(cols_present)
        df.write_csv(args.out)
        if args.verbose:
            print(f"Wrote {len(df)} rows to {args.out}")
    else:
        print("No comparison records produced.")


if __name__ == "__main__":
    main()
