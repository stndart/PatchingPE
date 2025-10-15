#!/usr/bin/env python3
"""
exports_both_names.py

Parse a PE/DLL and produce maps of decorated -> (ordinal, rva, forwarded)
and undecorated -> [decorated,...].

Requirements:
    pip install lief
Run on Windows to get undecoration through dbghelp.dll. On non-Windows, the script will still list decorated names
but undecoration will be a no-op (or will attempt c++filt if available).

Usage:
    python exports_both_names.py path\to\module.dll -o exports.json -v
"""

from __future__ import annotations
import argparse
import json
import logging
import os
import platform
import subprocess
import sys
from typing import Dict, List, Optional

try:
    import lief
except Exception as e:
    print("Missing dependency: install lief (pip install lief)\n", e)
    sys.exit(1)

# Optional: windows-only ctypes call to dbghelp UnDecorateSymbolName
UNDNAME_COMPLETE = 0  # full undecoration (flags as defined in dbghelp.h)


def undecorate_windows(decorated: str) -> Optional[str]:
    """Use dbghelp.UnDecorateSymbolNameA to undecorate MSVC-style names on Windows."""
    import ctypes
    from ctypes import create_string_buffer, c_char_p, c_uint32

    try:
        dbghelp = ctypes.windll.dbghelp  # raises AttributeError on non-Windows
    except Exception:
        return None

    # prepare argtypes/restype for UnDecorateSymbolNameA
    try:
        func = dbghelp.UnDecorateSymbolNameA
        func.argtypes = [c_char_p, c_char_p, c_uint32, c_uint32]
        func.restype = c_uint32
    except Exception:
        return None

    # input must be bytes (ANSI). LIEF returns Python str (likely ascii/utf-8), but Windows API expects ANSI.
    b = decorated.encode("utf-8", errors="ignore")  # keep it simple
    outbuf = create_string_buffer(2048)
    r = func(b, outbuf, len(outbuf), UNDNAME_COMPLETE)
    if r == 0:
        # failed to undecorate
        return None
    try:
        return outbuf.value.decode("utf-8", errors="ignore")
    except Exception:
        return outbuf.value.decode("latin-1", errors="ignore")


def undecorate_cxxfilt(decorated: str) -> Optional[str]:
    """Try to call c++filt (Itanium demangler) as fallback for non-MSVC mangling."""
    try:
        p = subprocess.run(
            ["c++filt"],
            input=decorated.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        out = p.stdout.decode("utf-8", errors="ignore").strip()
        return out or None
    except Exception:
        return None


def undecorate_any(decorated: str) -> str:
    """Try windows dbghelp first; then c++filt; otherwise return original decorated name."""
    if not decorated:
        return decorated
    if platform.system().lower() == "windows":
        u = undecorate_windows(decorated)
        if u:
            return u
    # try c++filt (useful for Itanium/gnu/clang mangling)
    u = undecorate_cxxfilt(decorated)
    if u:
        return u
    # fallback: return original
    return decorated


def parse_exports(dll_path: str, verbose: int = 0):
    """
    Returns:
        decorated_map: dict decorated_name -> {ordinal, rva, forwarded}
        undec_map: dict undecorated_name -> [decorated_name,...]
    """
    decorated_map: Dict[str, dict] = {}
    undec_map: Dict[str, List[str]] = {}

    logging.debug("Parsing with LIEF: %s", dll_path)
    try:
        pe = lief.parse(dll_path)
    except Exception as e:
        logging.error("Failed to parse %s: %s", dll_path, e)
        raise

    if not isinstance(pe, lief.PE.Binary):
        logging.error("%s does not look like a PE binary", dll_path)
        raise RuntimeError("Not a PE binary")

    # LIEF: exported functions usually available via pe.exported_functions
    exports = []
    try:
        exports = list(pe.exported_functions)
    except Exception:
        # try alternative attribute names
        try:
            exports = list(pe.get_exported_functions())
        except Exception:
            logging.warning(
                "Couldn't get exported functions via known LIEF APIs. Trying export table raw."
            )
            exports = []

    # fallback: populate by parsing export objects if LIEF provides export entries
    if not exports and hasattr(pe, "get_export"):
        ed = pe.get_export()
        if ed and hasattr(ed, "entries"):
            exports = ed.entries  # these entries may have name/ordinal/address

    # iterate entries
    for e in exports:
        # LIEF export entry attributes differ by version; guard with getattr.
        name = getattr(e, "name", None)
        ordinal = getattr(e, "ordinal", None)
        rva = getattr(e, "address", None) or getattr(e, "rva", None) or None
        forwarded = getattr(e, "is_forwarded", False) or getattr(e, "forward", None)

        if name is None:
            # ordinal-only export: create a synthetic decorated name
            name = f"<ordinal_{ordinal}>"

        # ensure string
        if isinstance(name, bytes):
            try:
                name = name.decode("utf-8", errors="ignore")
            except Exception:
                name = name.decode("latin-1", errors="ignore")

        decorated_map[name] = {"ordinal": ordinal, "rva": rva, "forwarded": forwarded}

        undec = undecorate_any(name)
        # if undecoration produced the same as decorated or failed, still keep it
        undec_map.setdefault(undec, []).append(name)

        if verbose >= 2:
            logging.info(
                "Export: decorated=%r undecorated=%r ordinal=%s rva=%s forwarded=%s",
                name,
                undec,
                ordinal,
                hex(rva) if rva else None,
                forwarded,
            )

    return decorated_map, undec_map


def main():
    ap = argparse.ArgumentParser(
        description="Extract decorated+undecorated exports from a DLL using LIEF + dbghelp"
    )
    ap.add_argument("dll", help="Path to DLL/PE to parse")
    ap.add_argument(
        "-o", "--out", help="Write JSON output file (decorated and undecorated maps)"
    )
    ap.add_argument(
        "-v", "--verbose", action="count", default=0, help="Increase verbosity"
    )
    args = ap.parse_args()

    # logging config
    level = logging.WARNING
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    dll = args.dll
    if not os.path.exists(dll):
        logging.error("File not found: %s", dll)
        sys.exit(2)

    logging.info("Parsing: %s", dll)
    decorated_map, undec_map = parse_exports(dll, verbose=args.verbose)

    # Summaries
    logging.info("Decorated exports: %d", len(decorated_map))
    logging.info("Undecorated names: %d", len(undec_map))

    # print brief table when verbosity low
    if args.verbose == 0:
        print(f"Parsed {len(decorated_map)} exports from {dll}. Use -v for details.")
    elif args.verbose == 1:
        for dec, info in decorated_map.items():
            print(
                f"{dec} -> ordinal={info['ordinal']} rva={hex(info['rva']) if info['rva'] else None}"
            )
    else:
        # verbose >= 2: show undecorated mapping
        for undec, decs in undec_map.items():
            print(f"{undec!r} -> {decs}")

    if args.out:
        outdata = {
            "decorated": decorated_map,
            "undecorated": undec_map,
            "source": os.path.abspath(dll),
        }
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(outdata, fh, indent=2, ensure_ascii=False)
        logging.info("Wrote JSON to %s", args.out)


if __name__ == "__main__":
    main()
