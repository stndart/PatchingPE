#!/usr/bin/env python3
"""
exports_both_names.py

Parse a PE/DLL and produce maps of decorated -> (ordinal, rva, forwarded)
and undecorated -> [decorated,...].

Requirements:
    pip install lief
Run on Windows to get undecoration through dbghelp.dll. On non-Windows, the script will still list decorated names
but undecoration will be a no-op (or will attempt c++filt if available).
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import platform
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

try:
    import lief
except Exception as e:
    print("Missing dependency: install lief (pip install lief)\n", e)
    sys.exit(1)

# Optional: windows-only ctypes call to dbghelp UnDecorateSymbolName
UNDNAME_COMPLETE = 0  # full undecoration (flags as defined in dbghelp.h)
MAX_STRING = 4096

ADDITIONAL_PATHS = [
    r"G:\Games\FA\FA-EMU\Shipping",
]

def find_dll(dll_name: str, additional_paths: list[str] = ADDITIONAL_PATHS) -> str:
    """
    Find DLL by searching in:
    1. Current directory
    2. C:\\Windows\\System32 (on Windows)
    3. Provided absolute/relative path
    
    Returns:
        Full path to found DLL
    Raises:
        FileNotFoundError if DLL not found
    """
    # If it's already an absolute path that exists
    if os.path.isabs(dll_name) and os.path.exists(dll_name):
        return dll_name
    
    for p in additional_paths:
        basename = os.path.basename(dll_name)
        cand_name = os.path.join(p, basename)
        if os.path.exists(cand_name):
            return cand_name
    
    # Check current directory first
    if os.path.exists(dll_name):
        return os.path.abspath(dll_name)
    
    # On Windows, check System32
    if platform.system().lower() == 'windows':
        system32_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', dll_name)
        if os.path.exists(system32_path):
            return system32_path
    
    # If we get here, file not found
    raise FileNotFoundError(f"DLL not found: {dll_name} (searched current directory and System32)")

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
        func = dbghelp.UnDecorateSymbolName
        func.argtypes = [c_char_p, c_char_p, c_uint32, c_uint32]
        func.restype = c_uint32
    except Exception:
        return None

    # input must be bytes (ANSI). LIEF returns Python str (likely ascii/utf-8), but Windows API expects ANSI.
    b = decorated.encode('utf-8', errors='ignore')  # keep it simple
    outbuf = create_string_buffer(MAX_STRING)
    r = func(b, outbuf, len(outbuf), UNDNAME_COMPLETE)
    if r == 0:
        # failed to undecorate
        return None
    try:
        return outbuf.value.decode('utf-8', errors='ignore')
    except Exception:
        return outbuf.value.decode('latin-1', errors='ignore')

def undecorate_cxxfilt(decorated: str) -> Optional[str]:
    """Try to call c++filt (Itanium demangler) as fallback for non-MSVC mangling."""
    try:
        p = subprocess.run(['c++filt'], input=decorated.encode('utf-8'), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
        out = p.stdout.decode('utf-8', errors='ignore').strip()
        return out or None
    except Exception:
        return None

def undecorate_any(decorated: str) -> str:
    """Try windows dbghelp first; then c++filt; otherwise return original decorated name."""
    if not decorated:
        return decorated
    if platform.system().lower() == 'windows':
        u = undecorate_windows(decorated)
        if u:
            return u
    # try c++filt (useful for Itanium/gnu/clang mangling)
    u = undecorate_cxxfilt(decorated)
    if u:
        return u
    # fallback: return original
    return decorated

def get_exports(dll_name: str, verbose: int = 0) -> Tuple[Dict[str, dict], Dict[str, List[str]]]:
    """
    Main function to get exports from a DLL.
    
    Args:
        dll_name: Name or path of the DLL (will search current dir and System32)
        verbose: Verbosity level (0, 1, 2)
        
    Returns:
        Tuple of (decorated_map, undec_map)
        decorated_map: dict decorated_name -> {ordinal, rva, forwarded}
        undec_map: dict undecorated_name -> [decorated_name,...]
        
    Raises:
        FileNotFoundError: If DLL not found
        RuntimeError: If parsing fails
    """
    # Find the DLL
    dll_path = find_dll(dll_name)
    
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
            logging.warning("Couldn't get exported functions via known LIEF APIs. Trying export table raw.")
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
                name = name.decode('utf-8', errors='ignore')
            except Exception:
                name = name.decode('latin-1', errors='ignore')

        decorated_map[name] = {
            "ordinal": ordinal,
            "rva": rva,
            "forwarded": forwarded
        }

        undec = undecorate_any(name)
        # if undecoration produced the same as decorated or failed, still keep it
        undec_map.setdefault(undec, []).append(name)

        if verbose >= 2:
            logging.info("Export: decorated=%r undecorated=%r ordinal=%s rva=%s forwarded=%s",
                         name, undec, ordinal, hex(rva) if rva else None, forwarded)

    return decorated_map, undec_map

def process_multiple_dlls(dll_names: List[str], verbose: int = 0) -> Dict[str, dict]:
    """
    Process multiple DLLs and return combined results.
    
    Args:
        dll_names: List of DLL names/paths
        verbose: Verbosity level
        
    Returns:
        Dict with DLL names as keys and their export data as values
    """
    results = {}
    for dll_name in dll_names:
        try:
            decorated_map, undec_map = get_exports(dll_name, verbose)
            results[dll_name] = {
                "decorated": decorated_map,
                "undecorated": undec_map,
                "source": find_dll(dll_name)
            }
        except Exception as e:
            logging.error("Failed to process %s: %s", dll_name, e)
            results[dll_name] = {"error": str(e)}
    
    return results

def main():
    ap = argparse.ArgumentParser(description="Extract decorated+undecorated exports from a DLL using LIEF + dbghelp")
    ap.add_argument("dll", nargs="+", help="Path to DLL/PE to parse (multiple allowed)")
    ap.add_argument("-o", "--out", help="Write JSON output file (decorated and undecorated maps)")
    ap.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")
    args = ap.parse_args()

    # logging config
    level = logging.WARNING
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    # Process all DLLs
    if len(args.dll) == 1:
        # Single DLL - maintain backward compatibility
        dll_name = args.dll[0]
        try:
            decorated_map, undec_map = get_exports(dll_name, verbose=args.verbose)
            
            # Summaries
            logging.info("Decorated exports: %d", len(decorated_map))
            logging.info("Undecorated names: %d", len(undec_map))

            # print brief table when verbosity low
            if args.verbose == 0:
                print(f"Parsed {len(decorated_map)} exports from {dll_name}. Use -v for details.")
            elif args.verbose == 1:
                for dec, info in decorated_map.items():
                    print(f"{dec} -> ordinal={info['ordinal']} rva={hex(info['rva']) if info['rva'] else None}")
            else:
                # verbose >= 2: show undecorated mapping
                for undec, decs in undec_map.items():
                    print(f"{undec!r} -> {decs}")

            if args.out:
                outdata = {
                    "decorated": decorated_map,
                    "undecorated": undec_map,
                    "source": find_dll(dll_name)
                }
                with open(args.out, "w", encoding="utf-8") as fh:
                    json.dump(outdata, fh, indent=2, ensure_ascii=False)
                logging.info("Wrote JSON to %s", args.out)
                
        except Exception as e:
            logging.error("Failed to process %s: %s", dll_name, e)
            sys.exit(2)
    else:
        # Multiple DLLs
        results = process_multiple_dlls(args.dll, verbose=args.verbose)
        
        # Print summary
        for dll_name, data in results.items():
            if "error" in data:
                print(f"{dll_name}: ERROR - {data['error']}")
            else:
                print(f"{dll_name}: {len(data['decorated'])} exports, {len(data['undecorated'])} undecorated names")
        
        # Write to file if requested
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=2, ensure_ascii=False)
            logging.info("Wrote JSON to %s", args.out)

if __name__ == "__main__":
    main()