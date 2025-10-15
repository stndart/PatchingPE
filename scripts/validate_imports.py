#!/usr/bin/env python3
# validate_imports_lief.py
# Usage: python validate_imports_lief.py Game_dump_mod.exe [--verbose]

import sys
import os
import argparse
import lief


def vprint(msg, level=1):
    """Verbose print according to global verbosity."""
    if VERBOSITY >= level:
        print(msg)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate PE imports against actual DLL exports using lief."
    )
    parser.add_argument("binary", help="Path to the PE file to analyze")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv for more detail)",
    )
    return parser.parse_args()


def list_exports(dllpath):
    """Return dict of export_name -> (ordinal, RVA) for given DLL."""
    exports = {}
    try:
        pe = lief.parse(dllpath)
        if not pe or not isinstance(pe, lief.PE.Binary):
            raise RuntimeError("Not a valid PE binary")
        if not pe.has_exports:
            return {}
        for ordinal, exp in enumerate(pe.exported_functions):
            name = exp.name
            rva = exp.address
            exports[name] = (ordinal, rva)
    except Exception as e:
        vprint(f"  [!] Failed to parse {dllpath}: {e}", 1)
    return exports


def resolve_dll_path(base_dir, dllname):
    """Try to resolve DLL path in local folder or System32."""
    system32 = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32")
    x86_compatible = r"C:\Windows\WinSxS\x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.30729.9625_none_508ef7e4bcbbe589"
    syswow = r"C:\Windows\SysWOW64"

    possible_paths = [x86_compatible, base_dir, syswow, system32]

    for p in possible_paths:
        if os.path.exists(os.path.join(p, dllname)):
            return os.path.join(p, dllname)
    return dllname  # fallback, may fail but is informative


def main():
    global VERBOSITY
    args = parse_args()
    VERBOSITY = args.verbose

    binary_path = args.binary
    if not os.path.exists(binary_path):
        print(f"Error: {binary_path} not found.")
        sys.exit(1)

    pe = lief.parse(binary_path)
    if not pe or not isinstance(pe, lief.PE.Binary):
        print("Error: not a valid PE file.")
        sys.exit(1)

    vprint(f"Parsing {binary_path} (ImageBase: {hex(pe.optional_header.imagebase)})", 0)

    if not pe.has_imports:
        print("No import directory found.")
        sys.exit(0)

    exports_cache = {}
    base_dir = os.path.dirname(binary_path)

    broken = 0
    for imp in pe.imports:
        dllname = imp.name
        vprint(f"\nDLL: {dllname}", 0)

        dllpath = resolve_dll_path(base_dir, dllname)
        vprint(f"  Load path used: {dllpath}", 1)

        if dllname.lower() not in exports_cache:
            exports_cache[dllname.lower()] = list_exports(dllpath)

        exports = exports_cache[dllname.lower()]
        vprint(f"  #exports: {len(exports)}", 2)

        for entry in imp.entries:
            name = entry.name
            addr = entry.iat_value

            if name in exports:
                ord_, rva = exports[name]
                vprint(f"    Import: {name!r} slotVA={hex(addr) if addr else None}", 2)
                if not name:
                    vprint(f"      (import by ordinal?) ordinal: {entry.ordinal}", 2)
                    continue
                vprint(f"      FOUND in DLL exports: ordinal {ord_}, rva {hex(rva)}", 2)
            else:
                vprint(f"    Import: {name!r} slotVA={hex(addr) if addr else None}", 1)
                if not name:
                    vprint(f"      (import by ordinal?) ordinal: {entry.ordinal}", 1)
                    continue
                matches = [k for k in exports if k and name in k]
                broken += 1
                if matches:
                    vprint(f"      NOT FOUND exact, similar exports: {matches[:5]}", 1)
                else:
                    vprint("      NOT FOUND in DLL exports.", 1)

    vprint(f"\nDone. {broken} broken calls.", 0)


if __name__ == "__main__":
    main()
