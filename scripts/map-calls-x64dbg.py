"""
x64dbgpy script: resolve an absolute address to a function/symbol name (best-effort).

Usage (inside x64dbg with x64dbgpy installed):
- Open "Open GUI Script..." or run via the python plugin console.
- Call `resolve_address("0x7ff6abcd1234")` or `resolve_address(0x7ff6abcd1234)`.

This script uses only documented x64dbgpy scriptapi functions (module, label, symbol, function, misc, x64dbg, gui).
It attempts multiple strategies (labels, symbol table, function table, module exports) and falls back to `module_name+offset`.

Note: result depends on which symbols/exports are loaded in x64dbg (PDBs, exported symbols, etc.).
"""

from x64dbgpy.pluginsdk import x64dbg, gui # type: ignore
from x64dbgpy.pluginsdk import module as modapi # type: ignore
from x64dbgpy.pluginsdk import label as labelapi # type: ignore
from x64dbgpy.pluginsdk import symbol as symapi # type: ignore
from x64dbgpy.pluginsdk import function as funcapi # type: ignore
from x64dbgpy.pluginsdk import misc as miscapi # type: ignore


def _to_int(addr):
    """Convert address input (int or hex string) to int. Raises ValueError if not valid."""
    if isinstance(addr, int):
        return addr
    if isinstance(addr, str):
        s = addr.strip().lower()
        if s.startswith("0x"):
            return int(s, 16)
        # allow plain hex like 7FF6ABCD
        try:
            return int(s, 16)
        except ValueError:
            # try decimal
            return int(s, 10)
    raise ValueError("address must be int or hex string")


def _try_extract_symbol_fields(entry):
    """Attempt to extract (addr, name, type) from a symbol entry returned by symapi.GetList().
    The exact structure can vary between versions; try several common patterns.
    Returns (addr:int or None, name:str or None, type:int or None).
    """
    addr = None
    name = None
    stype = None
    # dict-like
    try:
        if isinstance(entry, dict):
            addr = entry.get("Address") or entry.get("address") or entry.get("Addr")
            name = entry.get("Name") or entry.get("name") or entry.get("Label")
            stype = entry.get("Type") or entry.get("type")
            return (addr, name, stype)
    except Exception:
        pass
    # tuple/list-like
    try:
        if isinstance(entry, (tuple, list)) and len(entry) >= 2:
            # common: (address, name, type)
            addr = entry[0]
            name = entry[1]
            if len(entry) > 2:
                stype = entry[2]
            return (addr, name, stype)
    except Exception:
        pass
    # object with attributes
    try:
        addr = (
            getattr(entry, "Address", None)
            or getattr(entry, "address", None)
            or getattr(entry, "Addr", None)
        )
        name = (
            getattr(entry, "Name", None)
            or getattr(entry, "name", None)
            or getattr(entry, "Label", None)
        )
        stype = getattr(entry, "Type", None) or getattr(entry, "type", None)
        return (addr, name, stype)
    except Exception:
        pass
    return (None, None, None)


def resolve_address(addr):
    """Resolve an absolute address to the best candidate name.

    Returns a dict with keys: success(bool), name(str), detail(str).
    - If a label/symbol is found exactly at addr, name contains it.
    - If an enclosing function start is found, name contains the function's label plus offset.
    - If none found, returns module_name+offset.

    This is best-effort and depends on which symbols/exports x64dbg has loaded.
    """
    try:
        addr = _to_int(addr)
    except ValueError as e:
        return {"success": False, "name": None, "detail": "bad address: %s" % e}

    # 1) check if there's a label at that exact address
    try:
        lbl = labelapi.Get(addr)
        if lbl:
            return {"success": True, "name": lbl, "detail": "label.Get matched"}
    except Exception:
        # label api might raise if not available; ignore and continue
        pass

    # 2) search symbol list for an exact match (exports, imports, symbols)
    try:
        syms = symapi.GetList()
    except Exception:
        syms = None

    if syms:
        # iterate and try to match exact address
        for e in syms:
            saddr, sname, stype = _try_extract_symbol_fields(e)
            try:
                if saddr is None:
                    # sometimes the address is inside a nested structure; skip
                    continue
                # normalize numeric-like addresses (may be strings)
                if isinstance(saddr, str):
                    try:
                        saddr = int(saddr, 16)
                    except Exception:
                        try:
                            saddr = int(saddr, 10)
                        except Exception:
                            continue
                if int(saddr) == addr:
                    # prefer exact symbol match
                    if not sname:
                        # try ResolveLabel on address
                        try:
                            sname = miscapi.ResolveLabel(addr)
                        except Exception:
                            sname = None
                    if sname:
                        return {
                            "success": True,
                            "name": sname,
                            "detail": "symbol.GetList exact match",
                        }
                    else:
                        return {
                            "success": True,
                            "name": "<symbol@%s>" % hex(addr),
                            "detail": "symbol entry matched but no name field",
                        }
            except Exception:
                # defensive: continue on malformed entries
                continue

    # 3) try to find a function containing this address (function table)
    try:
        faddr = funcapi.Get(addr)
        # funcapi.Get usually returns the start address of the function if addr is inside one, otherwise 0/None
        if faddr:
            # if the function start equals addr, try to get label
            if faddr == addr:
                # exact function start
                finfo = funcapi.GetInfo(addr)
                # GetInfo may return a dict-like object containing name/start
                name = None
                try:
                    if isinstance(finfo, dict):
                        name = finfo.get("Name") or finfo.get("name")
                except Exception:
                    pass
                if not name:
                    name = labelapi.Get(faddr) or miscapi.ResolveLabel(faddr)
                if name:
                    return {
                        "success": True,
                        "name": name,
                        "detail": "function.Get exact start",
                    }
            else:
                # addr is inside a function but not its start
                # compute offset
                offset = addr - faddr
                fname = (
                    labelapi.Get(faddr)
                    or miscapi.ResolveLabel(faddr)
                    or ("sub_%s" % hex(faddr))
                )
                return {
                    "success": True,
                    "name": "%s+0x%x" % (fname, offset),
                    "detail": "inside function; function.Get returned start",
                }
    except Exception:
        pass

    # 4) try module information and present module+offset; also attempt to match exports by scanning symbols with Export type
    try:
        base = modapi.BaseFromAddr(addr)
        modname = (
            modapi.NameFromAddr(addr) or modapi.PathFromAddr(addr) or "<unknown_module>"
        )
        if base:
            offset = addr - int(base)
            # try to find an export at that address in symbol list (type Export)
            if syms:
                for e in syms:
                    saddr, sname, stype = _try_extract_symbol_fields(e)
                    try:
                        if saddr is None:
                            continue
                        if isinstance(saddr, str):
                            try:
                                saddr = int(saddr, 16)
                            except Exception:
                                try:
                                    saddr = int(saddr, 10)
                                except Exception:
                                    continue
                        if int(saddr) == addr:
                            # check type if available
                            try:
                                if (
                                    hasattr(symapi, "SymbolType")
                                    and stype == symapi.SymbolType.Export
                                ):
                                    return {
                                        "success": True,
                                        "name": "%s:%s"
                                        % (modname, sname or "<export>"),
                                        "detail": "export symbol matched",
                                    }
                            except Exception:
                                # if type check fails, still return the name
                                if sname:
                                    return {
                                        "success": True,
                                        "name": "%s:%s" % (modname, sname),
                                        "detail": "symbol matched (no type info)",
                                    }
                    except Exception:
                        continue
            # fallback: module+offset
            return {
                "success": False,
                "name": "%s+0x%x" % (modname, offset),
                "detail": "no symbol; returning module+offset",
            }
    except Exception:
        pass

    # 5) last resort: try ParseExpression to see if x64dbg can make sense of the address
    try:
        # ParseExpression will try to resolve expressions; if given a hex it may return numeric value only
        parsed = miscapi.ParseExpression(hex(addr))
        # Attempt ResolveLabel too
        rlbl = miscapi.ResolveLabel(hex(addr))
        if rlbl:
            return {
                "success": True,
                "name": rlbl,
                "detail": "misc.ResolveLabel matched",
            }
    except Exception:
        pass

    return {
        "success": False,
        "name": "<unknown@%s>" % hex(addr),
        "detail": "could not resolve",
    }


# Small helper for interactive usage


def show_resolve(addr):
    res = resolve_address(addr)
    if res["success"]:
        gui.Message("Resolved: %s (detail: %s)" % (res["name"], res["detail"]))
    else:
        gui.Message("Not resolved: %s (detail: %s)" % (res["name"], res["detail"]))
    return res


# If the script is run directly in the Python console (not imported), prompt the user
# if __name__ == "__main__":
#     try:
#         # ask for an address from the user using GUI input
#         v = gui.InputValue("Enter address (hex or decimal)")
#         if v is None:
#             gui.Message("No address provided, quitting")
#         else:
#             show_resolve(v)
#     except Exception as e:
#         gui.Message("Error: %s" % e)
