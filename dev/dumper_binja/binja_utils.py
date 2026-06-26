"""
Binary Ninja-specific helper utilities.
"""
import logging
import re
from functools import lru_cache

logger = logging.getLogger(__name__)

IMAGE_BASE = None  # set lazily on first use
_BV = None         # cached BinaryView reference

_QUALIFIERS = ("const ", "class ", "struct ", "volatile ")


def init(bv):
    global IMAGE_BASE, _BV
    _BV = bv
    IMAGE_BASE = bv.start


def get_bv():
    return _BV


def normalize_name(s):
    """Strip leading const/class/struct qualifiers from demangled names."""
    s = s.strip()
    changed = True
    while changed:
        changed = False
        for pfx in _QUALIFIERS:
            if s.startswith(pfx):
                s = s[len(pfx):]
                changed = True
                break
    return s


def is_api_oneme_name(name):
    return "Api::OneMe::Packets::" in name or "Api::OneMe::Types::" in name


def read_cstring(bv, addr, max_len=128):
    """Read null-terminated printable ASCII string at addr. Returns str or None."""
    try:
        addr = int(addr)
    except (TypeError, ValueError):
        return None
    if addr == 0:
        return None
    try:
        raw = bv.read(addr, max_len)
    except Exception:
        return None
    nul = raw.find(b"\x00")
    if nul != -1:
        raw = raw[:nul]
    if not raw:
        return None
    try:
        s = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not all(0x20 <= b <= 0x7E for b in raw):
        return None
    return s


def get_symbol_name_at(bv, addr):
    """
    Get the full demangled symbol name at addr.
    Tries Symbol.full_name, then DataVariable auto-name.
    """
    try:
        addr = int(addr)
    except (TypeError, ValueError):
        return None
    sym = bv.get_symbol_at(addr)
    if sym:
        return sym.full_name

    dv = bv.get_data_var_at(addr)
    if dv:
        # BN sometimes assigns auto-names to data vars
        s = bv.get_symbol_at(addr)
        if s:
            return s.full_name

    return None


@lru_cache(maxsize=4096)
def get_hlil_text(func_addr):
    """Get cached HLIL text for a function. Returns str or ''."""
    bv = _BV
    if bv is None:
        return ""
    func = bv.get_function_at(func_addr)
    if func is None:
        funcs = bv.get_functions_containing(func_addr)
        func = funcs[0] if funcs else None
    if func is None or func.hlil is None:
        return ""
    try:
        return "\n".join(str(il) for il in func.hlil.instructions)
    except Exception:
        return ""


def get_function_at(bv, addr):
    """Get function at addr, falling back to containing function."""
    func = bv.get_function_at(addr)
    if func is not None:
        return func
    funcs = bv.get_functions_containing(addr)
    return funcs[0] if funcs else None


def get_code_xref_functions(bv, addr):
    """Return set of Function objects that contain code refs to addr."""
    result = set()
    for ref in bv.get_code_refs(addr):
        func = ref.function
        if func is not None:
            result.add(func)
        else:
            funcs = bv.get_functions_containing(ref.address)
            if funcs:
                result.add(funcs[0])
    return result


def extract_app_version(bv):
    """
    Returns (app_version, build_number) from the first version string
    matching "{major}.{minor}.{patch}.{build}" or "{major}.{minor}.{patch}:{build}".
    """
    import common

    filepath = bv.file.original_filename or ""
    if not filepath:
        filepath = bv.file.filename or ""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        logger.warning("Failed to read file for version extraction: %s", e)
        return None, 0

    for m in common.RE_VERSION.finditer(data):
        raw = m.group().decode()
        parts = re.split(r"[.:]", raw)
        if len(parts) >= 4:
            return ".".join(parts[:3]), int(parts[3])
        elif len(parts) == 3:
            return raw, 0
    return None, 0
