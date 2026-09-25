"""
IDA-specific helper utilities.
"""
import idc
import idaapi
import ida_bytes
import ida_hexrays
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)

IMAGE_BASE = idaapi.get_imagebase()


@lru_cache(maxsize=None)
def decompile_text(func_ea):
    """Decompile a function and return its pseudocode text. Cached."""
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc is None:
            return ""
        return str(cfunc)
    except Exception:
        return ""


def _try_read_cstring(ea, max_len=128):
    """Read null-terminated printable ASCII string at ea. Returns str or None."""
    result = []
    for i in range(max_len):
        b = ida_bytes.get_byte(ea + i)
        if b == 0:
            break
        if 0x20 <= b <= 0x7E:
            result.append(chr(b))
        else:
            return None
    return "".join(result) if result else None


def _demangle(mangled):
    # disable_mask=0 -> full long-form demangled name (no features disabled).
    # Do NOT pass idc.get_inf_attr(idc.INF_LONG_DEMNAMES) here — that returns 0 or 1
    # from the IDB setting and gets interpreted as MNG_SHORT_FORM (bit 0), which
    # strips namespace qualifiers and breaks all suffix checks.
    d = idc.demangle_name(mangled, 0)
    return d if d else mangled


def _normalize_name(s):
    """Strip leading const/class/struct qualifiers IDA injects into demangled names."""
    s = s.strip()
    changed = True
    while changed:
        changed = False
        for pfx in ("const ", "class ", "struct ", "volatile "):
            if s.startswith(pfx):
                s = s[len(pfx):]
                changed = True
                break
    return s


def _is_api_oneme_name(name):
    return "Api::OneMe::Packets::" in name or "Api::OneMe::Types::" in name


def extract_app_version():
    """
    Returns (app_version, build_number) from the first version string
    matching "{major}.{minor}.{patch}.{build}" or "{major}.{minor}.{patch}:{build}".
    app_version is "major.minor.patch", build_number is int.
    """
    import common

    filepath = idaapi.get_input_file_path()
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        logger.warning("Failed to read input file for version extraction: %s", e)
        return None, 0

    for m in common.RE_VERSION.finditer(data):
        raw = m.group().decode()
        import re
        parts = re.split(r'[.:]', raw)
        if len(parts) >= 4:
            app_version = ".".join(parts[:3])
            build_number = int(parts[3])
            return app_version, build_number
        elif len(parts) == 3:
            return raw, 0
        return raw, 0
    return None, 0
