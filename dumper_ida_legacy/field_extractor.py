"""
Field extraction logic — primary (Hex-Rays) and fallback (disassembly).
Uses sequential state-machine pairing for reliable name+type+flag extraction.
"""
import re
import ida_bytes
import idaapi
import ida_funcs
import idautils
import ida_segment
import logging

import common
import ida_utils
import template_parser

logger = logging.getLogger(__name__)

# ── Regexes for field extraction ──────────────────────────────────────────────
_FLAG_RE = re.compile(r'=\s*([12])\s*;')
_NAME_RE = re.compile(r'=\s*"([A-Za-z_][A-Za-z0-9_\-]{0,63})"\s*;')
_NAME_RE2 = re.compile(r'\bv\d+\[\d+\]\s*=\s*"([A-Za-z_][A-Za-z0-9_\-]{0,63})"\s*;')
_NAME_PTR_RE = re.compile(r'=\s*&?(?:qword|off|unk|byte|word|dword)_(180[0-9A-Fa-f]+)\s*;')
_HELPER_CALL_RE = re.compile(r'\bsub_(180[0-9A-Fa-f]+)\s*\(')
_FIELD_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_\-]{0,63}$')

_HELPER_TYPE_CACHE = {}


# ── Name resolution helpers ───────────────────────────────────────────────────

def _try_resolve_name_ptr(line):
    m = _NAME_PTR_RE.search(line)
    if not m:
        return None

    try:
        ea = int(m.group(1), 16)
    except Exception:
        return None

    s = ida_utils._try_read_cstring(ea)
    if s and _FIELD_RE.match(s):
        return s

    try:
        ptr = ida_bytes.get_qword(ea)
    except Exception:
        return None

    if not ptr or ptr == idaapi.BADADDR:
        return None

    s = ida_utils._try_read_cstring(ptr)
    return s if s and _FIELD_RE.match(s) else None


def _extract_name_from_line(line):
    m = _NAME_RE.search(line) or _NAME_RE2.search(line)
    if m:
        return m.group(1)
    return _try_resolve_name_ptr(line)


# ── Helper type inference ─────────────────────────────────────────────────────

def _infer_helper_member_info(helper_ea):
    cached = _HELPER_TYPE_CACHE.get(helper_ea)
    if cached is not None:
        return cached
    text = ida_utils.decompile_text(helper_ea)

    info = (None, None)
    for line in text.splitlines():
        if "SerializableMember<" not in line or not common._line_has_vftable(line):
            continue
        if "ISerializableMember<" in line:
            continue
        idx = line.find("SerializableMember<")
        dem = line[idx:]
        raw_t = template_parser._extract_member_first_arg(dem)
        owner = template_parser._extract_member_last_arg(dem)
        if raw_t and owner:
            info = (ida_utils._normalize_name(raw_t), ida_utils._normalize_name(owner))
            break

    _HELPER_TYPE_CACHE[helper_ea] = info
    return info


# ── Sequential type extraction from a single line ─────────────────────────────

def _extract_seq_type_from_line(line):
    if "SerializableMember<" not in line or not common._line_has_vftable(line):
        return None
    if "ISerializableMember<" in line:
        return None
    idx = line.find("SerializableMember<")
    if idx == -1:
        return None
    after_sm = line[idx + len("SerializableMember<"):]
    raw_t = template_parser._extract_first_tpl_arg(after_sm)
    if not raw_t or "ISerializableMember" in raw_t:
        return None
    return raw_t


def extract_helper_type(line, owner_name):
    """
    Try to extract a type from a helper call on this line.
    Returns (raw_t, helper_owner) or (None, None).
    """
    helper_m = _HELPER_CALL_RE.search(line)
    if not helper_m:
        return None, None
    helper_ea = int(helper_m.group(1), 16)
    helper_raw_t, helper_owner = _infer_helper_member_info(helper_ea)
    if not helper_raw_t:
        return None, None
    return helper_raw_t, helper_owner


def extract_required_flag(line):
    """Return the flag value (1 or 2) if this line assigns a flag, else None."""
    m = _FLAG_RE.search(line)
    if m:
        return int(m.group(1))
    return None


# ── Paired sequential extraction (primary method) ─────────────────────────────

def extract_paired_fields(func_ea, owner_name=""):
    """
    Scan decompiled lines sequentially, pairing name → type → flag per field.

    Decompilation pattern per field:
      "fieldName"                           → name
      ISerializableMember<...>::vftable'    → temp (filtered)
      sub_180014358(...)                    → register call
      SerializableMember<T,...>::vftable'   → type T
      *(a1+N) = 0; ...                     → defaults (ignored)
      *(a1+N) = 1 or 2;                    → flag
      "nextFieldName"                       → triggers emit

    Returns list of {"name": str, "type": str, "required": bool} or [].
    """
    text = ida_utils.decompile_text(func_ea)
    if not text:
        return []

    lines = text.splitlines()
    fields = []

    pending_name = None
    pending_type = None
    pending_flag = None

    for line in lines:
        # Check for flag assignment (= 1 or = 2)
        flag = extract_required_flag(line)
        if flag is not None:
            pending_flag = flag
            continue

        # Check for field name string
        name = _extract_name_from_line(line)
        if name:
            # Emit previous field if we have one
            if pending_name is not None:
                required = (pending_flag != 2) if pending_flag is not None else True
                fields.append({
                    "name": pending_name,
                    "type": pending_type or "unknown",
                    "required": required,
                })
            pending_name = name
            pending_type = None
            pending_flag = None
            continue

        # Check for SerializableMember<T,...> type (not ISerializableMember)
        raw_t = _extract_seq_type_from_line(line)
        if raw_t is None:
            raw_t, helper_owner = extract_helper_type(line, owner_name)
        if raw_t:
            pending_type = raw_t

    # Emit last field
    if pending_name is not None:
        required = (pending_flag != 2) if pending_flag is not None else True
        fields.append({
            "name": pending_name,
            "type": pending_type or "unknown",
            "required": required,
        })

    return fields


# ── Fallback: disassembly scan ────────────────────────────────────────────────

def _extract_disasm(func_ea):
    """
    Fallback: scan data cross-refs in the function body for readable strings
    that look like field names.  No type or flag info.
    Returns list of {"name": str, "type": "unknown", "required": True} or [].
    """
    func = ida_funcs.get_func(func_ea)
    if not func:
        return []

    seen = set()
    fields = []

    for head in idautils.Heads(func.start_ea, func.end_ea):
        for ref in idautils.DataRefsFrom(head):
            if ref in seen:
                continue
            seen.add(ref)

            seg = ida_segment.getseg(ref)
            if seg is None:
                continue
            if seg.perm & ida_segment.SEGPERM_EXEC:
                continue

            s = ida_utils._try_read_cstring(ref)
            if s and _FIELD_RE.match(s):
                if "vtable" not in s and len(s) >= 2:
                    fields.append({"name": s, "type": "unknown", "required": True})

    return fields


# ── Public entry point ────────────────────────────────────────────────────────

def extract_fields_from_func(func_ea, owner_name=""):
    """
    Try paired Hex-Rays extraction first, fall back to disassembly scan.
    Returns (fields: [{name, type, required}], method: str|None).
    """
    paired = extract_paired_fields(func_ea, owner_name)
    if paired:
        return paired, "hexrays"

    disasm = _extract_disasm(func_ea)
    if disasm:
        return disasm, "disasm"

    return [], None


