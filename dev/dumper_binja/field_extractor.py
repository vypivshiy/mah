"""
Field extraction via Binary Ninja HLIL — the primary improvement over the
IDA version.

Instead of regex-parsing Hex-Rays text, we walk HLIL instruction objects and
use BN's symbol/type API for reliable type resolution.

Pattern per field in HLIL:
    result[N+0] = "fieldName"                               # string const
    result[N+1] = strlen                                    # int const
    result[N-1] = &ISerializableMember<...>::vftable        # temp (skip)
    result[N+2] = result                                    # self ptr (skip)
    j_sub_XXX(...)                                          # register call (skip)
    result[N-1] = &SerializableMember<T,...>::vftable       # actual type T
    __builtin_memset(...)                                   # zero defaults (skip)
    result[M].d = 1 | 2                                     # flag: 1=required, 2=optional
"""
import re
import logging

from binaryninja import HighLevelILOperation

import common
import binja_utils
import template_parser
import type_parser

logger = logging.getLogger(__name__)

_VTABLE_RE = re.compile(r"SerializableMember<")

_STRING_VAL_RE = re.compile(r'"[A-Za-z_][A-Za-z0-9_\-]{0,63}"')

# Max helper size (bytes) — skip mega-functions when looking for
# SerializableMember<T> in a callee body.
_MAX_HELPER_SIZE = 2000

# Max thunk size — thunks are tiny (5-16 bytes), 32 is generous.
_MAX_THUNK_SIZE = 32

_NOT_FOUND = object()
_HELPER_TYPE_CACHE = {}      # helper_ea -> raw_type_str | None | _NOT_FOUND


# ── MSVC mangled name handling ────────────────────────────────────────────────

_MSVC_PRIMITIVES = {
    'N': 'bool', 'D': 'char', 'E': 'unsigned char',
    'F': 'short', 'G': 'unsigned short',
    'H': 'int32_t', 'I': 'unsigned int',
    'J': 'int64_t', 'K': 'uint64_t',
    'M': 'float',
}


def _extract_type_from_mangled(text):
    """Extract T from MSVC mangled ``?$SerializableMember@<T>@...`` symbols.

    Binary Ninja cannot demangle very long (or truncated) MSVC symbols, so
    vtable references like ``.?AV?$SerializableMember@V?$unordered_map@...``
    appear verbatim in HLIL.  This function partially parses the mangled
    encoding to recover the first template argument ``T``.
    """
    idx = text.find("?$SerializableMember@")
    if idx == -1:
        return None
    mangled = text[idx + len("?$SerializableMember@"):]

    # Quick peek at wrapper type
    if "?$unordered_map@" in mangled[:25] or "?$map@" in mangled[:10]:
        # Map — extract value type via regex
        key = "std::string"
        value = _find_mangled_named_type(mangled)
        if value:
            return "std::unordered_map<%s, %s>" % (key, value)
        return "std::unordered_map"

    if "?$vector@" in mangled[:12]:
        inner = _find_mangled_named_type(mangled)
        return "std::vector<%s>" % inner if inner else "std::vector"

    if "?$optional@" in mangled[:13]:
        rest = mangled[mangled.find("@?$optional@"):] if "@?$optional@" in mangled else mangled[11:]
        inner = _find_mangled_named_type(rest)
        return "std::optional<%s>" % inner if inner else "std::optional"

    if "?$basic_string@" in mangled[:20]:
        return "std::string"

    # Primitive check
    if mangled and mangled[0] in _MSVC_PRIMITIVES:
        return _MSVC_PRIMITIVES[mangled[0]]

    # Named type
    named = _find_mangled_named_type(mangled)
    return named


def _find_mangled_named_type(mangled):
    """Find the first U/V struct/class name in a MSVC mangled string."""
    # Match U or V followed by Name@NS@...@@ (at least one @)
    for m in re.finditer(r'[UV]([A-Z][A-Za-z0-9_]*(?:@[A-Za-z0-9_]+)+?)@@', mangled):
        raw_parts = m.group(1).split('@')
        parts = [re.sub(r'^\d+', '', p) for p in raw_parts if p]
        if parts:
            return '::'.join(reversed(parts))
    return None


# ── Helper-call type inference ────────────────────────────────────────────────

def _scan_func_for_type(func):
    """Scan a function's HLIL for SerializableMember<T> vtable references."""
    if func is None or func.total_bytes > _MAX_HELPER_SIZE:
        return None
    text = binja_utils.get_hlil_text(func.start)
    if not text:
        return None
    for line in text.splitlines():
        if "SerializableMember<" not in line:
            continue
        if not common._line_has_vftable(line):
            continue
        raw_t = _extract_type_from_vtable_name(line)
        if raw_t:
            return raw_t
    return None


def _infer_helper_type(bv, helper_ea, _depth=0):
    """Decompile a helper function and extract the ``SerializableMember<T>``
    type from its body.

    Some initializer functions (e.g. ``ServerSettings`` with 179 fields) don't
    store the vtable inline.  Instead they call small per-type helpers::

        var_48 = "fieldName"
        j_sub_XXX(&result[off], result, &var_48, flag)

    The helper itself contains ``SerializableMember<T, ..., Owner>::vftable``,
    so decompiling it reveals ``T``.  Results are cached per helper address.

    If the helper is called via a **thunk** (``j_sub_XXX``), the thunk body
    won't contain the type — we transparently follow callees until the real
    implementation is found.
    """
    cached = _HELPER_TYPE_CACHE.get(helper_ea, _NOT_FOUND)
    if cached is not _NOT_FOUND:
        return cached

    raw_t = None
    func = binja_utils.get_function_at(bv, helper_ea)
    if func is not None:
        raw_t = _scan_func_for_type(func)

        # If no type found and this looks like a thunk, follow callees
        if raw_t is None and func.total_bytes <= _MAX_THUNK_SIZE and _depth < 3:
            for callee in func.callees:
                raw_t = _infer_helper_type(bv, callee.start, _depth + 1)
                if raw_t:
                    break

    _HELPER_TYPE_CACHE[helper_ea] = raw_t
    return raw_t


def extract_fields_from_func(bv, func):
    """
    Extract serializable fields from an initializer function via HLIL.

    Returns:
        (fields: [dict], method: str | None)
        method is "hlil" on success, "disasm" for fallback, None if empty.
    """
    # Reject functions that contain zero SerializableMember / ISerializableMember
    # references — they are not real initialisers (e.g. factory/dispatch functions
    # whose string constants would leak as false-positive field names like
    # "INLINE_KEYBOARD").
    text = binja_utils.get_hlil_text(func.start)
    if text and "SerializableMember" not in text and "ISerializableMember" not in text:
        return [], None

    hlil_result = _extract_via_hlil(bv, func)
    if hlil_result:
        return hlil_result, "hlil"

    disasm_result = _extract_via_data_refs(bv, func)
    if disasm_result:
        return disasm_result, "disasm"

    return [], None


# ── HLIL-based extraction ─────────────────────────────────────────────────────

def _get_ptr_value(expr):
    """Get address from HLIL_CONST_PTR or HLIL_CONST. Always returns int or None."""
    for attr in ("constant", "value"):
        try:
            val = getattr(expr, attr)
            if val is not None:
                return int(val)
        except (AttributeError, ValueError, TypeError):
            continue
    return None


# Operations that carry an rhs expression. Built dynamically because
# HLIL_VAR_DECLARE_WITH_INIT was only added in later Binary Ninja versions —
# older releases use HLIL_VAR_INIT for combined declare+init instead.
_ASSIGN_OPS = {
    HighLevelILOperation.HLIL_ASSIGN,
    HighLevelILOperation.HLIL_VAR_INIT,
}
_dwi = getattr(HighLevelILOperation, "HLIL_VAR_DECLARE_WITH_INIT", None)
if _dwi is not None:
    _ASSIGN_OPS.add(_dwi)


def _init_src(instr):
    """Return the source (rhs) expression from assign-like HLIL instructions.

    Handles plain assignments (``a = b``) as well as variable declarations with
    an initialiser (``int x = 5``).  Lazy / thread-safe initialiser functions
    declare every local up-front, so their field-name / strlen / vtable stores
    surface as VAR_DECLARE_WITH_INIT (or VAR_INIT in older BN) rather than
    ASSIGN — skipping them drops every field.
    """
    op = instr.operation
    if op in _ASSIGN_OPS:
        return instr.src
    return None


def _extract_via_hlil(bv, func):
    """Walk HLIL instructions sequentially, pairing name → type → flag."""
    if func is None or func.hlil is None:
        return []

    fields = []
    pending_name = None
    pending_type = None
    pending_flag = None

    try:
        instructions = list(func.hlil.instructions)
    except Exception:
        return []

    for instr in instructions:
        # ── Helper call: infer type from callee body + flag from last arg ──
        # Some functions register fields via per-type helpers instead of
        # storing the vtable inline:
        #   var_48 = "fieldName"
        #   j_sub_XXX(&result[off], result, &var_48, flag)
        if instr.operation == HighLevelILOperation.HLIL_CALL:
            callee_ea = _get_ptr_value(getattr(instr, "dest", None))
            if callee_ea:
                raw_t = _infer_helper_type(bv, callee_ea)
                # Only set type from a CALL when we don't already have one.
                # An inline vtable assignment (set earlier in the loop) is
                # always the correct field type.  A subsequent CALL to a
                # sub-initializer (e.g. UserAgent ctor inside SessionInit)
                # must NOT overwrite it with the first SerializableMember<T>
                # it finds in the callee body.
                if raw_t and not pending_type:
                    pending_type = raw_t
                params = getattr(instr, "params", None) or []
                if len(params) >= 4 and pending_name is not None and pending_type is not None:
                    flag_val = _get_ptr_value(params[-1])
                    if flag_val in (1, 2):
                        pending_flag = flag_val
            continue

        src = _init_src(instr)
        if src is None:
            continue

        # ── Flag: const 1 (required) or 2 (optional) ──
        # Only accept once we already have BOTH a pending name and type, so a
        # string-length store (which always precedes the type vtable) can never
        # be mistaken for a flag — even for 1-2 char field names whose strlen
        # is 1 or 2.
        if src.operation == HighLevelILOperation.HLIL_CONST:
            val = _get_ptr_value(src)
            if val in (1, 2) and pending_name is not None and pending_type is not None:
                pending_flag = val
                continue

        # ── Constant pointer: could be string or vtable ──
        if src.operation in (HighLevelILOperation.HLIL_CONST_PTR,
                             HighLevelILOperation.HLIL_CONST,
                             HighLevelILOperation.HLIL_CONST_DATA):
            addr = _get_ptr_value(src)
            if not addr:
                continue

            # Check symbol FIRST. Vtables carry named symbols whose leading
            # bytes may coincidentally form a short ASCII string terminated by
            # a null (e.g. the SerializableMember<std::string> vtable at
            # 0x180ca1208 starts with "cH\0"). Reading such an address as a
            # cstring before consulting the symbol table mis-identifies the
            # vtable as a field name. String literals in .rdata have no
            # Symbol object, so this only short-circuits real symbols.
            sym_name = binja_utils.get_symbol_name_at(bv, addr)
            if sym_name:
                # SerializableMember<T,...,Owner> vtable → field type
                if common.is_serializable_member_vtable(sym_name):
                    raw_t = _extract_type_from_vtable_name(sym_name)
                    if raw_t:
                        pending_type = raw_t
                # ISerializableMember interface / any other symbol → skip
                continue

            # No symbol → try interpreting as a string literal (field name)
            name = binja_utils.read_cstring(bv, addr)
            if name and common.is_valid_field_name(name):
                if pending_name is not None:
                    fields.append(_make_field(pending_name, pending_type, pending_flag))
                pending_name = name
                pending_type = None
                pending_flag = None
                continue

        # ── Fallback: check instruction text for SerializableMember ──
        line = str(instr)
        if "SerializableMember<" in line or "?$SerializableMember@" in line:
            raw_t = _extract_type_from_text(line)
            if raw_t and not pending_type:
                pending_type = raw_t

    # Emit last field
    if pending_name is not None:
        fields.append(_make_field(pending_name, pending_type, pending_flag))

    return fields


def _is_serializable_member_vtable(name):
    """True if name is a concrete SerializableMember vtable (not ISerializableMember)."""
    return common.is_serializable_member_vtable(name)


def _extract_type_from_vtable_name(name):
    """Extract T from 'Serialization::SerializableMember<T, ...>::vftable...'

    Also handles MSVC mangled form ``?$SerializableMember@<T>@...`` by
    delegating to :func:`_extract_type_from_mangled`.
    """
    # Try mangled form first if present
    if "?$SerializableMember@" in name:
        return _extract_type_from_mangled(name)

    idx = name.find("SerializableMember<")
    if idx == -1:
        return None
    # Skip ISerializableMember
    if idx > 0 and name[idx - 1] == "I":
        next_idx = name.find("SerializableMember<", idx + 1)
        if next_idx == -1:
            return None
        idx = next_idx
    start = idx + len("SerializableMember<")
    return template_parser._extract_first_tpl_arg(name[start:])


def _extract_type_from_text(line):
    """Fallback: extract type from HLIL instruction text.

    Delegates to _extract_type_from_vtable_name which correctly skips
    ISerializableMember occurrences by checking for a preceding 'I' character
    — necessary because BN decorates vtable references with a
    ``{for `...ISerializableMember<...>'}`` suffix.
    """
    return _extract_type_from_vtable_name(line)


# ── Fallback: instruction text scan ───────────────────────────────────────────

def _extract_via_data_refs(bv, func):
    """
    Fallback: scan HLIL instruction text for string literals that look like
    field names. No type or flag info.
    """
    if func is None or func.hlil is None:
        return []

    seen = set()
    fields = []

    for instr in func.hlil.instructions:
        line = str(instr)
        for m in re.finditer(r'"([A-Za-z_][A-Za-z0-9_\-]{0,63})"', line):
            name = m.group(1)
            if name in seen:
                continue
            if "vftable" in name.lower():
                continue
            seen.add(name)
            fields.append(_make_field(name, None, None))

    return fields


# ── Field construction ────────────────────────────────────────────────────────

def _make_field(name, raw_type, flag):
    """Build a structured field dict with decomposed type info.

    The ``type`` key nests all type-related attributes::

        "type": {
            "full":      "std::optional<bool>",   # normalised full type
            "name":      "bool",                  # base type after unwrapping
            "optional":  true,                    # wrapped in std::optional
            "array":     false,                   # wrapped in std::vector
            "map":       false,                   # is std::map / unordered_map
            "map_key":   null,                    # map key type (if map)
            "map_value": null,                    # map value type (if map)
        }
    """
    if raw_type:
        decomposed = type_parser.decompose_type(raw_type)
        type_info = {
            "full": decomposed["full_type"],
            "name": decomposed["type"],
            "optional": decomposed["optional"],
            "array": decomposed["array"],
            "map": decomposed["map"],
            "map_key": decomposed["map_key"],
            "map_value": decomposed["map_value"],
        }
    else:
        type_info = {
            "full": "unknown",
            "name": "unknown",
            "optional": False,
            "array": False,
            "map": False,
            "map_key": None,
            "map_value": None,
        }

    return {
        "name": name,
        "type": type_info,
        "required": (flag != 2) if flag is not None else True,
    }
