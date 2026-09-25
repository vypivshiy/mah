"""
Symbol indexing and initializer lookup logic.
Global state is confined to this module only.
"""
import ida_name
import idaapi
import idautils
import ida_funcs
import logging

import common
import ida_utils
import template_parser
import field_extractor

logger = logging.getLogger(__name__)

_SMEMBER_INDEX = None   # full_name (owner) -> sorted [(ea, raw_type)]
_VTABLE_INDEX = None    # full_name -> ea
_ISER_VTABLE = idaapi.BADADDR


def _build_index():
    global _SMEMBER_INDEX, _VTABLE_INDEX, _ISER_VTABLE

    smember = {}   # owner -> [(ea, raw_type)]
    vtables = {}   # full_name -> ea

    count = ida_name.get_nlist_size()
    logger.info("Indexing %d symbols...", count)

    for i in range(count):
        ea = ida_name.get_nlist_ea(i)
        mangled = ida_name.get_nlist_name(i)

        # Quick pre-filter: MSVC vftable mangling always starts with ??_7
        if not mangled.startswith("??_7"):
            continue

        dem = ida_utils._demangle(mangled)

        # Determine vftable suffix used in this IDB
        # IDA long-form: ::`vftable'   IDA short-form: ::vftable
        is_vtable = dem.endswith("::`vftable'") or dem.endswith("::vftable")

        if not is_vtable:
            continue

        if "SerializableMember<" in dem:
            if "meta_ptr" in dem:
                continue
            # Capture ISerializableMember vftable (no template owner arg for Packets)
            if "ISerializableMember<" in dem:
                if _ISER_VTABLE == idaapi.BADADDR:
                    _ISER_VTABLE = ea
                continue
            # Regular SerializableMember<T,...,Owner>
            owner = template_parser._extract_member_last_arg(dem)
            if owner:
                owner = ida_utils._normalize_name(owner)   # strip struct/class/const
                if ida_utils._is_api_oneme_name(owner):
                    raw_t = template_parser._extract_member_first_arg(dem)
                    if raw_t:
                        smember.setdefault(owner, []).append((ea, raw_t))
        else:
            # Strip vftable suffix to get type full_name
            if dem.endswith("::`vftable'"):
                full_name = dem[:-len("::`vftable'")]
            else:
                full_name = dem[:-len("::vftable")]
            full_name = ida_utils._normalize_name(full_name)   # strip leading "const " etc.
            if ida_utils._is_api_oneme_name(full_name):
                vtables[full_name] = ea

    # Sort each SerializableMember list by address
    for owner in smember:
        smember[owner].sort(key=lambda x: x[0])

    _SMEMBER_INDEX = smember
    _VTABLE_INDEX = vtables


def _ensure_index():
    global _SMEMBER_INDEX
    if _SMEMBER_INDEX is None:
        _build_index()


def find_initializer_ea(full_name):
    """
    Find the best initializer function for full_name:
      1. Look up full_name in vtable index.
      2. Collect all functions that xref to that vftable.
      3. Prefer functions that also xref ISerializableMember vftable.
      4. Break ties by function size (larger = richer initializer).
    Returns EA or None.
    """
    _ensure_index()
    vtable_ea = _VTABLE_INDEX.get(full_name, idaapi.BADADDR)
    if vtable_ea == idaapi.BADADDR:
        return None

    candidates = {}  # start_ea -> func

    for xref in idautils.XrefsTo(vtable_ea, 0):
        func = ida_funcs.get_func(xref.frm)
        if func and func.start_ea not in candidates:
            candidates[func.start_ea] = func

    if not candidates:
        return None

    # Exclude mega-functions (aggregate handlers that xref many types at once).
    trimmed = {ea: f for ea, f in candidates.items() if f.size() <= common.MAX_INIT_SIZE}
    if trimmed:
        candidates = trimmed

    # Build set of functions that reference ISerializableMember::vftable
    iser_funcs = set()
    if _ISER_VTABLE != idaapi.BADADDR:
        for xr in idautils.XrefsTo(_ISER_VTABLE, 0):
            f = ida_funcs.get_func(xr.frm)
            if f and f.start_ea in candidates:
                iser_funcs.add(f.start_ea)

    def score(ea):
        m = _candidate_metrics(ea, full_name)
        return (
            1 if m["first_self_vtable"] > 0 else 0,
            1 if m["self_vtable"] > 0 else 0,
            1 if m["member_lines"] > 0 else 0,
            1 if m["name_lines"] > 0 else 0,
            1 if ea in iser_funcs else 0,
            -m["size"],
        )

    best_ea = max(candidates.keys(), key=score)
    return best_ea


def _candidate_metrics(func_ea, full_name):
    func = ida_funcs.get_func(func_ea)
    size = func.size() if func else 0
    self_vtable_tokens = common._vtable_tokens(full_name)
    text = ida_utils.decompile_text(func_ea)

    member_lines = 0
    name_lines = 0
    self_vtable_lines = 0
    first_self_vtable = 0

    if text:
        for idx, line in enumerate(text.splitlines()):
            if "SerializableMember<" in line and full_name in line and common._line_has_vftable(line):
                member_lines += 1
            if field_extractor._extract_name_from_line(line):
                name_lines += 1
            if any(tok in line for tok in self_vtable_tokens):
                self_vtable_lines += 1
                if idx <= 24:
                    first_self_vtable = 1

    return {
        "member_lines": member_lines,
        "name_lines": name_lines,
        "self_vtable": self_vtable_lines,
        "first_self_vtable": first_self_vtable,
        "size": size,
    }
