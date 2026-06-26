"""
Symbol indexing and initializer lookup logic — ported from IDA dumper.
Uses Binary Ninja's symbol/data-var API instead of IDA's name list.
"""
import re
import logging

from binaryninja import SymbolType

import common
import binja_utils
import template_parser

logger = logging.getLogger(__name__)

_SMEMBER_INDEX = None   # owner_full_name -> [(ea, raw_type)]
_VTABLE_INDEX = None    # full_name -> vtable_ea
_ISER_VTABLE = None     # shared ISerializableMember vtable address


def _ensure_index():
    global _SMEMBER_INDEX
    if _SMEMBER_INDEX is None:
        _build_index()


def _build_index():
    global _SMEMBER_INDEX, _VTABLE_INDEX, _ISER_VTABLE

    bv = binja_utils.get_bv()
    smember = {}
    vtables = {}

    # Iterate all data symbols. In BN, vtables are data symbols with
    # demangled names containing ::`vftable' or ::vftable.
    sym_count = 0
    seen = 0
    total = len(bv.symbols)
    logger.info("  scanning %d symbol buckets...", total)
    for name, sym_list in bv.symbols.items():
        for sym in sym_list:
            seen += 1
            if seen % 20000 == 0:
                logger.info("  [index] %d/%d symbols...", seen, total)
            if sym.type != SymbolType.DataSymbol:
                continue
            full = sym.full_name
            if "`vftable'" not in full and "::vftable" not in full:
                continue

            sym_count += 1
            ea = sym.address

            if common.is_iserializable_member_vtable(full):
                if "meta_ptr" in full:
                    continue
                if _ISER_VTABLE is None:
                    _ISER_VTABLE = ea
                continue

            if common.is_serializable_member_vtable(full):
                if "meta_ptr" in full:
                    continue
                # Regular SerializableMember<T,...,Owner>
                owner = template_parser._extract_member_last_arg(full)
                if owner:
                    owner = binja_utils.normalize_name(owner)
                    if binja_utils.is_api_oneme_name(owner):
                        raw_t = template_parser._extract_member_first_arg(full)
                        if raw_t:
                            smember.setdefault(owner, []).append((ea, raw_t))
            else:
                # Type vtable — strip suffix to get full_name
                fn = common.strip_vftable_suffix(full)
                fn = binja_utils.normalize_name(fn)
                if binja_utils.is_api_oneme_name(fn):
                    vtables[fn] = ea

    logger.info("  [index] scanned %d symbols", seen)

    # Sort each SerializableMember list by address
    for owner in smember:
        smember[owner].sort(key=lambda x: x[0])

    _SMEMBER_INDEX = smember
    _VTABLE_INDEX = vtables

    logger.info("Indexed %d vtable symbols, %d types, %d SerializableMember owners",
                sym_count, len(vtables), len(smember))


def find_initializer_ea(full_name):
    """
    Find the best initializer function for full_name:
      1. Look up full_name in vtable index.
      2. Collect all functions that code-xref to that vftable.
      3. Prefer functions that also xref ISerializableMember vftable.
      4. Break ties by scoring (member lines, name lines, early self-vtable ref).
    Returns function address or None.
    """
    _ensure_index()
    bv = binja_utils.get_bv()

    vtable_ea = _VTABLE_INDEX.get(full_name)
    if vtable_ea is None:
        return None

    candidates = binja_utils.get_code_xref_functions(bv, vtable_ea)
    if not candidates:
        return None

    # Exclude mega-functions
    trimmed = {f for f in candidates if f.total_bytes <= common.MAX_INIT_SIZE}
    if trimmed:
        candidates = trimmed

    # Build set of functions that reference ISerializableMember vftable
    iser_funcs = set()
    if _ISER_VTABLE is not None:
        iser_funcs = binja_utils.get_code_xref_functions(bv, _ISER_VTABLE)

    def score(func):
        m = _candidate_metrics(func, full_name)
        return (
            1 if m["first_self_vtable"] > 0 else 0,
            1 if m["self_vtable"] > 0 else 0,
            1 if m["member_lines"] > 0 else 0,
            1 if m["name_lines"] > 0 else 0,
            1 if func in iser_funcs else 0,
            -m["size"],
        )

    best = max(candidates, key=score)
    return best.start


def _candidate_metrics(func, full_name):
    size = func.total_bytes
    self_vtable_tokens = common._vtable_tokens(full_name)
    text = binja_utils.get_hlil_text(func.start)

    member_lines = 0
    name_lines = 0
    self_vtable_lines = 0
    first_self_vtable = 0

    if text:
        for idx, line in enumerate(text.splitlines()):
            if "SerializableMember<" in line and full_name in line and common._line_has_vftable(line):
                member_lines += 1
            if '"' in line:
                if re.search(r'"[A-Za-z_][\w\-]{0,63}"', line):
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
