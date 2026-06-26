"""
Orchestration module — full discovery pipeline using Binary Ninja API.

Collects packets/events via string scanning, indexes RTTI vtables,
analyzes serializable types via HLIL, runs BFS over model references,
handles polymorphic types, and saves structured JSON.
"""
import json
import os
import time
import logging

import common
import binja_utils
import template_parser
import symbol_index
import field_extractor
import type_parser

logger = logging.getLogger(__name__)

_TYPE_FIXES = {}
_FIELD_REMOVES = []


def _load_type_fixes():
    global _TYPE_FIXES, _FIELD_REMOVES
    try:
        import PATCHES
        for full_name, fields in PATCHES.PATCHES.items():
            for field_name, new_type in fields.items():
                _TYPE_FIXES["{}::{}".format(full_name, field_name)] = new_type
        _FIELD_REMOVES = list(PATCHES.REMOVES)
        logger.info("[Patches] Loaded %d type fix(es), %d field remove(s)",
                    len(_TYPE_FIXES), len(_FIELD_REMOVES))
    except ImportError:
        logger.info("[Patches] No PATCHES.py found, skipping")
    except Exception as e:
        logger.warning("[Patches] Failed to load PATCHES.py: %s", e)


def _apply_field_fixes(full_name, fields):
    if not _TYPE_FIXES and not _FIELD_REMOVES:
        return fields
    fixed = []
    for f in fields:
        key = "{}::{}".format(full_name, f["name"])
        if key in _FIELD_REMOVES:
            continue
        if key in _TYPE_FIXES:
            f = dict(f)
            decomposed = type_parser.decompose_type(_TYPE_FIXES[key])
            f["type"] = {
                "full": decomposed["full_type"],
                "name": decomposed["type"],
                "optional": decomposed["optional"],
                "array": decomposed["array"],
                "map": decomposed["map"],
                "map_key": decomposed["map_key"],
                "map_value": decomposed["map_value"],
                "polymorphic": decomposed["polymorphic"],
                "polymorphic_base": decomposed["polymorphic_base"],
            }
        fixed.append(f)
    return fixed


if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(message)s")


# ── String iteration ──────────────────────────────────────────────────────────

def _iter_strings(bv):
    """Yield (value: str, address: int) for all strings in the binary."""
    for s in bv.get_strings():
        try:
            raw = bv.read(s.start, s.length)
        except Exception:
            continue
        try:
            val = raw.decode("ascii", errors="ignore")
        except Exception:
            continue
        if val:
            yield val, s.start


# ── Packet / event collection ─────────────────────────────────────────────────

def collect_common_packets(bv):
    """Scan strings for CommonPacket<N, Req, Resp, Flags>."""
    results = {}
    for val, _addr in _iter_strings(bv):
        m = common.COMMON_PACKET_RE.search(val)
        if not m:
            continue
        opcode = int(m.group(1))
        if opcode in results:
            continue
        req_full = m.group(2)
        resp_full = m.group(3)
        results[opcode] = {
            "opcode": opcode,
            "request_full_name": req_full,
            "request_kind": req_full.rsplit("::", 1)[-1],
            "response_full_name": resp_full,
            "response_kind": resp_full.rsplit("::", 1)[-1],
        }
    return sorted(results.values(), key=lambda x: x["opcode"])


def collect_common_events(bv):
    """Scan strings for CommonEvent<N, Req, RespLike>."""
    results = {}
    for val, _addr in _iter_strings(bv):
        m = common.COMMON_EVENT_PREFIX_RE.search(val)
        if not m:
            continue
        tail = val[m.end():]
        end = tail.find(">::")
        if end == -1:
            continue
        args = template_parser._extract_tpl_args(tail[:end])
        if len(args) < 3:
            continue
        try:
            opcode = int(args[0].strip())
        except Exception:
            continue
        if opcode in results:
            continue
        req_name = binja_utils.normalize_name(args[1])
        resp_name = binja_utils.normalize_name(args[2])
        for pfx in ("struct ", "class "):
            if req_name.startswith(pfx):
                req_name = req_name[len(pfx):]
            if resp_name.startswith(pfx):
                resp_name = resp_name[len(pfx):]
        results[opcode] = {
            "opcode": opcode,
            "request_full_name": req_name,
            "request_kind": req_name.split("::")[-1],
            "response_full_name": resp_name,
            "response_kind": resp_name.split("::")[-1],
        }
    return sorted(results.values(), key=lambda x: x["opcode"])


# ── Special factory-registered packets ────────────────────────────────────────

def collect_special_factory_packets(bv):
    """Find packets registered via Creator<> factory rather than CommonPacket."""
    from binaryninja import SymbolType

    results = {}
    total = len(bv.symbols)
    seen = 0
    for name, sym_list in bv.symbols.items():
        seen += 1
        if seen % 20000 == 0:
            logger.info("  [special] %d/%d symbols...", seen, total)
        for sym in sym_list:
            if sym.type != SymbolType.DataSymbol:
                continue
            full = sym.full_name
            if "`vftable'" not in full and "::vftable" not in full:
                continue
            if "Creator<" not in full:
                continue
            if "Api::OneMe::Packets::" not in full:
                continue
            if "BaseEvent" not in full and "BasePacket" not in full:
                continue

            msg_type, base_type = _parse_creator_vtable(full)
            if not msg_type or not base_type:
                continue

            ea = sym.address
            for func in binja_utils.get_code_xref_functions(bv, ea):
                opcode = _extract_opcode_from_func(bv, func)
                if opcode is None or opcode in results:
                    continue
                results[opcode] = {
                    "opcode": opcode,
                    "full_name": msg_type,
                    "base_kind": base_type.split("::")[-1],
                    "factory_ea": func.start,
                }

    return sorted(results.values(), key=lambda x: x["opcode"])


def _parse_creator_vtable(dem):
    idx = dem.find("Creator<")
    if idx == -1:
        return None, None
    inner = dem[idx + len("Creator<"):]
    args = template_parser._extract_tpl_args(inner)
    if len(args) < 2:
        return None, None
    return binja_utils.normalize_name(args[0]), binja_utils.normalize_name(args[1])


def _extract_opcode_from_func(bv, func):
    """Try to extract opcode from factory function via HLIL."""
    text = binja_utils.get_hlil_text(func.start)
    for rx in (common._CREATOR_OPCODE_RE_1,
               common._CREATOR_OPCODE_RE_2,
               common._CREATOR_OPCODE_RE_3,
               common._CREATOR_OPCODE_RE_4):
        m = rx.search(text)
        if m:
            try:
                val = int(m.group(1))
                if 0 < val <= 0xFFFF:
                    return val
            except Exception:
                pass

    # Fallback: scan first 20 HLIL instructions for small integer constants
    # assigned via BN's .w/.d suffixes or explicit store patterns.
    if func.hlil:
        for i, instr in enumerate(func.hlil.instructions):
            if i >= 20:
                break
            line = str(instr).strip()
            m = common._CREATOR_OPCODE_RE_4.search(line)
            if m:
                val = int(m.group(1))
                if 0 < val <= 0xFFFF:
                    return val
    return None


# ── Uppercase enum extraction ─────────────────────────────────────────────────

def extract_uppercase_enums(bv):
    """Scan the on-disk DLL for enum-like uppercase string constants."""
    filepath = bv.file.original_filename or ""
    if not filepath:
        filepath = bv.file.filename or ""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        logger.warning("Failed to read DLL for enum scan: %s", e)
        return []

    MIN_LEN, MAX_LEN = 3, 64
    seen = set()
    results = []
    i = 0
    n = len(data)

    while i < n:
        b = data[i]
        if b not in common._UPPER_ENUM_CHARS:
            i += 1
            continue
        end = i
        while end < n and data[end] in common._UPPER_ENUM_CHARS:
            end += 1
        length = end - i
        if length > MIN_LEN and length <= MAX_LEN:
            if end < n and data[end] == 0:
                s = data[i:end].decode("ascii")
                if s not in seen and common._is_likely_enum(s):
                    seen.add(s)
                    results.append(s)
        i = end if end > i else i + 1

    results.sort()
    return results


# ── Per-type analysis ─────────────────────────────────────────────────────────

def analyze_serializable_type(full_name, role):
    """
    Analyze a serializable type and extract its fields.
    Returns dict with name, offset, fields, warn.
    """
    kind = full_name.split("::")[-1]

    if kind in common._EMPTY_NAMES:
        return {
            "name": full_name,
            "offset": None,
            "fields": [],
            "warn": None,
        }

    init_ea = symbol_index.find_initializer_ea(full_name)
    fields = []
    method = None
    bv = binja_utils.get_bv()

    if init_ea is not None:
        func = binja_utils.get_function_at(bv, init_ea)
        if func:
            fields, method = field_extractor.extract_fields_from_func(bv, func)

    fields = _apply_field_fixes(full_name, fields)

    warn = None
    if not fields:
        if "Polymorphic" not in full_name:
            warn = "no data found"
    elif method == "disasm":
        warn = "names via data-refs (no type/flag info)"

    offset = None
    if init_ea is not None and binja_utils.IMAGE_BASE is not None:
        offset = "0x{:x}".format(init_ea - binja_utils.IMAGE_BASE)

    return {
        "name": full_name,
        "offset": offset,
        "fields": fields,
        "warn": warn,
    }


# ── Model collection (BFS) ────────────────────────────────────────────────────

def _api_model_refs_in_fields(fields):
    """Yield full_names of Api::OneMe::* structs referenced in field types."""
    for f in fields:
        ti = f.get("type", {})
        t = ti.get("name") or ""
        for m in common._API_MODEL_REF_RE.finditer(t):
            yield "Api::OneMe::{}::{}".format(m.group(1), m.group(2))
        # Also check map_key/map_value
        for key in ("map_key", "map_value"):
            v = ti.get(key)
            if v:
                for m in common._API_MODEL_REF_RE.finditer(v):
                    yield "Api::OneMe::{}::{}".format(m.group(1), m.group(2))


def _iter_type_refs_from_entries(entries):
    for item in entries:
        for side in ("request", "response"):
            info = item.get(side)
            if not info:
                continue
            for ref in _api_model_refs_in_fields(info.get("fields", [])):
                yield ref


def _collect_models_bfs(initial_refs):
    queue = set(initial_refs)
    visited = set()
    models = {}
    t0 = time.time()

    while queue:
        full_name = queue.pop()
        if full_name in visited:
            continue
        visited.add(full_name)

        if len(visited) % 25 == 0:
            logger.info("  [bfs] %d visited, %d pending...", len(visited), len(queue))

        info = analyze_serializable_type(full_name, "model")
        for ref in _api_model_refs_in_fields(info["fields"]):
            if ref not in visited:
                queue.add(ref)

        models[full_name] = {
            "name": info["name"],
            "offset": info["offset"],
            "fields": info["fields"],
            "warn": info["warn"],
        }

    logger.info("  [bfs] complete: %d models in %.1fs", len(models), time.time() - t0)
    return sorted(models.values(), key=lambda m: m["name"])


def collect_models_from_sections(*sections):
    queue = set()
    for entries in sections:
        for ref in _iter_type_refs_from_entries(entries):
            queue.add(ref)
    return _collect_models_bfs(queue)


# ── Inheritance / polymorphic types ───────────────────────────────────────────

def _analyze_inheritance_group(owner_full_name):
    """
    For an owner type used in Polymorphic<>, discover all derived classes
    that register SerializableMember entries under this owner.
    """
    symbol_index._ensure_index()

    short_name = owner_full_name.split("::")[-1]
    parts = owner_full_name.split("::")
    ns_parts = parts[:-1]
    derived_types = set()

    if ns_parts:
        ns_prefix = "::".join(ns_parts) + "::"
        for full_name in symbol_index._VTABLE_INDEX:
            if full_name == owner_full_name:
                continue
            if not full_name.startswith(ns_prefix):
                continue
            full_short = full_name.split("::")[-1]
            if full_short == short_name:
                continue
            if full_short.endswith("Attachment") or full_short.endswith("EventParams"):
                derived_types.add(full_name)

    if not derived_types:
        bv = binja_utils.get_bv()
        sm_entries = symbol_index._SMEMBER_INDEX.get(owner_full_name, [])
        for vft_ea, raw_type in sm_entries:
            text = binja_utils.get_hlil_text(vft_ea)
            if not text:
                # Try to get the function containing this vft_ea xref
                funcs = binja_utils.get_code_xref_functions(bv, vft_ea)
                for f in funcs:
                    text = binja_utils.get_hlil_text(f.start)
                    break
            if not text:
                continue
            for line in text.splitlines():
                if "SerializableMember<" not in line:
                    continue
                if "ISerializableMember<" in line:
                    continue
                if "vftable" not in line:
                    continue
                idx = line.find("SerializableMember<")
                dem = line[idx:]
                owner = template_parser._extract_member_last_arg(dem)
                if owner:
                    owner = binja_utils.normalize_name(owner)
                    if owner != owner_full_name and binja_utils.is_api_oneme_name(owner):
                        derived_types.add(owner)

    if not derived_types:
        return {}

    result = {}
    for class_name in sorted(derived_types):
        if class_name in result:
            continue
        if class_name not in symbol_index._VTABLE_INDEX:
            continue
        info = analyze_serializable_type(class_name, "model")
        result[class_name] = info

    base_info = analyze_serializable_type(owner_full_name, "model")
    result[owner_full_name] = base_info
    return result


def collect_inheritance_models(models, packets):
    """
    For types used in Polymorphic<>, discover derived types and group them.
    Returns list of {name, offset, variants: [{name, fields}]}.
    """
    polymorphic_bases = set()

    def scan_fields(fields):
        for f in fields:
            ti = f.get("type", {})
            if not ti.get("polymorphic"):
                continue
            base = ti.get("polymorphic_base")
            if base and binja_utils.is_api_oneme_name(base):
                polymorphic_bases.add(base)

    for model in models:
        scan_fields(model.get("fields", []))
    for pkt in packets:
        for side in ("request", "response"):
            info = pkt.get(side)
            if info:
                scan_fields(info.get("fields", []))

    if not polymorphic_bases:
        return []

    logger.info("[Inheritance] Scanning %d polymorphic base type(s)...",
                len(polymorphic_bases))

    result = []
    for base_name in sorted(polymorphic_bases):
        classes = _analyze_inheritance_group(base_name)
        if not classes:
            continue

        base_info = classes.get(base_name)
        base_fields = base_info["fields"] if base_info else []

        derived_names = [cn for cn in classes if cn != base_name]
        if not derived_names:
            continue

        base_short = base_name.split("::")[-1]
        logger.info("  %s -> %s", base_short, ", ".join(
            d.split("::")[-1] for d in derived_names))

        variants = []
        # Base first
        if base_info:
            variants.append({
                "name": base_name,
                "fields": base_info["fields"],
            })

        for class_name in sorted(derived_names):
            info = classes[class_name]
            merged = list(base_fields) + info["fields"]
            seen = set()
            deduped = []
            for f in merged:
                if f["name"] not in seen:
                    seen.add(f["name"])
                    deduped.append(f)
            variants.append({
                "name": class_name,
                "fields": deduped,
            })

        result.append({
            "name": base_name,
            "offset": base_info["offset"] if base_info else None,
            "variants": variants,
        })

    logger.info("  Found %d polymorphic group(s), %d total variant(s)",
                len(result), sum(len(g["variants"]) for g in result))
    return result


# ── Output helpers ────────────────────────────────────────────────────────────

def _fields_str(info):
    if not info["fields"]:
        return "(empty)"
    return ", ".join(
        "{}:{}{}".format(
            f["name"],
            f["type"]["name"],
            "?" if f["type"].get("optional") or not f.get("required", True) else ""
        )
        for f in info["fields"]
    )


def _build_side_record(info):
    return {
        "offset": info["offset"],
        "name": info["name"],
        "fields": info["fields"],
        "warn": info["warn"],
    }


# ── Analysis runners ──────────────────────────────────────────────────────────

def _analyze_packets(packets):
    logger.info("")
    logger.info("[Packets] Analyzing RPC packets...")
    logger.info("-" * 72)
    out = []
    warn_count = 0
    total = len(packets)
    t0 = time.time()

    for idx, p in enumerate(packets, 1):
        opcode = p["opcode"]
        req_info = analyze_serializable_type(p["request_full_name"], "request")
        resp_info = analyze_serializable_type(p["response_full_name"], "response")

        if req_info["warn"] or resp_info["warn"]:
            warn_count += 1

        req_short = p["request_full_name"].replace("Api::OneMe::Packets::", "")
        resp_short = p["response_full_name"].replace("Api::OneMe::Packets::", "")

        logger.info("[%d/%d] [%3d] req  %s -> %s%s", idx, total, opcode, req_short,
                    _fields_str(req_info),
                    "  WARN: " + req_info["warn"] if req_info["warn"] else "")
        logger.info("      resp %s -> %s%s", resp_short,
                    _fields_str(resp_info),
                    "  WARN: " + resp_info["warn"] if resp_info["warn"] else "")

        out.append({
            "opcode": opcode,
            "request": _build_side_record(req_info),
            "response": _build_side_record(resp_info),
        })

    logger.info("-" * 72)
    logger.info("[Packets] done: %d analyzed (%d ok, %d warn) in %.1fs",
                total, total - warn_count, warn_count, time.time() - t0)
    return out, warn_count


def _analyze_duplex_entries(entries, section_name):
    logger.info("")
    logger.info("[%s] Analyzing %s...", section_name, section_name)
    logger.info("-" * 72)
    out = []
    warn_count = 0
    total = len(entries)
    t0 = time.time()

    for idx, item in enumerate(entries, 1):
        opcode = item["opcode"]
        req_info = analyze_serializable_type(item["request_full_name"], "request")
        resp_info = analyze_serializable_type(item["response_full_name"], "response")

        if req_info["warn"] or resp_info["warn"]:
            warn_count += 1

        req_short = item["request_full_name"].replace("Api::OneMe::Packets::", "")
        resp_short = item["response_full_name"].replace("Api::OneMe::Packets::", "")

        logger.info("[%d/%d] [%3d] req  %s -> %s%s", idx, total, opcode, req_short,
                    _fields_str(req_info),
                    "  WARN: " + req_info["warn"] if req_info["warn"] else "")
        logger.info("      resp %s -> %s%s", resp_short,
                    _fields_str(resp_info),
                    "  WARN: " + resp_info["warn"] if resp_info["warn"] else "")

        out.append({
            "opcode": opcode,
            "request": _build_side_record(req_info),
            "response": _build_side_record(resp_info),
        })

    logger.info("-" * 72)
    logger.info("[%s] done: %d analyzed (%d ok, %d warn) in %.1fs",
                section_name, total, total - warn_count, warn_count, time.time() - t0)
    return out, warn_count


def _find_payload_type_for_special(full_name):
    symbol_index._ensure_index()
    pkt_vtable_ea = symbol_index._VTABLE_INDEX.get(full_name)
    if pkt_vtable_ea is None:
        return None

    best_name = None
    best_dist = common.PAYLOAD_VTABLE_DISTANCE
    for name, ea in symbol_index._VTABLE_INDEX.items():
        if name == full_name:
            continue
        if name not in symbol_index._SMEMBER_INDEX or not symbol_index._SMEMBER_INDEX[name]:
            continue
        dist = abs(ea - pkt_vtable_ea)
        if dist < best_dist:
            best_dist = dist
            best_name = name
    return best_name


def _find_payload_by_field_name(bv, field_name):
    """Fallback payload finder: locate the initializer that references a known
    field-name string and contains a SerializableMember registration.

    Used for special packets (e.g. Ping opcode=1) whose Payload type uses
    internal mangled names that vtable-proximity search can't match.
    """
    for s in bv.get_strings():
        if s.value != field_name:
            continue
        for ref in bv.get_code_refs(s.start):
            funcs = bv.get_functions_containing(ref.address)
            if not funcs:
                continue
            func = funcs[0]
            text = binja_utils.get_hlil_text(func.start)
            if text and "SerializableMember" in text:
                return func
    return None


# Stable field names for special packets that vtable-proximity can't resolve.
# {opcode: field_name}
_SPECIAL_PAYLOAD_FIELD_HINTS = {
    1: "interactive",      # Ping
}


def _analyze_special_packets(entries):
    logger.info("")
    logger.info("[Special] Analyzing factory-registered packets...")
    logger.info("-" * 72)
    out = []
    total = len(entries)
    t0 = time.time()
    for idx, item in enumerate(entries, 1):
        bv = binja_utils.get_bv()
        offset = None
        if item.get("factory_ea") is not None and binja_utils.IMAGE_BASE:
            offset = "0x{:x}".format(item["factory_ea"] - binja_utils.IMAGE_BASE)

        logger.info("[%d/%d] [%3d] special %s (%s)",
                    idx, total,
                    item["opcode"],
                    item["full_name"].replace("Api::OneMe::Packets::", ""),
                    item["base_kind"])

        request = None
        payload_name = _find_payload_type_for_special(item["full_name"])
        if payload_name:
            payload_info = analyze_serializable_type(payload_name, "request")
            display_name = item["full_name"] + "::Payload"
            request = {
                "offset": payload_info["offset"],
                "name": display_name,
                "fields": payload_info["fields"],
                "warn": payload_info["warn"],
            }
            if payload_info["fields"]:
                logger.info("      payload %s -> %s",
                            display_name.replace("Api::OneMe::Packets::", ""),
                            _fields_str(payload_info))

        # Fallback: for stable opcodes where vtable-proximity fails, find the
        # payload initializer by searching for a known field-name string.
        if request is None and item["opcode"] in _SPECIAL_PAYLOAD_FIELD_HINTS:
            hint = _SPECIAL_PAYLOAD_FIELD_HINTS[item["opcode"]]
            func = _find_payload_by_field_name(bv, hint)
            if func is not None:
                fields, method = field_extractor.extract_fields_from_func(bv, func)
                if fields:
                    p_offset = None
                    if binja_utils.IMAGE_BASE:
                        p_offset = "0x{:x}".format(func.start - binja_utils.IMAGE_BASE)
                    display_name = item["full_name"] + "::Payload"
                    request = {
                        "offset": p_offset,
                        "name": display_name,
                        "fields": fields,
                        "warn": None,
                    }
                    logger.info("      payload %s -> %s (via field hint '%s')",
                                display_name.replace("Api::OneMe::Packets::", ""),
                                _fields_str({"fields": fields}),
                                hint)

        out.append({
            "opcode": item["opcode"],
            "kind": "special_packet",
            "name": item["full_name"],
            "base_kind": item["base_kind"],
            "offset": offset,
            "request": request,
            "response": None,
            "warn": None,
        })

    logger.info("-" * 72)
    logger.info("[Special] done: %d analyzed in %.1fs", total, time.time() - t0)
    return out


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main(bv, output_path=None):
    binja_utils.init(bv)
    image_base = bv.start
    t_start = time.time()

    app_version, build_number = binja_utils.extract_app_version(bv)
    src_file = getattr(bv.file, "original_filename", None) or getattr(bv.file, "filename", "") or "?"
    logger.info("=" * 72)
    logger.info("Binary Ninja packet dumper")
    logger.info("  file:        %s", os.path.basename(src_file))
    logger.info("  app_version: %s (build %s)", app_version or "unknown", build_number)
    logger.info("  image_base:  0x%x", image_base)
    logger.info("=" * 72)

    _load_type_fixes()

    # ── Stage 1: Collect ──
    logger.info("")
    logger.info("[Stage 1] Collecting message registrations...")
    packets = collect_common_packets(bv)
    events = collect_common_events(bv)
    special_packets = collect_special_factory_packets(bv)
    logger.info("  RPC packets:      %d", len(packets))
    logger.info("  Events:           %d", len(events))
    logger.info("  Special packets:  %d", len(special_packets))
    if not packets and not events and not special_packets:
        logger.info("  Nothing to do.")
        return

    logger.info("")
    logger.info("[Enums]   Scanning DLL for uppercase enum strings...")
    string_enums = extract_uppercase_enums(bv)
    logger.info("  Found %d enum string(s)", len(string_enums))

    # ── Index ──
    logger.info("")
    logger.info("[Index]   Building vtable symbol index (one-time)...")
    symbol_index._ensure_index()
    logger.info("  SerializableMember owners: %d", len(symbol_index._SMEMBER_INDEX))
    logger.info("  Type vftables:             %d", len(symbol_index._VTABLE_INDEX))
    iser_str = "0x{:x}".format(symbol_index._ISER_VTABLE) if symbol_index._ISER_VTABLE else "NOT FOUND"
    logger.info("  ISerializableMember vtbl:  %s", iser_str)

    # ── Stages 2-4: Analyze ──
    out_packets, warn_count = _analyze_packets(packets)
    out_events, event_warn_count = _analyze_duplex_entries(events, "Events")
    out_special_packets = _analyze_special_packets(special_packets)

    # ── Stage 5: Models ──
    logger.info("")
    logger.info("[Stage 5] Collecting nested Types:: models...")
    models = collect_models_from_sections(out_packets, out_events)
    logger.info("  Found %d model(s)", len(models))
    m_warn = sum(1 for m in models if m["warn"])
    if m_warn:
        logger.info("  Models with warnings: %d", m_warn)

    # ── Classify packets vs events ──
    seen_opcodes = {p["opcode"] for p in out_packets} | {e["opcode"] for e in out_events}
    final_packets = list(out_packets)
    final_events = list(out_events)

    for sp in out_special_packets:
        if sp["opcode"] in seen_opcodes:
            continue
        seen_opcodes.add(sp["opcode"])
        if sp["base_kind"] == "BaseEvent":
            final_events.append(sp)
        else:
            final_packets.append(sp)

    # ── Stage 5b: Polymorphic ──
    polymorphic_models = collect_inheritance_models(models, final_packets + final_events)
    if polymorphic_models:
        poly_names = set()
        for group in polymorphic_models:
            for variant in group["variants"]:
                poly_names.add(variant["name"])
        # Remove polymorphic variants from flat models
        models = [m for m in models if m["name"] not in poly_names]

        # Collect new model refs from polymorphic variants
        poly_refs = set()
        for group in polymorphic_models:
            for variant in group["variants"]:
                for ref in _api_model_refs_in_fields(variant["fields"]):
                    if ref not in {m["name"] for m in models}:
                        poly_refs.add(ref)
        if poly_refs:
            new_models = _collect_models_bfs(poly_refs)
            existing = {m["name"] for m in models}
            for m in new_models:
                if m["name"] not in existing:
                    models.append(m)
            logger.info("  Models from polymorphic variants: %d", len(new_models))

        logger.info("  Total models (after excluding derived): %d", len(models))

    final_packets.sort(key=lambda x: x["opcode"])
    final_events.sort(key=lambda x: x["opcode"])

    # ── Save JSON ──
    if output_path is None:
        out_dir = os.path.dirname(os.path.abspath(__file__))
        output_path = os.path.join(out_dir, "packets_binja.json")

    out_data = {
        "options": {
            "app_version": app_version,
            "build_number": build_number,
        },
        "packets": final_packets,
        "events": final_events,
        "models": models,
        "polymorphic_models": polymorphic_models,
        "string_enums": string_enums,
        "error": common.ERROR_PAYLOAD,
    }

    try:
        with open(output_path, "w") as f:
            json.dump(out_data, f, indent=2, ensure_ascii=False)
        logger.info("")
        logger.info("[*] JSON saved: %s", output_path)
    except Exception as e:
        logger.error("[!] Failed to save JSON: %s", e)

    total_rpc = len(out_packets)
    total_events = len(out_events)
    total_special = len(out_special_packets)
    ok_rpc = total_rpc - warn_count
    ok_events = total_events - event_warn_count

    # field quality stats
    n_fields = n_unknown = n_bogus = 0
    def _tally(fields):
        nonlocal n_fields, n_unknown, n_bogus
        for f in fields:
            n_fields += 1
            ft = f.get("type", {}).get("name", "")
            if ft == "unknown":
                n_unknown += 1
            if len(f["name"]) <= 3 and ft == "unknown":
                n_bogus += 1
    for sec in (final_packets, final_events):
        for item in sec:
            for side in ("request", "response"):
                s = item.get(side)
                if s:
                    _tally(s.get("fields", []))
    for m in models:
        _tally(m.get("fields", []))
    for g in polymorphic_models:
        for v in g.get("variants", []):
            _tally(v.get("fields", []))

    elapsed = time.time() - t_start
    logger.info("")
    logger.info("=" * 72)
    logger.info("COMPLETED in %.1fs", elapsed)
    logger.info("  packets: %d (rpc=%d ok=%d warn=%d, special=%d)",
                len(final_packets), total_rpc, ok_rpc, warn_count,
                sum(1 for sp in out_special_packets if sp["base_kind"] != "BaseEvent"))
    logger.info("  events:  %d (duplex=%d ok=%d warn=%d, special=%d)",
                len(final_events), total_events, ok_events, event_warn_count,
                sum(1 for sp in out_special_packets if sp["base_kind"] == "BaseEvent"))
    logger.info("  models:  %d (polymorphic groups=%d)", len(models), len(polymorphic_models))
    logger.info("  fields:  %d total, %d unknown, %d bogus-short", n_fields, n_unknown, n_bogus)
    logger.info("=" * 72)
