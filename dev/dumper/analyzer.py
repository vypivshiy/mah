"""
Orchestration module.

Collects packets/events, analyzes serializable types, merges results, and saves JSON.
"""
import json
import os
import re
import logging

import idc
import idautils
import idaapi
import ida_name
import ida_funcs

import common
import ida_utils
import template_parser
import symbol_index
import field_extractor

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

    fixed_fields = []
    for f in fields:
        key = "{}::{}".format(full_name, f["name"])
        if key in _FIELD_REMOVES:
            continue
        if key in _TYPE_FIXES:
            f = dict(f)
            f["type"] = _TYPE_FIXES[key]
        fixed_fields.append(f)
    return fixed_fields


# Configure root logger so that IDA output window still sees messages.
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(message)s")


# ── Packet / event collection ─────────────────────────────────────────────────

def collect_common_packets():
    """
    Scan strings for CommonPacket<N, Req, Resp, Flags>.
    Returns list of dicts sorted by opcode.
    Deduplicates by opcode (first match wins).
    """
    results = {}
    for s in idautils.Strings():
        try:
            val = str(s)
        except Exception:
            continue

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


def collect_common_events():
    """
    Scan strings for CommonEvent<N, Req, RespLike>.
    Returns list of dicts sorted by opcode.
    """
    results = {}
    for s in idautils.Strings():
        try:
            val = str(s)
        except Exception:
            continue

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

        req_full_name = ida_utils._normalize_name(args[1])
        resp_full_name = ida_utils._normalize_name(args[2])
        for pfx in ("struct ", "class "):
            if req_full_name.startswith(pfx):
                req_full_name = req_full_name[len(pfx):]
            if resp_full_name.startswith(pfx):
                resp_full_name = resp_full_name[len(pfx):]

        results[opcode] = {
            "opcode": opcode,
            "request_full_name": req_full_name,
            "request_kind": req_full_name.split("::")[-1],
            "response_full_name": resp_full_name,
            "response_kind": resp_full_name.split("::")[-1],
        }

    return sorted(results.values(), key=lambda x: x["opcode"])


# ── Uppercase enum extraction ─────────────────────────────────────────────────

def extract_uppercase_enums():
    """
    Scan the on-disk DLL for enum-like uppercase string constants that IDA's
    string detection misses (e.g. MSVC RTTI blocks padded with null bytes).
    Returns sorted list of unique strings matching [A-Z0-9_]{2,64},
    with RTTI garbage and random codes filtered out.
    """
    filepath = idaapi.get_input_file_path()
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
            if end < n and data[end] == 0:  # must be null-terminated
                s = data[i:end].decode("ascii")
                if s not in seen and common._is_likely_enum(s):
                    seen.add(s)
                    results.append(s)

        i = end if end > i else i + 1

    results.sort()
    return results


# ── Special factory-registered packets ────────────────────────────────────────

def _parse_creator_vtable_demangled(dem):
    idx = dem.find("Creator<")
    if idx == -1:
        return None, None
    inner = dem[idx + len("Creator<"):]
    args = template_parser._extract_tpl_args(inner)
    if len(args) < 2:
        return None, None
    msg_type = ida_utils._normalize_name(args[0])
    base_type = ida_utils._normalize_name(args[1])
    return msg_type, base_type


def _extract_opcode_from_func(func_ea):
    text = ida_utils.decompile_text(func_ea)
    for rx in (common._CREATOR_OPCODE_RE_1, common._CREATOR_OPCODE_RE_2, common._CREATOR_OPCODE_RE_3):
        m = rx.search(text)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                pass

    func = ida_funcs.get_func(func_ea)
    if not func:
        return None

    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.print_insn_mnem(head).lower() != "mov":
            continue
        if idc.get_operand_type(head, 1) != idc.o_imm:
            continue
        line = idc.generate_disasm_line(head, 0) or ""
        if "word ptr" not in line and "dword ptr" not in line:
            continue
        imm = idc.get_operand_value(head, 1)
        if 0 <= imm <= 0xFFFF:
            return imm

    return None


def collect_special_factory_packets():
    """
    Find packet/event-like messages registered via factory creators rather than CommonPacket/CommonEvent.
    """
    results = {}
    count = ida_name.get_nlist_size()

    for i in range(count):
        ea = ida_name.get_nlist_ea(i)
        mangled = ida_name.get_nlist_name(i)
        if not mangled.startswith("??_7"):
            continue

        dem = ida_utils._demangle(mangled)
        if not (dem.endswith("::`vftable'") or dem.endswith("::vftable")):
            continue
        if "Creator<" not in dem:
            continue
        if "Api::OneMe::Packets::" not in dem:
            continue
        if "BaseEvent" not in dem and "BasePacket" not in dem:
            continue

        full_name, base_kind = _parse_creator_vtable_demangled(dem)
        if not full_name or not base_kind:
            continue

        for xr in idautils.XrefsTo(ea, 0):
            func = ida_funcs.get_func(xr.frm)
            if not func:
                continue
            opcode = _extract_opcode_from_func(func.start_ea)
            if opcode is None or opcode in results:
                continue
            results[opcode] = {
                "opcode": opcode,
                "full_name": full_name,
                "base_kind": base_kind.split("::")[-1],
                "factory_ea": func.start_ea,
            }

    return sorted(results.values(), key=lambda x: x["opcode"])


# ── Per-type analysis ─────────────────────────────────────────────────────────

def analyze_serializable_type(full_name, role):
    """
    Analyze a serializable type and extract its fields.
    Returns:
      {full_name, role, kind, offset, fields: [{name, type, required}], warn}
    """
    kind = full_name.split("::")[-1]

    if kind in common._EMPTY_NAMES:
        return {
            "full_name": full_name,
            "role": role,
            "kind": kind,
            "name_method": None,
            "offset": None,
            "fields": [],
            "warn": None,
        }

    init_ea = symbol_index.find_initializer_ea(full_name)
    fields = []
    method = None
    if init_ea:
        fields, method = field_extractor.extract_fields_from_func(init_ea, full_name)
    fields = _apply_field_fixes(full_name, fields)

    warn = None
    if not fields:
        if "Polymorphic" not in full_name:
            warn = "no data found"
    elif method == "disasm":
        warn = "names via disasm (no required flags)"

    offset = (init_ea - ida_utils.IMAGE_BASE) if init_ea else None

    return {
        "full_name": full_name,
        "role": role,
        "kind": kind,
        "name_method": method,
        "offset": "0x{:x}".format(offset) if offset is not None else None,
        "fields": fields,
        "warn": warn,
    }


# ── Model collection ──────────────────────────────────────────────────────────

def _api_model_refs_in_fields(fields):
    """Yield full_names of Api::OneMe::* structs referenced in field types."""
    for f in fields:
        for m in common._API_MODEL_REF_RE.finditer(f.get("type", "")):
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
    """BFS over Api::OneMe::* types starting from initial_refs."""
    queue = set(initial_refs)
    visited = set()
    models = {}

    while queue:
        full_name = queue.pop()
        if full_name in visited:
            continue
        visited.add(full_name)

        info = analyze_serializable_type(full_name, "model")

        for ref in _api_model_refs_in_fields(info["fields"]):
            if ref not in visited:
                queue.add(ref)

        models[full_name] = {
            "fields": info["fields"],
            "name_method": info["name_method"],
            "warn": info["warn"],
            "offset": info["offset"],
        }

    return dict(sorted(models.items()))


def collect_models_from_sections(*sections):
    """
    BFS over types referenced from any section entries that carry request/response field sets.
    """
    queue = set()
    for entries in sections:
        for ref in _iter_type_refs_from_entries(entries):
            queue.add(ref)
    return _collect_models_bfs(queue)


# ── Inheritance / derived types ───────────────────────────────────────────────

def _analyze_inheritance_group(owner_full_name):
    """
    For an owner type used in Polymorphic<>, discover all classes (base + derived)
    that register SerializableMember entries under this owner.
    """
    symbol_index._ensure_index()

    short_name = owner_full_name.split("::")[-1]
    parts = owner_full_name.split("::")

    ns_parts = parts[:-1]
    derived_types = set()

    if ns_parts:
        ns_prefix = "::".join(ns_parts) + "::"
        for full_name, vft_ea in symbol_index._VTABLE_INDEX.items():
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
        sm_entries = symbol_index._SMEMBER_INDEX.get(owner_full_name, [])
        for vft_ea, raw_type in sm_entries:
            text = ida_utils.decompile_text(vft_ea)
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
                    owner = ida_utils._normalize_name(owner)
                    if owner != owner_full_name and ida_utils._is_api_oneme_name(owner):
                        derived_types.add(owner)

    if not derived_types:
        return {}

    result = {}
    for class_name in derived_types:
        if class_name in result:
            continue

        if class_name not in symbol_index._VTABLE_INDEX:
            continue

        info = analyze_serializable_type(class_name, "model")
        result[class_name] = {
            "fields": info["fields"],
            "name_method": info["name_method"],
            "warn": info["warn"],
            "offset": info["offset"],
        }

    base_info = analyze_serializable_type(owner_full_name, "model")
    result[owner_full_name] = {
        "fields": base_info["fields"],
        "name_method": base_info["name_method"],
        "warn": base_info["warn"],
        "offset": base_info["offset"],
    }

    return result


def collect_inheritance_models(models, packets):
    """
    For types used in Polymorphic<>, discover derived types and group them
    under their polymorphic base type.
    Returns {base_full_name: {"variants": {class_full_name: {fields, name_method, warn}}}}.
    """
    poly_re = re.compile(r'Polymorphic<([^,>]+)')
    polymorphic_bases = set()

    def scan_fields(fields):
        for f in fields:
            for m in poly_re.finditer(f.get("type", "")):
                base = ida_utils._normalize_name(m.group(1))
                if ida_utils._is_api_oneme_name(base):
                    polymorphic_bases.add(base)

    for model in models.values():
        scan_fields(model.get("fields", []))
    for pkt in packets:
        for side in ("request", "response"):
            info = pkt.get(side)
            if info:
                scan_fields(info.get("fields", []))

    if not polymorphic_bases:
        return {}

    logger.info("[Inheritance] Scanning %d polymorphic base type(s)...", len(polymorphic_bases))

    result = {}
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

        variants = {}
        for class_name, info in classes.items():
            if class_name == base_name:
                merged_fields = info["fields"]
            else:
                merged = list(base_fields) + info["fields"]
                seen = set()
                deduped = []
                for f in merged:
                    if f["name"] not in seen:
                        seen.add(f["name"])
                        deduped.append(f)
                merged_fields = deduped

            variants[class_name] = {
                "fields": merged_fields,
                "name_method": "hexrays",
                "warn": info.get("warn"),
                "offset": info.get("offset"),
            }

        result[base_name] = {"variants": variants}

    total_variants = sum(len(g["variants"]) for g in result.values())
    logger.info("  Found %d polymorphic group(s), %d total variant(s)",
                len(result), total_variants)
    return result


# ── Output helpers ────────────────────────────────────────────────────────────

def _fields_str(info):
    if not info["fields"]:
        return "(empty)"
    return ", ".join(
        '{}:{}{}'.format(
            f["name"], f["type"], "" if f["required"] else "?"
        )
        for f in info["fields"]
    )


def _method_tag(info):
    m = info.get("name_method")
    return "" if m in (None, "hexrays") else " [{}]".format(m)


def _build_entry_record(opcode, req_info, resp_info):
    return {
        "opcode": opcode,
        "request": {
            "full_name": req_info["full_name"],
            "kind": req_info["kind"],
            "name_method": req_info["name_method"],
            "offset": req_info["offset"],
            "fields": req_info["fields"],
            "warn": req_info["warn"],
        },
        "response": {
            "full_name": resp_info["full_name"],
            "kind": resp_info["kind"],
            "name_method": resp_info["name_method"],
            "offset": resp_info["offset"],
            "fields": resp_info["fields"],
            "warn": resp_info["warn"],
        },
    }


# ── Analysis runners ──────────────────────────────────────────────────────────

def _analyze_packets(packets):
    """Analyze RPC packets collected via CommonPacket<> strings."""
    logger.info("")
    logger.info("[Packets] Analyzing RPC packets...")
    logger.info("-" * 72)

    out = []
    warn_count = 0

    for p in packets:
        opcode = p["opcode"]
        req_fn = p["request_full_name"]
        resp_fn = p["response_full_name"]

        req_short = req_fn.replace("Api::OneMe::Packets::", "")
        resp_short = resp_fn.replace("Api::OneMe::Packets::", "")

        req_info = analyze_serializable_type(req_fn, "request")
        resp_info = analyze_serializable_type(resp_fn, "response")

        if req_info["warn"] or resp_info["warn"]:
            warn_count += 1

        logger.info("[%3d] req  %s%s -> %s%s",
                    opcode, req_short, _method_tag(req_info), _fields_str(req_info),
                    "  WARN: " + req_info["warn"] if req_info["warn"] else "")
        logger.info("      resp %s%s -> %s%s",
                    resp_short, _method_tag(resp_info), _fields_str(resp_info),
                    "  WARN: " + resp_info["warn"] if resp_info["warn"] else "")

        out.append(_build_entry_record(opcode, req_info, resp_info))

    logger.info("-" * 72)
    return out, warn_count


def _analyze_duplex_entries(entries, section_name, req_label="req", resp_label="resp"):
    logger.info("")
    logger.info("[%s] Analyzing %s...", section_name, section_name)
    logger.info("-" * 72)

    out = []
    warn_count = 0

    for item in entries:
        opcode = item["opcode"]
        req_fn = item["request_full_name"]
        resp_fn = item["response_full_name"]

        req_short = req_fn.replace("Api::OneMe::Packets::", "")
        resp_short = resp_fn.replace("Api::OneMe::Packets::", "")

        req_info = analyze_serializable_type(req_fn, "request")
        resp_info = analyze_serializable_type(resp_fn, "response")

        if req_info["warn"] or resp_info["warn"]:
            warn_count += 1

        logger.info("[%3d] %s %s%s -> %s%s",
                    opcode, req_label, req_short, _method_tag(req_info), _fields_str(req_info),
                    "  WARN: " + req_info["warn"] if req_info["warn"] else "")
        logger.info("      %s %s%s -> %s%s",
                    resp_label, resp_short, _method_tag(resp_info), _fields_str(resp_info),
                    "  WARN: " + resp_info["warn"] if resp_info["warn"] else "")

        out.append(_build_entry_record(opcode, req_info, resp_info))

    logger.info("-" * 72)
    return out, warn_count


def _find_payload_type_for_special(full_name):
    """
    For a special (factory-registered) packet, try to find an associated
    Payload type by scanning vtable addresses near the packet's own vtable.
    """
    symbol_index._ensure_index()

    pkt_vtable_ea = symbol_index._VTABLE_INDEX.get(full_name, idaapi.BADADDR)
    if pkt_vtable_ea == idaapi.BADADDR:
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


def _analyze_special_packets(entries):
    logger.info("")
    logger.info("[Special] Analyzing special factory-registered packets...")
    logger.info("-" * 72)

    out = []
    for item in entries:
        offset = item["factory_ea"] - ida_utils.IMAGE_BASE if item.get("factory_ea") is not None else None
        logger.info("[%3d] special %s (%s)",
                    item["opcode"],
                    item["full_name"].replace("Api::OneMe::Packets::", ""),
                    item["base_kind"])

        request = None
        payload_name = _find_payload_type_for_special(item["full_name"])
        if payload_name:
            payload_info = analyze_serializable_type(payload_name, "request")
            display_name = item["full_name"] + "::Payload"
            request = {
                "full_name": display_name,
                "kind": "Payload",
                "name_method": payload_info["name_method"],
                "offset": payload_info["offset"],
                "fields": payload_info["fields"],
                "warn": payload_info["warn"],
            }
            if payload_info["fields"]:
                logger.info("      payload %s -> %s",
                            display_name.replace("Api::OneMe::Packets::", ""),
                            _fields_str(payload_info))

        out.append({
            "opcode": item["opcode"],
            "kind": "special_packet",
            "full_name": item["full_name"],
            "base_kind": item["base_kind"],
            "offset": "0x{:x}".format(offset) if offset is not None else None,
            "request": request,
            "response": None,
            "warn": None,
        })

    logger.info("-" * 72)
    return out


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    app_version, build_number = ida_utils.extract_app_version()
    logger.info("app_version = %s (build %d)", app_version or "unknown", build_number)

    logger.info("=" * 72)
    logger.info("ida_max_packet_dumper.py - Api::OneMe::Packets signature dumper")
    logger.info("image_base = 0x%x", ida_utils.IMAGE_BASE)
    logger.info("=" * 72)

    _load_type_fixes()

    # ── Stage 1: Collect ──────────────────────────────────────────────────────
    logger.info("")
    logger.info("[Stage 1] Collecting message registrations...")
    packets = collect_common_packets()
    events = collect_common_events()
    special_packets = collect_special_factory_packets()
    logger.info("  RPC packets:      %d", len(packets))
    logger.info("  Events:           %d", len(events))
    logger.info("  Special packets:  %d", len(special_packets))
    if not packets and not events and not special_packets:
        logger.info("  Nothing to do.")
        return

    logger.info("")
    logger.info("[Enums]   Scanning DLL for uppercase enum strings...")
    string_enums = extract_uppercase_enums()
    logger.info("  Found %d enum string(s)", len(string_enums))

    # ── Index ─────────────────────────────────────────────────────────────────
    logger.info("")
    logger.info("[Index]   Building name index (one-time)...")
    symbol_index._ensure_index()
    logger.info("  SerializableMember owners: %d", len(symbol_index._SMEMBER_INDEX))
    logger.info("  Type vftables:             %d", len(symbol_index._VTABLE_INDEX))
    iser_str = "0x{:x}".format(symbol_index._ISER_VTABLE) if symbol_index._ISER_VTABLE != idaapi.BADADDR else "NOT FOUND"
    logger.info("  ISerializableMember vtbl:  %s", iser_str)

    # ── Stages 2-4: Analyze ───────────────────────────────────────────────────
    out_packets, warn_count = _analyze_packets(packets)
    out_events, event_warn_count = _analyze_duplex_entries(
        events, "Events",
        req_label="event-req",
        resp_label="event-resp")
    out_special_packets = _analyze_special_packets(special_packets)

    # ── Stage 5: Models ───────────────────────────────────────────────────────
    logger.info("")
    logger.info("[Stage 5] Collecting nested Types:: models...")
    models = collect_models_from_sections(out_packets, out_events)
    logger.info("  Found %d model(s)", len(models))
    m_warn = sum(1 for v in models.values() if v["warn"])
    if m_warn:
        logger.info("  Models with warnings: %d", m_warn)

    # ── Merge packets + events + special -> unified list ──────────────────────
    seen_opcodes = {p["opcode"] for p in out_packets}
    merged_packets = list(out_packets)
    for ev in out_events:
        if ev["opcode"] not in seen_opcodes:
            merged_packets.append(ev)
            seen_opcodes.add(ev["opcode"])
    for sp in out_special_packets:
        if sp["opcode"] not in seen_opcodes:
            merged_packets.append(sp)
            seen_opcodes.add(sp["opcode"])

    # ── Stage 5b: Inheritance / derived types ──────────────────────────────────
    derived_models = collect_inheritance_models(models, merged_packets)
    if derived_models:
        # Remove derived variants from flat models; base types remain in models
        for base_name, group in derived_models.items():
            for variant_name in group["variants"]:
                if variant_name != base_name and variant_name in models:
                    del models[variant_name]

        # Collect models referenced from polymorphic variant fields
        poly_refs = set()
        for group in derived_models.values():
            for variant_info in group["variants"].values():
                for ref in _api_model_refs_in_fields(variant_info["fields"]):
                    if ref not in models:
                        poly_refs.add(ref)
        if poly_refs:
            new_models = _collect_models_bfs(poly_refs)
            for name, info in new_models.items():
                if name not in models:
                    models[name] = info
            logger.info("  Models from polymorphic variants: %d", len(new_models))

        logger.info("  Total models (after excluding derived): %d", len(models))
    merged_packets.sort(key=lambda x: x["opcode"])

    # ── Save JSON ─────────────────────────────────────────────────────────────
    idb_path = idc.get_idb_path()
    out_dir = os.path.dirname(idb_path) if idb_path else "."
    out_path = os.path.join(out_dir, "ida_packets.json")

    out_data = {
        "image_base": "0x{:x}".format(ida_utils.IMAGE_BASE),
        "app_version": app_version,
        "build_number": build_number,
        "rpc_ver": common.VER,
        "packets": merged_packets,
        "models": models,
        "polymorphic_models": derived_models,
        "string_enums": string_enums,
        "error": common.ERROR_PAYLOAD,
    }

    try:
        with open(out_path, "w") as f:
            json.dump(out_data, f, indent=2)
        logger.info("")
        logger.info("[*] JSON saved: %s", out_path)
    except Exception as e:
        logger.error("[!] Failed to save JSON: %s", e)

    total_rpc = len(out_packets)
    total_events = len(out_events)
    total_special = len(out_special_packets)
    ok_rpc = total_rpc - warn_count
    ok_events = total_events - event_warn_count
    logger.info("")
    logger.info("Done. packets=%d (rpc=%d ok=%d warn=%d, events=%d ok=%d warn=%d, special=%d), models=%d",
                len(merged_packets),
                total_rpc, ok_rpc, warn_count,
                total_events, ok_events, event_warn_count,
                total_special, len(models))
