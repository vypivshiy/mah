#!/usr/bin/env python3
"""
Генератор Python-кода для API обёртки мессенджера по сигнатурам (дампы C++ структур).

Использование:
  python generate2.py packets.json [output_dir] [transport_module]
"""

import json
import keyword
import re
import sys
from pathlib import Path
from typing import Any

# ---------- 1. Конвертация C++ типов в Python ----------

PRIMITIVES: dict[str, str] = {
    "bool": "bool",
    "signed char": "int",
    "unsigned char": "int",
    "std::byte": "int",
    "enum std::byte": "int",
    "short": "int",
    "int": "int",
    "__int64": "int",
    "float": "float",
    "std::string": "str",
    "std::basic_string<char,std::char_traits<char>,std::allocator<char>>": "str",
    "unknown": "Any",
}

BUILTIN_TYPES = frozenset({
    "bool", "int", "float", "str", "Any", "dict", "list", "bytes", "bytearray",
    "set", "frozenset", "tuple", "type", "None",
})

CPP_NAMESPACE_PREFIXES = [
    "Api::OneMe::Packets::",
    "Api::OneMe::Types::",
    "Api::OneMe::",
]

CPP_PREFIX_STRIPPED = [
    "ApiOneMePackets",
    "ApiOneMeTypes",
]


def find_matching(s: str, open_pos: int, open_char: str = '<', close_char: str = '>') -> int:
    depth = 0
    for i in range(open_pos, len(s)):
        if s[i] == open_char:
            depth += 1
        elif s[i] == close_char:
            depth -= 1
            if depth == 0:
                return i
    raise ValueError(f"Unmatched angle brackets in: {s}")


def split_top_level_commas(s: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in s:
        if ch == ',' and depth == 0:
            parts.append(''.join(current).strip())
            current = []
        else:
            if ch == '<':
                depth += 1
            elif ch == '>':
                depth -= 1
            current.append(ch)
    if current:
        parts.append(''.join(current).strip())
    return parts


def _short_name(cpp_type: str) -> str:
    clean = re.sub(r'\b(class|struct)\s+', '', cpp_type).replace('::', '')
    clean = re.sub(r'<.*>', '', clean)
    return clean


def to_python_type(
    cpp_type: str,
    polymorphic_model_bases: set[str] | None = None,
) -> tuple[str, bool]:
    """Convert C++ type to (python_type_str, is_optional)."""
    t = cpp_type.strip()
    t = re.sub(r'\b(class|struct)\s+', '', t)

    if t in PRIMITIVES:
        return PRIMITIVES[t], False

    if t.startswith("enum "):
        return to_python_type(t[5:], polymorphic_model_bases)

    if t.startswith("std::optional<"):
        inner_start = len("std::optional<")
        inner_end = find_matching(t, inner_start - 1)
        inner = t[inner_start:inner_end]
        py_inner, _ = to_python_type(inner, polymorphic_model_bases)
        return f"{py_inner} | None", True

    if t.startswith("std::vector<"):
        inner_start = len("std::vector<")
        inner_end = find_matching(t, inner_start - 1)
        inner = t[inner_start:inner_end]
        parts = split_top_level_commas(inner)
        py_inner, _ = to_python_type(parts[0], polymorphic_model_bases)
        return f"list[{py_inner}]", False

    if t.startswith("std::basic_string<"):
        return "str", False

    if t.startswith("std::shared_ptr<"):
        inner_start = len("std::shared_ptr<")
        inner_end = find_matching(t, inner_start - 1)
        inner = t[inner_start:inner_end]
        parts = split_top_level_commas(inner)
        py_inner, _ = to_python_type(parts[0], polymorphic_model_bases)
        return f"{py_inner} | None", True

    if t.startswith("std::allocator<"):
        return "Any", False

    for prefix in ["std::map<", "std::unordered_map<"]:
        if t.startswith(prefix):
            inner_start = len(prefix)
            inner_end = find_matching(t, inner_start - 1)
            inner = t[inner_start:inner_end]
            parts = split_top_level_commas(inner)
            if len(parts) != 2:
                raise ValueError(f"Expected 2 template args in map type: {t}")
            _, _ = to_python_type(parts[0], polymorphic_model_bases)
            val_py, _ = to_python_type(parts[1], polymorphic_model_bases)
            return f"dict[str, {val_py}]", False

    if 'Polymorphic<' in t:
        return "dict", False

    if polymorphic_model_bases and t in polymorphic_model_bases:
        return "dict", False

    if '<' in t:
        base_end = t.index('<')
        base_name = t[:base_end].replace('::', '')
        return _strip_known_prefixes(base_name), False

    return _strip_known_prefixes(t.replace('::', '')), False


def _strip_known_prefixes(s: str) -> str:
    for prefix in CPP_PREFIX_STRIPPED:
        if prefix in s:
            s = s.replace(prefix, "", 1)
            break
    return s


def normalize_struct_name(full_name: str) -> str:
    name = full_name
    for prefix in CPP_NAMESPACE_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    name = name.replace(':', '').replace('-', '').replace('_', '')
    for prefix in CPP_PREFIX_STRIPPED:
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return name


def normalize_field_name(name: str) -> str:
    """Convert field name to valid Python identifier (for @dataclass attrs)."""
    name = name.replace('-', '_').replace(' ', '')
    if not name:
        return "field"
    if name[0].isdigit():
        name = f"_{name}"
    if keyword.iskeyword(name):
        name = f"_{name}"
    return name


def to_snake_case(name: str) -> str:
    s = re.sub(r'(?<=[a-z0-9])([A-Z])', r'_\1', name)
    s = re.sub(r'(?<=[A-Z])([A-Z][a-z])', r'_\1', s)
    return s.lower().strip('_')


def opcode_const_name(resp_full_name: str) -> str | None:
    stripped = resp_full_name
    for p in CPP_NAMESPACE_PREFIXES:
        if stripped.startswith(p):
            stripped = stripped[len(p):]
            break
    parts = stripped.split("::")
    if not parts:
        return None
    meaningful_parts = parts[:-1]
    if not meaningful_parts:
        meaningful_parts = parts
    go_name = ""
    for part in meaningful_parts:
        clean = part.replace('-', '').replace('_', '').replace(' ', '')
        if clean:
            go_name += clean[0].upper() + clean[1:]
    return go_name if go_name else None


# ---------- 2. Генератор Python-кода ----------


class PythonCodegen:
    def __init__(self, json_path: str, transport_module: str = "transport") -> None:
        self.json_path = json_path
        self.transport_module = transport_module
        self._raw = json.loads(Path(json_path).read_text())

        self._polymorphic_models: dict[str, Any] = self._raw["polymorphic_models"]
        self._polymorphic_model_bases: set[str] = set(self._polymorphic_models.keys())

        self._models = self._raw.get("models", {})
        self._packets = self._raw.get("packets", [])
        self._events = self._raw.get("events", [])
        self._all_entries = self._packets + self._events
        self._error_def = self._raw.get("error", {})
        self._string_enums: list[str] = self._raw.get("string_enums", [])

        raw_version: str = self._raw["app_version"]
        self._app_version = ".".join(raw_version.split(".")[:3])
        self._build_number = self._raw.get("build_number", 0)

        self._struct_registry: set[str] = set()
        self._type_registry: dict[str, tuple[str, bool]] = {}

        # module_prefix maps normalized struct name -> prefix (e.g. "UserAgent" -> "m.")
        self._module_prefix: dict[str, str] = {}

    # ---------- type helpers ----------

    def _convert_type(self, cpp_type: str) -> tuple[str, bool]:
        if cpp_type not in self._type_registry:
            py_type, is_opt = to_python_type(cpp_type, self._polymorphic_model_bases)
            py_type = _strip_known_prefixes(py_type)
            self._type_registry[cpp_type] = (py_type, is_opt)
        return self._type_registry[cpp_type]

    def _prefixed_type(self, py_type: str) -> str:
        """Add module prefix to a non-builtin, non-generic type name."""
        # unwrap optionals: "Foo | None" -> "Foo"
        base = py_type.split(" | ")[0].strip()
        # unwrap generics: "list[Foo]" -> "Foo", "dict[str, Foo]" -> "Foo"
        if base.startswith("list[") and base.endswith("]"):
            inner = base[5:-1]
            prefix_inner = self._prefixed_type(inner)
            return py_type.replace(inner, prefix_inner, 1)
        if base.startswith("dict[str, ") and base.endswith("]"):
            inner = base[10:-1]
            prefix_inner = self._prefixed_type(inner)
            return py_type.replace(inner, prefix_inner, 1)
        # bare type name
        if base and base not in BUILTIN_TYPES and base in self._module_prefix:
            prefix = self._module_prefix[base]
            return py_type.replace(base, f"{prefix}{base}", 1)
        return py_type

    def _field_default(self, py_type: str, is_optional: bool) -> str | None:
        if is_optional:
            return "None"
        if py_type.startswith("list["):
            return "field(default_factory=list)"
        if py_type.startswith("dict["):
            return "field(default_factory=dict)"
        return None

    # ---------- file header ----------

    def _file_header(self, imports: str = "") -> list[str]:
        lines = ["# Autogenerated. DO NOT EDIT", "", "from __future__ import annotations", ""]
        if imports:
            lines.append(imports)
            lines.append("")
        return lines

    # ---------- opcode name building ----------

    def _build_opcode_map(self) -> dict[int, dict[str, Any]]:
        opcode_map: dict[int, dict[str, Any]] = {}
        for packet in self._all_entries:
            op = packet["opcode"]
            req = packet.get("request")
            resp = packet.get("response")
            if req is None and resp is None:
                continue
            opcode_map[op] = {
                "opcode": op,
                "req_full_name": req.get("full_name", "") if req else "",
                "resp_full_name": resp.get("full_name", "") if resp else "",
                "req_fields": req.get("fields", []) if req else [],
                "resp_fields": resp.get("fields", []) if resp else [],
                "is_notification": req is None or req.get("kind") == "NoParameters",
            }
        return opcode_map

    # ---------- generate opcodes ----------

    def generate_opcodes(self) -> str:
        opcode_names: dict[int, str] = {}
        for packet in self._all_entries:
            op = packet["opcode"]
            resp = packet.get("response")
            req = packet.get("request")
            if resp and resp.get("full_name"):
                name = opcode_const_name(resp["full_name"])
            elif req and req.get("full_name"):
                name = opcode_const_name(req["full_name"])
            elif packet.get("full_name"):
                name = opcode_const_name(packet["full_name"])
            else:
                continue
            if name:
                opcode_names[op] = name

        seen_names: dict[str, int] = {}
        deduped: dict[int, str] = {}
        for opcode, name in sorted(opcode_names.items()):
            if name in seen_names:
                seen_names[name] += 1
                deduped[opcode] = f"{name}{seen_names[name]}"
            else:
                seen_names[name] = 0
                deduped[opcode] = name

        lines = self._file_header("from enum import IntEnum\n")
        lines.append("class Opcode(IntEnum):")
        lines.append('    """Protocol opcodes."""')
        lines.append("")
        lines.append("    def __new__(cls, value: int) -> Opcode:")
        lines.append("        obj = int.__new__(cls, value)")
        lines.append("        obj._value_ = value")
        lines.append("        return obj")
        lines.append("")

        for opcode, name in sorted(deduped.items()):
            lines.append(f"    {name} = {opcode}")

        lines.append("")
        lines.append("")
        lines.append("class StringEnum:")
        lines.append('    """String constants used in the protocol."""')
        lines.append("")
        for name in self._string_enums:
            lines.append(f'    {name}: str = "{name}"')
        lines.append("")

        return "\n".join(lines)

    # ---------- generate TypedDict ----------

    def _generate_typeddict(
        self,
        full_name: str,
        fields: list[dict[str, Any]],
        target: list[str],
        prefix_map: dict[str, str] | None = None,
    ) -> str | None:
        class_name = normalize_struct_name(full_name)
        if class_name in self._struct_registry:
            return None
        self._struct_registry.add(class_name)

        if not fields:
            target.append(f'{class_name} = TypedDict("{class_name}", {{}}, total=False)')
            target.append("")
            return class_name

        entries: list[str] = []
        for f in fields:
            raw_name = f["name"]
            py_type, _ = self._convert_type(f["type"])
            if prefix_map:
                py_type = self._prefixed_type(py_type, prefix_map)
            entries.append(f'    "{raw_name}": {py_type},')

        target.append(f"{class_name} = TypedDict(")
        target.append(f'    "{class_name}",')
        target.append("    {")
        target.extend(entries)
        target.append("    },")
        target.append("    total=False,")
        target.append(")")
        target.append("")
        return class_name

    def _prefixed_type(self, py_type: str, prefix_map: dict[str, str] | None = None) -> str:
        pm = prefix_map or self._module_prefix
        base = py_type.split(" | ")[0].strip()
        if base.startswith("list[") and base.endswith("]"):
            inner = base[5:-1]
            prefix_inner = self._prefixed_type(inner, pm)
            return py_type.replace(inner, prefix_inner, 1)
        if base.startswith("dict[str, ") and base.endswith("]"):
            inner = base[10:-1]
            prefix_inner = self._prefixed_type(inner, pm)
            return py_type.replace(inner, prefix_inner, 1)
        if base and base not in BUILTIN_TYPES and base in pm:
            prefix = pm[base]
            return py_type.replace(base, f"{prefix}{base}", 1)
        return py_type

    # ---------- generate @dataclass ----------

    def _generate_dataclass(
        self,
        full_name: str,
        fields: list[dict[str, Any]],
        target: list[str],
        prefix_map: dict[str, str] | None = None,
    ) -> str | None:
        class_name = normalize_struct_name(full_name)
        if class_name in self._struct_registry:
            return None
        self._struct_registry.add(class_name)

        field_entries: list[tuple[str, str, str, bool]] = []
        for f in fields:
            raw_name = f["name"]
            py_attr = normalize_field_name(raw_name)
            py_type, is_opt = self._convert_type(f["type"])
            if prefix_map:
                py_type = self._prefixed_type(py_type, prefix_map)
            has_default = is_opt or py_type.startswith("list[") or py_type.startswith("dict[")
            field_entries.append((py_attr, raw_name, py_type, has_default))

        target.append("@dataclass")
        target.append(f"class {class_name}:")

        if not field_entries:
            target.append("    pass")
            target.append("")
            return class_name

        # Required fields first, then optional (dataclass constraint)
        required = [(a, r, t) for a, r, t, d in field_entries if not d]
        optional = [(a, r, t) for a, r, t, d in field_entries if d]

        for py_attr, raw_name, py_type in required + optional:
            _, is_opt = self._convert_type(self._get_field_type(fields, raw_name))
            default = self._field_default(py_type, is_opt)
            if default is None:
                target.append(f"    {py_attr}: {py_type}")
            elif default == "None":
                target.append(f"    {py_attr}: {py_type} = None")
            else:
                target.append(f"    {py_attr}: {py_type} = {default}")

        target.append("")
        target.append("    _FIELD_MAP: ClassVar[dict[str, str]] = {")
        for py_attr, raw_name, _, _ in field_entries:
            target.append(f'        "{py_attr}": "{raw_name}",')
        target.append("    }")
        target.append("")
        target.append("    def to_dict(self) -> dict[str, Any]:")
        target.append("        result: dict[str, Any] = {}")
        target.append("        for py_attr, orig_key in self._FIELD_MAP.items():")
        target.append("            val = getattr(self, py_attr)")
        target.append("            if val is not None:")
        target.append("                if isinstance(val, list):")
        target.append("                    if val:")
        target.append("                        result[orig_key] = val")
        target.append("                elif isinstance(val, dict):")
        target.append("                    if val:")
        target.append("                        result[orig_key] = val")
        target.append("                else:")
        target.append("                    result[orig_key] = val")
        target.append("        return result")
        target.append("")
        return class_name

    def _get_field_type(self, fields: list[dict], raw_name: str) -> str:
        for f in fields:
            if f["name"] == raw_name:
                return f["type"]
        return "unknown"

    # ---------- build module prefix maps ----------

    def _build_prefix_maps(self) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
        """Build prefix maps for models (m.), packets (p.), polymorphic (pm.)."""
        model_names: set[str] = set()
        for model_name in self._models:
            model_names.add(normalize_struct_name(model_name))

        poly_names: set[str] = set()
        for base_data in self._polymorphic_models.values():
            for variant_name in base_data.get("variants", {}):
                poly_names.add(normalize_struct_name(variant_name))

        packet_names: set[str] = set()
        for packet in self._all_entries:
            req = packet.get("request")
            resp = packet.get("response")
            if req:
                packet_names.add(normalize_struct_name(req["full_name"]))
            if resp:
                packet_names.add(normalize_struct_name(resp["full_name"]))

        m_prefix: dict[str, str] = {n: "m." for n in model_names}
        p_prefix: dict[str, str] = {n: "p." for n in packet_names}
        pm_prefix: dict[str, str] = {n: "pm." for n in poly_names}

        # packets see models with m. prefix
        p_sees: dict[str, str] = {**m_prefix}
        # client sees all three
        c_sees: dict[str, str] = {**m_prefix, **p_prefix, **pm_prefix}

        return p_sees, c_sees, pm_prefix

    # ---------- generate models ----------

    def _extract_type_names(self, py_type: str) -> list[str]:
        """Extract bare type names from a Python type string like 'list[Foo] | None'."""
        names: list[str] = []
        base = py_type.split(" | ")[0].strip()
        if base.startswith("list[") and base.endswith("]"):
            names.extend(self._extract_type_names(base[5:-1]))
        elif base.startswith("dict[str, ") and base.endswith("]"):
            names.extend(self._extract_type_names(base[10:-1]))
        elif base and base not in BUILTIN_TYPES:
            names.append(base)
        return names

    def _find_circular_edges(self, deps: dict[str, set[str]]) -> set[frozenset[str]]:
        """Find dependency edges that are part of cycles."""
        WHITE, GRAY, BLACK = 0, 1, 2
        color: dict[str, int] = {n: WHITE for n in deps}
        circular: set[frozenset[str]] = set()
        path: list[str] = []

        def dfs(node: str) -> None:
            color[node] = GRAY
            path.append(node)
            for dep in deps.get(node, set()):
                if dep not in color:
                    continue
                if color[dep] == GRAY:
                    # cycle found — mark all edges in the cycle
                    cycle_start = path.index(dep)
                    for i in range(cycle_start, len(path) - 1):
                        circular.add(frozenset({path[i], path[i + 1]}))
                elif color[dep] == WHITE:
                    dfs(dep)
            path.pop()
            color[node] = BLACK

        for node in deps:
            if color[node] == WHITE:
                dfs(node)
        return circular

    def generate_models(self) -> dict[str, str]:
        """Generate one file per model under models/. Returns {filepath: content}."""
        saved_registry = self._struct_registry
        self._struct_registry = set()

        norm_to_orig: dict[str, str] = {}
        for model_name in self._models:
            norm_to_orig[normalize_struct_name(model_name)] = model_name

        # Build dependency graph: norm_name -> set of dependency norm_names
        all_deps: dict[str, set[str]] = {}
        for full_name, model_data in self._models.items():
            norm = normalize_struct_name(full_name)
            deps: set[str] = set()
            for f in model_data.get("fields", []):
                py_type, _ = self._convert_type(f["type"])
                for ref in self._extract_type_names(py_type):
                    if ref in norm_to_orig and ref != norm:
                        deps.add(ref)
            all_deps[norm] = deps

        circular_edges = self._find_circular_edges(all_deps)

        files: dict[str, str] = {}
        init_lines = ["# Autogenerated. DO NOT EDIT", "", "from __future__ import annotations", ""]

        for full_name, model_data in self._models.items():
            norm_name = normalize_struct_name(full_name)
            file_name = to_snake_case(norm_name) + ".py"
            fields = model_data["fields"]

            # Separate deps into: normal imports vs circular (use `dict`)
            normal_deps: set[str] = set()
            circular_deps: set[str] = set()
            for dep in all_deps.get(norm_name, set()):
                if frozenset({norm_name, dep}) in circular_edges:
                    circular_deps.add(dep)
                else:
                    normal_deps.add(dep)

            lines = ["# Autogenerated. DO NOT EDIT", "", "from __future__ import annotations", ""]

            # Import non-circular dependencies
            if normal_deps:
                dep_file_map: dict[str, list[str]] = {}
                for dep_norm in sorted(normal_deps):
                    dep_file_map.setdefault(to_snake_case(dep_norm), []).append(dep_norm)
                for dep_file in sorted(dep_file_map):
                    lines.append(f"from models.{dep_file} import {', '.join(dep_file_map[dep_file])}")
                lines.append("")

            lines.append("from typing import TypedDict, Any")
            lines.append("")

            # Generate TypedDict — replace circular dep types with `dict`
            if not fields:
                lines.append(f'{norm_name} = TypedDict("{norm_name}", {{}}, total=False)')
            else:
                entries: list[str] = []
                for f in fields:
                    raw_name = f["name"]
                    py_type, _ = self._convert_type(f["type"])
                    # Replace circular dependency types with `dict`
                    for circ in circular_deps:
                        py_type = self._replace_type_name(py_type, circ, "dict")
                    entries.append(f'    "{raw_name}": {py_type},')
                lines.append(f"{norm_name} = TypedDict(")
                lines.append(f'    "{norm_name}",')
                lines.append("    {")
                lines.extend(entries)
                lines.append("    },")
                lines.append("    total=False,")
                lines.append(")")
            lines.append("")

            files[f"models/{file_name}"] = "\n".join(lines)
            init_lines.append(f"from models.{to_snake_case(norm_name)} import {norm_name}")

        init_lines.append("")
        files["models/__init__.py"] = "\n".join(init_lines)
        self._struct_registry = saved_registry
        return files

    def _replace_type_name(self, py_type: str, old: str, new: str) -> str:
        """Replace a type name in a Python type string, preserving structure."""
        base = py_type.split(" | ")[0].strip()
        if base.startswith("list[") and base.endswith("]"):
            inner = base[5:-1]
            new_inner = self._replace_type_name(inner, old, new)
            return py_type.replace(inner, new_inner, 1)
        if base.startswith("dict[str, ") and base.endswith("]"):
            inner = base[10:-1]
            new_inner = self._replace_type_name(inner, old, new)
            return py_type.replace(inner, new_inner, 1)
        if base == old:
            return py_type.replace(old, new, 1)
        return py_type

    # ---------- generate polymorphic ----------

    def generate_polymorphic(self) -> str:
        model_names = {normalize_struct_name(n) for n in self._models}

        # Collect all model deps across all variants
        all_model_deps: set[str] = set()
        variant_fields: list[tuple[str, list[dict]]] = []
        for base_name, base_data in self._polymorphic_models.items():
            variants: dict[str, Any] = base_data.get("variants", {})
            for variant_name, variant_data in variants.items():
                fields = variant_data.get("fields", [])
                variant_fields.append((variant_name, fields))
                for f in fields:
                    py_type, _ = self._convert_type(f["type"])
                    for ref in self._extract_type_names(py_type):
                        if ref in model_names:
                            all_model_deps.add(ref)

        lines = ["# Autogenerated. DO NOT EDIT", "", "from __future__ import annotations", ""]

        # Import model dependencies
        if all_model_deps:
            dep_file_map: dict[str, list[str]] = {}
            for dep in sorted(all_model_deps):
                dep_file_map.setdefault(to_snake_case(dep), []).append(dep)
            for dep_file in sorted(dep_file_map):
                names = ", ".join(dep_file_map[dep_file])
                lines.append(f"from models.{dep_file} import {names}")
            lines.append("")

        lines.append("from typing import TypedDict, Any")
        lines.append("")

        for variant_name, fields in variant_fields:
            self._generate_typeddict(variant_name, fields, lines)
        return "\n".join(lines)

    # ---------- generate packets ----------

    def generate_packets(self) -> str:
        p_sees, _, _ = self._build_prefix_maps()
        lines = self._file_header(
            "from dataclasses import dataclass, field\n"
            "from typing import ClassVar, Any, TypedDict\n"
            "import models as m\n"
        )

        for packet in self._all_entries:
            req = packet.get("request")
            resp = packet.get("response")

            if req and req.get("fields"):
                self._generate_dataclass(req["full_name"], req["fields"], lines, p_sees)
            elif req and req.get("kind") in ("EmptyParameters", "Parameters"):
                name = normalize_struct_name(req["full_name"])
                if name not in self._struct_registry:
                    self._struct_registry.add(name)
                    lines.append("@dataclass")
                    lines.append(f"class {name}:")
                    lines.append("    pass")
                    lines.append("")

            if resp and resp.get("fields"):
                self._generate_typeddict(resp["full_name"], resp["fields"], lines, p_sees)
            elif resp and resp.get("kind") in ("EmptyResponse", "Response"):
                name = normalize_struct_name(resp["full_name"])
                if name not in self._struct_registry:
                    self._struct_registry.add(name)
                    lines.append(f'{name} = TypedDict("{name}", {{}}, total=False)')
                    lines.append("")

        return "\n".join(lines)

    # ---------- generate client ----------

    def _opcode_ref_for(self, opcode: int, resp_full_name: str, use_prefix: bool = False) -> str:
        name = opcode_const_name(resp_full_name) if resp_full_name else None
        if not name:
            return str(opcode)
        seen: dict[str, int] = {}
        for pkt in self._all_entries:
            r = pkt.get("response")
            if not r or not r.get("full_name"):
                continue
            n = opcode_const_name(r["full_name"])
            if not n:
                continue
            if n == name and pkt["opcode"] != opcode:
                return str(opcode)
            if n in seen:
                seen[n] += 1
                if n == name and pkt["opcode"] == opcode:
                    ref = f"{name}{seen[n]}"
                    return f"op.Opcode.{ref}" if use_prefix else str(opcode)
            else:
                seen[n] = 0
        return f"op.Opcode.{name}" if use_prefix else f"Opcode.{name}"

    def generate_client(self) -> str:
        opcode_map = self._build_opcode_map()
        _, c_sees, _ = self._build_prefix_maps()

        lines = self._file_header(
            "from typing import Any, Callable\n"
            "\n"
            f"from {self.transport_module} import BaseClient, Packet\n"
            "import opcodes as op\n"
            "import models as m\n"
            "import packets as p\n"
            "import polymorphic as pm\n"
        )

        def pref(name: str) -> str:
            return c_sees.get(name, "")

        lines.append("class Client(BaseClient):")
        lines.append(f'    """Typed API client."""')
        lines.append("")
        lines.append("    def __init__(self) -> None:")
        lines.append(f'        super().__init__(app_version="{self._app_version}", build_number={self._build_number})')
        lines.append("        self._register_notification_opcodes()")
        lines.append("")
        lines.append("    def _register_notification_opcodes(self) -> None:")
        lines.append("        self._notification_opcodes = {")

        notification_opcodes = []
        for opcode, info in sorted(opcode_map.items()):
            if info["is_notification"]:
                ref = self._opcode_ref_for(opcode, info["resp_full_name"], use_prefix=True)
                notification_opcodes.append(ref)

        for ref in notification_opcodes:
            lines.append(f"            {ref},")
        lines.append("        }")
        lines.append("")

        # send_* methods
        used_methods: set[str] = set()
        for opcode, info in sorted(opcode_map.items()):
            if not info["req_full_name"]:
                continue
            if info["is_notification"]:
                continue

            req_name = normalize_struct_name(info["req_full_name"])
            method_base = to_snake_case(req_name)
            if method_base.endswith("_parameters"):
                method_base = method_base[: -len("_parameters")]
            if not method_base:
                method_base = to_snake_case(req_name)

            method_name = f"send_{method_base}"
            if method_name in used_methods:
                method_name = f"send_{method_base}_{opcode}"
            used_methods.add(method_name)

            opcode_ref = self._opcode_ref_for(opcode, info["resp_full_name"], use_prefix=True)
            req_pref = pref(req_name)

            if info["resp_full_name"] and info["resp_full_name"] != "":
                resp_name = normalize_struct_name(info["resp_full_name"])
                resp_kind = self._get_packet_kind(opcode, "response")
                resp_pref = pref(resp_name)
                if resp_kind == "EmptyResponse":
                    lines.append(f"    async def {method_name}(self, req: {req_pref}{req_name}) -> None:")
                    lines.append(f"        await self.send_raw({opcode_ref}, req.to_dict())")
                    lines.append("")
                else:
                    lines.append(f"    async def {method_name}(self, req: {req_pref}{req_name}) -> {resp_pref}{resp_name}:")
                    lines.append(f"        resp = await self.send_raw({opcode_ref}, req.to_dict())")
                    lines.append(f"        return resp.payload  # type: ignore[return-value]")
                    lines.append("")
            else:
                lines.append(f"    async def {method_name}(self, req: {req_pref}{req_name}) -> None:")
                lines.append(f"        await self.send_raw({opcode_ref}, req.to_dict())")
                lines.append("")

        # on_* methods for notifications
        used_on_methods: set[str] = set()
        for opcode, info in sorted(opcode_map.items()):
            if not info["is_notification"]:
                continue
            if not info["resp_full_name"]:
                continue

            resp_name = normalize_struct_name(info["resp_full_name"])
            opcode_name = opcode_const_name(info["resp_full_name"])
            if not opcode_name:
                continue
            method_snake = to_snake_case(opcode_name)
            on_name = f"on_{method_snake}"
            if on_name in used_on_methods:
                on_name = f"on_{method_snake}_{opcode}"
            used_on_methods.add(on_name)

            opcode_ref = self._opcode_ref_for(opcode, info["resp_full_name"], use_prefix=True)
            resp_pref = pref(resp_name)

            lines.append(f"    def {on_name}(self, handler: Callable[[{resp_pref}{resp_name}], Any]) -> None:")
            lines.append(f"        def _wrap(pkt: Packet) -> None:")
            lines.append(f"            handler(pkt.payload)  # type: ignore[arg-type]")
            lines.append(f"        self.on({opcode_ref}, _wrap)")
            lines.append("")

        return "\n".join(lines)

    def _get_packet_kind(self, opcode: int, side: str) -> str:
        for packet in self._all_entries:
            if packet["opcode"] == opcode:
                obj = packet.get(side)
                if obj:
                    return obj.get("kind", "")
        return ""

    # ---------- entry point ----------

    def convert(self) -> dict[str, str]:
        self._struct_registry.clear()
        self._type_registry.clear()

        files: dict[str, str] = {
            "opcodes.py": self.generate_opcodes(),
            "polymorphic.py": self.generate_polymorphic(),
            "packets.py": self.generate_packets(),
            "client.py": self.generate_client(),
        }
        files.update(self.generate_models())
        return files


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python generate2.py packets.json [output_dir] [transport_module]")
        sys.exit(1)

    out_dir = Path(sys.argv[2]) if len(sys.argv) >= 3 else Path(".")
    transport_module = sys.argv[3] if len(sys.argv) >= 4 else "transport"

    gen = PythonCodegen(sys.argv[1], transport_module)
    files = gen.convert()
    for fpath, content in files.items():
        full_path = out_dir / fpath
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content, encoding="utf-8")
        print(f"Written {full_path}")
