#!/usr/bin/env python3
"""
Генератор Go-кода для API обёртки мессенджера по сигнатурам (дампы C++ структур).

Использование:
  python generate.py packets.json [package_name] [output_dir]

  - package_name: имя Go-пакета (по умолчанию "main")
  - output_dir:   директория для сохранения .go файлов (по умолчанию текущая)
"""

import json
import re
import sys
from pathlib import Path
from typing import Any, List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field

# ---------- 1. Конвертация C++ типов в Go ----------

PRIMITIVES: Dict[str, str] = {
    "bool": "bool",
    "signed char": "int8",
    "unsigned char": "byte",
    "std::byte": "byte",
    "enum std::byte": "byte",
    "short": "int16",
    "int": "int32",
    "__int64": "int64",
    "float": "float32",
    "std::string": "string",
    "std::basic_string<char,std::char_traits<char>,std::allocator<char>>": "string",
    "unknown": "interface{}",
}

CPP_NAMESPACE_PREFIXES = [
    "Api::OneMe::Packets::",
    "Api::OneMe::Types::",
    "Api::OneMe::",
]

CPP_PREFIX_STRIPPED = [
    "ApiOneMePackets",
    "ApiOneMeTypes",
]


@dataclass
class TypeMappingResult:
    mapping: Dict[str, str]
    polymorphic_registry: Dict[str, str]
    polymorphic_params: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)


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


def split_top_level_commas(s: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    current: List[str] = []
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


def _parse_polymorphic_parts(cpp_type: str) -> Tuple[List[str], str]:
    idx = cpp_type.find('Polymorphic<')
    if idx == -1:
        raise ValueError(f"Not a Polymorphic type: {cpp_type}")
    t = cpp_type[idx:]
    inner_start = len('Polymorphic<')
    inner_end = find_matching(t, inner_start - 1)
    inner = t[inner_start:inner_end]
    parts = split_top_level_commas(inner)
    unique_parts = list(dict.fromkeys(parts))
    go_name = "Polymorphic" + ''.join(_short_name(p) for p in unique_parts)
    return unique_parts, go_name


def make_polymorphic_go_name(cpp_polymorphic_type: str) -> str:
    _, go_name = _parse_polymorphic_parts(cpp_polymorphic_type)
    return go_name


def to_go_type(
    cpp_type: str,
    polymorphic_registry: Optional[Dict[str, str]] = None,
    polymorphic_model_bases: Optional[Set[str]] = None,
) -> str:
    t = cpp_type.strip()
    t = re.sub(r'\b(class|struct)\s+', '', t)

    if t in PRIMITIVES:
        return PRIMITIVES[t]

    if t.startswith("enum "):
        return to_go_type(t[5:], polymorphic_registry, polymorphic_model_bases)

    if t.startswith("std::optional<"):
        inner_start = len("std::optional<")
        inner_end = find_matching(t, inner_start - 1)
        inner = t[inner_start:inner_end]
        go_inner = to_go_type(inner, polymorphic_registry, polymorphic_model_bases)
        return f"*{go_inner}"

    if t.startswith("std::vector<"):
        inner_start = len("std::vector<")
        inner_end = find_matching(t, inner_start - 1)
        inner = t[inner_start:inner_end]
        parts = split_top_level_commas(inner)
        go_inner = to_go_type(parts[0], polymorphic_registry, polymorphic_model_bases)
        return f"[]{go_inner}"

    if t.startswith("std::basic_string<"):
        return "string"

    if t.startswith("std::shared_ptr<"):
        inner_start = len("std::shared_ptr<")
        inner_end = find_matching(t, inner_start - 1)
        inner = t[inner_start:inner_end]
        parts = split_top_level_commas(inner)
        return f"*{to_go_type(parts[0], polymorphic_registry, polymorphic_model_bases)}"

    if t.startswith("std::allocator<"):
        return "interface{}"

    for prefix in ["std::map<", "std::unordered_map<"]:
        if t.startswith(prefix):
            inner_start = len(prefix)
            inner_end = find_matching(t, inner_start - 1)
            inner = t[inner_start:inner_end]
            parts = split_top_level_commas(inner)
            if len(parts) != 2:
                raise ValueError(f"Expected 2 template args in map type: {t}")
            key_go = to_go_type(parts[0], polymorphic_registry, polymorphic_model_bases)
            if key_go.startswith("[]") or key_go.startswith("map["):
                key_go = "string"
            val_go = to_go_type(parts[1], polymorphic_registry, polymorphic_model_bases)
            return f"map[{key_go}]{val_go}"

    # Polymorphic<X, Y> — проверяем, не является ли X известным polymorphic base
    if 'Polymorphic<' in t:
        # Извлекаем inner типы
        idx = t.find('Polymorphic<')
        poly_t = t[idx:]
        inner_start = len('Polymorphic<')
        inner_end = find_matching(poly_t, inner_start - 1)
        inner = poly_t[inner_start:inner_end]
        parts = split_top_level_commas(inner)
        unique_parts = list(dict.fromkeys(parts))

        # Если все части — это один и тот же base тип из polymorphic_models,
        # то возвращаем его контейнер напрямую
        if polymorphic_model_bases and len(unique_parts) == 1:
            base = unique_parts[0]
            base_clean = re.sub(r'\b(class|struct)\s+', '', base).strip()
            if base_clean in polymorphic_model_bases:
                container_name = _base_container_name(base_clean)
                return container_name

        go_name = make_polymorphic_go_name(t)
        if polymorphic_registry is not None:
            polymorphic_registry[t] = go_name
        return go_name

    # Проверяем, является ли тип базовым типом из polymorphic_models
    if polymorphic_model_bases and t in polymorphic_model_bases:
        return _base_container_name(t)

    if '<' in t:
        base_end = t.index('<')
        base_name = t[:base_end].replace('::', '')
        return base_name

    return t.replace('::', '')


def _base_container_name(cpp_full_name: str) -> str:
    """Возвращает Go-имя контейнера для polymorphic base типа."""
    name = cpp_full_name
    for prefix in CPP_NAMESPACE_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    # Убираем :: и прочее
    name = name.replace('::', '').replace('-', '').replace('_', '')
    for prefix in CPP_PREFIX_STRIPPED:
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return name + "Container"


def collect_all_types(packets_json: dict) -> Set[str]:
    types: Set[str] = set()
    for packet in packets_json.get("packets", []) + packets_json.get("events", []):
        for part in ("request", "response"):
            obj = packet.get(part)
            if obj and "fields" in obj:
                for f in obj["fields"]:
                    types.add(f["type"])
    for model in packets_json.get("models", {}).values():
        for f in model.get("fields", []):
            types.add(f["type"])
    # Типы из polymorphic_models вариантов
    for base_data in packets_json.get("polymorphic_models", {}).values():
        for variant_data in base_data.get("variants", {}).values():
            for f in variant_data.get("fields", []):
                types.add(f["type"])
    return types


def build_type_mapping(packets_json: dict) -> TypeMappingResult:
    mapping: Dict[str, str] = {}
    polymorphic_registry: Dict[str, str] = {}

    # Собираем множество базовых типов из polymorphic_models
    polymorphic_model_bases: Set[str] = set(packets_json.get("polymorphic_models", {}).keys())

    all_types = collect_all_types(packets_json)

    for cpp_type in all_types:
        go_type = to_go_type(cpp_type, polymorphic_registry, polymorphic_model_bases)
        mapping[cpp_type] = go_type

    polymorphic_params: Dict[str, List[Dict[str, str]]] = {}
    for poly_cpp, go_name in polymorphic_registry.items():
        unique_parts, _ = _parse_polymorphic_parts(poly_cpp)
        entries = []
        for p in unique_parts:
            p_clean = re.sub(r'\b(class|struct)\s+', '', p)
            go_type = to_go_type(p_clean, polymorphic_model_bases=polymorphic_model_bases)
            method_name = p.split('::')[-1]
            entries.append({"go_type": go_type, "method_name": method_name})
        polymorphic_params[go_name] = entries

    return TypeMappingResult(
        mapping=mapping,
        polymorphic_registry=polymorphic_registry,
        polymorphic_params=polymorphic_params,
    )


# ---------- 2. Генератор Go-кода ----------

ZERO_VALUES: Dict[str, str] = {
    "int8": "0", "int16": "0", "int32": "0", "int64": "0",
    "int": "0",
    "float32": "0.0", "float64": "0.0",
    "bool": "false",
    "string": '""',
}


def zero_value(base_type: str) -> str:
    if base_type in ZERO_VALUES:
        return ZERO_VALUES[base_type]
    if base_type.startswith("[]") or base_type.startswith("map["):
        return "nil"
    return f"{base_type}{{}}"


class Codegen:
    def __init__(self, json_path: str, package_name: str = "main") -> None:
        self.json_path = json_path
        self.package_name = package_name
        self._raw_data = json.loads(Path(json_path).read_text())

        # Обязательный ключ — падаем если нет
        self._polymorphic_models: Dict[str, Any] = self._raw_data["polymorphic_models"]

        self._mapping_types: TypeMappingResult = build_type_mapping(self._raw_data)

        self._models = self._raw_data["models"]
        self._packets = self._raw_data["packets"]
        self._events = self._raw_data.get("events", [])
        self._all_entries = self._packets + self._events

        raw_version: str = self._raw_data["app_version"]
        self._app_version = ".".join(raw_version.split(".")[:3])
        self._build_number = self._raw_data.get("build_number", 0)
        self._rpc_version = self._raw_data["rpc_ver"]

        self._models_code: List[str] = []
        self._packets_code: List[str] = []
        self._polymorphic_code: List[str] = []
        self._opcodes_code: List[str] = []
        self._enums_code: List[str] = []
        self._transport_code: List[str] = []
        self._client_code: List[str] = []
        self._struct_registry: Set[str] = set()

        # Имена Go-структур которые генерируются из polymorphic_models вариантов
        self._polymorphic_variant_structs: Set[str] = set()

    # ---------- helpers ----------

    @staticmethod
    def _strip_known_prefixes(s: str) -> str:
        for prefix in CPP_PREFIX_STRIPPED:
            if prefix in s:
                s = s.replace(prefix, "", 1)
                break
        return s

    @staticmethod
    def _normalize_struct_name(name: str) -> str:
        name = name.replace(':', '').replace('-', '').replace('_', '')
        return Codegen._strip_known_prefixes(name)

    @staticmethod
    def _normalize_field_name(name: str, is_private: bool = False) -> str:
        name = name.replace('-', '').replace('_', '').replace(' ', '')
        if not name:
            return "Field"
        if is_private:
            return name[0].lower() + name[1:]
        return name[0].upper() + name[1:]

    def _convert_cpp_type_to_go_type(self, cpp_type: str) -> str:
        go_type = self._mapping_types.mapping[cpp_type]
        return self._strip_known_prefixes(go_type)

    def _file_header(self, extra_imports: str = "") -> List[str]:
        header = ["// Autogenerated. DO NOT EDIT", "", f"package {self.package_name}", ""]
        if extra_imports:
            header.append(extra_imports)
            header.append("")
        return header

    # ---------- struct generation ----------

    def _generate_struct_and_getters(self, full_name: str, fields: List[Any], target: List[str]):
        model_name = self._normalize_struct_name(full_name)
        if model_name in self._struct_registry:
            return
        self._struct_registry.add(model_name)

        target.append(f"type {model_name} struct {{")
        for f in fields:
            field_name = self._normalize_field_name(f["name"])
            go_type = self._convert_cpp_type_to_go_type(f["type"])
            if go_type.startswith("*"):
                json_tag = f'`json:"{f["name"]},omitempty" msgpack:"{f["name"]},omitempty"`'
            else:
                json_tag = f'`json:"{f["name"]}" msgpack:"{f["name"]}"`'
            target.append(f"  {field_name} {go_type} {json_tag}")
        target.extend(["}", ""])

        receiver = model_name[0].lower()
        for f in fields:
            field_name = self._normalize_field_name(f["name"])
            go_type = self._convert_cpp_type_to_go_type(f["type"])
            is_ptr = go_type.startswith("*")
            base_type = go_type[1:] if is_ptr else go_type
            zero = "nil" if base_type.startswith("*") else zero_value(base_type)

            lines = [f"func ({receiver} *{model_name}) Get{field_name}() ({base_type}, bool) {{"]
            if is_ptr:
                lines.extend([
                    f"  if {receiver}.{field_name} != nil {{",
                    f"    return *{receiver}.{field_name}, true",
                    "  }",
                    f"  return {zero}, false",
                ])
            else:
                lines.append(f"  return {receiver}.{field_name}, true")
            lines.append("}")
            target.extend(lines)
        target.append("")

    def _generate_models(self):
        for model_full_name, model_data in self._models.items():
            self._generate_struct_and_getters(model_full_name, model_data["fields"], self._models_code)

    def _generate_packets(self):
        error_def = self._raw_data.get("error")
        if error_def:
            self._packets_code.append("type ApiError struct {")
            for field_name, cpp_type in error_def.items():
                go_type = to_go_type(cpp_type)
                json_tag = f'`json:"{field_name}" msgpack:"{field_name}"`'
                go_field = self._normalize_field_name(field_name)
                self._packets_code.append(f"  {go_field} {go_type} {json_tag}")
            self._packets_code.extend([
                "}",
                "",
                "func (e *ApiError) ErrorString() string {",
                "  if e.Title != \"\" {",
                "    return e.Title + \": \" + e.Message",
                "  }",
                "  return e.Message",
                "}",
                "",
            ])
        for packet in self._all_entries:
            if not packet.get("request") and not packet.get("response"):
                continue
            if packet.get("request"):
                self._generate_struct_and_getters(
                    packet["request"]["full_name"],
                    packet["request"]["fields"],
                    self._packets_code
                )
            if packet.get("response"):
                self._generate_struct_and_getters(
                    packet["response"]["full_name"],
                    packet["response"]["fields"],
                    self._packets_code
                )

    # ---------- polymorphic_models generation ----------

    def _variant_go_struct_name(self, cpp_variant_name: str) -> str:
        """Нормализует имя варианта в Go struct имя."""
        return self._normalize_struct_name(cpp_variant_name)

    def _base_container_go_name(self, cpp_base_name: str) -> str:
        return _base_container_name(cpp_base_name)

    def _generate_polymorphic_variant_struct(
        self,
        variant_cpp_name: str,
        variant_data: Dict[str, Any],
        target: List[str],
    ):
        """
        Генерирует Go struct для конкретного варианта polymorphic типа.
        Пропускает если struct с таким именем уже сгенерирован.
        """
        struct_name = self._variant_go_struct_name(variant_cpp_name)
        if struct_name in self._struct_registry:
            return
        self._struct_registry.add(struct_name)
        self._polymorphic_variant_structs.add(struct_name)

        fields = variant_data.get("fields", [])

        target.append(f"// {struct_name} is a variant of a polymorphic type.")
        target.append(f"// Source: {variant_cpp_name}")
        target.append(f"type {struct_name} struct {{")

        for f in fields:
            raw_field_name = f["name"]
            go_field_name = self._normalize_field_name(raw_field_name)
            cpp_type = f["type"]

            # Типы из вариантов могут не быть в общем маппинге — конвертируем напрямую
            if cpp_type in self._mapping_types.mapping:
                go_type = self._convert_cpp_type_to_go_type(cpp_type)
            else:
                polymorphic_model_bases = set(self._polymorphic_models.keys())
                go_type = to_go_type(cpp_type, polymorphic_model_bases=polymorphic_model_bases)
                go_type = self._strip_known_prefixes(go_type)

            required = f.get("required", True)
            is_ptr = go_type.startswith("*")

            if is_ptr or not required:
                json_tag = f'`json:"{raw_field_name},omitempty" msgpack:"{raw_field_name},omitempty"`'
            else:
                json_tag = f'`json:"{raw_field_name}" msgpack:"{raw_field_name}"`'

            target.append(f"  {go_field_name} {go_type} {json_tag}")

        target.extend(["}", ""])

    def _generate_base_container(
        self,
        cpp_base_name: str,
        variants: Dict[str, Any],
        target: List[str],
    ):
        """
        Генерирует контейнер для polymorphic base типа.

        Дизайн:
          - Хранит raw []byte от msgpack
          - TryAs{Variant}() — пытается десериализовать в конкретный вариант
          - Пользователь сам выбирает подходящий вариант по контексту
          - UnmarshalMsgpack / MarshalMsgpack для прозрачной сериализации
          - SetValue(v interface{}) для отправки конкретного варианта
        """
        container_name = self._base_container_go_name(cpp_base_name)
        if container_name in self._struct_registry:
            return
        self._struct_registry.add(container_name)

        # Собираем уникальные варианты (дедупликация по go struct name)
        seen_variants: Dict[str, str] = {}  # go_struct_name -> cpp_variant_name
        for cpp_variant_name in variants:
            go_struct_name = self._variant_go_struct_name(cpp_variant_name)
            if go_struct_name not in seen_variants:
                seen_variants[go_struct_name] = cpp_variant_name

        short_base = cpp_base_name.split("::")[-1]

        target.extend([
            f"// {container_name} is a container for the polymorphic type {short_base}.",
            f"// It stores the raw msgpack bytes and provides TryAs* methods for each known variant.",
            f"// Use the appropriate TryAs* method based on your application context",
            f"// (e.g. check a sibling _type field if available, or try each variant).",
            f"type {container_name} struct {{",
            f"  raw []byte",
            f"  enc interface{{}}",
            f"}}",
            "",
            f"// UnmarshalMsgpack captures raw bytes for deferred typed decoding.",
            f"func (c *{container_name}) UnmarshalMsgpack(data []byte) error {{",
            f"  c.raw = make([]byte, len(data))",
            f"  copy(c.raw, data)",
            f"  return nil",
            f"}}",
            "",
            f"// MarshalMsgpack serializes the container.",
            f"// If SetValue was called, serializes that value; otherwise re-serializes raw bytes.",
            f"func (c *{container_name}) MarshalMsgpack() ([]byte, error) {{",
            f"  if c.enc != nil {{",
            f"    return msgpack.Marshal(c.enc)",
            f"  }}",
            f"  if c.raw != nil {{",
            f"    return c.raw, nil",
            f"  }}",
            f'  return nil, fmt.Errorf("{container_name}: no value to marshal")',
            f"}}",
            "",
            f"// New{container_name} creates a container wrapping a concrete variant value.",
            f"// Pass a pointer to any of the {short_base} variant structs.",
            f"func New{container_name}(v interface{{}}) {container_name} {{",
            f"  return {container_name}{{enc: v}}",
            f"}}",
            "",
            f"// SetValue sets a concrete variant value for marshaling.",
            f"// Pass a pointer to any of the {short_base} variant structs.",
            f"func (c *{container_name}) SetValue(v interface{{}}) {{",
            f"  c.enc = v",
            f"}}",
            "",
            f"// RawBytes returns the raw msgpack bytes (for debugging or custom decoding).",

            f"func (c *{container_name}) RawBytes() []byte {{",
            f"  return c.raw",
            f"}}",
            "",
        ])

        # TryAs* методы для каждого варианта
        for go_struct_name in seen_variants:
            short_method_name = go_struct_name
            # Убираем суффикс из CPP namespace если он остался
            for prefix in CPP_PREFIX_STRIPPED:
                if short_method_name.startswith(prefix):
                    short_method_name = short_method_name[len(prefix):]
                    break

            target.extend([
                f"// TryAs{short_method_name} attempts to decode the container as {go_struct_name}.",
                f"// Returns an error if decoding fails — this does NOT guarantee the type is correct.",
                f"// Use contextual information (e.g. a _type field) to pick the right variant.",
                f"func (c *{container_name}) TryAs{short_method_name}() (*{go_struct_name}, error) {{",
                f"  if c.raw == nil {{",
                f'    return nil, fmt.Errorf("{container_name}.TryAs{short_method_name}: no raw data")',
                f"  }}",
                f"  var v {go_struct_name}",
                f"  if err := msgpack.Unmarshal(c.raw, &v); err != nil {{",
                f'    return nil, fmt.Errorf("{container_name}.TryAs{short_method_name}: %w", err)',
                f"  }}",
                f"  return &v, nil",
                f"}}",
                "",
            ])

    def _generate_polymorphic_models(self):
        """
        Основная точка входа для генерации кода из polymorphic_models.
        Порядок:
          1. Для каждого base типа генерируем struct'ы всех вариантов
          2. Генерируем контейнер base типа
        """
        for cpp_base_name, base_data in self._polymorphic_models.items():
            variants: Dict[str, Any] = base_data.get("variants", {})

            # Шаг 1: struct'ы вариантов
            for cpp_variant_name, variant_data in variants.items():
                self._generate_polymorphic_variant_struct(
                    cpp_variant_name,
                    variant_data,
                    self._polymorphic_code,
                )

            # Шаг 2: контейнер
            self._generate_base_container(
                cpp_base_name,
                variants,
                self._polymorphic_code,
            )

    def _generate_legacy_polymorphic_types(self):
        """
        Генерирует старые Polymorphic<T1,T2> контейнеры для типов,
        которые НЕ покрыты polymorphic_models.
        """
        polymorphic_model_bases = set(self._polymorphic_models.keys())

        for go_name, entries in self._mapping_types.polymorphic_params.items():
            go_name_short = self._strip_known_prefixes(go_name)

            # Пропускаем если все parts относятся к известным base типам
            all_covered = all(
                any(
                    entry["go_type"].replace("Container", "") in _base_container_name(b)
                    for b in polymorphic_model_bases
                )
                for entry in entries
            )
            if all_covered:
                continue

            if go_name_short in self._struct_registry:
                continue
            self._struct_registry.add(go_name_short)

            self._polymorphic_code.extend([
                f"// {go_name_short} is a raw polymorphic container (legacy, no schema available).",
                f"type {go_name_short} struct {{",
                "  raw []byte",
                "  enc interface{}",
                "}",
                "",
                f"func New{go_name_short}(v interface{{}}) {go_name_short} {{",
                f"  return {go_name_short}{{enc: v}}",
                "}",
                "",
                f"func (p *{go_name_short}) UnmarshalMsgpack(data []byte) error {{",
                "  p.raw = data",
                "  return nil",
                "}",
                "",
                f"func (p *{go_name_short}) MarshalMsgpack() ([]byte, error) {{",
                "  if p.enc != nil {",
                "    return msgpack.Marshal(p.enc)",
                "  }",
                "  if p.raw != nil {",
                "    return p.raw, nil",
                "  }",
                '  return nil, fmt.Errorf("empty polymorphic value")',
                "}",
                "",
            ])
            for entry in entries:
                go_type = entry["go_type"]
                go_type_short = self._strip_known_prefixes(go_type)
                method = entry["method_name"]
                zero = zero_value(go_type_short)
                self._polymorphic_code.extend([
                    f"func (p *{go_name_short}) As{method}() ({go_type_short}, bool) {{",
                    f"  var v {go_type_short}",
                    "  if msgpack.Unmarshal(p.raw, &v) == nil {",
                    "    return v, true",
                    "  }",
                    f"  return {zero}, false",
                    "}",
                    ""
                ])

    # ---------- transport ----------

    def _gen_transport_imports(self) -> List[str]:
        return [
            'import (',
            '  "bytes"',
            '  "encoding/binary"',
            '  "encoding/hex"',
            '  "fmt"',
            '  "log"',
            '',
            '  lz4 "github.com/pierrec/lz4/v4"',
            '  "github.com/vmihailenco/msgpack/v5"',
            ')',
            "",
        ]

    def _gen_transport_packet_struct(self) -> List[str]:
        return [
            "const (",
            f"  ProtocolVersion = {self._rpc_version}",
            "  MaxDecompressedSize = 8 * 1024 * 1024",
            ")",
            "",
            "// Packet represents a generic protocol packet.",
            "type Packet struct {",
            '  Ver        uint8       `json:"ver" msgpack:"ver"`',
            '  Cmd        uint16      `json:"cmd" msgpack:"cmd"`',
            '  Seq        uint8       `json:"seq" msgpack:"seq"`',
            '  Opcode     uint16      `json:"opcode" msgpack:"opcode"`',
            '  Payload    interface{} `json:"payload" msgpack:"payload"`',
            '  RawPayload []byte      `json:"-" msgpack:"-"`',
            "}",
            "",
        ]

    def _gen_opcode_registry(self) -> List[str]:
        opcode_map = self._build_opcode_map()
        lines = [
            "// opcodeResponseRegistry maps response opcodes to typed factory functions.",
            "var opcodeResponseRegistry = map[uint16]func() interface{}{",
        ]
        for opcode, info in sorted(opcode_map.items()):
            if info["resp_full_name"] == "":
                continue
            resp_name = self._normalize_struct_name(info["resp_full_name"])
            opcode_const = self._opcode_const_name(info["resp_full_name"])
            opcode_ref = opcode_const if opcode_const else str(opcode)
            lines.append(f'  {opcode_ref}: func() interface{{}} {{ return &{resp_name}{{}} }},')
        lines.extend(["}", ""])
        return lines

    def _gen_transport_pack(self) -> List[str]:
        return [
            "// PackPacket packs a packet for TCP transport (msgpack + optional lz4 raw block).",
            "func PackPacket(ver uint8, cmd uint16, seq uint8, opcode uint16, payload interface{}) ([]byte, error) {",
            "  var buf bytes.Buffer",
            "  enc := msgpack.NewEncoder(&buf)",
            '  enc.SetCustomStructTag("msgpack")',
            "  if err := enc.Encode(payload); err != nil {",
            '    return nil, fmt.Errorf("msgpack encode payload: %w", err)',
            "  }",
            "  payloadBytes := buf.Bytes()",
            "",
            "  compFlag := byte(0)",
            "  if len(payloadBytes) > 4096 {",
            "    dst := make([]byte, lz4.CompressBlockBound(len(payloadBytes)))",
            "    n, err := lz4.CompressBlock(payloadBytes, dst, nil)",
            "    if err != nil {",
            '      return nil, fmt.Errorf("lz4 compress: %w", err)',
            "    }",
            "    payloadBytes = dst[:n]",
            "    compFlag = 1",
            "  }",
            "",
            "  payloadLen := len(payloadBytes) & 0xFFFFFF",
            "  packedLen := uint32(compFlag)<<24 | uint32(payloadLen)",
            "",
            '  header := make([]byte, 10)',
            "  header[0] = ver",
            "  binary.BigEndian.PutUint16(header[1:3], cmd)",
            "  header[3] = seq",
            "  binary.BigEndian.PutUint16(header[4:6], opcode)",
            "  binary.BigEndian.PutUint32(header[6:10], packedLen)",
            "  return append(header, payloadBytes...), nil",
            "}",
            "",
        ]

    def _gen_transport_unpack(self) -> List[str]:
        return [
            "// UnpackPacket unpacks a TCP packet.",
            "func UnpackPacket(data []byte) (*Packet, error) {",
            "  if len(data) < 10 {",
            '    return nil, fmt.Errorf("packet too short: %d bytes", len(data))',
            "  }",
            "  ver := data[0]",
            "  cmd := binary.BigEndian.Uint16(data[1:3])",
            "  seq := data[3]",
            "  opcode := binary.BigEndian.Uint16(data[4:6])",
            "  packedLen := binary.BigEndian.Uint32(data[6:10])",
            "  compFlag := packedLen >> 24",
            "  payloadLen := int(packedLen & 0xFFFFFF)",
            "",
            "  if len(data) < 10+payloadLen {",
            '    return nil, fmt.Errorf("packet body incomplete: need %d, have %d", 10+payloadLen, len(data))',
            "  }",
            "  payloadBytes := data[10 : 10+payloadLen]",
            "",
            "  if compFlag != 0 {",
            "    decompressed := make([]byte, MaxDecompressedSize)",
            "    n, err := lz4.UncompressBlock(payloadBytes, decompressed)",
            "    if err != nil {",
            '      return nil, fmt.Errorf("lz4 decompress: %w", err)',
            "    }",
            "    payloadBytes = decompressed[:n]",
            "  }",
            "",
            "  var payload interface{}",
            "  if len(payloadBytes) > 0 {",
            "    dec := msgpack.NewDecoder(bytes.NewReader(payloadBytes))",
            '    dec.SetCustomStructTag("msgpack")',
            "    if cmd != 3 {",
            "      if factory, ok := opcodeResponseRegistry[opcode]; ok {",
            "        payload = factory()",
            "        if err := dec.Decode(payload); err != nil {",
            '          log.Printf("typed decode failed opcode=%d len=%d hex=%s: %v, falling back", opcode, len(payloadBytes), hex.EncodeToString(payloadBytes), err)',
            "          payload = nil",
            "          dec = msgpack.NewDecoder(bytes.NewReader(payloadBytes))",
            '          dec.SetCustomStructTag("msgpack")',
            "          if err := dec.Decode(&payload); err != nil {",
            '            log.Printf("fallback decode failed opcode=%d len=%d hex=%s: %v, returning nil payload", opcode, len(payloadBytes), hex.EncodeToString(payloadBytes), err)',
            "          }",
            "        }",
            "      } else {",
            "        if err := dec.Decode(&payload); err != nil {",
            '          log.Printf("fallback decode failed opcode=%d len=%d hex=%s: %v, returning nil payload", opcode, len(payloadBytes), hex.EncodeToString(payloadBytes), err)',
            "        }",
            "      }",
            "    } else {",
            "      if err := dec.Decode(&payload); err != nil {",
            '        log.Printf("fallback decode failed opcode=%d len=%d hex=%s: %v, returning nil payload", opcode, len(payloadBytes), hex.EncodeToString(payloadBytes), err)',
            "      }",
            "    }",
            "  }",
            "",
            "  return &Packet{Ver: ver, Cmd: cmd, Seq: seq, Opcode: opcode, Payload: payload, RawPayload: payloadBytes}, nil",
            "}",
            "",
        ]

    def _generate_transport(self):
        self._transport_code = (
            self._gen_transport_imports()
            + self._gen_transport_packet_struct()
            + self._gen_opcode_registry()
            + self._gen_transport_pack()
            + self._gen_transport_unpack()
        )

    # ---------- client ----------

    def _gen_client_imports(self) -> List[str]:
        return [
            "import (",
            '  "crypto/tls"',
            '  "encoding/json"',
            '  "errors"',
            '  "fmt"',
            '  "io"',
            '  "log"',
            '  "net"',
            '  "sync"',
            '  "time"',
            '',
            '  "github.com/vmihailenco/msgpack/v5"',
            ')',
            "",
        ]

    def _gen_client_struct(self) -> List[str]:
        return [
            "// Client is the main API client.",
            "type Client struct {",
            "  AppVersion  string",
            "  BuildNumber int32",
            "  VerboseLog bool",
            "  conn       net.Conn",
            "  seq        uint8",
            "  mu         sync.Mutex",
            "  writeMu    sync.Mutex",
            "  pending    map[uint8]chan *Packet",
            "  handlers   map[uint16][]func(*Packet)",
            "  closeCh    chan struct{}",
            "}",
            "",
        ]

    def _gen_client_new(self) -> List[str]:
        return [
            f"func NewClient() *Client {{",
            f"  return &Client{{",
            f"    AppVersion:  \"{self._app_version}\",",
            f"    BuildNumber: {self._build_number},",
            f"    VerboseLog: true,",
            f"    pending:    make(map[uint8]chan *Packet),",
            f"    handlers:   make(map[uint16][]func(*Packet)),",
            f"    closeCh:    make(chan struct{{}}),",
            f"  }}",
            f"}}",
            "",
        ]

    def _gen_client_connect(self) -> List[str]:
        return [
            '// DefaultServerAddr is the default TCP server address.',
            'const DefaultServerAddr = "api.oneme.ru:443"',
            "",
            "func (c *Client) ConnectTCP(addr string) error {",
            '  conn, err := tls.Dial("tcp", addr, &tls.Config{',
            '    ServerName: "",',
            "  })",
            "  if err != nil { return err }",
            "  c.conn = conn",
            "  go c.readLoop()",
            "  return nil",
            "}",
            "",
            "func (c *Client) Connect() error {",
            "  return c.ConnectTCP(DefaultServerAddr)",
            "}",
            "",
        ]

    def _gen_client_close(self) -> List[str]:
        return [
            "func (c *Client) Close() error {",
            "  close(c.closeCh)",
            "  if c.conn != nil {",
            "    return c.conn.Close()",
            "  }",
            "  return nil",
            "}",
            "",
        ]

    def _gen_client_cancel_pending(self) -> List[str]:
        return [
            "func (c *Client) cancelPending(err error) {",
            "  c.mu.Lock()",
            "  defer c.mu.Unlock()",
            "  errPkt := &Packet{Cmd: 3, Payload: err.Error()}",
            "  for seq, ch := range c.pending {",
            "    ch <- errPkt",
            "    delete(c.pending, seq)",
            "  }",
            "}",
            "",
        ]

    def _gen_client_read_loop(self) -> List[str]:
        return [
            "func (c *Client) readLoop() {",
            "  var loopErr error",
            "  defer func() {",
            "    if loopErr != nil {",
            "      c.cancelPending(loopErr)",
            "    }",
            "  }()",
            "",
            "  for {",
            "    select {",
            "    case <-c.closeCh:",
            "      return",
            "    default:",
            "    }",
            '    header := make([]byte, 10)',
            "    _, err := io.ReadFull(c.conn, header)",
            "    if err != nil {",
            "      loopErr = err",
            '      log.Printf("tcp read header: %v", err)',
            "      return",
            "    }",
            "    packedLen := int(header[6])<<24 | int(header[7])<<16 | int(header[8])<<8 | int(header[9])",
            "    payloadLen := packedLen & 0xFFFFFF",
            "    body := make([]byte, payloadLen)",
            "    _, err = io.ReadFull(c.conn, body)",
            "    if err != nil {",
            "      loopErr = err",
            '      log.Printf("tcp read body: %v", err)',
            "      return",
            "    }",
            "    p, err := UnpackPacket(append(header, body...))",
            "    if err != nil {",
            '      log.Printf("unpack error: %v", err)',
            "      continue",
            "    }",
            "    if c.VerboseLog {",
            "      data, _ := json.Marshal(p)",
            '      log.Printf("<<< %s", string(data))',
            "    }",
            "    c.dispatch(p)",
            "  }",
            "}",
            "",
        ]

    def _gen_client_dispatch(self) -> List[str]:
        return [
            "func (c *Client) dispatch(p *Packet) {",
            "  c.mu.Lock()",
            "  _, isNotification := notificationOpcodes[p.Opcode]",
            "  ch, ok := c.pending[p.Seq]",
            "  if ok && !isNotification {",
            "    delete(c.pending, p.Seq)",
            "    c.mu.Unlock()",
            "    ch <- p",
            "    return",
            "  }",
            "  c.mu.Unlock()",
            "  c.mu.Lock()",
            "  handlers := c.handlers[p.Opcode]",
            "  c.mu.Unlock()",
            "  for _, h := range handlers {",
            "    h(p)",
            "  }",
            "}",
            "",
        ]

    def _gen_client_on_handler(self) -> List[str]:
        return [
            "func (c *Client) On(opcode uint16, handler func(*Packet)) {",
            "  c.mu.Lock()",
            "  defer c.mu.Unlock()",
            "  c.handlers[opcode] = append(c.handlers[opcode], handler)",
            "}",
            "",
        ]

    def _gen_client_send_raw(self) -> List[str]:
        error_def = self._raw_data.get("error", {})

        error_extract_lines = []
        error_field_names = []
        for field_name in error_def:
            go_field = self._normalize_field_name(field_name)
            error_extract_lines.append(f'    if v, ok := m["{field_name}"].(string); ok {{ apiErr.{go_field} = v }}')
            error_field_names.append(f"apiErr.{go_field}")

        if len(error_field_names) >= 2:
            strict_check = " && ".join(f'{fn} != ""' for fn in error_field_names)
        elif len(error_field_names) == 1:
            strict_check = error_field_names[0] + ' != ""'
        else:
            strict_check = 'false'

        lines = [
            "func (c *Client) sendRaw(opcode uint16, payload interface{}) (*Packet, error) {",
            "  c.mu.Lock()",
            "  seq := c.seq",
            "  c.seq++",
            "  if _, busy := c.pending[seq]; busy {",
            "    c.mu.Unlock()",
            '    return nil, errors.New("seq overflow: too many concurrent requests")',
            "  }",
            "  ch := make(chan *Packet, 1)",
            "  c.pending[seq] = ch",
            "  c.mu.Unlock()",
            "",
            "  data, encErr := PackPacket(ProtocolVersion, 0, seq, opcode, payload)",
            "  if encErr != nil {",
            "    c.mu.Lock()",
            "    delete(c.pending, seq)",
            "    c.mu.Unlock()",
            "    return nil, encErr",
            "  }",
            "",
            '  if c.VerboseLog { raw, _ := json.Marshal(payload); log.Printf(">>> OP=%d %s", opcode, string(raw)) }',
            "  c.writeMu.Lock()",
            "  _, writeErr := c.conn.Write(data)",
            "  c.writeMu.Unlock()",
            "  if writeErr != nil {",
            "    c.mu.Lock()",
            "    delete(c.pending, seq)",
            "    c.mu.Unlock()",
            "    return nil, writeErr",
            "  }",
            "",
            "  select {",
            "  case resp := <-ch:",
        ]

        if error_def:
            lines.extend([
                '    if m, ok := resp.Payload.(map[string]interface{}); ok {',
                "      apiErr := ApiError{}",
            ])
            lines.extend(error_extract_lines)
            lines.extend([
                f"      if {strict_check} {{",
                "        return nil, fmt.Errorf(\"api error: %s\", apiErr.ErrorString())",
                "      }",
                "    }",
            ])

        lines.extend([
            "    if resp.Opcode != opcode {",
            '      return nil, fmt.Errorf("opcode mismatch: expected %d, got %d", opcode, resp.Opcode)',
            "    }",
            "    return resp, nil",
            "  case <-time.After(30 * time.Second):",
            "    c.mu.Lock()",
            "    delete(c.pending, seq)",
            "    c.mu.Unlock()",
            '    return nil, fmt.Errorf("request timeout (opcode=%d seq=%d)", opcode, seq)',
            "  }",
            "}",
            "",
        ])
        return lines

    def _gen_client_send_request(self) -> List[str]:
        return [
            "func (c *Client) Send(opcode uint16, payload interface{}, respPayload interface{}) error {",
            "  pkt, err := c.sendRaw(opcode, payload)",
            "  if err != nil {",
            "    return err",
            "  }",
            "  if respPayload != nil {",
            "    raw, err := msgpack.Marshal(pkt.Payload)",
            "    if err != nil {",
            '      return fmt.Errorf("encode response: %w", err)',
            "    }",
            '    if err := msgpack.Unmarshal(raw, respPayload); err != nil {',
            '      return fmt.Errorf("decode response: %w", err)',
            "    }",
            "  }",
            "  return nil",
            "}",
            "",
        ]

    def _gen_client_typed_methods(self, opcode_map: dict) -> List[str]:
        code = []
        for opcode, info in sorted(opcode_map.items(), key=lambda x: x[0]):
            if info["req_full_name"] == "":
                continue
            req_full_name = info["req_full_name"]
            resp_full_name = info["resp_full_name"]
            req_name = self._normalize_struct_name(req_full_name)

            if resp_full_name and not info["is_notification"]:
                resp_name = self._normalize_struct_name(resp_full_name)
                opcode_const = self._opcode_const_name(resp_full_name)
                if opcode_const:
                    method_name = "Send" + opcode_const[len("Opcode"):]
                    opcode_ref = opcode_const
                else:
                    method_name = f"SendOpcode{opcode}"
                    opcode_ref = str(opcode)

                code.extend([
                    f"// {method_name} sends {req_full_name} and returns {resp_full_name}.",
                    f"func (c *Client) {method_name}(req *{req_name}) (*{resp_name}, error) {{",
                    f"  pkt, err := c.sendRaw({opcode_ref}, req)",
                    "  if err != nil {",
                    "    return nil, err",
                    "  }",
                    f"  resp, ok := pkt.Payload.(*{resp_name})",
                    "  if ok {",
                    "    return resp, nil",
                    "  }",
                    "  if len(pkt.RawPayload) > 0 {",
                    f"    var resp {resp_name}",
                    "    if err := msgpack.Unmarshal(pkt.RawPayload, &resp); err == nil {",
                    "      return &resp, nil",
                    "    } else {",
                    f'      log.Printf("{method_name} raw unmarshal failed: %v", err)',
                    "    }",
                    "  }",
                    f'  return nil, fmt.Errorf("invalid response type: %T", pkt.Payload)',
                    "}",
                    "",
                ])
            elif not info["is_notification"]:
                req_name_for_const = req_full_name
                for p in CPP_NAMESPACE_PREFIXES:
                    if req_name_for_const.startswith(p):
                        req_name_for_const = req_name_for_const[len(p):]
                        break
                parts = req_name_for_const.split("::")
                go_name = ""
                for part in parts:
                    clean = part.replace('-', '').replace('_', '').replace(' ', '')
                    if clean:
                        go_name += clean[0].upper() + clean[1:]
                method_name = "Send" + go_name if go_name else f"SendOpcode{opcode}"

                code.extend([
                    f"// {method_name} sends {req_full_name} (fire-and-forget).",
                    f"func (c *Client) {method_name}(req *{req_name}) error {{",
                    f"  _, err := c.sendRaw({opcode}, req)",
                    "  return err",
                    "}",
                    "",
                ])
        return code

    def _build_opcode_map(self) -> dict:
        opcode_map = {}
        for packet in self._all_entries:
            op = packet["opcode"]
            req = packet.get("request")
            resp = packet.get("response")
            if req is None and resp is None:
                continue
            opcode_map[op] = {
                "opcode": op,
                "req_full_name": req["full_name"] if req else "",
                "resp_full_name": resp["full_name"] if resp else "",
                "req_fields": req["fields"] if req else [],
                "resp_fields": resp["fields"] if resp else [],
                "is_notification": (req is None or req.get("kind") == "NoParameters"),
            }
        return opcode_map

    def _gen_typed_push_handlers(self, opcode_map: dict) -> List[str]:
        code = []
        for opcode, info in sorted(opcode_map.items(), key=lambda x: x[0]):
            if not info["is_notification"]:
                continue
            resp_full_name = info["resp_full_name"]
            if not resp_full_name:
                continue
            resp_name = self._normalize_struct_name(resp_full_name)
            opcode_const = self._opcode_const_name(resp_full_name)
            opcode_ref = opcode_const if opcode_const else str(opcode)
            handler_name = "On" + opcode_const[len("Opcode"):] if opcode_const else f"OnOpcode{opcode}"

            code.extend([
                f"func (c *Client) {handler_name}(handler func(*{resp_name})) {{",
                f"  c.On({opcode_ref}, func(p *Packet) {{",
                f"    if v, ok := p.Payload.(*{resp_name}); ok {{",
                "      handler(v)",
                "      return",
                "    }",
                "    if len(p.RawPayload) > 0 {",
                f"      var v {resp_name}",
                "      if err := msgpack.Unmarshal(p.RawPayload, &v); err == nil {",
                "        handler(&v)",
                "      } else {",
                f'        log.Printf("{handler_name} raw unmarshal failed: %v", err)',
                "      }",
                "    }",
                "  })",
                "}",
                "",
            ])
        return code

    def _gen_notification_opcodes_map(self, opcode_map: dict) -> List[str]:
        lines = [
            "var notificationOpcodes = map[uint16]struct{}{",
        ]
        for opcode, info in sorted(opcode_map.items()):
            if info["is_notification"]:
                lines.append(f"  {opcode}: struct{{}}{{}},")
        lines.extend(["}", ""])
        return lines

    def _generate_client(self):
        opcode_map = self._build_opcode_map()
        self._client_code = (
            self._gen_client_imports()
            + self._gen_client_struct()
            + self._gen_client_new()
            + self._gen_client_connect()
            + self._gen_client_close()
            + self._gen_client_cancel_pending()
            + self._gen_client_read_loop()
            + self._gen_notification_opcodes_map(opcode_map)
            + self._gen_client_dispatch()
            + self._gen_client_on_handler()
            + self._gen_client_send_raw()
            + self._gen_client_send_request()
            + self._gen_client_typed_methods(opcode_map)
            + self._gen_typed_push_handlers(opcode_map)
        )

    # ---------- opcodes / enums ----------

    @staticmethod
    def _opcode_const_name(resp_full_name: str) -> Optional[str]:
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
            return None
        go_name = ""
        for part in meaningful_parts:
            clean = part.replace('-', '').replace('_', '').replace(' ', '')
            if clean:
                go_name += clean[0].upper() + clean[1:]
        return ("Opcode" + go_name) if go_name else None

    def _generate_opcodes(self):
        opcode_names = {}
        for packet in self._all_entries:
            op = packet["opcode"]
            resp = packet.get("response")
            if not resp or not resp.get("full_name"):
                continue
            name = self._opcode_const_name(resp["full_name"])
            if name:
                opcode_names[op] = name

        self._opcodes_code.extend([
            "const (",
        ])
        for opcode, name in sorted(opcode_names.items()):
            self._opcodes_code.append(f"  {name} uint16 = {opcode}")
        self._opcodes_code.extend([")", ""])

    def _generate_enums(self):
        string_enums = self._raw_data.get("string_enums", [])
        if not string_enums:
            return

        self._enums_code.extend([
            "const (",
        ])
        for name in string_enums:
            self._enums_code.append(f'  StringEnum_{name} = "{name}"')
        self._enums_code.extend([")", ""])

    # ---------- main entry ----------

    def convert(self) -> Dict[str, str]:
        self._models_code.clear()
        self._packets_code.clear()
        self._polymorphic_code.clear()
        self._transport_code.clear()
        self._client_code.clear()
        self._opcodes_code.clear()
        self._enums_code.clear()
        self._struct_registry.clear()
        self._polymorphic_variant_structs.clear()

        # Порядок важен: polymorphic structs до models/packets,
        # чтобы _struct_registry не генерировал их повторно
        self._generate_polymorphic_models()
        self._generate_legacy_polymorphic_types()
        self._generate_models()
        self._generate_packets()
        self._generate_transport()
        self._generate_client()
        self._generate_opcodes()
        self._generate_enums()

        polymorphic_imports = (
            'import (\n'
            '  "fmt"\n'
            '\n'
            '  "github.com/vmihailenco/msgpack/v5"\n'
            ')'
        )

        models_out = self._file_header() + self._models_code
        packets_out = self._file_header() + self._packets_code
        polymorphic_out = self._file_header(polymorphic_imports) + self._polymorphic_code
        transport_out = self._file_header() + self._transport_code
        client_out = self._file_header() + self._client_code

        return {
            "models.go": "\n".join(models_out),
            "packets.go": "\n".join(packets_out),
            "polymorphic.go": "\n".join(polymorphic_out),
            "transport.go": "\n".join(transport_out),
            "client.go": "\n".join(client_out),
            "opcodes.go": "\n".join(self._file_header() + self._opcodes_code),
            "enums.go": "\n".join(self._file_header() + self._enums_code),
        }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python generate.py packets.json [package_name] [output_dir]")
        sys.exit(1)

    pkg = sys.argv[2] if len(sys.argv) >= 3 else "main"
    out_dir = Path(sys.argv[3]) if len(sys.argv) >= 4 else Path(".")

    gen = Codegen(sys.argv[1], pkg)
    files = gen.convert()
    out_dir.mkdir(parents=True, exist_ok=True)
    for fname, content in files.items():
        (out_dir / fname).write_text(content, encoding="utf-8")
        print(f"Written {out_dir / fname}")