"""
Shared constants, regexes, config values and tiny pure helpers.
No Binary Ninja-specific code belongs here.
"""
import re

MAX_INIT_SIZE = 5000
PAYLOAD_VTABLE_DISTANCE = 0x400

VER = 11

ERROR_PAYLOAD = {
    "error": "std::string",
    "localizedMessage": "std::string",
    "message": "std::string",
    "title": "std::string",
}

RE_VERSION = re.compile(rb"\d+\.\d+\.\d+[\.:]\d+")

_EMPTY_NAMES = frozenset(("EmptyResponse", "EmptyParameters", "NoParameters"))

COMMON_PACKET_RE = re.compile(
    r"CommonPacket\s*<\s*(\d+)\s*,"
    r"\s*struct\s+(Api::OneMe::Packets::[\w:]+)"
    r"\s*,\s*struct\s+(Api::OneMe::Packets::[\w:]+)"
    r"\s*,"
)

COMMON_EVENT_PREFIX_RE = re.compile(r"CommonEvent\s*<")

_CREATOR_OPCODE_RE_1 = re.compile(r"LOWORD\([^)]*\)\s*=\s*(\d+)")
_CREATOR_OPCODE_RE_2 = re.compile(r"\*\(_WORD \*\)[^=]+=\s*(\d+)\s*;")
_CREATOR_OPCODE_RE_3 = re.compile(r"\*\(_DWORD \*\)[^=]+=\s*(\d+)\s*;")
# Binary Ninja HLIL uses .w/.d suffixes for word/dword-sized writes
_CREATOR_OPCODE_RE_4 = re.compile(r"\.\w\s*=\s*(\d+)\s*$")

_API_MODEL_REF_RE = re.compile(r"Api::OneMe::(Types|Packets)::([\w:]+)")

_UPPER_ENUM_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")

_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]{0,63}$")


def _vtable_token(full_name):
    return full_name + "::`vftable'"


def _vtable_tokens(full_name):
    return (full_name + "::`vftable'", full_name + "::vftable")


def _line_has_vftable(line):
    return "`vftable'" in line or "::vftable" in line


def is_valid_field_name(s):
    return bool(s) and bool(_FIELD_RE.match(s))


def strip_vftable_suffix(full):
    """
    Strip ::`vftable'{for ...} / ::vftable suffix from a BN symbol name.
    Returns the base name without the vtable qualifier or {for ...} decoration.
    """
    brace = full.rfind("'{")
    if brace != -1:
        full = full[:brace]
    for suffix in ("::`vftable'", "::`vftable", "::vftable"):
        if full.endswith(suffix):
            return full[: -len(suffix)]
    return full


def is_serializable_member_vtable(full):
    """
    True if the symbol's core name (before ::`vftable'{for ...}) is a
    concrete SerializableMember<...>, NOT an ISerializableMember<...>.

    Handles both the demangled form (``Serialization::SerializableMember<...>``)
    and the MSVC mangled form (``.?AV?$SerializableMember@...``) that Binary
    Ninja leaves undemangled for long/truncated symbols.
    """
    base = strip_vftable_suffix(full)
    if base.startswith("Serialization::SerializableMember<"):
        return True
    return "?$SerializableMember@" in base


def is_iserializable_member_vtable(full):
    """True if the symbol's core name is an ISerializableMember<...>."""
    base = strip_vftable_suffix(full)
    return base.startswith("Serialization::ISerializableMember<")


def _is_likely_enum(s):
    if s[0].isdigit():
        return False
    if s.endswith("XZ"):
        return False
    if s.isdigit():
        return False
    if all(seg.isdigit() for seg in s.split("_") if seg):
        return False
    if "_" not in s and len(s) <= 6:
        digit_frac = sum(1 for c in s if c.isdigit()) / len(s)
        if digit_frac >= 0.4:
            return False
    return True
