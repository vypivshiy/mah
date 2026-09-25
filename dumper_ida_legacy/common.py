"""
Shared constants, regexes, config values and tiny pure helpers.
No IDA-specific code belongs here.
"""
import re

# ── CONFIG ────────────────────────────────────────────────────────────────────
MAX_INIT_SIZE = 5000
PAYLOAD_VTABLE_DISTANCE = 0x400

# core.dll calls code like `Config::getApiVersionUint()` and cast to uint8
# TODO: extract automatically from config.dll
VER = 11

ERROR_PAYLOAD = {
    "error": "std::string",
    "localizedMessage": "std::string",
    "message": "std::string",
    "title": "std::string",
}

RE_VERSION = re.compile(rb"\d+\.\d+\.\d+[\.:]\d+")

_EMPTY_NAMES = frozenset(("EmptyResponse", "EmptyParameters", "NoParameters"))

# ── Regex for packet / event / creator parsing ────────────────────────────────
COMMON_PACKET_RE = re.compile(
    r"CommonPacket\s*<\s*(\d+)\s*,"
    r"\s*struct\s+(Api::OneMe::Packets::[\w:]+)"
    r"\s*,\s*struct\s+(Api::OneMe::Packets::[\w:]+)"
    r"\s*,"
)

COMMON_EVENT_PREFIX_RE = re.compile(r"CommonEvent\s*<")

_CREATOR_OPCODE_RE_1 = re.compile(r'LOWORD\([^)]*\)\s*=\s*(\d+)')
_CREATOR_OPCODE_RE_2 = re.compile(r'\*\(_WORD \*\)[^=]+=\s*(\d+)\s*;')
_CREATOR_OPCODE_RE_3 = re.compile(r'\*\(_DWORD \*\)[^=]+=\s*(\d+)\s*;')

# ── Model reference regex ─────────────────────────────────────────────────────
_API_MODEL_REF_RE = re.compile(r'Api::OneMe::(Types|Packets)::([\w:]+)')

# ── Upper-case enum string extraction (direct file scan) ─────────────────────
_UPPER_ENUM_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def _vtable_token(full_name):
    return full_name + "::`vftable'"


def _vtable_tokens(full_name):
    return (full_name + "::`vftable'", full_name + "::vftable")


def _line_has_vftable(line):
    return "`vftable'" in line or "::vftable" in line


def _is_likely_enum(s):
    """Filter out RTTI garbage, hex constants, and random codes."""
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
