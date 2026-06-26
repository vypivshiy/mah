"""
Type decomposition — converts raw C++ type strings from RTTI into structured
field descriptors that downstream code generators can consume without parsing
C++ template syntax.

Example:
    decompose_type("class std::optional<class std::vector<struct Api::OneMe::Types::Contact> >")
    -> {
        "full_type": "std::optional<std::vector<Api::OneMe::Types::Contact>>",
        "type": "Api::OneMe::Types::Contact",
        "optional": True,
        "array": True,
        "map": False,
        "map_key": None,
        "map_value": None,
        "polymorphic": False,
        "polymorphic_base": None,
    }
"""
import template_parser

_QUALIFIERS = ("class ", "struct ", "const ", "volatile ")


def _strip_qualifiers(s):
    """Repeatedly strip leading C++ qualifiers."""
    s = s.strip()
    changed = True
    while changed:
        changed = False
        for pfx in _QUALIFIERS:
            if s.startswith(pfx):
                s = s[len(pfx):].strip()
                changed = True
                break
    return s


def normalize_type(raw):
    """
    Recursively normalize a C++ type string from Binary Ninja's demangled output.

    - Strips class/struct/const/volatile qualifiers at every level.
    - Collapses std::basic_string<char,...> -> std::string
    - Collapses std::basic_string_view<char,...> -> std::string_view
    - Removes allocator/less template args from std::vector/std::map.
    """
    raw = _strip_qualifiers(raw)
    if not raw:
        return raw

    # Fast paths for common simple types
    if "<" not in raw:
        return raw

    # std::basic_string / std::basic_string_view simplification
    if raw.startswith("std::basic_string<"):
        return "std::string"
    if raw.startswith("std::basic_string_view<"):
        return "std::string_view"

    idx = raw.find("<")
    if idx == -1:
        return raw

    tpl_name = raw[:idx].strip()
    rest = raw[idx + 1:]

    # Find matching closing '>' at depth 0
    depth = 0
    close = -1
    for i, c in enumerate(rest):
        if c == "<":
            depth += 1
        elif c == ">":
            if depth == 0:
                close = i
                break
            depth -= 1

    if close == -1:
        return raw  # malformed, return as-is

    inner = rest[:close]
    args = template_parser._extract_tpl_args(inner)
    norm_args = [normalize_type(a) for a in args]

    if tpl_name in ("std::optional", "std::vector",
                     "std::shared_ptr", "std::unique_ptr"):
        if norm_args:
            return "{}<{}>".format(tpl_name, norm_args[0])
        return tpl_name

    if tpl_name in ("std::map", "std::unordered_map"):
        if len(norm_args) >= 2:
            return "{}<{}, {}>".format(tpl_name, norm_args[0], norm_args[1])
        return tpl_name

    if tpl_name == "Api::OneMe::Types::Polymorphic":
        if norm_args:
            return "Api::OneMe::Types::Polymorphic<{}>".format(norm_args[0])
        return tpl_name

    # Generic: keep all args
    return "{}<{}>".format(tpl_name, ", ".join(norm_args))


def _extract_polymorphic_base(s):
    """Return the normalized first arg T from a Polymorphic<T> substring, or None.

    Detection is by substring presence: any occurrence of "Polymorphic<"
    marks the type as polymorphic, regardless of how deeply it is nested
    inside std::optional / std::vector / std::map.
    """
    idx = s.find("Polymorphic<")
    if idx == -1:
        return None
    inner = s[idx + len("Polymorphic<"):]
    first = template_parser._extract_first_tpl_arg(inner)
    return normalize_type(first) if first else None


def decompose_type(raw_type):
    """
    Decompose a raw C++ type string into a structured dict.

    Returns:
        {
            "full_type": str,   # normalized original type
            "type": str | None, # unwrapped base type (None for pure maps)
            "optional": bool,   # wrapped in std::optional<>
            "array": bool,      # wrapped in std::vector<>
            "map": bool,        # is std::map<K,V>
            "map_key": str | None,
            "map_value": str | None,
            "polymorphic": bool,        # contains Api::OneMe::Types::Polymorphic<T>
            "polymorphic_base": str | None,  # inner base type T
        }
    """
    full = normalize_type(raw_type)

    poly_base = _extract_polymorphic_base(full)

    result = {
        "full_type": full,
        "type": full,
        "optional": False,
        "array": False,
        "map": False,
        "map_key": None,
        "map_value": None,
        "polymorphic": poly_base is not None,
        "polymorphic_base": poly_base,
    }

    current = full
    for _ in range(6):  # max nesting depth safety
        current = _strip_qualifiers(current)

        # std::optional<T>
        if current.startswith("std::optional<"):
            inner = _unwrap_single_template(current, "std::optional")
            if inner is not None:
                result["optional"] = True
                current = inner
                continue

        # std::vector<T>
        if current.startswith("std::vector<"):
            inner = _unwrap_single_template(current, "std::vector")
            if inner is not None:
                result["array"] = True
                current = inner
                continue

        # std::shared_ptr<T> / std::unique_ptr<T> — treat as transparent wrapper
        if current.startswith("std::shared_ptr<"):
            inner = _unwrap_single_template(current, "std::shared_ptr")
            if inner is not None:
                current = inner
                continue
        if current.startswith("std::unique_ptr<"):
            inner = _unwrap_single_template(current, "std::unique_ptr")
            if inner is not None:
                current = inner
                continue

        # std::map<K, V, ...> / std::unordered_map<K, V, ...>
        if current.startswith(("std::map<", "std::unordered_map<")):
            k, v = _unwrap_map_args(current)
            if k is not None:
                result["map"] = True
                result["map_key"] = normalize_type(k)
                result["map_value"] = normalize_type(v)
                result["type"] = None
                return result

        break

    result["type"] = normalize_type(current) if current else None
    return result


def _unwrap_single_template(s, prefix):
    """Extract inner type from prefix<T>."""
    s = _strip_qualifiers(s)
    pfx = prefix + "<"
    if not s.startswith(pfx):
        return None
    inner = s[len(pfx):]
    # Strip trailing '>'
    if inner.endswith(">"):
        inner = inner[:-1]
    else:
        # Find matching close
        depth = 0
        for i, c in enumerate(inner):
            if c == "<":
                depth += 1
            elif c == ">":
                if depth == 0:
                    inner = inner[:i]
                    break
                depth -= 1
    return inner.strip()


def _unwrap_map_args(s):
    """Extract (key, value) from std::map<K, V, ...> or std::unordered_map<K, V, ...>."""
    s = _strip_qualifiers(s)
    inner = None
    for pfx in ("std::map<", "std::unordered_map<"):
        if s.startswith(pfx):
            inner = s[len(pfx):]
            break
    if inner is None:
        return None, None
    # Find matching close
    depth = 0
    close = -1
    for i, c in enumerate(inner):
        if c == "<":
            depth += 1
        elif c == ">":
            if depth == 0:
                close = i
                break
            depth -= 1
    if close == -1:
        return None, None
    args = template_parser._extract_tpl_args(inner[:close])
    if len(args) < 2:
        return None, None
    return args[0], args[1]
