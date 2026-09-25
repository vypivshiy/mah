"""
Template parsing utilities — pure Python, no Binary Ninja dependency.
Ported from the IDA dumper.
"""


def _extract_first_tpl_arg(s):
    depth = 0
    for i, c in enumerate(s):
        if c == "<":
            depth += 1
        elif c == ">":
            if depth == 0:
                return s[:i].strip()
            depth -= 1
        elif c == "," and depth == 0:
            return s[:i].strip()
    return s.strip()


def _extract_tpl_args(s):
    args = []
    depth = 0
    start = 0
    for i, c in enumerate(s):
        if c == "<":
            depth += 1
        elif c == ">":
            if depth == 0:
                part = s[start:i].strip()
                if part:
                    args.append(part)
                break
            depth -= 1
        elif c == "," and depth == 0:
            part = s[start:i].strip()
            if part:
                args.append(part)
            start = i + 1
    else:
        tail = s[start:].strip()
        if tail:
            args.append(tail)
    return args


def _extract_member_first_arg(dem):
    """Extract T from SerializableMember<T, ...>"""
    idx = dem.find("SerializableMember<")
    if idx == -1:
        return None
    i = idx + len("SerializableMember<")
    start = i
    depth = 0
    while i < len(dem):
        c = dem[i]
        if c == "<":
            depth += 1
        elif c == ">":
            if depth == 0:
                return dem[start:i].split(",")[0].strip()
            depth -= 1
        elif c == "," and depth == 0:
            return dem[start:i].strip()
        i += 1
    return None


def _extract_member_last_arg(dem):
    """Extract last template arg (owner type) from SerializableMember<T,...,Owner>"""
    idx = dem.find("SerializableMember<")
    if idx == -1:
        return None
    i = idx + len("SerializableMember<")
    depth = 0
    last_comma_pos = i
    while i < len(dem):
        c = dem[i]
        if c == "<":
            depth += 1
        elif c == ">":
            if depth == 0:
                return dem[last_comma_pos:i].strip()
            depth -= 1
        elif c == "," and depth == 0:
            last_comma_pos = i + 1
        i += 1
    return None


def _extract_first_two_tpl_args(s):
    args = []
    depth = 0
    start = 0
    for i, c in enumerate(s):
        if c == "<":
            depth += 1
        elif c == ">":
            if depth == 0:
                part = s[start:i].strip()
                if part:
                    args.append(part)
                break
            depth -= 1
        elif c == "," and depth == 0:
            part = s[start:i].strip()
            if part:
                args.append(part)
            start = i + 1
            if len(args) >= 2:
                break
    return args
