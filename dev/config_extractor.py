#!/usr/bin/env python3
"""Extract embedded JSON config blob from config.dll."""

import json
import sys


def extract_json_blob(data: bytes) -> str:
    # WARNING
    # работает на эвристике что это поле идёт первым. Если изменять конфиг - не будет работать скрипт
    marker = b'"is_local_history_enabled"'
    pos = data.find(marker)
    if pos == -1:
        raise ValueError("marker not found in DLL")

    # scan back to opening {
    start = data.rfind(b'{', 0, pos)
    if start == -1:
        raise ValueError("opening { not found")

    # scan forward to matching }, tracking nested braces and strings
    depth = 0
    i = start
    in_string = False
    while i < len(data):
        b = data[i]
        if in_string:
            if b == ord('\\'):
                i += 2
                continue
            if b == ord('"'):
                in_string = False
        else:
            if b == ord('"'):
                in_string = True
            elif b == ord('{'):
                depth += 1
            elif b == ord('}'):
                depth -= 1
                if depth == 0:
                    return data[start:i + 1].decode('utf-8')
        i += 1

    raise ValueError("matching } not found")


def main():
    dll_path = sys.argv[1] if len(sys.argv) > 1 else "CM_FP_Unspecified.config.dll"
    out_path = "config.json"

    # parse -o flag
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "-o" and i + 1 < len(args):
            out_path = args[i + 1]
            args.pop(i)
            args.pop(i)
        else:
            i += 1
    dll_path = args[0] if args else dll_path

    with open(dll_path, "rb") as f:
        data = f.read()

    raw = extract_json_blob(data)
    config = json.loads(raw)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Extracted config -> {out_path}")


if __name__ == "__main__":
    main()
