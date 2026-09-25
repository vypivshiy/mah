#!/usr/bin/env python3
"""Extract embedded JSON config blob from config.dll.

Robust against client updates: не привязан к именам полей.
Сканирует бинарник, ищет все сбалансированные `{...}` подстроки,
парсит как JSON, возвращает самый большой dict.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Минимальное число ключей, чтобы считать найденный dict конфигом.
# Защита от случайных мелких JSON-ов в бинарнике.
MIN_KEYS = 20


def _try_extract_balanced(data: bytes, start: int) -> str | None:
    """Сканирует вперёд от `start` (указывает на `{`) до парной `}`.
    Учитывает вложенные скобки и строки. Возвращает декодированную подстроку
    или None, если баланс нарушен / UTF-8 невалидный."""
    depth = 0
    i = start
    in_string = False
    n = len(data)
    while i < n:
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
                    try:
                        return data[start : i + 1].decode("utf-8")
                    except UnicodeDecodeError:
                        return None
        i += 1
    return None


def extract_json_blob(data: bytes, min_keys: int = MIN_KEYS) -> str:
    """Найти самый большой валидный JSON-объект в бинарных данных.

    Алгоритм:
      1. Для каждого байта `{` в data пытаемся _try_extract_balanced
      2. Если подстрока парсится как dict с >= min_keys ключами — кандидат
      3. Скипаем вперёд за пределы найденного blob'а (не падаем на вложенные)
      4. Возвращаем кандидата с максимальным числом ключей
    """
    candidates = []  # (num_keys, offset, raw_text)
    n = len(data)
    i = 0
    while i < n:
        if data[i] != ord('{'):
            i += 1
            continue
        blob = _try_extract_balanced(data, i)
        if blob is None:
            i += 1
            continue
        try:
            obj = json.loads(blob)
        except (ValueError, UnicodeDecodeError):
            i += 1
            continue
        if isinstance(obj, dict) and len(obj) >= min_keys:
            candidates.append((len(obj), i, blob))
            i += len(blob)  # не пересканируем внутри найденного объекта
            continue
        i += 1

    if not candidates:
        raise ValueError(
            f"no JSON config blob with >= {min_keys} keys found in DLL"
        )

    candidates.sort(key=lambda c: -c[0])
    num_keys, offset, blob = candidates[0]
    if len(candidates) > 1:
        summary = ", ".join(f"{c[0]}@0x{c[1]:x}" for c in candidates)
        print(
            f"warning: multiple JSON candidates found ({summary}); "
            f"picked largest ({num_keys} keys @0x{offset:x})",
            file=sys.stderr,
        )
    return blob


def resolve_default_dll(repo_root: str) -> str:
    candidates = [
        os.path.join(repo_root, "CM_FP_Unspecified.config.dll"),
        os.path.join(os.getcwd(), "CM_FP_Unspecified.config.dll"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "CM_FP_Unspecified.config.dll"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return os.path.join(repo_root, "CM_FP_Unspecified.config.dll")


def main() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)

    parser = argparse.ArgumentParser(
        description="Extract embedded JSON config blob from config.dll."
    )
    parser.add_argument(
        "dll",
        nargs="?",
        default=None,
        help="Path to the config DLL (defaults to CM_FP_Unspecified.config.dll in repository root)",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        default=None,
        help="Path to output config.json (defaults to config.json in repository root)",
    )

    args = parser.parse_args()

    dll_path = args.dll if args.dll else resolve_default_dll(repo_root)

    if not os.path.isfile(dll_path):
        print(f"Error: configuration DLL not found at '{dll_path}'", file=sys.stderr)
        sys.exit(1)

    if args.output:
        out_path = args.output
        if os.path.isdir(out_path):
            out_path = os.path.join(out_path, "config.json")
    else:
        out_path = os.path.join(repo_root, "config.json")

    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

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
