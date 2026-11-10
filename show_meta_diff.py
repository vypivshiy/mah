#!/usr/bin/env python3
"""Generate a compact unified diff of metadata.json for Telegram."""

from __future__ import annotations

import argparse
import difflib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def load_json_from_git(rev: str, path: str) -> dict[str, Any]:
    spec = f"{rev}:{path}"
    res = subprocess.run(
        ["git", "show", spec],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return json.loads(res.stdout)


def load_json_from_file(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def j(val: Any) -> str:
    return json.dumps(val, ensure_ascii=False, separators=(", ", ": "))


def format_compact_metadata(data: dict[str, Any], include_logs: bool = True) -> list[str]:
    lines: list[str] = ["{"]
    keys = [k for k in data.keys() if include_logs or k != "log_templates"]

    for ki, k in enumerate(keys):
        v = data[k]
        is_last_section = ki == len(keys) - 1
        sec_comma = "" if is_last_section else ","

        if k == "packets_catalog" and isinstance(v, list):
            lines.append(f'  "{k}": [')
            for i, item in enumerate(v):
                c = "," if i + 1 < len(v) else ""
                if isinstance(item, dict) and "handler" in item and isinstance(item["handler"], dict):
                    h = item["handler"]
                    h_short = f'{h.get("class", "")}::{h.get("method", "")} ({h.get("source", "")})'
                    compact_item = {
                        "opcode": item["opcode"],
                        "name": item["name"],
                        "handler": h_short,
                    }
                    lines.append(f"    {j(compact_item)}{c}")
                else:
                    lines.append(f"    {j(item)}{c}")
            lines.append(f"  ]{sec_comma}")
        elif isinstance(v, dict):
            lines.append(f'  "{k}": {{')
            items = list(v.items())
            for i, (sk, sv) in enumerate(items):
                c = "," if i + 1 < len(items) else ""
                if isinstance(sv, dict):
                    lines.append(f'    "{sk}": {{')
                    sub_items = list(sv.items())
                    for si, (ssk, ssv) in enumerate(sub_items):
                        sc = "," if si + 1 < len(sub_items) else ""
                        lines.append(f'      "{ssk}": {j(ssv)}{sc}')
                    lines.append(f"    }}{c}")
                else:
                    lines.append(f'    "{sk}": {j(sv)}{c}')
            lines.append(f"  }}{sec_comma}")
        elif isinstance(v, list):
            lines.append(f'  "{k}": [')
            for i, item in enumerate(v):
                c = "," if i + 1 < len(v) else ""
                lines.append(f"    {j(item)}{c}")
            lines.append(f"  ]{sec_comma}")
        else:
            lines.append(f'  "{k}": {j(v)}{sec_comma}')

    lines.append("}")
    return lines


def find_enclosing_header(lines: list[str], idx: int) -> str | None:
    """Find the nearest enclosing top-level or nested key header above line idx."""
    indent = len(lines[idx]) - len(lines[idx].lstrip(" "))
    for i in range(idx - 1, -1, -1):
        line = lines[i]
        cur_indent = len(line) - len(line.lstrip(" "))
        if cur_indent < indent and (line.endswith("{") or line.endswith("[")):
            return line.rstrip()
    return None


def generate_compact_diff(
    old_meta: dict[str, Any],
    new_meta: dict[str, Any],
    include_logs: bool = True,
) -> str:
    old_lines = format_compact_metadata(old_meta, include_logs=include_logs)
    new_lines = format_compact_metadata(new_meta, include_logs=include_logs)

    matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
    out: list[str] = []
    last_header: str | None = None

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue

        # Determine enclosing section header
        header = (
            find_enclosing_header(new_lines, j1)
            if j1 < len(new_lines)
            else find_enclosing_header(old_lines, i1)
        )
        if header and header != last_header:
            if out:
                out.append("")
            out.append(header)
            last_header = header

        for line in old_lines[i1:i2]:
            # Strip trailing comma for cleaner diff noise reduction when matching
            out.append(f"-{line}")
        for line in new_lines[j1:j2]:
            out.append(f"+{line}")

    return "\n".join(out)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Generate a compact diff of metadata.json"
    )
    parser.add_argument(
        "--old",
        default="HEAD",
        help="Git revision or file path for old metadata.json (default: HEAD)",
    )
    parser.add_argument(
        "--new",
        default="metadata.json",
        help="File path or git revision for new metadata.json (default: metadata.json)",
    )
    parser.add_argument(
        "--path",
        default="metadata.json",
        help="Path inside git repo when using revisions",
    )
    parser.add_argument(
        "--no-logs",
        action="store_true",
        help="Omit log_templates section",
    )
    args = parser.parse_args()

    old_path = Path(args.old)
    old_meta = (
        load_json_from_file(args.old)
        if old_path.is_file()
        else load_json_from_git(args.old, args.path)
    )

    new_path = Path(args.new)
    new_meta = (
        load_json_from_file(args.new)
        if new_path.is_file()
        else load_json_from_git(args.new, args.path)
    )

    print(generate_compact_diff(old_meta, new_meta, include_logs=not args.no_logs))


if __name__ == "__main__":
    main()
