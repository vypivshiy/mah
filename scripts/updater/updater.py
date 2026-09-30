#!/usr/bin/env python3
"""Desktop Client Update Checker & Downloader.

Queries the native Sparkle Appcast XML feed (WinSparkle), compares versions,
and downloads the desktop client installer.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SPARKLE_NS = "http://www.andymatuschak.org/xml-namespaces/sparkle"
BUFFER_SIZE = 4 * 1024 * 1024  # 4 MB chunk buffer


@dataclass(frozen=True)
class PlatformConfig:
    """Platform-specific default settings."""

    feed_url: str
    installer_name: str


PLATFORMS: dict[str, PlatformConfig] = {
    "win": PlatformConfig(
        feed_url="https://download.max.ru/win/release/update.xml",
        installer_name="MAX.msi",
    ),
    "mac": PlatformConfig(
        feed_url="https://download.max.ru/mac/release/update.xml",
        installer_name="MAX.dmg",
    ),
}


class UpdaterError(Exception):
    """Base exception for updater failures."""


class DownloadError(UpdaterError):
    """Raised when an installer download fails."""


class FeedParseError(UpdaterError):
    """Raised when Sparkle feed XML cannot be parsed."""


def now_utc_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format with Zulu suffix."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, order=True)
class Version:
    """Comparable semantic version."""

    parts: tuple[int, ...]
    raw: str = field(compare=False)

    @classmethod
    def parse(cls, version_str: str) -> Version:
        clean = version_str.strip()
        if not clean:
            return cls((0, 0, 0), "0.0.0")
        normalized = clean.lstrip("vV")
        parts = []
        for part in normalized.split("."):
            digits = ""
            for ch in part:
                if ch.isdigit():
                    digits += ch
                else:
                    break
            parts.append(int(digits) if digits else 0)
        # Strip redundant trailing zeros so 26.33.0.0 == 26.33.0
        while len(parts) > 3 and parts[-1] == 0:
            parts.pop()
        while len(parts) < 3:
            parts.append(0)
        return cls(tuple(parts), clean)

    def __str__(self) -> str:
        return self.raw


@dataclass
class ReleaseInfo:
    """Parsed release information from Sparkle Appcast feed."""

    version: Version
    url: str
    ed_signature: str | None
    dsa_signature: str | None
    installer_arguments: str | None
    critical: bool

    def to_state_dict(self, checked_at: str | None = None) -> dict[str, Any]:
        """Convert release metadata to state.json schema."""
        return {
            "version": str(self.version),
            "url": self.url,
            "checked_at": checked_at or now_utc_iso(),
            "signatures": {
                "ed": self.ed_signature,
                "dsa": self.dsa_signature,
            },
            "installer_arguments": self.installer_arguments,
            "critical": self.critical,
        }

    def to_check_json(
        self,
        update_available: bool,
        current_version: Version,
        checked_at: str | None = None,
    ) -> dict[str, Any]:
        """Convert check result to machine-readable JSON."""
        state = self.to_state_dict(checked_at=checked_at)
        return {
            "update_available": update_available,
            "current_version": str(current_version),
            "latest_version": state["version"],
            "url": state["url"],
            "checked_at": state["checked_at"],
            "signatures": state["signatures"],
            "installer_arguments": state["installer_arguments"],
            "critical": state["critical"],
        }


def _read_json_file(path: Path) -> dict[str, Any] | None:
    """Safely read and parse a JSON dictionary from file."""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (ValueError, OSError):
        return None


def resolve_local_version(
    state_file: Path,
    metadata_file: Path,
) -> Version:
    """Determine local client version using 3-tier cascade."""
    # 1. Primary: state file
    state_data = _read_json_file(state_file)
    if state_data and isinstance(state_data.get("version"), str):
        return Version.parse(state_data["version"])

    # 2. Fallback: repository root metadata snapshot
    metadata_data = _read_json_file(metadata_file)
    if metadata_data:
        meta = metadata_data.get("meta")
        if isinstance(meta, dict) and isinstance(meta.get("app_version"), str):
            return Version.parse(meta["app_version"])

    # 3. Baseline: default 0.0.0
    return Version.parse("0.0.0")


def _get_sparkle_attr(element: ET.Element, attr_name: str) -> str | None:
    """Look up an attribute with or without Sparkle namespace."""
    return element.get(f"{{{SPARKLE_NS}}}{attr_name}") or element.get(f"sparkle:{attr_name}")


def _parse_item_enclosure(item: ET.Element) -> ReleaseInfo:
    """Extract release info from a feed item enclosure."""
    enclosure = item.find("enclosure")
    if enclosure is None:
        raise FeedParseError("No <enclosure> element found in appcast item")

    url = enclosure.get("url")
    if not url:
        raise FeedParseError("Missing 'url' attribute in <enclosure>")

    version_attr = _get_sparkle_attr(enclosure, "version")
    if not version_attr:
        raise FeedParseError("Missing sparkle:version attribute in <enclosure>")

    ed_sig = _get_sparkle_attr(enclosure, "edSignature")
    dsa_sig = _get_sparkle_attr(enclosure, "dsaSignature")
    installer_args = _get_sparkle_attr(enclosure, "installerArguments")

    critical_tag = item.find(f".//{{{SPARKLE_NS}}}criticalUpdate")
    if critical_tag is None:
        critical_tag = item.find(".//criticalUpdate")
    is_critical = critical_tag is not None

    return ReleaseInfo(
        version=Version.parse(version_attr),
        url=url,
        ed_signature=ed_sig,
        dsa_signature=dsa_sig,
        installer_arguments=installer_args,
        critical=is_critical,
    )


def parse_feed_xml(xml_content: bytes | str) -> ReleaseInfo:
    """Parse Sparkle Appcast XML feed into ReleaseInfo, selecting the highest release."""
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as exc:
        raise FeedParseError(f"Malformed XML in feed: {exc}") from exc

    items = root.findall(".//item")
    if not items:
        raise FeedParseError("No <item> element found in appcast feed")

    candidates: list[ReleaseInfo] = []
    for item in items:
        candidates.append(_parse_item_enclosure(item))

    # Return the item with the highest semantic version
    return max(candidates, key=lambda r: r.version)


def fetch_feed(url: str, timeout: int = 15) -> ReleaseInfo:
    """Fetch and parse Sparkle Appcast XML feed."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "OneMe Desktop Updater"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        content = resp.read()
    return parse_feed_xml(content)


def _download_with_curl(url: str, part_path: Path) -> None:
    """Execute curl download with retry and resume support."""
    cmd = [
        "curl",
        "-L",
        "--fail",
        "--retry",
        "3",
        "-C",
        "-",
        "-o",
        str(part_path),
        url,
    ]
    res = subprocess.run(cmd, check=False)
    if res.returncode != 0:
        raise DownloadError(f"curl download failed with exit code {res.returncode}")


def _download_with_urllib(url: str, part_path: Path, timeout: int = 30) -> None:
    """Stream download via urllib with chunked buffering and range resume."""
    existing_bytes = part_path.stat().st_size if part_path.is_file() else 0
    headers = {"User-Agent": "OneMe Desktop Updater"}
    if existing_bytes > 0:
        headers["Range"] = f"bytes={existing_bytes}-"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # If server responded 206 Partial Content, append to existing file
            # If server responded 200 OK, rewrite the file from start
            status = getattr(resp, "status", 200)
            mode = "ab" if (existing_bytes > 0 and status == 206) else "wb"
            cl_header = resp.headers.get("Content-Length")
            expected_bytes = int(cl_header) if cl_header and cl_header.isdigit() else None

            downloaded_in_session = 0
            with open(part_path, mode) as out_f:
                while True:
                    chunk = resp.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    out_f.write(chunk)
                    downloaded_in_session += len(chunk)

            if expected_bytes is not None and downloaded_in_session < expected_bytes:
                raise DownloadError(
                    f"Connection aborted prematurely: received {downloaded_in_session} of {expected_bytes} bytes"
                )
    except urllib.error.HTTPError as err:
        # HTTP 416 Range Not Satisfiable: file is already fully downloaded
        if err.code == 416 and existing_bytes > 0:
            return
        raise DownloadError(f"HTTP error during download: {err.code} {err.reason}") from err


def download_installer(url: str, dest_path: Path) -> Path:
    """Download installer using curl if present, falling back to buffered urllib."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    part_path = Path(str(dest_path) + ".part")

    curl_available = shutil.which("curl") is not None

    if curl_available:
        _download_with_curl(url, part_path)
    else:
        _download_with_urllib(url, part_path)

    if not part_path.is_file():
        raise DownloadError(f"Download completed but part file '{part_path}' not found")

    # Atomic rename upon 100% completion
    os.replace(part_path, dest_path)
    return dest_path


def save_state(
    state_file: Path,
    release: ReleaseInfo,
    checked_at: str | None = None,
) -> None:
    """Save release provenance to state file."""
    state_data = release.to_state_dict(checked_at=checked_at)
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(state_data, indent=2) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser matching specification."""
    parser = argparse.ArgumentParser(
        description="Desktop client update checker and downloader.",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Evaluate version and exit without downloading.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force download regardless of local version match.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Format --check-only output as single-line JSON to stdout.",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        default=None,
        help="Explicit destination path for the downloaded installer.",
    )
    parser.add_argument(
        "--os",
        dest="target_os",
        choices=["win", "mac"],
        default="win",
        help="Operating system target (default: win).",
    )
    parser.add_argument(
        "--appcast-url",
        dest="appcast_url",
        default=None,
        help="Override feed URL.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.json and not args.check_only:
        parser.error("--json requires --check-only")

    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent

    # Read state and metadata paths with support for environment overrides during test isolation
    resolved_state_path = (
        Path(os.environ["UPDATER_STATE_FILE"])
        if "UPDATER_STATE_FILE" in os.environ
        else script_dir / "state.json"
    )
    resolved_metadata_path = (
        Path(os.environ["UPDATER_METADATA_FILE"])
        if "UPDATER_METADATA_FILE" in os.environ
        else repo_root / "metadata.json"
    )

    platform_cfg = PLATFORMS[args.target_os]
    feed_url = args.appcast_url or platform_cfg.feed_url

    try:
        release = fetch_feed(feed_url)
    except (UpdaterError, OSError, ValueError, urllib.error.URLError) as exc:
        print(f"Error fetching/parsing feed: {exc}", file=sys.stderr)
        return 1

    local_version = resolve_local_version(resolved_state_path, resolved_metadata_path)
    has_update = release.version > local_version
    now_iso = now_utc_iso()

    if args.check_only:
        if args.json:
            payload = release.to_check_json(has_update, local_version, checked_at=now_iso)
            print(json.dumps(payload, separators=(",", ":")))
        elif has_update:
            print(f"Update available: {release.version} (current: {local_version})")
        else:
            print(f"Client is up to date ({local_version}).")
        return 10 if has_update else 0

    if not has_update and not args.force:
        print(f"Client is up to date ({local_version}). Use --force to re-download.")
        return 0

    # Resolve target output path
    if args.output:
        dest_candidate = Path(args.output)
        if dest_candidate.is_dir() or str(args.output).endswith(("/", "\\")):
            dest_file = dest_candidate / platform_cfg.installer_name
        else:
            dest_file = dest_candidate
    else:
        dest_file = repo_root / platform_cfg.installer_name

    dest_file = dest_file.resolve()

    print(f"Downloading {release.url} -> {dest_file}...")
    try:
        download_installer(release.url, dest_file)
    except (UpdaterError, OSError, urllib.error.URLError) as exc:
        print(f"Download failed: {exc}", file=sys.stderr)
        return 1

    save_state(resolved_state_path, release, checked_at=now_iso)
    print(f"Successfully downloaded {dest_file} (version {release.version})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
