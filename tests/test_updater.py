"""Tests for desktop client update checker & downloader CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Generator
from pathlib import Path

import pytest  # type: ignore[import-not-found]

from tests.mock_server import MockServer

REPO_ROOT = Path(__file__).resolve().parent.parent
UPDATER_SCRIPT = REPO_ROOT / "scripts" / "updater" / "updater.py"


@pytest.fixture
def mock_server() -> Generator[MockServer, None, None]:
    server = MockServer()
    server.start()
    yield server
    server.shutdown()


def make_sparkle_feed(
    version: str,
    url: str = "http://example.com/MAX.msi",
    ed_sig: str | None = "ed123",
    dsa_sig: str | None = "dsa123",
    installer_args: str | None = "/qb",
    critical: bool = False,
) -> str:
    critical_tag = "<sparkle:tags><sparkle:criticalUpdate/></sparkle:tags>" if critical else ""
    dsa_attr = f'sparkle:dsaSignature="{dsa_sig}"' if dsa_sig else ""
    ed_attr = f'sparkle:edSignature="{ed_sig}"' if ed_sig else ""
    args_attr = f'sparkle:installerArguments="{installer_args}"' if installer_args else ""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
    <channel>
        <title>MAX Updates</title>
        <item>
            <title>Version {version}</title>
            <enclosure url="{url}"
                       sparkle:version="{version}"
                       {dsa_attr}
                       {ed_attr}
                       {args_attr}
                       type="application/octet-stream" />
            {critical_tag}
        </item>
    </channel>
</rss>
"""


def run_cli(
    *args: str,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    state_file: Path | None = None,
    metadata_file: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Invoke updater CLI as a subprocess."""
    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    if state_file:
        run_env["UPDATER_STATE_FILE"] = str(state_file)
    if metadata_file:
        run_env["UPDATER_METADATA_FILE"] = str(metadata_file)
    cmd = [sys.executable, str(UPDATER_SCRIPT), *args]
    return subprocess.run(
        cmd,
        cwd=cwd or REPO_ROOT,
        capture_output=True,
        text=True,
        env=run_env,
        check=False,
    )


def test_cli_help() -> None:
    """Invoking with --help prints usage and exits with code 0."""
    result = run_cli("--help")
    assert result.returncode == 0
    assert "usage:" in result.stdout.lower()


def test_cli_invalid_argument_exit_code() -> None:
    """Invalid arguments must return exit code 2 per specification."""
    result = run_cli("--invalid-flag-that-does-not-exist")
    assert result.returncode == 2
    assert "unrecognized arguments" in result.stderr.lower()


def test_cli_invalid_os_exit_code() -> None:
    """Invalid --os value must return exit code 2."""
    result = run_cli("--os", "solaris")
    assert result.returncode == 2


def test_json_flag_without_check_only_errors_exit_code_2() -> None:
    """--json requires --check-only; invoking without it returns exit code 2."""
    result = run_cli("--json")
    assert result.returncode == 2
    assert "--json requires --check-only" in result.stderr


def test_check_only_update_available_exit_code_10(mock_server: MockServer, tmp_path: Path) -> None:
    """Exit code must be 10 when remote version > local version in --check-only mode."""
    feed_xml = make_sparkle_feed("26.34.0", url=f"{mock_server.base_url}/MAX.msi")
    mock_server.register_xml("/update.xml", feed_xml)

    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"version": "26.33.0"}), encoding="utf-8")

    result = run_cli(
        "--check-only",
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
        state_file=state_file,
    )
    assert result.returncode == 10
    assert "update available: 26.34.0" in result.stdout.lower()


def test_check_only_up_to_date_exit_code_0(mock_server: MockServer, tmp_path: Path) -> None:
    """Exit code must be 0 when remote version == local version in --check-only mode."""
    feed_xml = make_sparkle_feed("26.33.0", url=f"{mock_server.base_url}/MAX.msi")
    mock_server.register_xml("/update.xml", feed_xml)

    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"version": "26.33.0"}), encoding="utf-8")

    result = run_cli(
        "--check-only",
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
        state_file=state_file,
    )
    assert result.returncode == 0
    assert "up to date" in result.stdout.lower()


def test_check_only_does_not_mutate_state_file(mock_server: MockServer, tmp_path: Path) -> None:
    """Check mode is strictly read-only and must not modify or touch state.json."""
    feed_xml = make_sparkle_feed("26.33.0", url=f"{mock_server.base_url}/MAX.msi")
    mock_server.register_xml("/update.xml", feed_xml)

    state_file = tmp_path / "state.json"
    initial_content = json.dumps({"version": "26.33.0", "checked_at": "2020-01-01T00:00:00Z"})
    state_file.write_text(initial_content, encoding="utf-8")

    result = run_cli(
        "--check-only",
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
        state_file=state_file,
    )
    assert result.returncode == 0
    # State file content must remain completely untouched
    assert state_file.read_text(encoding="utf-8") == initial_content


def test_version_cascade_fallback_to_metadata(mock_server: MockServer, tmp_path: Path) -> None:
    """Cascade uses metadata.json if state.json does not exist."""
    feed_xml = make_sparkle_feed("26.33.0", url=f"{mock_server.base_url}/MAX.msi")
    mock_server.register_xml("/update.xml", feed_xml)

    meta_file = tmp_path / "metadata.json"
    meta_file.write_text(json.dumps({"meta": {"app_version": "26.33.0"}}), encoding="utf-8")
    state_file = tmp_path / "non_existent_state.json"

    result = run_cli(
        "--check-only",
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
        state_file=state_file,
        metadata_file=meta_file,
    )
    assert result.returncode == 0
    assert "up to date" in result.stdout.lower()


def test_version_cascade_fallback_to_zero(mock_server: MockServer, tmp_path: Path) -> None:
    """Cascade falls back to 0.0.0 if neither state.json nor metadata.json exists."""
    feed_xml = make_sparkle_feed("26.33.0", url=f"{mock_server.base_url}/MAX.msi")
    mock_server.register_xml("/update.xml", feed_xml)

    state_file = tmp_path / "no_state.json"
    meta_file = tmp_path / "no_metadata.json"

    result = run_cli(
        "--check-only",
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
        state_file=state_file,
        metadata_file=meta_file,
    )
    # Remote 26.33.0 > 0.0.0 -> update available -> exit code 10
    assert result.returncode == 10


def test_check_only_json_output_update_available(mock_server: MockServer, tmp_path: Path) -> None:
    """--json output in --check-only mode must be single-line JSON with full metadata and exit 10."""
    feed_xml = make_sparkle_feed(
        "26.34.0",
        url=f"{mock_server.base_url}/MAX.msi",
        ed_sig="ed_test_val",
        dsa_sig="dsa_test_val",
        installer_args="/quiet /norestart",
        critical=True,
    )
    mock_server.register_xml("/update.xml", feed_xml)

    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"version": "26.33.0"}), encoding="utf-8")

    result = run_cli(
        "--check-only",
        "--json",
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
        state_file=state_file,
    )
    assert result.returncode == 10
    data = json.loads(result.stdout.strip())
    assert data["update_available"] is True
    assert data["current_version"] == "26.33.0"
    assert data["latest_version"] == "26.34.0"
    assert data["url"] == f"{mock_server.base_url}/MAX.msi"
    assert data["signatures"] == {"ed": "ed_test_val", "dsa": "dsa_test_val"}
    assert data["installer_arguments"] == "/quiet /norestart"
    assert data["critical"] is True
    assert "checked_at" in data


def test_check_only_json_output_up_to_date(mock_server: MockServer, tmp_path: Path) -> None:
    """--json output in --check-only mode when up to date must exit 0 and indicate update_available=False."""
    feed_xml = make_sparkle_feed("26.33.0", url=f"{mock_server.base_url}/MAX.msi")
    mock_server.register_xml("/update.xml", feed_xml)

    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"version": "26.33.0"}), encoding="utf-8")

    result = run_cli(
        "--check-only",
        "--json",
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
        state_file=state_file,
    )
    assert result.returncode == 0
    data = json.loads(result.stdout.strip())
    assert data["update_available"] is False
    assert data["current_version"] == "26.33.0"
    assert data["latest_version"] == "26.33.0"


def test_download_installer_when_update_available(mock_server: MockServer, tmp_path: Path) -> None:
    """When update is available, download installer, rename .part atomically, and update state.json."""
    installer_data = b"MOCK_MSI_PACKAGE_PAYLOAD_1234567890" * 100
    mock_server.register_bytes("/MAX.msi", installer_data)

    feed_xml = make_sparkle_feed("26.34.0", url=f"{mock_server.base_url}/MAX.msi")
    mock_server.register_xml("/update.xml", feed_xml)

    dest_file = tmp_path / "custom_output.msi"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"version": "26.33.0"}), encoding="utf-8")

    result = run_cli(
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
        "-o",
        str(dest_file),
        state_file=state_file,
    )
    assert result.returncode == 0
    assert dest_file.is_file()
    assert dest_file.read_bytes() == installer_data
    # Temporary .part file must not exist
    assert not (tmp_path / "custom_output.msi.part").exists()
    # State file must be updated to version 26.34.0
    state_data = json.loads(state_file.read_text(encoding="utf-8"))
    assert state_data["version"] == "26.34.0"
    assert state_data["url"] == f"{mock_server.base_url}/MAX.msi"


def test_download_skipped_when_up_to_date_without_force(
    mock_server: MockServer,
    tmp_path: Path,
) -> None:
    """When up to date, download is skipped unless --force is specified."""
    feed_xml = make_sparkle_feed("26.33.0", url=f"{mock_server.base_url}/MAX.msi")
    mock_server.register_xml("/update.xml", feed_xml)

    dest_file = tmp_path / "custom_output.msi"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"version": "26.33.0"}), encoding="utf-8")

    result = run_cli(
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
        "-o",
        str(dest_file),
        state_file=state_file,
    )
    assert result.returncode == 0
    assert not dest_file.exists()
    assert "up to date" in result.stdout.lower()


def test_download_with_force_when_up_to_date(
    mock_server: MockServer,
    tmp_path: Path,
) -> None:
    """--force downloads installer even when client version matches remote version."""
    installer_data = b"FORCED_DOWNLOAD_PAYLOAD"
    mock_server.register_bytes("/MAX.msi", installer_data)

    feed_xml = make_sparkle_feed("26.33.0", url=f"{mock_server.base_url}/MAX.msi")
    mock_server.register_xml("/update.xml", feed_xml)

    dest_file = tmp_path / "custom_output.msi"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"version": "26.33.0"}), encoding="utf-8")

    result = run_cli(
        "--force",
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
        "-o",
        str(dest_file),
        state_file=state_file,
    )
    assert result.returncode == 0
    assert dest_file.is_file()
    assert dest_file.read_bytes() == installer_data


def test_download_urllib_fallback_and_resume(
    mock_server: MockServer,
    tmp_path: Path,
) -> None:
    """When curl is not in PATH, urllib fallback streams chunks and resumes existing .part file."""
    installer_data = b"ABCDEFGHIJ" * 200  # 2000 bytes
    mock_server.register_bytes("/MAX.msi", installer_data, support_range=True)

    feed_xml = make_sparkle_feed("26.34.0", url=f"{mock_server.base_url}/MAX.msi")
    mock_server.register_xml("/update.xml", feed_xml)

    dest_file = tmp_path / "resumed.msi"
    part_file = tmp_path / "resumed.msi.part"

    # Pre-write partial content (first 500 bytes)
    part_file.write_bytes(installer_data[:500])

    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"version": "26.33.0"}), encoding="utf-8")

    # Pass empty PATH directory so curl is not found on PATH
    empty_bin_dir = tmp_path / "empty_bin"
    empty_bin_dir.mkdir(parents=True, exist_ok=True)

    result = run_cli(
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
        "-o",
        str(dest_file),
        env={"PATH": str(empty_bin_dir)},
        state_file=state_file,
    )
    assert result.returncode == 0
    assert dest_file.is_file()
    assert dest_file.read_bytes() == installer_data
    assert not part_file.exists()


def test_feed_http_error_exit_code_1(mock_server: MockServer) -> None:
    """HTTP 500 error fetching feed must return exit code 1."""
    mock_server.register_error("/update.xml", status=500, message="Internal Server Error")
    result = run_cli(
        "--check-only",
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
    )
    assert result.returncode == 1
    assert "error" in result.stderr.lower()


def test_feed_malformed_xml_exit_code_1(mock_server: MockServer) -> None:
    """Malformed XML in feed must return exit code 1."""
    mock_server.register_xml("/update.xml", "<rss><channel><item>unclosed")
    result = run_cli(
        "--check-only",
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
    )
    assert result.returncode == 1
    assert "malformed xml" in result.stderr.lower()


def test_feed_missing_enclosure_exit_code_1(mock_server: MockServer) -> None:
    """XML feed without <enclosure> must return exit code 1."""
    xml = """<?xml version="1.0"?>
    <rss version="2.0">
      <channel>
        <item><title>Version 26.34.0</title></item>
      </channel>
    </rss>"""
    mock_server.register_xml("/update.xml", xml)
    result = run_cli(
        "--check-only",
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
    )
    assert result.returncode == 1
    assert "missing" in result.stderr.lower() or "no <enclosure>" in result.stderr.lower()


def test_download_http_error_exit_code_1(mock_server: MockServer, tmp_path: Path) -> None:
    """Download failure (e.g. HTTP 404 for installer) must return exit code 1 and clean up."""
    feed_xml = make_sparkle_feed("26.34.0", url=f"{mock_server.base_url}/missing.msi")
    mock_server.register_xml("/update.xml", feed_xml)
    mock_server.register_error("/missing.msi", status=404, message="Not Found")

    dest_file = tmp_path / "failed.msi"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"version": "26.33.0"}), encoding="utf-8")

    result = run_cli(
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
        "-o",
        str(dest_file),
        state_file=state_file,
    )
    assert result.returncode == 1
    assert not dest_file.exists()


def test_download_mac_os_default_filename(mock_server: MockServer, tmp_path: Path) -> None:
    """When --os mac is provided, default output filename is MAX.dmg."""
    feed_xml = make_sparkle_feed("26.34.0", url=f"{mock_server.base_url}/MAX.dmg")
    mock_server.register_xml("/update.xml", feed_xml)
    mock_server.register_bytes("/MAX.dmg", b"MAC_DMG_CONTENT")

    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"version": "26.33.0"}), encoding="utf-8")

    result = run_cli(
        "--os",
        "mac",
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
        "-o",
        str(tmp_path),
        state_file=state_file,
    )
    assert result.returncode == 0
    dmg_file = tmp_path / "MAX.dmg"
    assert dmg_file.is_file()
    assert dmg_file.read_bytes() == b"MAC_DMG_CONTENT"


def test_download_network_abort_preserves_partial_and_does_not_rename(
    mock_server: MockServer,
    tmp_path: Path,
) -> None:
    """Network abort during streaming leaves .part file and does not rename to target destination."""
    mock_server.register_abort("/aborted.msi", chunk_size=256)
    feed_xml = make_sparkle_feed("26.34.0", url=f"{mock_server.base_url}/aborted.msi")
    mock_server.register_xml("/update.xml", feed_xml)

    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"version": "26.33.0"}), encoding="utf-8")

    dest_file = tmp_path / "aborted.msi"
    part_file = tmp_path / "aborted.msi.part"

    empty_bin_dir = tmp_path / "empty_bin"
    empty_bin_dir.mkdir(parents=True, exist_ok=True)

    result = run_cli(
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
        "-o",
        str(dest_file),
        env={"PATH": str(empty_bin_dir)},
        state_file=state_file,
    )
    assert result.returncode == 1
    assert not dest_file.exists()
    assert part_file.exists()


def test_network_connection_refused_exit_code_1() -> None:
    """Network connection failure must return exit code 1."""
    # Port 59999 on 127.0.0.1 is extremely unlikely to have a listener
    result = run_cli(
        "--check-only",
        "--appcast-url",
        "http://127.0.0.1:59999/update.xml",
    )
    assert result.returncode == 1
    assert "error" in result.stderr.lower()


# ---------------------------------------------------------------------------
# Component unit tests (Version, parse_feed_xml & FeedParseError)
# ---------------------------------------------------------------------------


def test_version_semantic_comparisons() -> None:
    """Semantic version parsing correctly handles tuple comparisons and ignores prerelease labels in ordering."""
    from scripts.updater.updater import Version

    assert Version.parse("26.33.0") == Version.parse("26.33")
    assert Version.parse("v26.33.0") == Version.parse("26.33.0")
    assert Version.parse("26.33.0.0") == Version.parse("26.33.0")
    assert Version.parse("26.34.0") > Version.parse("26.33.9")
    assert Version.parse("26.34.0") > Version.parse("26.33.0")
    assert Version.parse("26.33.0") == Version.parse("26.33.0-rc1")
    assert Version.parse("1.0.0") < Version.parse("10.0.0")
    assert str(Version.parse("26.33.0")) == "26.33.0"


def test_parse_feed_xml_multiple_items_selects_highest_version() -> None:
    """When multiple <item> entries are in feed, parse_feed_xml selects the highest semantic version."""
    from scripts.updater.updater import parse_feed_xml

    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
        <channel>
            <item>
                <title>Version 26.33.0</title>
                <enclosure url="https://example.com/26.33.0.msi" sparkle:version="26.33.0"/>
            </item>
            <item>
                <title>Version 26.35.0</title>
                <enclosure url="https://example.com/26.35.0.msi" sparkle:version="26.35.0"/>
            </item>
            <item>
                <title>Version 26.34.0</title>
                <enclosure url="https://example.com/26.34.0.msi" sparkle:version="26.34.0"/>
            </item>
        </channel>
    </rss>"""
    info = parse_feed_xml(xml)
    assert str(info.version) == "26.35.0"
    assert info.url == "https://example.com/26.35.0.msi"


def test_download_urllib_handles_http_416_when_part_already_complete(
    mock_server: MockServer,
    tmp_path: Path,
) -> None:
    """When .part file is already fully downloaded, HTTP 416 Range Not Satisfiable completes without error."""
    full_content = b"ALREADY_COMPLETE_BYTES"
    mock_server.register_bytes("/MAX.msi", full_content, support_range=True)
    feed_xml = make_sparkle_feed("26.34.0", url=f"{mock_server.base_url}/MAX.msi")
    mock_server.register_xml("/update.xml", feed_xml)

    dest_file = tmp_path / "already_done.msi"
    part_file = tmp_path / "already_done.msi.part"
    part_file.write_bytes(full_content)

    empty_bin_dir = tmp_path / "empty_bin"
    empty_bin_dir.mkdir(parents=True, exist_ok=True)

    result = run_cli(
        "--appcast-url",
        f"{mock_server.base_url}/update.xml",
        "-o",
        str(dest_file),
        env={"PATH": str(empty_bin_dir)},
    )
    assert result.returncode == 0
    assert dest_file.is_file()
    assert dest_file.read_bytes() == full_content
    assert not part_file.exists()



def test_parse_feed_xml_valid_windows() -> None:
    """Component test: parse_feed_xml extracts all Windows Sparkle enclosure attributes."""
    from scripts.updater.updater import parse_feed_xml

    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
        <channel>
            <item>
                <title>Version 26.33.0</title>
                <enclosure url="https://download.max.ru/win/release/26.33.0/MAX.msi"
                           sparkle:version="26.33.0"
                           sparkle:dsaSignature="dsa_sig_test"
                           sparkle:edSignature="ed_sig_test"
                           sparkle:installerArguments="ProductLanguage=1049 /qb!"
                           type="application/octet-stream" />
                <sparkle:tags>
                    <sparkle:criticalUpdate/>
                </sparkle:tags>
            </item>
        </channel>
    </rss>"""
    info = parse_feed_xml(xml)
    assert str(info.version) == "26.33.0"
    assert info.version.parts == (26, 33, 0)
    assert info.url == "https://download.max.ru/win/release/26.33.0/MAX.msi"
    assert info.ed_signature == "ed_sig_test"
    assert info.dsa_signature == "dsa_sig_test"
    assert info.installer_arguments == "ProductLanguage=1049 /qb!"
    assert info.critical is True


def test_parse_feed_xml_valid_mac() -> None:
    """Component test: parse_feed_xml correctly handles macOS feeds without DSA or args."""
    from scripts.updater.updater import parse_feed_xml

    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
        <channel>
            <item>
                <title>Version 26.33.0</title>
                <enclosure url="https://download.max.ru/mac/release/26.33.0/MAX.dmg"
                           sparkle:version="26.33.0"
                           sparkle:edSignature="ed_mac_test"
                           type="application/octet-stream" />
            </item>
        </channel>
    </rss>"""
    info = parse_feed_xml(xml)
    assert str(info.version) == "26.33.0"
    assert info.url == "https://download.max.ru/mac/release/26.33.0/MAX.dmg"
    assert info.ed_signature == "ed_mac_test"
    assert info.dsa_signature is None
    assert info.installer_arguments is None
    assert info.critical is False


def test_parse_feed_xml_errors() -> None:
    """Component test: parse_feed_xml raises FeedParseError on missing tags or bad XML."""
    from scripts.updater.updater import FeedParseError, parse_feed_xml

    with pytest.raises(FeedParseError, match="Malformed XML"):
        parse_feed_xml("<not valid xml")

    with pytest.raises(FeedParseError, match="No <item>"):
        parse_feed_xml("<rss><channel></channel></rss>")

    with pytest.raises(FeedParseError, match="No <enclosure>"):
        parse_feed_xml("<rss><channel><item></item></channel></rss>")

    with pytest.raises(FeedParseError, match="Missing 'url'"):
        parse_feed_xml(
            '<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">'
            '<channel><item><enclosure sparkle:version="1.0"/></item></channel></rss>'
        )

    with pytest.raises(FeedParseError, match="Missing sparkle:version"):
        parse_feed_xml(
            '<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">'
            '<channel><item><enclosure url="http://x"/></item></channel></rss>'
        )
