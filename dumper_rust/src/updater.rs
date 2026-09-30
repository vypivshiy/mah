use clap::Args;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const SPARKLE_NS: &str = "http://www.andymatuschak.org/xml-namespaces/sparkle";
pub const DEFAULT_FEED_URL: &str = "https://download.max.ru/win/release/update.xml";
pub const DEFAULT_INSTALLER_NAME: &str = "MAX.msi";
pub const BUFFER_SIZE: usize = 64 * 1024;

/// Exit codes for the updater subsystem.
pub mod exit_codes {
    pub const SUCCESS: i32 = 0;
    pub const ERROR: i32 = 1;
    pub const CLI_ERROR: i32 = 2;
    pub const UPDATE_AVAILABLE: i32 = 10;
}

#[derive(Debug)]
pub enum UpdaterError {
    Network(String),
    FeedParse(String),
    Download(String),
    Io(String),
    Cli(String),
    Other(String),
}

impl UpdaterError {
    pub fn exit_code(&self) -> i32 {
        match self {
            UpdaterError::Cli(_) => exit_codes::CLI_ERROR,
            _ => exit_codes::ERROR,
        }
    }
}

impl std::fmt::Display for UpdaterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdaterError::Network(msg) => write!(f, "Network error: {msg}"),
            UpdaterError::FeedParse(msg) => write!(f, "Feed parse error: {msg}"),
            UpdaterError::Download(msg) => write!(f, "Download error: {msg}"),
            UpdaterError::Io(msg) => write!(f, "I/O error: {msg}"),
            UpdaterError::Cli(msg) => write!(f, "{msg}"),
            UpdaterError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for UpdaterError {}

impl From<io::Error> for UpdaterError {
    fn from(err: io::Error) -> Self {
        UpdaterError::Io(err.to_string())
    }
}

/// Comparable application version matching the Python updater's 4-component Windows semantics.
#[derive(Debug, Clone)]
pub struct AppVersion {
    pub parts: Vec<u64>,
    pub raw: String,
}

impl AppVersion {
    pub fn parse(s: &str) -> Self {
        let clean = s.trim();
        if clean.is_empty() {
            return Self {
                parts: vec![0, 0, 0],
                raw: "0.0.0".to_string(),
            };
        }
        let trimmed = clean.trim_start_matches(|c| c == 'v' || c == 'V');
        let mut parts: Vec<u64> = trimmed
            .split('.')
            .map(|seg| {
                let digits: String = seg.chars().take_while(|c| c.is_ascii_digit()).collect();
                if digits.is_empty() {
                    0
                } else {
                    digits.parse::<u64>().unwrap_or(0)
                }
            })
            .collect();

        // Strip redundant trailing zeros beyond 3 parts so 26.33.0.0 == 26.33.0
        while parts.len() > 3 && parts.last() == Some(&0) {
            parts.pop();
        }
        // Pad to at least 3 parts
        while parts.len() < 3 {
            parts.push(0);
        }

        Self {
            parts,
            raw: clean.to_string(),
        }
    }
}

impl Default for AppVersion {
    fn default() -> Self {
        Self::parse("0.0.0")
    }
}

impl PartialEq for AppVersion {
    fn eq(&self, other: &Self) -> bool {
        self.parts == other.parts
    }
}

impl Eq for AppVersion {}

impl PartialOrd for AppVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AppVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.parts.cmp(&other.parts)
    }
}

impl std::fmt::Display for AppVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl Serialize for AppVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for AppVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(AppVersion::parse(&s))
    }
}

/// Parsed release metadata from Sparkle Appcast feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub version: AppVersion,
    pub url: String,
    pub ed_signature: Option<String>,
    pub dsa_signature: Option<String>,
    pub installer_arguments: Option<String>,
    pub critical: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signatures {
    pub ed: Option<String>,
    pub dsa: Option<String>,
}

/// Structured machine-readable JSON output for update checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateCheckResult {
    pub update_available: bool,
    pub current_version: String,
    pub remote_version: String,
    pub latest_version: String,
    pub url: String,
    pub checked_at: String,
    pub signatures: Signatures,
    pub installer_arguments: Option<String>,
    pub critical: bool,
}

/// Command-line arguments for update checking and downloading.
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateArgs {
    /// Check for available updates without downloading
    #[arg(long, alias = "check-only")]
    pub check: bool,

    /// Force download even if local version matches remote
    #[arg(long)]
    pub force: bool,

    /// Format check output as single-line JSON to stdout (requires --check)
    #[arg(long)]
    pub json: bool,

    /// Suppress progress and status output
    #[arg(short, long)]
    pub quiet: bool,

    /// Destination path for downloaded installer (defaults to MAX.msi)
    #[arg(short, long, value_name = "PATH", default_value = DEFAULT_INSTALLER_NAME)]
    pub output: Option<PathBuf>,

    /// Override Sparkle feed URL
    #[arg(long, value_name = "URL", default_value = DEFAULT_FEED_URL)]
    pub appcast_url: Option<String>,

    /// Override metadata.json path for local version detection
    #[arg(long, value_name = "PATH")]
    pub metadata_path: Option<PathBuf>,
}

/// Return current UTC timestamp in ISO 8601 format with Zulu suffix.
pub fn now_utc_iso() -> String {
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let sec = secs % 60;
    let mins = secs / 60;
    let min = mins % 60;
    let hours = mins / 60;
    let hour = hours % 24;
    let days = (hours / 24) as i64;
    let (y, m, d) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hour, min, sec
    )
}

fn days_to_ymd(days: i64) -> (i64, u8, u8) {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Helper to get an attribute with or without Sparkle namespace prefix.
fn get_sparkle_attribute<'a>(node: &'a roxmltree::Node<'a, 'a>, name: &str) -> Option<&'a str> {
    node.attribute((SPARKLE_NS, name))
        .or_else(|| {
            let prefixed = format!("sparkle:{name}");
            node.attribute(prefixed.as_str())
        })
        .or_else(|| node.attribute(name))
}

/// Parse Sparkle Appcast XML feed into `ReleaseInfo`, selecting the item with highest semantic version.
pub fn parse_appcast_xml(xml: &str) -> Result<ReleaseInfo, UpdaterError> {
    let doc = roxmltree::Document::parse(xml)
        .map_err(|e| UpdaterError::FeedParse(format!("Malformed XML in feed: {e}")))?;

    let items: Vec<roxmltree::Node> = doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "item")
        .collect();

    if items.is_empty() {
        return Err(UpdaterError::FeedParse(
            "No <item> element found in appcast feed".into(),
        ));
    }

    let mut candidates = Vec::with_capacity(items.len());

    for item in items {
        let enclosure = item
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "enclosure")
            .ok_or_else(|| {
                UpdaterError::FeedParse("No <enclosure> element found in appcast item".into())
            })?;

        let url = enclosure
            .attribute("url")
            .ok_or_else(|| {
                UpdaterError::FeedParse("Missing 'url' attribute in <enclosure>".into())
            })?
            .to_string();

        let version_str = get_sparkle_attribute(&enclosure, "version").ok_or_else(|| {
            UpdaterError::FeedParse("Missing sparkle:version attribute in <enclosure>".into())
        })?;

        let ed_sig = get_sparkle_attribute(&enclosure, "edSignature").map(String::from);
        let dsa_sig = get_sparkle_attribute(&enclosure, "dsaSignature").map(String::from);
        let installer_args =
            get_sparkle_attribute(&enclosure, "installerArguments").map(String::from);

        let critical = item.descendants().any(|n| {
            n.is_element()
                && ((n.tag_name().namespace() == Some(SPARKLE_NS)
                    && n.tag_name().name() == "criticalUpdate")
                    || n.tag_name().name() == "criticalUpdate"
                    || n.tag_name().name().ends_with(":criticalUpdate"))
        });

        candidates.push(ReleaseInfo {
            version: AppVersion::parse(version_str),
            url,
            ed_signature: ed_sig,
            dsa_signature: dsa_sig,
            installer_arguments: installer_args,
            critical,
        });
    }

    candidates
        .into_iter()
        .max_by(|a, b| a.version.cmp(&b.version))
        .ok_or_else(|| UpdaterError::FeedParse("No release items found in feed".into()))
}

/// Fetch and parse Sparkle Appcast XML feed from remote URL.
pub fn fetch_feed(url: &str) -> Result<ReleaseInfo, UpdaterError> {
    let resp = ureq::get(url)
        .header("User-Agent", "OneMe Desktop Updater")
        .call()
        .map_err(|e| match e {
            ureq::Error::StatusCode(code) => {
                UpdaterError::Network(format!("HTTP error {code} fetching feed from {url}"))
            }
            err => UpdaterError::Network(format!("Failed to fetch feed from {url}: {err}")),
        })?;

    let mut body_str = String::new();
    resp.into_body()
        .into_reader()
        .read_to_string(&mut body_str)
        .map_err(|e| UpdaterError::Network(format!("Failed to read feed response: {e}")))?;

    parse_appcast_xml(&body_str)
}

/// Read version string from a JSON metadata file with `meta.app_version` schema.
fn read_version_from_file(path: &Path) -> Option<AppVersion> {
    if !path.is_file() {
        return None;
    }
    let content = fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&content).ok()?;
    let app_version = value.get("meta")?.get("app_version")?.as_str()?;
    Some(AppVersion::parse(app_version))
}

/// Determine local client version using version cascade:
/// 1. Explicit path parameter (if provided and valid)
/// 2. `UPDATER_METADATA_FILE` environment variable (if set and valid)
/// 3. Default `metadata.json` file in current directory
/// 4. Fallback default `0.0.0`
pub fn resolve_local_version(explicit_path: Option<&Path>) -> AppVersion {
    if let Some(path) = explicit_path {
        if let Some(v) = read_version_from_file(path) {
            return v;
        }
    }

    if let Ok(env_path) = std::env::var("UPDATER_METADATA_FILE") {
        if let Some(v) = read_version_from_file(Path::new(&env_path)) {
            return v;
        }
    }

    if let Some(v) = read_version_from_file(Path::new("metadata.json")) {
        return v;
    }

    AppVersion::parse("0.0.0")
}

/// Resolve destination path, appending default installer name if destination is a directory.
pub fn resolve_destination(output_arg: Option<&Path>) -> PathBuf {
    match output_arg {
        Some(path) => {
            let path_str = path.to_string_lossy();
            if path.is_dir() || path_str.ends_with('/') || path_str.ends_with('\\') {
                path.join(DEFAULT_INSTALLER_NAME)
            } else {
                path.to_path_buf()
            }
        }
        None => PathBuf::from(DEFAULT_INSTALLER_NAME),
    }
}

/// Replace target destination file atomically.
fn atomic_replace(from: &Path, to: &Path) -> Result<(), UpdaterError> {
    if !from.is_file() {
        return Err(UpdaterError::Download(format!(
            "Download completed but part file '{:?}' not found",
            from
        )));
    }
    if to.exists() {
        let _ = fs::remove_file(to);
    }
    fs::rename(from, to).map_err(|e| {
        UpdaterError::Io(format!("Failed to rename {:?} to {:?}: {}", from, to, e))
    })?;
    Ok(())
}

/// Stream download an installer to a `.part` file with HTTP Range resume support,
/// atomically renaming to destination upon full completion.
pub fn download_installer_with_progress<F>(
    url: &str,
    dest_path: &Path,
    mut progress: F,
) -> Result<(), UpdaterError>
where
    F: FnMut(u64, Option<u64>),
{
    if let Some(parent) = dest_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| {
                UpdaterError::Io(format!("Failed to create directory {:?}: {e}", parent))
            })?;
        }
    }

    let part_path = PathBuf::from(format!("{}.part", dest_path.display()));

    let existing_bytes = if part_path.is_file() {
        part_path.metadata().map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };

    let mut req = ureq::get(url).header("User-Agent", "OneMe Desktop Updater");
    if existing_bytes > 0 {
        req = req.header("Range", format!("bytes={existing_bytes}-"));
    }

    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::StatusCode(416)) if existing_bytes > 0 => {
            // HTTP 416 Range Not Satisfiable: file is already fully downloaded
            atomic_replace(&part_path, dest_path)?;
            return Ok(());
        }
        Err(ureq::Error::StatusCode(code)) => {
            return Err(UpdaterError::Download(format!(
                "HTTP error {code} downloading installer from {url}"
            )));
        }
        Err(err) => {
            return Err(UpdaterError::Download(format!(
                "Download request failed for {url}: {err}"
            )));
        }
    };

    let status = resp.status().as_u16();
    if status != 200 && status != 206 {
        return Err(UpdaterError::Download(format!(
            "Unexpected HTTP status {status} from {url}"
        )));
    }

    let is_partial = status == 206;
    let content_length: Option<u64> = resp
        .headers()
        .get("Content-Length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    let (mut out_file, initial_bytes, expected_total) = if is_partial && existing_bytes > 0 {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&part_path)
            .map_err(|e| {
                UpdaterError::Io(format!("Failed to open {:?} for append: {e}", part_path))
            })?;
        let total = content_length.map(|cl| existing_bytes + cl);
        (f, existing_bytes, total)
    } else {
        let f = File::create(&part_path).map_err(|e| {
            UpdaterError::Io(format!("Failed to create {:?}: {e}", part_path))
        })?;
        (f, 0, content_length)
    };

    let mut body_reader = resp.into_body().into_reader();
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut session_downloaded: u64 = 0;

    progress(initial_bytes, expected_total);

    loop {
        let n = body_reader
            .read(&mut buffer)
            .map_err(|e| UpdaterError::Download(format!("Read error during download: {e}")))?;
        if n == 0 {
            break;
        }
        out_file
            .write_all(&buffer[..n])
            .map_err(|e| UpdaterError::Io(format!("Write error during download: {e}")))?;
        session_downloaded += n as u64;
        progress(initial_bytes + session_downloaded, expected_total);
    }

    out_file
        .flush()
        .map_err(|e| UpdaterError::Io(format!("Flush error: {e}")))?;
    drop(out_file);

    if let Some(expected_cl) = content_length {
        if session_downloaded < expected_cl {
            return Err(UpdaterError::Download(format!(
                "Connection aborted prematurely: received {} of {} bytes",
                session_downloaded, expected_cl
            )));
        }
    }

    atomic_replace(&part_path, dest_path)?;
    Ok(())
}

/// Download installer with default progress reporting to stderr.
pub fn download_installer(
    url: &str,
    dest_path: &Path,
    quiet: bool,
) -> Result<(), UpdaterError> {
    let mut last_percent: Option<u8> = None;
    download_installer_with_progress(url, dest_path, |downloaded, total| {
        if !quiet {
            if let Some(tot) = total {
                if tot > 0 {
                    let percent = ((downloaded as f64 / tot as f64) * 100.0) as u8;
                    if last_percent != Some(percent) {
                        last_percent = Some(percent);
                        let mb_down = downloaded as f64 / (1024.0 * 1024.0);
                        let mb_total = tot as f64 / (1024.0 * 1024.0);
                        eprint!(
                            "\rProgress: {:.2} MB / {:.2} MB ({:.1}%)",
                            mb_down,
                            mb_total,
                            (downloaded as f64 / tot as f64) * 100.0
                        );
                        let _ = io::stderr().flush();
                    }
                }
            } else {
                let mb_down = downloaded as f64 / (1024.0 * 1024.0);
                eprint!("\rProgress: {:.2} MB downloaded", mb_down);
                let _ = io::stderr().flush();
            }
        }
    })?;

    if !quiet {
        eprintln!();
    }
    Ok(())
}

/// Perform an update check against the feed URL and local version metadata.
pub fn check_update(
    feed_url: &str,
    metadata_path: Option<&Path>,
) -> Result<UpdateCheckResult, UpdaterError> {
    let release = fetch_feed(feed_url)?;
    let local_version = resolve_local_version(metadata_path);
    let update_available = release.version > local_version;
    let checked_at = now_utc_iso();

    Ok(UpdateCheckResult {
        update_available,
        current_version: local_version.to_string(),
        remote_version: release.version.to_string(),
        latest_version: release.version.to_string(),
        url: release.url,
        checked_at,
        signatures: Signatures {
            ed: release.ed_signature,
            dsa: release.dsa_signature,
        },
        installer_arguments: release.installer_arguments,
        critical: release.critical,
    })
}

/// Execute the updater operation with configurable output writers and return an integer exit code.
pub fn execute_update(
    args: &UpdateArgs,
    stdout: &mut dyn Write,
    _stderr: &mut dyn Write,
) -> Result<i32, UpdaterError> {
    if args.json && !args.check {
        return Err(UpdaterError::Cli("--json requires --check".into()));
    }

    let feed_url = args
        .appcast_url
        .as_deref()
        .unwrap_or(DEFAULT_FEED_URL);

    if args.check {
        let result = check_update(feed_url, args.metadata_path.as_deref())?;
        if args.json {
            let json_str = serde_json::to_string(&result)
                .map_err(|e| UpdaterError::Other(e.to_string()))?;
            writeln!(stdout, "{}", json_str)?;
        } else if !args.quiet {
            if result.update_available {
                writeln!(
                    stdout,
                    "Update available: {} (current: {})",
                    result.latest_version, result.current_version
                )?;
            } else {
                writeln!(stdout, "Client is up to date ({}).", result.current_version)?;
            }
        }
        return Ok(if result.update_available {
            exit_codes::UPDATE_AVAILABLE
        } else {
            exit_codes::SUCCESS
        });
    }

    let release = fetch_feed(feed_url)?;
    let local_version = resolve_local_version(args.metadata_path.as_deref());
    let has_update = release.version > local_version;

    if !has_update && !args.force {
        if !args.quiet {
            writeln!(
                stdout,
                "Client is up to date ({}). Use --force to re-download.",
                local_version
            )?;
        }
        return Ok(exit_codes::SUCCESS);
    }

    let dest_file = resolve_destination(args.output.as_deref());

    if !args.quiet {
        writeln!(
            stdout,
            "Downloading {} -> {}...",
            release.url,
            dest_file.display()
        )?;
    }

    download_installer(&release.url, &dest_file, args.quiet)?;

    if !args.quiet {
        writeln!(
            stdout,
            "Successfully downloaded {} (version {})",
            dest_file.display(),
            release.version
        )?;
    }

    Ok(exit_codes::SUCCESS)
}

/// Main entrypoint for update execution, dispatching to `execute_update` and formatting errors.
pub fn run_with_output(
    args: &UpdateArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    match execute_update(args, stdout, stderr) {
        Ok(code) => code,
        Err(err) => {
            let _ = writeln!(stderr, "Error: {err}");
            err.exit_code()
        }
    }
}

/// Convenience entrypoint using standard stdout and stderr.
pub fn run(args: &UpdateArgs) -> i32 {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    run_with_output(args, &mut stdout, &mut stderr)
}
