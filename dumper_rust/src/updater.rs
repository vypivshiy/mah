use clap::Args;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const SPARKLE_NS: &str = "http://www.andymatuschak.org/xml-namespaces/sparkle";
pub const DEFAULT_FEED_URL: &str = "https://download.max.ru/win/release/update.xml";
pub const DEFAULT_INSTALLER_NAME: &str = "MAX.msi";
pub const BUFFER_SIZE: usize = 64 * 1024;
pub const DEFAULT_CONCURRENCY: usize = 8;
pub const DEFAULT_RETRIES: usize = 5;
pub const DEFAULT_CHUNK_SIZE: u64 = 4 * 1024 * 1024; // 4 MB
pub const CONNECT_TIMEOUT_SECS: u64 = 10;
pub const READ_TIMEOUT_SECS: u64 = 15;

/// Exit codes for the updater subsystem.
pub mod exit_codes {
    pub const SUCCESS: i32 = 0;
    pub const ERROR: i32 = 1;
    pub const CLI_ERROR: i32 = 1;
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
        exit_codes::ERROR
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

/// Comparable semantic application version adhering to three-tier (major, minor, patch) semantics.
#[derive(Debug, Clone)]
pub struct FeedVersion {
    pub parts: Vec<u64>,
    pub raw: String,
}

impl FeedVersion {
    pub fn parse(s: &str) -> Self {
        let clean = s.trim();
        if clean.is_empty() {
            return Self {
                parts: vec![0, 0, 0],
                raw: "0.0.0".to_string(),
            };
        }
        let trimmed = clean.trim_start_matches(['v', 'V']);
        let mut parts: Vec<u64> = trimmed
            .split('.')
            .take(3)
            .map(|seg| {
                let digits: String = seg.chars().take_while(|c| c.is_ascii_digit()).collect();
                if digits.is_empty() {
                    0
                } else {
                    digits.parse::<u64>().unwrap_or(0)
                }
            })
            .collect();

        // Pad to 3 tiers: major, minor, patch
        while parts.len() < 3 {
            parts.push(0);
        }

        Self {
            parts,
            raw: clean.to_string(),
        }
    }

    #[inline]
    pub fn major(&self) -> u64 {
        self.parts.first().copied().unwrap_or(0)
    }

    #[inline]
    pub fn minor(&self) -> u64 {
        self.parts.get(1).copied().unwrap_or(0)
    }

    #[inline]
    pub fn patch(&self) -> u64 {
        self.parts.get(2).copied().unwrap_or(0)
    }

    #[inline]
    pub fn semver_tuple(&self) -> (u64, u64, u64) {
        (self.major(), self.minor(), self.patch())
    }
}

impl Default for FeedVersion {
    fn default() -> Self {
        Self::parse("0.0.0")
    }
}

impl PartialEq for FeedVersion {
    fn eq(&self, other: &Self) -> bool {
        self.semver_tuple() == other.semver_tuple()
    }
}

impl Eq for FeedVersion {}

impl PartialOrd for FeedVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FeedVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.semver_tuple().cmp(&other.semver_tuple())
    }
}

impl std::fmt::Display for FeedVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl Serialize for FeedVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for FeedVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(FeedVersion::parse(&s))
    }
}

/// Type alias for backward compatibility.
pub type AppVersion = FeedVersion;

/// Parsed release metadata from Sparkle Appcast feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub version: FeedVersion,
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
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct UpdateArgs {
    /// Check for available updates without downloading
    #[arg(long, alias = "check-only")]
    pub check: bool,

    /// Force download even if local version matches remote
    #[arg(long)]
    pub force: bool,

    /// Format check output as single-line JSON to stdout (implies check-only)
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

    /// Number of concurrent download threads (defaults to 8, 1 for sequential)
    #[arg(short = 'j', long, value_name = "NUM", default_value = "8")]
    pub threads: Option<usize>,

    /// Maximum retry attempts per chunk (defaults to 5)
    #[arg(long, value_name = "NUM", default_value = "5")]
    pub retries: Option<usize>,
}

impl Default for UpdateArgs {
    fn default() -> Self {
        Self {
            check: false,
            force: false,
            json: false,
            quiet: false,
            output: Some(PathBuf::from(DEFAULT_INSTALLER_NAME)),
            appcast_url: Some(DEFAULT_FEED_URL.to_string()),
            metadata_path: None,
            threads: Some(DEFAULT_CONCURRENCY),
            retries: Some(DEFAULT_RETRIES),
        }
    }
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
            version: FeedVersion::parse(version_str),
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
fn read_version_from_file(path: &Path) -> Option<FeedVersion> {
    if !path.is_file() {
        return None;
    }
    let content = fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&content).ok()?;
    let app_version = value.get("meta")?.get("app_version")?.as_str()?;
    Some(FeedVersion::parse(app_version))
}

/// Determine local client version using version cascade:
/// 1. Explicit path parameter (if provided and valid)
/// 2. `UPDATER_METADATA_FILE` environment variable (if set and valid)
/// 3. Default `metadata.json` file in current directory
/// 4. Fallback default `0.0.0`
pub fn resolve_local_version(explicit_path: Option<&Path>) -> FeedVersion {
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

    FeedVersion::parse("0.0.0")
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

/// Helper to parse total size from HTTP Content-Range header (e.g. "bytes 100-200/500" -> 500).
fn parse_content_range_total(header_val: &str) -> Option<u64> {
    let slash_pos = header_val.rfind('/')?;
    let total_part = header_val[slash_pos + 1..].trim();
    if total_part == "*" {
        None
    } else {
        total_part.parse().ok()
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

/// Download configuration options.
#[derive(Debug, Clone)]
pub struct DownloadOptions {
    pub threads: usize,
    pub retries: usize,
    pub quiet: bool,
    pub chunk_size: u64,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            threads: DEFAULT_CONCURRENCY,
            retries: DEFAULT_RETRIES,
            quiet: false,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

/// Metadata tracker for segmented downloads to allow inter-process resumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadMeta {
    pub url: String,
    pub total_size: u64,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub chunk_size: u64,
    pub completed_chunks: Vec<usize>,
}

impl DownloadMeta {
    pub fn meta_path(part_path: &Path) -> PathBuf {
        PathBuf::from(format!("{}.meta", part_path.display()))
    }

    pub fn load(meta_path: &Path) -> Option<Self> {
        if !meta_path.is_file() {
            return None;
        }
        let content = fs::read_to_string(meta_path).ok()?;
        serde_json::from_str(&content).ok()
    }

    pub fn save(&self, meta_path: &Path) -> Result<(), UpdaterError> {
        let tmp_path = PathBuf::from(format!("{}.tmp", meta_path.display()));
        let json = serde_json::to_string(self)
            .map_err(|e| UpdaterError::Io(format!("Failed to serialize meta: {e}")))?;
        fs::write(&tmp_path, json)
            .map_err(|e| UpdaterError::Io(format!("Failed to write meta: {e}")))?;
        let _ = fs::rename(&tmp_path, meta_path);
        Ok(())
    }
}

/// Range chunk description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkInfo {
    pub index: usize,
    pub start: u64,
    pub end: u64, // inclusive
}

impl ChunkInfo {
    #[inline]
    pub fn size(&self) -> u64 {
        self.end - self.start + 1
    }
}

/// Divide total size into chunk ranges.
pub fn compute_chunks(total_size: u64, chunk_size: u64) -> Vec<ChunkInfo> {
    if total_size == 0 || chunk_size == 0 {
        return Vec::new();
    }
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while start < total_size {
        let end = (start + chunk_size - 1).min(total_size - 1);
        chunks.push(ChunkInfo { index, start, end });
        start = end + 1;
        index += 1;
    }
    chunks
}

/// Build standard ureq Agent with configured connection and read timeouts.
pub fn create_http_agent(connect_timeout_secs: u64, read_timeout_secs: u64) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(connect_timeout_secs)))
        .timeout_recv_response(Some(Duration::from_secs(read_timeout_secs)))
        .timeout_recv_body(Some(Duration::from_secs(read_timeout_secs * 8)))
        .build()
        .new_agent()
}

/// Thread-safe progress reporter computing download speed and estimated time of arrival (ETA).
pub struct ProgressReporter {
    initial_bytes: u64,
    total_bytes: Option<u64>,
    session_downloaded: AtomicU64,
    start_time: Instant,
    last_print: Mutex<Instant>,
    quiet: bool,
}

impl ProgressReporter {
    pub fn new(initial_bytes: u64, total_bytes: Option<u64>, quiet: bool) -> Self {
        Self {
            initial_bytes,
            total_bytes,
            session_downloaded: AtomicU64::new(0),
            start_time: Instant::now(),
            last_print: Mutex::new(Instant::now()),
            quiet,
        }
    }

    pub fn add_bytes(&self, n: u64) {
        self.session_downloaded.fetch_add(n, Ordering::Relaxed);
        self.render(false);
    }

    pub fn log_warning(&self, msg: &str) {
        if self.quiet {
            return;
        }
        eprint!("\r{:80}\r[warning] {msg}\n", "");
        let _ = io::stderr().flush();
        self.render(true);
    }

    pub fn render(&self, force: bool) {
        if self.quiet {
            return;
        }

        let now = Instant::now();
        let total_downloaded = self.initial_bytes + self.session_downloaded.load(Ordering::Relaxed);

        if !force {
            let mut last = self.last_print.lock().unwrap();
            if now.duration_since(*last) < Duration::from_millis(150) {
                if let Some(tot) = self.total_bytes {
                    if total_downloaded < tot {
                        return;
                    }
                } else {
                    return;
                }
            }
            *last = now;
        }

        let elapsed = self.start_time.elapsed().as_secs_f64();
        let session_bytes = self.session_downloaded.load(Ordering::Relaxed);
        let speed_mb_s = if elapsed > 0.05 {
            (session_bytes as f64 / (1024.0 * 1024.0)) / elapsed
        } else {
            0.0
        };

        if let Some(tot) = self.total_bytes {
            if tot > 0 {
                let mb_down = total_downloaded as f64 / (1024.0 * 1024.0);
                let mb_total = tot as f64 / (1024.0 * 1024.0);
                let pct = ((total_downloaded as f64 / tot as f64) * 100.0).min(100.0);
                let remaining = tot.saturating_sub(total_downloaded);
                let eta_str = if speed_mb_s > 0.01 {
                    let eta_secs = (remaining as f64 / (speed_mb_s * 1024.0 * 1024.0)).ceil() as u64;
                    if eta_secs < 60 {
                        format!("{eta_secs}s")
                    } else {
                        format!("{}m {:02}s", eta_secs / 60, eta_secs % 60)
                    }
                } else {
                    "--".to_string()
                };

                eprint!(
                    "\rProgress: {:.2} MB / {:.2} MB ({:.1}%) [{:.2} MB/s, ETA: {}]   ",
                    mb_down, mb_total, pct, speed_mb_s, eta_str
                );
                let _ = io::stderr().flush();
            }
        } else {
            let mb_down = total_downloaded as f64 / (1024.0 * 1024.0);
            eprint!(
                "\rProgress: {:.2} MB downloaded [{:.2} MB/s]   ",
                mb_down, speed_mb_s
            );
            let _ = io::stderr().flush();
        }
    }

    pub fn finish(&self) {
        if !self.quiet {
            self.render(true);
            eprintln!();
            let _ = io::stderr().flush();
        }
    }
}

/// Download a single chunk range with granular retries and exponential backoff.
fn download_single_chunk(
    url: &str,
    chunk: ChunkInfo,
    file_mutex: &Arc<Mutex<File>>,
    reporter: &Arc<ProgressReporter>,
    first_error: &Arc<Mutex<Option<UpdaterError>>>,
    max_retries: usize,
    quiet: bool,
) -> Result<(), UpdaterError> {
    let chunk_len = chunk.size();
    let mut bytes_downloaded_in_chunk = 0u64;
    let mut last_error_msg = String::new();
    let mut attempt = 0;

    while attempt <= max_retries {
        attempt += 1;

        if first_error.lock().unwrap().is_some() {
            return Err(UpdaterError::Download(
                "Cancelled due to failure in another stream".to_string(),
            ));
        }

        if attempt > 1 {
            let base_ms = 500u64 * (1u64 << (attempt - 2).min(4));
            let jitter = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
                % 300) as u64;
            std::thread::sleep(Duration::from_millis(base_ms + jitter));
        }

        let range_start = chunk.start + bytes_downloaded_in_chunk;
        let range_end = chunk.end;
        let range_header = format!("bytes={range_start}-{range_end}");

        let agent = create_http_agent(CONNECT_TIMEOUT_SECS, READ_TIMEOUT_SECS);
        let req = agent
            .get(url)
            .header("User-Agent", "OneMe Desktop Updater")
            .header("Range", &range_header);

        let resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::StatusCode(code)) => {
                last_error_msg = format!("HTTP error {code}");
                if !quiet {
                    reporter.log_warning(&format!(
                        "Chunk {} HTTP error {code}, retry {attempt}/{max_retries}...",
                        chunk.index
                    ));
                }
                continue;
            }
            Err(e) => {
                last_error_msg = format!("{e}");
                if !quiet {
                    reporter.log_warning(&format!(
                        "Chunk {} connect error ({last_error_msg}), retry {attempt}/{max_retries}...",
                        chunk.index
                    ));
                }
                continue;
            }
        };

        let status = resp.status().as_u16();
        if status != 206 && !(status == 200 && chunk.start == 0) {
            last_error_msg = format!("Unexpected HTTP status {status}");
            if !quiet {
                reporter.log_warning(&format!(
                    "Chunk {} status {status}, retry {attempt}/{max_retries}...",
                    chunk.index
                ));
            }
            continue;
        }

        let mut reader = resp.into_body().into_reader();
        let mut buf = [0u8; BUFFER_SIZE];
        let mut read_failed = false;

        while bytes_downloaded_in_chunk < chunk_len {
            let needed = (chunk_len - bytes_downloaded_in_chunk).min(BUFFER_SIZE as u64) as usize;
            match reader.read(&mut buf[..needed]) {
                Ok(0) => {
                    if bytes_downloaded_in_chunk < chunk_len {
                        last_error_msg = format!(
                            "Premature EOF: received {bytes_downloaded_in_chunk} of {chunk_len} bytes"
                        );
                        read_failed = true;
                    }
                    break;
                }
                Ok(n) => {
                    let write_pos = chunk.start + bytes_downloaded_in_chunk;
                    {
                        let mut f = file_mutex.lock().unwrap();
                        f.seek(SeekFrom::Start(write_pos))
                            .map_err(|e| UpdaterError::Io(format!("Seek error: {e}")))?;
                        f.write_all(&buf[..n])
                            .map_err(|e| UpdaterError::Io(format!("Write error: {e}")))?;
                    }
                    bytes_downloaded_in_chunk += n as u64;
                    reporter.add_bytes(n as u64);
                }
                Err(e) => {
                    last_error_msg = format!("Read error: {e}");
                    read_failed = true;
                    break;
                }
            }
        }

        if read_failed {
            if !quiet {
                reporter.log_warning(&format!(
                    "Chunk {} read interrupted ({last_error_msg}), retry {attempt}/{max_retries}...",
                    chunk.index
                ));
            }
            continue;
        }

        if bytes_downloaded_in_chunk == chunk_len {
            return Ok(());
        }
    }

    Err(UpdaterError::Download(format!(
        "Chunk {} (bytes {}-{}) failed after {max_retries} retry attempts: {last_error_msg}",
        chunk.index, chunk.start, chunk.end
    )))
}

/// Download installer using parallel range chunks and a synchronized work queue.
fn download_parallel_chunks(
    url: &str,
    dest_path: &Path,
    part_path: &Path,
    meta_path: &Path,
    total_size: u64,
    etag: Option<String>,
    last_modified: Option<String>,
    options: &DownloadOptions,
) -> Result<(), UpdaterError> {
    let chunks = compute_chunks(total_size, options.chunk_size);
    let total_chunks = chunks.len();

    let mut completed_chunks: HashSet<usize> = HashSet::new();
    let mut is_valid_existing_meta = false;

    if let Some(loaded_meta) = DownloadMeta::load(meta_path) {
        if loaded_meta.url == url
            && loaded_meta.total_size == total_size
            && loaded_meta.chunk_size == options.chunk_size
            && (etag.is_none() || loaded_meta.etag == etag)
            && (last_modified.is_none() || loaded_meta.last_modified == last_modified)
            && part_path.is_file()
            && part_path.metadata().map(|m| m.len()).unwrap_or(0) == total_size
        {
            completed_chunks = loaded_meta.completed_chunks.into_iter().collect();
            is_valid_existing_meta = true;
        }
    }

    if !is_valid_existing_meta {
        // Salvage full chunks from an existing legacy single-stream download if available
        if part_path.is_file() {
            let existing_len = part_path.metadata().map(|m| m.len()).unwrap_or(0);
            if existing_len <= total_size {
                let full_chunks = (existing_len / options.chunk_size) as usize;
                for i in 0..full_chunks.min(total_chunks) {
                    completed_chunks.insert(i);
                }
            }
        }

        // Pre-allocate part_path to total_size
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(part_path)
            .map_err(|e| UpdaterError::Io(format!("Failed to open {:?}: {e}", part_path)))?;
        f.set_len(total_size)
            .map_err(|e| UpdaterError::Io(format!("Failed to set_len {:?}: {e}", part_path)))?;
        drop(f);

        let initial_meta = DownloadMeta {
            url: url.to_string(),
            total_size,
            etag: etag.clone(),
            last_modified: last_modified.clone(),
            chunk_size: options.chunk_size,
            completed_chunks: completed_chunks.iter().copied().collect(),
        };
        let _ = initial_meta.save(meta_path);
    }

    if completed_chunks.len() == total_chunks {
        let _ = fs::remove_file(meta_path);
        atomic_replace(part_path, dest_path)?;
        return Ok(());
    }

    let initial_bytes: u64 = completed_chunks
        .iter()
        .map(|&idx| chunks[idx].size())
        .sum();

    let remaining_chunks: VecDeque<ChunkInfo> = chunks
        .iter()
        .filter(|c| !completed_chunks.contains(&c.index))
        .copied()
        .collect();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(part_path)
        .map_err(|e| UpdaterError::Io(format!("Failed to open {:?}: {e}", part_path)))?;
    let file_mutex = Arc::new(Mutex::new(file));

    let queue = Arc::new(Mutex::new(remaining_chunks));
    let completed_set = Arc::new(Mutex::new(completed_chunks));
    let current_meta = DownloadMeta {
        url: url.to_string(),
        total_size,
        etag,
        last_modified,
        chunk_size: options.chunk_size,
        completed_chunks: Vec::new(),
    };
    let meta_mutex = Arc::new(Mutex::new(current_meta));
    let first_error = Arc::new(Mutex::new(None::<UpdaterError>));
    let reporter = Arc::new(ProgressReporter::new(
        initial_bytes,
        Some(total_size),
        options.quiet,
    ));

    let num_workers = options.threads.min(queue.lock().unwrap().len()).max(1);

    std::thread::scope(|s| {
        for _ in 0..num_workers {
            s.spawn(|| {
                loop {
                    if first_error.lock().unwrap().is_some() {
                        break;
                    }
                    let chunk = match queue.lock().unwrap().pop_front() {
                        Some(c) => c,
                        None => break,
                    };

                    match download_single_chunk(
                        url,
                        chunk,
                        &file_mutex,
                        &reporter,
                        &first_error,
                        options.retries,
                        options.quiet,
                    ) {
                        Ok(()) => {
                            let mut comp = completed_set.lock().unwrap();
                            comp.insert(chunk.index);
                            let mut meta_guard = meta_mutex.lock().unwrap();
                            meta_guard.completed_chunks = comp.iter().copied().collect();
                            let _ = meta_guard.save(meta_path);
                        }
                        Err(e) => {
                            let mut err_guard = first_error.lock().unwrap();
                            if err_guard.is_none() {
                                *err_guard = Some(e);
                            }
                            break;
                        }
                    }
                }
            });
        }
    });

    if let Some(err) = first_error.lock().unwrap().take() {
        return Err(err);
    }

    let final_size = fs::metadata(part_path).map(|m| m.len()).unwrap_or(0);
    if final_size != total_size {
        return Err(UpdaterError::Download(format!(
            "Downloaded file size mismatch: expected {total_size} bytes, got {final_size} bytes"
        )));
    }

    if completed_set.lock().unwrap().len() != total_chunks {
        return Err(UpdaterError::Download(
            "Some chunks failed to download completely".to_string(),
        ));
    }

    reporter.finish();
    let _ = fs::remove_file(meta_path);
    atomic_replace(part_path, dest_path)?;
    Ok(())
}

/// Fallback sequential streaming download with retry and resume support.
fn download_sequential_with_retry(
    url: &str,
    dest_path: &Path,
    part_path: &Path,
    initial_probe_resp: Option<ureq::http::Response<ureq::Body>>,
    expected_total: Option<u64>,
    options: &DownloadOptions,
) -> Result<(), UpdaterError> {
    let mut existing_bytes = if part_path.is_file() {
        part_path.metadata().map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };

    if let Some(tot) = expected_total {
        if existing_bytes == tot && tot > 0 {
            atomic_replace(part_path, dest_path)?;
            return Ok(());
        }
    }

    let reporter = Arc::new(ProgressReporter::new(
        existing_bytes,
        expected_total,
        options.quiet,
    ));

    let mut attempt = 0;
    let mut last_err = String::new();
    let mut probe_resp_opt = initial_probe_resp;

    while attempt <= options.retries {
        attempt += 1;

        if attempt > 1 {
            let base_ms = 500u64 * (1u64 << (attempt - 2).min(4));
            let jitter = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
                % 300) as u64;
            std::thread::sleep(Duration::from_millis(base_ms + jitter));
        }

        let resp = if let Some(resp) = probe_resp_opt.take() {
            resp
        } else {
            let agent = create_http_agent(CONNECT_TIMEOUT_SECS, READ_TIMEOUT_SECS);
            let mut req = agent
                .get(url)
                .header("User-Agent", "OneMe Desktop Updater");
            if existing_bytes > 0 {
                req = req.header("Range", format!("bytes={existing_bytes}-"));
            }

            match req.call() {
                Ok(r) => r,
                Err(ureq::Error::StatusCode(416)) if existing_bytes > 0 => {
                    // HTTP 416 Range Not Satisfiable: file is already fully downloaded
                    reporter.finish();
                    atomic_replace(part_path, dest_path)?;
                    return Ok(());
                }
                Err(ureq::Error::StatusCode(code)) => {
                    return Err(UpdaterError::Download(format!(
                        "HTTP error {code} downloading installer from {url}"
                    )));
                }
                Err(err) => {
                    last_err = format!("{err}");
                    if !options.quiet {
                        reporter.log_warning(&format!(
                            "Connection error ({last_err}), retry {attempt}/{}...",
                            options.retries
                        ));
                    }
                    continue;
                }
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

        let content_range_total: Option<u64> = if is_partial {
            resp.headers()
                .get("Content-Range")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_content_range_total)
        } else {
            None
        };

        let effective_total = if is_partial {
            content_range_total.or_else(|| content_length.map(|cl| existing_bytes + cl))
        } else {
            content_length
        }
        .or(expected_total);

        let (mut out_file, is_append) = if is_partial && existing_bytes > 0 {
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(part_path)
                .map_err(|e| {
                    UpdaterError::Io(format!("Failed to open {:?} for append: {e}", part_path))
                })?;
            (f, true)
        } else {
            existing_bytes = 0;
            let f = File::create(part_path).map_err(|e| {
                UpdaterError::Io(format!("Failed to create {:?}: {e}", part_path))
            })?;
            (f, false)
        };

        let mut body_reader = resp.into_body().into_reader();
        let mut buffer = [0u8; BUFFER_SIZE];
        let mut session_downloaded: u64 = 0;
        let mut read_failed = false;

        loop {
            match body_reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = out_file.write_all(&buffer[..n]) {
                        return Err(UpdaterError::Io(format!(
                            "Write error during download: {e}"
                        )));
                    }
                    session_downloaded += n as u64;
                    reporter.add_bytes(n as u64);
                }
                Err(e) => {
                    last_err = format!("Read error during download: {e}");
                    read_failed = true;
                    break;
                }
            }
        }

        let _ = out_file.flush();
        drop(out_file);

        if read_failed {
            existing_bytes = part_path.metadata().map(|m| m.len()).unwrap_or(0);
            if !options.quiet {
                reporter.log_warning(&format!(
                    "Read interrupted ({last_err}), retry {attempt}/{}...",
                    options.retries
                ));
            }
            continue;
        }

        if let Some(expected_cl) = content_length {
            if session_downloaded < expected_cl {
                last_err = format!(
                    "Connection aborted prematurely: received {} of {} bytes",
                    session_downloaded, expected_cl
                );
                existing_bytes = part_path.metadata().map(|m| m.len()).unwrap_or(0);
                if attempt <= options.retries && is_append {
                    continue;
                }
                return Err(UpdaterError::Download(last_err));
            }
        }

        let final_file_size = fs::metadata(part_path)
            .map(|m| m.len())
            .unwrap_or(existing_bytes + session_downloaded);

        if let Some(expected_size) = effective_total {
            if final_file_size != expected_size {
                return Err(UpdaterError::Download(format!(
                    "Downloaded file size mismatch: expected {} bytes, got {} bytes",
                    expected_size, final_file_size
                )));
            }
        }

        reporter.finish();
        atomic_replace(part_path, dest_path)?;
        return Ok(());
    }

    Err(UpdaterError::Download(format!(
        "Download failed after {} retry attempts: {last_err}",
        options.retries
    )))
}

/// Download installer with options, automatically selecting multi-threaded segmented downloading
/// when supported by the server and falling back to single-stream download with retries.
pub fn download_installer_with_options(
    url: &str,
    dest_path: &Path,
    options: &DownloadOptions,
) -> Result<(), UpdaterError> {
    if let Some(parent) = dest_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| {
                UpdaterError::Io(format!("Failed to create directory {:?}: {e}", parent))
            })?;
        }
    }

    let part_path = PathBuf::from(format!("{}.part", dest_path.display()));
    let meta_path = DownloadMeta::meta_path(&part_path);

    let existing_bytes = if part_path.is_file() {
        part_path.metadata().map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };

    let is_range_remainder = existing_bytes > 0 && !meta_path.is_file();
    let probe_range = if is_range_remainder {
        format!("bytes={existing_bytes}-")
    } else {
        "bytes=0-0".to_string()
    };

    let agent = create_http_agent(CONNECT_TIMEOUT_SECS, READ_TIMEOUT_SECS);
    let probe_req = agent
        .get(url)
        .header("User-Agent", "OneMe Desktop Updater")
        .header("Range", &probe_range);

    let (accept_ranges, total_size, etag, last_modified, probe_resp) = match probe_req.call() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let etag = resp
                .headers()
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            let last_modified = resp
                .headers()
                .get("last-modified")
                .and_then(|v| v.to_str().ok())
                .map(String::from);

            if status == 206 {
                let range_total = resp
                    .headers()
                    .get("Content-Range")
                    .and_then(|v| v.to_str().ok())
                    .and_then(parse_content_range_total);
                let resp_to_use = if is_range_remainder {
                    Some(resp)
                } else {
                    let mut reader = resp.into_body().into_reader();
                    let mut discard = [0u8; 1];
                    let _ = reader.read(&mut discard);
                    None
                };
                (true, range_total, etag, last_modified, resp_to_use)
            } else if status == 200 {
                let content_len = resp
                    .headers()
                    .get("Content-Length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse().ok());
                (false, content_len, etag, last_modified, Some(resp))
            } else {
                return Err(UpdaterError::Download(format!(
                    "Unexpected HTTP status {status} from {url}"
                )));
            }
        }
        Err(ureq::Error::StatusCode(416)) if existing_bytes > 0 => {
            atomic_replace(&part_path, dest_path)?;
            return Ok(());
        }
        Err(ureq::Error::StatusCode(416)) => {
            (true, Some(0), None, None, None)
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

    if options.threads > 1
        && accept_ranges
        && total_size.is_some()
        && total_size.unwrap() > options.chunk_size
    {
        download_parallel_chunks(
            url,
            dest_path,
            &part_path,
            &meta_path,
            total_size.unwrap(),
            etag,
            last_modified,
            options,
        )
    } else {
        if !options.quiet && options.threads > 1 && !accept_ranges {
            eprintln!("[notice] Server does not support Range requests, falling back to single stream");
        }
        download_sequential_with_retry(
            url,
            dest_path,
            &part_path,
            probe_resp,
            total_size,
            options,
        )
    }
}

/// Download installer with default progress reporting to stderr using standard options.
pub fn download_installer(
    url: &str,
    dest_path: &Path,
    quiet: bool,
) -> Result<(), UpdaterError> {
    let options = DownloadOptions {
        quiet,
        ..Default::default()
    };
    download_installer_with_options(url, dest_path, &options)
}

/// Stream download an installer to a `.part` file with HTTP Range resume support,
/// atomically renaming to destination upon full completion.
pub fn download_installer_with_progress<F>(
    url: &str,
    dest_path: &Path,
    mut _progress: F,
) -> Result<(), UpdaterError>
where
    F: FnMut(u64, Option<u64>),
{
    let options = DownloadOptions {
        threads: 1,
        ..Default::default()
    };
    download_installer_with_options(url, dest_path, &options)
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
    let feed_url = args
        .appcast_url
        .as_deref()
        .unwrap_or(DEFAULT_FEED_URL);

    if args.check || args.json {
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

    let options = DownloadOptions {
        threads: args.threads.unwrap_or(DEFAULT_CONCURRENCY).max(1),
        retries: args.retries.unwrap_or(DEFAULT_RETRIES),
        quiet: args.quiet,
        chunk_size: DEFAULT_CHUNK_SIZE,
    };

    download_installer_with_options(&release.url, &dest_file, &options)?;

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
