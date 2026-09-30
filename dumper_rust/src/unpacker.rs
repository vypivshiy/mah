use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Command-line arguments and configuration for the unpack subcommand.
#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct UnpackArgs {
    /// Positional path to MSI file (defaults to MAX.msi)
    #[arg(value_name = "MSI_PATH", default_value = "MAX.msi")]
    pub msi_path: PathBuf,

    /// Destination directory for extracted files
    #[arg(short = 'o', long = "out-dir", default_value = ".", value_name = "OUT_DIR")]
    pub out_dir: PathBuf,

    /// Extract all files from the cabinet archive
    #[arg(long, default_value_t = false)]
    pub all: bool,

    /// Custom wildcard / glob filter pattern (e.g. "*.dll", "CM_FP_*.core.dll")
    #[arg(long, value_name = "PATTERN")]
    pub filter: Option<String>,

    /// Suppress progress and status console output
    #[arg(short = 'q', long = "quiet", default_value_t = false)]
    pub quiet: bool,
}

impl Default for UnpackArgs {
    fn default() -> Self {
        Self {
            msi_path: PathBuf::from("MAX.msi"),
            out_dir: PathBuf::from("."),
            all: false,
            filter: None,
            quiet: false,
        }
    }
}

impl UnpackArgs {
    pub fn new(msi_path: impl Into<PathBuf>, out_dir: impl Into<PathBuf>) -> Self {
        Self {
            msi_path: msi_path.into(),
            out_dir: out_dir.into(),
            all: false,
            filter: None,
            quiet: false,
        }
    }
}

/// Metadata describing an extracted file artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedFile {
    /// Preserved entry name inside the cabinet
    pub name: String,
    /// Absolute or resolved output path on disk
    pub path: PathBuf,
    /// Uncompressed file size in bytes
    pub size: u64,
}

/// Result summary of an archive unpacking operation.
#[derive(Debug, Clone)]
pub struct UnpackResult {
    /// Source MSI path
    pub msi_path: PathBuf,
    /// Destination directory
    pub out_dir: PathBuf,
    /// Cabinet stream name unpacked
    pub cabinet_name: String,
    /// List of extracted files
    pub extracted: Vec<ExtractedFile>,
    /// Total duration of the unpacking operation
    pub elapsed: Duration,
}

/// Domain errors encountered during unpacking.
#[derive(Debug)]
pub enum UnpackError {
    /// Target MSI file not found on disk
    MsiNotFound {
        path: PathBuf,
    },
    /// Failed to open or parse the MSI container
    MsiOpenError {
        path: PathBuf,
        source: String,
    },
    /// No Cabinet stream was found inside the MSI
    CabinetNotFound {
        path: PathBuf,
        message: String,
    },
    /// Error decompressing or reading Cabinet stream
    CabinetError {
        stream: String,
        source: String,
    },
    /// Invalid wildcard / glob filter pattern
    FilterError(String),
    /// File system or stream I/O failure
    Io(io::Error),
}

impl std::error::Error for UnpackError {}

impl std::fmt::Display for UnpackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnpackError::MsiNotFound { path } => {
                write!(
                    f,
                    "MSI file '{}' not found. Run 'dumper_rust update' first or specify a valid path with 'dumper_rust unpack <MSI_PATH>'.",
                    path.display()
                )
            }
            UnpackError::MsiOpenError { path, source } => {
                write!(
                    f,
                    "Failed to open MSI file '{}': {}",
                    path.display(),
                    source
                )
            }
            UnpackError::CabinetNotFound { path, message } => {
                write!(
                    f,
                    "No cabinet stream found in MSI '{}': {}",
                    path.display(),
                    message
                )
            }
            UnpackError::CabinetError { stream, source } => {
                write!(
                    f,
                    "Failed to process cabinet stream '{}': {}",
                    stream, source
                )
            }
            UnpackError::FilterError(msg) => {
                write!(f, "Invalid filter pattern: {}", msg)
            }
            UnpackError::Io(err) => {
                write!(f, "I/O error during extraction: {}", err)
            }
        }
    }
}

impl From<io::Error> for UnpackError {
    fn from(err: io::Error) -> Self {
        UnpackError::Io(err)
    }
}

impl UnpackError {
    /// Process exit code associated with this error (contract: exit code 1).
    pub fn exit_code(&self) -> i32 {
        1
    }
}

/// Filter strategy to select which files are decompressed from the cabinet.
#[derive(Debug, Clone)]
pub enum FileFilter {
    /// Decompress all files in the cabinet (`--all`)
    All,
    /// Default selective filter matching `*.core.dll` and `*.config.dll` (case-insensitive)
    Default,
    /// Custom wildcard / glob regex matcher list (`--filter <pattern>`)
    Custom(Vec<regex::Regex>),
}

impl FileFilter {
    /// Resolve filter from arguments.
    pub fn from_args(all: bool, filter: Option<&str>) -> Result<Self, UnpackError> {
        if all {
            Ok(FileFilter::All)
        } else if let Some(pattern) = filter {
            Self::parse(pattern)
        } else {
            Ok(FileFilter::Default)
        }
    }

    /// Parse wildcard/glob pattern(s) into a `FileFilter::Custom`.
    /// Supports comma- or semicolon-separated pattern lists.
    pub fn parse(pattern: &str) -> Result<Self, UnpackError> {
        let mut regexes = Vec::new();
        for part in pattern.split([',', ';']) {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            let rx = glob_to_regex(trimmed).map_err(|e| {
                UnpackError::FilterError(format!("Failed to compile pattern '{}': {}", trimmed, e))
            })?;
            regexes.push(rx);
        }

        if regexes.is_empty() {
            Ok(FileFilter::All)
        } else {
            Ok(FileFilter::Custom(regexes))
        }
    }

    /// Check if a filename matches the filter rules.
    pub fn matches(&self, filename: &str) -> bool {
        match self {
            FileFilter::All => true,
            FileFilter::Default => Self::matches_default(filename),
            FileFilter::Custom(regexes) => regexes.iter().any(|rx| rx.is_match(filename)),
        }
    }

    /// Default matching predicate: specifically `CM_FP_Unspecified.core.dll` and `CM_FP_Unspecified.config.dll` (case-insensitive).
    pub fn matches_default(filename: &str) -> bool {
        let clean = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
        clean.eq_ignore_ascii_case("CM_FP_Unspecified.core.dll")
            || clean.eq_ignore_ascii_case("CM_FP_Unspecified.config.dll")
    }
}

/// Convert a wildcard pattern (with `*` and `?`) into a case-insensitive anchored regex.
pub fn glob_to_regex(glob: &str) -> Result<regex::Regex, regex::Error> {
    let mut regex_str = String::from("(?i)^");
    for c in glob.chars() {
        match c {
            '*' => regex_str.push_str(".*"),
            '?' => regex_str.push('.'),
            '.' | '(' | ')' | '+' | '|' | '[' | ']' | '{' | '}' | '^' | '$' | '\\' => {
                regex_str.push('\\');
                regex_str.push(c);
            }
            _ => regex_str.push(c),
        }
    }
    regex_str.push('$');
    regex::Regex::new(&regex_str)
}

/// Safely join relative path to base directory, preventing directory traversal.
pub fn safe_join(base: &Path, rel: &str) -> PathBuf {
    let clean = rel.replace('\\', "/");
    let mut path = base.to_path_buf();
    for part in clean.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            continue;
        }
        path.push(part);
    }
    path
}

/// Locate cabinet stream inside an MSI package.
/// Checks `media1.cab`, any stream ending in `.cab`, and the `Media` table.
pub fn find_cabinet_stream<F: Read + Seek>(package: &mut msi::Package<F>) -> Option<String> {
    if package.has_stream("media1.cab") {
        return Some("media1.cab".to_string());
    }

    for stream in package.streams() {
        if stream.to_ascii_lowercase().ends_with(".cab") {
            return Some(stream.to_string());
        }
    }

    let candidates: Vec<String> = if let Ok(rows) = package.select_rows(msi::Select::table("Media")) {
        rows.into_iter()
            .filter(|r| r.has_column("Cabinet"))
            .filter_map(|r| r["Cabinet"].as_str().map(|s| s.to_string()))
            .collect()
    } else {
        Vec::new()
    };

    for cab_field in candidates {
        let clean = cab_field.trim_start_matches('#');
        if package.has_stream(clean) {
            return Some(clean.to_string());
        }
        if package.has_stream(&cab_field) {
            return Some(cab_field);
        }
    }

    None
}

/// Extract matching files from an already opened MSI package.
pub fn unpack_from_package<F: Read + Seek>(
    package: &mut msi::Package<F>,
    out_dir: &Path,
    filter: &FileFilter,
    cab_stream_name: &str,
) -> Result<Vec<ExtractedFile>, UnpackError> {
    let stream = package
        .read_stream(cab_stream_name)
        .map_err(|e| UnpackError::CabinetError {
            stream: cab_stream_name.to_string(),
            source: e.to_string(),
        })?;

    let mut cabinet = cab::Cabinet::new(stream).map_err(|e| UnpackError::CabinetError {
        stream: cab_stream_name.to_string(),
        source: e.to_string(),
    })?;

    // 1. Collect all matching file entries with deduplication
    let mut matched_entries = Vec::new();
    let mut seen = HashSet::new();

    for folder in cabinet.folder_entries() {
        for file in folder.file_entries() {
            let name = file.name();
            if filter.matches(name) && seen.insert(name.to_string()) {
                matched_entries.push((name.to_string(), file.uncompressed_size() as u64));
            }
        }
    }

    // 2. Ensure destination directory exists
    fs::create_dir_all(out_dir)?;

    let mut extracted = Vec::new();

    // 3. Decompress each matching file directly to disk, overwriting by default
    for (name, size) in matched_entries {
        let dest_path = safe_join(out_dir, &name);
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut reader = cabinet
            .read_file(&name)
            .map_err(|e| UnpackError::CabinetError {
                stream: cab_stream_name.to_string(),
                source: format!("Failed to read file '{}' from cabinet: {}", name, e),
            })?;

        let mut writer = File::create(&dest_path)?;
        io::copy(&mut reader, &mut writer)?;
        writer.flush()?;

        extracted.push(ExtractedFile {
            name,
            path: dest_path,
            size,
        });
    }

    Ok(extracted)
}

/// Convenience function to unpack an open package into a destination directory.
pub fn unpack_package<F: Read + Seek>(
    package: &mut msi::Package<F>,
    out_dir: &Path,
    filter: &FileFilter,
) -> Result<(String, Vec<ExtractedFile>), UnpackError> {
    let cab_stream_name = find_cabinet_stream(package).ok_or_else(|| {
        UnpackError::CabinetNotFound {
            path: PathBuf::from("<in-memory>"),
            message: "No embedded cabinet stream found (e.g. media1.cab)".to_string(),
        }
    })?;
    let extracted = unpack_from_package(package, out_dir, filter, &cab_stream_name)?;
    Ok((cab_stream_name, extracted))
}

/// Primary programmatic entrypoint: unpack files from an MSI installer according to arguments.
pub fn unpack(args: &UnpackArgs) -> Result<UnpackResult, UnpackError> {
    let t0 = Instant::now();

    if !args.msi_path.is_file() {
        return Err(UnpackError::MsiNotFound {
            path: args.msi_path.clone(),
        });
    }

    let mut package = msi::open(&args.msi_path).map_err(|e| UnpackError::MsiOpenError {
        path: args.msi_path.clone(),
        source: e.to_string(),
    })?;

    let cab_stream_name =
        find_cabinet_stream(&mut package).ok_or_else(|| UnpackError::CabinetNotFound {
            path: args.msi_path.clone(),
            message: "No embedded cabinet stream found (e.g. media1.cab)".to_string(),
        })?;

    let filter = FileFilter::from_args(args.all, args.filter.as_deref())?;

    let extracted = unpack_from_package(
        &mut package,
        &args.out_dir,
        &filter,
        &cab_stream_name,
    )?;

    Ok(UnpackResult {
        msi_path: args.msi_path.clone(),
        out_dir: args.out_dir.clone(),
        cabinet_name: cab_stream_name,
        extracted,
        elapsed: t0.elapsed(),
    })
}

/// CLI runner entrypoint: executes unpack and prints user-facing logs unless quiet.
pub fn run_unpack(args: &UnpackArgs) -> Result<UnpackResult, UnpackError> {
    if !args.quiet {
        println!("=== Unpacking MSI Archive ===");
        println!("Target MSI: {}", args.msi_path.display());
        println!("Destination: {}", args.out_dir.display());
    }

    let result = unpack(args)?;

    if !args.quiet {
        println!("Cabinet stream: {}", result.cabinet_name);
        if result.extracted.is_empty() {
            println!("Warning: No files matched filter in cabinet.");
        } else {
            for file in &result.extracted {
                println!(
                    "Extracted: {} ({:.2} MB) -> {}",
                    file.name,
                    file.size as f64 / 1_048_576.0,
                    file.path.display()
                );
            }
            println!(
                "Unpacked {} file(s) in {:.2?}",
                result.extracted.len(),
                result.elapsed
            );
        }
    }

    Ok(result)
}
