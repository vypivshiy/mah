use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Cursor, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

static CLI_TEST_COUNTER: AtomicUsize = AtomicUsize::new(100);

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let count = CLI_TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "mah_e2e_cli_{}_{}_{}",
            prefix,
            std::process::id(),
            count
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("failed to create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Mock HTTP Server for CLI E2E tests
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum RouteHandler {
    Xml { status: u16, content: String },
    Bytes { content: Vec<u8> },
}

struct MockServer {
    base_url: String,
    routes: Arc<Mutex<HashMap<String, RouteHandler>>>,
    running: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        let base_url = format!("http://127.0.0.1:{port}");
        let routes = Arc::new(Mutex::new(HashMap::new()));
        let running = Arc::new(AtomicBool::new(true));

        let routes_clone = Arc::clone(&routes);
        let running_clone = Arc::clone(&running);

        let handle = thread::spawn(move || {
            listener.set_nonblocking(true).ok();
            while running_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let routes = Arc::clone(&routes_clone);
                        thread::spawn(move || {
                            handle_connection(stream, routes);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            base_url,
            routes,
            running,
            handle: Some(handle),
        }
    }

    fn register_xml(&self, path: &str, content: &str) {
        self.routes.lock().unwrap().insert(
            path.to_string(),
            RouteHandler::Xml {
                status: 200,
                content: content.to_string(),
            },
        );
    }

    fn register_bytes(&self, path: &str, bytes: Vec<u8>) {
        self.routes.lock().unwrap().insert(
            path.to_string(),
            RouteHandler::Bytes {
                content: bytes,
            },
        );
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        let _ = TcpStream::connect(self.base_url.trim_start_matches("http://"));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle_connection(mut stream: TcpStream, routes: Arc<Mutex<HashMap<String, RouteHandler>>>) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let req_path = parts[1].to_string();

    let mut range_header: Option<String> = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if trimmed.to_lowercase().starts_with("range:") {
            let val = trimmed[6..].trim().to_string();
            range_header = Some(val);
        }
    }

    let handler = {
        let lock = routes.lock().unwrap();
        lock.get(&req_path).cloned()
    };

    match handler {
        Some(RouteHandler::Xml { status, content }) => {
            let body = content.into_bytes();
            let header = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
        Some(RouteHandler::Bytes { content }) => {
            if let Some(range) = range_header {
                if let Some(start_str) = range.strip_prefix("bytes=") {
                    let parts: Vec<&str> = start_str.split('-').collect();
                    let start: usize = parts[0].parse().unwrap_or(0);
                    let end: usize = if parts.len() > 1 && !parts[1].is_empty() {
                        parts[1].parse().unwrap_or(content.len().saturating_sub(1))
                    } else {
                        content.len().saturating_sub(1)
                    };

                    if start >= content.len() {
                        let header = format!(
                            "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{}\r\nConnection: close\r\n\r\n",
                            content.len()
                        );
                        let _ = stream.write_all(header.as_bytes());
                        let _ = stream.flush();
                        return;
                    }
                    let end = end.min(content.len().saturating_sub(1));
                    let slice = &content[start..=end];
                    let header = format!(
                        "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {}-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        start, end, content.len(), slice.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
                    let _ = stream.write_all(slice);
                    let _ = stream.flush();
                    return;
                }
            }

            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                content.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&content);
            let _ = stream.flush();
        }
        None => {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.flush();
        }
    }
}

/// Helper to create a synthetic MSI compound file in memory containing a cabinet stream
fn create_synthetic_msi(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut cab_builder = cab::CabinetBuilder::new();
    {
        let folder = cab_builder.add_folder(cab::CompressionType::MsZip);
        for (name, _) in files {
            folder.add_file(*name);
        }
    }

    let cab_cursor = Cursor::new(Vec::new());
    let mut cab_writer = cab_builder.build(cab_cursor).expect("build cab");

    for (_, data) in files {
        let mut file_writer = cab_writer
            .next_file()
            .expect("next_file call")
            .expect("file_writer option");
        file_writer.write_all(data).expect("write file data");
    }
    let cab_bytes = cab_writer.finish().expect("finish cab").into_inner();

    let msi_cursor = Cursor::new(Vec::new());
    let mut package =
        msi::Package::create(msi::PackageType::Installer, msi_cursor).expect("create msi");
    {
        let mut stream = package.write_stream("media1.cab").expect("write_stream");
        stream.write_all(&cab_bytes).expect("write stream data");
    }
    package.into_inner().expect("into_inner").into_inner()
}

// ---------------------------------------------------------------------------
// E2E Tests
// ---------------------------------------------------------------------------

#[test]
fn test_cli_help_and_subcommand_help() {
    let bin = env!("CARGO_BIN_EXE_dumper_rust");

    // 1. Root --help
    let root = Command::new(bin).arg("--help").output().unwrap();
    assert!(root.status.success());
    let root_out = String::from_utf8_lossy(&root.stdout);
    assert!(root_out.contains("update"));
    assert!(root_out.contains("unpack"));
    assert!(root_out.contains("dump"));

    // 2. update --help
    let update = Command::new(bin).args(["update", "--help"]).output().unwrap();
    assert!(update.status.success());
    let update_out = String::from_utf8_lossy(&update.stdout);
    assert!(update_out.contains("--check"));
    assert!(update_out.contains("--force"));
    assert!(update_out.contains("--json"));
    assert!(update_out.contains("--quiet"));
    assert!(update_out.contains("--appcast-url"));

    // 3. unpack --help
    let unpack = Command::new(bin).args(["unpack", "--help"]).output().unwrap();
    assert!(unpack.status.success());
    let unpack_out = String::from_utf8_lossy(&unpack.stdout);
    assert!(unpack_out.contains("--out-dir"));
    assert!(unpack_out.contains("--all"));
    assert!(unpack_out.contains("--filter"));

    // 4. dump --help
    let dump = Command::new(bin).args(["dump", "--help"]).output().unwrap();
    assert!(dump.status.success());
    let dump_out = String::from_utf8_lossy(&dump.stdout);
    assert!(dump_out.contains("--config"));
    assert!(dump_out.contains("--metadata-output"));
    assert!(dump_out.contains("--with-rva"));
    assert!(dump_out.contains("--no-metadata"));
}

#[test]
fn test_cli_update_check_exit_codes_and_json() {
    let bin = env!("CARGO_BIN_EXE_dumper_rust");
    let server = MockServer::new();
    let temp = TempDirGuard::new("check");

    let feed_xml = format!(r#"<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
    <channel>
        <item>
            <enclosure url="{}/release/MAX.msi" sparkle:version="26.34.0" length="12345"/>
        </item>
    </channel>
</rss>"#, server.base_url);

    server.register_xml("/feed/update.xml", &feed_xml);
    let appcast_url = format!("{}/feed/update.xml", server.base_url);

    // 1. Without metadata.json (defaults to 0.0.0) -> Update available, exit code 10
    let out1 = Command::new(bin)
        .args(["update", "--check", "--appcast-url", &appcast_url])
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert_eq!(out1.status.code(), Some(10), "Update available must exit code 10");

    // 2. With --json output
    let out2 = Command::new(bin)
        .args(["update", "--check", "--json", "--appcast-url", &appcast_url])
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert_eq!(out2.status.code(), Some(10));
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout2.trim()).expect("valid JSON stdout");
    assert_eq!(parsed["update_available"], true);
    assert_eq!(parsed["current_version"], "0.0.0");
    assert_eq!(parsed["remote_version"], "26.34.0");

    // 3. With matching local metadata.json -> Up-to-date, exit code 0
    let meta_json = r#"{"meta":{"app_version":"26.34.0","build_number":100}}"#;
    fs::write(temp.path().join("metadata.json"), meta_json).unwrap();

    let out3 = Command::new(bin)
        .args(["update", "--check", "--appcast-url", &appcast_url])
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert_eq!(out3.status.code(), Some(0), "Up-to-date must exit code 0");
}

#[test]
fn test_cli_update_download_and_resume() {
    let bin = env!("CARGO_BIN_EXE_dumper_rust");
    let server = MockServer::new();
    let temp = TempDirGuard::new("dl_resume");

    let full_content = b"Simulated MSI package contents for range resume testing 1234567890".to_vec();
    server.register_bytes("/release/MAX.msi", full_content.clone());

    let feed_xml = format!(r#"<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
    <channel>
        <item>
            <enclosure url="{}/release/MAX.msi" sparkle:version="26.34.0" length="{}"/>
        </item>
    </channel>
</rss>"#, server.base_url, full_content.len());

    server.register_xml("/feed/update.xml", &feed_xml);
    let appcast_url = format!("{}/feed/update.xml", server.base_url);

    // Pre-create partial file MAX.msi.part with first 20 bytes
    let part_path = temp.path().join("MAX.msi.part");
    fs::write(&part_path, &full_content[..20]).unwrap();

    let out = Command::new(bin)
        .args(["update", "--force", "-q", "--appcast-url", &appcast_url])
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0), "Download must succeed: {:?}", out);

    let msi_path = temp.path().join("MAX.msi");
    assert!(msi_path.is_file(), "MAX.msi must be created after atomic rename");
    assert!(!part_path.exists(), "MAX.msi.part must no longer exist");

    let downloaded = fs::read(&msi_path).unwrap();
    assert_eq!(downloaded, full_content, "Downloaded content must match resumed server content");
}

#[test]
fn test_cli_unpack_selective_all_filter_and_overwrite() {
    let bin = env!("CARGO_BIN_EXE_dumper_rust");
    let temp = TempDirGuard::new("unpack_ops");

    let core_data = b"MOCK_PE_CORE_DLL_DATA_HERE";
    let config_data = b"{\"api_version_uint\": 11}";
    let other_data = b"OTHER_ASSET_CONTENT";

    let msi_bytes = create_synthetic_msi(&[
        ("CM_FP_Unspecified.core.dll", core_data),
        ("CM_FP_Unspecified.config.dll", config_data),
        ("other_asset.txt", other_data),
    ]);

    let msi_path = temp.path().join("MAX.msi");
    fs::write(&msi_path, msi_bytes).unwrap();

    // 1. Default unpack (selective: core.dll and config.dll only)
    let out1 = Command::new(bin)
        .args(["unpack", "-q"])
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert_eq!(out1.status.code(), Some(0), "Default unpack must succeed");
    assert!(temp.path().join("CM_FP_Unspecified.core.dll").is_file());
    assert!(temp.path().join("CM_FP_Unspecified.config.dll").is_file());
    assert!(!temp.path().join("other_asset.txt").exists(), "Default unpack must not extract other assets");

    // 2. Overwrite test: modify core.dll on disk, unpack again, verify overwritten
    fs::write(temp.path().join("CM_FP_Unspecified.core.dll"), b"TAMPERED_DATA").unwrap();
    let out_overwrite = Command::new(bin)
        .args(["unpack", "-q"])
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert_eq!(out_overwrite.status.code(), Some(0));
    let restored_core = fs::read(temp.path().join("CM_FP_Unspecified.core.dll")).unwrap();
    assert_eq!(restored_core, core_data, "Unpack must overwrite existing target files");

    // 3. Unpack with --all
    let out2 = Command::new(bin)
        .args(["unpack", "--all", "-q"])
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert_eq!(out2.status.code(), Some(0));
    assert!(temp.path().join("other_asset.txt").is_file(), "--all must extract other assets");

    // 4. Unpack with custom --filter
    let filter_dir = temp.path().join("filter_test");
    fs::create_dir_all(&filter_dir).unwrap();

    let out3 = Command::new(bin)
        .args(["unpack", msi_path.to_str().unwrap(), "-o", filter_dir.to_str().unwrap(), "--filter", "*.txt", "-q"])
        .output()
        .unwrap();

    assert_eq!(out3.status.code(), Some(0));
    assert!(filter_dir.join("other_asset.txt").is_file());
    assert!(!filter_dir.join("CM_FP_Unspecified.core.dll").exists());
}

#[test]
fn test_cli_error_guidance_for_missing_prerequisites() {
    let bin = env!("CARGO_BIN_EXE_dumper_rust");
    let temp = TempDirGuard::new("guidance");

    // 1. unpack without MAX.msi -> error suggesting 'dumper_rust update'
    let unpack_out = Command::new(bin)
        .args(["unpack"])
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert_eq!(unpack_out.status.code(), Some(1));
    let unpack_err = String::from_utf8_lossy(&unpack_out.stderr);
    assert!(
        unpack_err.contains("dumper_rust update"),
        "Unpack error must point to update command: {}",
        unpack_err
    );

    // 2. dump without CM_FP_Unspecified.core.dll -> error suggesting 'dumper_rust unpack'
    let dump_out = Command::new(bin)
        .args(["dump"])
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert_eq!(dump_out.status.code(), Some(1));
    let dump_err = String::from_utf8_lossy(&dump_out.stderr);
    assert!(
        dump_err.contains("dumper_rust unpack"),
        "Dump error must point to unpack command: {}",
        dump_err
    );
}

#[test]
fn test_cli_chained_workflow_update_unpack_dump() {
    let bin = env!("CARGO_BIN_EXE_dumper_rust");
    let server = MockServer::new();
    let temp = TempDirGuard::new("chained");

    // Check if real core.dll exists in workspace root
    let workspace_core = Path::new("..").join("CM_FP_Unspecified.core.dll");
    let workspace_config = Path::new("..").join("CM_FP_Unspecified.config.dll");

    let (core_bytes, config_bytes) = if workspace_core.is_file() && workspace_config.is_file() {
        (fs::read(&workspace_core).unwrap(), fs::read(&workspace_config).unwrap())
    } else {
        // Fallback for minimal environments
        return;
    };

    // Create synthetic MSI with real core and config DLL bytes
    let msi_content = create_synthetic_msi(&[
        ("CM_FP_Unspecified.core.dll", &core_bytes),
        ("CM_FP_Unspecified.config.dll", &config_bytes),
    ]);

    server.register_bytes("/release/MAX.msi", msi_content.clone());

    let feed_xml = format!(r#"<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
    <channel>
        <item>
            <enclosure url="{}/release/MAX.msi" sparkle:version="26.33.0" length="{}"/>
        </item>
    </channel>
</rss>"#, server.base_url, msi_content.len());

    server.register_xml("/feed/update.xml", &feed_xml);
    let appcast_url = format!("{}/feed/update.xml", server.base_url);

    // Step 1: dumper_rust update
    let update_out = Command::new(bin)
        .args(["update", "--force", "-q", "--appcast-url", &appcast_url])
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert!(update_out.status.success(), "Update step must succeed");
    assert!(temp.path().join("MAX.msi").is_file());

    // Step 2: dumper_rust unpack
    let unpack_out = Command::new(bin)
        .args(["unpack", "-q"])
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert!(unpack_out.status.success(), "Unpack step must succeed");
    assert!(temp.path().join("CM_FP_Unspecified.core.dll").is_file());
    assert!(temp.path().join("CM_FP_Unspecified.config.dll").is_file());

    // Step 3: dumper_rust dump (with no arguments, auto-targeting unpacked DLLs)
    let dump_out = Command::new(bin)
        .args(["dump", "--no-metadata"])
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert!(dump_out.status.success(), "Dump step must succeed: {:?}", dump_out);
    assert!(temp.path().join("packets_rust.json").is_file());
    assert!(temp.path().join("config.json").is_file());
}
