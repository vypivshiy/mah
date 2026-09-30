use dumper_rust::updater::{
    self, exit_codes, parse_appcast_xml, resolve_destination, resolve_local_version, AppVersion,
    UpdateArgs, UpdateCheckResult,
};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

// ---------------------------------------------------------------------------
// Mock HTTP Server
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum RouteHandler {
    Xml { status: u16, content: String },
    Bytes { content: Vec<u8>, support_range: bool },
    TruncatedBytes { declared_len: usize, content: Vec<u8> },
    Error { status: u16, message: String },
}

struct MockServer {
    port: u16,
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
            port,
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

    fn register_bytes(&self, path: &str, content: Vec<u8>, support_range: bool) {
        self.routes.lock().unwrap().insert(
            path.to_string(),
            RouteHandler::Bytes {
                content,
                support_range,
            },
        );
    }

    fn register_truncated(&self, path: &str, declared_len: usize, content: Vec<u8>) {
        self.routes.lock().unwrap().insert(
            path.to_string(),
            RouteHandler::TruncatedBytes {
                declared_len,
                content,
            },
        );
    }

    fn register_error(&self, path: &str, status: u16, message: &str) {
        self.routes.lock().unwrap().insert(
            path.to_string(),
            RouteHandler::Error {
                status,
                message: message.to_string(),
            },
        );
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
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
    let path = parts[1];

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

    let route = {
        let guard = routes.lock().unwrap();
        guard.get(path).cloned()
    };

    match route {
        Some(RouteHandler::Xml { status, content }) => {
            let body = content.as_bytes();
            let status_line = if status == 200 { "200 OK" } else { "Error" };
            let response = format!(
                "HTTP/1.1 {status} {status_line}\r\n\
                 Content-Type: application/xml; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
            let _ = stream.flush();
        }
        Some(RouteHandler::Bytes {
            content,
            support_range,
        }) => {
            if support_range && range_header.is_some() {
                let range_str = range_header.unwrap();
                if let Some(bytes_spec) = range_str.strip_prefix("bytes=") {
                    let parts: Vec<&str> = bytes_spec.split('-').collect();
                    let start: usize = parts[0].parse().unwrap_or(0);
                    let end: usize = if parts.len() > 1 && !parts[1].is_empty() {
                        parts[1].parse().unwrap_or(content.len().saturating_sub(1))
                    } else {
                        content.len().saturating_sub(1)
                    };

                    if start >= content.len() {
                        let response = format!(
                            "HTTP/1.1 416 Range Not Satisfiable\r\n\
                             Content-Range: bytes */{}\r\n\
                             Content-Length: 0\r\n\
                             Connection: close\r\n\r\n",
                            content.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                        return;
                    }

                    let end = end.min(content.len().saturating_sub(1));
                    let chunk = &content[start..=end];
                    let response = format!(
                        "HTTP/1.1 206 Partial Content\r\n\
                         Content-Type: application/octet-stream\r\n\
                         Content-Range: bytes {start}-{end}/{}\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\r\n",
                        content.len(),
                        chunk.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.write_all(chunk);
                    let _ = stream.flush();
                    return;
                }
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                content.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&content);
            let _ = stream.flush();
        }
        Some(RouteHandler::TruncatedBytes {
            declared_len,
            content,
        }) => {
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Length: {declared_len}\r\n\
                 Connection: close\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&content);
            let _ = stream.flush();
        }
        Some(RouteHandler::Error { status, message }) => {
            let body = message.as_bytes();
            let response = format!(
                "HTTP/1.1 {status} Error\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
            let _ = stream.flush();
        }
        None => {
            let body = b"Not Found";
            let response = format!(
                "HTTP/1.1 404 Not Found\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
            let _ = stream.flush();
        }
    }
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("mah_updater_test_{prefix}_{pid}_{id}"));
        fs::create_dir_all(&path).expect("create test temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn make_sparkle_feed(
    version: &str,
    url: &str,
    ed_sig: Option<&str>,
    dsa_sig: Option<&str>,
    installer_args: Option<&str>,
    critical: bool,
) -> String {
    let critical_tag = if critical {
        "<sparkle:tags><sparkle:criticalUpdate/></sparkle:tags>"
    } else {
        ""
    };
    let dsa_attr = dsa_sig
        .map(|s| format!("sparkle:dsaSignature=\"{s}\""))
        .unwrap_or_default();
    let ed_attr = ed_sig
        .map(|s| format!("sparkle:edSignature=\"{s}\""))
        .unwrap_or_default();
    let args_attr = installer_args
        .map(|s| format!("sparkle:installerArguments=\"{s}\""))
        .unwrap_or_default();

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
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
</rss>"#
    )
}

// ---------------------------------------------------------------------------
// Unit Tests: AppVersion
// ---------------------------------------------------------------------------

#[test]
fn test_version_parsing_and_normalization() {
    let v1 = AppVersion::parse("26.33.0");
    assert_eq!(v1.parts, vec![26, 33, 0]);
    assert_eq!(v1.to_string(), "26.33.0");

    let v2 = AppVersion::parse("26.33.0.13970");
    assert_eq!(v2.parts, vec![26, 33, 0, 13970]);

    let v3 = AppVersion::parse("26.33");
    assert_eq!(v3.parts, vec![26, 33, 0]);

    let v4 = AppVersion::parse("26.33.0.0");
    assert_eq!(v4.parts, vec![26, 33, 0]);

    let v5 = AppVersion::parse("v26.34.0");
    assert_eq!(v5.parts, vec![26, 34, 0]);

    let v6 = AppVersion::parse("");
    assert_eq!(v6.parts, vec![0, 0, 0]);
    assert_eq!(v6.to_string(), "0.0.0");
}

#[test]
fn test_version_comparisons() {
    assert_eq!(
        AppVersion::parse("26.33.0.0"),
        AppVersion::parse("26.33.0")
    );
    assert_eq!(
        AppVersion::parse("26.33.0"),
        AppVersion::parse("26.33")
    );
    assert!(AppVersion::parse("26.34.0") > AppVersion::parse("26.33.0"));
    assert!(AppVersion::parse("26.33.0.13970") > AppVersion::parse("26.33.0"));
    assert!(AppVersion::parse("26.33.0.13970") < AppVersion::parse("26.33.1"));
    assert!(AppVersion::parse("26.33.0") > AppVersion::parse("0.0.0"));
}

// ---------------------------------------------------------------------------
// Unit Tests: XML Feed Parsing
// ---------------------------------------------------------------------------

#[test]
fn test_parse_feed_xml_valid_windows() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
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
    </rss>"#;

    let info = parse_appcast_xml(xml).expect("parse windows feed");
    assert_eq!(info.version.to_string(), "26.33.0");
    assert_eq!(info.version.parts, vec![26, 33, 0]);
    assert_eq!(info.url, "https://download.max.ru/win/release/26.33.0/MAX.msi");
    assert_eq!(info.ed_signature.as_deref(), Some("ed_sig_test"));
    assert_eq!(info.dsa_signature.as_deref(), Some("dsa_sig_test"));
    assert_eq!(info.installer_arguments.as_deref(), Some("ProductLanguage=1049 /qb!"));
    assert!(info.critical);
}

#[test]
fn test_parse_feed_xml_valid_mac() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
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
    </rss>"#;

    let info = parse_appcast_xml(xml).expect("parse mac feed");
    assert_eq!(info.version.to_string(), "26.33.0");
    assert_eq!(info.url, "https://download.max.ru/mac/release/26.33.0/MAX.dmg");
    assert_eq!(info.ed_signature.as_deref(), Some("ed_mac_test"));
    assert_eq!(info.dsa_signature, None);
    assert_eq!(info.installer_arguments, None);
    assert!(!info.critical);
}

#[test]
fn test_parse_feed_xml_multiple_items_selects_highest_version() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
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
    </rss>"#;

    let info = parse_appcast_xml(xml).expect("parse multiple items");
    assert_eq!(info.version.to_string(), "26.35.0");
    assert_eq!(info.url, "https://example.com/26.35.0.msi");
}

#[test]
fn test_parse_feed_xml_errors() {
    // Malformed XML
    assert!(parse_appcast_xml("<not valid xml").is_err());

    // No <item>
    assert!(parse_appcast_xml("<rss><channel></channel></rss>").is_err());

    // No <enclosure>
    assert!(parse_appcast_xml("<rss><channel><item></item></channel></rss>").is_err());

    // Missing 'url'
    let no_url = r#"<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
        <channel><item><enclosure sparkle:version="1.0"/></item></channel></rss>"#;
    assert!(parse_appcast_xml(no_url).is_err());

    // Missing 'version'
    let no_ver = r#"<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
        <channel><item><enclosure url="http://x"/></item></channel></rss>"#;
    assert!(parse_appcast_xml(no_ver).is_err());
}

// ---------------------------------------------------------------------------
// Unit Tests: Version Cascade
// ---------------------------------------------------------------------------

#[test]
fn test_version_cascade() {
    let temp = TestDir::new("cascade");
    let meta_file = temp.path().join("metadata.json");

    // 1. Explicit valid file
    fs::write(
        &meta_file,
        r#"{"meta": {"app_version": "26.33.0", "build_number": 123}}"#,
    )
    .unwrap();
    assert_eq!(
        resolve_local_version(Some(&meta_file)),
        AppVersion::parse("26.33.0")
    );

    // 2. Non-existent file defaults to 0.0.0
    let missing_file = temp.path().join("missing.json");
    assert_eq!(
        resolve_local_version(Some(&missing_file)),
        AppVersion::parse("0.0.0")
    );

    // 3. Malformed JSON defaults to 0.0.0
    let malformed_file = temp.path().join("bad.json");
    fs::write(&malformed_file, "not-json").unwrap();
    assert_eq!(
        resolve_local_version(Some(&malformed_file)),
        AppVersion::parse("0.0.0")
    );

    // 4. Missing meta.app_version defaults to 0.0.0
    let no_meta_ver = temp.path().join("no_meta.json");
    fs::write(&no_meta_ver, r#"{"meta": {}}"#).unwrap();
    assert_eq!(
        resolve_local_version(Some(&no_meta_ver)),
        AppVersion::parse("0.0.0")
    );
}

// ---------------------------------------------------------------------------
// Integration Tests: Check Mode & JSON Output
// ---------------------------------------------------------------------------

#[test]
fn test_check_mode_update_available_exit_code_10() {
    let server = MockServer::new();
    let feed_xml = make_sparkle_feed("26.34.0", &format!("{}/MAX.msi", server.base_url), None, None, None, false);
    server.register_xml("/update.xml", &feed_xml);

    let temp = TestDir::new("check_avail");
    let meta_file = temp.path().join("metadata.json");
    fs::write(&meta_file, r#"{"meta": {"app_version": "26.33.0"}}"#).unwrap();

    let args = UpdateArgs {
        check: true,
        appcast_url: Some(format!("{}/update.xml", server.base_url)),
        metadata_path: Some(meta_file),
        ..Default::default()
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = updater::run_with_output(&args, &mut stdout, &mut stderr);

    assert_eq!(code, exit_codes::UPDATE_AVAILABLE);
    let out = String::from_utf8(stdout).unwrap();
    assert!(out.contains("Update available: 26.34.0"));
    assert!(out.contains("current: 26.33.0"));
}

#[test]
fn test_check_mode_up_to_date_exit_code_0() {
    let server = MockServer::new();
    let feed_xml = make_sparkle_feed("26.33.0", &format!("{}/MAX.msi", server.base_url), None, None, None, false);
    server.register_xml("/update.xml", &feed_xml);

    let temp = TestDir::new("check_uptodate");
    let meta_file = temp.path().join("metadata.json");
    fs::write(&meta_file, r#"{"meta": {"app_version": "26.33.0"}}"#).unwrap();

    let args = UpdateArgs {
        check: true,
        appcast_url: Some(format!("{}/update.xml", server.base_url)),
        metadata_path: Some(meta_file),
        ..Default::default()
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = updater::run_with_output(&args, &mut stdout, &mut stderr);

    assert_eq!(code, exit_codes::SUCCESS);
    let out = String::from_utf8(stdout).unwrap();
    assert!(out.contains("Client is up to date (26.33.0)."));
}

#[test]
fn test_check_mode_does_not_mutate_or_download() {
    let server = MockServer::new();
    let feed_xml = make_sparkle_feed("26.34.0", &format!("{}/MAX.msi", server.base_url), None, None, None, false);
    server.register_xml("/update.xml", &feed_xml);

    let temp = TestDir::new("check_nomutate");
    let meta_file = temp.path().join("metadata.json");
    let initial_content = r#"{"meta": {"app_version": "26.33.0"}}"#;
    fs::write(&meta_file, initial_content).unwrap();

    let dest_file = temp.path().join("MAX.msi");
    let args = UpdateArgs {
        check: true,
        output: Some(dest_file.clone()),
        appcast_url: Some(format!("{}/update.xml", server.base_url)),
        metadata_path: Some(meta_file.clone()),
        ..Default::default()
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = updater::run_with_output(&args, &mut stdout, &mut stderr);

    assert_eq!(code, exit_codes::UPDATE_AVAILABLE);
    assert!(!dest_file.exists());
    let part_file = temp.path().join("MAX.msi.part");
    assert!(!part_file.exists());
    assert_eq!(fs::read_to_string(&meta_file).unwrap(), initial_content);
}

#[test]
fn test_check_mode_json_output() {
    let server = MockServer::new();
    let feed_xml = make_sparkle_feed(
        "26.34.0",
        &format!("{}/MAX.msi", server.base_url),
        Some("ed_val"),
        Some("dsa_val"),
        Some("/qb!"),
        true,
    );
    server.register_xml("/update.xml", &feed_xml);

    let temp = TestDir::new("check_json");
    let meta_file = temp.path().join("metadata.json");
    fs::write(&meta_file, r#"{"meta": {"app_version": "26.33.0"}}"#).unwrap();

    let args = UpdateArgs {
        check: true,
        json: true,
        appcast_url: Some(format!("{}/update.xml", server.base_url)),
        metadata_path: Some(meta_file),
        ..Default::default()
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = updater::run_with_output(&args, &mut stdout, &mut stderr);

    assert_eq!(code, exit_codes::UPDATE_AVAILABLE);
    let out = String::from_utf8(stdout).unwrap();
    let parsed: UpdateCheckResult = serde_json::from_str(out.trim()).expect("deserialize json");
    assert!(parsed.update_available);
    assert_eq!(parsed.current_version, "26.33.0");
    assert_eq!(parsed.latest_version, "26.34.0");
    assert_eq!(parsed.remote_version, "26.34.0");
    assert_eq!(parsed.url, format!("{}/MAX.msi", server.base_url));
    assert_eq!(parsed.signatures.ed.as_deref(), Some("ed_val"));
    assert_eq!(parsed.signatures.dsa.as_deref(), Some("dsa_val"));
    assert_eq!(parsed.installer_arguments.as_deref(), Some("/qb!"));
    assert!(parsed.critical);
    assert!(!parsed.checked_at.is_empty());
}

#[test]
fn test_json_flag_without_check_returns_exit_code_2() {
    let args = UpdateArgs {
        check: false,
        json: true,
        ..Default::default()
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = updater::run_with_output(&args, &mut stdout, &mut stderr);

    assert_eq!(code, exit_codes::CLI_ERROR);
    let err_out = String::from_utf8(stderr).unwrap();
    assert!(err_out.contains("--json requires --check"));
}

// ---------------------------------------------------------------------------
// Integration Tests: Staged Downloader with Range Resume
// ---------------------------------------------------------------------------

#[test]
fn test_download_full_from_scratch() {
    let server = MockServer::new();
    let installer_data = b"MOCK_INSTALLER_BINARY_DATA_CHUNK_ABC".to_vec();
    server.register_bytes("/MAX.msi", installer_data.clone(), true);

    let feed_xml = make_sparkle_feed("26.34.0", &format!("{}/MAX.msi", server.base_url), None, None, None, false);
    server.register_xml("/update.xml", &feed_xml);

    let temp = TestDir::new("dl_full");
    let dest_file = temp.path().join("output.msi");
    let meta_file = temp.path().join("metadata.json");
    fs::write(&meta_file, r#"{"meta": {"app_version": "26.33.0"}}"#).unwrap();

    let args = UpdateArgs {
        output: Some(dest_file.clone()),
        appcast_url: Some(format!("{}/update.xml", server.base_url)),
        metadata_path: Some(meta_file),
        ..Default::default()
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = updater::run_with_output(&args, &mut stdout, &mut stderr);

    assert_eq!(code, exit_codes::SUCCESS);
    assert!(dest_file.is_file());
    assert_eq!(fs::read(&dest_file).unwrap(), installer_data);
    let part_file = temp.path().join("output.msi.part");
    assert!(!part_file.exists());
}

#[test]
fn test_download_skipped_when_up_to_date_unless_force() {
    let server = MockServer::new();
    let installer_data = b"FORCE_REQUIRED_DATA".to_vec();
    server.register_bytes("/MAX.msi", installer_data.clone(), true);

    let feed_xml = make_sparkle_feed("26.33.0", &format!("{}/MAX.msi", server.base_url), None, None, None, false);
    server.register_xml("/update.xml", &feed_xml);

    let temp = TestDir::new("dl_uptodate");
    let dest_file = temp.path().join("output.msi");
    let meta_file = temp.path().join("metadata.json");
    fs::write(&meta_file, r#"{"meta": {"app_version": "26.33.0"}}"#).unwrap();

    // 1. Without --force: should NOT download
    let args_no_force = UpdateArgs {
        output: Some(dest_file.clone()),
        appcast_url: Some(format!("{}/update.xml", server.base_url)),
        metadata_path: Some(meta_file.clone()),
        force: false,
        ..Default::default()
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = updater::run_with_output(&args_no_force, &mut stdout, &mut stderr);
    assert_eq!(code, exit_codes::SUCCESS);
    assert!(!dest_file.exists());

    // 2. With --force: MUST download
    let args_force = UpdateArgs {
        output: Some(dest_file.clone()),
        appcast_url: Some(format!("{}/update.xml", server.base_url)),
        metadata_path: Some(meta_file),
        force: true,
        ..Default::default()
    };
    let mut stdout2 = Vec::new();
    let mut stderr2 = Vec::new();
    let code2 = updater::run_with_output(&args_force, &mut stdout2, &mut stderr2);
    assert_eq!(code2, exit_codes::SUCCESS);
    assert!(dest_file.is_file());
    assert_eq!(fs::read(&dest_file).unwrap(), installer_data);
}

#[test]
fn test_download_resume_partial_content_206() {
    let server = MockServer::new();
    let full_content = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".repeat(50); // 1800 bytes
    server.register_bytes("/MAX.msi", full_content.clone(), true);

    let feed_xml = make_sparkle_feed("26.34.0", &format!("{}/MAX.msi", server.base_url), None, None, None, false);
    server.register_xml("/update.xml", &feed_xml);

    let temp = TestDir::new("dl_resume");
    let dest_file = temp.path().join("resumed.msi");
    let part_file = temp.path().join("resumed.msi.part");
    let meta_file = temp.path().join("metadata.json");
    fs::write(&meta_file, r#"{"meta": {"app_version": "26.33.0"}}"#).unwrap();

    // Pre-create partial file with first 400 bytes
    let initial_chunk = &full_content[..400];
    fs::write(&part_file, initial_chunk).unwrap();
    assert_eq!(part_file.metadata().unwrap().len(), 400);

    let args = UpdateArgs {
        output: Some(dest_file.clone()),
        appcast_url: Some(format!("{}/update.xml", server.base_url)),
        metadata_path: Some(meta_file),
        ..Default::default()
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = updater::run_with_output(&args, &mut stdout, &mut stderr);

    assert_eq!(code, exit_codes::SUCCESS);
    assert!(dest_file.is_file());
    assert_eq!(fs::read(&dest_file).unwrap(), full_content);
    assert!(!part_file.exists());
}

#[test]
fn test_download_resume_http_416_when_already_complete() {
    let server = MockServer::new();
    let full_content = b"ALREADY_FINISHED_PAYLOAD_BYTES".to_vec();
    server.register_bytes("/MAX.msi", full_content.clone(), true);

    let feed_xml = make_sparkle_feed("26.34.0", &format!("{}/MAX.msi", server.base_url), None, None, None, false);
    server.register_xml("/update.xml", &feed_xml);

    let temp = TestDir::new("dl_416");
    let dest_file = temp.path().join("finished.msi");
    let part_file = temp.path().join("finished.msi.part");
    let meta_file = temp.path().join("metadata.json");
    fs::write(&meta_file, r#"{"meta": {"app_version": "26.33.0"}}"#).unwrap();

    // Pre-create part file with 100% of bytes
    fs::write(&part_file, &full_content).unwrap();

    let args = UpdateArgs {
        output: Some(dest_file.clone()),
        appcast_url: Some(format!("{}/update.xml", server.base_url)),
        metadata_path: Some(meta_file),
        ..Default::default()
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = updater::run_with_output(&args, &mut stdout, &mut stderr);

    assert_eq!(code, exit_codes::SUCCESS);
    assert!(dest_file.is_file());
    assert_eq!(fs::read(&dest_file).unwrap(), full_content);
    assert!(!part_file.exists());
}

#[test]
fn test_download_restarts_from_zero_when_server_ignores_range_200() {
    let server = MockServer::new();
    let full_content = b"FRESH_SERVER_CONTENT_BYTES_200".to_vec();
    // support_range: false simulates server responding 200 OK to range requests
    server.register_bytes("/MAX.msi", full_content.clone(), false);

    let feed_xml = make_sparkle_feed("26.34.0", &format!("{}/MAX.msi", server.base_url), None, None, None, false);
    server.register_xml("/update.xml", &feed_xml);

    let temp = TestDir::new("dl_200_restart");
    let dest_file = temp.path().join("restart.msi");
    let part_file = temp.path().join("restart.msi.part");
    let meta_file = temp.path().join("metadata.json");
    fs::write(&meta_file, r#"{"meta": {"app_version": "26.33.0"}}"#).unwrap();

    // Pre-create part file with garbage data
    fs::write(&part_file, b"GARBAGE_INITIAL_DATA").unwrap();

    let args = UpdateArgs {
        output: Some(dest_file.clone()),
        appcast_url: Some(format!("{}/update.xml", server.base_url)),
        metadata_path: Some(meta_file),
        ..Default::default()
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = updater::run_with_output(&args, &mut stdout, &mut stderr);

    assert_eq!(code, exit_codes::SUCCESS);
    assert!(dest_file.is_file());
    // Truncated and replaced from 0
    assert_eq!(fs::read(&dest_file).unwrap(), full_content);
    assert!(!part_file.exists());
}

#[test]
fn test_download_fails_on_truncated_connection() {
    let server = MockServer::new();
    // Server advertises 1000 bytes but only sends 200
    server.register_truncated("/MAX.msi", 1000, vec![b'X'; 200]);

    let feed_xml = make_sparkle_feed("26.34.0", &format!("{}/MAX.msi", server.base_url), None, None, None, false);
    server.register_xml("/update.xml", &feed_xml);

    let temp = TestDir::new("dl_truncated");
    let dest_file = temp.path().join("incomplete.msi");
    let part_file = temp.path().join("incomplete.msi.part");
    let meta_file = temp.path().join("metadata.json");
    fs::write(&meta_file, r#"{"meta": {"app_version": "26.33.0"}}"#).unwrap();

    let args = UpdateArgs {
        output: Some(dest_file.clone()),
        appcast_url: Some(format!("{}/update.xml", server.base_url)),
        metadata_path: Some(meta_file),
        ..Default::default()
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = updater::run_with_output(&args, &mut stdout, &mut stderr);

    assert_eq!(code, exit_codes::ERROR);
    assert!(!dest_file.exists());
    assert!(part_file.is_file()); // partial file preserved for resume
    let err_out = String::from_utf8(stderr).unwrap();
    assert!(
        err_out.contains("Connection aborted prematurely")
            || err_out.contains("Read error")
            || err_out.to_lowercase().contains("error"),
        "actual error: {err_out}"
    );
}

#[test]
fn test_quiet_flag_suppresses_stdout() {
    let server = MockServer::new();
    let installer_data = b"QUIET_TEST_PAYLOAD".to_vec();
    server.register_bytes("/MAX.msi", installer_data, true);

    let feed_xml = make_sparkle_feed("26.34.0", &format!("{}/MAX.msi", server.base_url), None, None, None, false);
    server.register_xml("/update.xml", &feed_xml);

    let temp = TestDir::new("dl_quiet");
    let dest_file = temp.path().join("quiet.msi");
    let meta_file = temp.path().join("metadata.json");
    fs::write(&meta_file, r#"{"meta": {"app_version": "26.33.0"}}"#).unwrap();

    let args = UpdateArgs {
        output: Some(dest_file.clone()),
        appcast_url: Some(format!("{}/update.xml", server.base_url)),
        metadata_path: Some(meta_file),
        quiet: true,
        ..Default::default()
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = updater::run_with_output(&args, &mut stdout, &mut stderr);

    assert_eq!(code, exit_codes::SUCCESS);
    assert!(dest_file.is_file());
    assert!(stdout.is_empty(), "Stdout must be empty when quiet=true");
}

#[test]
fn test_http_error_fetching_feed_exit_code_1() {
    let server = MockServer::new();
    server.register_error("/update.xml", 500, "Internal Server Error");

    let args = UpdateArgs {
        check: true,
        appcast_url: Some(format!("{}/update.xml", server.base_url)),
        ..Default::default()
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = updater::run_with_output(&args, &mut stdout, &mut stderr);

    assert_eq!(code, exit_codes::ERROR);
    let err_out = String::from_utf8(stderr).unwrap();
    assert!(err_out.to_lowercase().contains("error"));
}

#[test]
fn test_http_error_downloading_installer_exit_code_1() {
    let server = MockServer::new();
    server.register_error("/missing.msi", 404, "Not Found");

    let feed_xml = make_sparkle_feed("26.34.0", &format!("{}/missing.msi", server.base_url), None, None, None, false);
    server.register_xml("/update.xml", &feed_xml);

    let temp = TestDir::new("dl_404");
    let dest_file = temp.path().join("missing.msi");
    let meta_file = temp.path().join("metadata.json");
    fs::write(&meta_file, r#"{"meta": {"app_version": "26.33.0"}}"#).unwrap();

    let args = UpdateArgs {
        output: Some(dest_file.clone()),
        appcast_url: Some(format!("{}/update.xml", server.base_url)),
        metadata_path: Some(meta_file),
        ..Default::default()
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = updater::run_with_output(&args, &mut stdout, &mut stderr);

    assert_eq!(code, exit_codes::ERROR);
    assert!(!dest_file.exists());
    let err_out = String::from_utf8(stderr).unwrap();
    assert!(err_out.contains("404"));
}

#[test]
fn test_resolve_destination_directory() {
    let temp = TestDir::new("dest_dir");
    let dir = temp.path();

    let resolved = resolve_destination(Some(dir));
    assert_eq!(resolved, dir.join("MAX.msi"));

    let file_dest = temp.path().join("custom.msi");
    let resolved_file = resolve_destination(Some(&file_dest));
    assert_eq!(resolved_file, file_dest);

    let default_dest = resolve_destination(None);
    assert_eq!(default_dest, PathBuf::from("MAX.msi"));
}
