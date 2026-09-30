use clap::Parser;
use dumper_rust::unpacker::{
    run_unpack, safe_join, unpack, unpack_package, FileFilter, UnpackArgs, UnpackError,
};
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(1);

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "mah_test_{}_{}_{}",
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

/// Helper to construct synthetic MSI binary bytes containing a cabinet stream.
fn create_synthetic_msi_bytes(files: &[(&str, &[u8])], cab_stream_name: &str) -> Vec<u8> {
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
        let mut stream = package.write_stream(cab_stream_name).expect("write_stream");
        stream.write_all(&cab_bytes).expect("write stream data");
    }
    package.into_inner().expect("into_inner").into_inner()
}

#[derive(Parser, Debug)]
struct TestCli {
    #[command(flatten)]
    unpack: UnpackArgs,
}

#[test]
fn test_missing_msi_returns_actionable_error_and_exit_code_1() {
    let missing_path = PathBuf::from("completely_nonexistent_MAX.msi");
    let args = UnpackArgs {
        msi_path: missing_path.clone(),
        out_dir: PathBuf::from("."),
        all: false,
        filter: None,
        quiet: true,
    };

    let result = unpack(&args);
    assert!(result.is_err(), "Unpack must fail if MSI is missing");

    let err = result.unwrap_err();
    assert_eq!(err.exit_code(), 1, "Exit code must be 1 on missing MSI");

    let err_msg = err.to_string();
    assert!(
        err_msg.contains("not found"),
        "Error message must indicate file not found, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("dumper_rust update"),
        "Error message must guide user to 'dumper_rust update', got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("dumper_rust unpack"),
        "Error message must suggest unpack syntax, got: {}",
        err_msg
    );
}

#[test]
fn test_corrupted_msi_file_error() {
    let temp = TempDirGuard::new("corrupt_msi");
    let bad_msi = temp.path().join("bad.msi");
    fs::write(&bad_msi, b"This is not a CFB OLE2 file").unwrap();

    let args = UnpackArgs {
        msi_path: bad_msi.clone(),
        out_dir: temp.path().join("out"),
        all: false,
        filter: None,
        quiet: true,
    };

    let result = unpack(&args);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.exit_code(), 1);
    assert!(matches!(err, UnpackError::MsiOpenError { .. }));
}

#[test]
fn test_msi_without_cabinet_stream_error() {
    let temp = TempDirGuard::new("no_cab_msi");
    let msi_path = temp.path().join("empty_package.msi");

    let msi_cursor = Cursor::new(Vec::new());
    let mut package =
        msi::Package::create(msi::PackageType::Installer, msi_cursor).expect("create msi");
    {
        let mut stream = package.write_stream("DummyStream").unwrap();
        stream.write_all(b"not a cabinet").unwrap();
    }
    let msi_bytes = package.into_inner().unwrap().into_inner();
    fs::write(&msi_path, &msi_bytes).unwrap();

    let args = UnpackArgs {
        msi_path,
        out_dir: temp.path().join("out"),
        all: false,
        filter: None,
        quiet: true,
    };

    let result = unpack(&args);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.exit_code(), 1);
    assert!(matches!(err, UnpackError::CabinetNotFound { .. }));
}

#[test]
fn test_synthetic_msi_default_extraction() {
    let temp = TempDirGuard::new("synth_default");
    let msi_path = temp.path().join("test.msi");
    let out_dir = temp.path().join("out");

    let files = [
        ("CM_FP_Unspecified.core.dll", &b"MZ core dll payload 12345"[..]),
        ("CM_FP_Unspecified.config.dll", &b"MZ config dll payload"[..]),
        (
            "CM_FP_Messenger.max_service.config.dll",
            &b"MZ service config payload"[..],
        ),
        ("CM_FP_Messenger.max.exe", &b"MZ executable payload"[..]),
        ("assets/icon.png", &b"\x89PNG header bytes"[..]),
        (
            "CM_FP_Unspecified.api_ms_win_core_file.dll",
            &b"MZ api dll"[..],
        ),
    ];

    let msi_bytes = create_synthetic_msi_bytes(&files, "media1.cab");
    fs::write(&msi_path, &msi_bytes).unwrap();

    let args = UnpackArgs {
        msi_path,
        out_dir: out_dir.clone(),
        all: false,
        filter: None,
        quiet: true,
    };

    let res = unpack(&args).expect("unpack should succeed");
    assert_eq!(res.cabinet_name, "media1.cab");
    assert_eq!(res.extracted.len(), 2, "Only the 2 target DLLs must be extracted by default");

    let mut names: Vec<String> = res.extracted.iter().map(|f| f.name.clone()).collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "CM_FP_Unspecified.config.dll".to_string(),
            "CM_FP_Unspecified.core.dll".to_string(),
        ]
    );

    // Verify content on disk
    let core_content = fs::read(out_dir.join("CM_FP_Unspecified.core.dll")).unwrap();
    assert_eq!(core_content, b"MZ core dll payload 12345");

    let config_content = fs::read(out_dir.join("CM_FP_Unspecified.config.dll")).unwrap();
    assert_eq!(config_content, b"MZ config dll payload");

    // Verify non-matching files and extra config DLLs were NOT extracted
    assert!(!out_dir.join("CM_FP_Messenger.max_service.config.dll").exists());
    assert!(!out_dir.join("CM_FP_Messenger.max.exe").exists());
    assert!(!out_dir.join("assets/icon.png").exists());
    assert!(!out_dir.join("CM_FP_Unspecified.api_ms_win_core_file.dll").exists());
}

#[test]
fn test_synthetic_msi_extract_all() {
    let temp = TempDirGuard::new("synth_all");
    let msi_path = temp.path().join("test.msi");
    let out_dir = temp.path().join("out");

    let files = [
        ("file1.dll", &b"data1"[..]),
        ("file2.txt", &b"data2"[..]),
        ("image.png", &b"data3"[..]),
    ];

    let msi_bytes = create_synthetic_msi_bytes(&files, "media1.cab");
    fs::write(&msi_path, &msi_bytes).unwrap();

    let args = UnpackArgs {
        msi_path,
        out_dir: out_dir.clone(),
        all: true,
        filter: None,
        quiet: true,
    };

    let res = unpack(&args).expect("unpack --all should succeed");
    assert_eq!(res.extracted.len(), 3);
    assert!(out_dir.join("file1.dll").is_file());
    assert!(out_dir.join("file2.txt").is_file());
    assert!(out_dir.join("image.png").is_file());
}

#[test]
fn test_synthetic_msi_custom_glob_filters() {
    let temp = TempDirGuard::new("synth_filters");
    let msi_path = temp.path().join("test.msi");
    let out_dir = temp.path().join("out");

    let files = [
        ("CM_FP_Unspecified.core.dll", &b"core"[..]),
        ("CM_FP_Unspecified.config.dll", &b"config"[..]),
        ("doc_readme.txt", &b"readme"[..]),
        ("test_report.txt", &b"report"[..]),
        ("logo.png", &b"png"[..]),
    ];

    let msi_bytes = create_synthetic_msi_bytes(&files, "media1.cab");
    fs::write(&msi_path, &msi_bytes).unwrap();

    // 1. Filter: *.txt
    let args_txt = UnpackArgs {
        msi_path: msi_path.clone(),
        out_dir: out_dir.join("txt"),
        all: false,
        filter: Some("*.txt".to_string()),
        quiet: true,
    };
    let res_txt = unpack(&args_txt).unwrap();
    assert_eq!(res_txt.extracted.len(), 2);
    assert!(out_dir.join("txt").join("doc_readme.txt").is_file());
    assert!(out_dir.join("txt").join("test_report.txt").is_file());

    // 2. Filter: multiple comma-separated patterns
    let args_multi = UnpackArgs {
        msi_path: msi_path.clone(),
        out_dir: out_dir.join("multi"),
        all: false,
        filter: Some("*.png, *core*".to_string()),
        quiet: true,
    };
    let res_multi = unpack(&args_multi).unwrap();
    assert_eq!(res_multi.extracted.len(), 2);
    assert!(out_dir.join("multi").join("logo.png").is_file());
    assert!(out_dir.join("multi").join("CM_FP_Unspecified.core.dll").is_file());

    // 3. Filter: prefix wildcard
    let args_prefix = UnpackArgs {
        msi_path,
        out_dir: out_dir.join("prefix"),
        all: false,
        filter: Some("CM_FP_*.config.dll".to_string()),
        quiet: true,
    };
    let res_prefix = unpack(&args_prefix).unwrap();
    assert_eq!(res_prefix.extracted.len(), 1);
    assert_eq!(res_prefix.extracted[0].name, "CM_FP_Unspecified.config.dll");
}

#[test]
fn test_synthetic_msi_case_insensitive_filtering() {
    let temp = TempDirGuard::new("synth_case");
    let msi_path = temp.path().join("test.msi");
    let out_dir = temp.path().join("out");

    let files = [
        ("cm_fp_unspecified.core.dll", &b"lower core"[..]),
        ("CM_FP_UNSPECIFIED.CONFIG.DLL", &b"upper config"[..]),
    ];

    let msi_bytes = create_synthetic_msi_bytes(&files, "media1.cab");
    fs::write(&msi_path, &msi_bytes).unwrap();

    let args = UnpackArgs {
        msi_path,
        out_dir: out_dir.clone(),
        all: false,
        filter: None,
        quiet: true,
    };

    let res = unpack(&args).unwrap();
    assert_eq!(res.extracted.len(), 2);
    assert!(out_dir.join("cm_fp_unspecified.core.dll").is_file());
    assert!(out_dir.join("CM_FP_UNSPECIFIED.CONFIG.DLL").is_file());
}

#[test]
fn test_synthetic_msi_overwrites_existing_files() {
    let temp = TempDirGuard::new("synth_overwrite");
    let msi_path = temp.path().join("test.msi");
    let out_dir = temp.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let target_file = out_dir.join("CM_FP_Unspecified.core.dll");
    fs::write(&target_file, b"OLD PRE-EXISTING DATA THAT SHOULD BE OVERWRITTEN").unwrap();

    let files = [("CM_FP_Unspecified.core.dll", &b"FRESH NEW PAYLOAD"[..])];
    let msi_bytes = create_synthetic_msi_bytes(&files, "media1.cab");
    fs::write(&msi_path, &msi_bytes).unwrap();

    let args = UnpackArgs {
        msi_path,
        out_dir: out_dir.clone(),
        all: false,
        filter: None,
        quiet: true,
    };

    let res = unpack(&args).expect("unpack should overwrite existing file");
    assert_eq!(res.extracted.len(), 1);

    let updated_content = fs::read(&target_file).unwrap();
    assert_eq!(
        updated_content, b"FRESH NEW PAYLOAD",
        "Destination file must be overwritten with fresh cabinet content"
    );
}

#[test]
fn test_safe_join_prevents_traversal() {
    let base = Path::new("test_base");

    // Relative path with ..
    let joined = safe_join(base, "../../secret.txt");
    assert_eq!(joined, base.join("secret.txt"));

    // Windows backslash traversal
    let joined2 = safe_join(base, r"..\..\foo\bar.txt");
    assert_eq!(joined2, base.join("foo").join("bar.txt"));

    // Absolute-looking path
    let joined3 = safe_join(base, "/etc/config.dll");
    assert_eq!(joined3, base.join("etc").join("config.dll"));

    // Normal path
    let normal = safe_join(base, "CM_FP_Unspecified.core.dll");
    assert_eq!(normal, base.join("CM_FP_Unspecified.core.dll"));
}

#[test]
fn test_unpack_package_in_memory() {
    let files = [
        ("CM_FP_Unspecified.core.dll", &b"in-memory core"[..]),
        ("CM_FP_Unspecified.config.dll", &b"in-memory config"[..]),
    ];
    let msi_bytes = create_synthetic_msi_bytes(&files, "media1.cab");
    let cursor = Cursor::new(msi_bytes);
    let mut package = msi::Package::open(cursor).unwrap();

    let temp = TempDirGuard::new("in_memory_unpack");
    let filter = FileFilter::Default;
    let (cab_name, extracted) = unpack_package(&mut package, temp.path(), &filter).unwrap();

    assert_eq!(cab_name, "media1.cab");
    assert_eq!(extracted.len(), 2);
    assert_eq!(
        fs::read(temp.path().join("CM_FP_Unspecified.core.dll")).unwrap(),
        b"in-memory core"
    );
}

#[test]
fn test_cli_argument_parsing() {
    // 1. Defaults
    let cli = TestCli::parse_from(["app"]);
    assert_eq!(cli.unpack.msi_path, PathBuf::from("MAX.msi"));
    assert_eq!(cli.unpack.out_dir, PathBuf::from("."));
    assert!(!cli.unpack.all);
    assert!(cli.unpack.filter.is_none());
    assert!(!cli.unpack.quiet);

    // 2. Custom values
    let cli = TestCli::parse_from([
        "app",
        "custom_archive.msi",
        "-o",
        "output_dir",
        "--all",
        "-q",
    ]);
    assert_eq!(cli.unpack.msi_path, PathBuf::from("custom_archive.msi"));
    assert_eq!(cli.unpack.out_dir, PathBuf::from("output_dir"));
    assert!(cli.unpack.all);
    assert!(cli.unpack.quiet);

    // 3. Custom filter
    let cli = TestCli::parse_from(["app", "--filter", "*.dll", "--out-dir", "dest"]);
    assert_eq!(cli.unpack.filter, Some("*.dll".to_string()));
    assert_eq!(cli.unpack.out_dir, PathBuf::from("dest"));
}

#[test]
fn test_run_unpack_quiet_and_verbose() {
    let temp = TempDirGuard::new("run_unpack");
    let msi_path = temp.path().join("test.msi");
    let out_dir = temp.path().join("out");

    let files = [("CM_FP_Unspecified.core.dll", &b"payload"[..])];
    let msi_bytes = create_synthetic_msi_bytes(&files, "media1.cab");
    fs::write(&msi_path, &msi_bytes).unwrap();

    // Quiet mode
    let args_quiet = UnpackArgs {
        msi_path: msi_path.clone(),
        out_dir: out_dir.clone(),
        all: false,
        filter: None,
        quiet: true,
    };
    let res_quiet = run_unpack(&args_quiet).unwrap();
    assert_eq!(res_quiet.extracted.len(), 1);

    // Non-quiet mode
    let args_verbose = UnpackArgs {
        msi_path,
        out_dir,
        all: false,
        filter: None,
        quiet: false,
    };
    let res_verbose = run_unpack(&args_verbose).unwrap();
    assert_eq!(res_verbose.extracted.len(), 1);
}

#[test]
fn test_real_max_msi_if_present() {
    let real_msi = Path::new(r"D:\PycharmProjects\mah\MAX.msi");
    if !real_msi.is_file() {
        println!("MAX.msi not found at D:\\PycharmProjects\\mah\\MAX.msi, skipping real test");
        return;
    }

    let temp = TempDirGuard::new("real_max_msi");
    let out_dir = temp.path().join("unpacked");

    let args = UnpackArgs {
        msi_path: real_msi.to_path_buf(),
        out_dir: out_dir.clone(),
        all: false,
        filter: None,
        quiet: false,
    };

    let t0 = Instant::now();
    let res = unpack(&args).expect("unpack on real MAX.msi must succeed");
    let duration = t0.elapsed();

    println!(
        "Real MAX.msi default selective extraction took: {:.2?}",
        duration
    );
    assert_eq!(res.cabinet_name, "media1.cab");
    assert_eq!(
        res.extracted.len(),
        2,
        "Expected 2 target DLLs (core.dll, config.dll)"
    );

    let core_dll = out_dir.join("CM_FP_Unspecified.core.dll");
    let config_dll = out_dir.join("CM_FP_Unspecified.config.dll");
    let service_config_dll = out_dir.join("CM_FP_Messenger.max_service.config.dll");

    assert!(core_dll.is_file(), "core.dll must exist");
    assert!(config_dll.is_file(), "config.dll must exist");
    assert!(!service_config_dll.exists(), "service config.dll must not be extracted by default");

    let core_meta = fs::metadata(&core_dll).unwrap();
    assert!(
        core_meta.len() > 30_000_000,
        "CM_FP_Unspecified.core.dll must be > 30MB, got {}",
        core_meta.len()
    );

    let config_meta = fs::metadata(&config_dll).unwrap();
    assert!(
        config_meta.len() > 800_000,
        "CM_FP_Unspecified.config.dll must be > 800KB, got {}",
        config_meta.len()
    );

    // Verify overwrite works seamlessly on real files
    let res_overwrite = unpack(&args).expect("unpack overwrite must succeed");
    assert_eq!(res_overwrite.extracted.len(), 2);
}
