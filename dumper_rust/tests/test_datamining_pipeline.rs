use dumper_rust::datamining::{
    discover_config_dll, emit_config_json, emit_metadata_json, extract_config_from_file,
    DataminingCoordinator, MetadataSnapshot,
};
use dumper_rust::dumper::{AppVersion, DumpResult, Dumper, DumperOptions};
use dumper_rust::pe::PeImage;
use dumper_rust::rtti::RttiEngine;
use dumper_rust::scanner::ProtocolScanner;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

mod common;
use common::resolve_env_path;

fn resolve_core_dll() -> Option<PathBuf> {
    if let Some(path) = resolve_env_path("CORE_DLL_PATH") {
        if path.exists() {
            return Some(path);
        }
    }
    let direct = PathBuf::from(r"D:\PycharmProjects\mah\CM_FP_Unspecified.core.dll");
    if direct.exists() {
        return Some(direct);
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(parent) = manifest_dir.parent() {
        let candidate = parent.join("CM_FP_Unspecified.core.dll");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn resolve_config_dll() -> Option<PathBuf> {
    if let Some(path) = resolve_env_path("CONFIG_DLL_PATH") {
        if path.exists() {
            return Some(path);
        }
    }
    let direct = PathBuf::from(r"D:\PycharmProjects\mah\CM_FP_Unspecified.config.dll");
    if direct.exists() {
        return Some(direct);
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(parent) = manifest_dir.parent() {
        let candidate = parent.join("CM_FP_Unspecified.config.dll");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn contains_key_recursive(value: &Value, target: &str) -> bool {
    match value {
        Value::Object(map) => {
            map.contains_key(target)
                || map.values().any(|v| contains_key_recursive(v, target))
        }
        Value::Array(arr) => arr.iter().any(|v| contains_key_recursive(v, target)),
        _ => false,
    }
}

fn execute_pipeline(
    core_path: &Path,
    config_path: Option<&Path>,
    output_dir: &Path,
    with_rva: bool,
) -> (PathBuf, PathBuf, PathBuf, DumpResult, MetadataSnapshot) {
    fs::create_dir_all(output_dir).expect("Failed to create output dir");
    let packets_output = output_dir.join("packets_rust.json");
    let metadata_output = output_dir.join("metadata.json");
    let config_output = output_dir.join("config.json");

    // 1. Config discovery & extraction
    let discovered_cfg = discover_config_dll(core_path, config_path);
    let mut config_val = None;
    if let Some(ref cfg_file) = discovered_cfg {
        let val = extract_config_from_file(cfg_file).expect("Failed to extract config");
        emit_config_json(&val, &config_output).expect("Failed to emit config.json");
        config_val = Some(val);
    }

    // 2. Parse PE & index RTTI & ProtocolScanner
    let bytes = fs::read(core_path).expect("Failed to read core DLL");
    let pe = PeImage::parse(&bytes).expect("Failed to parse PE image");
    let rtti = RttiEngine::build(&pe).expect("Failed to build RTTI engine");
    let scanner = ProtocolScanner::scan(&pe, &rtti).expect("Failed to scan protocol entities");

    // 3. Dumper
    let options = DumperOptions {
        version: AppVersion {
            version: String::new(),
            build: 0,
        },
        config: config_val.clone(),
    };
    let dump_res = Dumper::dump_with_diagnostics(&pe, &rtti, &scanner, &options)
        .expect("Failed to run dumper");

    let json_bytes =
        serde_json::to_vec_pretty(&dump_res.dump).expect("Failed to serialize packets_rust.json");
    fs::write(&packets_output, &json_bytes).expect("Failed to write packets_rust.json");

    // 4. Coordinator & metadata.json
    let snapshot = DataminingCoordinator::build(
        &pe,
        &rtti,
        &scanner,
        &dump_res.dump,
        config_val.as_ref(),
        with_rva,
    )
    .expect("Failed to build metadata snapshot");
    emit_metadata_json(&snapshot, &metadata_output).expect("Failed to emit metadata.json");

    (
        packets_output,
        metadata_output,
        config_output,
        dump_res.dump,
        snapshot,
    )
}

#[test]
fn test_datamining_pipeline_end_to_end() {
    let core_dll = match resolve_core_dll() {
        Some(p) => p,
        None => {
            eprintln!("Skipping: core.dll not found");
            return;
        }
    };
    let config_dll = match resolve_config_dll() {
        Some(p) => p,
        None => {
            eprintln!("Skipping: config.dll not found");
            return;
        }
    };

    let temp_root = std::env::temp_dir().join(format!(
        "mah_test_pipeline_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));

    let run1_dir = temp_root.join("run1");
    let run2_dir = temp_root.join("run2");
    let rva_dir = temp_root.join("with_rva");

    // Measure execution time
    let start_time = Instant::now();
    let (p1, m1, c1, dump1, snap1) =
        execute_pipeline(&core_dll, Some(&config_dll), &run1_dir, false);
    let elapsed = start_time.elapsed();
    println!("Pipeline run 1 completed in {:.3?}", elapsed);

    // 1. All 3 files generated
    assert!(p1.is_file(), "packets_rust.json must be generated");
    assert!(m1.is_file(), "metadata.json must be generated");
    assert!(c1.is_file(), "config.json must be generated");

    // 2. Validate metadata.json contents
    let meta_raw = fs::read_to_string(&m1).expect("Failed to read metadata.json");
    let meta_val: Value = serde_json::from_str(&meta_raw).expect("metadata.json must be valid JSON");

    assert!(!snap1.features.is_empty(), "features must not be empty");
    assert!(!snap1.enums.is_empty(), "enums must not be empty");
    assert!(
        !snap1.discriminators.is_empty(),
        "discriminators must not be empty"
    );
    assert!(
        !snap1.source_files.is_empty(),
        "source_files must not be empty"
    );
    assert!(
        !snap1.log_templates.is_empty(),
        "log_templates must not be empty"
    );
    assert!(
        !snap1.packets_catalog.is_empty(),
        "packets_catalog must not be empty"
    );

    // 3. Summary counts match array/map lengths
    assert_eq!(
        snap1.summary.total_packets,
        snap1.packets_catalog.len(),
        "summary.total_packets must match packets_catalog length"
    );
    assert_eq!(
        snap1.summary.total_events,
        dump1.events.len(),
        "summary.total_events must match events length"
    );
    assert_eq!(
        snap1.summary.total_models,
        dump1.models.len(),
        "summary.total_models must match models length"
    );
    assert_eq!(
        snap1.summary.total_features,
        snap1.features.len(),
        "summary.total_features must match features length"
    );
    assert_eq!(
        snap1.summary.total_source_files,
        snap1.source_files.len(),
        "summary.total_source_files must match source_files length"
    );
    assert_eq!(
        snap1.summary.total_log_templates,
        snap1.log_templates.len(),
        "summary.total_log_templates must match log_templates length"
    );

    // 4. Validate packets_rust.json enhancements
    assert!(
        dump1.options.config.is_some(),
        "packets_rust.json options.config must be populated"
    );
    let cfg_val: Value =
        serde_json::from_str(&fs::read_to_string(&c1).unwrap()).expect("Valid config.json");
    assert_eq!(
        dump1.options.config.as_ref().unwrap(),
        &cfg_val,
        "options.config must match config.json"
    );
    assert!(!dump1.enums.is_empty(), "dump.enums must be populated");
    assert_eq!(dump1.enums, snap1.enums, "dump.enums must match metadata.json enums");
    assert!(
        !dump1.discriminators.is_empty(),
        "dump.discriminators must be populated"
    );
    assert_eq!(
        dump1.discriminators, snap1.discriminators,
        "dump.discriminators must match metadata.json discriminators"
    );
    assert!(
        dump1.models.iter().any(|m| m.offset.is_some()),
        "dump.models must retain structural offset values"
    );

    // 5. Invariant: without --with-rva, neither "rva" nor "offset" appears as a key anywhere in metadata.json
    assert!(
        !contains_key_recursive(&meta_val, "rva"),
        "metadata.json must not contain any 'rva' key without --with-rva"
    );
    assert!(
        !contains_key_recursive(&meta_val, "offset"),
        "metadata.json must not contain any 'offset' key without --with-rva"
    );

    // 6. With with_rva = true, "rva" key is present on packets_catalog, but "offset" is still absent
    let (_pr, mr, _cr, _dumpr, _snapr) =
        execute_pipeline(&core_dll, Some(&config_dll), &rva_dir, true);
    let meta_rva_val: Value =
        serde_json::from_str(&fs::read_to_string(&mr).unwrap()).expect("Valid with_rva JSON");
    assert!(
        contains_key_recursive(&meta_rva_val, "rva"),
        "metadata.json must contain 'rva' key when with_rva is true"
    );
    assert!(
        !contains_key_recursive(&meta_rva_val, "offset"),
        "metadata.json must not contain 'offset' key even when with_rva is true"
    );

    // 7. Determinism: running extraction twice produces byte-for-byte identical output
    let (p2, m2, c2, _dump2, _snap2) =
        execute_pipeline(&core_dll, Some(&config_dll), &run2_dir, false);
    let meta1_bytes = fs::read(&m1).unwrap();
    let meta2_bytes = fs::read(&m2).unwrap();
    assert_eq!(
        meta1_bytes, meta2_bytes,
        "metadata.json must be byte-for-byte identical across repeated runs"
    );

    let packets1_bytes = fs::read(&p1).unwrap();
    let packets2_bytes = fs::read(&p2).unwrap();
    assert_eq!(
        packets1_bytes, packets2_bytes,
        "packets_rust.json must be byte-for-byte identical across repeated runs"
    );

    let config1_bytes = fs::read(&c1).unwrap();
    let config2_bytes = fs::read(&c2).unwrap();
    assert_eq!(
        config1_bytes, config2_bytes,
        "config.json must be byte-for-byte identical across repeated runs"
    );

    // 8. Execution time SLA assertion (sub-2-seconds in release mode, reasonable bounds in debug mode)
    if !cfg!(debug_assertions) {
        assert!(
            elapsed < Duration::from_secs(2),
            "Release execution time must be strictly sub-2-seconds: {:?}",
            elapsed
        );
    } else {
        assert!(
            elapsed < Duration::from_secs(15),
            "Debug execution time must finish within reasonable bounds: {:?}",
            elapsed
        );
    }

    // Clean up temporary test files
    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_cli_default_invocation_produces_all_three_artifacts() {
    let core_dll = match resolve_core_dll() {
        Some(p) => p,
        None => {
            eprintln!("Skipping: core.dll not found");
            return;
        }
    };
    let config_dll = match resolve_config_dll() {
        Some(p) => p,
        None => {
            eprintln!("Skipping: config.dll not found");
            return;
        }
    };

    let temp_root = std::env::temp_dir().join(format!(
        "mah_test_cli_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir_all(&temp_root).unwrap();

    let out_packets = temp_root.join("packets_rust.json");
    let out_metadata = temp_root.join("metadata.json");
    let out_config = temp_root.join("config.json");

    let status = Command::new(env!("CARGO_BIN_EXE_dumper_rust"))
        .arg(&core_dll)
        .arg("--config")
        .arg(&config_dll)
        .arg("-o")
        .arg(&out_packets)
        .arg("--metadata-output")
        .arg(&out_metadata)
        .arg("--config-output")
        .arg(&out_config)
        .status()
        .expect("Failed to execute dumper_rust CLI");

    assert!(status.success(), "CLI exit status must be success");
    assert!(out_packets.is_file(), "CLI must generate packets_rust.json");
    assert!(out_metadata.is_file(), "CLI must generate metadata.json");
    assert!(out_config.is_file(), "CLI must generate config.json");

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_cli_positional_target_only_generates_default_artifacts() {
    let core_dll = match resolve_core_dll() {
        Some(p) => p,
        None => return,
    };

    let temp_root = std::env::temp_dir().join(format!(
        "mah_test_cli_default_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir_all(&temp_root).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_dumper_rust"))
        .arg(&core_dll)
        .current_dir(&temp_root)
        .status()
        .expect("Failed to execute dumper_rust CLI");

    assert!(status.success(), "CLI exit status must be success");
    assert!(
        temp_root.join("packets_rust.json").is_file(),
        "Default CLI run must generate packets_rust.json"
    );
    assert!(
        temp_root.join("metadata.json").is_file(),
        "Default CLI run must generate metadata.json"
    );
    assert!(
        temp_root.join("config.json").is_file(),
        "Default CLI run must generate config.json"
    );

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_cli_no_metadata_flag_suppresses_metadata_json() {
    let core_dll = match resolve_core_dll() {
        Some(p) => p,
        None => return,
    };

    let temp_root = std::env::temp_dir().join(format!(
        "mah_test_cli_no_meta_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir_all(&temp_root).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_dumper_rust"))
        .arg(&core_dll)
        .arg("--no-metadata")
        .current_dir(&temp_root)
        .status()
        .expect("Failed to execute dumper_rust CLI");

    assert!(status.success(), "CLI exit status must be success");
    assert!(temp_root.join("packets_rust.json").is_file());
    assert!(!temp_root.join("metadata.json").exists());
    assert!(temp_root.join("config.json").is_file());

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_compact_output_honors_with_rva_toggle() {
    let core_dll = match resolve_core_dll() {
        Some(p) => p,
        None => return,
    };

    let temp_root = std::env::temp_dir().join(format!(
        "mah_test_compact_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir_all(&temp_root).unwrap();

    let compact_no_rva = temp_root.join("compact_no_rva.txt");
    let compact_with_rva = temp_root.join("compact_with_rva.txt");

    // 1. Without --with-rva
    let status1 = Command::new(env!("CARGO_BIN_EXE_dumper_rust"))
        .arg(&core_dll)
        .arg("-c")
        .arg(&compact_no_rva)
        .arg("--no-metadata")
        .current_dir(&temp_root)
        .status()
        .expect("Failed to execute CLI");
    assert!(status1.success());
    let txt_no_rva = fs::read_to_string(&compact_no_rva).unwrap();
    assert!(
        !txt_no_rva.contains("rva="),
        "Compact dump without --with-rva must not contain 'rva='"
    );

    // 2. With --with-rva
    let status2 = Command::new(env!("CARGO_BIN_EXE_dumper_rust"))
        .arg(&core_dll)
        .arg("-c")
        .arg(&compact_with_rva)
        .arg("--with-rva")
        .arg("--no-metadata")
        .current_dir(&temp_root)
        .status()
        .expect("Failed to execute CLI");
    assert!(status2.success());
    let txt_with_rva = fs::read_to_string(&compact_with_rva).unwrap();
    assert!(
        txt_with_rva.contains("rva="),
        "Compact dump with --with-rva must contain 'rva='"
    );

    let _ = fs::remove_dir_all(&temp_root);
}
