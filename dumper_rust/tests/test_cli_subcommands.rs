use std::fs;
use std::process::Command;

#[test]
fn test_cli_help_lists_all_subcommands() {
    let output = Command::new(env!("CARGO_BIN_EXE_dumper_rust"))
        .arg("--help")
        .output()
        .expect("Failed to execute dumper_rust --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("update"), "Help must list 'update' subcommand");
    assert!(stdout.contains("unpack"), "Help must list 'unpack' subcommand");
    assert!(stdout.contains("dump"), "Help must list 'dump' subcommand");
}

#[test]
fn test_cli_no_args_displays_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_dumper_rust"))
        .output()
        .expect("Failed to execute dumper_rust with no arguments");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("update"));
    assert!(stdout.contains("unpack"));
    assert!(stdout.contains("dump"));
}

#[test]
fn test_cli_dump_missing_target_prints_actionable_error() {
    let temp_root = std::env::temp_dir().join(format!(
        "mah_test_cli_missing_dump_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir_all(&temp_root).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dumper_rust"))
        .arg("dump")
        .current_dir(&temp_root)
        .output()
        .expect("Failed to execute dumper_rust dump");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("CM_FP_Unspecified.core.dll") && stderr.contains("dumper_rust unpack"),
        "Error message must guide user to run 'dumper_rust unpack': {}",
        stderr
    );

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_cli_unpack_missing_msi_prints_actionable_error() {
    let temp_root = std::env::temp_dir().join(format!(
        "mah_test_cli_missing_unpack_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir_all(&temp_root).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dumper_rust"))
        .arg("unpack")
        .current_dir(&temp_root)
        .output()
        .expect("Failed to execute dumper_rust unpack");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("dumper_rust update"),
        "Error message must guide user to run 'dumper_rust update': {}",
        stderr
    );

    let _ = fs::remove_dir_all(&temp_root);
}
