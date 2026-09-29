use dumper_rust::datamining::config::{
    derive_config_path, discover_config_dll, emit_config_json, extract_config_candidate,
    extract_config_from_file, format_config_json,
};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

mod common;
use common::resolve_env_path;

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

const EXPECTED_CONFIG_KEYS: &[&str] = &[
    "allow_message_text_with_files",
    "api_version_uint",
    "app_folder_name",
    "app_settings_version",
    "auto_update_enabled",
    "base_url",
    "booking_bot_url",
    "bot_start_param",
    "chat_inactive_interval",
    "check_connection_timeout",
    "check_for_updates_interval",
    "check_packets_interval",
    "chunk_size",
    "client_friendly_name",
    "client_inactive_interval",
    "code_confirmation_chat_name",
    "company_friendly_name",
    "csn_stream_ttl_sec",
    "dc_stream_ttl_sec",
    "default_avatar_format",
    "default_miniapp_height",
    "default_miniapp_width",
    "faq_url",
    "how_to_register_url",
    "init_updater_interval",
    "internal_url_scheme",
    "is_local_chat_list_enabled",
    "is_local_config_enabled",
    "is_local_contact_list_enabled",
    "is_local_folders_enabled",
    "is_polls_enabled",
    "is_qrcode_login_first",
    "is_unreleased_languages_enabled",
    "locale_replaces_with_ru",
    "local_server_pipe_name",
    "logger_severity",
    "logs_sending_max_files_count_calls",
    "logs_sending_max_files_count_client",
    "min_miniapp_height",
    "min_miniapp_width",
    "mouse_press_and_hold_interval_ms",
    "name_max_length",
    "need_mask_logs",
    "override_polls_version",
    "personal_recommendations_rules_url",
    "ping_interval",
    "prevalidate_public_link_on_client",
    "privacy_policy_url",
    "rooms_auto_update_enabled",
    "rooms_friendly_name",
    "rooms_init_updater_interval",
    "rooms_update_appcast_filename",
    "rooms_update_path",
    "rooms_update_url",
    "screen_type",
    "self_recovery_url",
    "send_error_logs_to_crash_server",
    "short_link_prefix_url",
    "single_instance_id",
    "sn_stream_ttl_sec",
    "ssl_port",
    "ssl_url2",
    "start_app_param",
    "support_bot_url",
    "update_appcast_filename",
    "update_fallback_url",
    "update_fallback_url_self_service_mac",
    "update_fallback_url_self_service_win",
    "update_path",
    "update_url",
    "use_encrypted_connection",
    "user_agent",
    "user_agreement_url",
    "web_app_user_gesture_timeout",
];

#[test]
fn test_config_extraction_from_real_dll() {
    let dll_path = match resolve_config_dll() {
        Some(path) => path,
        None => {
            eprintln!("Skipping: CONFIG_DLL_PATH not set or file does not exist");
            return;
        }
    };

    assert!(dll_path.exists(), "Target config DLL must exist: {:?}", dll_path);
    let bytes = fs::read(&dll_path).expect("Failed to read config DLL");

    // 1. Test balanced brace scanner candidate extraction
    let candidate = extract_config_candidate(&bytes, 20).expect("Must extract config candidate");
    assert_eq!(candidate.key_count, 74, "Config must contain exactly 74 keys");
    assert_eq!(
        candidate.offset, 0x8a2c4,
        "JSON opening brace in CM_FP_Unspecified.config.dll must match known offset 0x8a2c4 (+4 from Qt resource header 0x8a2c0)"
    );

    // 2. Test file-based helper
    let config_val = extract_config_from_file(&dll_path).expect("Must extract config from file");
    let map = config_val.as_object().expect("Config must be a JSON object");
    assert_eq!(map.len(), 74, "Object must have 74 keys");

    // 3. Verify all 74 keys match expected keys from scripts/config_extractor.py
    let actual_keys: HashSet<&str> = map.keys().map(|k| k.as_str()).collect();
    let expected_keys: HashSet<&str> = EXPECTED_CONFIG_KEYS.iter().copied().collect();

    assert_eq!(
        actual_keys.len(),
        74,
        "Actual unique key count must be 74"
    );
    assert_eq!(
        actual_keys, expected_keys,
        "Extracted keys must identically match scripts/config_extractor.py key set"
    );

    // 4. Verify canonical values for core gateway and configuration parameters
    assert_eq!(map["api_version_uint"], serde_json::json!(11));
    assert_eq!(map["base_url"], serde_json::json!("max.ru"));
    assert_eq!(map["app_folder_name"], serde_json::json!("ONEME"));
    assert_eq!(map["client_friendly_name"], serde_json::json!("MAX"));
    assert_eq!(map["chunk_size"], serde_json::json!(10485760));
    assert_eq!(map["single_instance_id"], serde_json::json!("oneme_instance"));
    assert_eq!(map["is_local_chat_list_enabled"], serde_json::json!(true));
    assert_eq!(
        map["locale_replaces_with_ru"],
        serde_json::json!(["az", "hy", "be", "kk", "ky", "mo", "tg", "uz", "tk"])
    );

    // 5. Test standalone formatting and emission
    let formatted = format_config_json(&config_val).expect("Must format config.json");
    assert!(formatted.ends_with('\n'), "Formatted output must end with newline");
    assert!(
        formatted.contains("  \"api_version_uint\": 11"),
        "Formatted output must use 2-space indentation"
    );

    let temp_dir = std::env::temp_dir().join("mah_test_config_emit");
    let output_file = temp_dir.join("config.json");
    emit_config_json(&config_val, &output_file).expect("Must emit config.json");

    let read_back_str = fs::read_to_string(&output_file).expect("Must read back emitted file");
    assert_eq!(read_back_str, formatted);

    let parsed_back: serde_json::Value =
        serde_json::from_str(&read_back_str).expect("Emitted file must parse as valid JSON");
    assert_eq!(parsed_back, config_val);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_config_dll_auto_discovery_from_core_dll() {
    let core_candidate = PathBuf::from(r"D:\PycharmProjects\mah\CM_FP_Unspecified.core.dll");
    if !core_candidate.exists() {
        eprintln!("Skipping: core DLL not found for discovery test");
        return;
    }

    // 1. Auto-discovery replacing .core.dll with .config.dll
    let discovered = discover_config_dll(&core_candidate, None);
    assert!(discovered.is_some(), "Must auto-discover config DLL next to core DLL");
    let discovered_path = discovered.unwrap();
    assert!(discovered_path.is_file(), "Discovered path must exist as a file");
    assert_eq!(
        discovered_path.file_name().unwrap(),
        "CM_FP_Unspecified.config.dll"
    );

    // 2. Explicit path override
    let override_path = PathBuf::from("custom/explicit.config.dll");
    let explicit_discovered = discover_config_dll(&core_candidate, Some(&override_path));
    assert_eq!(explicit_discovered, Some(override_path));

    // 3. Helper derive_config_path
    let derived = derive_config_path(&core_candidate);
    assert_eq!(
        derived.file_name().unwrap(),
        "CM_FP_Unspecified.config.dll"
    );
}
