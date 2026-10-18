use dumper_rust::datamining::features::{
    extract_server_settings, extract_server_settings_features, locate_server_settings,
    SERVER_SETTINGS_DEMANGLED, SERVER_SETTINGS_MANGLED,
};
use dumper_rust::pe::PeImage;
use dumper_rust::rtti::RttiEngine;
use std::fs;

mod common;
use common::resolve_core_dll;

#[test]
fn test_server_settings_features_integration() {
    let dll_path = match resolve_core_dll() {
        Some(path) => path,
        None => {
            eprintln!("Skipping: core.dll not found");
            return;
        }
    };

    let bytes = fs::read(&dll_path).expect("Failed to read DLL");
    let pe = PeImage::parse(&bytes).expect("Failed to parse PE image");
    let rtti = RttiEngine::build(&pe).expect("Failed to build RTTI engine");

    // 1. Locate ServerSettings model within RTTI (both mangled and demangled)
    let (model_name, vtable_rva) =
        locate_server_settings(&rtti).expect("Must locate ServerSettings in RTTI");
    assert_eq!(model_name, SERVER_SETTINGS_DEMANGLED);
    assert!(vtable_rva > 0);

    // Verify type descriptor exists for mangled symbol
    let mangled_found = rtti
        .type_descriptors
        .values()
        .any(|td| td.mangled_name == SERVER_SETTINGS_MANGLED);
    assert!(
        mangled_found,
        "RTTI must contain type descriptor with mangled symbol {}",
        SERVER_SETTINGS_MANGLED
    );

    // 2. Full extraction verifying candidate evaluation chooses 0x5051d0
    let full = extract_server_settings(&pe, &rtti).expect("Must extract ServerSettings features");
    assert_eq!(
        full.initializer_rva, 0x5051d0,
        "Candidate evaluation must select 0x5051d0"
    );
    assert_eq!(
        full.features.len(),
        262,
        "Must extract exactly 262 field registrations"
    );

    // 3. Extract sorted feature map
    let features = extract_server_settings_features(&pe, &rtti)
        .expect("Must extract features dictionary");
    assert_eq!(features.len(), 262, "Total count must be exactly 262");

    // 4. Assert presence and canonical types of key feature toggles
    assert_eq!(
        features.get("account-nickname-enabled").map(String::as_str),
        Some("std::optional<bool>")
    );
    assert_eq!(
        features.get("video-msg-config").map(String::as_str),
        Some("std::optional<Api::OneMe::Types::VideoMessageConfig>")
    );
    assert_eq!(
        features.get("channels-enabled").map(String::as_str),
        Some("std::optional<bool>")
    );

    // Additional known toggles from research notes
    assert_eq!(
        features.get("file-upload-max-size").map(String::as_str),
        Some("std::optional<int64_t>")
    );
    assert_eq!(
        features.get("max-msg-length").map(String::as_str),
        Some("std::optional<int32_t>")
    );
    assert_eq!(
        features.get("reactions-menu").map(String::as_str),
        Some("std::optional<std::vector<std::string>>")
    );

    // 5. Invariant: keys are strictly sorted and contain no empty keys or values
    let mut prev_key = "";
    for (k, v) in &features {
        assert!(!k.is_empty(), "Feature name cannot be empty");
        assert!(!v.is_empty(), "Feature type cannot be empty");
        assert!(
            k.as_str() > prev_key,
            "Features must be strictly sorted without duplicates: {} vs {}",
            k,
            prev_key
        );
        prev_key = k.as_str();
    }
}
