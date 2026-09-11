use dumper_rust::dumper::{Dumper, DumperFormat, DumperOptions};
use dumper_rust::pe::PeImage;
use dumper_rust::rtti::RttiEngine;
use dumper_rust::scanner::ProtocolScanner;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

#[test]
fn test_dumper_full_pipeline_structural_invariants() {
    let dll_path = PathBuf::from("../../dev/CM_FP_Unspecified.core.dll");
    assert!(dll_path.exists());
    let bytes = fs::read(&dll_path).expect("Failed to read DLL");
    let pe = PeImage::parse(&bytes).expect("Failed to parse PE image");
    let rtti = RttiEngine::build(&pe).expect("Failed to build RTTI engine");
    let scanner = ProtocolScanner::scan(&pe, &rtti).expect("Failed to scan protocol entities");

    // Pass empty options to test dynamic version detection from DLL
    let options = DumperOptions {
        version: dumper_rust::dumper::AppVersion {
            version: String::new(),
            build: 0,
        },
        format: DumperFormat::Binja,
    };

    let start_time = Instant::now();
    let result = Dumper::dump(&pe, &rtti, &scanner, &options).expect("Failed to execute dumper");
    let dump_duration = start_time.elapsed();

    // Performance SLA assertion: < 400 ms in release mode, < 15000 ms in unoptimized debug mode
    if !cfg!(debug_assertions) {
        assert!(
            dump_duration.as_millis() < 400,
            "Release mode dump exceeded 400ms SLA: {:?}",
            dump_duration
        );
    } else {
        assert!(
            dump_duration.as_millis() < 15000,
            "Debug mode dump exceeded 15000ms: {:?}",
            dump_duration
        );
    }

    // 1. Dynamic version invariant in Binja format (inside options, root omitted)
    let opts = result.options.as_ref().expect("Options must be present in Binja mode");
    assert!(!opts.version.is_empty(), "App version must be dynamically detected");
    assert!(opts.build > 0, "Build number must be positive");
    assert!(result.app_version.is_none(), "Root app_version must be omitted in Binja mode");
    assert!(result.build_number.is_none(), "Root build_number must be omitted in Binja mode");

    // 2. Packets invariants (exactly 128 packets)
    assert_eq!(result.packets.len(), 128, "Must discover exactly 128 packets");
    let mut packet_opcodes = HashSet::new();
    for p in &result.packets {
        let opcode = p.get("opcode").and_then(|v| v.as_u64()).expect("Packet must have opcode");
        assert!(opcode > 0, "Opcode must be positive");
        assert!(
            packet_opcodes.insert(opcode),
            "Duplicate packet opcode: {}",
            opcode
        );
        let req_name = p.pointer("/request/name").and_then(|v| v.as_str()).expect("Req name missing");
        let resp_name = p.pointer("/response/name").and_then(|v| v.as_str()).expect("Resp name missing");
        assert!(!req_name.is_empty());
        assert!(!resp_name.is_empty());
    }

    // 3. Events invariants (exactly 24 events)
    assert_eq!(result.events.len(), 24, "Must discover exactly 24 events");
    let mut event_opcodes = HashSet::new();
    for e in &result.events {
        let opcode = e.get("opcode").and_then(|v| v.as_u64()).expect("Event must have opcode");
        assert!(opcode > 0, "Event opcode must be positive");
        assert!(
            event_opcodes.insert(opcode),
            "Duplicate event opcode: {}",
            opcode
        );
    }
    assert!(
        result.events.iter().any(|e| e.get("kind").and_then(|v| v.as_str()) == Some("special_packet")),
        "Must contain special factory packet (e.g. Ping)"
    );

    // 4. Polymorphic models invariants: 4 roots present
    assert!(result.polymorphic_models.is_array());
    let poly_arr = result.polymorphic_models.as_array().unwrap();
    assert_eq!(poly_arr.len(), 4, "Must discover exactly 4 polymorphic roots");
    let poly_root_names: HashSet<&str> = poly_arr
        .iter()
        .filter_map(|pm| pm.get("name").and_then(|v| v.as_str()))
        .collect();
    assert!(poly_root_names.contains("Api::OneMe::Types::BaseAttachment"));
    assert!(poly_root_names.contains("Api::OneMe::Types::Log::EventParams"));
    assert!(poly_root_names.contains("Api::OneMe::Types::Log::UnknownContactInteractionParams"));
    assert!(poly_root_names.contains("Api::OneMe::Types::Outgoing::BaseAttachment"));

    // 5. Models invariants (BFS discovery) & Transitive discovery of VideoCollage
    assert!(result.models.is_array());
    let models_arr = result.models.as_array().unwrap();
    assert!(!models_arr.is_empty());

    let video_collage = models_arr
        .iter()
        .find(|m| m.get("name").and_then(|v| v.as_str()) == Some("Api::OneMe::Types::VideoCollage"))
        .expect("VideoCollage must be transitively discovered in models");
    let vc_fields = video_collage
        .get("fields")
        .and_then(|v| v.as_array())
        .expect("VideoCollage must have fields");
    let vc_field_names: Vec<&str> = vc_fields
        .iter()
        .filter_map(|f| f.get("name").and_then(|v| v.as_str()))
        .collect();
    assert_eq!(vc_field_names, vec!["url", "frequency", "height", "width", "count"]);

    // 6. Cleanliness invariants: no blacklisted false fields & no raw MSVC primitives
    let blacklisted = ["PUBLIC", "POLL", "BlacklistConverter"];
    let check_fields_cleanliness = |fields: &[serde_json::Value]| {
        for f in fields {
            let name = f.get("name").and_then(|v| v.as_str()).unwrap_or("");
            for bad in &blacklisted {
                assert_ne!(&name, bad, "Blacklisted field name '{}' leaked into output", bad);
            }
            if let Some(t) = f.get("type") {
                let full = t.get("full").and_then(|v| v.as_str()).unwrap_or("");
                assert!(!full.contains("__int64"), "Raw __int64 in type: {}", full);
                assert!(!full.contains("signed char"), "Raw signed char in type: {}", full);
                assert!(!full.contains("basic_string"), "Raw basic_string in type: {}", full);

                let is_opt = t.get("optional").and_then(|v| v.as_bool()).unwrap_or(false);
                let is_req = f.get("required").and_then(|v| v.as_bool()).unwrap_or(false);
                if is_opt {
                    assert!(!is_req, "Field '{}' with optional type cannot be required: true", name);
                }
            }
        }
    };

    for m in models_arr {
        if let Some(fields) = m.get("fields").and_then(|v| v.as_array()) {
            check_fields_cleanliness(fields);
        }
    }
    for pm in poly_arr {
        if let Some(variants) = pm.get("variants").and_then(|v| v.as_array()) {
            for v in variants {
                if let Some(fields) = v.get("fields").and_then(|v| v.as_array()) {
                    check_fields_cleanliness(fields);
                }
            }
        }
    }

    // 7. JSON serialization validity
    let json_str = serde_json::to_string_pretty(&result).expect("Failed to serialize to JSON");
    assert!(json_str.starts_with('{'));
    assert!(json_str.ends_with('}'));

    // 8. Also test Ida format output
    let ida_opts = DumperOptions {
        version: dumper_rust::dumper::AppVersion {
            version: String::new(),
            build: 0,
        },
        format: DumperFormat::Ida,
    };
    let ida_result = Dumper::dump(&pe, &rtti, &scanner, &ida_opts).expect("Failed to execute ida dump");
    assert!(ida_result.options.is_none(), "Options must be omitted in Ida mode");
    assert!(!ida_result.app_version.as_deref().unwrap_or("").is_empty());
    assert!(ida_result.build_number.unwrap_or(0) > 0);
    assert!(ida_result.models.is_object());
    assert!(ida_result.polymorphic_models.is_object());
    assert_eq!(ida_result.image_base.as_deref(), Some("0x180000000"));
}

#[test]
fn test_schema_diff_against_reference() {
    let binja_path = PathBuf::from("../../dev/packets_binja.json");
    let rust_path = PathBuf::from("../../dev/packets_rust.json");
    if !binja_path.exists() || !rust_path.exists() {
        return;
    }

    let binja_data: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&binja_path).unwrap()).unwrap();
    let rust_data: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&rust_path).unwrap()).unwrap();

    let binja_packets = binja_data.get("packets").and_then(|v| v.as_array()).unwrap();
    let rust_packets = rust_data.get("packets").and_then(|v| v.as_array()).unwrap();
    assert_eq!(rust_packets.len(), binja_packets.len(), "Packet count mismatch");

    let binja_events = binja_data.get("events").and_then(|v| v.as_array()).unwrap();
    let rust_events = rust_data.get("events").and_then(|v| v.as_array()).unwrap();
    assert_eq!(rust_events.len(), binja_events.len(), "Event count mismatch");

    // Structural diff of models
    let binja_models = binja_data.get("models").and_then(|v| v.as_array()).unwrap();
    let rust_models = rust_data.get("models").and_then(|v| v.as_array()).unwrap();

    let rust_model_names: HashSet<&str> = rust_models
        .iter()
        .filter_map(|m| m.get("name").and_then(|v| v.as_str()))
        .collect();
    let binja_model_names: HashSet<&str> = binja_models
        .iter()
        .filter_map(|m| m.get("name").and_then(|v| v.as_str()))
        .collect();

    // Verify key models exist in both
    for key_model in &[
        "Api::OneMe::Types::Contact",
        "Api::OneMe::Types::Message",
        "Api::OneMe::Types::ServerSettings",
        "Api::OneMe::Types::VideoCollage",
    ] {
        assert!(rust_model_names.contains(key_model), "Missing key model {}", key_model);
        assert!(binja_model_names.contains(key_model), "Missing in binja: {}", key_model);
    }
}
