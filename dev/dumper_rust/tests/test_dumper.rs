use dumper_rust::dumper::{Dumper, DumperOptions};
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

    // 1. Dynamic version invariant in canonical Binja format
    assert!(!result.options.version.is_empty(), "App version must be dynamically detected");
    assert!(result.options.build > 0, "Build number must be positive");

    // 2. Packets invariants (exactly 128 packets)
    assert_eq!(result.packets.len(), 128, "Must discover exactly 128 packets");
    let mut packet_opcodes = HashSet::new();
    for p in &result.packets {
        let opcode = p.opcode;
        assert!(opcode > 0, "Opcode must be positive");
        assert!(
            packet_opcodes.insert(opcode),
            "Duplicate packet opcode: {}",
            opcode
        );
        assert!(!p.request.name.is_empty());
        assert!(!p.response.name.is_empty());
    }

    // 3. Events invariants (exactly 24 events)
    assert_eq!(result.events.len(), 24, "Must discover exactly 24 events");
    let mut event_opcodes = HashSet::new();
    for e in &result.events {
        let opcode = e.opcode;
        assert!(opcode > 0, "Event opcode must be positive");
        assert!(
            event_opcodes.insert(opcode),
            "Duplicate event opcode: {}",
            opcode
        );
    }
    assert!(
        result.events.iter().any(|e| e.kind.as_deref() == Some("special_packet")),
        "Must contain special factory packet (e.g. Ping)"
    );

    // 4. Polymorphic models invariants: 4 roots present
    assert_eq!(result.polymorphic_models.len(), 4, "Must discover exactly 4 polymorphic roots");
    let poly_root_names: HashSet<&str> = result.polymorphic_models
        .iter()
        .map(|pm| pm.name.as_str())
        .collect();
    assert!(poly_root_names.contains("Api::OneMe::Types::BaseAttachment"));
    assert!(poly_root_names.contains("Api::OneMe::Types::Log::EventParams"));
    assert!(poly_root_names.contains("Api::OneMe::Types::Log::UnknownContactInteractionParams"));
    assert!(poly_root_names.contains("Api::OneMe::Types::Outgoing::BaseAttachment"));

    // 5. Models invariants (BFS discovery) & Transitive discovery of VideoCollage
    assert!(!result.models.is_empty());

    let video_collage = result.models
        .iter()
        .find(|m| m.name == "Api::OneMe::Types::VideoCollage")
        .expect("VideoCollage must be transitively discovered in models");
    let vc_field_names: Vec<&str> = video_collage.fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(vc_field_names, vec!["url", "frequency", "height", "width", "count"]);

    // 6. Cleanliness invariants: no blacklisted false fields & no raw MSVC primitives
    let blacklisted = ["PUBLIC", "POLL", "BlacklistConverter"];
    let check_fields_cleanliness = |fields: &[dumper_rust::extractor::ExtractedField]| {
        for f in fields {
            for bad in &blacklisted {
                assert_ne!(&f.name.as_str(), bad, "Blacklisted field name '{}' leaked into output", bad);
            }
            let full = &f.field_type.full;
            assert!(!full.contains("__int64"), "Raw __int64 in type: {}", full);
            assert!(!full.contains("signed char"), "Raw signed char in type: {}", full);
            assert!(!full.contains("basic_string"), "Raw basic_string in type: {}", full);

            if f.field_type.optional {
                assert!(!f.required, "Field '{}' with optional type cannot be required: true", f.name);
            }
        }
    };

    for m in &result.models {
        check_fields_cleanliness(&m.fields);
    }
    for pm in &result.polymorphic_models {
        for v in &pm.variants {
            check_fields_cleanliness(&v.fields);
        }
    }

    // 7. JSON serialization validity
    let json_str = serde_json::to_string_pretty(&result).expect("Failed to serialize to JSON");
    assert!(json_str.starts_with('{'));
    assert!(json_str.ends_with('}'));
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
