use dumper_rust::dumper::{Dumper, DumperFormat, DumperOptions};
use dumper_rust::pe::PeImage;
use dumper_rust::rtti::RttiEngine;
use dumper_rust::scanner::ProtocolScanner;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

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
        app_version: String::new(),
        build_number: 0,
        format: DumperFormat::Binja,
    };

    let result = Dumper::dump(&pe, &rtti, &scanner, &options).expect("Failed to execute dumper");

    // 1. Dynamic version invariant
    assert!(!result.app_version.is_empty(), "App version must be dynamically detected");
    assert!(result.build_number > 0, "Build number must be positive");

    // 2. Packets invariants
    assert!(!result.packets.is_empty(), "Must discover packets");
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

    // 3. Events invariants
    assert!(!result.events.is_empty(), "Must discover events");
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

    // 4. Polymorphic models invariants
    assert!(result.polymorphic_models.is_array());
    let poly_arr = result.polymorphic_models.as_array().unwrap();
    assert!(!poly_arr.is_empty());
    for pm in poly_arr {
        let name = pm.get("name").and_then(|v| v.as_str()).unwrap();
        assert!(!name.is_empty());
        let variants = pm.get("variants").and_then(|v| v.as_array()).unwrap();
        assert!(!variants.is_empty());
    }

    // 5. Models invariants (BFS discovery)
    assert!(result.models.is_array());
    let models_arr = result.models.as_array().unwrap();
    assert!(!models_arr.is_empty());

    // 6. JSON serialization validity
    let json_str = serde_json::to_string_pretty(&result).expect("Failed to serialize to JSON");
    assert!(json_str.starts_with('{'));
    assert!(json_str.ends_with('}'));

    // 7. Also test Ida format output
    let ida_opts = DumperOptions {
        app_version: String::new(),
        build_number: 0,
        format: DumperFormat::Ida,
    };
    let ida_result = Dumper::dump(&pe, &rtti, &scanner, &ida_opts).expect("Failed to execute ida dump");
    assert!(ida_result.models.is_object());
    assert!(ida_result.polymorphic_models.is_object());
    assert_eq!(ida_result.image_base.as_deref(), Some("0x180000000"));
}
