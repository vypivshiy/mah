use dumper_rust::pe::PeImage;
use dumper_rust::rtti::RttiEngine;
use dumper_rust::scanner::ProtocolScanner;
use std::collections::HashSet;
use std::fs;

mod common;
use common::resolve_env_path;

#[test]
fn test_scan_packets_and_events_invariants() {
    let dll_path = match resolve_env_path("CORE_DLL_PATH") {
        Some(path) => path,
        None => {
            eprintln!("Skipping: CORE_DLL_PATH not set or file does not exist");
            return;
        }
    };
    if !dll_path.exists() {
        eprintln!("Skipping: CORE_DLL_PATH not set or file does not exist: {:?}", dll_path);
        return;
    }
    let bytes = fs::read(&dll_path).expect("Failed to read DLL");
    let pe = PeImage::parse(&bytes).expect("Failed to parse PE image");
    let rtti = RttiEngine::build(&pe).expect("Failed to build RTTI engine");

    let scanner = ProtocolScanner::scan(&pe, &rtti).expect("Failed to scan protocol entities");

    // Packets invariants
    assert!(
        !scanner.packets.is_empty(),
        "Packets list should not be empty"
    );
    let mut packet_opcodes = HashSet::new();
    for p in &scanner.packets {
        assert!(p.opcode > 0);
        assert!(
            packet_opcodes.insert(p.opcode),
            "Duplicate opcode: {}",
            p.opcode
        );
        assert!(!p.request_full_name.is_empty());
        assert!(!p.response_full_name.is_empty());
    }

    // Events invariants
    assert!(
        !scanner.events.is_empty(),
        "Events list should not be empty"
    );
    let mut event_opcodes = HashSet::new();
    for e in &scanner.events {
        assert!(e.opcode > 0);
        assert!(
            event_opcodes.insert(e.opcode),
            "Duplicate event opcode: {}",
            e.opcode
        );
    }
    // Must contain special packet (Ping with opcode 1)
    assert!(scanner.events.iter().any(|e| e.is_special && e.opcode == 1));

    // String enums invariants: valid ASCII uppercase identifiers
    assert!(!scanner.string_enums.is_empty());
    for s in &scanner.string_enums {
        assert!(s.len() >= 3 && s.len() <= 64);
        assert!(s
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'));
    }
}
