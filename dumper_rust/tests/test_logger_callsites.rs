use dumper_rust::datamining::LoggerAnalyzer;
use dumper_rust::pe::PeImage;
use dumper_rust::rtti::RttiEngine;
use dumper_rust::scanner::ProtocolScanner;
use std::fs;

mod common;
use common::resolve_env_path;

#[test]
fn test_logger_callsites_and_packet_binding_integration() {
    let dll_path = match resolve_env_path("CORE_DLL_PATH") {
        Some(path) => path,
        None => {
            eprintln!("Skipping: CORE_DLL_PATH not set or file does not exist");
            return;
        }
    };
    if !dll_path.exists() {
        eprintln!(
            "Skipping: CORE_DLL_PATH not set or file does not exist: {:?}",
            dll_path
        );
        return;
    }

    let bytes = fs::read(&dll_path).expect("Failed to read DLL");
    let pe = PeImage::parse(&bytes).expect("Failed to parse PE image");
    let rtti = RttiEngine::build(&pe).expect("Failed to build RTTI engine");
    let scanner = ProtocolScanner::scan(&pe, &rtti).expect("Failed to scan protocol entities");

    let result = LoggerAnalyzer::analyze(&pe, &rtti, &scanner)
        .expect("Failed to analyze logger and packet bindings");

    // 1. Invariants on source_files
    assert!(
        result.source_files.len() >= 100,
        "Expected at least 100 source files, found {}",
        result.source_files.len()
    );
    assert!(
        result.source_files.windows(2).all(|w| w[0] < w[1]),
        "source_files must be strictly sorted and deduplicated"
    );
    assert!(
        result
            .source_files
            .iter()
            .any(|s| s == "components/core/src/oneme_auth/oneme_auth_session.cpp"),
        "Expected oneme_auth_session.cpp in source_files"
    );
    assert!(
        result
            .source_files
            .iter()
            .any(|s| s == "components/core/src/business/calls/calls_interactor.cpp"),
        "Expected calls_interactor.cpp in source_files"
    );

    // 2. Invariants on log_templates
    assert!(
        result.log_templates.len() >= 100,
        "Expected at least 100 log templates, found {}",
        result.log_templates.len()
    );
    assert!(
        result.log_templates.windows(2).all(|w| w[0] < w[1]),
        "log_templates must be strictly sorted and deduplicated"
    );
    assert!(
        result
            .log_templates
            .iter()
            .any(|t| t == "CheckEmail send error({}): {}"),
        "Expected CheckEmail template in log_templates"
    );
    assert!(
        result
            .log_templates
            .iter()
            .any(|t| t == "VerifyEmail send error({}): {}"),
        "Expected VerifyEmail template in log_templates"
    );

    // 3. Invariants on packets_catalog
    assert!(
        result.packets_catalog.len() >= 120,
        "Expected at least 120 catalog entries, found {}",
        result.packets_catalog.len()
    );
    assert!(
        result.packets_catalog.windows(2).all(|w| w[0].opcode <= w[1].opcode),
        "packets_catalog must be sorted by opcode"
    );

    let bound_count = result
        .packets_catalog
        .iter()
        .filter(|e| e.handler.is_some())
        .count();
    assert!(
        bound_count >= 60,
        "Expected at least 60 packets bound to handlers, found {}",
        bound_count
    );

    // Verify Opcode 32 (ContactInfo -> CallsInteractor::doRequestContacts)
    let op32 = result
        .packets_catalog
        .iter()
        .find(|e| e.opcode == 32)
        .expect("Opcode 32 must exist in catalog");
    assert!(op32.handler.is_some(), "Opcode 32 should have a resolved handler");
    let h32 = op32.handler.as_ref().unwrap();
    assert_eq!(h32.class, "Core::Calls::CallsInteractor");
    assert_eq!(h32.method, "doRequestContacts");
    assert_eq!(h32.source, "components/core/src/business/calls/calls_interactor.cpp");

    // Verify Opcode 110 (CheckEmail -> OneMeAuthSession::doSendEmailCheckCode)
    let op110 = result
        .packets_catalog
        .iter()
        .find(|e| e.opcode == 110)
        .expect("Opcode 110 must exist in catalog");
    assert!(op110.handler.is_some(), "Opcode 110 should have a resolved handler");
    let h110 = op110.handler.as_ref().unwrap();
    assert_eq!(h110.class, "Core::Auth::OneMeAuthSession");
    assert_eq!(h110.method, "doSendEmailCheckCode");
    assert_eq!(h110.source, "components/core/src/oneme_auth/oneme_auth_session.cpp");

    // Verify Opcode 109 (VerifyEmail -> OneMeAuthSession::doSendEmailVerifyRequest)
    let op109 = result
        .packets_catalog
        .iter()
        .find(|e| e.opcode == 109)
        .expect("Opcode 109 must exist in catalog");
    assert!(op109.handler.is_some(), "Opcode 109 should have a resolved handler");
    let h109 = op109.handler.as_ref().unwrap();
    assert_eq!(h109.class, "Core::Auth::OneMeAuthSession");
    assert_eq!(h109.method, "doSendEmailVerifyRequest");
    assert_eq!(h109.source, "components/core/src/oneme_auth/oneme_auth_session.cpp");
}
