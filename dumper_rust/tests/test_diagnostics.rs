use dumper_rust::discriminator::{
    DiscriminatorExtractionMiss, DiscriminatorScanDiagnostics, DiscriminatorValueEvidence,
};
use dumper_rust::dumper::{
    AppVersion, DumpDiagnostics, DumpResult, InitializerCandidateDiagnostic,
};
use serde_json::Value;

#[test]
fn diagnostics_sidecar_serializes_initializer_and_discriminator_sections() {
    let diagnostics = DumpDiagnostics {
        initializer_candidates: vec![InitializerCandidateDiagnostic {
            model_name: "Api::OneMe::Types::BotInfo::Parameters".to_string(),
            kind: "rejected_initializer_candidate".to_string(),
            function_rva: Some("0x400".to_string()),
            reason: "selected 0x300".to_string(),
        }],
        discriminator: DiscriminatorScanDiagnostics {
            evidence: vec![DiscriminatorValueEvidence {
                variant_name: "Api::OneMe::Types::PhotoAttachment".to_string(),
                value: "PHOTO".to_string(),
                function_rva: "0x1000".to_string(),
            }],
            misses: vec![DiscriminatorExtractionMiss {
                variant_name: Some("Api::OneMe::Types::VideoAttachment".to_string()),
                function_rva: Some("0x2000".to_string()),
                reason: "no _type assignment observed".to_string(),
                constructed_variants: vec!["Api::OneMe::Types::VideoAttachment".to_string()],
                type_assignments: Vec::new(),
            }],
        },
    };

    let value = serde_json::to_value(&diagnostics).expect("diagnostics should serialize");

    assert_eq!(
        value["initializer_candidates"][0]["kind"],
        "rejected_initializer_candidate"
    );
    assert_eq!(value["initializer_candidates"][0]["function_rva"], "0x400");
    assert_eq!(value["discriminator"]["evidence"][0]["value"], "PHOTO");
    assert_eq!(
        value["discriminator"]["misses"][0]["reason"],
        "no _type assignment observed"
    );
}

#[test]
fn main_dump_serialization_does_not_include_diagnostics_by_default() {
    let dump = DumpResult {
        options: AppVersion {
            version: "test".to_string(),
            build: 1,
        },
        packets: Vec::new(),
        events: Vec::new(),
        models: Vec::new(),
        polymorphic_models: Vec::new(),
        string_enums: Vec::new(),
        error: serde_json::json!({}),
    };

    let value = serde_json::to_value(&dump).expect("dump should serialize");

    assert!(value.get("diagnostics").is_none());
    assert!(value.get("initializer_candidates").is_none());
    assert!(!contains_key_recursive(&value, "evidence"));
    assert!(!contains_key_recursive(&value, "misses"));
}

fn contains_key_recursive(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(current_key, current_value)| {
            current_key == key || contains_key_recursive(current_value, key)
        }),
        Value::Array(values) => values
            .iter()
            .any(|current_value| contains_key_recursive(current_value, key)),
        _ => false,
    }
}
