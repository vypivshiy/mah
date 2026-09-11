use dumper_rust::extractor::{FieldExtractor, VtableXrefIndex};
use dumper_rust::pe::PeImage;
use dumper_rust::rtti::RttiEngine;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_dynamic_extract_fields_by_model_name() {
    let dll_path = PathBuf::from("../../dev/CM_FP_Unspecified.core.dll");
    assert!(dll_path.exists());
    let bytes = fs::read(&dll_path).expect("Failed to read DLL");
    let pe = PeImage::parse(&bytes).expect("Failed to parse PE image");
    let rtti = RttiEngine::build(&pe).expect("Failed to build RTTI engine");

    let extractor = FieldExtractor::new(&pe, &rtti);
    let xref_index = VtableXrefIndex::build(&pe, &rtti);

    // 1. Dynamically find and extract Log::Parameters
    let log_params_vtable = rtti
        .type_to_vtable
        .get("Api::OneMe::Packets::Log::Parameters")
        .expect("Log::Parameters vtable must exist");
    let (func_rva, fields) = xref_index
        .find_best_initializer(*log_params_vtable, &extractor)
        .expect("Must find initializer for Log::Parameters");
    assert!(func_rva > 0);
    assert!(!fields.is_empty());
    assert_eq!(fields[0].name, "events");
    assert!(fields[0].required);

    // 2. Dynamically find and extract ServerSettings (mega-initializer with helpers)
    let ss_vtable = rtti
        .type_to_vtable
        .get("Api::OneMe::Types::ServerSettings")
        .expect("ServerSettings vtable must exist");
    let (_ss_func, ss_fields) = xref_index
        .find_best_initializer(*ss_vtable, &extractor)
        .expect("Must find initializer for ServerSettings");
    assert!(ss_fields.len() > 50, "ServerSettings should have many fields");
    for f in &ss_fields {
        assert!(!f.name.is_empty());
        assert!(!f.field_type.full.is_empty());
    }

    // 3. Test MapSubject has only organizationIds (no PUBLIC)
    let map_sub_vt = rtti
        .type_to_vtable
        .get("Api::OneMe::Types::MapSubject")
        .expect("MapSubject vtable must exist");
    let (_, map_fields) = xref_index
        .find_best_initializer(*map_sub_vt, &extractor)
        .expect("Must find initializer for MapSubject");
    let map_field_names: Vec<&str> = map_fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(map_field_names, vec!["organizationIds"]);

    // 4. Test PollAnswer has only text and answerId (no POLL)
    let poll_ans_vt = rtti
        .type_to_vtable
        .get("Api::OneMe::Types::PollAnswer")
        .expect("PollAnswer vtable must exist");
    let (_, poll_fields) = xref_index
        .find_best_initializer(*poll_ans_vt, &extractor)
        .expect("Must find initializer for PollAnswer");
    let poll_field_names: Vec<&str> = poll_fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(poll_field_names, vec!["text", "answerId"]);

    // 5. Test Presence has only on, status, seen (no BlacklistConverter)
    let presence_vt = rtti
        .type_to_vtable
        .get("Api::OneMe::Types::Presence")
        .expect("Presence vtable must exist");
    let (_, presence_fields) = xref_index
        .find_best_initializer(*presence_vt, &extractor)
        .expect("Must find initializer for Presence");
    let presence_field_names: Vec<&str> = presence_fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(presence_field_names, vec!["on", "status", "seen"]);

    // 6. Test VideoAttachment field types (Issue 02)
    let va_vtable = rtti
        .type_to_vtable
        .get("Api::OneMe::Types::VideoAttachment")
        .expect("VideoAttachment vtable must exist");
    let (_, va_fields) = xref_index
        .find_best_initializer(*va_vtable, &extractor)
        .expect("Must find initializer for VideoAttachment");
    let va_map: std::collections::HashMap<&str, &str> = va_fields
        .iter()
        .map(|f| (f.name.as_str(), f.field_type.full.as_str()))
        .collect();
    assert_eq!(va_map.get("collage"), Some(&"std::optional<Api::OneMe::Types::VideoCollage>"));
    assert_eq!(va_map.get("paid"), Some(&"std::optional<bool>"));
    assert_eq!(va_map.get("previewData"), Some(&"std::optional<std::vector<std::byte>>"));
    assert_eq!(va_map.get("wave"), Some(&"std::optional<std::vector<std::byte>>"));
    assert_eq!(va_map.get("thumbhash"), Some(&"std::optional<std::vector<std::byte>>"));
    assert_eq!(va_map.get("token"), Some(&"std::optional<std::string>"));
    assert_eq!(va_map.get("MP4_1080"), Some(&"std::optional<std::string>"));
}
