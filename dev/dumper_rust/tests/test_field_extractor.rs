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
}
