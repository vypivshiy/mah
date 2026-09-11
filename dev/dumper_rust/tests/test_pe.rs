use dumper_rust::pe::PeImage;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_pe_parse_and_lookup() {
    let dll_path = PathBuf::from("../../dev/CM_FP_Unspecified.core.dll");
    assert!(dll_path.exists(), "Test DLL should exist at {:?}", dll_path);
    let bytes = fs::read(&dll_path).expect("Failed to read DLL");

    let pe = PeImage::parse(&bytes).expect("Failed to parse PE image");

    // Check image base
    assert_eq!(pe.image_base, 0x180000000);

    // Check core sections
    let text_sec = pe.section_by_name(".text").expect(".text section must exist");
    assert_eq!(text_sec.virtual_address, 0x1000);

    let rdata_sec = pe.section_by_name(".rdata").expect(".rdata section must exist");
    assert!(rdata_sec.virtual_address > 0x1000);

    // Check RVA to offset mapping
    let text_off = pe.rva_to_offset(0x1000).expect("RVA 0x1000 should map to file offset");
    assert_eq!(text_off, text_sec.pointer_to_raw_data as usize);

    // Check .pdata exception directory parsing
    assert!(!pe.pdata.is_empty(), "pdata functions must be parsed");
    assert!(pe.pdata.len() > 10000, "pdata should contain thousands of functions");

    // Check find_function binary search
    let first_func = &pe.pdata[0];
    let found = pe.find_function(first_func.begin_address);
    assert!(found.is_some());
    assert_eq!(found.unwrap().begin_address, first_func.begin_address);

    // Check query inside the function body
    let mid_rva = (first_func.begin_address + first_func.end_address) / 2;
    let found_mid = pe.find_function(mid_rva);
    assert!(found_mid.is_some());
    assert_eq!(found_mid.unwrap().begin_address, first_func.begin_address);
}
