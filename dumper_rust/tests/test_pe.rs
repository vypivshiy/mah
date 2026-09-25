use dumper_rust::pe::PeImage;
use std::fs;

mod common;
use common::resolve_env_path;

#[test]
fn test_pe_parsing_standalone() {
    let mut bytes = vec![0u8; 0x1000];

    // 1. DOS Header
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3C..0x40].copy_from_slice(&(0x80u32).to_le_bytes()); // e_lfanew

    // 2. PE Signature
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

    // 3. COFF File Header (IMAGE_FILE_HEADER) at 0x84 (20 bytes)
    bytes[0x84..0x86].copy_from_slice(&(0x8664u16).to_le_bytes()); // Machine: AMD64
    bytes[0x86..0x88].copy_from_slice(&(2u16).to_le_bytes()); // NumberOfSections: 2
    bytes[0x88..0x8C].copy_from_slice(&(0u32).to_le_bytes()); // TimeDateStamp
    bytes[0x8C..0x90].copy_from_slice(&(0u32).to_le_bytes()); // PointerToSymbolTable
    bytes[0x90..0x94].copy_from_slice(&(0u32).to_le_bytes()); // NumberOfSymbols
    bytes[0x94..0x96].copy_from_slice(&(240u16).to_le_bytes()); // SizeOfOptionalHeader (0xF0)
    bytes[0x96..0x98].copy_from_slice(&(0x0022u16).to_le_bytes()); // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // 4. Optional Header 64 (IMAGE_OPTIONAL_HEADER64) at 0x98 (240 bytes)
    // Standard fields (24 bytes)
    bytes[0x98..0x9A].copy_from_slice(&(0x020Bu16).to_le_bytes()); // Magic: PE32+
    bytes[0x9A] = 1; // MajorLinkerVersion
    bytes[0x9B] = 0; // MinorLinkerVersion
    bytes[0x9C..0xA0].copy_from_slice(&(0x200u32).to_le_bytes()); // SizeOfCode
    bytes[0xA0..0xA4].copy_from_slice(&(0x200u32).to_le_bytes()); // SizeOfInitializedData
    bytes[0xA4..0xA8].copy_from_slice(&(0u32).to_le_bytes()); // SizeOfUninitializedData
    bytes[0xA8..0xAC].copy_from_slice(&(0x1000u32).to_le_bytes()); // AddressOfEntryPoint
    bytes[0xAC..0xB0].copy_from_slice(&(0x1000u32).to_le_bytes()); // BaseOfCode

    // Windows fields (88 bytes)
    bytes[0xB0..0xB8].copy_from_slice(&(0x180000000u64).to_le_bytes()); // ImageBase
    bytes[0xB8..0xBC].copy_from_slice(&(0x1000u32).to_le_bytes()); // SectionAlignment
    bytes[0xBC..0xC0].copy_from_slice(&(0x200u32).to_le_bytes()); // FileAlignment
    bytes[0xC0..0xC2].copy_from_slice(&(6u16).to_le_bytes()); // MajorOperatingSystemVersion
    bytes[0xC2..0xC4].copy_from_slice(&(0u16).to_le_bytes()); // MinorOperatingSystemVersion
    bytes[0xC4..0xC6].copy_from_slice(&(0u16).to_le_bytes()); // MajorImageVersion
    bytes[0xC6..0xC8].copy_from_slice(&(0u16).to_le_bytes()); // MinorImageVersion
    bytes[0xC8..0xCA].copy_from_slice(&(6u16).to_le_bytes()); // MajorSubsystemVersion
    bytes[0xCA..0xCC].copy_from_slice(&(0u16).to_le_bytes()); // MinorSubsystemVersion
    bytes[0xCC..0xD0].copy_from_slice(&(0u32).to_le_bytes()); // Win32VersionValue
    bytes[0xD0..0xD4].copy_from_slice(&(0x3000u32).to_le_bytes()); // SizeOfImage
    bytes[0xD4..0xD8].copy_from_slice(&(0x200u32).to_le_bytes()); // SizeOfHeaders
    bytes[0xD8..0xDC].copy_from_slice(&(0u32).to_le_bytes()); // CheckSum
    bytes[0xDC..0xDE].copy_from_slice(&(3u16).to_le_bytes()); // Subsystem: Windows CUI
    bytes[0xDE..0xE0].copy_from_slice(&(0u16).to_le_bytes()); // DllCharacteristics
    bytes[0xE0..0xE8].copy_from_slice(&(0x100000u64).to_le_bytes()); // SizeOfStackReserve
    bytes[0xE8..0xF0].copy_from_slice(&(0x1000u64).to_le_bytes()); // SizeOfStackCommit
    bytes[0xF0..0xF8].copy_from_slice(&(0x100000u64).to_le_bytes()); // SizeOfHeapReserve
    bytes[0xF8..0x100].copy_from_slice(&(0x1000u64).to_le_bytes()); // SizeOfHeapCommit
    bytes[0x100..0x104].copy_from_slice(&(0u32).to_le_bytes()); // LoaderFlags
    bytes[0x104..0x108].copy_from_slice(&(16u32).to_le_bytes()); // NumberOfRvaAndSizes

    // Data Directories (16 * 8 = 128 bytes, 0x108..0x188): all zeros

    // 5. Section Headers (IMAGE_SECTION_HEADER) at 0x188
    // Section 1: .text (40 bytes at 0x188..0x1B0)
    bytes[0x188..0x190].copy_from_slice(b".text\0\0\0");
    bytes[0x190..0x194].copy_from_slice(&(0x1000u32).to_le_bytes()); // VirtualSize
    bytes[0x194..0x198].copy_from_slice(&(0x1000u32).to_le_bytes()); // VirtualAddress
    bytes[0x198..0x19C].copy_from_slice(&(0x200u32).to_le_bytes()); // SizeOfRawData
    bytes[0x19C..0x1A0].copy_from_slice(&(0x200u32).to_le_bytes()); // PointerToRawData
    bytes[0x1A0..0x1A4].copy_from_slice(&(0u32).to_le_bytes());
    bytes[0x1A4..0x1A8].copy_from_slice(&(0u32).to_le_bytes());
    bytes[0x1A8..0x1AA].copy_from_slice(&(0u16).to_le_bytes());
    bytes[0x1AA..0x1AC].copy_from_slice(&(0u16).to_le_bytes());
    bytes[0x1AC..0x1B0].copy_from_slice(&(0x60000020u32).to_le_bytes()); // Characteristics: CODE | EXECUTE | READ

    // Section 2: .rdata (40 bytes at 0x1B0..0x1D8)
    bytes[0x1B0..0x1B8].copy_from_slice(b".rdata\0\0");
    bytes[0x1B8..0x1BC].copy_from_slice(&(0x1000u32).to_le_bytes()); // VirtualSize
    bytes[0x1BC..0x1C0].copy_from_slice(&(0x2000u32).to_le_bytes()); // VirtualAddress
    bytes[0x1C0..0x1C4].copy_from_slice(&(0x200u32).to_le_bytes()); // SizeOfRawData
    bytes[0x1C4..0x1C8].copy_from_slice(&(0x400u32).to_le_bytes()); // PointerToRawData
    bytes[0x1C8..0x1CC].copy_from_slice(&(0u32).to_le_bytes());
    bytes[0x1CC..0x1D0].copy_from_slice(&(0u32).to_le_bytes());
    bytes[0x1D0..0x1D2].copy_from_slice(&(0u16).to_le_bytes());
    bytes[0x1D2..0x1D4].copy_from_slice(&(0u16).to_le_bytes());
    bytes[0x1D4..0x1D8].copy_from_slice(&(0x40000040u32).to_le_bytes()); // Characteristics: INITIALIZED_DATA | READ

    // Raw payload data for sections
    bytes[0x200..0x204].copy_from_slice(&[0x90, 0x90, 0xC3, 0x00]);
    bytes[0x400..0x409].copy_from_slice(b"Hello PE\0");

    let pe = PeImage::parse(&bytes).expect("Synthetic PE must parse cleanly without external files");

    assert_eq!(pe.image_base, 0x180000000);
    assert_eq!(pe.sections.len(), 2);

    let text = pe.section_by_name(".text").expect(".text must exist");
    assert_eq!(text.virtual_address, 0x1000);
    assert_eq!(text.pointer_to_raw_data, 0x200);

    let rdata = pe.section_by_name(".rdata").expect(".rdata must exist");
    assert_eq!(rdata.virtual_address, 0x2000);
    assert_eq!(rdata.pointer_to_raw_data, 0x400);

    // Assert RVA translation
    assert_eq!(pe.rva_to_offset(0x1000), Some(0x200));
    assert_eq!(pe.rva_to_offset(0x1050), Some(0x250));
    assert_eq!(pe.rva_to_offset(0x2000), Some(0x400));
    assert_eq!(pe.rva_to_offset(0x3000), None);

    assert_eq!(pe.offset_to_rva(0x200), Some(0x1000));
    assert_eq!(pe.offset_to_rva(0x400), Some(0x2000));
    assert_eq!(pe.read_cstring(0x2000), Some("Hello PE"));
}

#[test]
fn test_pe_parse_and_lookup() {
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

    // Check image base
    assert_eq!(pe.image_base, 0x180000000);

    // Check core sections
    let text_sec = pe
        .section_by_name(".text")
        .expect(".text section must exist");
    assert_eq!(text_sec.virtual_address, 0x1000);

    let rdata_sec = pe
        .section_by_name(".rdata")
        .expect(".rdata section must exist");
    assert!(rdata_sec.virtual_address > 0x1000);

    // Check RVA to offset mapping
    let text_off = pe
        .rva_to_offset(0x1000)
        .expect("RVA 0x1000 should map to file offset");
    assert_eq!(text_off, text_sec.pointer_to_raw_data as usize);

    // Check .pdata exception directory parsing
    assert!(!pe.pdata.is_empty(), "pdata functions must be parsed");
    assert!(
        pe.pdata.len() > 10000,
        "pdata should contain thousands of functions"
    );

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
