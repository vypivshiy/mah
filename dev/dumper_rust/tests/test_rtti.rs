use dumper_rust::pe::PeImage;
use dumper_rust::rtti::RttiEngine;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_demangle_sample() {
    let raw = ".?AUUpdateContent@Assets@Types@OneMe@Api@@";
    let r0_symbol = format!("??_R0{}@8", &raw[1..]);
    let demangled = msvc_demangler::demangle(&r0_symbol, msvc_demangler::DemangleFlags::COMPLETE).unwrap();
    println!("Demangled with R0: {:?}", demangled);

    let smember = ".?AV?$SerializableMember@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VSerializedType@Msgpack@Serialization@@V?$basic_string_view@DU?$char_traits@D@std@@@2@UUpdateContent@Assets@Types@OneMe@Api@@@Serialization@@";
    let smember_r0 = format!("??_R0{}@8", &smember[1..]);
    let smember_dem = msvc_demangler::demangle(&smember_r0, msvc_demangler::DemangleFlags::COMPLETE).unwrap();
    println!("Smember demangled: {:?}", smember_dem);
}

#[test]
fn test_rtti_engine_build() {
    let dll_path = PathBuf::from("../../dev/CM_FP_Unspecified.core.dll");
    assert!(dll_path.exists());
    let bytes = fs::read(&dll_path).expect("Failed to read DLL");
    let pe = PeImage::parse(&bytes).expect("Failed to parse PE image");

    let rtti = RttiEngine::build(&pe).expect("Failed to build RTTI engine");

    assert!(
        !rtti.type_descriptors.is_empty(),
        "Should find type descriptors"
    );

    assert!(
        !rtti.vtable_to_type.is_empty(),
        "Should find vtables"
    );

    assert!(
        !rtti.smember_vtables.is_empty(),
        "smember_vtables must not be empty"
    );

    let derived = rtti.hierarchy.derived_of("Api::OneMe::Types::BaseAttachment");
    assert!(derived.is_some(), "BaseAttachment must have derived types");
    let derived_list = derived.unwrap();
    assert!(
        derived_list.len() > 5,
        "BaseAttachment should have multiple derived types, got {}",
        derived_list.len()
    );

    let event_params = rtti.hierarchy.derived_of("Api::OneMe::Types::Log::EventParams");
    assert!(event_params.is_some());
    assert!(event_params.unwrap().len() > 10);

    let outgoing = rtti.hierarchy.derived_of("Api::OneMe::Types::Outgoing::BaseAttachment");
    assert!(outgoing.is_some());
    assert!(outgoing.unwrap().len() > 5);

    // Check known models in type_to_vtable
    assert!(rtti.type_to_vtable.contains_key("Api::OneMe::Types::ServerSettings"));
    assert!(rtti.type_to_vtable.contains_key("Api::OneMe::Packets::Log::Parameters"));
    assert!(rtti.type_to_vtable.contains_key("Api::OneMe::Packets::SessionInit::Payload"));
}
