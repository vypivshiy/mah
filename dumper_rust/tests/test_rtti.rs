use dumper_rust::pe::PeImage;
use dumper_rust::rtti::{extract_smember_metadata, RttiEngine};
use dumper_rust::type_parser::decompose_type;
use std::fs;

mod common;
use common::resolve_env_path;

fn serializable_member_rtti(value_type: &str, owner_type: &str) -> String {
    format!(
        "class Serialization::SerializableMember<{value_type},class Serialization::Msgpack::SerializedType,class std::basic_string_view<char,struct std::char_traits<char> >,{owner_type}>::`RTTI Type Descriptor'"
    )
}

#[test]
fn test_extract_smember_metadata_preserves_owner_for_supported_value_shapes() {
    let owner = "struct Api::OneMe::Types::OwnerModel";
    let cases = [
        ("normal", "int", "int32_t", Some("int32_t"), false, false, false, None, None, None),
        (
            "optional",
            "class std::optional<struct Api::OneMe::Types::Contact>",
            "std::optional<Api::OneMe::Types::Contact>",
            Some("Api::OneMe::Types::Contact"),
            true,
            false,
            false,
            None,
            None,
            None,
        ),
        (
            "vector",
            "class std::vector<struct Api::OneMe::Types::Contact,class std::allocator<struct Api::OneMe::Types::Contact> >",
            "std::vector<Api::OneMe::Types::Contact>",
            Some("Api::OneMe::Types::Contact"),
            false,
            true,
            false,
            None,
            None,
            None,
        ),
        (
            "map",
            "class std::unordered_map<class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> >,unsigned __int64>",
            "std::unordered_map<std::string, uint64_t>",
            None,
            false,
            false,
            true,
            Some("std::string"),
            Some("uint64_t"),
            None,
        ),
        (
            "polymorphic",
            "class Api::OneMe::Types::Polymorphic<struct Api::OneMe::Types::BaseAttachment>",
            "Api::OneMe::Types::Polymorphic<Api::OneMe::Types::BaseAttachment>",
            Some("Api::OneMe::Types::BaseAttachment"),
            false,
            false,
            false,
            None,
            None,
            Some("Api::OneMe::Types::BaseAttachment"),
        ),
    ];

    for (
        case_name,
        value_type,
        expected_full,
        expected_name,
        optional,
        array,
        map,
        map_key,
        map_value,
        polymorphic_base,
    ) in cases
    {
        let demangled = serializable_member_rtti(value_type, owner);
        let metadata = extract_smember_metadata(&demangled, "")
            .unwrap_or_else(|| panic!("{case_name}: expected SerializableMember metadata"));
        assert_eq!(
            metadata.owner_type.as_deref(),
            Some("Api::OneMe::Types::OwnerModel"),
            "{case_name}: owner type"
        );

        let decomposed = decompose_type(&metadata.value_type);
        assert_eq!(
            decomposed.full, expected_full,
            "{case_name}: normalized full type"
        );
        assert_eq!(
            decomposed.name.as_deref(),
            expected_name,
            "{case_name}: extracted name"
        );
        assert_eq!(decomposed.optional, optional, "{case_name}: optional flag");
        assert_eq!(decomposed.array, array, "{case_name}: array flag");
        assert_eq!(decomposed.map, map, "{case_name}: map flag");
        assert_eq!(
            decomposed.map_key.as_deref(),
            map_key,
            "{case_name}: map key"
        );
        assert_eq!(
            decomposed.map_value.as_deref(),
            map_value,
            "{case_name}: map value"
        );
        assert_eq!(
            decomposed.polymorphic_base.as_deref(),
            polymorphic_base,
            "{case_name}: polymorphic base"
        );
    }
}

#[test]
fn test_demangle_sample() {
    let raw = ".?AUUpdateContent@Assets@Types@OneMe@Api@@";
    let r0_symbol = format!("??_R0{}@8", &raw[1..]);
    let demangled =
        msvc_demangler::demangle(&r0_symbol, msvc_demangler::DemangleFlags::COMPLETE).unwrap();
    println!("Demangled with R0: {:?}", demangled);

    let smember = ".?AV?$SerializableMember@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@VSerializedType@Msgpack@Serialization@@V?$basic_string_view@DU?$char_traits@D@std@@@2@UUpdateContent@Assets@Types@OneMe@Api@@@Serialization@@";
    let smember_r0 = format!("??_R0{}@8", &smember[1..]);
    let smember_dem =
        msvc_demangler::demangle(&smember_r0, msvc_demangler::DemangleFlags::COMPLETE).unwrap();
    println!("Smember demangled: {:?}", smember_dem);
}

#[test]
fn test_rtti_engine_build() {
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

    assert!(
        !rtti.type_descriptors.is_empty(),
        "Should find type descriptors"
    );

    assert!(!rtti.vtable_to_type.is_empty(), "Should find vtables");

    assert!(
        !rtti.smember_vtables.is_empty(),
        "smember_vtables must not be empty"
    );

    let derived = rtti
        .hierarchy
        .derived_of("Api::OneMe::Types::BaseAttachment");
    assert!(derived.is_some(), "BaseAttachment must have derived types");
    let derived_list = derived.unwrap();
    assert!(
        derived_list.len() > 5,
        "BaseAttachment should have multiple derived types, got {}",
        derived_list.len()
    );

    let event_params = rtti
        .hierarchy
        .derived_of("Api::OneMe::Types::Log::EventParams");
    assert!(event_params.is_some());
    assert!(event_params.unwrap().len() > 10);

    let outgoing = rtti
        .hierarchy
        .derived_of("Api::OneMe::Types::Outgoing::BaseAttachment");
    assert!(outgoing.is_some());
    assert!(outgoing.unwrap().len() > 5);

    // Check known models in type_to_vtable
    assert!(rtti
        .type_to_vtable
        .contains_key("Api::OneMe::Types::ServerSettings"));
    assert!(rtti
        .type_to_vtable
        .contains_key("Api::OneMe::Packets::Log::Parameters"));
    assert!(rtti
        .type_to_vtable
        .contains_key("Api::OneMe::Packets::SessionInit::Payload"));
}
