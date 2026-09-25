use dumper_rust::type_parser::{decompose_type, normalize_type};

#[test]
fn test_normalize_basic_types() {
    let raw_str =
        "class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> >";
    assert_eq!(normalize_type(raw_str), "std::string");

    let raw_vec = "class std::vector<class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> >,class std::allocator<class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> > > >";
    assert_eq!(normalize_type(raw_vec), "std::vector<std::string>");
}

#[test]
fn test_decompose_optional_vector() {
    let raw = "class std::optional<class std::vector<struct Api::OneMe::Types::Contact> >";
    let d = decompose_type(raw);
    assert_eq!(
        d.full,
        "std::optional<std::vector<Api::OneMe::Types::Contact>>"
    );
    assert_eq!(d.name.as_deref(), Some("Api::OneMe::Types::Contact"));
    assert!(d.optional);
    assert!(d.array);
    assert!(!d.map);
    assert!(!d.polymorphic);
}

#[test]
fn test_decompose_map() {
    let raw = "std::unordered_map<std::string, uint64_t>";
    let d = decompose_type(raw);
    assert!(d.map);
    assert_eq!(d.map_key.as_deref(), Some("std::string"));
    assert_eq!(d.map_value.as_deref(), Some("uint64_t"));
    assert_eq!(d.name, None);
}

#[test]
fn test_decompose_nested_map() {
    let raw =
        "std::optional<std::unordered_map<std::string, std::unordered_map<std::string, int>>>";
    let d = decompose_type(raw);

    assert_eq!(
        d.full,
        "std::optional<std::unordered_map<std::string, std::unordered_map<std::string, int32_t>>>"
    );
    assert!(d.optional);
    assert!(d.map);
    assert_eq!(d.map_key.as_deref(), Some("std::string"));
    assert_eq!(
        d.map_value.as_deref(),
        Some("std::unordered_map<std::string, int32_t>")
    );
    assert_eq!(d.name, None);
}

#[test]
fn test_decompose_polymorphic() {
    let raw = "std::optional<std::shared_ptr<Api::OneMe::Types::Polymorphic<Api::OneMe::Types::BaseAttachment>>>";
    let d = decompose_type(raw);
    assert!(d.polymorphic);
    assert_eq!(
        d.polymorphic_base.as_deref(),
        Some("Api::OneMe::Types::BaseAttachment")
    );
    assert_eq!(d.name.as_deref(), Some("Api::OneMe::Types::BaseAttachment"));
    assert!(d.optional);
    assert!(!d.array);
}

#[test]
fn test_decompose_unwrapped_polymorphic_base() {
    let raw = "Api::OneMe::Types::Polymorphic<Api::OneMe::Types::BaseAttachment>";
    let d = decompose_type(raw);

    assert_eq!(
        d.full,
        "Api::OneMe::Types::Polymorphic<Api::OneMe::Types::BaseAttachment>"
    );
    assert!(d.polymorphic);
    assert_eq!(
        d.polymorphic_base.as_deref(),
        Some("Api::OneMe::Types::BaseAttachment")
    );
    assert_eq!(d.name.as_deref(), Some("Api::OneMe::Types::BaseAttachment"));
    assert!(!d.optional);
}

#[test]
fn test_known_nested_token_attrs_and_counters_shapes() {
    let token_attrs = decompose_type(
        "std::optional<std::unordered_map<std::string, Api::OneMe::Types::TokenAttributes>>",
    );
    assert_eq!(
        token_attrs.full,
        "std::optional<std::unordered_map<std::string, Api::OneMe::Types::TokenAttributes>>"
    );
    assert!(token_attrs.optional);
    assert!(token_attrs.map);
    assert_eq!(token_attrs.map_key.as_deref(), Some("std::string"));
    assert_eq!(
        token_attrs.map_value.as_deref(),
        Some("Api::OneMe::Types::TokenAttributes")
    );

    let counters = decompose_type("std::optional<std::unordered_map<std::string, int>>");
    assert_eq!(
        counters.full,
        "std::optional<std::unordered_map<std::string, int32_t>>"
    );
    assert!(counters.optional);
    assert!(counters.map);
    assert_eq!(counters.map_key.as_deref(), Some("std::string"));
    assert_eq!(counters.map_value.as_deref(), Some("int32_t"));
}

#[test]
fn test_concise_compact_type_display_shapes() {
    let d = decompose_type("class std::optional<class std::vector<signed char> >");

    assert_eq!(d.full, "std::optional<std::vector<char>>");
    assert!(!d.full.contains("class "));
    assert!(!d.full.contains("struct "));
    assert!(!d.full.contains("basic_string"));
    assert!(!d.full.contains("signed char"));
}

#[test]
fn test_canonical_primitive_type_normalization() {
    // std::optional<int> -> int32_t, std::optional<int32_t>
    let d1 = decompose_type("std::optional<int>");
    assert_eq!(d1.name.as_deref(), Some("int32_t"));
    assert_eq!(d1.full, "std::optional<int32_t>");
    assert!(d1.optional);

    // signed char -> char
    let d2 = decompose_type("signed char");
    assert_eq!(d2.name.as_deref(), Some("char"));
    assert_eq!(d2.full, "char");
    assert!(!d2.optional);

    // std::vector<__int64> -> int64_t, std::vector<int64_t>
    let d3 = decompose_type("std::vector<__int64>");
    assert_eq!(d3.name.as_deref(), Some("int64_t"));
    assert_eq!(d3.full, "std::vector<int64_t>");
    assert!(d3.array);

    // short -> int16_t
    let d4 = decompose_type("short");
    assert_eq!(d4.name.as_deref(), Some("int16_t"));
    assert_eq!(d4.full, "int16_t");

    // unsigned int -> uint32_t
    let d5 = decompose_type("unsigned int");
    assert_eq!(d5.name.as_deref(), Some("uint32_t"));
    assert_eq!(d5.full, "uint32_t");

    // unsigned __int64 -> uint64_t
    let d6 = decompose_type("unsigned __int64");
    assert_eq!(d6.name.as_deref(), Some("uint64_t"));
    assert_eq!(d6.full, "uint64_t");

    // unsigned short -> uint16_t
    let d7 = decompose_type("unsigned short");
    assert_eq!(d7.name.as_deref(), Some("uint16_t"));
    assert_eq!(d7.full, "uint16_t");

    // unsigned char -> uint8_t
    let d8 = decompose_type("unsigned char");
    assert_eq!(d8.name.as_deref(), Some("uint8_t"));
    assert_eq!(d8.full, "uint8_t");
}
