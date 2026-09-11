use dumper_rust::type_parser::{decompose_type, normalize_type};

#[test]
fn test_normalize_basic_types() {
    let raw_str = "class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> >";
    assert_eq!(normalize_type(raw_str), "std::string");

    let raw_vec = "class std::vector<class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> >,class std::allocator<class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> > > >";
    assert_eq!(normalize_type(raw_vec), "std::vector<std::string>");
}

#[test]
fn test_decompose_optional_vector() {
    let raw = "class std::optional<class std::vector<struct Api::OneMe::Types::Contact> >";
    let d = decompose_type(raw);
    assert_eq!(d.full, "std::optional<std::vector<Api::OneMe::Types::Contact>>");
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
fn test_decompose_polymorphic() {
    let raw = "std::optional<std::shared_ptr<Api::OneMe::Types::Polymorphic<Api::OneMe::Types::BaseAttachment>>>";
    let d = decompose_type(raw);
    assert!(d.polymorphic);
    assert_eq!(d.polymorphic_base.as_deref(), Some("Api::OneMe::Types::BaseAttachment"));
    assert_eq!(d.name.as_deref(), Some("Api::OneMe::Types::BaseAttachment"));
    assert!(d.optional);
    assert!(!d.array);
}
