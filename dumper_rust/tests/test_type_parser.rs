use dumper_rust::type_parser::{
    cpp_to_ident, cpp_to_ident_uncollapsed, decompose_type, derive_event_operation,
    derive_packet_operation, normalize_type, qualify_endpoint_ident,
};

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

#[test]
fn test_nested_qualifier_stripping() {
    assert_eq!(
        normalize_type("ClickParams<struct Api::OneMe::Types::Log::CalloutScreenMeta>"),
        "ClickParams<Api::OneMe::Types::Log::CalloutScreenMeta>"
    );
    assert_eq!(
        normalize_type(
            "struct Api::OneMe::Types::Log::ClickParams<struct Api::OneMe::Types::Log::CalloutScreenMeta>"
        ),
        "Api::OneMe::Types::Log::ClickParams<Api::OneMe::Types::Log::CalloutScreenMeta>"
    );
    assert_eq!(
        normalize_type(
            "const volatile class std::optional<const struct Api::OneMe::Types::Outer<enum Api::OneMe::Types::Kind, union Api::OneMe::Types::RawUnion>>"
        ),
        "std::optional<Api::OneMe::Types::Outer<Api::OneMe::Types::Kind, Api::OneMe::Types::RawUnion>>"
    );
}

#[test]
fn test_strong_typedef_unwrapping() {
    let raw = "struct Utilities::StrongTypedef<class std::optional<__int64>,struct Api::OneMe::Types::ServerSettings::AbStatusTag,0>";
    assert_eq!(normalize_type(raw), "std::optional<int64_t>");

    let d = decompose_type(raw);
    assert_eq!(d.full, "std::optional<int64_t>");
    assert_eq!(d.name.as_deref(), Some("int64_t"));
    assert_eq!(d.ident, None);
    assert!(d.optional);
    assert!(!d.array);
    assert!(!d.bytes);
    assert!(!d.map);
}

#[test]
fn test_bytes_flag_detection() {
    let byte_vec = decompose_type("class std::vector<enum std::byte>");
    assert_eq!(byte_vec.full, "std::vector<std::byte>");
    assert_eq!(byte_vec.name.as_deref(), Some("std::byte"));
    assert_eq!(byte_vec.ident, None);
    assert!(byte_vec.array);
    assert!(byte_vec.bytes);

    let char_vec = decompose_type("std::optional<std::vector<signed char>>");
    assert_eq!(char_vec.full, "std::optional<std::vector<char>>");
    assert_eq!(char_vec.name.as_deref(), Some("char"));
    assert_eq!(char_vec.ident, None);
    assert!(char_vec.optional);
    assert!(char_vec.array);
    assert!(char_vec.bytes);

    let scalar_char = decompose_type("char");
    assert!(!scalar_char.array);
    assert!(!scalar_char.bytes);

    let int_vec = decompose_type("std::vector<int32_t>");
    assert!(int_vec.array);
    assert!(!int_vec.bytes);
}

#[test]
fn test_cpp_to_ident_rules_and_collisions() {
    // Prefix stripping & duplicate category prefix collapsing
    assert_eq!(cpp_to_ident("Api::OneMe::Types::Message"), "Message");
    assert_eq!(
        cpp_to_ident("Api::OneMe::Types::Contact::ContactInfo"),
        "ContactInfo"
    );
    assert_eq!(
        cpp_to_ident("Api::OneMe::Types::Stories::StoriesList"),
        "StoriesList"
    );
    assert_eq!(
        cpp_to_ident("Api::OneMe::Packets::Auth::OneMe::TokenAttributes"),
        "AuthTokenAttributes"
    );
    assert_eq!(
        cpp_to_ident("Auth::OneMe::TokenAttributes"),
        "TokenAttributes"
    );
    assert_eq!(
        cpp_to_ident("Api::OneMe::Packets::Events::SessionInit::Response"),
        "SessionInitResponse"
    );
    assert_eq!(
        cpp_to_ident("Api::OneMe::Events::Telemetry::Request"),
        "TelemetryRequest"
    );

    // Deterministic collision resolution: EventParams vs LogEventParams
    assert_eq!(
        cpp_to_ident("Api::OneMe::Types::Log::EventParams"),
        "LogEventParams"
    );
    assert_eq!(
        cpp_to_ident("Api::OneMe::Types::Log::LogEventParams"),
        "LogLogEventParams"
    );
    assert_eq!(
        cpp_to_ident_uncollapsed("Api::OneMe::Types::Log::LogEventParams"),
        "LogLogEventParams"
    );

    // Template concatenation with inner struct qualifier
    assert_eq!(
        cpp_to_ident(
            "Api::OneMe::Types::Log::ClickParams<struct Api::OneMe::Types::Log::CalloutScreenMeta>"
        ),
        "LogClickParamsLogCalloutScreenMeta"
    );
}

#[test]
fn test_operation_and_endpoint_ident_helpers() {
    let (op_name, op_ident) = derive_packet_operation(
        19,
        "Api::OneMe::Packets::Auth::OneMe::Auth::Parameters",
        "Api::OneMe::Packets::Auth::OneMe::Auth::Response",
    );
    assert_eq!(op_name, "Api::OneMe::Packets::Auth::OneMe::Auth");
    assert_eq!(op_ident, "Auth");

    let (asset_name, asset_ident) = derive_packet_operation(
        26,
        "Api::OneMe::Packets::Assets::GetAsset::Common::Parameters",
        "Api::OneMe::Packets::Assets::GetAsset::StickerSet::Response",
    );
    assert_eq!(asset_name, "Api::OneMe::Packets::Assets::GetAsset");
    assert_eq!(asset_ident, "AssetsGetAsset");

    let (empty_name, empty_ident) = derive_packet_operation(
        20,
        "Api::OneMe::Packets::EmptyParameters",
        "Api::OneMe::Packets::EmptyResponse",
    );
    assert_eq!(empty_name, "Api::OneMe::Packets::Opcode20");
    assert_eq!(empty_ident, "Opcode20");

    let (ev_name, ev_ident) = derive_event_operation(
        1,
        Some("Api::OneMe::Packets::Ping"),
        "Api::OneMe::Packets::Ping::Payload",
        "",
    );
    assert_eq!(ev_name, "Api::OneMe::Packets::Ping");
    assert_eq!(ev_ident, "Ping");

    assert_eq!(
        qualify_endpoint_ident("Ping", "Api::OneMe::Packets::EmptyParameters"),
        "EmptyParameters"
    );
    assert_eq!(
        qualify_endpoint_ident("Ping", "Api::OneMe::Packets::Payload"),
        "PingPayload"
    );
}

#[test]
fn test_recursive_map_decomposition_and_ident_population() {
    let raw =
        "std::optional<std::unordered_map<int64_t, std::vector<Api::OneMe::Types::Message>>>";
    let d = decompose_type(raw);

    assert_eq!(
        d.full,
        "std::optional<std::unordered_map<int64_t, std::vector<Api::OneMe::Types::Message>>>"
    );
    assert_eq!(d.name, None);
    assert_eq!(d.ident, None);
    assert!(d.optional);
    assert!(!d.array);
    assert!(!d.bytes);
    assert!(d.map);
    assert_eq!(d.map_key.as_deref(), Some("int64_t"));
    assert_eq!(
        d.map_value.as_deref(),
        Some("std::vector<Api::OneMe::Types::Message>")
    );

    let key_type = d.map_key_type.as_ref().expect("map_key_type must be Some");
    assert_eq!(key_type.full, "int64_t");
    assert_eq!(key_type.name.as_deref(), Some("int64_t"));
    assert_eq!(key_type.ident, None);
    assert!(!key_type.optional);
    assert!(!key_type.array);
    assert!(!key_type.bytes);
    assert!(!key_type.map);
    assert!(!key_type.polymorphic);

    let val_type = d
        .map_value_type
        .as_ref()
        .expect("map_value_type must be Some");
    assert_eq!(val_type.full, "std::vector<Api::OneMe::Types::Message>");
    assert_eq!(val_type.name.as_deref(), Some("Api::OneMe::Types::Message"));
    assert_eq!(val_type.ident.as_deref(), Some("Message"));
    assert!(!val_type.optional);
    assert!(val_type.array);
    assert!(!val_type.bytes);
    assert!(!val_type.map);
    assert!(!val_type.polymorphic);

    let poly_d = decompose_type(
        "std::optional<Api::OneMe::Types::Polymorphic<Api::OneMe::Types::BaseAttachment>>",
    );
    assert_eq!(
        poly_d.name.as_deref(),
        Some("Api::OneMe::Types::BaseAttachment")
    );
    assert_eq!(poly_d.ident.as_deref(), Some("BaseAttachment"));

    let json_val = serde_json::to_value(&d).expect("DecomposedType must serialize to JSON");
    assert_eq!(
        json_val,
        serde_json::json!({
            "full": "std::optional<std::unordered_map<int64_t, std::vector<Api::OneMe::Types::Message>>>",
            "name": null,
            "ident": null,
            "optional": true,
            "array": false,
            "bytes": false,
            "map": true,
            "map_key": "int64_t",
            "map_value": "std::vector<Api::OneMe::Types::Message>",
            "map_key_type": {
                "full": "int64_t",
                "name": "int64_t",
                "ident": null,
                "optional": false,
                "array": false,
                "bytes": false,
                "map": false,
                "polymorphic": false
            },
            "map_value_type": {
                "full": "std::vector<Api::OneMe::Types::Message>",
                "name": "Api::OneMe::Types::Message",
                "ident": "Message",
                "optional": false,
                "array": true,
                "bytes": false,
                "map": false,
                "polymorphic": false
            },
            "polymorphic": false
        })
    );
}
