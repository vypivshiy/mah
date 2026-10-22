use dumper_rust::compact::{format_compact_dump, format_compact_dump_with_options};
use dumper_rust::dumper::{
    DumpResult, EventEntry, ModelEntry, OptionsInfo, PolymorphicBase, PolymorphicDiscriminator,
    PolymorphicModelEntry, PolymorphicVariant, TypeDescriptorEntry,
};
use dumper_rust::extractor::ExtractedField;
use dumper_rust::type_parser::{cpp_to_ident, decompose_type};

fn field(name: &str, type_name: &str, required: bool) -> ExtractedField {
    ExtractedField {
        name: name.to_string(),
        field_type: decompose_type(type_name),
        required,
    }
}

fn type_entry(
    name: &str,
    offset: &str,
    warn: Option<&str>,
    fields: Vec<ExtractedField>,
) -> TypeDescriptorEntry {
    TypeDescriptorEntry {
        offset: Some(offset.to_string()),
        name: name.to_string(),
        ident: cpp_to_ident(name),
        fields,
        warn: warn.map(str::to_string),
    }
}

fn model_entry(
    name: &str,
    offset: &str,
    warn: Option<&str>,
    fields: Vec<ExtractedField>,
) -> ModelEntry {
    ModelEntry {
        name: name.to_string(),
        ident: cpp_to_ident(name),
        offset: Some(offset.to_string()),
        fields,
        warn: warn.map(str::to_string),
    }
}

fn variant(
    name: &str,
    offset: &str,
    fields: Vec<ExtractedField>,
    all_fields: Vec<ExtractedField>,
    tag: Option<&str>,
) -> PolymorphicVariant {
    PolymorphicVariant {
        name: name.to_string(),
        ident: cpp_to_ident(name),
        offset: Some(offset.to_string()),
        fields,
        all_fields,
        tag: tag.map(str::to_string),
    }
}

fn synthetic_dump() -> DumpResult {
    let alpha_request = type_entry(
        "Api::OneMe::Packets::Alpha::Request",
        "0x10",
        None,
        vec![
            field("first", "int", true),
            field("second", "std::string", false),
        ],
    );
    let alpha_response = type_entry(
        "Api::OneMe::Packets::Alpha::Response",
        "0x11",
        None,
        Vec::new(),
    );
    let zeta_request = type_entry(
        "Api::OneMe::Packets::Zeta::Request",
        "0x20",
        Some("no data found"),
        Vec::new(),
    );
    let zeta_response = type_entry(
        "Api::OneMe::Packets::Zeta::Response",
        "0x21",
        None,
        vec![field("ok", "bool", false)],
    );

    let base_field = field("_type", "std::string", false);
    let variant_field = field("url", "std::string", false);
    let alpha_variant = variant(
        "Api::OneMe::Types::AlphaVariant",
        "0x71",
        vec![variant_field.clone()],
        vec![base_field.clone(), variant_field],
        Some("ALPHA"),
    );

    DumpResult {
        options: OptionsInfo {
            version: "5.6.7".to_string(),
            build: 890,
            protocol_version: None,
            config: None,
        },
        packets: vec![
            dumper_rust::dumper::PacketEntry {
                opcode: 20,
                name: "Api::OneMe::Packets::Zeta".to_string(),
                ident: "Zeta".to_string(),
                request: zeta_request,
                response: zeta_response,
            },
            dumper_rust::dumper::PacketEntry {
                opcode: 10,
                name: "Api::OneMe::Packets::Alpha".to_string(),
                ident: "Alpha".to_string(),
                request: alpha_request,
                response: alpha_response,
            },
        ],
        events: vec![
            EventEntry {
                opcode: 9,
                kind: Some("special_packet".to_string()),
                name: "Api::OneMe::Packets::Ping".to_string(),
                ident: "Ping".to_string(),
                base_kind: Some("Api::OneMe::Packets::BaseEvent".to_string()),
                offset: Some("0x40".to_string()),
                request: Some(type_entry(
                    "Api::OneMe::Packets::Ping::Payload",
                    "0x40",
                    None,
                    vec![field("interactive", "bool", false)],
                )),
                response: None,
                warn: Some("event incomplete".to_string()),
            },
            EventEntry {
                opcode: 2,
                kind: None,
                name: "Api::OneMe::Events::Beta".to_string(),
                ident: "Beta".to_string(),
                base_kind: None,
                offset: None,
                request: Some(type_entry(
                    "Api::OneMe::Events::Beta::Request",
                    "0x30",
                    None,
                    Vec::new(),
                )),
                response: Some(type_entry(
                    "Api::OneMe::Events::Beta::Response",
                    "0x31",
                    Some("no response data"),
                    Vec::new(),
                )),
                warn: None,
            },
        ],
        models: vec![
            model_entry(
                "Api::OneMe::Types::Zeta",
                "0x60",
                Some("model no data"),
                Vec::new(),
            ),
            model_entry(
                "Api::OneMe::Types::Alpha",
                "0x50",
                None,
                vec![field("id", "__int64", false)],
            ),
        ],
        polymorphic_models: vec![
            PolymorphicModelEntry {
                name: "Api::OneMe::Types::ZetaBase".to_string(),
                ident: "ZetaBase".to_string(),
                root_sources: vec!["rtti_heuristic".to_string()],
                discriminator: None,
                base: PolymorphicBase {
                    offset: Some("0x80".to_string()),
                    fields: Vec::new(),
                },
                variants: Vec::new(),
                rtti_subclasses: Vec::new(),
            },
            PolymorphicModelEntry {
                name: "Api::OneMe::Types::AlphaBase".to_string(),
                ident: "AlphaBase".to_string(),
                root_sources: vec!["rtti_heuristic".to_string(), "protocol_field".to_string()],
                discriminator: Some(PolymorphicDiscriminator {
                    field: "_type".to_string(),
                    r#type: "std::string".to_string(),
                }),
                base: PolymorphicBase {
                    offset: Some("0x70".to_string()),
                    fields: vec![base_field],
                },
                variants: vec![alpha_variant.clone()],
                rtti_subclasses: vec![PolymorphicVariant {
                    tag: None,
                    ..alpha_variant
                }],
            },
        ],
        enums: Default::default(),
        discriminators: Default::default(),
        string_enums: Some(vec!["ZULU".to_string(), "ALPHA".to_string(), "BETA".to_string()]),
        error: serde_json::json!({}),
    }
}

#[test]
fn compact_formatter_emits_stable_line_oriented_output() {
    let formatted = format_compact_dump(&synthetic_dump());

    let expected = concat!(
        "app_version: 5.6.7\n",
        "build_number: 890\n",
        "\n",
        "Packets\n",
        "packet opcode=10\n",
        "  request Api::OneMe::Packets::Alpha::Request\n",
        "  request field first: int32_t\n",
        "  request field second: std::string\n",
        "  response Api::OneMe::Packets::Alpha::Response\n",
        "packet opcode=20\n",
        "  request Api::OneMe::Packets::Zeta::Request\n",
        "  request warn: no data found\n",
        "  response Api::OneMe::Packets::Zeta::Response\n",
        "  response field ok: bool\n",
        "\n",
        "Events\n",
        "event opcode=2\n",
        "  request Api::OneMe::Events::Beta::Request\n",
        "  response Api::OneMe::Events::Beta::Response\n",
        "  response warn: no response data\n",
        "event opcode=9\n",
        "  kind: special_packet\n",
        "  name: Api::OneMe::Packets::Ping\n",
        "  base_kind: Api::OneMe::Packets::BaseEvent\n",
        "  warn: event incomplete\n",
        "  request Api::OneMe::Packets::Ping::Payload\n",
        "  request field interactive: bool\n",
        "\n",
        "Models\n",
        "model Api::OneMe::Types::Alpha\n",
        "  field id: int64_t\n",
        "model Api::OneMe::Types::Zeta\n",
        "  warn: model no data\n",
        "\n",
        "Polymorphic Models\n",
        "polymorphic Api::OneMe::Types::AlphaBase\n",
        "  root_sources: protocol_field, rtti_heuristic\n",
        "  discriminator: _type: std::string\n",
        "  base fields=1\n",
        "  variant Api::OneMe::Types::AlphaVariant local_fields=1 all_fields=2 tag=ALPHA\n",
        "  rtti_subclass Api::OneMe::Types::AlphaVariant local_fields=1 all_fields=2\n",
        "polymorphic Api::OneMe::Types::ZetaBase\n",
        "  root_sources: rtti_heuristic\n",
        "  base fields=0\n",
        "\n",
        "String Enums\n",
        "string_enum ALPHA\n",
        "string_enum BETA\n",
        "string_enum ZULU\n",
    );

    assert_eq!(formatted, expected);
}

#[test]
fn compact_formatter_keeps_header_metadata_stable_and_omits_noisy_fields() {
    let formatted = format_compact_dump(&synthetic_dump());

    assert!(formatted.contains("app_version: 5.6.7"));
    assert!(formatted.contains("build_number: 890"));
    assert!(!formatted.contains("timestamp"));
    assert!(!formatted.contains("image_base"));
    assert!(!formatted.contains("required"));
    assert!(!formatted.contains('|'));
    assert!(!formatted.contains("rva="));
}

#[test]
fn compact_formatter_summarizes_polymorphic_groups_without_expanding_fields() {
    let formatted = format_compact_dump(&synthetic_dump());
    let polymorphic_section = formatted
        .split("Polymorphic Models\n")
        .nth(1)
        .expect("polymorphic section must exist")
        .split("\nString Enums")
        .next()
        .unwrap();

    assert!(polymorphic_section.contains(
        "variant Api::OneMe::Types::AlphaVariant local_fields=1 all_fields=2 tag=ALPHA"
    ));
    assert!(polymorphic_section.contains(
        "rtti_subclass Api::OneMe::Types::AlphaVariant local_fields=1 all_fields=2"
    ));
    assert!(!polymorphic_section.contains("wire_variant"));
    assert!(!polymorphic_section.contains("rtti_variant"));
    assert!(!polymorphic_section.contains("discriminator_value"));
    assert!(!polymorphic_section.contains("field _type"));
    assert!(!polymorphic_section.contains("field url"));
}

#[test]
fn compact_formatter_omits_discriminator_line_when_none() {
    let mut dump = synthetic_dump();
    dump.polymorphic_models = vec![PolymorphicModelEntry {
        name: "Api::OneMe::Types::Log::EventParams".to_string(),
        ident: "LogEventParams".to_string(),
        root_sources: vec!["protocol_field".to_string()],
        discriminator: None,
        base: PolymorphicBase {
            offset: Some("0x100".to_string()),
            fields: vec![field("common", "int32_t", false)],
        },
        variants: vec![variant(
            "Api::OneMe::Types::Log::CallEventParams",
            "0x110",
            vec![field("duration", "int32_t", false)],
            vec![
                field("common", "int32_t", false),
                field("duration", "int32_t", false),
            ],
            None,
        )],
        rtti_subclasses: Vec::new(),
    }];

    let formatted = format_compact_dump(&dump);
    assert!(formatted.contains("polymorphic Api::OneMe::Types::Log::EventParams\n"));
    assert!(!formatted.contains("discriminator:"));
    assert!(formatted.contains("  variant Api::OneMe::Types::Log::CallEventParams local_fields=1 all_fields=2\n"));
}

#[test]
fn compact_formatter_with_rva_option_includes_rvas() {
    let formatted = format_compact_dump_with_options(&synthetic_dump(), true);
    assert!(formatted.contains("rva=0x10"));
    assert!(formatted.contains("rva: 0x40"));
    assert!(formatted.contains(
        "variant Api::OneMe::Types::AlphaVariant rva=0x71 local_fields=1 all_fields=2 tag=ALPHA"
    ));
}

#[test]
fn compact_formatter_sorts_string_enums_alphabetically() {
    let formatted = format_compact_dump(&synthetic_dump());
    let alpha = formatted
        .find("string_enum ALPHA")
        .expect("ALPHA string enum must be present");
    let beta = formatted
        .find("string_enum BETA")
        .expect("BETA string enum must be present");
    let zulu = formatted
        .find("string_enum ZULU")
        .expect("ZULU string enum must be present");

    assert!(alpha < beta && beta < zulu);
}
