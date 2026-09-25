use dumper_rust::dumper::{
    build_model_catalog, Dumper, DumperOptions, PolymorphicBase, PolymorphicDiscriminator,
    PolymorphicModelEntry, PolymorphicVariant, TypeDescriptorEntry,
};
use dumper_rust::extractor::ExtractedField;
use dumper_rust::pe::PeImage;
use dumper_rust::rtti::RttiEngine;
use dumper_rust::scanner::ProtocolScanner;
use dumper_rust::type_parser::decompose_type;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::{Duration, Instant};

mod common;
use common::resolve_env_path;

#[test]
fn test_dumper_full_pipeline_structural_invariants() {
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
    let scanner = ProtocolScanner::scan(&pe, &rtti).expect("Failed to scan protocol entities");

    // Pass empty options to test dynamic version detection from DLL
    let options = DumperOptions {
        version: dumper_rust::dumper::AppVersion {
            version: String::new(),
            build: 0,
        },
    };

    let start_time = Instant::now();
    let result = Dumper::dump(&pe, &rtti, &scanner, &options).expect("Failed to execute dumper");
    let dump_duration = start_time.elapsed();

    // Performance SLA assertion: complete model dump must finish within 20 seconds.
    assert!(
        dump_duration < Duration::from_secs(20),
        "Dump exceeded 20s SLA: {:?}",
        dump_duration
    );

    // 1. Dynamic version invariant in canonical Binja format
    assert!(
        !result.options.version.is_empty(),
        "App version must be dynamically detected"
    );
    assert!(result.options.build > 0, "Build number must be positive");

    // 2. Packets invariants (exactly 128 packets)
    assert_eq!(
        result.packets.len(),
        128,
        "Must discover exactly 128 packets"
    );
    let mut packet_opcodes = HashSet::new();
    for p in &result.packets {
        let opcode = p.opcode;
        assert!(opcode > 0, "Opcode must be positive");
        assert!(
            packet_opcodes.insert(opcode),
            "Duplicate packet opcode: {}",
            opcode
        );
        assert!(!p.request.name.is_empty());
        assert!(!p.response.name.is_empty());
    }

    // 3. Events invariants (exactly 24 events)
    assert_eq!(result.events.len(), 24, "Must discover exactly 24 events");
    let mut event_opcodes = HashSet::new();
    for e in &result.events {
        let opcode = e.opcode;
        assert!(opcode > 0, "Event opcode must be positive");
        assert!(
            event_opcodes.insert(opcode),
            "Duplicate event opcode: {}",
            opcode
        );
    }
    assert!(
        result
            .events
            .iter()
            .any(|e| e.kind.as_deref() == Some("special_packet")),
        "Must contain special factory packet (e.g. Ping)"
    );

    // 4. Polymorphic models invariants: 4 roots present
    assert_eq!(
        result.polymorphic_models.len(),
        4,
        "Must discover exactly 4 polymorphic roots"
    );
    let poly_root_names: HashSet<&str> = result
        .polymorphic_models
        .iter()
        .map(|pm| pm.name.as_str())
        .collect();
    assert!(poly_root_names.contains("Api::OneMe::Types::BaseAttachment"));
    assert!(poly_root_names.contains("Api::OneMe::Types::Log::EventParams"));
    assert!(poly_root_names.contains("Api::OneMe::Types::Log::UnknownContactInteractionParams"));
    assert!(poly_root_names.contains("Api::OneMe::Types::Outgoing::BaseAttachment"));
    for pm in &result.polymorphic_models {
        assert!(
            !pm.root_sources.is_empty(),
            "Polymorphic root {} must have sources",
            pm.name
        );
        if pm.base.fields.iter().any(|f| f.name == "_type") {
            let disc = pm.discriminator.as_ref().unwrap_or_else(|| {
                panic!("Root {} with _type field must have discriminator", pm.name)
            });
            assert_eq!(disc.field, "_type");
            assert_eq!(disc.r#type, "std::string");
        } else {
            assert!(
                pm.discriminator.is_none(),
                "Root {} without _type field must have discriminator: None",
                pm.name
            );
        }
        if pm
            .root_sources
            .iter()
            .any(|source| source == "rtti_heuristic")
            && !pm
                .root_sources
                .iter()
                .any(|source| source == "protocol_field")
        {
            assert!(
                pm.variants.is_empty(),
                "RTTI-only root {} must not emit API wire variants",
                pm.name
            );
        }
        assert!(
            !pm.variants.iter().any(|variant| variant.name == pm.name),
            "Polymorphic base {} must not be duplicated as a wire variant",
            pm.name
        );
    }

    // 5. Models invariants (BFS discovery) & Transitive discovery of VideoCollage
    assert!(!result.models.is_empty());

    let video_collage = result
        .models
        .iter()
        .find(|m| m.name == "Api::OneMe::Types::VideoCollage")
        .expect("VideoCollage must be transitively discovered in models");
    let vc_field_names: Vec<&str> = video_collage
        .fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(
        vc_field_names,
        vec!["url", "frequency", "height", "width", "count"]
    );

    // 6. Cleanliness invariants: no blacklisted false fields & no raw MSVC primitives
    let blacklisted = ["PUBLIC", "POLL", "BlacklistConverter"];
    let check_fields_cleanliness = |fields: &[dumper_rust::extractor::ExtractedField]| {
        for f in fields {
            for bad in &blacklisted {
                assert_ne!(
                    &f.name.as_str(),
                    bad,
                    "Blacklisted field name '{}' leaked into output",
                    bad
                );
            }
            let full = &f.field_type.full;
            assert!(!full.contains("__int64"), "Raw __int64 in type: {}", full);
            assert!(
                !full.contains("signed char"),
                "Raw signed char in type: {}",
                full
            );
            assert!(
                !full.contains("basic_string"),
                "Raw basic_string in type: {}",
                full
            );

            if f.field_type.optional {
                assert!(
                    !f.required,
                    "Field '{}' with optional type cannot be required: true",
                    f.name
                );
            }
        }
    };

    for m in &result.models {
        check_fields_cleanliness(&m.fields);
    }
    for pm in &result.polymorphic_models {
        check_fields_cleanliness(&pm.base.fields);
        for v in pm.variants.iter().chain(pm.rtti_subclasses.iter()) {
            check_fields_cleanliness(&v.fields);
            check_fields_cleanliness(&v.all_fields);
        }
    }

    // 7. JSON serialization validity
    let json_str = serde_json::to_string_pretty(&result).expect("Failed to serialize to JSON");
    assert!(json_str.starts_with('{'));
    assert!(json_str.ends_with('}'));
}

#[test]
fn test_compare_with_binja() {
    let binja_path = match resolve_env_path("BINJA_DUMP_PATH") {
        Some(path) => path,
        None => {
            eprintln!("Skipping: BINJA_DUMP_PATH not set or file does not exist");
            return;
        }
    };
    if !binja_path.exists() {
        eprintln!("Skipping: BINJA_DUMP_PATH not set or file does not exist: {:?}", binja_path);
        return;
    }

    let rust_path = match resolve_env_path("RUST_DUMP_PATH") {
        Some(path) => path,
        None => {
            eprintln!("Skipping: RUST_DUMP_PATH not set or file does not exist");
            return;
        }
    };
    if !rust_path.exists() {
        eprintln!("Skipping: RUST_DUMP_PATH not set or file does not exist: {:?}", rust_path);
        return;
    }

    let binja_data: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&binja_path).unwrap()).unwrap();
    let rust_data: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&rust_path).unwrap()).unwrap();

    let binja_packets = binja_data
        .get("packets")
        .and_then(|v| v.as_array())
        .unwrap();
    let rust_packets = rust_data.get("packets").and_then(|v| v.as_array()).unwrap();
    assert_eq!(
        rust_packets.len(),
        128,
        "Rust packets count must be exactly 128"
    );
    assert_eq!(
        rust_packets.len(),
        binja_packets.len(),
        "Packet count mismatch"
    );

    let binja_events = binja_data.get("events").and_then(|v| v.as_array()).unwrap();
    let rust_events = rust_data.get("events").and_then(|v| v.as_array()).unwrap();
    assert_eq!(
        rust_events.len(),
        24,
        "Rust events count must be exactly 24"
    );
    assert_eq!(
        rust_events.len(),
        binja_events.len(),
        "Event count mismatch"
    );

    // Compare packet opcodes and field sets against reference
    let rust_packet_map: HashMap<u64, &serde_json::Value> = rust_packets
        .iter()
        .filter_map(|p| p.get("opcode").and_then(|op| op.as_u64()).map(|op| (op, p)))
        .collect();
    let binja_packet_map: HashMap<u64, &serde_json::Value> = binja_packets
        .iter()
        .filter_map(|p| p.get("opcode").and_then(|op| op.as_u64()).map(|op| (op, p)))
        .collect();
    assert_eq!(
        rust_packet_map.keys().collect::<HashSet<_>>(),
        binja_packet_map.keys().collect::<HashSet<_>>(),
        "Packet opcodes must match reference"
    );
    for (op, rp) in &rust_packet_map {
        let bp = &binja_packet_map[op];
        let r_req_fields: Vec<&str> = rp["request"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["name"].as_str())
            .collect();
        let b_req_fields: Vec<&str> = bp["request"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["name"].as_str())
            .collect();
        assert_eq!(
            r_req_fields, b_req_fields,
            "Packet {op} request fields mismatch"
        );
        let r_resp_fields: Vec<&str> = rp["response"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["name"].as_str())
            .collect();
        let b_resp_fields: Vec<&str> = bp["response"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["name"].as_str())
            .collect();
        assert_eq!(
            r_resp_fields, b_resp_fields,
            "Packet {op} response fields mismatch"
        );
    }

    // Compare event opcodes and field sets against reference
    let rust_event_map: HashMap<u64, &serde_json::Value> = rust_events
        .iter()
        .filter_map(|e| e.get("opcode").and_then(|op| op.as_u64()).map(|op| (op, e)))
        .collect();
    let binja_event_map: HashMap<u64, &serde_json::Value> = binja_events
        .iter()
        .filter_map(|e| e.get("opcode").and_then(|op| op.as_u64()).map(|op| (op, e)))
        .collect();
    assert_eq!(
        rust_event_map.keys().collect::<HashSet<_>>(),
        binja_event_map.keys().collect::<HashSet<_>>(),
        "Event opcodes must match reference"
    );
    for (op, re) in &rust_event_map {
        let be = &binja_event_map[op];
        if re.get("request").is_some() || be.get("request").is_some() {
            let r_fields: Vec<&str> = re
                .get("request")
                .and_then(|r| r.get("fields"))
                .and_then(|f| f.as_array())
                .map(|arr| arr.iter().filter_map(|f| f["name"].as_str()).collect())
                .unwrap_or_default();
            let b_fields: Vec<&str> = be
                .get("request")
                .and_then(|r| r.get("fields"))
                .and_then(|f| f.as_array())
                .map(|arr| arr.iter().filter_map(|f| f["name"].as_str()).collect())
                .unwrap_or_default();
            assert_eq!(r_fields, b_fields, "Event {op} request fields mismatch");
        }
    }

    // Structural diff of models
    let binja_models = binja_data.get("models").and_then(|v| v.as_array()).unwrap();
    let rust_models = rust_data.get("models").and_then(|v| v.as_array()).unwrap();

    let rust_model_names: HashSet<&str> = rust_models
        .iter()
        .filter_map(|m| m.get("name").and_then(|v| v.as_str()))
        .collect();
    let binja_model_names: HashSet<&str> = binja_models
        .iter()
        .filter_map(|m| m.get("name").and_then(|v| v.as_str()))
        .collect();

    // Verify key models exist in both
    for key_model in &[
        "Api::OneMe::Types::Contact",
        "Api::OneMe::Types::Message",
        "Api::OneMe::Types::ServerSettings",
        "Api::OneMe::Types::VideoCollage",
    ] {
        assert!(
            rust_model_names.contains(key_model),
            "Missing key model {}",
            key_model
        );
        assert!(
            binja_model_names.contains(key_model),
            "Missing in binja: {}",
            key_model
        );
    }

    let rust_model_map: HashMap<&str, &serde_json::Value> = rust_models
        .iter()
        .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(|n| (n, m)))
        .collect();

    // Verify Attachment models have complete field sets
    let photo = rust_model_map["Api::OneMe::Types::PhotoAttachment"];
    assert_eq!(
        photo["fields"].as_array().unwrap().len(),
        11,
        "PhotoAttachment must have 11 fields"
    );
    assert!(photo.get("warn").map_or(true, |w| w.is_null()));

    let audio = rust_model_map["Api::OneMe::Types::AudioAttachment"];
    assert_eq!(
        audio["fields"].as_array().unwrap().len(),
        5,
        "AudioAttachment must have 5 fields"
    );
    assert!(audio.get("warn").map_or(true, |w| w.is_null()));

    let video = rust_model_map["Api::OneMe::Types::VideoAttachment"];
    assert_eq!(
        video["fields"].as_array().unwrap().len(),
        17,
        "VideoAttachment must have 17 fields"
    );
    assert!(video.get("warn").map_or(true, |w| w.is_null()));

    // Verify UnsupportedAttachment has zero local fields and warn: null
    let unsupported = rust_model_map["Api::OneMe::Types::UnsupportedAttachment"];
    assert_eq!(
        unsupported["fields"].as_array().unwrap().len(),
        0,
        "UnsupportedAttachment must have 0 local fields"
    );
    assert!(
        unsupported.get("warn").map_or(true, |w| w.is_null()),
        "UnsupportedAttachment must have warn: null"
    );

    // Verify false 'warn: no data found' entries on attachment models are completely eliminated
    for (name, model) in &rust_model_map {
        if name.contains("Attachment") {
            assert!(
                model.get("warn").map_or(true, |w| w.is_null()),
                "Attachment model {name} has unexpected warning: {:?}",
                model.get("warn")
            );
        }
    }

    // Verify metric event parameter models have populated fields
    let call_params = rust_model_map["Api::OneMe::Types::Log::CallEventParams"];
    assert_eq!(
        call_params["fields"].as_array().unwrap().len(),
        8,
        "CallEventParams must have 8 fields"
    );
    assert!(call_params.get("warn").map_or(true, |w| w.is_null()));

    let nav_params = rust_model_map["Api::OneMe::Types::Log::NavEventParams"];
    assert_eq!(
        nav_params["fields"].as_array().unwrap().len(),
        8,
        "NavEventParams must have 8 fields"
    );
    assert!(nav_params.get("warn").map_or(true, |w| w.is_null()));

    let stories_params = rust_model_map["Api::OneMe::Types::Log::StoriesParams"];
    assert_eq!(
        stories_params["fields"].as_array().unwrap().len(),
        8,
        "StoriesParams must have 8 fields"
    );
    assert!(stories_params.get("warn").map_or(true, |w| w.is_null()));

    let comments_ttl = rust_model_map["Api::OneMe::Types::CommentsCounterTtl"];
    assert_eq!(
        comments_ttl["fields"].as_array().unwrap().len(),
        3,
        "CommentsCounterTtl must have 3 fields"
    );
    assert!(comments_ttl.get("warn").map_or(true, |w| w.is_null()));

    let opus_support = rust_model_map["Api::OneMe::Types::OpusSupport"];
    assert_eq!(
        opus_support["fields"].as_array().unwrap().len(),
        3,
        "OpusSupport must have 3 fields"
    );
    assert!(opus_support.get("warn").map_or(true, |w| w.is_null()));
}

#[test]
fn test_compact_formatting_invariants() {
    let compact_path = match resolve_env_path("RUST_COMPACT_DUMP_PATH") {
        Some(path) => path,
        None => {
            eprintln!("Skipping: RUST_COMPACT_DUMP_PATH not set or file does not exist");
            return;
        }
    };
    if !compact_path.exists() {
        eprintln!("Skipping: RUST_COMPACT_DUMP_PATH not set or file does not exist: {:?}", compact_path);
        return;
    }

    let compact_text = fs::read_to_string(&compact_path).expect("Failed to read compact dump");
    assert!(
        compact_text.contains("  variant "),
        "Compact dump must use 'variant' keyword"
    );
    assert!(
        compact_text.contains("  rtti_subclass "),
        "Compact dump must use 'rtti_subclass' keyword"
    );
    assert!(
        !compact_text.contains("  subclass "),
        "Compact dump must not use obsolete 'subclass' keyword"
    );
}

#[test]
fn test_model_catalog_filtering_and_variant_local_fields() {
    let base_attach = "Api::OneMe::Types::BaseAttachment";
    let photo_attach = "Api::OneMe::Types::PhotoAttachment";
    let video_attach = "Api::OneMe::Types::VideoAttachment";
    let unsupported = "Api::OneMe::Types::UnsupportedAttachment";
    let video_collage = "Api::OneMe::Types::VideoCollage";
    let event_params = "Api::OneMe::Types::Log::EventParams";
    let call_params = "Api::OneMe::Types::Log::CallEventParams";
    let unknown_params = "Api::OneMe::Types::Log::UnknownContactInteractionParams";
    let ab_status = "Api::OneMe::Types::Log::AbStatusParams";
    let banner_params = "Api::OneMe::Types::Log::BannerParams";

    let make_field = |name: &str, type_name: &str| ExtractedField {
        name: name.to_string(),
        field_type: decompose_type(type_name),
        required: false,
    };

    let poly_models = vec![
        PolymorphicModelEntry {
            name: base_attach.to_string(),
            root_sources: vec!["protocol_field".to_string()],
            discriminator: Some(PolymorphicDiscriminator {
                field: "_type".to_string(),
                r#type: "std::string".to_string(),
            }),
            base: PolymorphicBase {
                offset: Some("0x100".to_string()),
                fields: vec![
                    make_field("_type", "std::string"),
                    make_field("deleted", "std::optional<bool>"),
                ],
            },
            variants: vec![
                PolymorphicVariant {
                    name: photo_attach.to_string(),
                    offset: Some("0x200".to_string()),
                    fields: vec![
                        make_field("photoId", "int64_t"),
                        make_field("baseUrl", "std::string"),
                        make_field("width", "int32_t"),
                        make_field("height", "int32_t"),
                    ],
                    all_fields: vec![
                        make_field("_type", "std::string"),
                        make_field("deleted", "std::optional<bool>"),
                        make_field("photoId", "int64_t"),
                        make_field("baseUrl", "std::string"),
                        make_field("width", "int32_t"),
                        make_field("height", "int32_t"),
                    ],
                    tag: Some("PHOTO".to_string()),
                },
                PolymorphicVariant {
                    name: video_attach.to_string(),
                    offset: Some("0x210".to_string()),
                    fields: vec![make_field("collage", video_collage)],
                    all_fields: vec![
                        make_field("_type", "std::string"),
                        make_field("deleted", "std::optional<bool>"),
                        make_field("collage", video_collage),
                    ],
                    tag: Some("VIDEO".to_string()),
                },
                PolymorphicVariant {
                    name: unsupported.to_string(),
                    offset: Some("0x531d90".to_string()),
                    fields: vec![],
                    all_fields: vec![
                        make_field("_type", "std::string"),
                        make_field("deleted", "std::optional<bool>"),
                    ],
                    tag: Some("UNSUPPORTED".to_string()),
                },
            ],
            rtti_subclasses: vec![],
        },
        PolymorphicModelEntry {
            name: event_params.to_string(),
            root_sources: vec!["protocol_field".to_string(), "rtti_heuristic".to_string()],
            discriminator: None,
            base: PolymorphicBase {
                offset: Some("0x300".to_string()),
                fields: vec![make_field("common", "std::string")],
            },
            variants: vec![PolymorphicVariant {
                name: call_params.to_string(),
                offset: Some("0x400".to_string()),
                fields: vec![make_field("callDuration", "int64_t")],
                all_fields: vec![make_field("common", "std::string"), make_field("callDuration", "int64_t")],
                tag: None,
            }],
            rtti_subclasses: vec![],
        },
        PolymorphicModelEntry {
            name: unknown_params.to_string(),
            root_sources: vec!["rtti_heuristic".to_string()],
            discriminator: None,
            base: PolymorphicBase {
                offset: Some("0x500".to_string()),
                fields: vec![],
            },
            variants: vec![], // Heuristic root has no variants
            rtti_subclasses: vec![
                PolymorphicVariant {
                    name: ab_status.to_string(),
                    offset: Some("0x510".to_string()),
                    fields: vec![],
                    all_fields: vec![],
                    tag: None,
                },
                PolymorphicVariant {
                    name: banner_params.to_string(),
                    offset: Some("0x520".to_string()),
                    fields: vec![],
                    all_fields: vec![],
                    tag: None,
                },
            ],
        },
    ];

    let entries: HashMap<String, TypeDescriptorEntry> = vec![
        TypeDescriptorEntry {
            name: base_attach.to_string(),
            offset: Some("0x100".to_string()),
            fields: vec![
                make_field("_type", "std::string"),
                make_field("deleted", "std::optional<bool>"),
            ],
            warn: None,
        },
        TypeDescriptorEntry {
            name: photo_attach.to_string(),
            offset: Some("0x200".to_string()),
            fields: vec![
                make_field("photoId", "int64_t"),
                make_field("baseUrl", "std::string"),
                make_field("width", "int32_t"),
                make_field("height", "int32_t"),
            ],
            warn: None,
        },
        TypeDescriptorEntry {
            name: video_attach.to_string(),
            offset: Some("0x210".to_string()),
            fields: vec![make_field("collage", video_collage)],
            warn: None,
        },
        TypeDescriptorEntry {
            name: unsupported.to_string(),
            offset: Some("0x531d90".to_string()),
            fields: vec![],
            warn: Some("no data found".to_string()),
        },
        TypeDescriptorEntry {
            name: video_collage.to_string(),
            offset: Some("0x220".to_string()),
            fields: vec![
                make_field("url", "std::string"),
                make_field("frequency", "int32_t"),
                make_field("height", "int32_t"),
                make_field("width", "int32_t"),
                make_field("count", "int32_t"),
            ],
            warn: None,
        },
        TypeDescriptorEntry {
            name: event_params.to_string(),
            offset: Some("0x300".to_string()),
            fields: vec![make_field("common", "std::string")],
            warn: None,
        },
        TypeDescriptorEntry {
            name: call_params.to_string(),
            offset: Some("0x400".to_string()),
            fields: vec![make_field("callDuration", "int64_t")],
            warn: None,
        },
        TypeDescriptorEntry {
            name: unknown_params.to_string(),
            offset: Some("0x500".to_string()),
            fields: vec![],
            warn: Some("no data found".to_string()),
        },
        TypeDescriptorEntry {
            name: ab_status.to_string(),
            offset: Some("0x510".to_string()),
            fields: vec![],
            warn: Some("no data found".to_string()),
        },
        TypeDescriptorEntry {
            name: banner_params.to_string(),
            offset: Some("0x520".to_string()),
            fields: vec![],
            warn: Some("no data found".to_string()),
        },
    ]
    .into_iter()
    .map(|e| (e.name.clone(), e))
    .collect();

    let mut resolve = |name: &str| {
        entries
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("missing entry for {name}"))
    };

    let models = build_model_catalog(&[], &[], &poly_models, &mut resolve);
    let model_names: Vec<&str> = models.iter().map(|m| m.name.as_str()).collect();

    // 1. Inclusion of real variants from polymorphic_models.variants
    assert!(model_names.contains(&photo_attach));
    assert!(model_names.contains(&video_attach));
    assert!(model_names.contains(&call_params));
    assert!(model_names.contains(&unsupported));

    // 2. Exclusion of empty RTTI subclasses from models
    assert!(
        !model_names.contains(&ab_status),
        "AbStatusParams must be excluded from models"
    );
    assert!(
        !model_names.contains(&banner_params),
        "BannerParams must be excluded from models"
    );
    assert!(
        !model_names.contains(&unknown_params),
        "UnknownContactInteractionParams without protocol usage must be excluded from models"
    );

    // 3. Correctness of local fields on variant entries in models
    let photo = models.iter().find(|m| m.name == photo_attach).unwrap();
    let photo_field_names: Vec<&str> = photo.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        photo_field_names,
        vec!["photoId", "baseUrl", "width", "height"]
    );
    assert!(!photo_field_names.contains(&"_type"));
    assert!(!photo_field_names.contains(&"deleted"));

    // 4. Suppression of warn on marker classes like UnsupportedAttachment
    let unsupp = models.iter().find(|m| m.name == unsupported).unwrap();
    assert_eq!(unsupp.offset.as_deref(), Some("0x531d90"));
    assert!(unsupp.fields.is_empty());
    assert_eq!(
        unsupp.warn, None,
        "warn must be None (null in JSON) on UnsupportedAttachment"
    );

    // 5. Transitive standalone model discovery from variant field
    let vc = models.iter().find(|m| m.name == video_collage).unwrap();
    let vc_field_names: Vec<&str> = vc.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        vc_field_names,
        vec!["url", "frequency", "height", "width", "count"]
    );
}
