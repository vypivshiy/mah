use dumper_rust::dumper::{
    build_model_catalog, build_polymorphic_models, mark_recursive_fields, Dumper, DumperOptions,
    PacketEntry, PolymorphicBase, PolymorphicDiscriminator, PolymorphicModelEntry,
    PolymorphicVariant, RootSource, TypeDescriptorEntry,
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
use common::{resolve_core_dll, resolve_env_path};

#[test]
fn test_dumper_full_pipeline_structural_invariants() {
    let dll_path = match resolve_core_dll() {
        Some(path) => path,
        None => {
            eprintln!("Skipping: core.dll not found");
            return;
        }
    };
    let bytes = fs::read(&dll_path).expect("Failed to read DLL");
    let pe = PeImage::parse(&bytes).expect("Failed to parse PE image");
    let rtti = RttiEngine::build(&pe).expect("Failed to build RTTI engine");
    let scanner = ProtocolScanner::scan(&pe, &rtti).expect("Failed to scan protocol entities");

    // Pass empty options to test dynamic version detection from DLL
    let options = DumperOptions {
        version: dumper_rust::dumper::AppVersion {
            version: String::new(),
            build: 0,
            protocol_version: None,
        },
        config: None,
        protocol_version: None,
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

    let is_valid_ident = |ident: &str| -> bool {
        !ident.is_empty()
            && ident.chars().next().unwrap().is_ascii_uppercase()
            && ident.chars().all(|c| c.is_ascii_alphanumeric())
    };

    // 2. Packets invariants (at least 128 packets)
    assert!(
        result.packets.len() >= 128,
        "Must discover at least 128 packets, found {}",
        result.packets.len()
    );
    let mut packet_opcodes = HashSet::new();
    let mut packet_ident_to_name: HashMap<&str, &str> = HashMap::new();
    for p in &result.packets {
        let opcode = p.opcode;
        assert!(opcode > 0, "Opcode must be positive");
        assert!(
            packet_opcodes.insert(opcode),
            "Duplicate packet opcode: {}",
            opcode
        );
        assert!(!p.name.is_empty());
        assert!(
            is_valid_ident(&p.ident),
            "Packet {} ({}) has invalid ident '{}'",
            opcode,
            p.name,
            p.ident
        );
        assert!(
            packet_ident_to_name.insert(&p.ident, &p.name).is_none(),
            "Duplicate packet ident '{}' on opcode {} ({})",
            p.ident,
            opcode,
            p.name
        );
        assert!(!p.request.name.is_empty());
        assert!(
            is_valid_ident(&p.request.ident),
            "Packet {} request {} has invalid ident '{}'",
            opcode,
            p.request.name,
            p.request.ident
        );
        assert!(!p.response.name.is_empty());
        assert!(
            is_valid_ident(&p.response.ident),
            "Packet {} response {} has invalid ident '{}'",
            opcode,
            p.response.name,
            p.response.ident
        );
    }

    // Verify empty-parameter packet fallback and counterpart derivation
    let pkt_20 = result
        .packets
        .iter()
        .find(|p| p.opcode == 20)
        .expect("Opcode 20 must exist");
    assert_eq!(pkt_20.ident, "Opcode20");
    assert_eq!(pkt_20.request.ident, "EmptyParameters");
    assert_eq!(pkt_20.response.ident, "EmptyResponse");

    let pkt_25 = result
        .packets
        .iter()
        .find(|p| p.opcode == 25)
        .expect("Opcode 25 must exist");
    assert_eq!(pkt_25.ident, "AvatarPresetAvatar");
    assert_eq!(pkt_25.request.ident, "EmptyParameters");
    assert_eq!(pkt_25.response.ident, "AvatarPresetAvatarResponse");

    // 3. Events invariants (exactly 24 events)
    assert_eq!(result.events.len(), 24, "Must discover exactly 24 events");
    let mut event_opcodes = HashSet::new();
    let mut event_idents = HashSet::new();
    for e in &result.events {
        let opcode = e.opcode;
        assert!(opcode > 0, "Event opcode must be positive");
        assert!(
            event_opcodes.insert(opcode),
            "Duplicate event opcode: {}",
            opcode
        );
        assert!(!e.name.is_empty());
        assert!(
            is_valid_ident(&e.ident),
            "Event {} ({}) has invalid ident '{}'",
            opcode,
            e.name,
            e.ident
        );
        assert!(
            event_idents.insert(e.ident.as_str()),
            "Duplicate event ident '{}' on opcode {}",
            e.ident,
            opcode
        );
        if let Some(req) = &e.request {
            assert!(!req.name.is_empty());
            assert!(
                is_valid_ident(&req.ident),
                "Event {} request {} has invalid ident '{}'",
                opcode,
                req.name,
                req.ident
            );
        }
        if let Some(resp) = &e.response {
            assert!(!resp.name.is_empty());
            assert!(
                is_valid_ident(&resp.ident),
                "Event {} response {} has invalid ident '{}'",
                opcode,
                resp.name,
                resp.ident
            );
        }
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

    // 5. Models & Polymorphic models invariants:
    //    - BFS discovery, disjoint separation between `models` and `polymorphic_models`
    //    - Valid, collision-free `ident` across all models, polymorphic bases, variants, and subclasses
    //    - Specific disambiguations (`LogEventParams` vs `LogLogEventParams`, `LogClickParamsLogCalloutScreenMeta`)
    //    - Standalone models referenced by variants (`VideoCollage`, `Crop`, `Keyboard`, `StoryOwner`, `WidgetContent`)
    assert!(!result.models.is_empty());

    let mut poly_all_names = HashSet::new();
    let mut all_type_ident_to_name: HashMap<String, String> = HashMap::new();
    let mut record_type_ident = |ident: &str, name: &str| {
        assert!(
            is_valid_ident(ident),
            "Type '{}' has invalid ident '{}'",
            name,
            ident
        );
        assert!(
            !name.contains("struct ") && !name.contains("Utilities::StrongTypedef"),
            "Type name '{}' contains unnormalized qualifier",
            name
        );
        if let Some(existing_name) = all_type_ident_to_name.get(ident) {
            assert_eq!(
                existing_name, name,
                "Type ident collision: '{}' maps to both '{}' and '{}'",
                ident, existing_name, name
            );
        } else {
            all_type_ident_to_name.insert(ident.to_string(), name.to_string());
        }
    };

    for pm in &result.polymorphic_models {
        record_type_ident(&pm.ident, &pm.name);
        poly_all_names.insert(pm.name.as_str());
        for v in &pm.variants {
            record_type_ident(&v.ident, &v.name);
            poly_all_names.insert(v.name.as_str());
        }
        for s in &pm.rtti_subclasses {
            record_type_ident(&s.ident, &s.name);
            poly_all_names.insert(s.name.as_str());
        }
    }

    let mut model_idents = HashSet::new();
    for m in &result.models {
        record_type_ident(&m.ident, &m.name);
        assert!(
            !poly_all_names.contains(m.name.as_str()),
            "Polymorphic type {} must not be duplicated in models",
            m.name
        );
        assert!(
            model_idents.insert(m.ident.as_str()),
            "Duplicate model ident '{}' for {}",
            m.ident,
            m.name
        );
    }

    let log_event_pm = result
        .polymorphic_models
        .iter()
        .find(|pm| pm.name == "Api::OneMe::Types::Log::EventParams")
        .expect("Log::EventParams polymorphic model must exist");
    assert_eq!(log_event_pm.ident, "LogEventParams");

    let log_log_event_var = log_event_pm
        .variants
        .iter()
        .find(|v| v.name == "Api::OneMe::Types::Log::LogEventParams")
        .expect("Log::LogEventParams variant must exist");
    assert_eq!(log_log_event_var.ident, "LogLogEventParams");

    let callout_click_var = log_event_pm
        .variants
        .iter()
        .find(|v| {
            v.name
                == "Api::OneMe::Types::Log::ClickParams<Api::OneMe::Types::Log::CalloutScreenMeta>"
        })
        .expect("ClickParams<CalloutScreenMeta> variant must exist with stripped 'struct '");
    assert_eq!(
        callout_click_var.ident,
        "LogClickParamsLogCalloutScreenMeta"
    );

    for (expected_name, expected_ident) in [
        ("Api::OneMe::Types::VideoCollage", "VideoCollage"),
        ("Api::OneMe::Types::Crop", "Crop"),
        ("Api::OneMe::Types::Keyboard", "Keyboard"),
        ("Api::OneMe::Types::StoryOwner", "StoryOwner"),
        ("Api::OneMe::Types::WidgetContent", "WidgetContent"),
    ] {
        let model = result
            .models
            .iter()
            .find(|m| m.name == expected_name)
            .unwrap_or_else(|| {
                panic!("Standalone model {expected_name} referenced by variant must exist in models")
            });
        assert_eq!(model.ident, expected_ident);
        assert!(
            !model.fields.is_empty(),
            "Standalone model {expected_name} must have extracted fields"
        );
    }

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

    // 6. Cleanliness & DecomposedType invariants:
    //    - No blacklisted false fields, raw MSVC primitives, "struct ", or "Utilities::StrongTypedef"
    //    - `bytes: true` iff array of `std::byte` or `char`
    //    - Recursive `map_key_type` and `map_value_type` on all maps
    let blacklisted = ["PUBLIC", "POLL", "BlacklistConverter"];
    fn check_decomposed_type(
        dt: &dumper_rust::type_parser::DecomposedType,
        is_valid_ident: &dyn Fn(&str) -> bool,
    ) {
        for s in [
            Some(dt.full.as_str()),
            dt.name.as_deref(),
            dt.map_key.as_deref(),
            dt.map_value.as_deref(),
            dt.polymorphic_base.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            assert!(!s.contains("__int64"), "Raw __int64 in type: {s}");
            assert!(!s.contains("signed char"), "Raw signed char in type: {s}");
            assert!(!s.contains("basic_string"), "Raw basic_string in type: {s}");
            assert!(!s.contains("struct "), "Raw 'struct ' qualifier in type: {s}");
            assert!(
                !s.contains("Utilities::StrongTypedef"),
                "Unwrapped StrongTypedef leaked in type: {s}"
            );
        }

        if let Some(ref ident) = dt.ident {
            assert!(
                is_valid_ident(ident),
                "DecomposedType '{}' has invalid ident '{}'",
                dt.full,
                ident
            );
        }

        let expected_bytes = dt.array && matches!(dt.name.as_deref(), Some("std::byte" | "char"));
        assert_eq!(
            dt.bytes, expected_bytes,
            "DecomposedType '{}' bytes flag mismatch (expected {})",
            dt.full, expected_bytes
        );

        if dt.map {
            assert!(dt.name.is_none(), "Map type '{}' must have name: None", dt.full);
            assert!(dt.ident.is_none(), "Map type '{}' must have ident: None", dt.full);
            assert!(dt.map_key.is_some(), "Map type '{}' missing map_key", dt.full);
            assert!(dt.map_value.is_some(), "Map type '{}' missing map_value", dt.full);
            let kt = dt
                .map_key_type
                .as_ref()
                .unwrap_or_else(|| panic!("Map type '{}' missing map_key_type", dt.full));
            let vt = dt
                .map_value_type
                .as_ref()
                .unwrap_or_else(|| panic!("Map type '{}' missing map_value_type", dt.full));
            check_decomposed_type(kt, is_valid_ident);
            check_decomposed_type(vt, is_valid_ident);
        } else {
            assert!(dt.map_key.is_none());
            assert!(dt.map_value.is_none());
            assert!(dt.map_key_type.is_none());
            assert!(dt.map_value_type.is_none());
        }
    }

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
            check_decomposed_type(&f.field_type, &is_valid_ident);

            if f.field_type.optional {
                assert!(
                    !f.required,
                    "Field '{}' with optional type cannot be required: true",
                    f.name
                );
            }
            if f.field_type.array || f.field_type.map {
                assert!(
                    !f.recursive,
                    "Indirected field '{}' (array/map) must have recursive: false",
                    f.name
                );
            }
        }
    };

    for p in &result.packets {
        check_fields_cleanliness(&p.request.fields);
        check_fields_cleanliness(&p.response.fields);
        assert!(p.request.fields.iter().all(|f| !f.recursive));
        assert!(p.response.fields.iter().all(|f| !f.recursive));
    }
    for e in &result.events {
        if let Some(req) = &e.request {
            check_fields_cleanliness(&req.fields);
            assert!(req.fields.iter().all(|f| !f.recursive));
        }
        if let Some(resp) = &e.response {
            check_fields_cleanliness(&resp.fields);
            assert!(resp.fields.iter().all(|f| !f.recursive));
        }
    }
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

    // Concrete verification of StrongTypedef unwrapping, bytes: true, and recursive map_value_type
    let find_model_field = |model_name: &str, field_name: &str| {
        result
            .models
            .iter()
            .find(|m| m.name == model_name)
            .unwrap_or_else(|| panic!("Missing model {model_name}"))
            .fields
            .iter()
            .find(|f| f.name == field_name)
            .unwrap_or_else(|| panic!("Missing field {model_name}.{field_name}"))
    };

    let ab_status = find_model_field("Api::OneMe::Types::ServerSettings", "ab-status");
    assert_eq!(ab_status.field_type.full, "std::optional<int64_t>");
    assert_eq!(ab_status.field_type.name.as_deref(), Some("int64_t"));
    assert_eq!(ab_status.field_type.ident, None);

    let chat_folder_filters = find_model_field("Api::OneMe::Types::ChatFolder", "filters");
    assert_eq!(
        chat_folder_filters.field_type.full,
        "std::optional<std::vector<char>>"
    );
    assert!(chat_folder_filters.field_type.array);
    assert!(chat_folder_filters.field_type.bytes);
    assert_eq!(chat_folder_filters.field_type.ident, None);

    let pkt_19 = result
        .packets
        .iter()
        .find(|p| p.opcode == 19)
        .expect("Opcode 19 (Auth::Login) must exist");
    let fingerprint_field = pkt_19
        .request
        .fields
        .iter()
        .find(|f| f.name == "chatCacheFingerprint")
        .expect("Auth::Login request must have chatCacheFingerprint");
    assert_eq!(
        fingerprint_field.field_type.full,
        "std::optional<std::vector<std::byte>>"
    );
    assert!(fingerprint_field.field_type.array);
    assert!(fingerprint_field.field_type.bytes);
    assert_eq!(fingerprint_field.field_type.ident, None);

    let login_messages_field = pkt_19
        .response
        .fields
        .iter()
        .find(|f| f.name == "messages")
        .expect("Auth::Login response must have messages map");
    assert_eq!(
        login_messages_field.field_type.full,
        "std::optional<std::unordered_map<int64_t, std::vector<Api::OneMe::Types::Message>>>"
    );
    assert!(login_messages_field.field_type.map);
    let msg_map_vt = login_messages_field
        .field_type
        .map_value_type
        .as_ref()
        .expect("messages map must have map_value_type");
    assert_eq!(msg_map_vt.full, "std::vector<Api::OneMe::Types::Message>");
    assert_eq!(
        msg_map_vt.name.as_deref(),
        Some("Api::OneMe::Types::Message")
    );
    assert_eq!(msg_map_vt.ident.as_deref(), Some("Message"));
    assert!(msg_map_vt.array);
    assert!(!msg_map_vt.bytes);

    // 7. Recursive ownership cycle detection invariants (exact 7 cycle-forming fields)
    assert!(
        find_model_field("Api::OneMe::Types::Message", "link").recursive,
        "Message.link must be recursive"
    );
    assert!(
        find_model_field("Api::OneMe::Types::MessageLink", "message").recursive,
        "MessageLink.message must be recursive"
    );
    assert!(
        find_model_field("Api::OneMe::Types::Message", "messagePreview").recursive,
        "Message.messagePreview must be recursive"
    );
    assert!(
        find_model_field("Api::OneMe::Types::MessagePreview", "attachment").recursive,
        "MessagePreview.attachment must be recursive"
    );
    assert!(
        !find_model_field("Api::OneMe::Types::Message", "attaches").recursive,
        "Message.attaches (array: true) must remain recursive: false"
    );

    let base_attach_pm = result
        .polymorphic_models
        .iter()
        .find(|pm| pm.name == "Api::OneMe::Types::BaseAttachment")
        .expect("BaseAttachment polymorphic model must exist");
    for variant_list in [&base_attach_pm.variants, &base_attach_pm.rtti_subclasses] {
        let file_var = variant_list
            .iter()
            .find(|v| v.name == "Api::OneMe::Types::FileAttachment")
            .expect("FileAttachment variant must exist");
        assert!(file_var.fields.iter().find(|f| f.name == "preview").unwrap().recursive);
        assert!(file_var.all_fields.iter().find(|f| f.name == "preview").unwrap().recursive);

        let share_var = variant_list
            .iter()
            .find(|v| v.name == "Api::OneMe::Types::ShareAttachment")
            .expect("ShareAttachment variant must exist");
        assert!(share_var.fields.iter().find(|f| f.name == "media").unwrap().recursive);
        assert!(share_var.all_fields.iter().find(|f| f.name == "media").unwrap().recursive);
        assert!(!share_var.fields.iter().find(|f| f.name == "image").unwrap().recursive);

        let control_var = variant_list
            .iter()
            .find(|v| v.name == "Api::OneMe::Types::ControlAttachment")
            .expect("ControlAttachment variant must exist");
        assert!(control_var.fields.iter().find(|f| f.name == "pinnedMessage").unwrap().recursive);
        assert!(control_var.all_fields.iter().find(|f| f.name == "pinnedMessage").unwrap().recursive);
    }

    let mut recursive_edges = HashSet::new();
    for m in &result.models {
        for f in &m.fields {
            if f.recursive {
                recursive_edges.insert((m.name.as_str(), f.name.as_str()));
            }
        }
    }
    for pm in &result.polymorphic_models {
        for f in &pm.base.fields {
            if f.recursive {
                recursive_edges.insert((pm.name.as_str(), f.name.as_str()));
            }
        }
        for v in pm.variants.iter().chain(pm.rtti_subclasses.iter()) {
            for f in v.fields.iter().chain(v.all_fields.iter()) {
                if f.recursive {
                    recursive_edges.insert((v.name.as_str(), f.name.as_str()));
                }
            }
        }
    }
    let expected_recursive_edges: HashSet<(&str, &str)> = [
        ("Api::OneMe::Types::Message", "link"),
        ("Api::OneMe::Types::MessageLink", "message"),
        ("Api::OneMe::Types::Message", "messagePreview"),
        ("Api::OneMe::Types::MessagePreview", "attachment"),
        ("Api::OneMe::Types::FileAttachment", "preview"),
        ("Api::OneMe::Types::ShareAttachment", "media"),
        ("Api::OneMe::Types::ControlAttachment", "pinnedMessage"),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        recursive_edges, expected_recursive_edges,
        "Exact set of 7 cycle-forming fields must be marked recursive: true"
    );

    // 8. JSON serialization validity & global string cleanliness
    let json_str = serde_json::to_string_pretty(&result).expect("Failed to serialize to JSON");
    assert!(json_str.starts_with('{'));
    assert!(json_str.ends_with('}'));
    assert!(
        !json_str.contains("struct "),
        "Serialized JSON must not contain any 'struct ' qualifier"
    );
    assert!(
        !json_str.contains("Utilities::StrongTypedef"),
        "Serialized JSON must not contain any 'Utilities::StrongTypedef'"
    );
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

    let mut rust_model_map: HashMap<&str, &serde_json::Value> = rust_models
        .iter()
        .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(|n| (n, m)))
        .collect();
    if let Some(poly_models) = rust_data.get("polymorphic_models").and_then(|v| v.as_array()) {
        for pm in poly_models {
            if let Some(variants) = pm.get("variants").and_then(|v| v.as_array()) {
                for v in variants {
                    if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
                        rust_model_map.entry(name).or_insert(v);
                    }
                }
            }
        }
    }

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
        recursive: false,
    };

    let poly_models = vec![
        PolymorphicModelEntry {
            name: base_attach.to_string(),
            ident: "BaseAttachment".to_string(),
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
                    ident: "PhotoAttachment".to_string(),
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
                    ident: "VideoAttachment".to_string(),
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
                    ident: "UnsupportedAttachment".to_string(),
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
            ident: "LogEventParams".to_string(),
            root_sources: vec!["protocol_field".to_string(), "rtti_heuristic".to_string()],
            discriminator: None,
            base: PolymorphicBase {
                offset: Some("0x300".to_string()),
                fields: vec![make_field("common", "std::string")],
            },
            variants: vec![PolymorphicVariant {
                name: call_params.to_string(),
                ident: "LogCallEventParams".to_string(),
                offset: Some("0x400".to_string()),
                fields: vec![make_field("callDuration", "int64_t")],
                all_fields: vec![make_field("common", "std::string"), make_field("callDuration", "int64_t")],
                tag: None,
            }],
            rtti_subclasses: vec![],
        },
        PolymorphicModelEntry {
            name: unknown_params.to_string(),
            ident: "LogUnknownContactInteractionParams".to_string(),
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
                    ident: "LogAbStatusParams".to_string(),
                    offset: Some("0x510".to_string()),
                    fields: vec![],
                    all_fields: vec![],
                    tag: None,
                },
                PolymorphicVariant {
                    name: banner_params.to_string(),
                    ident: "LogBannerParams".to_string(),
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
            ident: "BaseAttachment".to_string(),
            offset: Some("0x100".to_string()),
            fields: vec![
                make_field("_type", "std::string"),
                make_field("deleted", "std::optional<bool>"),
            ],
            warn: None,
        },
        TypeDescriptorEntry {
            name: photo_attach.to_string(),
            ident: "PhotoAttachment".to_string(),
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
            ident: "VideoAttachment".to_string(),
            offset: Some("0x210".to_string()),
            fields: vec![make_field("collage", video_collage)],
            warn: None,
        },
        TypeDescriptorEntry {
            name: unsupported.to_string(),
            ident: "UnsupportedAttachment".to_string(),
            offset: Some("0x531d90".to_string()),
            fields: vec![],
            warn: Some("no data found".to_string()),
        },
        TypeDescriptorEntry {
            name: video_collage.to_string(),
            ident: "VideoCollage".to_string(),
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
            ident: "LogEventParams".to_string(),
            offset: Some("0x300".to_string()),
            fields: vec![make_field("common", "std::string")],
            warn: None,
        },
        TypeDescriptorEntry {
            name: call_params.to_string(),
            ident: "LogCallEventParams".to_string(),
            offset: Some("0x400".to_string()),
            fields: vec![make_field("callDuration", "int64_t")],
            warn: None,
        },
        TypeDescriptorEntry {
            name: unknown_params.to_string(),
            ident: "LogUnknownContactInteractionParams".to_string(),
            offset: Some("0x500".to_string()),
            fields: vec![],
            warn: Some("no data found".to_string()),
        },
        TypeDescriptorEntry {
            name: ab_status.to_string(),
            ident: "LogAbStatusParams".to_string(),
            offset: Some("0x510".to_string()),
            fields: vec![],
            warn: Some("no data found".to_string()),
        },
        TypeDescriptorEntry {
            name: banner_params.to_string(),
            ident: "LogBannerParams".to_string(),
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

    // 1. Exclusion of all polymorphic bases, active variants, and RTTI subclasses from `models`
    assert!(!model_names.contains(&base_attach));
    assert!(!model_names.contains(&photo_attach));
    assert!(!model_names.contains(&video_attach));
    assert!(!model_names.contains(&event_params));
    assert!(!model_names.contains(&call_params));
    assert!(!model_names.contains(&unsupported));
    assert!(!model_names.contains(&ab_status));
    assert!(!model_names.contains(&banner_params));
    assert!(!model_names.contains(&unknown_params));

    // 2. Transitive standalone model discovery from variant field
    assert_eq!(models.len(), 1);
    let vc = models.iter().find(|m| m.name == video_collage).unwrap();
    assert_eq!(vc.ident, "VideoCollage");
    let vc_field_names: Vec<&str> = vc.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        vc_field_names,
        vec!["url", "frequency", "height", "width", "count"]
    );
}

#[test]
fn test_discriminator_catalog_and_tag_discovery_invariants() {
    let dll_path = match resolve_core_dll() {
        Some(path) => path,
        None => {
            eprintln!("Skipping: core.dll not found");
            return;
        }
    };
    let bytes = fs::read(&dll_path).expect("Failed to read DLL");
    let pe = PeImage::parse(&bytes).expect("Failed to parse PE image");
    let rtti = RttiEngine::build(&pe).expect("Failed to build RTTI engine");
    let scanner = ProtocolScanner::scan(&pe, &rtti).expect("Failed to scan protocol entities");
    let options = DumperOptions {
        version: dumper_rust::dumper::AppVersion {
            version: String::new(),
            build: 0,
            protocol_version: None,
        },
        config: None,
        protocol_version: None,
    };
    let result = Dumper::dump(&pe, &rtti, &scanner, &options).expect("Failed to execute dumper");

    // 1. Discriminator catalog exists and contains BaseAttachment
    assert!(
        result.discriminators.contains_key("Api::OneMe::Types::BaseAttachment"),
        "Catalog must contain Api::OneMe::Types::BaseAttachment"
    );

    let base_disc = &result.discriminators["Api::OneMe::Types::BaseAttachment"];
    println!("BaseAttachment discriminators: {:#?}", base_disc);

    // 2. All core attachment variants have expected tags
    assert_eq!(base_disc.get("PHOTO").map(String::as_str), Some("Api::OneMe::Types::PhotoAttachment"));
    assert_eq!(base_disc.get("VIDEO").map(String::as_str), Some("Api::OneMe::Types::VideoAttachment"));
    assert_eq!(base_disc.get("STICKER").map(String::as_str), Some("Api::OneMe::Types::StickerAttachment"));
    assert_eq!(base_disc.get("AUDIO").map(String::as_str), Some("Api::OneMe::Types::AudioAttachment"));
    assert_eq!(base_disc.get("FILE").map(String::as_str), Some("Api::OneMe::Types::FileAttachment"));
    assert_eq!(base_disc.get("CONTROL").map(String::as_str), Some("Api::OneMe::Types::ControlAttachment"));
    assert_eq!(base_disc.get("SHARE").map(String::as_str), Some("Api::OneMe::Types::ShareAttachment"));
    assert_eq!(base_disc.get("CALL").map(String::as_str), Some("Api::OneMe::Types::CallAttachment"));
    assert_eq!(base_disc.get("APP").map(String::as_str), Some("Api::OneMe::Types::AppAttachment"));
    assert_eq!(base_disc.get("INLINE_KEYBOARD").map(String::as_str), Some("Api::OneMe::Types::InlineKeyboardAttachment"));
    assert_eq!(base_disc.get("REPLY_KEYBOARD").map(String::as_str), Some("Api::OneMe::Types::ReplyKeyboardAttachment"));
    assert_eq!(base_disc.get("CONTACT").map(String::as_str), Some("Api::OneMe::Types::ContactAttachment"));
    assert_eq!(base_disc.get("LOCATION").map(String::as_str), Some("Api::OneMe::Types::GeoPositionAttachment"));
    assert_eq!(base_disc.get("WIDGET").map(String::as_str), Some("Api::OneMe::Types::WidgetAttachment"));
    assert_eq!(base_disc.get("POLL").map(String::as_str), Some("Api::OneMe::Types::PollAttachment"));
    assert_eq!(base_disc.get("STORY_REPLY").map(String::as_str), Some("Api::OneMe::Types::StoryAttachment"));

    // 3. Outgoing::BaseAttachment also has tags
    if let Some(outgoing_disc) = result.discriminators.get("Api::OneMe::Types::Outgoing::BaseAttachment") {
        println!("Outgoing::BaseAttachment discriminators: {:#?}", outgoing_disc);
        assert_eq!(outgoing_disc.get("PHOTO").map(String::as_str), Some("Api::OneMe::Types::Outgoing::PhotoAttachment"));
        assert_eq!(outgoing_disc.get("VIDEO").map(String::as_str), Some("Api::OneMe::Types::Outgoing::VideoAttachment"));
        assert_eq!(outgoing_disc.get("STICKER").map(String::as_str), Some("Api::OneMe::Types::Outgoing::StickerAttachment"));
        assert_eq!(outgoing_disc.get("AUDIO").map(String::as_str), Some("Api::OneMe::Types::Outgoing::AudioAttachment"));
    }

    // 4. Verify tag discovery on PolymorphicModelEntry variants
    let base_poly = result.polymorphic_models.iter().find(|m| m.name == "Api::OneMe::Types::BaseAttachment").unwrap();
    let photo_var = base_poly.variants.iter().find(|v| v.name == "Api::OneMe::Types::PhotoAttachment").unwrap();
    assert_eq!(photo_var.tag.as_deref(), Some("PHOTO"));

    let video_var = base_poly.variants.iter().find(|v| v.name == "Api::OneMe::Types::VideoAttachment").unwrap();
    assert_eq!(video_var.tag.as_deref(), Some("VIDEO"));

    let sticker_var = base_poly.variants.iter().find(|v| v.name == "Api::OneMe::Types::StickerAttachment").unwrap();
    assert_eq!(sticker_var.tag.as_deref(), Some("STICKER"));

    let audio_var = base_poly.variants.iter().find(|v| v.name == "Api::OneMe::Types::AudioAttachment").unwrap();
    assert_eq!(audio_var.tag.as_deref(), Some("AUDIO"));
}

#[test]
fn test_recursive_ownership_cycle_detection_end_to_end() {
    use std::collections::{BTreeMap, BTreeSet};

    let base_attach = "Api::OneMe::Types::BaseAttachment";
    let file_attach = "Api::OneMe::Types::FileAttachment";
    let share_attach = "Api::OneMe::Types::ShareAttachment";
    let control_attach = "Api::OneMe::Types::ControlAttachment";
    let photo_attach = "Api::OneMe::Types::PhotoAttachment";
    let msg = "Api::OneMe::Types::Message";
    let msg_link = "Api::OneMe::Types::MessageLink";
    let msg_preview = "Api::OneMe::Types::MessagePreview";
    let out_msg = "Api::OneMe::Types::OutgoingMessage";
    let out_msg_link = "Api::OneMe::Types::OutgoingMessage::OutgoingMessageLink";

    let make_field = |name: &str, type_name: &str| ExtractedField {
        name: name.to_string(),
        field_type: decompose_type(type_name),
        required: false,
        recursive: false,
    };

    let make_entry = |name: &str, offset: &str, fields: Vec<ExtractedField>| TypeDescriptorEntry {
        name: name.to_string(),
        ident: dumper_rust::type_parser::cpp_to_ident(name),
        offset: Some(offset.to_string()),
        fields,
        warn: None,
    };

    let entries: HashMap<String, TypeDescriptorEntry> = vec![
        make_entry(base_attach, "0x100", vec![make_field("_type", "std::string")]),
        make_entry(
            file_attach,
            "0x200",
            vec![
                make_field("fileId", "int64_t"),
                make_field(
                    "preview",
                    &format!("std::optional<Api::OneMe::Types::Polymorphic<{base_attach}>>"),
                ),
            ],
        ),
        make_entry(
            share_attach,
            "0x300",
            vec![
                make_field("shareId", "int64_t"),
                make_field("image", &format!("std::optional<{photo_attach}>")),
                make_field(
                    "media",
                    &format!("std::optional<Api::OneMe::Types::Polymorphic<{base_attach}>>"),
                ),
            ],
        ),
        make_entry(
            control_attach,
            "0x400",
            vec![
                make_field("event", "std::string"),
                make_field("pinnedMessage", &format!("std::optional<{msg}>")),
            ],
        ),
        make_entry(photo_attach, "0x500", vec![make_field("photoId", "int64_t")]),
        make_entry(
            msg,
            "0x600",
            vec![
                make_field(
                    "attaches",
                    &format!(
                        "std::optional<std::vector<Api::OneMe::Types::Polymorphic<{base_attach}>>>"
                    ),
                ),
                make_field(
                    "link",
                    &format!("std::optional<std::shared_ptr<{msg_link}>>"),
                ),
                make_field("messagePreview", &format!("std::optional<{msg_preview}>")),
                make_field(
                    "byId",
                    &format!("std::unordered_map<int64_t, {msg}>"),
                ),
            ],
        ),
        make_entry(
            msg_link,
            "0x700",
            vec![
                make_field("type", "std::string"),
                make_field("message", msg),
            ],
        ),
        make_entry(
            msg_preview,
            "0x800",
            vec![
                make_field("text", "std::optional<std::string>"),
                make_field(
                    "attachment",
                    &format!("std::optional<Api::OneMe::Types::Polymorphic<{base_attach}>>"),
                ),
            ],
        ),
        make_entry(
            out_msg,
            "0x900",
            vec![
                make_field("text", "std::optional<std::string>"),
                make_field("link", &format!("std::optional<{out_msg_link}>")),
            ],
        ),
        make_entry(
            out_msg_link,
            "0xa00",
            vec![
                make_field("type", "std::string"),
                make_field("message", &format!("std::optional<{out_msg}>")),
            ],
        ),
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

    let mut roots = BTreeMap::new();
    let mut sources = BTreeSet::new();
    sources.insert(RootSource::ProtocolField);
    roots.insert(base_attach.to_string(), sources);

    let mut hierarchy = HashMap::new();
    hierarchy.insert(
        base_attach.to_string(),
        vec![
            file_attach.to_string(),
            share_attach.to_string(),
            control_attach.to_string(),
            photo_attach.to_string(),
        ],
    );

    let (mut poly_models, _) =
        build_polymorphic_models(&roots, &hierarchy, &mut resolve, &BTreeMap::new());

    let packet = PacketEntry {
        opcode: 64,
        name: "Api::OneMe::Packets::Msg::Send".to_string(),
        ident: "MsgSend".to_string(),
        request: make_entry(
            "Api::OneMe::Packets::Msg::Send::Parameters",
            "0x10",
            vec![make_field("message", out_msg)],
        ),
        response: make_entry(
            "Api::OneMe::Packets::Msg::Send::Response",
            "0x20",
            vec![make_field("message", msg)],
        ),
    };

    let mut models = build_model_catalog(&[packet], &[], &poly_models, &mut resolve);
    mark_recursive_fields(&mut models, &mut poly_models);

    let find_model_field = |model_name: &str, field_name: &str| -> &ExtractedField {
        models
            .iter()
            .find(|m| m.name == model_name)
            .unwrap_or_else(|| panic!("missing model {model_name}"))
            .fields
            .iter()
            .find(|f| f.name == field_name)
            .unwrap_or_else(|| panic!("missing field {model_name}.{field_name}"))
    };

    // 1. 2-node model cycles: Message <-> MessageLink, OutgoingMessage <-> OutgoingMessageLink
    assert!(find_model_field(msg, "link").recursive);
    assert!(find_model_field(msg_link, "message").recursive);
    assert!(!find_model_field(msg_link, "type").recursive);

    assert!(find_model_field(out_msg, "link").recursive);
    assert!(find_model_field(out_msg_link, "message").recursive);
    assert!(!find_model_field(out_msg, "text").recursive);

    // 2. Indirected fields (array: true, map: true) remain recursive: false
    assert!(!find_model_field(msg, "attaches").recursive);
    assert!(!find_model_field(msg, "byId").recursive);

    // 3. Multi-hop cycle: BaseAttachment -> ControlAttachment.pinnedMessage -> Message -> MessagePreview -> BaseAttachment
    assert!(find_model_field(msg, "messagePreview").recursive);
    assert!(find_model_field(msg_preview, "attachment").recursive);
    assert!(!find_model_field(msg_preview, "text").recursive);

    // 4. Polymorphic base-variant cycles across variants and rtti_subclasses (both fields and all_fields)
    let poly = &poly_models[0];
    assert!(poly.base.fields.iter().all(|f| !f.recursive));
    for list in [&poly.variants, &poly.rtti_subclasses] {
        let file = list.iter().find(|v| v.name == file_attach).unwrap();
        assert!(file.fields.iter().find(|f| f.name == "preview").unwrap().recursive);
        assert!(file.all_fields.iter().find(|f| f.name == "preview").unwrap().recursive);
        assert!(!file.fields.iter().find(|f| f.name == "fileId").unwrap().recursive);

        let share = list.iter().find(|v| v.name == share_attach).unwrap();
        assert!(share.fields.iter().find(|f| f.name == "media").unwrap().recursive);
        assert!(share.all_fields.iter().find(|f| f.name == "media").unwrap().recursive);
        assert!(!share.fields.iter().find(|f| f.name == "image").unwrap().recursive);

        let control = list.iter().find(|v| v.name == control_attach).unwrap();
        assert!(
            control
                .fields
                .iter()
                .find(|f| f.name == "pinnedMessage")
                .unwrap()
                .recursive
        );
        assert!(
            control
                .all_fields
                .iter()
                .find(|f| f.name == "pinnedMessage")
                .unwrap()
                .recursive
        );
    }

    // 5. Verify serde serialization emits `"recursive": true` / `"recursive": false`
    let msg_json = serde_json::to_value(models.iter().find(|m| m.name == msg).unwrap()).unwrap();
    let msg_fields = msg_json["fields"].as_array().unwrap();
    let link_json = msg_fields.iter().find(|f| f["name"] == "link").unwrap();
    let attaches_json = msg_fields.iter().find(|f| f["name"] == "attaches").unwrap();
    assert_eq!(link_json["recursive"], serde_json::json!(true));
    assert_eq!(attaches_json["recursive"], serde_json::json!(false));
}
