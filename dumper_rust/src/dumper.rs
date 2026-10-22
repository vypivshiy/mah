use crate::discriminator::{
    scan_discriminator_values_with_diagnostics, DiscriminatorScanDiagnostics,
};
pub use crate::discriminator::build_discriminator_catalog;
use crate::extractor::ExtractedField;
use crate::model_resolver::{
    is_empty_model_type_name, ModelResolver, ModelResolverDiagnostic, ModelResolverDiagnosticKind,
    PeModelResolutionSource, ResolvedModel,
};
use crate::pe::PeImage;
use crate::rtti::RttiEngine;
use crate::scanner::ProtocolScanner;
use crate::type_parser::{
    cpp_to_ident, cpp_to_ident_uncollapsed, derive_event_operation, derive_packet_operation,
    extract_polymorphic_base, qualify_endpoint_ident,
};
use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppVersion {
    #[serde(rename = "app_version")]
    pub version: String,
    #[serde(rename = "build_number")]
    pub build: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionsInfo {
    #[serde(rename = "app_version")]
    pub version: String,
    #[serde(rename = "build_number")]
    pub build: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
}

impl From<AppVersion> for OptionsInfo {
    fn from(v: AppVersion) -> Self {
        Self {
            version: v.version,
            build: v.build,
            protocol_version: v.protocol_version,
            config: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DumperOptions {
    pub version: AppVersion,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDescriptorEntry {
    pub offset: Option<String>,
    pub name: String,
    #[serde(default)]
    pub ident: String,
    pub fields: Vec<ExtractedField>,
    pub warn: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEntry {
    pub opcode: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub ident: String,
    pub request: TypeDescriptorEntry,
    pub response: TypeDescriptorEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEntry {
    pub opcode: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub ident: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<TypeDescriptorEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<TypeDescriptorEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warn: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelEntry {
    pub name: String,
    #[serde(default)]
    pub ident: String,
    pub offset: Option<String>,
    pub fields: Vec<ExtractedField>,
    pub warn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolymorphicDiscriminator {
    pub field: String,
    #[serde(rename = "type")]
    pub r#type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolymorphicBase {
    pub offset: Option<String>,
    pub fields: Vec<ExtractedField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolymorphicVariant {
    pub name: String,
    #[serde(default)]
    pub ident: String,
    pub offset: Option<String>,
    pub fields: Vec<ExtractedField>,
    pub all_fields: Vec<ExtractedField>,
    #[serde(
        default,
        alias = "discriminator_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolymorphicModelEntry {
    pub name: String,
    #[serde(default)]
    pub ident: String,
    pub root_sources: Vec<String>,
    #[serde(default)]
    pub discriminator: Option<PolymorphicDiscriminator>,
    pub base: PolymorphicBase,
    #[serde(default, alias = "wire_variants")]
    pub variants: Vec<PolymorphicVariant>,
    #[serde(default, alias = "rtti_variants")]
    pub rtti_subclasses: Vec<PolymorphicVariant>,
}

pub type PolymorphicModelGroup = PolymorphicModelEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpResult {
    pub options: OptionsInfo,
    pub packets: Vec<PacketEntry>,
    pub events: Vec<EventEntry>,
    pub models: Vec<ModelEntry>,
    pub polymorphic_models: Vec<PolymorphicModelEntry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub enums: BTreeMap<String, BTreeMap<String, u64>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub discriminators: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub string_enums: Option<Vec<String>>,
    pub error: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpWithDiagnostics {
    pub dump: DumpResult,
    pub diagnostics: DumpDiagnostics,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DumpDiagnostics {
    pub initializer_candidates: Vec<InitializerCandidateDiagnostic>,
    pub discriminator: DiscriminatorScanDiagnostics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RootSource {
    ProtocolField,
    RttiHeuristic,
}

impl RootSource {
    pub fn as_str(self) -> &'static str {
        match self {
            RootSource::ProtocolField => "protocol_field",
            RootSource::RttiHeuristic => "rtti_heuristic",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitializerCandidateDiagnostic {
    pub model_name: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_rva: Option<String>,
    pub reason: String,
}

impl From<&ModelResolverDiagnostic> for InitializerCandidateDiagnostic {
    fn from(diagnostic: &ModelResolverDiagnostic) -> Self {
        Self {
            model_name: diagnostic.model_name.clone(),
            kind: model_resolver_diagnostic_kind_name(&diagnostic.kind).to_string(),
            function_rva: diagnostic.function_rva.map(|rva| format!("0x{rva:x}")),
            reason: diagnostic.message.clone(),
        }
    }
}

pub struct Dumper;

impl Dumper {
    pub fn dump(
        pe: &PeImage,
        rtti: &RttiEngine,
        scanner: &ProtocolScanner,
        options: &DumperOptions,
    ) -> Result<DumpResult> {
        Ok(Self::dump_with_diagnostics(pe, rtti, scanner, options)?.dump)
    }

    pub fn dump_with_diagnostics(
        pe: &PeImage,
        rtti: &RttiEngine,
        scanner: &ProtocolScanner,
        options: &DumperOptions,
    ) -> Result<DumpWithDiagnostics> {
        let mut proto_ver = options.protocol_version.or(options.version.protocol_version);
        if proto_ver.is_none() {
            if let Some(cfg) = &options.config {
                if let Some(pv) = cfg.get("api_version_uint").and_then(|v| v.as_u64()) {
                    proto_ver = Some(pv as u32);
                }
            }
        }

        let (mut app_ver, mut build_num) =
            if !options.version.version.is_empty() && options.version.build > 0 {
                (options.version.version.clone(), options.version.build)
            } else if let Some(av) = detect_version_from_bytes(pe.raw) {
                let v = if !options.version.version.is_empty() {
                    options.version.version.clone()
                } else {
                    av.version
                };
                let b = if options.version.build > 0 {
                    options.version.build
                } else {
                    av.build
                };
                (v, b)
            } else {
                ("unknown".to_string(), 0)
            };

        if let Some(pv) = proto_ver {
            if app_ver.is_empty() || app_ver == "unknown" {
                app_ver = format!("proto-{}", pv);
            }
            if build_num == 0 {
                build_num = pv;
            }
        }

        let source = PeModelResolutionSource::new(pe, rtti);
        let mut model_resolver = ModelResolver::new(source);
        let mut find_type_entry = |type_name: &str| -> TypeDescriptorEntry {
            type_entry_from_resolved(model_resolver.resolve_model(type_name))
        };

        // 1. Packets
        let mut packets = Vec::new();
        for p in &scanner.packets {
            let mut req = find_type_entry(&p.request_full_name);
            let mut resp = find_type_entry(&p.response_full_name);
            let (op_name, op_ident) = derive_packet_operation(p.opcode, &req.name, &resp.name);
            req.ident = qualify_endpoint_ident(&op_ident, &req.name);
            resp.ident = qualify_endpoint_ident(&op_ident, &resp.name);
            packets.push(PacketEntry {
                opcode: p.opcode,
                name: op_name,
                ident: op_ident,
                request: req,
                response: resp,
            });
        }
        packets.sort_by_key(|p| p.opcode);

        // 2. Events
        let mut events = Vec::new();
        for e in &scanner.events {
            if e.is_special {
                let mut req = apply_special_request_fields(
                    find_type_entry(&e.request_full_name),
                    &e.special_request_fields,
                );
                let (op_name, op_ident) = derive_event_operation(
                    e.opcode,
                    e.special_name.as_deref(),
                    &req.name,
                    "",
                );
                req.ident = qualify_endpoint_ident(&op_ident, &req.name);
                events.push(EventEntry {
                    opcode: e.opcode,
                    kind: Some("special_packet".to_string()),
                    name: op_name,
                    ident: op_ident,
                    base_kind: e.base_kind.clone(),
                    offset: req.offset.clone(),
                    request: Some(req),
                    response: None,
                    warn: None,
                });
            } else {
                let mut req = find_type_entry(&e.request_full_name);
                let mut resp = find_type_entry(&e.response_full_name);
                let (op_name, op_ident) =
                    derive_event_operation(e.opcode, None, &req.name, &resp.name);
                req.ident = qualify_endpoint_ident(&op_ident, &req.name);
                resp.ident = qualify_endpoint_ident(&op_ident, &resp.name);
                events.push(EventEntry {
                    opcode: e.opcode,
                    kind: None,
                    name: op_name,
                    ident: op_ident,
                    base_kind: None,
                    offset: None,
                    request: Some(req),
                    response: Some(resp),
                    warn: None,
                });
            }
        }
        events.sort_by_key(|e| e.opcode);

        // 3. Dynamic Polymorphic models discovery
        let poly_roots = discover_polymorphic_roots(
            &packets,
            &events,
            &rtti.hierarchy.base_to_derived,
            &mut find_type_entry,
        );

        // 4. Discriminator scanning and polymorphic models assembly
        let polymorphic_variant_names =
            collect_polymorphic_variant_names(&poly_roots, &rtti.hierarchy.base_to_derived);
        let (discriminator_values, discriminator_diagnostics) =
            scan_discriminator_values_with_diagnostics(pe, rtti, &polymorphic_variant_names);
        let (polymorphic_models, _polymorphic_type_names) = build_polymorphic_models(
            &poly_roots,
            &rtti.hierarchy.base_to_derived,
            &mut find_type_entry,
            &discriminator_values,
        );

        // 5. Models catalog construction (standalone models and active variants)
        let models_list =
            build_model_catalog(&packets, &events, &polymorphic_models, &mut find_type_entry);

        let discriminators = build_discriminator_catalog(&polymorphic_models);

        let default_error_payload = serde_json::json!({
            "error": "std::string",
            "localizedMessage": "std::string",
            "message": "std::string",
            "title": "std::string",
        });

        let diagnostics = DumpDiagnostics {
            initializer_candidates: model_resolver
                .diagnostics()
                .iter()
                .filter(|diagnostic| {
                    matches!(
                        diagnostic.kind,
                        ModelResolverDiagnosticKind::RejectedInitializerCandidate
                            | ModelResolverDiagnosticKind::ConflictingInitializerCandidates
                    )
                })
                .map(InitializerCandidateDiagnostic::from)
                .collect(),
            discriminator: discriminator_diagnostics,
        };

        let enums = crate::datamining::enums::extract_static_enums(pe);
        let string_enums = if enums.is_empty() {
            Some(scanner.string_enums.clone())
        } else {
            None
        };

        Ok(DumpWithDiagnostics {
            dump: DumpResult {
                options: OptionsInfo {
                    version: app_ver,
                    build: build_num,
                    protocol_version: proto_ver,
                    config: options.config.clone(),
                },
                packets,
                events,
                models: models_list,
                polymorphic_models,
                enums,
                discriminators,
                string_enums,
                error: default_error_payload,
            },
            diagnostics,
        })
    }
}

fn model_resolver_diagnostic_kind_name(kind: &ModelResolverDiagnosticKind) -> &'static str {
    match kind {
        ModelResolverDiagnosticKind::RejectedField => "rejected_field",
        ModelResolverDiagnosticKind::RejectedInitializerCandidate => {
            "rejected_initializer_candidate"
        }
        ModelResolverDiagnosticKind::ConflictingInitializerCandidates => {
            "conflicting_initializer_candidates"
        }
        ModelResolverDiagnosticKind::ExtractorError => "extractor_error",
        ModelResolverDiagnosticKind::NoInitializer => "no_initializer",
    }
}

fn type_entry_from_resolved(resolved: ResolvedModel) -> TypeDescriptorEntry {
    let ident = cpp_to_ident(&resolved.name);
    TypeDescriptorEntry {
        offset: resolved.offset,
        name: resolved.name,
        ident,
        fields: resolved.fields,
        warn: resolved.warn,
    }
}

pub fn extract_polymorphic_base_from_field(field: &ExtractedField) -> Option<String> {
    if let Some(base) = &field.field_type.polymorphic_base {
        return Some(base.clone());
    }
    extract_polymorphic_base(&field.field_type.full)
        .or_else(|| {
            field
                .field_type
                .name
                .as_deref()
                .and_then(extract_polymorphic_base)
        })
        .or_else(|| {
            field
                .field_type
                .map_value
                .as_deref()
                .and_then(extract_polymorphic_base)
        })
        .or_else(|| {
            field
                .field_type
                .map_key
                .as_deref()
                .and_then(extract_polymorphic_base)
        })
}

pub fn is_primitive_or_builtin_type(name: &str) -> bool {
    matches!(
        name,
        "bool"
            | "char"
            | "int8_t"
            | "uint8_t"
            | "int16_t"
            | "uint16_t"
            | "int32_t"
            | "uint32_t"
            | "int64_t"
            | "uint64_t"
            | "int"
            | "unsigned int"
            | "short"
            | "unsigned short"
            | "long long"
            | "unsigned long long"
            | "float"
            | "double"
            | "std::string"
            | "std::string_view"
    ) || name.starts_with("std::")
}

static API_REF_RE: OnceLock<Regex> = OnceLock::new();

pub fn collect_model_refs_from_field(field: &ExtractedField, queue: &mut Vec<String>) {
    let api_ref_re =
        API_REF_RE.get_or_init(|| Regex::new(r"Api::OneMe::([A-Za-z0-9_:]+)").unwrap());
    let mut found_any = false;
    for s in [
        Some(&field.field_type.full),
        field.field_type.name.as_ref(),
        field.field_type.map_key.as_ref(),
        field.field_type.map_value.as_ref(),
        field.field_type.polymorphic_base.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        for cap in api_ref_re.find_iter(s) {
            queue.push(cap.as_str().to_string());
            found_any = true;
        }
    }
    if !found_any {
        for type_name in [
            field.field_type.name.as_deref(),
            field.field_type.map_value.as_deref(),
            field.field_type.polymorphic_base.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !is_primitive_or_builtin_type(type_name) && !is_empty_model_type_name(type_name) {
                queue.push(type_name.to_string());
            }
        }
    }
}

pub fn discover_polymorphic_roots<F>(
    packets: &[PacketEntry],
    events: &[EventEntry],
    base_to_derived: &HashMap<String, Vec<String>>,
    find_type_entry: &mut F,
) -> BTreeMap<String, BTreeSet<RootSource>>
where
    F: FnMut(&str) -> TypeDescriptorEntry,
{
    let mut poly_roots: BTreeMap<String, BTreeSet<RootSource>> = BTreeMap::new();

    // 1. Collect heuristic roots from RTTI hierarchy
    for (base, derived) in base_to_derived {
        if base.starts_with("Api::OneMe::")
            && !derived.is_empty()
            && (base.ends_with("Attachment") || base.ends_with("Params"))
        {
            poly_roots
                .entry(base.clone())
                .or_default()
                .insert(RootSource::RttiHeuristic);
        }
    }

    // 2. Identify top-level packet/event request/response names to avoid re-resolving them as models
    let mut packet_req_resp_names = HashSet::new();
    for p in packets {
        packet_req_resp_names.insert(p.request.name.clone());
        packet_req_resp_names.insert(p.response.name.clone());
    }
    for e in events {
        if let Some(r) = &e.request {
            packet_req_resp_names.insert(r.name.clone());
        }
        if let Some(r) = &e.response {
            packet_req_resp_names.insert(r.name.clone());
        }
    }

    let mut queue = Vec::new();
    let mut visited = HashSet::new();

    let inspect_field = |field: &ExtractedField,
                         poly_roots: &mut BTreeMap<String, BTreeSet<RootSource>>,
                         queue: &mut Vec<String>| {
        if let Some(base) = extract_polymorphic_base_from_field(field) {
            poly_roots
                .entry(base.clone())
                .or_default()
                .insert(RootSource::ProtocolField);
            queue.push(base.clone());
            if let Some(derived) = base_to_derived.get(&base) {
                for d in derived {
                    queue.push(d.clone());
                }
            }
        }
        collect_model_refs_from_field(field, queue);
    };

    // Inspect all top-level packet and event fields as seed points
    for p in packets {
        for f in &p.request.fields {
            inspect_field(f, &mut poly_roots, &mut queue);
        }
        for f in &p.response.fields {
            inspect_field(f, &mut poly_roots, &mut queue);
        }
    }
    for e in events {
        if let Some(r) = &e.request {
            for f in &r.fields {
                inspect_field(f, &mut poly_roots, &mut queue);
            }
        }
        if let Some(r) = &e.response {
            for f in &r.fields {
                inspect_field(f, &mut poly_roots, &mut queue);
            }
        }
    }

    // 3. Recursive traversal across all reachable models
    while let Some(model_name) = queue.pop() {
        if is_empty_model_type_name(&model_name)
            || model_name.ends_with("::Polymorphic")
            || is_primitive_or_builtin_type(&model_name)
            || packet_req_resp_names.contains(&model_name)
        {
            continue;
        }
        if !visited.insert(model_name.clone()) {
            continue;
        }

        let entry = find_type_entry(&model_name);
        for field in &entry.fields {
            inspect_field(field, &mut poly_roots, &mut queue);
        }
    }

    poly_roots
}

pub fn build_polymorphic_models<F>(
    roots: &BTreeMap<String, BTreeSet<RootSource>>,
    base_to_derived: &HashMap<String, Vec<String>>,
    find_type_entry: &mut F,
    discriminator_values: &BTreeMap<String, String>,
) -> (Vec<PolymorphicModelEntry>, BTreeSet<String>)
where
    F: FnMut(&str) -> TypeDescriptorEntry,
{
    let mut models = Vec::new();
    let mut model_catalog_names = BTreeSet::new();

    for (base_name, root_sources) in roots {
        let base_entry = find_type_entry(base_name);
        let mut derived_names: Vec<String> = base_to_derived
            .get(base_name)
            .into_iter()
            .flat_map(|names| names.iter())
            .filter(|name| *name != base_name)
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        derived_names.sort();

        let mut rtti_subclasses = Vec::new();
        for derived_name in derived_names {
            let derived_entry = find_type_entry(&derived_name);
            rtti_subclasses.push(polymorphic_variant_from_entry(
                derived_name,
                &base_entry.fields,
                derived_entry,
                None,
            ));
        }

        let variants = if root_sources.contains(&RootSource::ProtocolField) {
            rtti_subclasses
                .iter()
                .cloned()
                .map(|mut variant| {
                    variant.tag = discriminator_values.get(&variant.name).cloned();
                    variant
                })
                .collect()
        } else {
            Vec::new()
        };

        if root_sources.contains(&RootSource::ProtocolField) {
            model_catalog_names.insert(base_name.clone());
            for variant in &variants {
                model_catalog_names.insert(variant.name.clone());
            }
        }

        let discriminator = if base_entry.fields.iter().any(|field| field.name == "_type") {
            Some(PolymorphicDiscriminator {
                field: "_type".to_string(),
                r#type: "std::string".to_string(),
            })
        } else {
            None
        };

        models.push(PolymorphicModelEntry {
            name: base_name.clone(),
            ident: cpp_to_ident(base_name),
            root_sources: root_sources
                .iter()
                .map(|source| source.as_str().to_string())
                .collect(),
            discriminator,
            base: PolymorphicBase {
                offset: base_entry.offset,
                fields: base_entry.fields,
            },
            variants,
            rtti_subclasses,
        });
    }

    disambiguate_polymorphic_idents(&mut models);

    (models, model_catalog_names)
}

pub fn build_model_catalog<F>(
    packets: &[PacketEntry],
    events: &[EventEntry],
    polymorphic_models: &[PolymorphicModelEntry],
    find_type_entry: &mut F,
) -> Vec<ModelEntry>
where
    F: FnMut(&str) -> TypeDescriptorEntry,
{
    let mut packet_req_resp_names = HashSet::new();
    for p in packets {
        packet_req_resp_names.insert(p.request.name.clone());
        packet_req_resp_names.insert(p.response.name.clone());
    }
    for e in events {
        if let Some(r) = &e.request {
            packet_req_resp_names.insert(r.name.clone());
        }
        if let Some(r) = &e.response {
            packet_req_resp_names.insert(r.name.clone());
        }
    }

    let mut polymorphic_excluded = HashSet::new();
    for poly in polymorphic_models {
        polymorphic_excluded.insert(poly.name.clone());
        for v in &poly.variants {
            polymorphic_excluded.insert(v.name.clone());
        }
        for s in &poly.rtti_subclasses {
            polymorphic_excluded.insert(s.name.clone());
        }
    }

    let mut models_map: BTreeMap<String, ModelEntry> = BTreeMap::new();
    let mut bfs_queue = Vec::new();
    let mut visited = HashSet::new();

    let collect_refs_from_fields = |fields: &[ExtractedField], queue: &mut Vec<String>| {
        for f in fields {
            collect_model_refs_from_field(f, queue);
        }
    };

    // 1. Traverse fields of polymorphic bases and active variants so standalone models
    // reachable only through polymorphic variants (e.g. VideoCollage, Keyboard, WidgetContent, Log::*Meta)
    // are discovered, while excluding polymorphic bases, variants, and rtti_subclasses from `models`.
    for poly in polymorphic_models {
        collect_refs_from_fields(&poly.base.fields, &mut bfs_queue);

        for variant in &poly.variants {
            collect_refs_from_fields(&variant.fields, &mut bfs_queue);
            collect_refs_from_fields(&variant.all_fields, &mut bfs_queue);
            if !packet_req_resp_names.contains(&variant.name)
                && !is_empty_model_type_name(&variant.name)
                && !variant.name.ends_with("::Polymorphic")
            {
                let entry = find_type_entry(&variant.name);
                collect_refs_from_fields(&entry.fields, &mut bfs_queue);
            }
        }
    }

    // 2. Enqueue standalone models directly referenced by Packets and Events
    for p in packets {
        collect_refs_from_fields(&p.request.fields, &mut bfs_queue);
        collect_refs_from_fields(&p.response.fields, &mut bfs_queue);
    }
    for e in events {
        if let Some(r) = &e.request {
            collect_refs_from_fields(&r.fields, &mut bfs_queue);
        }
        if let Some(r) = &e.response {
            collect_refs_from_fields(&r.fields, &mut bfs_queue);
        }
    }

    // 3. BFS traversal for standalone models directly or transitively referenced
    while let Some(model_name) = bfs_queue.pop() {
        if !visited.insert(model_name.clone()) {
            continue;
        }

        if is_empty_model_type_name(&model_name)
            || model_name.ends_with("::Polymorphic")
            || is_primitive_or_builtin_type(&model_name)
            || packet_req_resp_names.contains(&model_name)
            || polymorphic_excluded.contains(&model_name)
        {
            continue;
        }

        if models_map.contains_key(&model_name) {
            continue;
        }

        let entry = find_type_entry(&model_name);

        collect_refs_from_fields(&entry.fields, &mut bfs_queue);

        let ident = cpp_to_ident(&model_name);
        models_map.insert(
            model_name.clone(),
            ModelEntry {
                name: model_name,
                ident,
                offset: entry.offset,
                fields: entry.fields,
                warn: entry.warn,
            },
        );
    }

    let mut models: Vec<ModelEntry> = models_map.into_values().collect();
    disambiguate_model_idents(&mut models, polymorphic_models);
    models
}

fn disambiguate_polymorphic_idents(polymorphic_models: &mut [PolymorphicModelEntry]) {
    let mut ident_to_names: HashMap<String, BTreeSet<String>> = HashMap::new();
    for poly in polymorphic_models.iter() {
        ident_to_names
            .entry(poly.ident.clone())
            .or_default()
            .insert(poly.name.clone());
        for v in &poly.variants {
            ident_to_names
                .entry(v.ident.clone())
                .or_default()
                .insert(v.name.clone());
        }
        for s in &poly.rtti_subclasses {
            ident_to_names
                .entry(s.ident.clone())
                .or_default()
                .insert(s.name.clone());
        }
    }

    let colliding_idents: HashSet<String> = ident_to_names
        .into_iter()
        .filter_map(|(ident, names)| if names.len() > 1 { Some(ident) } else { None })
        .collect();

    if colliding_idents.is_empty() {
        return;
    }

    for poly in polymorphic_models.iter_mut() {
        if colliding_idents.contains(&poly.ident) {
            let uncollapsed = cpp_to_ident_uncollapsed(&poly.name);
            if !uncollapsed.is_empty() {
                poly.ident = uncollapsed;
            }
        }
        for v in &mut poly.variants {
            if colliding_idents.contains(&v.ident) {
                let uncollapsed = cpp_to_ident_uncollapsed(&v.name);
                if !uncollapsed.is_empty() {
                    v.ident = uncollapsed;
                }
            }
        }
        for s in &mut poly.rtti_subclasses {
            if colliding_idents.contains(&s.ident) {
                let uncollapsed = cpp_to_ident_uncollapsed(&s.name);
                if !uncollapsed.is_empty() {
                    s.ident = uncollapsed;
                }
            }
        }
    }
}

fn disambiguate_model_idents(
    models: &mut [ModelEntry],
    polymorphic_models: &[PolymorphicModelEntry],
) {
    let mut ident_to_names: HashMap<String, BTreeSet<String>> = HashMap::new();
    for poly in polymorphic_models {
        ident_to_names
            .entry(poly.ident.clone())
            .or_default()
            .insert(poly.name.clone());
        for v in &poly.variants {
            ident_to_names
                .entry(v.ident.clone())
                .or_default()
                .insert(v.name.clone());
        }
        for s in &poly.rtti_subclasses {
            ident_to_names
                .entry(s.ident.clone())
                .or_default()
                .insert(s.name.clone());
        }
    }
    for m in models.iter() {
        ident_to_names
            .entry(m.ident.clone())
            .or_default()
            .insert(m.name.clone());
    }

    let colliding_idents: HashSet<String> = ident_to_names
        .into_iter()
        .filter_map(|(ident, names)| if names.len() > 1 { Some(ident) } else { None })
        .collect();

    if colliding_idents.is_empty() {
        return;
    }

    for m in models.iter_mut() {
        if colliding_idents.contains(&m.ident) {
            let uncollapsed = cpp_to_ident_uncollapsed(&m.name);
            if !uncollapsed.is_empty() {
                m.ident = uncollapsed;
            }
        }
    }
}

fn polymorphic_variant_from_entry(
    name: String,
    base_fields: &[ExtractedField],
    entry: TypeDescriptorEntry,
    tag: Option<String>,
) -> PolymorphicVariant {
    let fields = entry.fields;
    let ident = cpp_to_ident(&name);
    PolymorphicVariant {
        name,
        ident,
        offset: entry.offset,
        all_fields: flattened_polymorphic_fields(base_fields, &fields),
        fields,
        tag,
    }
}

fn collect_polymorphic_variant_names(
    roots: &BTreeMap<String, BTreeSet<RootSource>>,
    base_to_derived: &HashMap<String, Vec<String>>,
) -> BTreeSet<String> {
    roots
        .keys()
        .flat_map(|base_name| {
            base_to_derived
                .get(base_name)
                .into_iter()
                .flat_map(move |names| names.iter().filter(move |name| *name != base_name).cloned())
        })
        .collect()
}

fn flattened_polymorphic_fields(
    base_fields: &[ExtractedField],
    local_fields: &[ExtractedField],
) -> Vec<ExtractedField> {
    let mut fields = base_fields.to_vec();
    let mut seen_names: HashSet<String> = fields.iter().map(|field| field.name.clone()).collect();
    for field in local_fields {
        if seen_names.insert(field.name.clone()) {
            fields.push(field.clone());
        }
    }
    fields
}

pub fn detect_version_from_bytes(bytes: &[u8]) -> Option<AppVersion> {
    let re = regex::bytes::Regex::new(r"\d+\.\d+\.\d+[\.:]\d+").ok()?;
    for m in re.find_iter(bytes) {
        if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
            let parts: Vec<&str> = s.split(['.', ':']).collect();
            if parts.len() >= 4 {
                let ver = parts[..3].join(".");
                if let Ok(build) = parts[3].parse::<u32>() {
                    return Some(AppVersion {
                        version: ver,
                        build,
                        protocol_version: None,
                    });
                }
            }
        }
    }
    None
}
fn apply_special_request_fields(
    mut entry: TypeDescriptorEntry,
    fields: &[ExtractedField],
) -> TypeDescriptorEntry {
    if entry.fields.is_empty() && !fields.is_empty() {
        entry.fields = fields.to_vec();
        entry.warn = None;
    }
    entry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ping_payload_fields;

    fn field(name: &str, type_name: &str) -> ExtractedField {
        ExtractedField {
            name: name.to_string(),
            field_type: crate::type_parser::decompose_type(type_name),
            required: false,
        }
    }

    fn entry(name: &str, offset: &str, fields: Vec<ExtractedField>) -> TypeDescriptorEntry {
        TypeDescriptorEntry {
            offset: Some(offset.to_string()),
            name: name.to_string(),
            ident: cpp_to_ident(name),
            fields,
            warn: None,
        }
    }

    fn roots(base_name: &str, sources: &[&str]) -> BTreeMap<String, BTreeSet<RootSource>> {
        let mut roots = BTreeMap::new();
        roots.insert(
            base_name.to_string(),
            sources
                .iter()
                .map(|source| match *source {
                    "protocol_field" => RootSource::ProtocolField,
                    "rtti_heuristic" => RootSource::RttiHeuristic,
                    other => panic!("unknown test root source {other}"),
                })
                .collect(),
        );
        roots
    }

    fn hierarchy(base_name: &str, derived_names: &[&str]) -> HashMap<String, Vec<String>> {
        let mut hierarchy = HashMap::new();
        hierarchy.insert(
            base_name.to_string(),
            derived_names.iter().map(|name| name.to_string()).collect(),
        );
        hierarchy
    }

    fn build_test_polymorphic_models(
        roots: BTreeMap<String, BTreeSet<RootSource>>,
        hierarchy: HashMap<String, Vec<String>>,
        entries: Vec<TypeDescriptorEntry>,
    ) -> (Vec<PolymorphicModelEntry>, BTreeSet<String>) {
        build_test_polymorphic_models_with_values(roots, hierarchy, entries, BTreeMap::new())
    }

    fn build_test_polymorphic_models_with_values(
        roots: BTreeMap<String, BTreeSet<RootSource>>,
        hierarchy: HashMap<String, Vec<String>>,
        entries: Vec<TypeDescriptorEntry>,
        discriminator_values: BTreeMap<String, String>,
    ) -> (Vec<PolymorphicModelEntry>, BTreeSet<String>) {
        let entries_by_name: HashMap<String, TypeDescriptorEntry> = entries
            .into_iter()
            .map(|entry| (entry.name.clone(), entry))
            .collect();
        let mut resolve = |name: &str| {
            entries_by_name
                .get(name)
                .unwrap_or_else(|| panic!("missing test entry for {name}"))
                .clone()
        };

        build_polymorphic_models(&roots, &hierarchy, &mut resolve, &discriminator_values)
    }

    fn field_names(fields: &[ExtractedField]) -> Vec<&str> {
        fields.iter().map(|field| field.name.as_str()).collect()
    }

    fn variant_names(variants: &[PolymorphicVariant]) -> Vec<&str> {
        variants
            .iter()
            .map(|variant| variant.name.as_str())
            .collect()
    }

    fn build_test_model_catalog(
        packets: Vec<PacketEntry>,
        events: Vec<EventEntry>,
        polymorphic_models: Vec<PolymorphicModelEntry>,
        entries: Vec<TypeDescriptorEntry>,
    ) -> Vec<ModelEntry> {
        let entries_by_name: HashMap<String, TypeDescriptorEntry> = entries
            .into_iter()
            .map(|entry| (entry.name.clone(), entry))
            .collect();
        let mut resolve = |name: &str| {
            entries_by_name
                .get(name)
                .unwrap_or_else(|| panic!("missing test entry for {name}"))
                .clone()
        };
        build_model_catalog(&packets, &events, &polymorphic_models, &mut resolve)
    }

    #[test]
    fn polymorphic_builder_protocol_field_root_populates_variants_and_rtti_subclasses() {
        let base = "Api::OneMe::Types::BaseAttachment";
        let photo = "Api::OneMe::Types::PhotoAttachment";
        let (models, catalog_names) = build_test_polymorphic_models(
            roots(base, &["protocol_field"]),
            hierarchy(base, &[photo]),
            vec![
                entry(base, "0x100", vec![field("_type", "std::string")]),
                entry(photo, "0x200", vec![field("url", "std::string")]),
            ],
        );

        assert_eq!(models.len(), 1);
        let model = &models[0];
        assert_eq!(model.name, base);
        assert_eq!(model.root_sources, vec!["protocol_field"]);
        let discriminator = model
            .discriminator
            .as_ref()
            .expect("must have discriminator");
        assert_eq!(discriminator.field, "_type");
        assert_eq!(discriminator.r#type, "std::string");
        assert_eq!(field_names(&model.base.fields), vec!["_type"]);
        assert_eq!(variant_names(&model.variants), vec![photo]);
        assert_eq!(variant_names(&model.rtti_subclasses), vec![photo]);
        assert!(catalog_names.contains(base));
        assert!(catalog_names.contains(photo));
    }

    #[test]
    fn polymorphic_builder_rtti_heuristic_root_keeps_empty_variants() {
        let base = "Api::OneMe::Types::Log::EventParams";
        let opened = "Api::OneMe::Types::Log::OpenedParams";
        let (models, catalog_names) = build_test_polymorphic_models(
            roots(base, &["rtti_heuristic"]),
            hierarchy(base, &[opened]),
            vec![
                entry(base, "0x300", vec![field("common", "int")]),
                entry(opened, "0x400", vec![field("duration", "int")]),
            ],
        );

        let model = &models[0];
        assert_eq!(model.root_sources, vec!["rtti_heuristic"]);
        assert!(model.variants.is_empty());
        assert_eq!(variant_names(&model.rtti_subclasses), vec![opened]);
        assert_eq!(model.discriminator, None);
        assert!(!catalog_names.contains(opened));
        assert!(!catalog_names.contains(base));
    }

    #[test]
    fn polymorphic_builder_excludes_base_from_variants() {
        let base = "Api::OneMe::Types::BaseAttachment";
        let video = "Api::OneMe::Types::VideoAttachment";
        let (models, _) = build_test_polymorphic_models(
            roots(base, &["protocol_field"]),
            hierarchy(base, &[base, video]),
            vec![
                entry(base, "0x500", vec![field("_type", "std::string")]),
                entry(
                    video,
                    "0x600",
                    vec![field("collage", "Api::OneMe::Types::VideoCollage")],
                ),
            ],
        );

        assert_eq!(variant_names(&models[0].variants), vec![video]);
    }

    #[test]
    fn polymorphic_builder_variant_fields_are_local() {
        let base = "Api::OneMe::Types::BaseAttachment";
        let file = "Api::OneMe::Types::FileAttachment";
        let (models, _) = build_test_polymorphic_models(
            roots(base, &["protocol_field"]),
            hierarchy(base, &[file]),
            vec![
                entry(base, "0x700", vec![field("baseId", "int64_t")]),
                entry(file, "0x800", vec![field("fileId", "int64_t")]),
            ],
        );

        let variant = &models[0].variants[0];
        assert_eq!(field_names(&variant.fields), vec!["fileId"]);
    }

    #[test]
    fn polymorphic_builder_all_fields_are_base_first_and_base_wins_duplicate_names() {
        let base = "Api::OneMe::Types::BaseAttachment";
        let sticker = "Api::OneMe::Types::StickerAttachment";
        let (models, _) = build_test_polymorphic_models(
            roots(base, &["protocol_field"]),
            hierarchy(base, &[sticker]),
            vec![
                entry(
                    base,
                    "0x900",
                    vec![field("shared", "int"), field("baseOnly", "bool")],
                ),
                entry(
                    sticker,
                    "0xa00",
                    vec![
                        field("shared", "std::string"),
                        field("localOnly", "std::string"),
                    ],
                ),
            ],
        );

        let all_fields = &models[0].variants[0].all_fields;
        assert_eq!(
            field_names(all_fields),
            vec!["shared", "baseOnly", "localOnly"]
        );
        assert_eq!(all_fields[0].field_type.full, "int32_t");
    }

    #[test]
    fn polymorphic_builder_attaches_direct_tag_to_variant() {
        let base = "Api::OneMe::Types::BaseAttachment";
        let photo = "Api::OneMe::Types::PhotoAttachment";
        let mut discriminator_values = BTreeMap::new();
        discriminator_values.insert(photo.to_string(), "PHOTO".to_string());
        let (models, _) = build_test_polymorphic_models_with_values(
            roots(base, &["protocol_field"]),
            hierarchy(base, &[photo]),
            vec![
                entry(base, "0x100", vec![field("_type", "std::string")]),
                entry(photo, "0x200", vec![field("url", "std::string")]),
            ],
            discriminator_values,
        );

        assert_eq!(models[0].variants[0].tag.as_deref(), Some("PHOTO"));
        assert_eq!(models[0].rtti_subclasses[0].tag, None);
    }

    #[test]
    fn polymorphic_builder_omits_missing_tag() {
        let base = "Api::OneMe::Types::BaseAttachment";
        let photo = "Api::OneMe::Types::PhotoAttachment";
        let (models, _) = build_test_polymorphic_models(
            roots(base, &["protocol_field"]),
            hierarchy(base, &[photo]),
            vec![
                entry(base, "0x100", vec![field("_type", "std::string")]),
                entry(photo, "0x200", vec![field("url", "std::string")]),
            ],
        );

        assert_eq!(models[0].variants[0].tag, None);
        let serialized = serde_json::to_value(&models[0].variants[0]).unwrap();
        assert!(serialized.get("tag").is_none());
        assert!(serialized.get("discriminator_value").is_none());
    }

    #[test]
    fn polymorphic_builder_omits_tags_for_rtti_only_roots() {
        let base = "Api::OneMe::Types::Log::EventParams";
        let opened = "Api::OneMe::Types::Log::OpenedParams";
        let mut discriminator_values = BTreeMap::new();
        discriminator_values.insert(opened.to_string(), "OPENED".to_string());
        let (models, _) = build_test_polymorphic_models_with_values(
            roots(base, &["rtti_heuristic"]),
            hierarchy(base, &[opened]),
            vec![
                entry(base, "0x300", vec![field("common", "int")]),
                entry(opened, "0x400", vec![field("duration", "int")]),
            ],
            discriminator_values,
        );

        assert!(models[0].variants.is_empty());
        assert_eq!(models[0].rtti_subclasses[0].tag, None);
    }

    #[test]
    fn polymorphic_group_serializes_with_variants_rtti_subclasses_and_tag() {
        let base_field = field("_type", "std::string");
        let local_field = field("caption", "std::string");
        let group = PolymorphicModelEntry {
            name: "Api::OneMe::Types::BaseAttachment".to_string(),
            ident: "BaseAttachment".to_string(),
            root_sources: vec!["protocol_field".to_string()],
            discriminator: Some(PolymorphicDiscriminator {
                field: "_type".to_string(),
                r#type: "std::string".to_string(),
            }),
            base: PolymorphicBase {
                offset: Some("0x1000".to_string()),
                fields: vec![base_field.clone()],
            },
            variants: vec![
                PolymorphicVariant {
                    name: "Api::OneMe::Types::PhotoAttachment".to_string(),
                    ident: "PhotoAttachment".to_string(),
                    offset: Some("0x2000".to_string()),
                    fields: vec![local_field.clone()],
                    all_fields: vec![base_field.clone(), local_field.clone()],
                    tag: Some("PHOTO".to_string()),
                },
                PolymorphicVariant {
                    name: "Api::OneMe::Types::UnknownAttachment".to_string(),
                    ident: "UnknownAttachment".to_string(),
                    offset: Some("0x2100".to_string()),
                    fields: vec![],
                    all_fields: vec![base_field.clone()],
                    tag: None,
                },
            ],
            rtti_subclasses: vec![PolymorphicVariant {
                name: "Api::OneMe::Types::PhotoAttachment".to_string(),
                ident: "PhotoAttachment".to_string(),
                offset: Some("0x2000".to_string()),
                fields: vec![local_field],
                all_fields: vec![base_field.clone(), field("caption", "std::string")],
                tag: None,
            }],
        };

        let json = serde_json::to_string_pretty(&group).expect("serialization must succeed");
        let val: serde_json::Value =
            serde_json::from_str(&json).expect("deserialization must succeed");

        assert!(
            val.get("variants").is_some(),
            "Must serialize as 'variants'"
        );
        assert!(
            val.get("wire_variants").is_none(),
            "Must not serialize as 'wire_variants'"
        );
        assert!(
            val.get("rtti_subclasses").is_some(),
            "Must serialize as 'rtti_subclasses'"
        );
        assert!(
            val.get("rtti_variants").is_none(),
            "Must not serialize as 'rtti_variants'"
        );

        let variants = val["variants"].as_array().expect("variants must be array");
        assert_eq!(variants.len(), 2);
        assert_eq!(variants[0]["tag"], "PHOTO");
        assert!(variants[0].get("discriminator_value").is_none());
        assert!(variants[1].get("tag").is_none(), "None tag must be omitted");

        let rtti_subclasses = val["rtti_subclasses"]
            .as_array()
            .expect("rtti_subclasses must be array");
        assert_eq!(rtti_subclasses.len(), 1);
        assert!(rtti_subclasses[0].get("tag").is_none());
    }

    #[test]
    fn polymorphic_group_serializes_discriminator_null_when_base_lacks_type_field() {
        let base = "Api::OneMe::Types::Log::EventParams";
        let call = "Api::OneMe::Types::Log::CallEventParams";
        let (models, _) = build_test_polymorphic_models(
            roots(base, &["protocol_field"]),
            hierarchy(base, &[call]),
            vec![
                entry(base, "0x300", vec![field("common", "int32_t")]),
                entry(call, "0x400", vec![field("duration", "int32_t")]),
            ],
        );

        assert_eq!(models.len(), 1);
        let model = &models[0];
        assert_eq!(model.discriminator, None);

        let json = serde_json::to_string(&model).expect("serialization must succeed");
        assert!(
            json.contains("\"discriminator\":null"),
            "Missing _type must serialize as '\"discriminator\":null', got: {json}"
        );

        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(val.get("discriminator").is_some());
        assert!(val["discriminator"].is_null());
    }

    #[test]
    fn polymorphic_group_serializes_discriminator_object_when_base_has_type_field() {
        let base = "Api::OneMe::Types::BaseAttachment";
        let photo = "Api::OneMe::Types::PhotoAttachment";
        let (models, _) = build_test_polymorphic_models(
            roots(base, &["protocol_field"]),
            hierarchy(base, &[photo]),
            vec![
                entry(base, "0x100", vec![field("_type", "std::string")]),
                entry(photo, "0x200", vec![field("url", "std::string")]),
            ],
        );

        assert_eq!(models.len(), 1);
        let model = &models[0];
        assert_eq!(
            model.discriminator,
            Some(PolymorphicDiscriminator {
                field: "_type".to_string(),
                r#type: "std::string".to_string(),
            })
        );

        let json = serde_json::to_string(&model).expect("serialization must succeed");
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(val["discriminator"]["field"], "_type");
        assert_eq!(val["discriminator"]["type"], "std::string");
    }

    #[test]
    fn special_ping_payload_fields_replace_no_data_warning() {
        let entry = TypeDescriptorEntry {
            offset: None,
            name: "Api::OneMe::Packets::Ping::Payload".to_string(),
            ident: "PingPayload".to_string(),
            fields: Vec::new(),
            warn: Some("no data found".to_string()),
        };

        let resolved = apply_special_request_fields(entry, &ping_payload_fields());

        assert_eq!(resolved.warn, None);
        assert_eq!(resolved.fields, ping_payload_fields());
    }

    #[test]
    fn special_fields_do_not_override_generic_resolution() {
        let existing_fields = vec![ExtractedField {
            name: "existing".to_string(),
            field_type: crate::type_parser::decompose_type("int32_t"),
            required: false,
        }];
        let entry = TypeDescriptorEntry {
            offset: Some("0x1234".to_string()),
            name: "Api::OneMe::Packets::Ping::Payload".to_string(),
            ident: "PingPayload".to_string(),
            fields: existing_fields.clone(),
            warn: None,
        };

        let resolved = apply_special_request_fields(entry, &ping_payload_fields());

        assert_eq!(resolved.offset.as_deref(), Some("0x1234"));
        assert_eq!(resolved.fields, existing_fields);
        assert_eq!(resolved.warn, None);
    }

    #[test]
    fn transitive_polymorphic_root_discovery_elevates_nested_model_polymorphic_types_to_protocol_field(
    ) {
        let packet_req = "Api::OneMe::Packets::Log::Event::Request";
        let packet_resp = "Api::OneMe::Packets::Log::Event::Response";
        let log_event = "Api::OneMe::Packets::Log::LogEvent";
        let event_params = "Api::OneMe::Types::Log::EventParams";
        let call_params = "Api::OneMe::Types::Log::CallEventParams";
        let unknown_params = "Api::OneMe::Types::Log::UnknownContactInteractionParams";
        let unknown_sub_params = "Api::OneMe::Types::Log::UnknownContactInteractionSubParams";

        let packet = PacketEntry {
            opcode: 5,
            name: "Api::OneMe::Packets::Log::Event".to_string(),
            ident: "LogEvent".to_string(),
            request: entry(
                packet_req,
                "0x1000",
                vec![field("events", &format!("std::vector<{log_event}>"))],
            ),
            response: entry(packet_resp, "0x1010", vec![]),
        };

        let mut hierarchy_map = HashMap::new();
        hierarchy_map.insert(
            event_params.to_string(),
            vec![call_params.to_string(), unknown_params.to_string()],
        );
        hierarchy_map.insert(
            unknown_params.to_string(),
            vec![unknown_sub_params.to_string()],
        );

        let entries_by_name: HashMap<String, TypeDescriptorEntry> = vec![
            entry(
                log_event,
                "0x1020",
                vec![field(
                    "params",
                    &format!("std::optional<Api::OneMe::Types::Polymorphic<{event_params}>>"),
                )],
            ),
            entry(event_params, "0x1030", vec![field("common", "int32_t")]),
            entry(call_params, "0x1040", vec![field("duration", "int32_t")]),
            entry(
                unknown_params,
                "0x1050",
                vec![field("unknownField", "int32_t")],
            ),
            entry(
                unknown_sub_params,
                "0x1060",
                vec![field("subField", "int32_t")],
            ),
        ]
        .into_iter()
        .map(|e| (e.name.clone(), e))
        .collect();

        let mut resolve = |name: &str| {
            entries_by_name
                .get(name)
                .cloned()
                .unwrap_or_else(|| entry(name, "0x0", vec![]))
        };

        let roots = discover_polymorphic_roots(&[packet], &[], &hierarchy_map, &mut resolve);

        // Assert EventParams was elevated to ProtocolField while retaining RttiHeuristic
        assert!(roots.contains_key(event_params));
        let event_params_sources = &roots[event_params];
        assert!(
            event_params_sources.contains(&RootSource::ProtocolField),
            "EventParams must be recognized as protocol_field"
        );
        assert!(
            event_params_sources.contains(&RootSource::RttiHeuristic),
            "EventParams must retain rtti_heuristic"
        );

        // Assert intermediate root UnknownContactInteractionParams remains present as RttiHeuristic only
        assert!(roots.contains_key(unknown_params));
        let unknown_sources = &roots[unknown_params];
        assert!(
            !unknown_sources.contains(&RootSource::ProtocolField),
            "UnknownContactInteractionParams must not be marked as protocol_field"
        );
        assert!(
            unknown_sources.contains(&RootSource::RttiHeuristic),
            "UnknownContactInteractionParams must remain as rtti_heuristic"
        );

        // Assert polymorphic builder assembly populates wire variants for EventParams but not UnknownContactInteractionParams
        let (poly_models, _) =
            build_polymorphic_models(&roots, &hierarchy_map, &mut resolve, &BTreeMap::new());

        let event_model = poly_models
            .iter()
            .find(|m| m.name == event_params)
            .expect("EventParams polymorphic model must be present");
        assert_eq!(
            event_model.root_sources,
            vec!["protocol_field", "rtti_heuristic"]
        );
        let event_variant_names = variant_names(&event_model.variants);
        assert_eq!(event_variant_names, vec![call_params, unknown_params]);

        let unknown_model = poly_models
            .iter()
            .find(|m| m.name == unknown_params)
            .expect("UnknownContactInteractionParams polymorphic model must be present");
        assert_eq!(unknown_model.root_sources, vec!["rtti_heuristic"]);
        assert!(
            unknown_model.variants.is_empty(),
            "Heuristic-only intermediate root must have empty variants"
        );
        assert_eq!(
            variant_names(&unknown_model.rtti_subclasses),
            vec![unknown_sub_params]
        );
    }

    #[test]
    fn model_field_referencing_polymorphic_via_decompiled_type_marks_protocol_root() {
        let packet_req = "Api::OneMe::Packets::Log::Event::Request";
        let packet_resp = "Api::OneMe::Packets::Log::Event::Response";
        let log_event = "Api::OneMe::Packets::Log::LogEvent";
        let event_params = "Api::OneMe::Types::Log::EventParams";
        let call_params = "Api::OneMe::Types::Log::CallEventParams";

        let packet = PacketEntry {
            opcode: 5,
            name: "Api::OneMe::Packets::Log::Event".to_string(),
            ident: "LogEvent".to_string(),
            request: entry(
                packet_req,
                "0x1000",
                vec![field("events", &format!("std::vector<{log_event}>"))],
            ),
            response: entry(packet_resp, "0x1010", vec![]),
        };

        let mut hierarchy_map = HashMap::new();
        hierarchy_map.insert(event_params.to_string(), vec![call_params.to_string()]);

        // Construct a field where polymorphic_base is None, but full contains decompiled C++ type
        let raw_decompiled_field = ExtractedField {
            name: "params".to_string(),
            field_type: crate::type_parser::DecomposedType {
                full: format!("class Api::OneMe::Types::Polymorphic<class {event_params}>"),
                name: None,
                ident: None,
                optional: false,
                array: false,
                bytes: false,
                map: false,
                map_key: None,
                map_value: None,
                map_key_type: None,
                map_value_type: None,
                polymorphic: false,
                polymorphic_base: None,
            },
            required: false,
        };

        assert_eq!(
            extract_polymorphic_base_from_field(&raw_decompiled_field),
            Some(event_params.to_string())
        );

        let entries_by_name: HashMap<String, TypeDescriptorEntry> = vec![
            entry(log_event, "0x1020", vec![raw_decompiled_field]),
            entry(event_params, "0x1030", vec![field("common", "int32_t")]),
            entry(call_params, "0x1040", vec![field("duration", "int32_t")]),
        ]
        .into_iter()
        .map(|e| (e.name.clone(), e))
        .collect();

        let mut resolve = |name: &str| {
            entries_by_name
                .get(name)
                .cloned()
                .unwrap_or_else(|| entry(name, "0x0", vec![]))
        };

        let roots = discover_polymorphic_roots(&[packet], &[], &hierarchy_map, &mut resolve);
        assert!(roots.contains_key(event_params));
        assert!(
            roots[event_params].contains(&RootSource::ProtocolField),
            "Decompiled Polymorphic<T> must mark T as protocol_field"
        );
    }

    #[test]
    fn event_payload_transitive_polymorphic_root_discovery() {
        let event_req = "Api::OneMe::Events::Telemetry::Request";
        let log_event = "Api::OneMe::Packets::Log::LogEvent";
        let event_params = "Api::OneMe::Types::Log::EventParams";
        let call_params = "Api::OneMe::Types::Log::CallEventParams";

        let event = EventEntry {
            opcode: 100,
            kind: None,
            name: "Api::OneMe::Events::Telemetry".to_string(),
            ident: "Telemetry".to_string(),
            base_kind: None,
            offset: None,
            request: Some(entry(
                event_req,
                "0x2000",
                vec![field("events", &format!("std::vector<{log_event}>"))],
            )),
            response: None,
            warn: None,
        };

        let mut hierarchy_map = HashMap::new();
        hierarchy_map.insert(event_params.to_string(), vec![call_params.to_string()]);

        let entries_by_name: HashMap<String, TypeDescriptorEntry> = vec![
            entry(
                log_event,
                "0x2010",
                vec![field(
                    "params",
                    &format!("Api::OneMe::Types::Polymorphic<{event_params}>"),
                )],
            ),
            entry(event_params, "0x2020", vec![field("common", "int32_t")]),
            entry(call_params, "0x2030", vec![field("duration", "int32_t")]),
        ]
        .into_iter()
        .map(|e| (e.name.clone(), e))
        .collect();

        let mut resolve = |name: &str| {
            entries_by_name
                .get(name)
                .cloned()
                .unwrap_or_else(|| entry(name, "0x0", vec![]))
        };

        let roots = discover_polymorphic_roots(&[], &[event], &hierarchy_map, &mut resolve);
        assert!(roots.contains_key(event_params));
        assert!(roots[event_params].contains(&RootSource::ProtocolField));
    }

    #[test]
    fn multi_hop_model_transitive_polymorphic_discovery() {
        let outer_model = "Api::OneMe::Types::OuterModel";
        let inner_model = "Api::OneMe::Types::InnerModel";
        let poly_root = "Api::OneMe::Types::DeepAttachment";
        let poly_variant = "Api::OneMe::Types::ConcreteDeepAttachment";

        let packet = PacketEntry {
            opcode: 10,
            name: "Api::OneMe::Packets::Test".to_string(),
            ident: "Test".to_string(),
            request: entry(
                "Api::OneMe::Packets::Test::Request",
                "0x3000",
                vec![field("outer", outer_model)],
            ),
            response: entry("Api::OneMe::Packets::Test::Response", "0x3010", vec![]),
        };

        let mut hierarchy_map = HashMap::new();
        hierarchy_map.insert(poly_root.to_string(), vec![poly_variant.to_string()]);

        let entries_by_name: HashMap<String, TypeDescriptorEntry> = vec![
            entry(outer_model, "0x3020", vec![field("inner", inner_model)]),
            entry(
                inner_model,
                "0x3030",
                vec![field(
                    "attachment",
                    &format!("Api::OneMe::Types::Polymorphic<{poly_root}>"),
                )],
            ),
            entry(poly_root, "0x3040", vec![field("_type", "std::string")]),
            entry(poly_variant, "0x3050", vec![field("data", "std::string")]),
        ]
        .into_iter()
        .map(|e| (e.name.clone(), e))
        .collect();

        let mut resolve = |name: &str| {
            entries_by_name
                .get(name)
                .cloned()
                .unwrap_or_else(|| entry(name, "0x0", vec![]))
        };

        let roots = discover_polymorphic_roots(&[packet], &[], &hierarchy_map, &mut resolve);
        assert!(roots.contains_key(poly_root));
        assert!(roots[poly_root].contains(&RootSource::ProtocolField));
    }

    #[test]
    fn model_catalog_excludes_polymorphic_bases_variants_and_rtti_subclasses_even_when_referenced() {
        let base_attach = "Api::OneMe::Types::BaseAttachment";
        let photo_attach = "Api::OneMe::Types::PhotoAttachment";
        let file_attach = "Api::OneMe::Types::FileAttachment";
        let event_params = "Api::OneMe::Types::Log::EventParams";
        let story_link_meta = "Api::OneMe::Types::Log::StoryLinkMeta";
        let click_story_link =
            "Api::OneMe::Types::Log::ClickParams<Api::OneMe::Types::Log::StoryLinkMeta>";
        let callout_meta = "Api::OneMe::Types::Log::CalloutScreenMeta";
        let click_callout =
            "Api::OneMe::Types::Log::ClickParams<Api::OneMe::Types::Log::CalloutScreenMeta>";
        let unknown_params = "Api::OneMe::Types::Log::UnknownContactInteractionParams";
        let ab_status = "Api::OneMe::Types::Log::AbStatusParams";
        let msg_model = "Api::OneMe::Types::Message";

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
                    fields: vec![field("_type", "std::string")],
                },
                variants: vec![
                    PolymorphicVariant {
                        name: photo_attach.to_string(),
                        ident: "PhotoAttachment".to_string(),
                        offset: Some("0x200".to_string()),
                        fields: vec![field("photoId", "int64_t")],
                        all_fields: vec![
                            field("_type", "std::string"),
                            field("photoId", "int64_t"),
                        ],
                        tag: Some("PHOTO".to_string()),
                    },
                    PolymorphicVariant {
                        name: file_attach.to_string(),
                        ident: "FileAttachment".to_string(),
                        offset: Some("0x300".to_string()),
                        fields: vec![field("preview", &format!("std::optional<{photo_attach}>"))],
                        all_fields: vec![
                            field("_type", "std::string"),
                            field("preview", &format!("std::optional<{photo_attach}>")),
                        ],
                        tag: Some("FILE".to_string()),
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
                    offset: Some("0x400".to_string()),
                    fields: vec![field("common", "std::string")],
                },
                variants: vec![
                    PolymorphicVariant {
                        name: story_link_meta.to_string(),
                        ident: "LogStoryLinkMeta".to_string(),
                        offset: Some("0x500".to_string()),
                        fields: vec![field("storyId", "int64_t")],
                        all_fields: vec![
                            field("common", "std::string"),
                            field("storyId", "int64_t"),
                        ],
                        tag: None,
                    },
                    PolymorphicVariant {
                        name: click_story_link.to_string(),
                        ident: "LogClickParamsLogStoryLinkMeta".to_string(),
                        offset: Some("0x510".to_string()),
                        fields: vec![field("source_meta", story_link_meta)],
                        all_fields: vec![
                            field("common", "std::string"),
                            field("source_meta", story_link_meta),
                        ],
                        tag: Some("CLICK".to_string()),
                    },
                    PolymorphicVariant {
                        name: click_callout.to_string(),
                        ident: "LogClickParamsLogCalloutScreenMeta".to_string(),
                        offset: Some("0x520".to_string()),
                        fields: vec![field("source_meta", callout_meta)],
                        all_fields: vec![
                            field("common", "std::string"),
                            field("source_meta", callout_meta),
                        ],
                        tag: Some("CLICK".to_string()),
                    },
                ],
                rtti_subclasses: vec![],
            },
            PolymorphicModelEntry {
                name: unknown_params.to_string(),
                ident: "LogUnknownContactInteractionParams".to_string(),
                root_sources: vec!["rtti_heuristic".to_string()],
                discriminator: None,
                base: PolymorphicBase {
                    offset: Some("0x600".to_string()),
                    fields: vec![],
                },
                variants: vec![],
                rtti_subclasses: vec![PolymorphicVariant {
                    name: ab_status.to_string(),
                    ident: "LogAbStatusParams".to_string(),
                    offset: Some("0x610".to_string()),
                    fields: vec![],
                    all_fields: vec![],
                    tag: None,
                }],
            },
        ];

        let packet = PacketEntry {
            opcode: 1,
            name: "Api::OneMe::Packets::Msg::Get".to_string(),
            ident: "MsgGet".to_string(),
            request: entry(
                "Api::OneMe::Packets::Msg::Get::Parameters",
                "0x10",
                vec![field("msg", msg_model)],
            ),
            response: entry("Api::OneMe::Packets::Msg::Get::Response", "0x20", vec![]),
        };

        let entries = vec![
            entry(base_attach, "0x100", vec![field("_type", "std::string")]),
            entry(photo_attach, "0x200", vec![field("photoId", "int64_t")]),
            entry(
                file_attach,
                "0x300",
                vec![field("preview", &format!("std::optional<{photo_attach}>"))],
            ),
            entry(event_params, "0x400", vec![field("common", "std::string")]),
            entry(story_link_meta, "0x500", vec![field("storyId", "int64_t")]),
            entry(
                click_story_link,
                "0x510",
                vec![field("source_meta", story_link_meta)],
            ),
            entry(
                click_callout,
                "0x520",
                vec![field("source_meta", callout_meta)],
            ),
            entry(
                callout_meta,
                "0x530",
                vec![field("actionId", "int32_t")],
            ),
            entry(unknown_params, "0x600", vec![]),
            entry(ab_status, "0x610", vec![]),
            entry(
                msg_model,
                "0x700",
                vec![field(
                    "attaches",
                    &format!("std::vector<Api::OneMe::Types::Polymorphic<{base_attach}>>"),
                )],
            ),
        ];

        let models = build_test_model_catalog(vec![packet], vec![], poly_models, entries);
        let model_names: Vec<&str> = models.iter().map(|m| m.name.as_str()).collect();

        // Polymorphic bases, active variants, and rtti_subclasses must be excluded from `models`
        assert!(!model_names.contains(&base_attach));
        assert!(!model_names.contains(&photo_attach));
        assert!(!model_names.contains(&file_attach));
        assert!(!model_names.contains(&event_params));
        assert!(!model_names.contains(&story_link_meta));
        assert!(!model_names.contains(&click_story_link));
        assert!(!model_names.contains(&click_callout));
        assert!(!model_names.contains(&unknown_params));
        assert!(!model_names.contains(&ab_status));

        // Standalone models referenced by packets or polymorphic variants must be included
        assert!(model_names.contains(&msg_model));
        assert!(model_names.contains(&callout_meta));

        let callout = models.iter().find(|m| m.name == callout_meta).unwrap();
        assert_eq!(callout.ident, "LogCalloutScreenMeta");
    }

    #[test]
    fn model_catalog_and_polymorphic_models_disambiguate_colliding_idents() {
        let base = "Api::OneMe::Types::Log::EventParams";
        let log_event_params = "Api::OneMe::Types::Log::LogEventParams";
        let custom_short = "Api::OneMe::Types::Foo::Bar";
        let custom_dup = "Api::OneMe::Types::Foo::FooBar";

        let (poly_models, _) = build_test_polymorphic_models(
            roots(base, &["protocol_field"]),
            hierarchy(base, &[log_event_params]),
            vec![
                entry(base, "0x100", vec![field("common", "int32_t")]),
                entry(log_event_params, "0x200", vec![field("extra", "int32_t")]),
            ],
        );

        assert_eq!(poly_models[0].ident, "LogEventParams");
        assert_eq!(poly_models[0].variants[0].ident, "LogLogEventParams");
        assert_eq!(poly_models[0].rtti_subclasses[0].ident, "LogLogEventParams");

        let packet = PacketEntry {
            opcode: 1,
            name: "Api::OneMe::Packets::Test".to_string(),
            ident: "Test".to_string(),
            request: entry(
                "Api::OneMe::Packets::Test::Parameters",
                "0x10",
                vec![field("a", custom_short), field("b", custom_dup)],
            ),
            response: entry("Api::OneMe::Packets::Test::Response", "0x20", vec![]),
        };

        let entries = vec![
            entry(base, "0x100", vec![field("common", "int32_t")]),
            entry(log_event_params, "0x200", vec![field("extra", "int32_t")]),
            entry(custom_short, "0x300", vec![field("x", "int32_t")]),
            entry(custom_dup, "0x400", vec![field("y", "int32_t")]),
        ];

        let models = build_test_model_catalog(vec![packet], vec![], poly_models, entries);
        let short_model = models.iter().find(|m| m.name == custom_short).unwrap();
        let dup_model = models.iter().find(|m| m.name == custom_dup).unwrap();

        assert_eq!(short_model.ident, "FooBar");
        assert_eq!(dup_model.ident, "FooFooBar");
    }

    #[test]
    fn model_catalog_transitively_discovers_standalone_models_referenced_by_variant() {
        let base_attach = "Api::OneMe::Types::BaseAttachment";
        let video_attach = "Api::OneMe::Types::VideoAttachment";
        let video_collage = "Api::OneMe::Types::VideoCollage";

        let poly_models = vec![PolymorphicModelEntry {
            name: base_attach.to_string(),
            ident: "BaseAttachment".to_string(),
            root_sources: vec!["protocol_field".to_string()],
            discriminator: None,
            base: PolymorphicBase {
                offset: Some("0x100".to_string()),
                fields: vec![field("_type", "std::string")],
            },
            variants: vec![PolymorphicVariant {
                name: video_attach.to_string(),
                ident: "VideoAttachment".to_string(),
                offset: Some("0x200".to_string()),
                fields: vec![field("collage", video_collage)],
                all_fields: vec![
                    field("_type", "std::string"),
                    field("collage", video_collage),
                ],
                tag: None,
            }],
            rtti_subclasses: vec![],
        }];

        let entries = vec![
            entry(base_attach, "0x100", vec![field("_type", "std::string")]),
            entry(video_attach, "0x200", vec![field("collage", video_collage)]),
            entry(
                video_collage,
                "0x300",
                vec![
                    field("url", "std::string"),
                    field("frequency", "int32_t"),
                    field("height", "int32_t"),
                    field("width", "int32_t"),
                    field("count", "int32_t"),
                ],
            ),
        ];

        let models = build_test_model_catalog(vec![], vec![], poly_models, entries);
        assert_eq!(models.len(), 1);
        let vc_model = models.iter().find(|m| m.name == video_collage).expect(
            "VideoCollage must be transitively discovered via VideoAttachment variant fields",
        );
        assert_eq!(vc_model.ident, "VideoCollage");

        let vc_fields: Vec<&str> = vc_model.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            vc_fields,
            vec!["url", "frequency", "height", "width", "count"]
        );
    }

    #[test]
    fn model_catalog_preserves_standalone_models_referenced_by_packets_and_events() {
        let packet_req = "Api::OneMe::Packets::Msg::Send::Request";
        let packet_resp = "Api::OneMe::Packets::Msg::Send::Response";
        let msg_model = "Api::OneMe::Types::Message";
        let contact_model = "Api::OneMe::Types::Contact";
        let event_req = "Api::OneMe::Events::Notify::Request";

        let packet = PacketEntry {
            opcode: 1,
            name: "Api::OneMe::Packets::Msg::Send".to_string(),
            ident: "MsgSend".to_string(),
            request: entry(packet_req, "0x10", vec![field("msg", msg_model)]),
            response: entry(packet_resp, "0x20", vec![]),
        };

        let event = EventEntry {
            opcode: 2,
            kind: None,
            name: "Api::OneMe::Events::Notify".to_string(),
            ident: "Notify".to_string(),
            base_kind: None,
            offset: None,
            request: Some(entry(
                event_req,
                "0x30",
                vec![field("contact", contact_model)],
            )),
            response: None,
            warn: None,
        };

        let entries = vec![
            entry(packet_req, "0x10", vec![field("msg", msg_model)]),
            entry(packet_resp, "0x20", vec![]),
            entry(event_req, "0x30", vec![field("contact", contact_model)]),
            entry(msg_model, "0x100", vec![field("text", "std::string")]),
            entry(contact_model, "0x200", vec![field("userId", "int64_t")]),
        ];

        let models = build_test_model_catalog(vec![packet], vec![event], vec![], entries);
        let model_names: Vec<&str> = models.iter().map(|m| m.name.as_str()).collect();

        assert!(
            model_names.contains(&msg_model),
            "Message model referenced by Packet must be in models"
        );
        assert!(
            model_names.contains(&contact_model),
            "Contact model referenced by Event must be in models"
        );
        assert!(
            !model_names.contains(&packet_req),
            "Packet request must not be treated as standalone model in models"
        );
        assert!(
            !model_names.contains(&event_req),
            "Event request must not be treated as standalone model in models"
        );
    }
}
