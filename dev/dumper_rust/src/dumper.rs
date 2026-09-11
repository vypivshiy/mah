use crate::extractor::{ExtractedField, FieldExtractor, VtableXrefIndex};
use crate::pe::PeImage;
use crate::rtti::RttiEngine;
use crate::scanner::ProtocolScanner;
use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppVersion {
    #[serde(rename = "app_version")]
    pub version: String,
    #[serde(rename = "build_number")]
    pub build: u32,
}

pub type OptionsInfo = AppVersion;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumperOptions {
    pub version: AppVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDescriptorEntry {
    pub offset: Option<String>,
    pub name: String,
    pub fields: Vec<ExtractedField>,
    pub warn: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEntry {
    pub opcode: u32,
    pub request: TypeDescriptorEntry,
    pub response: TypeDescriptorEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEntry {
    pub opcode: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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
    pub offset: Option<String>,
    pub fields: Vec<ExtractedField>,
    pub warn: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolymorphicVariant {
    pub name: String,
    pub fields: Vec<ExtractedField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolymorphicModelEntry {
    pub name: String,
    pub offset: Option<String>,
    pub variants: Vec<PolymorphicVariant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpResult {
    pub options: OptionsInfo,
    pub packets: Vec<PacketEntry>,
    pub events: Vec<EventEntry>,
    pub models: Vec<ModelEntry>,
    pub polymorphic_models: Vec<PolymorphicModelEntry>,
    pub string_enums: Vec<String>,
    pub error: serde_json::Value,
}

pub struct Dumper;

impl Dumper {
    pub fn dump(
        pe: &PeImage,
        rtti: &RttiEngine,
        scanner: &ProtocolScanner,
        options: &DumperOptions,
    ) -> Result<DumpResult> {
        let (app_ver, build_num) = if !options.version.version.is_empty() && options.version.build > 0 {
            (options.version.version.clone(), options.version.build)
        } else if let Some(av) = detect_version_from_bytes(pe.raw) {
            (av.version, av.build)
        } else {
            ("unknown".to_string(), 0)
        };

        let extractor = FieldExtractor::new(pe, rtti);
        let xref_index = VtableXrefIndex::build(pe, rtti);

        let find_type_entry = |type_name: &str| -> TypeDescriptorEntry {
            if is_empty_type_name(type_name) {
                return TypeDescriptorEntry {
                    offset: None,
                    name: type_name.to_string(),
                    fields: Vec::new(),
                    warn: None,
                };
            }

            if let Some(&vtable_rva) = rtti.type_to_vtable.get(type_name) {
                if let Some((func_rva, fields)) = xref_index.find_best_initializer(vtable_rva, &extractor) {
                    let offset = format!("0x{:x}", func_rva);
                    let warn = if fields.is_empty() && !type_name.contains("Polymorphic") {
                        Some("no data found".to_string())
                    } else {
                        None
                    };
                    return TypeDescriptorEntry {
                        offset: Some(offset),
                        name: type_name.to_string(),
                        fields,
                        warn,
                    };
                }
            }

            TypeDescriptorEntry {
                offset: None,
                name: type_name.to_string(),
                fields: Vec::new(),
                warn: if type_name.contains("Polymorphic") {
                    None
                } else {
                    Some("no data found".to_string())
                },
            }
        };

        // 1. Packets
        let mut packets = Vec::new();
        for p in &scanner.packets {
            let req = find_type_entry(&p.request_full_name);
            let resp = find_type_entry(&p.response_full_name);
            packets.push(PacketEntry {
                opcode: p.opcode,
                request: req,
                response: resp,
            });
        }
        packets.sort_by_key(|p| p.opcode);

        // 2. Events
        let mut events = Vec::new();
        for e in &scanner.events {
            if e.is_special {
                let req = find_type_entry(&e.request_full_name);
                events.push(EventEntry {
                    opcode: e.opcode,
                    kind: Some("special_packet".to_string()),
                    name: e.special_name.clone(),
                    base_kind: e.base_kind.clone(),
                    offset: req.offset.clone(),
                    request: Some(req),
                    response: None,
                    warn: None,
                });
            } else {
                let req = find_type_entry(&e.request_full_name);
                let resp = find_type_entry(&e.response_full_name);
                events.push(EventEntry {
                    opcode: e.opcode,
                    kind: None,
                    name: None,
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
        let mut poly_base_names: Vec<String> = Vec::new();
        for p in &packets {
            for f in p.request.fields.iter().chain(p.response.fields.iter()) {
                if let Some(base) = &f.field_type.polymorphic_base {
                    if !poly_base_names.contains(base) {
                        poly_base_names.push(base.clone());
                    }
                }
            }
        }
        for e in &events {
            if let Some(r) = &e.request {
                for f in &r.fields {
                    if let Some(base) = &f.field_type.polymorphic_base {
                        if !poly_base_names.contains(base) {
                            poly_base_names.push(base.clone());
                        }
                    }
                }
            }
        }
        for (base, derived) in &rtti.hierarchy.base_to_derived {
            if base.starts_with("Api::OneMe::")
                && !derived.is_empty()
                && (base.ends_with("Attachment") || base.ends_with("Params"))
                && !poly_base_names.contains(base)
            {
                poly_base_names.push(base.clone());
            }
        }
        poly_base_names.sort();

        let mut polymorphic_models = Vec::new();
        let mut poly_type_names = HashSet::new();

        for base in &poly_base_names {
            poly_type_names.insert(base.clone());
            let base_entry = find_type_entry(base);
            let mut variants = Vec::new();

            if !base_entry.fields.is_empty() {
                variants.push(PolymorphicVariant {
                    name: base.to_string(),
                    fields: base_entry.fields.clone(),
                });
            }

            if let Some(derived_list) = rtti.hierarchy.derived_of(base) {
                let mut sorted_derived: Vec<String> = derived_list.to_vec();
                sorted_derived.sort();
                for der in sorted_derived {
                    poly_type_names.insert(der.clone());
                    let der_entry = find_type_entry(&der);
                    let mut merged_fields = base_entry.fields.clone();
                    let mut seen_fields: HashSet<String> = merged_fields.iter().map(|f| f.name.clone()).collect();
                    for f in der_entry.fields {
                        if seen_fields.insert(f.name.clone()) {
                            merged_fields.push(f);
                        }
                    }
                    variants.push(PolymorphicVariant {
                        name: der,
                        fields: merged_fields,
                    });
                }
            }

            polymorphic_models.push(PolymorphicModelEntry {
                name: base.to_string(),
                offset: base_entry.offset,
                variants,
            });
        }

        // 4. BFS for auxiliary models
        let mut packet_req_resp_names = HashSet::new();
        for p in &packets {
            packet_req_resp_names.insert(p.request.name.clone());
            packet_req_resp_names.insert(p.response.name.clone());
        }
        for e in &events {
            if let Some(r) = &e.request {
                packet_req_resp_names.insert(r.name.clone());
            }
            if let Some(r) = &e.response {
                packet_req_resp_names.insert(r.name.clone());
            }
        }

        let mut bfs_queue = Vec::new();
        let mut visited = HashSet::new();

        let api_ref_re = Regex::new(r"Api::OneMe::([A-Za-z0-9_:]+)")?;

        let collect_refs_from_fields = |fields: &[ExtractedField], queue: &mut Vec<String>| {
            for f in fields {
                for s in [
                    Some(&f.field_type.full),
                    f.field_type.name.as_ref(),
                    f.field_type.map_key.as_ref(),
                    f.field_type.map_value.as_ref(),
                    f.field_type.polymorphic_base.as_ref(),
                ]
                .into_iter()
                .flatten()
                {
                    for cap in api_ref_re.find_iter(s) {
                        queue.push(cap.as_str().to_string());
                    }
                }
            }
        };

        for p in &packets {
            collect_refs_from_fields(&p.request.fields, &mut bfs_queue);
            collect_refs_from_fields(&p.response.fields, &mut bfs_queue);
        }
        for e in &events {
            if let Some(r) = &e.request {
                collect_refs_from_fields(&r.fields, &mut bfs_queue);
            }
            if let Some(r) = &e.response {
                collect_refs_from_fields(&r.fields, &mut bfs_queue);
            }
        }
        for pm in &polymorphic_models {
            for v in &pm.variants {
                collect_refs_from_fields(&v.fields, &mut bfs_queue);
            }
        }

        let mut models_map: BTreeMap<String, ModelEntry> = BTreeMap::new();

        while let Some(model_name) = bfs_queue.pop() {
            if visited.contains(&model_name) {
                continue;
            }
            visited.insert(model_name.clone());

            if is_empty_type_name(&model_name) || model_name.ends_with("::Polymorphic") {
                continue;
            }
            if packet_req_resp_names.contains(&model_name) {
                continue;
            }

            let entry = find_type_entry(&model_name);
            collect_refs_from_fields(&entry.fields, &mut bfs_queue);

            models_map.insert(
                model_name.clone(),
                ModelEntry {
                    name: model_name,
                    offset: entry.offset,
                    fields: entry.fields,
                    warn: entry.warn,
                },
            );
        }

        let models_list: Vec<ModelEntry> = models_map.values().cloned().collect();

        let default_error_payload = serde_json::json!({
            "error": "std::string",
            "localizedMessage": "std::string",
            "message": "std::string",
            "title": "std::string",
        });

        Ok(DumpResult {
            options: OptionsInfo {
                version: app_ver,
                build: build_num,
            },
            packets,
            events,
            models: models_list,
            polymorphic_models,
            string_enums: scanner.string_enums.clone(),
            error: default_error_payload,
        })
    }
}

pub fn detect_version_from_bytes(bytes: &[u8]) -> Option<AppVersion> {
    let re = regex::bytes::Regex::new(r"\d+\.\d+\.\d+[\.:]\d+").ok()?;
    for m in re.find_iter(bytes) {
        if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
            let parts: Vec<&str> = s.split(['.', ':']).collect();
            if parts.len() >= 4 {
                let ver = parts[..3].join(".");
                if let Ok(build) = parts[3].parse::<u32>() {
                    return Some(AppVersion { version: ver, build });
                }
            }
        }
    }
    None
}

fn is_empty_type_name(name: &str) -> bool {
    let kind = name.rsplit("::").next().unwrap_or(name);
    matches!(
        kind,
        "EmptyResponse" | "EmptyParameters" | "NoParameters" | "EmptyData"
    )
}
