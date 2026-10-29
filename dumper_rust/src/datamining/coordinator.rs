use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::datamining::features::extract_server_settings_features;
use crate::datamining::logger::{LoggerAnalyzer, PacketHandlerInfo};
use crate::discriminator::build_discriminator_catalog;
use crate::dumper::DumpResult;
use crate::pe::PeImage;
use crate::rtti::RttiEngine;
use crate::scanner::ProtocolScanner;

/// Application metadata header block in `metadata.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataMeta {
    pub app_version: String,
    pub build_number: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u32>,
}

/// Executive summary counters at the top of `metadata.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataSummary {
    pub total_packets: usize,
    pub total_events: usize,
    pub total_models: usize,
    pub total_features: usize,
    pub total_source_files: usize,
    pub total_log_templates: usize,
}

/// A single catalog entry representing a protocol packet and its C++ handler binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataPacketEntry {
    pub opcode: u32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rva: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<PacketHandlerInfo>,
}

/// Canonical, diff-optimized metadata snapshot aggregating all datamined entities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataSnapshot {
    pub meta: MetadataMeta,
    pub summary: MetadataSummary,
    pub client_config: serde_json::Value,
    pub features: BTreeMap<String, String>,
    pub enums: BTreeMap<String, BTreeMap<String, u64>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub user_settings_defaults: BTreeMap<String, serde_json::Value>,
    pub discriminators: BTreeMap<String, BTreeMap<String, String>>,
    pub packets_catalog: Vec<MetadataPacketEntry>,
    pub source_files: Vec<String>,
    pub log_templates: Vec<String>,
}

/// Datamining coordinator driving extraction and building normalized metadata snapshots.
pub struct DataminingCoordinator;

impl DataminingCoordinator {
    /// Builds a canonical `MetadataSnapshot` across all datamining subsystems.
    pub fn build(
        pe: &PeImage,
        rtti: &RttiEngine,
        scanner: &ProtocolScanner,
        dump: &DumpResult,
        config: Option<&serde_json::Value>,
        with_rva: bool,
    ) -> Result<MetadataSnapshot> {
        build_metadata_snapshot(pe, rtti, scanner, dump, config, with_rva)
    }
}

/// Builds a canonical `MetadataSnapshot` across all datamining subsystems.
pub fn build_metadata_snapshot(
    pe: &PeImage,
    rtti: &RttiEngine,
    scanner: &ProtocolScanner,
    dump: &DumpResult,
    config: Option<&serde_json::Value>,
    with_rva: bool,
) -> Result<MetadataSnapshot> {
    // 1. Features from ServerSettings (sorted BTreeMap<String, String>)
    let features = extract_server_settings_features(pe, rtti).unwrap_or_default();

    // 2. Typed enum tables & UserSettings default values
    let (enums, user_settings_defaults) = if !dump.enums.is_empty() {
        let defaults = if !dump.user_settings_defaults.is_empty() {
            dump.user_settings_defaults.clone()
        } else {
            crate::datamining::enums::extract_user_settings_defaults(pe)
        };
        (dump.enums.clone(), defaults)
    } else {
        let tables = crate::datamining::enums::extract_static_enum_tables(pe);
        let mut catalog = BTreeMap::new();
        let mut defaults = BTreeMap::new();
        for table in tables {
            if table.category == "UserSettings" && !table.defaults.is_empty() {
                defaults = table.defaults;
            }
            catalog.insert(table.category, table.entries);
        }
        (catalog, defaults)
    };

    // 3. Polymorphic model discriminators catalog
    let discriminators = if !dump.discriminators.is_empty() {
        dump.discriminators.clone()
    } else {
        build_discriminator_catalog(&dump.polymorphic_models)
    };

    // 4. Logger callsites, source files, log templates, packets catalog
    let logger_res = LoggerAnalyzer::analyze(pe, rtti, scanner)?;
    let mut source_files = logger_res.source_files;
    source_files.sort();
    source_files.dedup();

    let mut log_templates = logger_res.log_templates;
    log_templates.sort();
    log_templates.dedup();

    // Clean packet RVA lookup if with_rva is requested (using CommonPacket vtable address)
    let mut opcode_rvas: HashMap<u32, String> = HashMap::new();
    if with_rva {
        let re = Regex::new(r"Api::OneMe::Packets::CommonPacket<(\d+)\s*,").unwrap();
        for (&vtable_rva, name) in &rtti.vtable_to_type {
            if let Some(cap) = re.captures(name) {
                if let Ok(op) = cap[1].parse::<u32>() {
                    let is_wrapper = name.contains("_Ref_count_obj2");
                    if !is_wrapper {
                        opcode_rvas.insert(op, format!("0x{:x}", vtable_rva));
                    } else {
                        opcode_rvas.entry(op).or_insert_with(|| format!("0x{:x}", vtable_rva));
                    }
                }
            }
        }
    }

    let mut packets_catalog = Vec::with_capacity(logger_res.packets_catalog.len());
    for entry in logger_res.packets_catalog {
        let rva = if with_rva {
            opcode_rvas.get(&entry.opcode).cloned()
        } else {
            None
        };
        packets_catalog.push(MetadataPacketEntry {
            opcode: entry.opcode,
            name: entry.name,
            rva,
            handler: entry.handler,
        });
    }
    packets_catalog.sort_by_key(|e| e.opcode);

    // 5. Executive summary counters
    let summary = MetadataSummary {
        total_packets: packets_catalog.len(),
        total_events: dump.events.len(),
        total_models: dump.models.len(),
        total_features: features.len(),
        total_source_files: source_files.len(),
        total_log_templates: log_templates.len(),
    };

    // 6. Application version header
    let proto_ver = dump.options.protocol_version.or_else(|| {
        config
            .and_then(|c| c.get("api_version_uint"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
    });

    let mut app_version = dump.options.version.clone();
    let mut build_number = dump.options.build;

    if let Some(pv) = proto_ver {
        if app_version.is_empty() || app_version == "unknown" {
            app_version = format!("proto-{}", pv);
        }
        if build_number == 0 {
            build_number = pv;
        }
    }

    let meta = MetadataMeta {
        app_version,
        build_number,
        protocol_version: proto_ver,
    };

    // 7. Client config (sorted object if dictionary)
    let client_config = match config {
        Some(serde_json::Value::Object(map)) => {
            let mut sorted = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), v.clone());
            }
            serde_json::to_value(sorted).unwrap_or_else(|_| serde_json::Value::Object(map.clone()))
        }
        Some(v) => v.clone(),
        None => serde_json::json!({}),
    };

    Ok(MetadataSnapshot {
        meta,
        summary,
        client_config,
        features,
        enums,
        user_settings_defaults,
        discriminators,
        packets_catalog,
        source_files,
        log_templates,
    })
}

/// Formats a `MetadataSnapshot` into a pretty-printed JSON string with 2-space indentation and trailing newline.
pub fn format_metadata_json(snapshot: &MetadataSnapshot) -> Result<String> {
    let mut buf = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"  ");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    snapshot.serialize(&mut ser)?;
    let mut s = String::from_utf8(buf)?;
    s.push('\n');
    Ok(s)
}

/// Emits the `metadata.json` file to the specified path.
pub fn emit_metadata_json<P: AsRef<Path>>(snapshot: &MetadataSnapshot, path: P) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create parent directory {:?}", parent))?;
    }
    let formatted = format_metadata_json(snapshot)?;
    std::fs::write(path, formatted)
        .with_context(|| format!("Failed to write metadata.json to {:?}", path))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains_key_recursive(value: &serde_json::Value, target: &str) -> bool {
        match value {
            serde_json::Value::Object(map) => {
                map.contains_key(target)
                    || map.values().any(|v| contains_key_recursive(v, target))
            }
            serde_json::Value::Array(arr) => {
                arr.iter().any(|v| contains_key_recursive(v, target))
            }
            _ => false,
        }
    }

    #[test]
    fn test_metadata_snapshot_serialization_and_rva_suppression() {
        let snapshot = MetadataSnapshot {
            meta: MetadataMeta {
                app_version: "1.2.3".to_string(),
                build_number: 456,
                protocol_version: None,
            },
            summary: MetadataSummary {
                total_packets: 1,
                total_events: 0,
                total_models: 0,
                total_features: 1,
                total_source_files: 1,
                total_log_templates: 1,
            },
            client_config: serde_json::json!({ "base_url": "test.com" }),
            features: BTreeMap::from([("test-flag".to_string(), "bool".to_string())]),
            enums: BTreeMap::from([(
                "TestCategory".to_string(),
                BTreeMap::from([("TEST_KEY".to_string(), 10u64)]),
            )]),
            user_settings_defaults: BTreeMap::new(),
            discriminators: BTreeMap::from([(
                "BaseModel".to_string(),
                BTreeMap::from([("TAG".to_string(), "DerivedModel".to_string())]),
            )]),
            packets_catalog: vec![MetadataPacketEntry {
                opcode: 10,
                name: "TestPacket".to_string(),
                rva: None,
                handler: Some(PacketHandlerInfo {
                    class: "TestClass".to_string(),
                    method: "testMethod".to_string(),
                    source: "src/test.cpp".to_string(),
                }),
            }],
            source_files: vec!["src/test.cpp".to_string()],
            log_templates: vec!["Test log {}".to_string()],
        };

        let json_str = format_metadata_json(&snapshot).expect("Must format metadata JSON");
        let val: serde_json::Value =
            serde_json::from_str(&json_str).expect("Must parse formatted JSON");

        // Verify structure
        assert_eq!(val["meta"]["app_version"], "1.2.3");
        assert_eq!(val["meta"]["build_number"], 456);
        assert_eq!(val["summary"]["total_packets"], 1);

        // Invariant: without with_rva, neither "rva" nor "offset" keys appear anywhere
        assert!(!contains_key_recursive(&val, "rva"));
        assert!(!contains_key_recursive(&val, "offset"));
    }

    #[test]
    fn test_metadata_snapshot_with_rva_includes_rva_key() {
        let snapshot = MetadataSnapshot {
            meta: MetadataMeta {
                app_version: "1.2.3".to_string(),
                build_number: 456,
                protocol_version: None,
            },
            summary: MetadataSummary {
                total_packets: 1,
                total_events: 0,
                total_models: 0,
                total_features: 0,
                total_source_files: 0,
                total_log_templates: 0,
            },
            client_config: serde_json::json!({}),
            features: BTreeMap::new(),
            enums: BTreeMap::new(),
            user_settings_defaults: BTreeMap::new(),
            discriminators: BTreeMap::new(),
            packets_catalog: vec![MetadataPacketEntry {
                opcode: 10,
                name: "TestPacket".to_string(),
                rva: Some("0x12345".to_string()),
                handler: None,
            }],
            source_files: Vec::new(),
            log_templates: Vec::new(),
        };

        let json_str = format_metadata_json(&snapshot).expect("Must format metadata JSON");
        let val: serde_json::Value =
            serde_json::from_str(&json_str).expect("Must parse formatted JSON");

        assert!(contains_key_recursive(&val, "rva"));
        assert!(!contains_key_recursive(&val, "offset"));
        assert_eq!(val["packets_catalog"][0]["rva"], "0x12345");
    }

    #[test]
    fn test_metadata_snapshot_protocol_version_from_config() {
        let snapshot = MetadataSnapshot {
            meta: MetadataMeta {
                app_version: "1.2.3".to_string(),
                build_number: 456,
                protocol_version: Some(11),
            },
            summary: MetadataSummary {
                total_packets: 0,
                total_events: 0,
                total_models: 0,
                total_features: 0,
                total_source_files: 0,
                total_log_templates: 0,
            },
            client_config: serde_json::json!({ "api_version_uint": 11 }),
            features: BTreeMap::new(),
            enums: BTreeMap::new(),
            user_settings_defaults: BTreeMap::new(),
            discriminators: BTreeMap::new(),
            packets_catalog: Vec::new(),
            source_files: Vec::new(),
            log_templates: Vec::new(),
        };

        let json_str = format_metadata_json(&snapshot).expect("Must format metadata JSON");
        let val: serde_json::Value =
            serde_json::from_str(&json_str).expect("Must parse formatted JSON");
        assert_eq!(val["meta"]["protocol_version"], 11);
    }
}
