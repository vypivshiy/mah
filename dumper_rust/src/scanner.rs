use crate::extractor::ExtractedField;
use crate::pe::PeImage;
use crate::rtti::RttiEngine;
use crate::type_parser::decompose_type;
use anyhow::Result;
use regex::bytes::Regex;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketDescriptor {
    pub opcode: u32,
    pub request_full_name: String,
    pub request_kind: String,
    pub response_full_name: String,
    pub response_kind: String,
    pub is_special: bool,
    pub special_name: Option<String>,
    pub base_kind: Option<String>,
    pub special_request_fields: Vec<ExtractedField>,
}

pub struct ProtocolScanner {
    pub packets: Vec<PacketDescriptor>,
    pub events: Vec<PacketDescriptor>,
    pub string_enums: Vec<String>,
}

impl ProtocolScanner {
    pub fn scan(pe: &PeImage, rtti: &RttiEngine) -> Result<Self> {
        let packets = scan_common_packets(pe)?;
        let mut events = scan_common_events(pe)?;

        let special_packets = scan_special_packets(pe, rtti);
        for sp in special_packets {
            // If opcode not already in events, insert it (usually opcode 1 Ping)
            if !events.iter().any(|e| e.opcode == sp.opcode) {
                events.push(sp);
            }
        }
        events.sort_by_key(|e| e.opcode);

        let string_enums = extract_uppercase_enums(pe.raw);

        Ok(ProtocolScanner {
            packets,
            events,
            string_enums,
        })
    }
}

fn scan_descriptors(pe: &PeImage, regex: &Regex) -> Result<Vec<PacketDescriptor>> {
    let mut map: BTreeMap<u32, PacketDescriptor> = BTreeMap::new();

    if let Some(rdata) = pe.section_data(".rdata") {
        for cap in regex.captures_iter(rdata) {
            let opcode_str = std::str::from_utf8(&cap[1])?;
            let opcode: u32 = match opcode_str.parse() {
                Ok(op) => op,
                Err(_) => continue,
            };
            if map.contains_key(&opcode) {
                continue;
            }

            let req = clean_type_name(std::str::from_utf8(&cap[2])?);
            let resp = clean_type_name(std::str::from_utf8(&cap[3])?);

            let req_kind = req.rsplit("::").next().unwrap_or("").to_string();
            let resp_kind = resp.rsplit("::").next().unwrap_or("").to_string();

            map.insert(
                opcode,
                PacketDescriptor {
                    opcode,
                    request_full_name: req,
                    request_kind: req_kind,
                    response_full_name: resp,
                    response_kind: resp_kind,
                    is_special: false,
                    special_name: None,
                    base_kind: None,
                    special_request_fields: Vec::new(),
                },
            );
        }
    }

    Ok(map.into_values().collect())
}

pub fn scan_common_packets(pe: &PeImage) -> Result<Vec<PacketDescriptor>> {
    let re = Regex::new(
        r"Api::OneMe::Packets::CommonPacket<(\d+)\s*,\s*(?:struct\s+|class\s+)?([^,>]+)\s*,\s*(?:struct\s+|class\s+)?([^,>]+)",
    )?;
    scan_descriptors(pe, &re)
}

pub fn scan_common_events(pe: &PeImage) -> Result<Vec<PacketDescriptor>> {
    let re = Regex::new(
        r"CommonEvent<(\d+)\s*,\s*(?:struct\s+|class\s+)?([^,>]+)\s*,\s*(?:struct\s+|class\s+)?([^,>]+)>",
    )?;
    scan_descriptors(pe, &re)
}

pub fn scan_special_packets(_pe: &PeImage, rtti: &RttiEngine) -> Vec<PacketDescriptor> {
    scan_special_packets_from_rtti(rtti)
}

pub fn scan_special_packets_from_rtti(rtti: &RttiEngine) -> Vec<PacketDescriptor> {
    let mut results = Vec::new();
    // Scan RTTI for Creator<VPing@Packets@OneMe@Api@@, VBaseEvent...>
    for td in rtti.type_descriptors.values() {
        if td.demangled_name.contains("Creator<")
            && td.demangled_name.contains("Api::OneMe::Packets::")
            && (td.demangled_name.contains("BaseEvent") || td.demangled_name.contains("BasePacket"))
        {
            // For Ping: opcode is 1
            if td.demangled_name.contains("Ping") {
                results.push(PacketDescriptor {
                    opcode: 1,
                    request_full_name: "Api::OneMe::Packets::Ping::Payload".to_string(),
                    request_kind: "Payload".to_string(),
                    response_full_name: String::new(),
                    response_kind: String::new(),
                    is_special: true,
                    special_name: Some("Api::OneMe::Packets::Ping".to_string()),
                    base_kind: Some("Api::OneMe::Packets::BaseEvent".to_string()),
                    special_request_fields: ping_payload_fields(),
                });
            }
        }
    }
    results
}

pub fn ping_payload_fields() -> Vec<ExtractedField> {
    vec![ExtractedField {
        name: "interactive".to_string(),
        field_type: decompose_type("bool"),
        required: false,
    }]
}

fn clean_type_name(s: &str) -> String {
    let mut cleaned = s.trim();
    for pfx in &["struct ", "class "] {
        if cleaned.starts_with(pfx) {
            cleaned = &cleaned[pfx.len()..];
            break;
        }
    }
    cleaned.trim().to_string()
}

pub fn extract_uppercase_enums(data: &[u8]) -> Vec<String> {
    let min_len = 3;
    let max_len = 64;
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    let n = data.len();
    let mut i = 0;

    while i < n {
        let b = data[i];
        if !is_upper_enum_byte(b) {
            i += 1;
            continue;
        }
        let mut end = i;
        while end < n && is_upper_enum_byte(data[end]) {
            end += 1;
        }
        let length = end - i;
        if length > min_len && length <= max_len && end < n && data[end] == 0 {
            if let Ok(s) = std::str::from_utf8(&data[i..end]) {
                if is_likely_enum(s) && seen.insert(s.to_string()) {
                    results.push(s.to_string());
                }
            }
        }
        i = if end > i { end } else { i + 1 };
    }

    results.sort();
    results
}

#[inline]
fn is_upper_enum_byte(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'
}

fn is_likely_enum(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes[0].is_ascii_digit() {
        return false;
    }
    if s.ends_with("XZ") {
        return false;
    }
    if bytes.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let parts: Vec<&str> = s.split('_').filter(|p| !p.is_empty()).collect();
    if parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit())) {
        return false;
    }
    if !s.contains('_') && s.len() <= 6 {
        let digit_count = bytes.iter().filter(|b| b.is_ascii_digit()).count();
        if (digit_count as f32) / (s.len() as f32) >= 0.4 {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtti::{ClassHierarchy, TypeDescriptor};
    use std::collections::HashMap;

    fn synthetic_rtti_with_type(demangled_name: &str) -> RttiEngine {
        let mut type_descriptors = HashMap::new();
        type_descriptors.insert(
            0x1000,
            TypeDescriptor {
                rva: 0x1000,
                mangled_name: String::new(),
                demangled_name: demangled_name.to_string(),
            },
        );

        RttiEngine {
            type_descriptors,
            vtable_to_type: HashMap::new(),
            type_to_vtable: HashMap::new(),
            smember_vtables: HashMap::new(),
            hierarchy: ClassHierarchy::default(),
        }
    }

    #[test]
    fn special_ping_discovery_includes_interactive_payload_field() {
        let rtti = synthetic_rtti_with_type(
            "Api::OneMe::Packets::Creator<Api::OneMe::Packets::Ping, Api::OneMe::Packets::BaseEvent>",
        );

        let descriptors = scan_special_packets_from_rtti(&rtti);

        assert_eq!(descriptors.len(), 1);
        let ping = &descriptors[0];
        assert_eq!(ping.opcode, 1);
        assert_eq!(ping.request_full_name, "Api::OneMe::Packets::Ping::Payload");
        assert_eq!(
            ping.base_kind.as_deref(),
            Some("Api::OneMe::Packets::BaseEvent")
        );
        assert_eq!(ping.special_request_fields, ping_payload_fields());
    }

    #[test]
    fn special_discovery_does_not_mark_unrelated_creator_as_ping() {
        let rtti = synthetic_rtti_with_type(
            "Api::OneMe::Packets::Creator<Api::OneMe::Packets::SessionInit, Api::OneMe::Packets::BasePacket>",
        );

        assert!(scan_special_packets_from_rtti(&rtti).is_empty());
    }
}
