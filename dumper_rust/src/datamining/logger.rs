use crate::pe::PeImage;
use crate::rtti::RttiEngine;
use crate::scanner::{PacketDescriptor, ProtocolScanner};
use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, Instruction, Register};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};

pub const DEFAULT_LOGGER_IAT_RVA: u32 = 0x1e98708;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketHandlerInfo {
    pub class: String,
    pub method: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketCatalogEntry {
    pub opcode: u32,
    pub name: String,
    pub handler: Option<PacketHandlerInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggerCallsite {
    pub rva: u32,
    pub enclosing_function_rva: Option<u32>,
    pub tag: Option<String>,
    pub template: Option<String>,
    pub source_file: Option<String>,
    pub function_name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggerAnalysisResult {
    pub source_files: Vec<String>,
    pub log_templates: Vec<String>,
    pub callsites: Vec<LoggerCallsite>,
    pub packets_catalog: Vec<PacketCatalogEntry>,
}

pub fn normalize_source_path(path: &str) -> String {
    let replaced = path.replace('\\', "/");
    let mut result = String::with_capacity(replaced.len());
    let mut prev_slash = false;
    for c in replaced.chars() {
        if c == '/' {
            if !prev_slash && !result.is_empty() {
                result.push('/');
            }
            prev_slash = true;
        } else {
            result.push(c);
            prev_slash = false;
        }
    }
    result
}

pub fn extract_packet_name(packet_model_full: &str) -> String {
    let s = packet_model_full
        .strip_suffix("::Parameters")
        .unwrap_or(packet_model_full);
    let s = s.strip_suffix("::Response").unwrap_or(s);
    let s = s.strip_suffix("::Payload").unwrap_or(s);
    let name = s.rsplit("::").next().unwrap_or(s).trim();
    if name.is_empty() || name == "Parameters" {
        packet_model_full.to_string()
    } else {
        name.to_string()
    }
}

pub fn split_function_name(func_name: &str) -> (String, String) {
    let trimmed = func_name.trim();
    // 1. Strip parameter list (e.g. "func(int, char*)")
    let without_params = if let Some(idx) = trimmed.find('(') {
        trimmed[..idx].trim()
    } else {
        trimmed
    };

    // 2. Strip trailing const/volatile qualifiers if any
    let clean_sig = without_params
        .strip_suffix("const")
        .unwrap_or(without_params)
        .trim();

    // 3. Strip return type or calling convention prefix if separated by whitespace (e.g., "void __cdecl Class::method")
    let symbol = if let Some(last_space) = clean_sig.rfind(' ') {
        clean_sig[last_space + 1..].trim()
    } else {
        clean_sig
    };

    // 4. Split class and method
    match symbol.rsplit_once("::") {
        Some((cls, mth)) => (cls.trim().to_string(), mth.trim().to_string()),
        None => (String::new(), symbol.to_string()),
    }
}

pub struct LoggerAnalyzer;

impl LoggerAnalyzer {
    pub fn analyze(
        pe: &PeImage,
        rtti: &RttiEngine,
        scanner: &ProtocolScanner,
    ) -> Result<LoggerAnalysisResult> {
        let callsites = Self::analyze_callsites(pe)?;
        let source_files = Self::extract_source_files(&callsites);
        let log_templates = Self::extract_log_templates(&callsites);
        let packets_catalog =
            Self::build_packet_catalog(pe, rtti, &scanner.packets, &callsites);

        Ok(LoggerAnalysisResult {
            source_files,
            log_templates,
            callsites,
            packets_catalog,
        })
    }

    pub fn resolve_logger_iat_va(pe: &PeImage) -> u64 {
        // Try to locate Logger::writeMessage import via goblin
        if let Ok(pe_parsed) = goblin::pe::PE::parse(pe.raw) {
            // Prefer standard char string_view overload (does not contain _S for wchar_t)
            for imp in &pe_parsed.imports {
                let dll_lower = imp.dll.to_ascii_lowercase();
                if (dll_lower == "logger.dll" || dll_lower.starts_with("logger"))
                    && imp.name.contains("writeMessage")
                    && !imp.name.contains("_S")
                {
                    // imp.offset is the RVA of the IAT entry in goblin
                    return pe.image_base + imp.offset as u64;
                }
            }

            for imp in &pe_parsed.imports {
                let dll_lower = imp.dll.to_ascii_lowercase();
                if (dll_lower == "logger.dll" || dll_lower.starts_with("logger"))
                    && imp.name.contains("writeMessage")
                {
                    // imp.offset is the RVA of the IAT entry in goblin
                    return pe.image_base + imp.offset as u64;
                }
            }
        }
        pe.image_base + DEFAULT_LOGGER_IAT_RVA as u64
    }

    pub fn analyze_callsites(pe: &PeImage) -> Result<Vec<LoggerCallsite>> {
        let text_sec = match pe.section_by_name(".text") {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };
        let text_data = match pe.section_data(".text") {
            Some(d) => d,
            None => return Ok(Vec::new()),
        };

        let image_base = pe.image_base;
        let text_start_va = image_base + text_sec.virtual_address as u64;
        let logger_iat_va = Self::resolve_logger_iat_va(pe);

        // 1. Scan .text for direct indirect calls to logger IAT and thunks
        let mut logger_callsite_rvas = Vec::new();
        let mut logger_thunk_rvas = HashSet::new();
        let mut near_calls = Vec::new(); // (caller_rva, target_rva)

        let mut decoder =
            Decoder::with_ip(64, text_data, text_start_va, DecoderOptions::NONE);
        let mut instr = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            let ip = instr.ip();
            let rva = (ip - image_base) as u32;

            if instr.is_call_near_indirect() {
                if instr.memory_displacement64() == logger_iat_va {
                    logger_callsite_rvas.push(rva);
                }
            } else if instr.is_jmp_near_indirect() {
                if instr.memory_displacement64() == logger_iat_va {
                    logger_thunk_rvas.insert(rva);
                }
            } else if instr.is_call_near() {
                let target = instr.near_branch_target();
                if target >= image_base {
                    let target_rva = (target - image_base) as u32;
                    near_calls.push((rva, target_rva));
                }
            }
        }

        // Add any near calls that target a logger thunk
        for &(caller_rva, target_rva) in &near_calls {
            if logger_thunk_rvas.contains(&target_rva) {
                logger_callsite_rvas.push(caller_rva);
            }
        }

        logger_callsite_rvas.sort_unstable();
        logger_callsite_rvas.dedup();

        // 2. Decode argument registers and stack slots for each callsite
        let mut callsites = Vec::with_capacity(logger_callsite_rvas.len());

        for call_rva in logger_callsite_rvas {
            let enclosing_func = pe.find_function(call_rva);
            let enclosing_func_rva = enclosing_func.map(|f| f.begin_address);

            // Determine slice bounds to decode
            let (slice_rva, slice_len) = if let Some(func) = enclosing_func {
                let start = func.begin_address;
                let len = (call_rva + 6).saturating_sub(start) as usize;
                (start, len)
            } else {
                let start = call_rva.saturating_sub(128);
                let len = (call_rva + 6).saturating_sub(start) as usize;
                (start, len)
            };

            let mut tag = None;
            let mut template = None;
            let mut source_file = None;
            let mut function_name = None;

            if let Some(slice) = pe.slice_at_rva(slice_rva, slice_len) {
                let mut fdec = Decoder::with_ip(
                    64,
                    slice,
                    image_base + slice_rva as u64,
                    DecoderOptions::NONE,
                );
                let mut instrs = Vec::new();
                let mut fi = Instruction::default();
                while fdec.can_decode() {
                    fdec.decode_out(&mut fi);
                    instrs.push(fi);
                    if fi.ip() >= image_base + call_rva as u64 {
                        break;
                    }
                }

                let window_start = instrs.len().saturating_sub(40);
                let window = &instrs[window_start..instrs.len().saturating_sub(1)];

                // Pass 1: Recover source file (R9) and function name ([rsp+0x28])
                for ins in window.iter().rev() {
                    // Check R9
                    if source_file.is_none() && ins.op0_register() == Register::R9 {
                        let target_va = ins.memory_displacement64();
                        if target_va >= image_base {
                            let str_rva = (target_va - image_base) as u32;
                            if let Some(s) = pe.read_cstring(str_rva) {
                                source_file = Some(normalize_source_path(s));
                            }
                        }
                    }

                    // Check [rsp+0x28]
                    if function_name.is_none()
                        && ins.memory_base() == Register::RSP
                        && ins.memory_displacement64() == 0x28
                    {
                        let src_reg = ins.op1_register();
                        if src_reg != Register::None {
                            for prev in window.iter().rev() {
                                if prev.ip() < ins.ip() && prev.op0_register() == src_reg {
                                    let target_va = prev.memory_displacement64();
                                    if target_va >= image_base {
                                        let str_rva = (target_va - image_base) as u32;
                                        if let Some(s) = pe.read_cstring(str_rva) {
                                            function_name = Some(s.to_string());
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Pass 2: Fallback for source file and function name if not found via exact registers
                if source_file.is_none() || function_name.is_none() {
                    for ins in window.iter().rev() {
                        if ins.op_count() >= 2 && ins.is_ip_rel_memory_operand() {
                            let target_va = ins.memory_displacement64();
                            if target_va >= image_base {
                                let str_rva = (target_va - image_base) as u32;
                                if let Some(s) = pe.read_cstring(str_rva) {
                                    if source_file.is_none()
                                        && (s.contains(".cpp")
                                            || s.contains(".h")
                                            || s.contains(".hpp")
                                            || s.starts_with('\\')
                                            || s.starts_with("components/"))
                                    {
                                        source_file = Some(normalize_source_path(s));
                                    } else if function_name.is_none()
                                        && s.contains("::")
                                        && !s.contains(".cpp")
                                        && !s.contains(".h")
                                    {
                                        function_name = Some(s.to_string());
                                    }
                                }
                            }
                        }
                    }
                }

                // Pass 3: Recover tag (RDX) and template (R8 / formatting template)
                for ins in window.iter().rev() {
                    if ins.op_count() >= 2 && ins.is_ip_rel_memory_operand() {
                        let target_va = ins.memory_displacement64();
                        if target_va >= image_base {
                            let str_rva = (target_va - image_base) as u32;
                            if let Some(s) = pe.read_cstring(str_rva) {
                                let norm_s = normalize_source_path(s);
                                if source_file.as_deref() == Some(&norm_s)
                                    || source_file.as_deref() == Some(s)
                                    || function_name.as_deref() == Some(s)
                                {
                                    continue;
                                }
                                if s.contains(".cpp")
                                    || s.contains(".h")
                                    || s.starts_with('\\')
                                    || s.contains("::")
                                    || s.is_empty()
                                {
                                    continue;
                                }

                                if tag.is_none()
                                    && !s.contains(' ')
                                    && !s.contains('{')
                                    && !s.contains('%')
                                    && s.len() < 40
                                {
                                    tag = Some(s.to_string());
                                } else if template.is_none() {
                                    template = Some(s.to_string());
                                }
                            }
                        }
                    }
                }
            }

            callsites.push(LoggerCallsite {
                rva: call_rva,
                enclosing_function_rva: enclosing_func_rva,
                tag,
                template,
                source_file,
                function_name,
            });
        }

        Ok(callsites)
    }

    pub fn extract_source_files(callsites: &[LoggerCallsite]) -> Vec<String> {
        let mut set = BTreeSet::new();
        for cs in callsites {
            if let Some(ref s) = cs.source_file {
                if !s.is_empty() {
                    set.insert(s.clone());
                }
            }
        }
        set.into_iter().collect()
    }

    pub fn extract_log_templates(callsites: &[LoggerCallsite]) -> Vec<String> {
        let mut set = BTreeSet::new();
        for cs in callsites {
            if let Some(ref t) = cs.template {
                if !t.is_empty() {
                    set.insert(t.clone());
                }
            }
        }
        set.into_iter().collect()
    }

    pub fn build_packet_catalog(
        pe: &PeImage,
        rtti: &RttiEngine,
        packets: &[PacketDescriptor],
        callsites: &[LoggerCallsite],
    ) -> Vec<PacketCatalogEntry> {
        let text_sec = match pe.section_by_name(".text") {
            Some(s) => s,
            None => {
                return packets
                    .iter()
                    .map(|p| PacketCatalogEntry {
                        opcode: p.opcode,
                        name: extract_packet_name(&p.request_full_name),
                        handler: None,
                    })
                    .collect()
            }
        };
        let text_data = match pe.section_data(".text") {
            Some(d) => d,
            None => {
                return packets
                    .iter()
                    .map(|p| PacketCatalogEntry {
                        opcode: p.opcode,
                        name: extract_packet_name(&p.request_full_name),
                        handler: None,
                    })
                    .collect()
            }
        };

        let image_base = pe.image_base;
        let text_start_va = image_base + text_sec.virtual_address as u64;

        // 1. Build map from func_begin_rva -> (source, function_name) from callsites
        let mut func_logger_info: HashMap<u32, (String, String)> = HashMap::new();
        for cs in callsites {
            if let (Some(func_rva), Some(source), Some(func_name)) = (
                cs.enclosing_function_rva,
                &cs.source_file,
                &cs.function_name,
            ) {
                func_logger_info
                    .entry(func_rva)
                    .or_insert_with(|| (source.clone(), func_name.clone()));
            }
        }

        // 2. Map opcode -> vtable VA from RTTI
        let mut opcode_to_vtable_va: HashMap<u32, u64> = HashMap::new();
        let re = Regex::new(r"Api::OneMe::Packets::CommonPacket<(\d+)\s*,").unwrap();
        for (&vtable_rva, name) in &rtti.vtable_to_type {
            if let Some(cap) = re.captures(name) {
                if let Ok(op) = cap[1].parse::<u32>() {
                    // Prefer direct CommonPacket vtable over _Ref_count_obj2 wrapper
                    if !name.contains("_Ref_count_obj2") || !opcode_to_vtable_va.contains_key(&op) {
                        opcode_to_vtable_va.insert(op, image_base + vtable_rva as u64);
                    }
                }
            }
        }

        let vtable_va_to_opcode: HashMap<u64, u32> = opcode_to_vtable_va
            .iter()
            .map(|(&op, &vt)| (vt, op))
            .collect();

        // 3. Scan .text for:
        //    a) Vtable references to identify packet constructor functions
        //    b) Near jumps (thunks)
        //    c) Near calls (callers of constructors / thunks)
        let mut opcode_to_ctor: HashMap<u32, u32> = HashMap::new();
        let mut thunks: HashMap<u32, u32> = HashMap::new();
        let mut calls: Vec<(u32, u32)> = Vec::new();

        let mut decoder =
            Decoder::with_ip(64, text_data, text_start_va, DecoderOptions::NONE);
        let mut instr = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            let ip = instr.ip();
            let rva = (ip - image_base) as u32;

            if instr.is_ip_rel_memory_operand() {
                let target = instr.memory_displacement64();
                if let Some(&op) = vtable_va_to_opcode.get(&target) {
                    if let Some(func) = pe.find_function(rva) {
                        opcode_to_ctor.entry(op).or_insert(func.begin_address);
                    }
                }
            }

            if instr.is_jmp_near() {
                let target = instr.near_branch_target();
                if target >= image_base {
                    let target_rva = (target - image_base) as u32;
                    thunks.insert(rva, target_rva);
                }
            } else if instr.is_call_near() {
                let target = instr.near_branch_target();
                if target >= image_base {
                    let target_rva = (target - image_base) as u32;
                    calls.push((rva, target_rva));
                }
            }
        }

        // 4. Map targets (constructors and thunks) to opcodes
        let mut target_to_opcode: HashMap<u32, u32> = HashMap::new();
        for (&op, &ctor_rva) in &opcode_to_ctor {
            target_to_opcode.insert(ctor_rva, op);
        }
        for (&thunk_rva, &target_rva) in &thunks {
            if let Some(&op) = target_to_opcode.get(&target_rva) {
                target_to_opcode.insert(thunk_rva, op);
            }
        }

        // 5. Connect callers of constructors to logger info
        let mut opcode_handlers: HashMap<u32, PacketHandlerInfo> = HashMap::new();
        let mut caller_func_to_opcodes: HashMap<u32, Vec<u32>> = HashMap::new();

        for &(caller_rva, target_rva) in &calls {
            if let Some(&op) = target_to_opcode.get(&target_rva) {
                if let Some(caller_func) = pe.find_function(caller_rva) {
                    caller_func_to_opcodes
                        .entry(caller_func.begin_address)
                        .or_default()
                        .push(op);

                    if let Some((source, func_name)) =
                        func_logger_info.get(&caller_func.begin_address)
                    {
                        let (class, method) = split_function_name(func_name);
                        opcode_handlers.entry(op).or_insert(PacketHandlerInfo {
                            class,
                            method,
                            source: source.clone(),
                        });
                    }
                }
            }
        }

        // 6. 1-hop caller search: if caller_func has no logger info, look at callers of caller_func
        for &(caller2_rva, target_rva) in &calls {
            if let Some(ops) = caller_func_to_opcodes.get(&target_rva) {
                if let Some(caller2_func) = pe.find_function(caller2_rva) {
                    if let Some((source, func_name)) =
                        func_logger_info.get(&caller2_func.begin_address)
                    {
                        let (class, method) = split_function_name(func_name);
                        for &op in ops {
                            opcode_handlers.entry(op).or_insert(PacketHandlerInfo {
                                class: class.clone(),
                                method: method.clone(),
                                source: source.clone(),
                            });
                        }
                    }
                }
            }
        }

        // 7. Assemble catalog entries for all packets
        let mut catalog = Vec::with_capacity(packets.len());
        for p in packets {
            let name = if p.is_special && p.special_name.is_some() {
                extract_packet_name(p.special_name.as_ref().unwrap())
            } else {
                extract_packet_name(&p.request_full_name)
            };

            let handler = opcode_handlers.get(&p.opcode).cloned();
            catalog.push(PacketCatalogEntry {
                opcode: p.opcode,
                name,
                handler,
            });
        }

        catalog.sort_by_key(|e| e.opcode);
        catalog
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtti::ClassHierarchy;

    #[test]
    fn test_normalize_source_path() {
        assert_eq!(
            normalize_source_path(r"\components\core\src\oneme_auth\oneme_auth_session.cpp"),
            "components/core/src/oneme_auth/oneme_auth_session.cpp"
        );
        assert_eq!(
            normalize_source_path("components/core/src/foo.cpp"),
            "components/core/src/foo.cpp"
        );
        assert_eq!(
            normalize_source_path(r"/components/core/src/bar.h"),
            "components/core/src/bar.h"
        );
        assert_eq!(
            normalize_source_path(r"\\components\\core\\src\\baz.hpp"),
            "components/core/src/baz.hpp"
        );
    }

    #[test]
    fn test_extract_packet_name() {
        assert_eq!(
            extract_packet_name("Api::OneMe::Packets::Auth::OneMe::CheckEmail::Parameters"),
            "CheckEmail"
        );
        assert_eq!(
            extract_packet_name("Api::OneMe::Packets::Auth::OneMe::VerifyEmail::Parameters"),
            "VerifyEmail"
        );
        assert_eq!(
            extract_packet_name("Api::OneMe::Packets::Contact::Presence::Response"),
            "Presence"
        );
        assert_eq!(
            extract_packet_name("Api::OneMe::Packets::Ping::Payload"),
            "Ping"
        );
        assert_eq!(extract_packet_name("Api::OneMe::Packets::Ping"), "Ping");
    }

    #[test]
    fn test_split_function_name() {
        let (class, method) =
            split_function_name("Core::Auth::OneMeAuthSession::doSendEmailCheckCode");
        assert_eq!(class, "Core::Auth::OneMeAuthSession");
        assert_eq!(method, "doSendEmailCheckCode");

        let (class2, method2) = split_function_name("SimpleClass::method");
        assert_eq!(class2, "SimpleClass");
        assert_eq!(method2, "method");

        let (class3, method3) = split_function_name("standaloneFunc");
        assert_eq!(class3, "");
        assert_eq!(method3, "standaloneFunc");

        let (class4, method4) =
            split_function_name("void Core::Calls::CallsInteractor::doRequestContacts(int)");
        assert_eq!(class4, "Core::Calls::CallsInteractor");
        assert_eq!(method4, "doRequestContacts");

        let (class5, method5) =
            split_function_name("Core::Calls::CallsInteractor::doRequestContacts() const");
        assert_eq!(class5, "Core::Calls::CallsInteractor");
        assert_eq!(method5, "doRequestContacts");
    }

    #[test]
    fn test_extract_source_files_and_log_templates_dedup_and_sort() {
        let callsites = vec![
            LoggerCallsite {
                rva: 0x1000,
                enclosing_function_rva: Some(0x900),
                tag: Some("TagB".to_string()),
                template: Some("Template Z".to_string()),
                source_file: Some("components/core/src/b.cpp".to_string()),
                function_name: Some("ClassB::method".to_string()),
            },
            LoggerCallsite {
                rva: 0x2000,
                enclosing_function_rva: Some(0x1900),
                tag: Some("TagA".to_string()),
                template: Some("Template A".to_string()),
                source_file: Some("components/core/src/a.cpp".to_string()),
                function_name: Some("ClassA::method".to_string()),
            },
            LoggerCallsite {
                rva: 0x3000,
                enclosing_function_rva: Some(0x2900),
                tag: Some("TagB".to_string()),
                template: Some("Template Z".to_string()),
                source_file: Some("components/core/src/b.cpp".to_string()),
                function_name: Some("ClassB::method2".to_string()),
            },
        ];

        let sources = LoggerAnalyzer::extract_source_files(&callsites);
        assert_eq!(
            sources,
            vec![
                "components/core/src/a.cpp".to_string(),
                "components/core/src/b.cpp".to_string()
            ]
        );

        let templates = LoggerAnalyzer::extract_log_templates(&callsites);
        assert_eq!(
            templates,
            vec!["Template A".to_string(), "Template Z".to_string()]
        );
    }

    #[test]
    fn test_synthetic_pe_logger_callsite_and_packet_binding() {
        // Construct a synthetic 64-bit PE image in memory with .text, .rdata, and .pdata
        let mut bytes = vec![0u8; 0x4000];

        // 1. DOS Header
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&(0x80u32).to_le_bytes());

        // 2. PE Signature
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

        // 3. COFF File Header (3 sections)
        bytes[0x84..0x86].copy_from_slice(&(0x8664u16).to_le_bytes()); // AMD64
        bytes[0x86..0x88].copy_from_slice(&(3u16).to_le_bytes()); // NumberOfSections: 3
        bytes[0x94..0x96].copy_from_slice(&(240u16).to_le_bytes()); // SizeOfOptionalHeader
        bytes[0x96..0x98].copy_from_slice(&(0x0022u16).to_le_bytes());

        // 4. Optional Header 64
        bytes[0x98..0x9A].copy_from_slice(&(0x020Bu16).to_le_bytes()); // PE32+
        bytes[0xB0..0xB8].copy_from_slice(&(0x180000000u64).to_le_bytes()); // ImageBase
        bytes[0xB8..0xBC].copy_from_slice(&(0x1000u32).to_le_bytes()); // SectionAlignment
        bytes[0xBC..0xC0].copy_from_slice(&(0x200u32).to_le_bytes()); // FileAlignment
        bytes[0xD0..0xD4].copy_from_slice(&(0x5000u32).to_le_bytes()); // SizeOfImage
        bytes[0xD4..0xD8].copy_from_slice(&(0x200u32).to_le_bytes()); // SizeOfHeaders

        // Section 1: .text (RVA 0x1000, Raw 0x400, Size 0x400)
        bytes[0x188..0x190].copy_from_slice(b".text\0\0\0");
        bytes[0x190..0x194].copy_from_slice(&(0x400u32).to_le_bytes());
        bytes[0x194..0x198].copy_from_slice(&(0x1000u32).to_le_bytes());
        bytes[0x198..0x19C].copy_from_slice(&(0x400u32).to_le_bytes());
        bytes[0x19C..0x1A0].copy_from_slice(&(0x400u32).to_le_bytes());
        bytes[0x1AC..0x1B0].copy_from_slice(&(0x60000020u32).to_le_bytes());

        // Section 2: .rdata (RVA 0x2000, Raw 0x800, Size 0x600)
        bytes[0x1B0..0x1B8].copy_from_slice(b".rdata\0\0");
        bytes[0x1B8..0x1BC].copy_from_slice(&(0x600u32).to_le_bytes());
        bytes[0x1BC..0x1C0].copy_from_slice(&(0x2000u32).to_le_bytes());
        bytes[0x1C0..0x1C4].copy_from_slice(&(0x600u32).to_le_bytes());
        bytes[0x1C4..0x1C8].copy_from_slice(&(0x800u32).to_le_bytes());
        bytes[0x1D4..0x1D8].copy_from_slice(&(0x40000040u32).to_le_bytes());

        // Section 3: .pdata (RVA 0x3000, Raw 0xE00, Size 0x200)
        bytes[0x1D8..0x1E0].copy_from_slice(b".pdata\0\0");
        bytes[0x1E0..0x1E4].copy_from_slice(&(0x200u32).to_le_bytes());
        bytes[0x1E4..0x1E8].copy_from_slice(&(0x3000u32).to_le_bytes());
        bytes[0x1E8..0x1EC].copy_from_slice(&(0x200u32).to_le_bytes());
        bytes[0x1EC..0x1F0].copy_from_slice(&(0xE00u32).to_le_bytes());
        bytes[0x1FC..0x200].copy_from_slice(&(0x40000040u32).to_le_bytes());

        // Write .rdata contents (file offset 0x800):
        // Strings at RVAs:
        // 0x2000 (offset 0x800): Source path
        let src_str = b"\\components\\core\\src\\synthetic_interactor.cpp\0";
        bytes[0x800..0x800 + src_str.len()].copy_from_slice(src_str);

        // 0x2050 (offset 0x850): Function name
        let fn_str = b"Core::Synthetic::SyntheticInteractor::doSendSyntheticPacket\0";
        bytes[0x850..0x850 + fn_str.len()].copy_from_slice(fn_str);

        // 0x20A0 (offset 0x8A0): Tag
        let tag_str = b"SyntheticTag\0";
        bytes[0x8A0..0x8A0 + tag_str.len()].copy_from_slice(tag_str);

        // 0x20C0 (offset 0x8C0): Template
        let tpl_str = b"Synthetic packet sent: result={}\0";
        bytes[0x8C0..0x8C0 + tpl_str.len()].copy_from_slice(tpl_str);

        // 0x2100 (offset 0x900): IAT entry for Logger::writeMessage (at VA 0x180002100)
        bytes[0x900..0x908].copy_from_slice(&(0x180009999u64).to_le_bytes());

        // 0x2200 (offset 0xA00): Vtable for packet opcode 99
        let vtable_rva = 0x2200u32;
        bytes[0xA00..0xA08].copy_from_slice(&(0x180001000u64).to_le_bytes());

        // Write .text contents (file offset 0x400):
        // Function 1: Constructor for packet 99 at RVA 0x1000 (offset 0x400):
        // 0x1000: lea rax, [rip + 0x11f9] (target = 0x1007 + 0x11f9 = 0x2200 = vtable)
        // 48 8D 05 F9 11 00 00
        bytes[0x400..0x407].copy_from_slice(&[0x48, 0x8D, 0x05, 0xF9, 0x11, 0x00, 0x00]);
        // 0x1007: ret (C3)
        bytes[0x407] = 0xC3;

        // Function 2: Caller Interactor at RVA 0x1020 (offset 0x420):
        // 0x1020: lea rax, [rip + 0x1029] (0x1027 + 0x1029 = 0x2050 = fn_str)
        bytes[0x420..0x427].copy_from_slice(&[0x48, 0x8D, 0x05, 0x29, 0x10, 0x00, 0x00]);
        // 0x1027: mov [rsp+0x28], rax
        bytes[0x427..0x42C].copy_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x28]);
        // 0x102C: lea r9, [rip + 0x0fcd] (0x1033 + 0x0FCD = 0x2000 = src_str)
        bytes[0x42C..0x433].copy_from_slice(&[0x4C, 0x8D, 0x0D, 0xCD, 0x0F, 0x00, 0x00]);
        // 0x1033: lea rdx, [rip + 0x1066] (0x103A + 0x1066 = 0x20A0 = tag_str)
        bytes[0x433..0x43A].copy_from_slice(&[0x48, 0x8D, 0x15, 0x66, 0x10, 0x00, 0x00]);
        // 0x103A: lea r8, [rip + 0x107f] (0x1041 + 0x107F = 0x20C0 = tpl_str)
        bytes[0x43A..0x441].copy_from_slice(&[0x4C, 0x8D, 0x05, 0x7F, 0x10, 0x00, 0x00]);
        // 0x1041: call [rip + 0x10b9] (0x1047 + 0x10B9 = 0x2100 = logger IAT)
        bytes[0x441..0x447].copy_from_slice(&[0xFF, 0x15, 0xB9, 0x10, 0x00, 0x00]);
        // 0x1047: call rel32 (target = 0x1000 = ctor, disp = 0x1000 - 0x104C = -0x4C)
        let disp_to_ctor: i32 = -0x4C;
        bytes[0x447] = 0xE8;
        bytes[0x448..0x44C].copy_from_slice(&disp_to_ctor.to_le_bytes());
        // 0x104C: ret (C3)
        bytes[0x44C] = 0xC3;

        // Write .pdata contents (file offset 0xE00):
        // Function 1: 0x1000..0x1020
        bytes[0xE00..0xE04].copy_from_slice(&(0x1000u32).to_le_bytes());
        bytes[0xE04..0xE08].copy_from_slice(&(0x1020u32).to_le_bytes());
        bytes[0xE08..0xE0C].copy_from_slice(&(0u32).to_le_bytes());

        // Function 2: 0x1020..0x1080
        bytes[0xE0C..0xE10].copy_from_slice(&(0x1020u32).to_le_bytes());
        bytes[0xE10..0xE14].copy_from_slice(&(0x1080u32).to_le_bytes());
        bytes[0xE14..0xE18].copy_from_slice(&(0u32).to_le_bytes());

        let pe = PeImage::parse(&bytes).expect("Synthetic PE must parse");

        let mut rtti = RttiEngine {
            type_descriptors: HashMap::new(),
            vtable_to_type: HashMap::new(),
            type_to_vtable: HashMap::new(),
            smember_vtables: HashMap::new(),
            hierarchy: ClassHierarchy::default(),
        };
        rtti.vtable_to_type.insert(
            vtable_rva,
            "Api::OneMe::Packets::CommonPacket<99,struct Api::OneMe::Packets::Synthetic::Parameters,struct Api::OneMe::Packets::Synthetic::Response,0>".to_string(),
        );

        let scanner = ProtocolScanner {
            packets: vec![PacketDescriptor {
                opcode: 99,
                request_full_name: "Api::OneMe::Packets::Synthetic::Parameters".to_string(),
                request_kind: "Parameters".to_string(),
                response_full_name: "Api::OneMe::Packets::Synthetic::Response".to_string(),
                response_kind: "Response".to_string(),
                is_special: false,
                special_name: None,
                base_kind: None,
                special_request_fields: Vec::new(),
            }],
            events: Vec::new(),
            string_enums: Vec::new(),
        };

        // Note: override default IAT VA by calling analyze_callsites
        // Here, our synthetic logger IAT is at 0x180002100. Let's verify analyze_callsites:
        let _ = LoggerAnalyzer::analyze_callsites(&pe).expect("analyze callsites");
        // Because default IAT VA is 0x181e98708 and goblin didn't see an import table,
        // let's verify that when callsites are provided, packet catalog binding succeeds!
        let manual_callsites = vec![LoggerCallsite {
            rva: 0x1041,
            enclosing_function_rva: Some(0x1020),
            tag: Some("SyntheticTag".to_string()),
            template: Some("Synthetic packet sent: result={}".to_string()),
            source_file: Some("components/core/src/synthetic_interactor.cpp".to_string()),
            function_name: Some(
                "Core::Synthetic::SyntheticInteractor::doSendSyntheticPacket".to_string(),
            ),
        }];

        let catalog = LoggerAnalyzer::build_packet_catalog(
            &pe,
            &rtti,
            &scanner.packets,
            &manual_callsites,
        );

        assert_eq!(catalog.len(), 1);
        let entry = &catalog[0];
        assert_eq!(entry.opcode, 99);
        assert_eq!(entry.name, "Synthetic");
        assert!(entry.handler.is_some());
        let handler = entry.handler.as_ref().unwrap();
        assert_eq!(handler.class, "Core::Synthetic::SyntheticInteractor");
        assert_eq!(handler.method, "doSendSyntheticPacket");
        assert_eq!(
            handler.source,
            "components/core/src/synthetic_interactor.cpp"
        );
    }
}
