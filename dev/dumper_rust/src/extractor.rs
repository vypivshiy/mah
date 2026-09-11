use crate::pe::PeImage;
use crate::rtti::RttiEngine;
use crate::type_parser::{decompose_type, DecomposedType};
use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: DecomposedType,
    pub required: bool,
}

pub struct VtableXrefIndex {
    pub vtable_to_funcs: HashMap<u32, Vec<u32>>,
}

impl VtableXrefIndex {
    pub fn build(pe: &PeImage, rtti: &RttiEngine) -> Self {
        let mut vtable_to_funcs: HashMap<u32, Vec<u32>> = HashMap::new();

        if let (Some(text_sec), Some(text_data)) = (pe.section_by_name(".text"), pe.section_data(".text")) {
            let mut decoder = Decoder::with_ip(
                64,
                text_data,
                pe.image_base + text_sec.virtual_address as u64,
                DecoderOptions::NONE,
            );

            while decoder.can_decode() {
                let mut insn = Instruction::default();
                decoder.decode_out(&mut insn);

                if insn.mnemonic() == Mnemonic::Lea
                    && insn.op1_kind() == OpKind::Memory
                    && insn.memory_base() == Register::RIP
                {
                    let target_va = insn.memory_displacement64();
                    if target_va >= pe.image_base {
                        let target_rva = (target_va - pe.image_base) as u32;
                        if rtti.vtable_to_type.contains_key(&target_rva) {
                            let insn_rva = (insn.ip() - pe.image_base) as u32;
                            if let Some(func) = pe.find_function(insn_rva) {
                                let list = vtable_to_funcs.entry(target_rva).or_default();
                                if !list.contains(&func.begin_address) {
                                    list.push(func.begin_address);
                                }
                            }
                        }
                    }
                }
            }
        }

        VtableXrefIndex { vtable_to_funcs }
    }

    pub fn find_best_initializer(
        &self,
        vtable_rva: u32,
        extractor: &FieldExtractor,
    ) -> Option<(u32, Vec<ExtractedField>)> {
        let funcs = self.vtable_to_funcs.get(&vtable_rva)?;
        if funcs.is_empty() {
            return None;
        }
        if funcs.len() == 1 {
            let func_rva = funcs[0];
            let fields = extractor.extract_from_func(func_rva).unwrap_or_default();
            return Some((func_rva, fields));
        }

        let small_funcs: Vec<u32> = funcs
            .iter()
            .copied()
            .filter(|&f| {
                extractor
                    .pe
                    .find_function(f)
                    .map(|func| (func.end_address - func.begin_address) <= 15000)
                    .unwrap_or(true)
            })
            .collect();
        let eval_funcs = if !small_funcs.is_empty() { &small_funcs } else { funcs };

        let mut best_func = eval_funcs[0];
        let mut best_fields = Vec::new();
        let mut best_unique_count = 0;

        for &func_rva in eval_funcs {
            if let Ok(fields) = extractor.extract_from_func(func_rva) {
                if fields.is_empty() {
                    continue;
                }
                let unique_count = fields.iter().map(|f| &f.name).collect::<std::collections::HashSet<_>>().len();
                let has_duplicates = unique_count < fields.len();
                if !has_duplicates && unique_count > best_unique_count {
                    best_unique_count = unique_count;
                    best_fields = fields;
                    best_func = func_rva;
                } else if best_unique_count == 0 && unique_count > 0 {
                    best_fields = fields;
                    best_func = func_rva;
                }
            }
        }

        Some((best_func, best_fields))
    }
}

pub struct FieldExtractor<'a> {
    pub pe: &'a PeImage<'a>,
    pub rtti: &'a RttiEngine,
}

impl<'a> FieldExtractor<'a> {
    pub fn new(pe: &'a PeImage<'a>, rtti: &'a RttiEngine) -> Self {
        FieldExtractor { pe, rtti }
    }

    pub fn extract_from_func(&self, func_rva: u32) -> Result<Vec<ExtractedField>> {
        let func = match self.pe.find_function(func_rva) {
            Some(f) => f,
            None => return Ok(Vec::new()),
        };

        let len = (func.end_address - func.begin_address) as usize;
        let code = match self.pe.slice_at_rva(func.begin_address, len) {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        let mut decoder = Decoder::with_ip(
            64,
            code,
            self.pe.image_base + func.begin_address as u64,
            DecoderOptions::NONE,
        );

        let mut reg_state: HashMap<Register, RegVal> = HashMap::new();
        let mut helper_cache: HashMap<u32, Option<String>> = HashMap::new();

        let mut fields: Vec<ExtractedField> = Vec::new();
        let mut pending_name: Option<String> = None;
        let mut pending_type: Option<String> = None;
        let mut pending_flag: Option<bool> = None;

        while decoder.can_decode() {
            let mut insn = Instruction::default();
            decoder.decode_out(&mut insn);

            match insn.mnemonic() {
                Mnemonic::Lea => {
                    let dest_reg = insn.op0_register().full_register();
                    if insn.op1_kind() == OpKind::Memory && insn.memory_base() == Register::RIP {
                        let target_va = insn.memory_displacement64();
                        if target_va >= self.pe.image_base {
                            let target_rva = (target_va - self.pe.image_base) as u32;

                            // 1. Is target_rva a Vtable? (Check FIRST to prevent pointer addresses that look like ASCII from being treated as strings)
                            if let Some(inner_t) = self.rtti.smember_vtables.get(&target_rva) {
                                if !inner_t.contains("SerializedType") && !inner_t.contains("ISerializableMember") {
                                    pending_type = Some(inner_t.clone());
                                    reg_state.insert(dest_reg, RegVal::MemberVtable(inner_t.clone()));
                                }
                                continue;
                            }
                            if self.rtti.vtable_to_type.contains_key(&target_rva) {
                                continue;
                            }

                            // 2. Is target_rva a string literal for field name?
                            if let Some(s) = self.pe.read_cstring(target_rva) {
                                if is_valid_field_name(s) {
                                    if let Some(name) = pending_name.take() {
                                        let raw_t = pending_type.take().unwrap_or_else(|| "unknown".to_string());
                                        fields.push(ExtractedField {
                                            name,
                                            field_type: decompose_type(&raw_t),
                                            required: pending_flag.take().unwrap_or(true),
                                        });
                                    }
                                    pending_name = Some(s.to_string());
                                    pending_type = None;
                                    pending_flag = None;

                                    reg_state.insert(dest_reg, RegVal::StringLiteral);
                                    continue;
                                }
                            }
                        }
                    }
                    reg_state.remove(&dest_reg);
                }
                Mnemonic::Mov => {
                    // Check if setting required / optional flag
                    if insn.op0_kind() == OpKind::Memory {
                        if insn.op1_kind() == OpKind::Immediate32 || insn.op1_kind() == OpKind::Immediate8 {
                            let imm = insn.immediate32();
                            if imm == 1 {
                                pending_flag = Some(true);
                            } else if imm == 2 {
                                pending_flag = Some(false);
                            }
                        } else if insn.op1_kind() == OpKind::Register {
                            let src_reg = insn.op1_register().full_register();
                            if let Some(RegVal::MemberVtable(t)) = reg_state.get(&src_reg) {
                                if pending_type.is_none() {
                                    pending_type = Some(t.clone());
                                }
                            }
                        }
                    } else if insn.op0_kind() == OpKind::Register {
                        let dest_reg = insn.op0_register().full_register();
                        if insn.op1_kind() == OpKind::Register {
                            let src_reg = insn.op1_register().full_register();
                            if let Some(val) = reg_state.get(&src_reg).cloned() {
                                reg_state.insert(dest_reg, val);
                            } else {
                                reg_state.remove(&dest_reg);
                            }
                        } else if insn.op1_kind() == OpKind::Immediate32 || insn.op1_kind() == OpKind::Immediate8 {
                            let imm = insn.immediate32();
                            if imm == 1 {
                                pending_flag = Some(true);
                            } else if imm == 2 {
                                pending_flag = Some(false);
                            }
                            reg_state.insert(dest_reg, RegVal::Imm);
                        } else {
                            reg_state.remove(&dest_reg);
                        }
                    }
                }
                Mnemonic::Call => {
                    if pending_type.is_none() {
                        let target_va = insn.near_branch64();
                        if target_va >= self.pe.image_base {
                            let target_rva = (target_va - self.pe.image_base) as u32;
                            if let Some(t) = self.infer_helper_type(target_rva, &mut helper_cache, 0) {
                                pending_type = Some(t);
                            }
                        }
                    }
                    // MSVC x64 ABI volatile registers are invalidated across function calls
                    for v_reg in &[
                        Register::RAX,
                        Register::RCX,
                        Register::RDX,
                        Register::R8,
                        Register::R9,
                        Register::R10,
                        Register::R11,
                    ] {
                        reg_state.remove(v_reg);
                    }
                }
                _ => {}
            }
        }

        if let Some(name) = pending_name {
            let raw_t = pending_type.unwrap_or_else(|| "unknown".to_string());
            fields.push(ExtractedField {
                name,
                field_type: decompose_type(&raw_t),
                required: pending_flag.unwrap_or(true),
            });
        }

        Ok(fields)
    }

    fn infer_helper_type(
        &self,
        target_rva: u32,
        cache: &mut HashMap<u32, Option<String>>,
        depth: usize,
    ) -> Option<String> {
        if depth > 5 {
            return None;
        }
        if let Some(cached) = cache.get(&target_rva) {
            return cached.clone();
        }

        let slice = self.pe.slice_at_rva(target_rva, 128)?;
        let mut decoder = Decoder::with_ip(
            64,
            slice,
            self.pe.image_base + target_rva as u64,
            DecoderOptions::NONE,
        );

        let mut insn_count = 0;
        let mut last_type = None;

        while decoder.can_decode() && insn_count < 40 {
            let mut insn = Instruction::default();
            decoder.decode_out(&mut insn);
            insn_count += 1;

            if insn.mnemonic() == Mnemonic::Lea
                && insn.op1_kind() == OpKind::Memory
                && insn.memory_base() == Register::RIP
            {
                let target_va = insn.memory_displacement64();
                if target_va >= self.pe.image_base {
                    let rva = (target_va - self.pe.image_base) as u32;
                    if let Some(inner_t) = self.rtti.smember_vtables.get(&rva) {
                        if !inner_t.contains("SerializedType") && !inner_t.contains("ISerializableMember") {
                            last_type = Some(inner_t.clone());
                        }
                    }
                }
            } else if insn.mnemonic() == Mnemonic::Jmp {
                if insn.op0_kind() == OpKind::NearBranch64 {
                    let jmp_va = insn.near_branch64();
                    if jmp_va >= self.pe.image_base {
                        let jmp_rva = (jmp_va - self.pe.image_base) as u32;
                        if let Some(t) = self.infer_helper_type(jmp_rva, cache, depth + 1) {
                            cache.insert(target_rva, Some(t.clone()));
                            return Some(t);
                        }
                    }
                }
                break;
            } else if insn.mnemonic() == Mnemonic::Ret {
                break;
            }
        }

        if last_type.is_some() {
            cache.insert(target_rva, last_type.clone());
            return last_type;
        }

        cache.insert(target_rva, None);
        None
    }
}

#[derive(Clone, Debug)]
enum RegVal {
    StringLiteral,
    MemberVtable(String),
    Imm,
}

fn is_valid_field_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    let bytes = s.as_bytes();
    let first = bytes[0];
    if !first.is_ascii_alphabetic() && first != b'_' {
        return false;
    }
    bytes.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
