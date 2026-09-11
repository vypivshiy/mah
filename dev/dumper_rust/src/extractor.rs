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

pub fn is_dispatch_function(pe: &PeImage, func_rva: u32) -> bool {
    let func = match pe.find_function(func_rva) {
        Some(f) => f,
        None => return false,
    };
    if func.len() > 15000 {
        return true;
    }
    let check_len = (func.len() as usize).min(120);
    let slice = match pe.slice_at_rva(func.begin_address, check_len) {
        Some(s) => s,
        None => return false,
    };
    let mut decoder = Decoder::with_ip(64, slice, pe.image_base + func_rva as u64, DecoderOptions::NONE);
    let mut count = 0;
    let mut saw_large_eax = false;
    while decoder.can_decode() && count < 25 {
        let mut insn = Instruction::default();
        decoder.decode_out(&mut insn);
        count += 1;

        if insn.mnemonic() == Mnemonic::Mov && insn.op0_register() == Register::EAX {
            if insn.op1_kind() == OpKind::Immediate32 && insn.immediate32() > 0x1000 {
                saw_large_eax = true;
            }
        }
        if insn.mnemonic() == Mnemonic::Sub && insn.op0_register() == Register::RSP {
            if insn.op1_kind() == OpKind::Register && insn.op1_register() == Register::RAX && saw_large_eax {
                return true;
            }
            if (insn.op1_kind() == OpKind::Immediate32 || insn.op1_kind() == OpKind::Immediate16)
                && insn.immediate32() > 0x1000
            {
                return true;
            }
        }
        if insn.mnemonic() == Mnemonic::Lea && insn.op0_register() == Register::RBP && insn.memory_base() == Register::RSP {
            if (insn.memory_displacement64() as i64).unsigned_abs() > 0x1000 {
                return true;
            }
        }
    }
    false
}

pub fn contains_serializable_member_refs(pe: &PeImage, rtti: &RttiEngine, func_rva: u32) -> bool {
    let func = match pe.find_function(func_rva) {
        Some(f) => f,
        None => return false,
    };
    let slice = match pe.slice_at_rva(func.begin_address, func.len() as usize) {
        Some(s) => s,
        None => return false,
    };
    let mut decoder = Decoder::with_ip(64, slice, pe.image_base + func_rva as u64, DecoderOptions::NONE);
    while decoder.can_decode() {
        let mut insn = Instruction::default();
        decoder.decode_out(&mut insn);

        if insn.mnemonic() == Mnemonic::Lea && insn.op1_kind() == OpKind::Memory && insn.memory_base() == Register::RIP {
            let target_va = insn.memory_displacement64();
            if target_va >= pe.image_base {
                let target_rva = (target_va - pe.image_base) as u32;
                if let Some(inner_t) = rtti.smember_vtables.get(&target_rva) {
                    if !inner_t.contains("SerializedType") && !inner_t.contains("ISerializableMember") {
                        return true;
                    }
                }
            }
        } else if insn.mnemonic() == Mnemonic::Call {
            let target_va = insn.near_branch64();
            if target_va >= pe.image_base {
                let target_rva = (target_va - pe.image_base) as u32;
                if target_rva == 0x35477 {
                    return true;
                }
            }
        }
    }
    false
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

        // Filter out functions with dispatch characteristics and verify member registration references
        let qualified_funcs: Vec<u32> = funcs
            .iter()
            .copied()
            .filter(|&f| {
                !is_dispatch_function(extractor.pe, f)
                    && contains_serializable_member_refs(extractor.pe, extractor.rtti, f)
            })
            .collect();
        let eval_funcs = if !qualified_funcs.is_empty() {
            &qualified_funcs
        } else {
            funcs
        };

        let mut best_func = eval_funcs[0];
        let mut best_fields = Vec::new();
        let mut best_unique_count = 0;

        for &func_rva in eval_funcs {
            if let Ok(fields) = extractor.extract_from_func(func_rva) {
                if fields.is_empty() {
                    continue;
                }
                let unique_count = fields.len();
                if unique_count > best_unique_count {
                    best_unique_count = unique_count;
                    best_fields = fields;
                    best_func = func_rva;
                } else if unique_count == best_unique_count && unique_count > 0 {
                    let curr_len = extractor.pe.find_function(func_rva).map(|f| f.len()).unwrap_or(u32::MAX);
                    let best_len = extractor.pe.find_function(best_func).map(|f| f.len()).unwrap_or(u32::MAX);
                    if curr_len < best_len {
                        best_fields = fields;
                        best_func = func_rva;
                    }
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

#[derive(Debug)]
struct PendingField {
    name: String,
    insn_idx: usize,
    type_name: Option<String>,
    type_insn_idx: Option<usize>,
    required: Option<bool>,
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
        let mut pending_field: Option<PendingField> = None;
        let mut pending_r9_required: Option<bool> = None;
        let mut insn_idx: usize = 0;

        let commit_field = |pf: PendingField, fields: &mut Vec<ExtractedField>| {
            if let Some(raw_t) = pf.type_name {
                let field_t = decompose_type(&raw_t);
                let req = if field_t.optional {
                    false
                } else {
                    pf.required.unwrap_or(false)
                };
                if !fields.iter().any(|f| f.name == pf.name) {
                    fields.push(ExtractedField {
                        name: pf.name,
                        field_type: field_t,
                        required: req,
                    });
                }
            }
        };

        while decoder.can_decode() {
            let mut insn = Instruction::default();
            decoder.decode_out(&mut insn);
            insn_idx += 1;

            match insn.mnemonic() {
                Mnemonic::Lea => {
                    let dest_reg = insn.op0_register().full_register();
                    if insn.op1_kind() == OpKind::Memory && insn.memory_base() == Register::RIP {
                        let target_va = insn.memory_displacement64();
                        if target_va >= self.pe.image_base {
                            let target_rva = (target_va - self.pe.image_base) as u32;

                            // 1. Is target_rva a SerializableMember Vtable?
                            if let Some(inner_t) = self.rtti.smember_vtables.get(&target_rva) {
                                if !inner_t.contains("SerializedType") && !inner_t.contains("ISerializableMember") {
                                    reg_state.insert(dest_reg, RegVal::MemberVtable(inner_t.clone()));
                                    if let Some(ref mut pf) = pending_field {
                                        if insn_idx.saturating_sub(pf.insn_idx) <= 35 {
                                            pf.type_name = Some(inner_t.clone());
                                            pf.type_insn_idx = Some(insn_idx);
                                        }
                                    }
                                    continue;
                                }
                            }
                            if self.rtti.vtable_to_type.contains_key(&target_rva) {
                                reg_state.remove(&dest_reg);
                                continue;
                            }

                            // 2. Is target_rva a string literal for field name?
                            if let Some(s) = self.pe.read_cstring(target_rva) {
                                if is_valid_field_name(s) {
                                    if let Some(pf) = pending_field.take() {
                                        commit_field(pf, &mut fields);
                                    }
                                    pending_field = Some(PendingField {
                                        name: s.to_string(),
                                        insn_idx,
                                        type_name: None,
                                        type_insn_idx: None,
                                        required: None,
                                    });
                                    reg_state.insert(dest_reg, RegVal::StringLiteral);
                                    continue;
                                }
                            }
                        }
                    }
                    reg_state.remove(&dest_reg);
                }
                Mnemonic::Mov => {
                    if insn.op0_kind() == OpKind::Memory && insn.memory_base() != Register::RIP && insn.memory_base() != Register::None {
                        if insn.op1_kind() == OpKind::Immediate32 || insn.op1_kind() == OpKind::Immediate8 {
                            let imm = insn.immediate32();
                            if imm == 1 || imm == 2 {
                                if let Some(ref mut pf) = pending_field {
                                    if pf.type_name.is_some() && insn_idx.saturating_sub(pf.type_insn_idx.unwrap_or(0)) <= 10 {
                                        pf.required = Some(imm == 1);
                                    }
                                }
                            }
                        } else if insn.op1_kind() == OpKind::Register {
                            if insn.op1_register().is_gpr64() {
                                let src_reg = insn.op1_register().full_register();
                                if let Some(RegVal::MemberVtable(t)) = reg_state.get(&src_reg) {
                                    if let Some(ref mut pf) = pending_field {
                                        if insn_idx.saturating_sub(pf.insn_idx) <= 35 {
                                            pf.type_name = Some(t.clone());
                                            pf.type_insn_idx = Some(insn_idx);
                                        }
                                    }
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
                            if dest_reg == Register::R9 {
                                if imm == 1 || imm == 2 {
                                    pending_r9_required = Some(imm == 1);
                                }
                            }
                            reg_state.insert(dest_reg, RegVal::Imm);
                        } else {
                            reg_state.remove(&dest_reg);
                        }
                    }
                }
                Mnemonic::Xor | Mnemonic::Sub => {
                    if insn.op0_kind() == OpKind::Register {
                        let dest_reg = insn.op0_register().full_register();
                        if insn.op1_kind() == OpKind::Register && dest_reg == insn.op1_register().full_register() {
                            reg_state.insert(dest_reg, RegVal::Imm);
                        } else {
                            reg_state.remove(&dest_reg);
                        }
                    }
                }
                Mnemonic::Call => {
                    if let Some(ref mut pf) = pending_field {
                        if let Some(req) = pending_r9_required.take() {
                            pf.required = Some(req);
                        }
                        if pf.type_name.is_none() && insn_idx.saturating_sub(pf.insn_idx) <= 35 {
                            let target_va = insn.near_branch64();
                            if target_va >= self.pe.image_base {
                                let target_rva = (target_va - self.pe.image_base) as u32;
                                if target_rva != 0x35477 {
                                    if let Some(t) = self.infer_helper_type(target_rva, &mut helper_cache, 0) {
                                        pf.type_name = Some(t);
                                        pf.type_insn_idx = Some(insn_idx);
                                    }
                                }
                            }
                        }
                    }
                    pending_r9_required = None;
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

        if let Some(pf) = pending_field {
            commit_field(pf, &mut fields);
        }

        Ok(fields)
    }

    fn infer_helper_type(
        &self,
        target_rva: u32,
        cache: &mut HashMap<u32, Option<String>>,
        depth: usize,
    ) -> Option<String> {
        if depth > 4 {
            return None;
        }
        if let Some(cached) = cache.get(&target_rva) {
            return cached.clone();
        }

        let slice = self.pe.slice_at_rva(target_rva, 256)?;
        let mut decoder = Decoder::with_ip(
            64,
            slice,
            self.pe.image_base + target_rva as u64,
            DecoderOptions::NONE,
        );

        let mut insn_count = 0;
        let mut last_type = None;

        while decoder.can_decode() && insn_count < 50 {
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
                            break;
                        }
                    }
                }
            } else if insn.mnemonic() == Mnemonic::Jmp {
                if insn.op0_kind() == OpKind::NearBranch64 {
                    let jmp_va = insn.near_branch64();
                    if jmp_va >= self.pe.image_base {
                        let jmp_rva = (jmp_va - self.pe.image_base) as u32;
                        if let Some(t) = self.infer_helper_type(jmp_rva, cache, depth + 1) {
                            last_type = Some(t);
                            break;
                        }
                    }
                }
                break;
            } else if insn.mnemonic() == Mnemonic::Call {
                if insn.op0_kind() == OpKind::NearBranch64 {
                    let call_va = insn.near_branch64();
                    if call_va >= self.pe.image_base {
                        let call_rva = (call_va - self.pe.image_base) as u32;
                        if let Some(t) = self.infer_helper_type(call_rva, cache, depth + 1) {
                            last_type = Some(t);
                            break;
                        }
                    }
                }
            } else if insn.mnemonic() == Mnemonic::Ret {
                break;
            }
        }

        cache.insert(target_rva, last_type.clone());
        last_type
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
