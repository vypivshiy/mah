use crate::msvc::X64_VOLATILE_REGISTERS;
use crate::pe::{PeImage, RuntimeFunction};
use crate::rtti::RttiEngine;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const MAX_FACTORY_FUNCTION_LEN: u32 = 4096;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscriminatorScanDiagnostics {
    pub evidence: Vec<DiscriminatorValueEvidence>,
    pub misses: Vec<DiscriminatorExtractionMiss>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscriminatorValueEvidence {
    pub variant_name: String,
    pub value: String,
    pub function_rva: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscriminatorExtractionMiss {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_rva: Option<String>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constructed_variants: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub type_assignments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiscriminatorEvidence {
    pub variant_name: String,
    pub value: String,
    pub function_rva: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FactoryDiscriminatorFacts {
    pub function_rva: u32,
    pub constructed_variants: BTreeSet<String>,
    pub type_assignments: BTreeSet<String>,
    pub direct_type_assignments: BTreeMap<String, BTreeSet<String>>,
    pub ambiguous_type_assignment: bool,
}

pub(crate) fn scan_discriminator_values_with_diagnostics(
    pe: &PeImage,
    rtti: &RttiEngine,
    candidate_variants: &BTreeSet<String>,
) -> (BTreeMap<String, String>, DiscriminatorScanDiagnostics) {
    if candidate_variants.is_empty() {
        return (BTreeMap::new(), DiscriminatorScanDiagnostics::default());
    }

    let facts = candidate_converter_factory_functions(pe, rtti, candidate_variants)
        .into_iter()
        .filter_map(|func| scan_function_facts(pe, rtti, candidate_variants, func))
        .collect::<Vec<_>>();
    let evidence = evidence_from_factory_facts(&facts);
    let values = values_from_evidence(&evidence);
    let diagnostics = diagnostics_from_scan(candidate_variants, &facts, &evidence, &values);
    (values, diagnostics)
}

fn diagnostics_from_scan(
    candidate_variants: &BTreeSet<String>,
    facts: &[FactoryDiscriminatorFacts],
    evidence: &[DiscriminatorEvidence],
    values: &BTreeMap<String, String>,
) -> DiscriminatorScanDiagnostics {
    let evidence_entries = evidence
        .iter()
        .map(|item| DiscriminatorValueEvidence {
            variant_name: item.variant_name.clone(),
            value: item.value.clone(),
            function_rva: format!("0x{:x}", item.function_rva),
        })
        .collect();

    let mut misses = facts
        .iter()
        .filter_map(miss_from_factory_fact)
        .collect::<Vec<_>>();
    misses.extend(variant_value_misses(candidate_variants, evidence, values));

    DiscriminatorScanDiagnostics {
        evidence: evidence_entries,
        misses,
    }
}

fn miss_from_factory_fact(fact: &FactoryDiscriminatorFacts) -> Option<DiscriminatorExtractionMiss> {
    if !fact.direct_type_assignments.is_empty() {
        return None;
    }
    let reason = factory_fact_miss_reason(fact)?;
    let variant_name = if fact.constructed_variants.len() == 1 {
        fact.constructed_variants.iter().next().cloned()
    } else {
        None
    };

    Some(DiscriminatorExtractionMiss {
        variant_name,
        function_rva: Some(format!("0x{:x}", fact.function_rva)),
        reason,
        constructed_variants: fact.constructed_variants.iter().cloned().collect(),
        type_assignments: fact.type_assignments.iter().cloned().collect(),
    })
}

fn factory_fact_miss_reason(fact: &FactoryDiscriminatorFacts) -> Option<String> {
    if fact.ambiguous_type_assignment {
        return Some("ambiguous _type assignment".to_string());
    }
    if fact.constructed_variants.is_empty() {
        return Some("no candidate variant construction observed".to_string());
    }
    if fact.constructed_variants.len() > 1 {
        return Some("multiple candidate variant constructions observed".to_string());
    }
    if fact.type_assignments.is_empty() {
        return Some("no _type assignment observed".to_string());
    }
    if fact.type_assignments.len() > 1 {
        return Some("multiple _type assignment values observed".to_string());
    }

    let value = fact.type_assignments.iter().next().expect("single value");
    if !is_scream_case_discriminator_value(value) {
        return Some(format!("_type value '{value}' is not SCREAM_CASE"));
    }

    None
}

fn variant_value_misses(
    candidate_variants: &BTreeSet<String>,
    evidence: &[DiscriminatorEvidence],
    values: &BTreeMap<String, String>,
) -> Vec<DiscriminatorExtractionMiss> {
    let mut evidence_values_by_variant: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for item in evidence {
        evidence_values_by_variant
            .entry(item.variant_name.clone())
            .or_default()
            .insert(item.value.clone());
    }

    candidate_variants
        .iter()
        .filter(|variant| !values.contains_key(*variant))
        .map(|variant| {
            let evidence_values = evidence_values_by_variant
                .get(variant)
                .map(|values| values.iter().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let reason = if evidence_values.len() > 1 {
                format!(
                    "conflicting discriminator values: {}",
                    evidence_values.join(", ")
                )
            } else {
                "no high-confidence discriminator value found".to_string()
            };

            DiscriminatorExtractionMiss {
                variant_name: Some(variant.clone()),
                function_rva: None,
                reason,
                constructed_variants: vec![variant.clone()],
                type_assignments: evidence_values,
            }
        })
        .collect()
}

fn evidence_from_factory_facts(facts: &[FactoryDiscriminatorFacts]) -> Vec<DiscriminatorEvidence> {
    facts
        .iter()
        .filter(|fact| !fact.ambiguous_type_assignment)
        .flat_map(|fact| {
            fact.direct_type_assignments
                .iter()
                .filter_map(|(variant_name, values)| {
                    if values.len() != 1 {
                        return None;
                    }

                    let value = values.iter().next()?.clone();
                    if !is_scream_case_discriminator_value(&value) {
                        return None;
                    }

                    Some(DiscriminatorEvidence {
                        variant_name: variant_name.clone(),
                        value,
                        function_rva: fact.function_rva,
                    })
                })
        })
        .collect()
}

fn values_from_evidence(evidence: &[DiscriminatorEvidence]) -> BTreeMap<String, String> {
    let mut values_by_variant: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for item in evidence {
        if is_scream_case_discriminator_value(&item.value) {
            values_by_variant
                .entry(item.variant_name.clone())
                .or_default()
                .insert(item.value.clone());
        }
    }

    values_by_variant
        .into_iter()
        .filter_map(|(variant_name, values)| {
            if values.len() == 1 {
                Some((
                    variant_name,
                    values.into_iter().next().expect("single value"),
                ))
            } else {
                None
            }
        })
        .collect()
}

pub fn is_scream_case_discriminator_value(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }

    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_uppercase() {
        return false;
    }
    if bytes.iter().all(|byte| byte.is_ascii_digit()) {
        return false;
    }

    bytes
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

pub fn strip_ref_count_obj2(type_name: &str) -> Option<&str> {
    let mut s = type_name.trim();
    for prefix in &["class ", "struct "] {
        if s.starts_with(prefix) {
            s = &s[prefix.len()..];
            break;
        }
    }
    let rest = if let Some(r) = s.strip_prefix("std::_Ref_count_obj2<") {
        r
    } else if let Some(r) = s.strip_prefix("_Ref_count_obj2<") {
        r
    } else {
        return None;
    };
    let trimmed = rest.trim();
    let inner = trimmed.strip_suffix('>')?;
    let mut inner = inner.trim();
    for prefix in &["class ", "struct "] {
        if inner.starts_with(prefix) {
            inner = &inner[prefix.len()..];
            break;
        }
    }
    Some(inner.trim())
}

pub fn match_candidate_variant(
    raw_type_name: &str,
    candidate_variants: &BTreeSet<String>,
) -> Option<String> {
    if candidate_variants.contains(raw_type_name) {
        return Some(raw_type_name.to_string());
    }
    if let Some(inner) = strip_ref_count_obj2(raw_type_name) {
        if candidate_variants.contains(inner) {
            return Some(inner.to_string());
        }
    }
    None
}

pub fn resolve_vtable_variant(
    rtti: &RttiEngine,
    vtable_rva: u32,
    candidate_variants: &BTreeSet<String>,
) -> Option<String> {
    let type_name = rtti.vtable_to_type.get(&vtable_rva)?;
    match_candidate_variant(type_name, candidate_variants)
}

pub fn resolve_string_literal(pe: &PeImage, target_rva: u32) -> Option<String> {
    if let Some(val) = pe.read_cstring(target_rva) {
        if val == "_type" || is_scream_case_discriminator_value(val) {
            return Some(val.to_string());
        }
    }
    if let Some(slice) = pe.slice_at_rva(target_rva, 8) {
        if let Ok(bytes) = slice.try_into() {
            let ptr = u64::from_le_bytes(bytes);
            if ptr >= pe.image_base {
                let str_rva = (ptr - pe.image_base) as u32;
                if let Some(val) = pe.read_cstring(str_rva) {
                    if val == "_type" || is_scream_case_discriminator_value(val) {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }
    None
}

pub fn build_discriminator_catalog(
    polymorphic_models: &[crate::dumper::PolymorphicModelEntry],
) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut catalog: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for poly in polymorphic_models {
        let mut map = BTreeMap::new();
        for variant in poly.variants.iter().chain(poly.rtti_subclasses.iter()) {
            if let Some(ref tag) = variant.tag {
                map.insert(tag.clone(), variant.name.clone());
            }
        }
        if !map.is_empty() {
            catalog.insert(poly.name.clone(), map);
        }
    }
    catalog
}

fn candidate_converter_factory_functions<'pe, 'data>(
    pe: &'pe PeImage<'data>,
    rtti: &RttiEngine,
    candidate_variants: &BTreeSet<String>,
) -> Vec<&'pe RuntimeFunction> {
    pe.pdata
        .iter()
        .filter(|func| is_converter_factory_candidate(pe, rtti, candidate_variants, func))
        .collect()
}

fn is_converter_factory_candidate(
    pe: &PeImage,
    rtti: &RttiEngine,
    candidate_variants: &BTreeSet<String>,
    func: &RuntimeFunction,
) -> bool {
    let len = func.len();
    if len == 0 || len > MAX_FACTORY_FUNCTION_LEN {
        return false;
    }

    let Some(code) = pe.slice_at_rva(func.begin_address, len as usize) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(
        64,
        code,
        pe.image_base + func.begin_address as u64,
        DecoderOptions::NONE,
    );
    let mut saw_variant_construction = false;
    let mut saw_type_field = false;
    let mut saw_type_value = false;

    while decoder.can_decode() {
        let mut insn = Instruction::default();
        decoder.decode_out(&mut insn);

        let mem_disp = if insn.op0_kind() == OpKind::Memory && insn.memory_base() == Register::RIP {
            Some(insn.memory_displacement64())
        } else if insn.op1_kind() == OpKind::Memory && insn.memory_base() == Register::RIP {
            Some(insn.memory_displacement64())
        } else {
            None
        };

        let Some(target_va) = mem_disp else {
            continue;
        };

        if target_va < pe.image_base {
            continue;
        }
        let target_rva = (target_va - pe.image_base) as u32;

        if resolve_vtable_variant(rtti, target_rva, candidate_variants).is_some() {
            saw_variant_construction = true;
        }
        if let Some(value) = resolve_string_literal(pe, target_rva) {
            saw_type_field |= value == "_type";
            saw_type_value |= is_scream_case_discriminator_value(&value);
        }

        if saw_variant_construction && (saw_type_field || saw_type_value) {
            return true;
        }
    }

    false
}

fn scan_function_facts(
    pe: &PeImage,
    rtti: &RttiEngine,
    candidate_variants: &BTreeSet<String>,
    func: &RuntimeFunction,
) -> Option<FactoryDiscriminatorFacts> {
    let len = func.len();
    if len == 0 || len > MAX_FACTORY_FUNCTION_LEN {
        return None;
    }

    let code = pe.slice_at_rva(func.begin_address, len as usize)?;
    let mut decoder = Decoder::with_ip(
        64,
        code,
        pe.image_base + func.begin_address as u64,
        DecoderOptions::NONE,
    );
    let mut reg_state: HashMap<Register, RegValue> = HashMap::new();
    let mut facts = FactoryDiscriminatorFacts {
        function_rva: func.begin_address,
        ..FactoryDiscriminatorFacts::default()
    };
    let mut current_candidate_tag: Option<String> = None;

    while decoder.can_decode() {
        let mut insn = Instruction::default();
        decoder.decode_out(&mut insn);

        match insn.mnemonic() {
            Mnemonic::Lea => handle_lea(
                pe,
                rtti,
                candidate_variants,
                &mut reg_state,
                &mut current_candidate_tag,
                &insn,
            ),
            Mnemonic::Mov => handle_mov(
                pe,
                rtti,
                candidate_variants,
                &mut reg_state,
                &mut current_candidate_tag,
                &mut facts,
                &insn,
            ),
            Mnemonic::Xor | Mnemonic::Sub => clear_written_register(&mut reg_state, &insn),
            Mnemonic::Call => {
                record_type_assignment_from_call(&reg_state, &mut facts);
                clear_volatile_registers(&mut reg_state);
            }
            Mnemonic::Jmp | Mnemonic::Ret => {
                current_candidate_tag = None;
                clear_written_register(&mut reg_state, &insn);
            }
            _ => clear_written_register(&mut reg_state, &insn),
        }
    }

    if facts.constructed_variants.is_empty() && facts.type_assignments.is_empty() {
        None
    } else {
        Some(facts)
    }
}

fn handle_lea(
    pe: &PeImage,
    rtti: &RttiEngine,
    candidate_variants: &BTreeSet<String>,
    reg_state: &mut HashMap<Register, RegValue>,
    current_candidate_tag: &mut Option<String>,
    insn: &Instruction,
) {
    let dest = insn.op0_register().full_register();
    if insn.op1_kind() != OpKind::Memory || insn.memory_base() != Register::RIP {
        reg_state.remove(&dest);
        return;
    }

    let target_va = insn.memory_displacement64();
    if target_va < pe.image_base {
        reg_state.remove(&dest);
        return;
    }
    let target_rva = (target_va - pe.image_base) as u32;

    if let Some(variant_name) = resolve_vtable_variant(rtti, target_rva, candidate_variants) {
        reg_state.insert(dest, RegValue::VariantVtable(variant_name));
        return;
    }

    if let Some(value) = resolve_string_literal(pe, target_rva) {
        if is_scream_case_discriminator_value(&value) {
            *current_candidate_tag = Some(value.clone());
        }
        reg_state.insert(dest, RegValue::StringLiteral(value));
        return;
    }

    reg_state.remove(&dest);
}

fn handle_mov(
    pe: &PeImage,
    rtti: &RttiEngine,
    candidate_variants: &BTreeSet<String>,
    reg_state: &mut HashMap<Register, RegValue>,
    current_candidate_tag: &mut Option<String>,
    facts: &mut FactoryDiscriminatorFacts,
    insn: &Instruction,
) {
    if insn.op0_kind() == OpKind::Register {
        let dest = insn.op0_register().full_register();
        if insn.op1_kind() == OpKind::Register {
            let src = insn.op1_register().full_register();
            if let Some(value) = reg_state.get(&src).cloned() {
                reg_state.insert(dest, value);
            } else {
                reg_state.remove(&dest);
            }
        } else if insn.op1_kind() == OpKind::Memory && insn.memory_base() == Register::RIP {
            let target_va = insn.memory_displacement64();
            if target_va >= pe.image_base {
                let target_rva = (target_va - pe.image_base) as u32;
                if let Some(variant_name) =
                    resolve_vtable_variant(rtti, target_rva, candidate_variants)
                {
                    reg_state.insert(dest, RegValue::VariantVtable(variant_name));
                    return;
                }
                if let Some(value) = resolve_string_literal(pe, target_rva) {
                    if is_scream_case_discriminator_value(&value) {
                        *current_candidate_tag = Some(value.clone());
                    }
                    reg_state.insert(dest, RegValue::StringLiteral(value));
                    return;
                }
            }
            reg_state.remove(&dest);
        } else {
            reg_state.remove(&dest);
        }
        return;
    }

    if insn.op0_kind() == OpKind::Memory && insn.op1_kind() == OpKind::Register {
        let src = insn.op1_register().full_register();
        if let Some(RegValue::VariantVtable(variant_name)) = reg_state.get(&src).cloned() {
            if is_object_memory_store(insn) {
                facts.constructed_variants.insert(variant_name.clone());
                let object_reg = insn.memory_base().full_register();
                if object_reg != Register::None && object_reg != Register::RIP {
                    reg_state.insert(object_reg, RegValue::ConstructedVariant(variant_name.clone()));
                }
                if let Some(tag) = current_candidate_tag.take() {
                    facts.type_assignments.insert(tag.clone());
                    facts
                        .direct_type_assignments
                        .entry(variant_name)
                        .or_default()
                        .insert(tag);
                }
            }
        }
    }
}

fn record_type_assignment_from_call(
    reg_state: &HashMap<Register, RegValue>,
    facts: &mut FactoryDiscriminatorFacts,
) {
    let args = [Register::RCX, Register::RDX, Register::R8, Register::R9]
        .iter()
        .filter_map(|reg| match reg_state.get(reg) {
            Some(RegValue::StringLiteral(value)) => Some(value.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let constructed_args = [Register::RCX, Register::RDX, Register::R8, Register::R9]
        .iter()
        .filter_map(|reg| match reg_state.get(reg) {
            Some(RegValue::ConstructedVariant(variant_name)) => Some(variant_name.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();

    if !args.iter().any(|value| *value == "_type") {
        return;
    }

    let values = args
        .iter()
        .copied()
        .filter(|value| is_scream_case_discriminator_value(value))
        .collect::<BTreeSet<_>>();
    if values.len() == 1 {
        let value = values
            .into_iter()
            .next()
            .expect("single assignment")
            .to_string();
        facts.type_assignments.insert(value.clone());
        if constructed_args.len() == 1 {
            let variant_name = constructed_args
                .into_iter()
                .next()
                .expect("single constructed variant arg")
                .to_string();
            facts
                .direct_type_assignments
                .entry(variant_name)
                .or_default()
                .insert(value);
        }
    } else {
        facts.ambiguous_type_assignment = true;
    }
}

fn is_object_memory_store(insn: &Instruction) -> bool {
    let base = insn.memory_base();
    base != Register::None && base != Register::RIP
}

fn clear_written_register(reg_state: &mut HashMap<Register, RegValue>, insn: &Instruction) {
    if insn.op0_kind() == OpKind::Register {
        let dest = insn.op0_register().full_register();
        reg_state.remove(&dest);
    }
}

fn clear_volatile_registers(reg_state: &mut HashMap<Register, RegValue>) {
    for reg in X64_VOLATILE_REGISTERS {
        reg_state.remove(&reg);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RegValue {
    VariantVtable(String),
    ConstructedVariant(String),
    StringLiteral(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(
        function_rva: u32,
        constructed_variants: &[&str],
        type_assignments: &[&str],
    ) -> FactoryDiscriminatorFacts {
        let direct_type_assignments =
            if constructed_variants.len() == 1 && type_assignments.len() == 1 {
                [(
                    constructed_variants[0].to_string(),
                    [type_assignments[0].to_string()].into_iter().collect(),
                )]
                .into_iter()
                .collect()
            } else {
                BTreeMap::new()
            };

        FactoryDiscriminatorFacts {
            function_rva,
            constructed_variants: constructed_variants
                .iter()
                .map(|value| value.to_string())
                .collect(),
            type_assignments: type_assignments
                .iter()
                .map(|value| value.to_string())
                .collect(),
            direct_type_assignments,
            ambiguous_type_assignment: false,
        }
    }

    #[test]
    fn direct_factory_evidence_maps_variant_to_discriminator_value() {
        let photo = "Api::OneMe::Types::PhotoAttachment";
        let evidence = evidence_from_factory_facts(&[facts(0x1000, &[photo], &["PHOTO"])]);
        let values = values_from_evidence(&evidence);

        assert_eq!(values.get(photo).map(String::as_str), Some("PHOTO"));
    }

    #[test]
    fn ambiguous_factory_evidence_is_not_emitted() {
        let photo = "Api::OneMe::Types::PhotoAttachment";
        let video = "Api::OneMe::Types::VideoAttachment";
        assert!(
            evidence_from_factory_facts(&[facts(0x1000, &[photo, video], &["PHOTO"])]).is_empty()
        );
        assert!(
            evidence_from_factory_facts(&[facts(0x1000, &[photo], &["PHOTO", "VIDEO"])]).is_empty()
        );

        let mut ambiguous = facts(0x1000, &[photo], &["PHOTO"]);
        ambiguous.ambiguous_type_assignment = true;
        assert!(evidence_from_factory_facts(&[ambiguous]).is_empty());
    }

    #[test]
    fn missing_factory_evidence_is_not_emitted() {
        let photo = "Api::OneMe::Types::PhotoAttachment";

        assert!(evidence_from_factory_facts(&[facts(0x1000, &[photo], &[])]).is_empty());
        assert!(evidence_from_factory_facts(&[facts(0x1000, &[], &["PHOTO"])]).is_empty());
    }

    #[test]
    fn conflicting_values_for_same_variant_are_omitted() {
        let photo = "Api::OneMe::Types::PhotoAttachment";
        let evidence = evidence_from_factory_facts(&[
            facts(0x1000, &[photo], &["PHOTO"]),
            facts(0x2000, &[photo], &["VIDEO"]),
        ]);
        let values = values_from_evidence(&evidence);

        assert!(!values.contains_key(photo));
    }

    #[test]
    fn diagnostics_report_evidence_and_extraction_misses() {
        let photo = "Api::OneMe::Types::PhotoAttachment";
        let video = "Api::OneMe::Types::VideoAttachment";
        let candidate_variants = [photo.to_string(), video.to_string()]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let facts = vec![
            facts(0x1000, &[photo], &["PHOTO"]),
            facts(0x2000, &[video], &[]),
        ];
        let evidence = evidence_from_factory_facts(&facts);
        let values = values_from_evidence(&evidence);

        let diagnostics = diagnostics_from_scan(&candidate_variants, &facts, &evidence, &values);

        assert_eq!(diagnostics.evidence.len(), 1);
        assert_eq!(diagnostics.evidence[0].variant_name, photo);
        assert_eq!(diagnostics.evidence[0].value, "PHOTO");
        assert!(diagnostics.misses.iter().any(|miss| {
            miss.variant_name.as_deref() == Some(video)
                && miss.function_rva.as_deref() == Some("0x2000")
                && miss.reason == "no _type assignment observed"
        }));
    }

    #[test]
    fn diagnostics_report_conflicting_discriminator_values_as_miss() {
        let photo = "Api::OneMe::Types::PhotoAttachment";
        let candidate_variants = [photo.to_string()].into_iter().collect::<BTreeSet<_>>();
        let evidence = evidence_from_factory_facts(&[
            facts(0x1000, &[photo], &["PHOTO"]),
            facts(0x2000, &[photo], &["VIDEO"]),
        ]);
        let values = values_from_evidence(&evidence);

        let diagnostics = diagnostics_from_scan(&candidate_variants, &[], &evidence, &values);

        assert!(diagnostics.misses.iter().any(|miss| {
            miss.variant_name.as_deref() == Some(photo)
                && miss.reason == "conflicting discriminator values: PHOTO, VIDEO"
                && miss.type_assignments == vec!["PHOTO", "VIDEO"]
        }));
    }

    #[test]
    fn non_scream_case_values_are_not_evidence() {
        let photo = "Api::OneMe::Types::PhotoAttachment";

        assert!(evidence_from_factory_facts(&[facts(0x1000, &[photo], &["Photo"])]).is_empty());
        assert!(!is_scream_case_discriminator_value("_type"));
        assert!(is_scream_case_discriminator_value("VIDEO_NOTE"));
    }

    #[test]
    fn test_strip_ref_count_obj2_variants() {
        assert_eq!(
            strip_ref_count_obj2("std::_Ref_count_obj2<struct Api::OneMe::Types::PhotoAttachment>"),
            Some("Api::OneMe::Types::PhotoAttachment")
        );
        assert_eq!(
            strip_ref_count_obj2("class std::_Ref_count_obj2<struct Api::OneMe::Types::VideoAttachment>"),
            Some("Api::OneMe::Types::VideoAttachment")
        );
        assert_eq!(
            strip_ref_count_obj2("_Ref_count_obj2<class Api::OneMe::Types::AudioAttachment>"),
            Some("Api::OneMe::Types::AudioAttachment")
        );
        assert_eq!(
            strip_ref_count_obj2("std::_Ref_count_obj2<Api::OneMe::Types::FileAttachment >"),
            Some("Api::OneMe::Types::FileAttachment")
        );
        assert_eq!(
            strip_ref_count_obj2("Api::OneMe::Types::PhotoAttachment"),
            None
        );
    }

    #[test]
    fn test_match_candidate_variant() {
        let mut candidates = BTreeSet::new();
        candidates.insert("Api::OneMe::Types::PhotoAttachment".to_string());
        candidates.insert("Api::OneMe::Types::VideoAttachment".to_string());

        // Direct match
        assert_eq!(
            match_candidate_variant("Api::OneMe::Types::PhotoAttachment", &candidates).as_deref(),
            Some("Api::OneMe::Types::PhotoAttachment")
        );

        // Wrapped in std::_Ref_count_obj2
        assert_eq!(
            match_candidate_variant(
                "std::_Ref_count_obj2<struct Api::OneMe::Types::PhotoAttachment>",
                &candidates
            )
            .as_deref(),
            Some("Api::OneMe::Types::PhotoAttachment")
        );

        // Unknown type
        assert_eq!(
            match_candidate_variant(
                "std::_Ref_count_obj2<struct Api::OneMe::Types::UnknownAttachment>",
                &candidates
            ),
            None
        );
    }

    #[test]
    fn test_build_discriminator_catalog_lexicographical_sorting() {
        use crate::dumper::{PolymorphicBase, PolymorphicModelEntry, PolymorphicVariant};

        let make_variant = |name: &str, tag: Option<&str>| PolymorphicVariant {
            name: name.to_string(),
            offset: None,
            fields: Vec::new(),
            all_fields: Vec::new(),
            tag: tag.map(str::to_string),
        };

        let models = vec![
            PolymorphicModelEntry {
                name: "BaseB".to_string(),
                root_sources: vec!["protocol_field".to_string()],
                discriminator: None,
                base: PolymorphicBase {
                    offset: None,
                    fields: Vec::new(),
                },
                variants: vec![
                    make_variant("VariantZ", Some("ZETA")),
                    make_variant("VariantA", Some("ALPHA")),
                ],
                rtti_subclasses: Vec::new(),
            },
            PolymorphicModelEntry {
                name: "BaseA".to_string(),
                root_sources: vec!["protocol_field".to_string()],
                discriminator: None,
                base: PolymorphicBase {
                    offset: None,
                    fields: Vec::new(),
                },
                variants: vec![
                    make_variant("VariantPhoto", Some("PHOTO")),
                    make_variant("VariantVideo", Some("VIDEO")),
                    make_variant("VariantNoTag", None),
                ],
                rtti_subclasses: Vec::new(),
            },
            PolymorphicModelEntry {
                name: "BaseEmpty".to_string(),
                root_sources: vec!["rtti_heuristic".to_string()],
                discriminator: None,
                base: PolymorphicBase {
                    offset: None,
                    fields: Vec::new(),
                },
                variants: Vec::new(),
                rtti_subclasses: vec![make_variant("EmptyVariant", None)],
            },
        ];

        let catalog = build_discriminator_catalog(&models);

        // BaseEmpty has no tags, so it must not be present
        assert_eq!(catalog.len(), 2);
        assert!(catalog.contains_key("BaseA"));
        assert!(catalog.contains_key("BaseB"));
        assert!(!catalog.contains_key("BaseEmpty"));

        let base_a = &catalog["BaseA"];
        assert_eq!(base_a.len(), 2);
        let tags_a: Vec<&str> = base_a.keys().map(String::as_str).collect();
        assert_eq!(tags_a, vec!["PHOTO", "VIDEO"]);
        assert_eq!(base_a["PHOTO"], "VariantPhoto");
        assert_eq!(base_a["VIDEO"], "VariantVideo");

        let base_b = &catalog["BaseB"];
        assert_eq!(base_b.len(), 2);
        let tags_b: Vec<&str> = base_b.keys().map(String::as_str).collect();
        assert_eq!(tags_b, vec!["ALPHA", "ZETA"]);
    }

    #[test]
    fn test_max_factory_function_len_is_at_least_4096() {
        assert!(MAX_FACTORY_FUNCTION_LEN >= 4096);
    }
}
