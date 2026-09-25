use crate::msvc::X64_VOLATILE_REGISTERS;
use crate::pe::{PeImage, RuntimeFunction};
use crate::rtti::RttiEngine;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const MAX_FACTORY_FUNCTION_LEN: u32 = 2048;

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

fn is_scream_case_discriminator_value(value: &str) -> bool {
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
        if insn.mnemonic() != Mnemonic::Lea
            || insn.op1_kind() != OpKind::Memory
            || insn.memory_base() != Register::RIP
        {
            continue;
        }

        let target_va = insn.memory_displacement64();
        if target_va < pe.image_base {
            continue;
        }
        let target_rva = (target_va - pe.image_base) as u32;
        if rtti
            .vtable_to_type
            .get(&target_rva)
            .is_some_and(|type_name| candidate_variants.contains(type_name))
        {
            saw_variant_construction = true;
        }
        if let Some(value) = pe.read_cstring(target_rva) {
            saw_type_field |= value == "_type";
            saw_type_value |= is_scream_case_discriminator_value(value);
        }

        if saw_variant_construction && saw_type_field && saw_type_value {
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

    while decoder.can_decode() {
        let mut insn = Instruction::default();
        decoder.decode_out(&mut insn);

        match insn.mnemonic() {
            Mnemonic::Lea => handle_lea(pe, rtti, candidate_variants, &mut reg_state, &insn),
            Mnemonic::Mov => handle_mov(&mut reg_state, &mut facts, &insn),
            Mnemonic::Xor | Mnemonic::Sub => clear_written_register(&mut reg_state, &insn),
            Mnemonic::Call => {
                record_type_assignment_from_call(&reg_state, &mut facts);
                clear_volatile_registers(&mut reg_state);
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

    if let Some(type_name) = rtti.vtable_to_type.get(&target_rva) {
        if candidate_variants.contains(type_name) {
            reg_state.insert(dest, RegValue::VariantVtable(type_name.clone()));
            return;
        }
    }

    if let Some(value) = pe.read_cstring(target_rva) {
        if value == "_type" || is_scream_case_discriminator_value(value) {
            reg_state.insert(dest, RegValue::StringLiteral(value.to_string()));
            return;
        }
    }

    reg_state.remove(&dest);
}

fn handle_mov(
    reg_state: &mut HashMap<Register, RegValue>,
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
                    reg_state.insert(object_reg, RegValue::ConstructedVariant(variant_name));
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
}
