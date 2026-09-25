use crate::extractor::{
    contains_serializable_member_refs, is_dispatch_function, ExtractedField, FieldCandidate,
    FieldExtractor, VtableXrefIndex,
};
use crate::pe::PeImage;
use crate::rtti::{clean_demangled_rtti_name, RttiEngine};
use crate::type_parser::DecomposedType;
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};

pub trait ModelResolutionSource {
    fn vtable_rva_for_type(&self, type_name: &str) -> Option<u32>;
    fn functions_for_vtable(&self, vtable_rva: u32) -> Vec<u32>;
    fn function_len(&self, func_rva: u32) -> u32;
    fn is_qualified_initializer(&self, func_rva: u32) -> bool;
    fn extract_fields(&mut self, func_rva: u32) -> Result<Vec<FieldCandidate>, String>;

    fn function_initializes_model(&self, type_name: &str, func_rva: u32) -> bool {
        self.vtable_rva_for_type(type_name)
            .map(|vtable_rva| self.functions_for_vtable(vtable_rva).contains(&func_rva))
            .unwrap_or(false)
    }

    fn owner_is_base_of_model(&self, _owner_type: &str, _model_type: &str) -> bool {
        false
    }

    fn base_models_of(&self, _model_type: &str) -> Vec<String> {
        Vec::new()
    }
}

pub struct PeModelResolutionSource<'a> {
    extractor: FieldExtractor<'a>,
    xref_index: VtableXrefIndex,
}

impl<'a> PeModelResolutionSource<'a> {
    pub fn new(pe: &'a PeImage<'a>, rtti: &'a RttiEngine) -> Self {
        Self {
            extractor: FieldExtractor::new(pe, rtti),
            xref_index: VtableXrefIndex::build(pe, rtti),
        }
    }
}

impl ModelResolutionSource for PeModelResolutionSource<'_> {
    fn vtable_rva_for_type(&self, type_name: &str) -> Option<u32> {
        self.extractor.rtti.type_to_vtable.get(type_name).copied()
    }

    fn functions_for_vtable(&self, vtable_rva: u32) -> Vec<u32> {
        self.xref_index
            .vtable_to_funcs
            .get(&vtable_rva)
            .cloned()
            .unwrap_or_default()
    }

    fn function_len(&self, func_rva: u32) -> u32 {
        self.extractor
            .pe
            .find_function(func_rva)
            .map(|func| func.len())
            .unwrap_or(u32::MAX)
    }

    fn is_qualified_initializer(&self, func_rva: u32) -> bool {
        !is_dispatch_function(self.extractor.pe, func_rva)
            && contains_serializable_member_refs(self.extractor.pe, self.extractor.rtti, func_rva)
    }

    fn extract_fields(&mut self, func_rva: u32) -> Result<Vec<FieldCandidate>, String> {
        self.extractor
            .extract_candidates_from_func(func_rva)
            .map_err(|err| err.to_string())
    }

    fn owner_is_base_of_model(&self, owner_type: &str, model_type: &str) -> bool {
        self.extractor
            .rtti
            .hierarchy
            .is_base_of(owner_type, model_type)
    }

    fn base_models_of(&self, model_type: &str) -> Vec<String> {
        self.extractor
            .rtti
            .hierarchy
            .bases_of(model_type)
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedModel {
    pub name: String,
    pub offset: Option<String>,
    pub fields: Vec<ExtractedField>,
    pub warn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelResolverDiagnosticKind {
    RejectedField,
    RejectedInitializerCandidate,
    ConflictingInitializerCandidates,
    ExtractorError,
    NoInitializer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelResolverDiagnostic {
    pub model_name: String,
    pub function_rva: Option<u32>,
    pub kind: ModelResolverDiagnosticKind,
    pub message: String,
}

pub struct ModelResolver<S> {
    source: S,
    cache: HashMap<String, ResolvedModel>,
    diagnostics: Vec<ModelResolverDiagnostic>,
    in_progress: HashSet<String>,
}

impl<S: ModelResolutionSource> ModelResolver<S> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            cache: HashMap::new(),
            diagnostics: Vec::new(),
            in_progress: HashSet::new(),
        }
    }

    pub fn resolve_model(&mut self, type_name: &str) -> ResolvedModel {
        if let Some(cached) = self.cache.get(type_name) {
            return cached.clone();
        }

        if !self.in_progress.insert(type_name.to_string()) {
            return no_data_model(type_name, None, warn_for_no_data(type_name));
        }

        let resolved = self.resolve_uncached(type_name);
        self.in_progress.remove(type_name);
        self.cache.insert(type_name.to_string(), resolved.clone());
        resolved
    }

    pub fn diagnostics(&self) -> &[ModelResolverDiagnostic] {
        &self.diagnostics
    }

    fn resolve_uncached(&mut self, type_name: &str) -> ResolvedModel {
        if is_empty_model_type_name(type_name) {
            return no_data_model(type_name, None, None);
        }

        let Some(vtable_rva) = self.source.vtable_rva_for_type(type_name) else {
            self.diagnostics.push(ModelResolverDiagnostic {
                model_name: type_name.to_string(),
                function_rva: None,
                kind: ModelResolverDiagnosticKind::NoInitializer,
                message: "no vtable found for model".to_string(),
            });
            return no_data_model(type_name, None, warn_for_no_data(type_name));
        };

        let funcs = self.source.functions_for_vtable(vtable_rva);
        if funcs.is_empty() {
            self.diagnostics.push(ModelResolverDiagnostic {
                model_name: type_name.to_string(),
                function_rva: None,
                kind: ModelResolverDiagnosticKind::NoInitializer,
                message: format!("no initializer candidates found for vtable 0x{vtable_rva:x}"),
            });
            return no_data_model(type_name, None, warn_for_no_data(type_name));
        }

        let qualified_funcs: Vec<u32> = funcs
            .iter()
            .copied()
            .filter(|&func_rva| self.source.is_qualified_initializer(func_rva))
            .collect();
        let eval_funcs = if qualified_funcs.is_empty() {
            funcs
        } else {
            qualified_funcs
        };

        let mut evaluated = Vec::new();
        for func_rva in eval_funcs {
            let function_len = self.source.function_len(func_rva);
            match self.source.extract_fields(func_rva) {
                Ok(fields) => {
                    let candidate =
                        evaluate_candidate(&self.source, type_name, func_rva, function_len, fields);
                    for rejected in &candidate.rejected_fields {
                        self.diagnostics.push(ModelResolverDiagnostic {
                            model_name: type_name.to_string(),
                            function_rva: Some(func_rva),
                            kind: ModelResolverDiagnosticKind::RejectedField,
                            message: format!(
                                "rejected field '{}' owned by {:?}: {}",
                                rejected.name,
                                rejected.owner_type,
                                rejected
                                    .rejection_reason
                                    .as_deref()
                                    .unwrap_or("owner mismatch")
                            ),
                        });
                    }
                    evaluated.push(candidate);
                }
                Err(message) => self.diagnostics.push(ModelResolverDiagnostic {
                    model_name: type_name.to_string(),
                    function_rva: Some(func_rva),
                    kind: ModelResolverDiagnosticKind::ExtractorError,
                    message,
                }),
            }
        }

        let Some(selected) = select_best_candidate(type_name, &evaluated, &mut self.diagnostics)
        else {
            return no_data_model(type_name, None, warn_for_no_data(type_name));
        };

        let selected_function_rva = selected.function_rva;
        let fields = selected.accepted_fields.clone();
        for candidate in evaluated
            .iter()
            .filter(|candidate| candidate.function_rva != selected_function_rva)
        {
            self.diagnostics.push(ModelResolverDiagnostic {
                model_name: type_name.to_string(),
                function_rva: Some(candidate.function_rva),
                kind: ModelResolverDiagnosticKind::RejectedInitializerCandidate,
                message: format!(
                    "rejected initializer candidate; selected 0x{selected_function_rva:x}; owner_rank={}, accepted_fields={}, rejected_fields={}",
                    candidate.score.owner_rank,
                    candidate.accepted_fields.len(),
                    candidate.rejected_fields.len()
                ),
            });
        }
        let warn = if fields.is_empty() {
            if self.has_non_empty_base_fields(type_name) {
                None
            } else {
                warn_for_no_data(type_name)
            }
        } else {
            None
        };

        ResolvedModel {
            name: type_name.to_string(),
            offset: Some(format!("0x{:x}", selected_function_rva)),
            warn,
            fields,
        }
    }

    fn has_non_empty_base_fields(&mut self, type_name: &str) -> bool {
        let base_names = self.source.base_models_of(type_name);
        for base_name in base_names {
            if base_name == type_name || self.in_progress.contains(&base_name) {
                continue;
            }
            if self.source.vtable_rva_for_type(&base_name).is_none() {
                continue;
            }
            let base_model = self.resolve_model(&base_name);
            if !base_model.fields.is_empty() {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone)]
struct EvaluatedCandidate {
    function_rva: u32,
    function_len: u32,
    accepted_fields: Vec<ExtractedField>,
    rejected_fields: Vec<FieldCandidate>,
    score: CandidateSemanticScore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CandidateSemanticScore {
    owner_rank: u8,
    accepted_field_count: usize,
    rejected_field_count: Reverse<usize>,
}

fn evaluate_candidate<S: ModelResolutionSource>(
    source: &S,
    model_name: &str,
    function_rva: u32,
    function_len: u32,
    fields: Vec<FieldCandidate>,
) -> EvaluatedCandidate {
    let mut accepted_fields: Vec<ExtractedField> = Vec::new();
    let mut field_indices: HashMap<String, (usize, bool)> = HashMap::new();
    let mut rejected_fields = Vec::new();
    let mut direct_owner_count = 0;
    let mut proven_helper_count = 0;
    let mut unknown_owner_count = 0;

    for mut candidate in fields.clone() {
        match owner_acceptance(source, model_name, &candidate, &fields) {
            OwnerAcceptance::Direct => {
                direct_owner_count += 1;
                if let Some((idx, is_direct)) = field_indices.get_mut(&candidate.name) {
                    if !*is_direct {
                        *is_direct = true;
                        accepted_fields[*idx] = candidate.into_field();
                    }
                } else {
                    let idx = accepted_fields.len();
                    field_indices.insert(candidate.name.clone(), (idx, true));
                    accepted_fields.push(candidate.into_field());
                }
            }
            OwnerAcceptance::ProvenHelper => {
                proven_helper_count += 1;
                if !field_indices.contains_key(&candidate.name) {
                    let idx = accepted_fields.len();
                    field_indices.insert(candidate.name.clone(), (idx, false));
                    accepted_fields.push(candidate.into_field());
                }
            }
            OwnerAcceptance::Unknown => {
                unknown_owner_count += 1;
                if !field_indices.contains_key(&candidate.name) {
                    let idx = accepted_fields.len();
                    field_indices.insert(candidate.name.clone(), (idx, false));
                    accepted_fields.push(candidate.into_field());
                }
            }
            OwnerAcceptance::Mismatch(reason) => {
                candidate.rejection_reason = Some(reason);
                rejected_fields.push(candidate);
            }
        }
    }

    let owner_rank = if direct_owner_count > 0 {
        3
    } else if proven_helper_count > 0 {
        2
    } else if unknown_owner_count > 0 {
        1
    } else {
        0
    };

    EvaluatedCandidate {
        function_rva,
        function_len,
        score: CandidateSemanticScore {
            owner_rank,
            accepted_field_count: accepted_fields.len(),
            rejected_field_count: Reverse(rejected_fields.len()),
        },
        accepted_fields,
        rejected_fields,
    }
}

fn select_best_candidate<'a>(
    model_name: &str,
    candidates: &'a [EvaluatedCandidate],
    diagnostics: &mut Vec<ModelResolverDiagnostic>,
) -> Option<&'a EvaluatedCandidate> {
    let top_score = candidates.iter().map(|candidate| candidate.score).max()?;
    let mut top_candidates: Vec<&EvaluatedCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.score == top_score)
        .collect();

    if top_candidates.len() > 1 && has_conflicting_field_sets(&top_candidates) {
        let rvas = top_candidates
            .iter()
            .map(|candidate| format!("0x{:x}", candidate.function_rva))
            .collect::<Vec<_>>()
            .join(", ");
        diagnostics.push(ModelResolverDiagnostic {
            model_name: model_name.to_string(),
            function_rva: None,
            kind: ModelResolverDiagnosticKind::ConflictingInitializerCandidates,
            message: format!("initializer candidates tie after semantic scoring: {rvas}"),
        });
    }

    top_candidates.sort_by_key(|candidate| (candidate.function_len, candidate.function_rva));
    top_candidates.into_iter().next()
}

fn has_conflicting_field_sets(candidates: &[&EvaluatedCandidate]) -> bool {
    let Some(first) = candidates.first() else {
        return false;
    };
    let first_fields = field_signature(&first.accepted_fields);
    candidates
        .iter()
        .skip(1)
        .any(|candidate| field_signature(&candidate.accepted_fields) != first_fields)
}

fn field_signature(fields: &[ExtractedField]) -> Vec<(&str, &str)> {
    fields
        .iter()
        .map(|field| (field.name.as_str(), field.field_type.full.as_str()))
        .collect()
}

enum OwnerAcceptance {
    Direct,
    ProvenHelper,
    Unknown,
    Mismatch(String),
}

fn owner_acceptance<S: ModelResolutionSource>(
    source: &S,
    model_name: &str,
    candidate: &FieldCandidate,
    all_fields: &[FieldCandidate],
) -> OwnerAcceptance {
    if let Some(reason) = non_field_string_rejection(candidate) {
        return OwnerAcceptance::Mismatch(reason);
    }

    let Some(owner) = candidate.owner_type.as_deref() else {
        return OwnerAcceptance::Unknown;
    };
    if owner == model_name {
        return OwnerAcceptance::Direct;
    }
    if has_base_initializer_proof(
        source,
        model_name,
        owner,
        candidate.function_rva,
    ) {
        return OwnerAcceptance::ProvenHelper;
    }
    if has_helper_initializer_proof(
        source,
        model_name,
        owner,
        candidate.function_rva,
        all_fields,
    ) {
        return OwnerAcceptance::ProvenHelper;
    }
    if has_nested_helper_proof(model_name, owner, all_fields) {
        return OwnerAcceptance::ProvenHelper;
    }
    OwnerAcceptance::Mismatch(format!(
        "owner '{owner}' does not match model '{model_name}'"
    ))
}

fn non_field_string_rejection(candidate: &FieldCandidate) -> Option<String> {
    let lower_name_source = candidate.name_source.to_ascii_lowercase();
    if lower_name_source.contains("converter") || lower_name_source.contains("logging") {
        return Some("field name came from converter/logging string evidence".to_string());
    }

    if looks_like_converter_or_logging_type_name(&candidate.name) {
        return Some(format!(
            "field name '{}' looks like converter/logging string evidence",
            candidate.name
        ));
    }

    None
}

fn looks_like_converter_or_logging_type_name(name: &str) -> bool {
    const NON_FIELD_SUFFIXES: [&str; 5] = [
        "Converter",
        "Logger",
        "Factory",
        "Serializer",
        "Deserializer",
    ];

    let Some(first) = name.as_bytes().first() else {
        return false;
    };
    first.is_ascii_uppercase()
        && NON_FIELD_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

fn has_base_initializer_proof<S: ModelResolutionSource>(
    source: &S,
    model_name: &str,
    owner: &str,
    func_rva: u32,
) -> bool {
    (source.owner_is_base_of_model(owner, model_name)
        || is_crtp_base_parameter(source, model_name, owner))
        && source.function_initializes_model(model_name, func_rva)
}

fn is_crtp_base_parameter<S: ModelResolutionSource>(
    source: &S,
    model_name: &str,
    owner: &str,
) -> bool {
    source
        .base_models_of(model_name)
        .iter()
        .any(|base| base_has_template_argument(base, owner))
}

fn base_has_template_argument(base: &str, owner: &str) -> bool {
    let Some(start) = base.find('<') else {
        return false;
    };
    let Some(end) = base.rfind('>') else {
        return false;
    };
    if end <= start {
        return false;
    }
    let inner = &base[start + 1..end];
    let mut depth = 0;
    let mut arg_start = 0;

    for (i, c) in inner.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            ',' if depth == 0 => {
                if clean_demangled_rtti_name(&inner[arg_start..i]) == owner {
                    return true;
                }
                arg_start = i + 1;
            }
            _ => {}
        }
    }

    if arg_start < inner.len() && clean_demangled_rtti_name(&inner[arg_start..]) == owner {
        return true;
    }

    false
}

fn has_helper_initializer_proof<S: ModelResolutionSource>(
    source: &S,
    model_name: &str,
    owner: &str,
    func_rva: u32,
    fields: &[FieldCandidate],
) -> bool {
    let Some(model_parent) = namespace_parent(model_name) else {
        return false;
    };
    let Some(owner_parent) = namespace_parent(owner) else {
        return false;
    };

    source.function_initializes_model(model_name, func_rva)
        && model_parent == owner_parent
        && model_parent.split("::").count() >= 4
        && coherent_helper_fields(owner, func_rva, fields)
        && fields
            .iter()
            .any(|field| helper_field_type_has_api_reference(&field.field_type, model_name, owner))
}

fn coherent_helper_fields(owner: &str, func_rva: u32, fields: &[FieldCandidate]) -> bool {
    !fields.is_empty()
        && fields.iter().all(|field| {
            field.function_rva == func_rva && field.owner_type.as_deref() == Some(owner)
        })
}

fn namespace_parent(type_name: &str) -> Option<&str> {
    type_name.rsplit_once("::").map(|(parent, _)| parent)
}

fn helper_field_type_has_api_reference(
    field_type: &DecomposedType,
    model_name: &str,
    owner: &str,
) -> bool {
    [
        field_type.full.as_str(),
        field_type.name.as_deref().unwrap_or(""),
        field_type.map_key.as_deref().unwrap_or(""),
        field_type.map_value.as_deref().unwrap_or(""),
        field_type.polymorphic_base.as_deref().unwrap_or(""),
    ]
    .into_iter()
    .any(|type_name| {
        type_name.contains("Api::OneMe::")
            && !type_name.contains(model_name)
            && !type_name.contains(owner)
    })
}

fn has_nested_helper_proof(
    model_name: &str,
    nested_owner: &str,
    fields: &[FieldCandidate],
) -> bool {
    fields.iter().any(|field| {
        field.owner_type.as_deref() == Some(model_name)
            && field_type_references_model(&field.field_type, nested_owner)
    })
}

fn field_type_references_model(field_type: &DecomposedType, model_name: &str) -> bool {
    field_type.name.as_deref() == Some(model_name)
        || field_type.map_key.as_deref() == Some(model_name)
        || field_type.map_value.as_deref() == Some(model_name)
        || field_type.polymorphic_base.as_deref() == Some(model_name)
        || field_type.full.contains(model_name)
}

fn no_data_model(type_name: &str, offset: Option<String>, warn: Option<String>) -> ResolvedModel {
    ResolvedModel {
        name: type_name.to_string(),
        offset,
        fields: Vec::new(),
        warn,
    }
}

fn warn_for_no_data(type_name: &str) -> Option<String> {
    if type_name.contains("Polymorphic") {
        None
    } else {
        Some("no data found".to_string())
    }
}

pub fn is_empty_model_type_name(name: &str) -> bool {
    let kind = name.rsplit("::").next().unwrap_or(name);
    matches!(
        kind,
        "EmptyResponse" | "EmptyParameters" | "NoParameters" | "EmptyData"
    )
}
