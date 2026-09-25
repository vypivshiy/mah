use dumper_rust::extractor::FieldCandidate;
use dumper_rust::model_resolver::{
    ModelResolutionSource, ModelResolver, ModelResolverDiagnosticKind,
};
use dumper_rust::rtti::ClassHierarchy;
use dumper_rust::type_parser::decompose_type;
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

#[derive(Clone, Default)]
struct FakeSource {
    vtables: HashMap<String, u32>,
    funcs: HashMap<u32, Vec<u32>>,
    lengths: HashMap<u32, u32>,
    fields: HashMap<u32, Vec<FieldCandidate>>,
    qualified: HashSet<u32>,
    hierarchy: ClassHierarchy,
    extraction_count: Rc<Cell<usize>>,
}

impl FakeSource {
    fn with_model(mut self, model: &str, vtable_rva: u32, funcs: Vec<u32>) -> Self {
        self.vtables.insert(model.to_string(), vtable_rva);
        self.funcs.insert(vtable_rva, funcs);
        self
    }

    fn with_func(mut self, func_rva: u32, len: u32, fields: Vec<FieldCandidate>) -> Self {
        self.lengths.insert(func_rva, len);
        self.fields.insert(func_rva, fields);
        self.qualified.insert(func_rva);
        self
    }

    fn with_base_relation(mut self, base: &str, derived: &str) -> Self {
        self.hierarchy
            .base_to_derived
            .entry(base.to_string())
            .or_default()
            .push(derived.to_string());
        self
    }

    fn extraction_count(&self) -> Rc<Cell<usize>> {
        Rc::clone(&self.extraction_count)
    }
}

impl ModelResolutionSource for FakeSource {
    fn vtable_rva_for_type(&self, type_name: &str) -> Option<u32> {
        self.vtables.get(type_name).copied()
    }

    fn functions_for_vtable(&self, vtable_rva: u32) -> Vec<u32> {
        self.funcs.get(&vtable_rva).cloned().unwrap_or_default()
    }

    fn function_len(&self, func_rva: u32) -> u32 {
        self.lengths.get(&func_rva).copied().unwrap_or(u32::MAX)
    }

    fn is_qualified_initializer(&self, func_rva: u32) -> bool {
        self.qualified.contains(&func_rva)
    }

    fn extract_fields(&mut self, func_rva: u32) -> Result<Vec<FieldCandidate>, String> {
        self.extraction_count.set(self.extraction_count.get() + 1);
        Ok(self.fields.get(&func_rva).cloned().unwrap_or_default())
    }

    fn owner_is_base_of_model(&self, owner_type: &str, model_type: &str) -> bool {
        self.hierarchy.is_base_of(owner_type, model_type)
    }

    fn base_models_of(&self, model_type: &str) -> Vec<String> {
        self.hierarchy.bases_of(model_type)
    }
}

fn field(name: &str, type_name: &str, owner: Option<&str>, function_rva: u32) -> FieldCandidate {
    field_with_sources(name, type_name, owner, function_rva, "test", "test")
}

fn field_with_sources(
    name: &str,
    type_name: &str,
    owner: Option<&str>,
    function_rva: u32,
    name_source: &str,
    type_source: &str,
) -> FieldCandidate {
    FieldCandidate {
        name: name.to_string(),
        field_type: decompose_type(type_name),
        required: false,
        owner_type: owner.map(str::to_string),
        function_rva,
        name_source: name_source.to_string(),
        type_source: type_source.to_string(),
        rejection_reason: None,
    }
}

#[test]
fn resolver_prefers_owner_match_before_field_count() {
    let target = "Api::OneMe::Types::Target";
    let wrong_owner = "Api::OneMe::Types::WrongOwner";
    let source = FakeSource::default()
        .with_model(target, 0x10, vec![0x100, 0x200])
        .with_func(
            0x100,
            100,
            vec![field("correct", "std::string", Some(target), 0x100)],
        )
        .with_func(
            0x200,
            10,
            vec![
                field("wrong1", "std::string", Some(wrong_owner), 0x200),
                field("wrong2", "int", Some(wrong_owner), 0x200),
                field("wrong3", "bool", Some(wrong_owner), 0x200),
            ],
        );

    let mut resolver = ModelResolver::new(source);
    let resolved = resolver.resolve_model(target);

    assert_eq!(resolved.offset.as_deref(), Some("0x100"));
    assert_eq!(
        resolved
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        vec!["correct"]
    );
    assert!(resolver
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.kind == ModelResolverDiagnosticKind::RejectedField));
    assert!(resolver.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind == ModelResolverDiagnosticKind::RejectedInitializerCandidate
            && diagnostic.function_rva == Some(0x200)
    }));
}

#[test]
fn resolver_caches_resolved_models() {
    let target = "Api::OneMe::Types::Cached";
    let source = FakeSource::default()
        .with_model(target, 0x20, vec![0x300])
        .with_func(0x300, 25, vec![field("id", "int", Some(target), 0x300)]);
    let extraction_count = source.extraction_count();
    let mut resolver = ModelResolver::new(source);

    let first = resolver.resolve_model(target);
    let second = resolver.resolve_model(target);

    assert_eq!(first.offset, second.offset);
    assert_eq!(extraction_count.get(), 1);
}

#[test]
fn resolver_reports_conflicting_initializer_ties() {
    let target = "Api::OneMe::Types::Conflict";
    let source = FakeSource::default()
        .with_model(target, 0x30, vec![0x400, 0x500])
        .with_func(
            0x400,
            40,
            vec![field("alpha", "std::string", Some(target), 0x400)],
        )
        .with_func(
            0x500,
            20,
            vec![field("beta", "std::string", Some(target), 0x500)],
        );

    let mut resolver = ModelResolver::new(source);
    let resolved = resolver.resolve_model(target);

    assert_eq!(resolved.offset.as_deref(), Some("0x500"));
    assert_eq!(
        resolved
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        vec!["beta"]
    );
    assert!(resolver.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind == ModelResolverDiagnosticKind::ConflictingInitializerCandidates
            && diagnostic.message.contains("0x400")
            && diagnostic.message.contains("0x500")
    }));
}

#[test]
fn resolver_allows_proven_nested_helper_owner_but_rejects_unrelated_mismatch() {
    let parent = "Api::OneMe::Types::Parent";
    let child = "Api::OneMe::Types::Child";
    let converter = "Api::OneMe::Types::AttachmentConverter";
    let source = FakeSource::default()
        .with_model(parent, 0x40, vec![0x600])
        .with_func(
            0x600,
            60,
            vec![
                field("child", child, Some(parent), 0x600),
                field("childValue", "std::string", Some(child), 0x600),
                field("converterName", "std::string", Some(converter), 0x600),
            ],
        );

    let mut resolver = ModelResolver::new(source);
    let resolved = resolver.resolve_model(parent);
    let field_names = resolved
        .fields
        .iter()
        .map(|f| f.name.as_str())
        .collect::<Vec<_>>();

    assert_eq!(field_names, vec!["child", "childValue"]);
    assert!(resolver.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind == ModelResolverDiagnosticKind::RejectedField
            && diagnostic.message.contains("converterName")
    }));
}

#[test]
fn resolver_allows_rtti_proven_base_owner_helper_for_derived_model() {
    let base = "Api::OneMe::Types::BaseAttachment";
    let video = "Api::OneMe::Types::VideoAttachment";
    let converter = "Api::OneMe::Types::AttachmentConverter";
    let source = FakeSource::default()
        .with_model(video, 0x50, vec![0x700, 0x800])
        .with_base_relation(base, video)
        .with_func(0x700, 20, Vec::new())
        .with_func(
            0x800,
            200,
            vec![
                field(
                    "collage",
                    "std::optional<Api::OneMe::Types::VideoCollage>",
                    Some(base),
                    0x800,
                ),
                field("converterName", "std::string", Some(converter), 0x800),
            ],
        );

    let mut resolver = ModelResolver::new(source);
    let resolved = resolver.resolve_model(video);
    let field_names = resolved
        .fields
        .iter()
        .map(|f| f.name.as_str())
        .collect::<Vec<_>>();

    assert_eq!(resolved.offset.as_deref(), Some("0x800"));
    assert_eq!(field_names, vec!["collage"]);
    assert!(resolver.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind == ModelResolverDiagnosticKind::RejectedField
            && diagnostic.message.contains("converterName")
    }));
}

#[test]
fn resolver_rejects_bot_fields_from_the_wrong_owner_initializer() {
    let bot_info_params = "Api::OneMe::Packets::Bot::BotInfo::Parameters";
    let start_message = "Api::OneMe::Types::Bot::StartMessage";
    let bot_command_helper = "Api::OneMe::Types::Bot::BotCommand";
    let source = FakeSource::default()
        .with_model(bot_info_params, 0x60, vec![0x900, 0x910])
        .with_model(start_message, 0x70, vec![0x900, 0x920])
        .with_func(
            0x900,
            100,
            vec![
                field("botId", "int64_t", Some(bot_info_params), 0x900),
                field(
                    "media",
                    "std::optional<Api::OneMe::Types::Polymorphic<Api::OneMe::Types::BaseAttachment>>",
                    Some(bot_command_helper),
                    0x900,
                ),
                field(
                    "text",
                    "Api::OneMe::Types::Bot::Text",
                    Some(bot_command_helper),
                    0x900,
                ),
            ],
        )
        .with_func(
            0x910,
            20,
            vec![field("botId", "int64_t", Some(bot_info_params), 0x910)],
        )
        .with_func(
            0x920,
            20,
            vec![
                field(
                    "media",
                    "std::optional<Api::OneMe::Types::Polymorphic<Api::OneMe::Types::BaseAttachment>>",
                    Some(bot_command_helper),
                    0x920,
                ),
                field(
                    "text",
                    "Api::OneMe::Types::Bot::Text",
                    Some(bot_command_helper),
                    0x920,
                ),
            ],
        );

    let mut resolver = ModelResolver::new(source);
    let bot_info = resolver.resolve_model(bot_info_params);
    let start = resolver.resolve_model(start_message);

    assert_eq!(field_names(&bot_info.fields), vec!["botId"]);
    assert_eq!(field_names(&start.fields), vec!["media", "text"]);
    assert!(resolver.diagnostics().iter().any(|diagnostic| {
        diagnostic.model_name == bot_info_params
            && diagnostic.kind == ModelResolverDiagnosticKind::RejectedField
            && diagnostic.message.contains("media")
    }));
    assert!(resolver.diagnostics().iter().any(|diagnostic| {
        diagnostic.model_name == start_message
            && diagnostic.kind == ModelResolverDiagnosticKind::RejectedField
            && diagnostic.message.contains("botId")
    }));
}

#[test]
fn resolver_rejects_converter_and_logging_string_evidence_for_attachment() {
    let unsupported = "Api::OneMe::Types::UnsupportedAttachment";
    let source = FakeSource::default()
        .with_model(unsupported, 0x80, vec![0xa00])
        .with_func(
            0xa00,
            80,
            vec![
                field("_type", "std::string", Some(unsupported), 0xa00),
                field("deleted", "std::optional<bool>", Some(unsupported), 0xa00),
                field_with_sources(
                    "AttachmentConverter",
                    "std::string",
                    Some(unsupported),
                    0xa00,
                    "string_literal",
                    "serializable_member",
                ),
                field_with_sources(
                    "UnsupportedAttachmentLogger",
                    "std::string",
                    Some(unsupported),
                    0xa00,
                    "logging_string_literal",
                    "serializable_member",
                ),
            ],
        );

    let mut resolver = ModelResolver::new(source);
    let resolved = resolver.resolve_model(unsupported);

    assert_eq!(field_names(&resolved.fields), vec!["_type", "deleted"]);
    assert!(resolver.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind == ModelResolverDiagnosticKind::RejectedField
            && diagnostic.message.contains("AttachmentConverter")
    }));
    assert!(resolver.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind == ModelResolverDiagnosticKind::RejectedField
            && diagnostic.message.contains("UnsupportedAttachmentLogger")
    }));
}

#[test]
fn resolver_accepts_primitive_fields_from_rtti_base_owner_for_attachment_and_ttl_models() {
    let base = "Api::OneMe::Types::BaseAttachment";
    let photo = "Api::OneMe::Types::PhotoAttachment";
    let source = FakeSource::default()
        .with_model(photo, 0x110, vec![0x1100])
        .with_base_relation(base, photo)
        .with_func(
            0x1100,
            250,
            vec![
                field("photoId", "int64_t", Some(base), 0x1100),
                field("baseUrl", "std::string", Some(base), 0x1100),
                field("width", "int32_t", Some(base), 0x1100),
                field("height", "int32_t", Some(base), 0x1100),
                field("hasThumbnail", "bool", Some(base), 0x1100),
                field("rawBytes", "std::vector<uint8_t>", Some(base), 0x1100),
            ],
        );

    let mut resolver = ModelResolver::new(source);
    let resolved = resolver.resolve_model(photo);

    assert_eq!(resolved.offset.as_deref(), Some("0x1100"));
    assert_eq!(
        field_names(&resolved.fields),
        vec![
            "photoId",
            "baseUrl",
            "width",
            "height",
            "hasThumbnail",
            "rawBytes"
        ]
    );
    assert_eq!(resolved.warn, None);
    assert!(
        !resolver
            .diagnostics()
            .iter()
            .any(|d| d.kind == ModelResolverDiagnosticKind::RejectedField),
        "primitive fields from proven base owner should not be rejected"
    );
}

#[test]
fn resolver_accepts_fields_from_crtp_base_template_owner_for_ttl_models() {
    let ttl_model = "Api::OneMe::Types::CommentsCounterTtl";
    let crtp_base = "Api::OneMe::Types::SerializableClass<struct Api::OneMe::Types::PollTtl,std::string_view >";
    let member_owner = "Api::OneMe::Types::PollTtl";

    let source = FakeSource::default()
        .with_model(ttl_model, 0x130, vec![0x1300, 0x1350])
        .with_base_relation(crtp_base, ttl_model)
        .with_func(
            0x1300,
            200,
            vec![
                field("channel", "std::optional<int64_t>", Some(member_owner), 0x1300),
                field("bigchannel", "std::optional<int64_t>", Some(member_owner), 0x1300),
                field("participantsCount", "std::optional<int64_t>", Some(member_owner), 0x1300),
            ],
        )
        .with_func(0x1350, 100, vec![]);

    let mut resolver = ModelResolver::new(source);
    let resolved = resolver.resolve_model(ttl_model);

    assert_eq!(resolved.offset.as_deref(), Some("0x1300"));
    assert_eq!(
        field_names(&resolved.fields),
        vec!["channel", "bigchannel", "participantsCount"]
    );
    assert_eq!(resolved.warn, None);
    assert!(
        !resolver
            .diagnostics()
            .iter()
            .any(|d| d.kind == ModelResolverDiagnosticKind::RejectedField),
        "fields with CRTP template argument owner should be accepted"
    );
}

#[test]
fn resolver_accepts_telemetry_event_metrics_fields_from_event_params_base() {
    let base = "Api::OneMe::Types::Log::EventParams";
    let call_params = "Api::OneMe::Types::Log::CallEventParams";
    let source = FakeSource::default()
        .with_model(call_params, 0x120, vec![0x1200])
        .with_base_relation(base, call_params)
        .with_func(
            0x1200,
            180,
            vec![
                field("callId", "std::string", Some(base), 0x1200),
                field("durationMs", "int64_t", Some(base), 0x1200),
                field("isSuccess", "bool", Some(base), 0x1200),
                field("errorCode", "int32_t", Some(base), 0x1200),
            ],
        );

    let mut resolver = ModelResolver::new(source);
    let resolved = resolver.resolve_model(call_params);

    assert_eq!(resolved.offset.as_deref(), Some("0x1200"));
    assert_eq!(
        field_names(&resolved.fields),
        vec!["callId", "durationMs", "isSuccess", "errorCode"]
    );
    assert_eq!(resolved.warn, None);
}

#[test]
fn resolver_prioritizes_direct_owner_over_base_owner_across_initializers() {
    let base = "Api::OneMe::Types::BaseAttachment";
    let custom = "Api::OneMe::Types::CustomAttachment";
    let source = FakeSource::default()
        .with_model(custom, 0x130, vec![0x1300, 0x1310])
        .with_base_relation(base, custom)
        .with_func(
            0x1300,
            100,
            vec![field("localExtra", "std::string", Some(custom), 0x1300)],
        )
        .with_func(
            0x1310,
            40,
            vec![
                field("baseField1", "std::string", Some(base), 0x1310),
                field("baseField2", "int32_t", Some(base), 0x1310),
                field("baseField3", "bool", Some(base), 0x1310),
            ],
        );

    let mut resolver = ModelResolver::new(source);
    let resolved = resolver.resolve_model(custom);

    assert_eq!(resolved.offset.as_deref(), Some("0x1300"));
    assert_eq!(field_names(&resolved.fields), vec!["localExtra"]);
    assert!(resolver.diagnostics().iter().any(|d| {
        d.kind == ModelResolverDiagnosticKind::RejectedInitializerCandidate
            && d.function_rva == Some(0x1310)
            && d.message.contains("owner_rank=2")
    }));
}

#[test]
fn resolver_prioritizes_direct_owner_over_base_owner_for_duplicate_field_name() {
    let base = "Api::OneMe::Types::BaseAttachment";
    let target = "Api::OneMe::Types::DerivedAttachment";
    let source = FakeSource::default()
        .with_model(target, 0x140, vec![0x1400])
        .with_base_relation(base, target)
        .with_func(
            0x1400,
            120,
            vec![
                field("title", "int64_t", Some(base), 0x1400),
                field("title", "std::string", Some(target), 0x1400),
                field("count", "int32_t", Some(base), 0x1400),
            ],
        );

    let mut resolver = ModelResolver::new(source);
    let resolved = resolver.resolve_model(target);

    assert_eq!(resolved.offset.as_deref(), Some("0x1400"));
    assert_eq!(field_names(&resolved.fields), vec!["title", "count"]);
    let title_field = resolved.fields.iter().find(|f| f.name == "title").unwrap();
    assert_eq!(title_field.field_type.full, "std::string");
}

#[test]
fn resolver_suppresses_warning_for_empty_marker_class_with_verified_initializer_and_base_fields() {
    let base = "Api::OneMe::Types::BaseAttachment";
    let unsupported = "Api::OneMe::Types::UnsupportedAttachment";
    let source = FakeSource::default()
        .with_model(base, 0x150, vec![0x1500])
        .with_model(unsupported, 0x160, vec![0x1600])
        .with_base_relation(base, unsupported)
        .with_func(
            0x1500,
            80,
            vec![
                field("_type", "std::string", Some(base), 0x1500),
                field("deleted", "std::optional<bool>", Some(base), 0x1500),
            ],
        )
        .with_func(0x1600, 20, Vec::new());

    let mut resolver = ModelResolver::new(source);
    let resolved = resolver.resolve_model(unsupported);

    assert_eq!(resolved.offset.as_deref(), Some("0x1600"));
    assert!(resolved.fields.is_empty());
    assert_eq!(resolved.warn, None);
}

#[test]
fn resolver_does_not_suppress_warning_when_base_has_no_fields() {
    let base = "Api::OneMe::Types::EmptyBase";
    let derived = "Api::OneMe::Types::EmptyDerived";
    let source = FakeSource::default()
        .with_model(base, 0x170, vec![0x1700])
        .with_model(derived, 0x180, vec![0x1800])
        .with_base_relation(base, derived)
        .with_func(0x1700, 20, Vec::new())
        .with_func(0x1800, 20, Vec::new());

    let mut resolver = ModelResolver::new(source);
    let resolved = resolver.resolve_model(derived);

    assert_eq!(resolved.offset.as_deref(), Some("0x1800"));
    assert!(resolved.fields.is_empty());
    assert_eq!(resolved.warn, Some("no data found".to_string()));
}

#[test]
fn resolver_does_not_suppress_warning_when_initializer_is_unverified() {
    let base = "Api::OneMe::Types::BaseAttachment";
    let uninit = "Api::OneMe::Types::UninitializedModel";
    let source = FakeSource::default()
        .with_model(base, 0x190, vec![0x1900])
        .with_base_relation(base, uninit)
        .with_func(
            0x1900,
            80,
            vec![field("_type", "std::string", Some(base), 0x1900)],
        );

    let mut resolver = ModelResolver::new(source);
    let resolved = resolver.resolve_model(uninit);

    assert_eq!(resolved.offset, None);
    assert!(resolved.fields.is_empty());
    assert_eq!(resolved.warn, Some("no data found".to_string()));
}

fn field_names(fields: &[dumper_rust::extractor::ExtractedField]) -> Vec<&str> {
    fields.iter().map(|field| field.name.as_str()).collect()
}
