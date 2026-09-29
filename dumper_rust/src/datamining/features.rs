use crate::model_resolver::{ModelResolutionSource, ModelResolver, PeModelResolutionSource};
use crate::pe::PeImage;
use crate::rtti::RttiEngine;
use crate::type_parser::normalize_type;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SERVER_SETTINGS_MANGLED: &str = ".?AUServerSettings@Types@OneMe@Api@@";
pub const SERVER_SETTINGS_DEMANGLED: &str = "Api::OneMe::Types::ServerSettings";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSettingsFeatures {
    pub model_name: String,
    pub initializer_rva: u32,
    pub features: BTreeMap<String, String>,
}

/// Locates the `ServerSettings` model within RTTI.
///
/// Searches both by demangled symbol (`Api::OneMe::Types::ServerSettings`) and
/// mangled symbol (`.?AUServerSettings@Types@OneMe@Api@@`).
pub fn locate_server_settings(rtti: &RttiEngine) -> Result<(&'static str, u32)> {
    if let Some(&vtable_rva) = rtti.type_to_vtable.get(SERVER_SETTINGS_DEMANGLED) {
        return Ok((SERVER_SETTINGS_DEMANGLED, vtable_rva));
    }

    for td in rtti.type_descriptors.values() {
        if td.mangled_name == SERVER_SETTINGS_MANGLED {
            if let Some(&vtable_rva) = rtti.type_to_vtable.get(&td.demangled_name) {
                return Ok((SERVER_SETTINGS_DEMANGLED, vtable_rva));
            }
        }
    }

    bail!(
        "ServerSettings model not found in RTTI (mangled: '{}', demangled: '{}')",
        SERVER_SETTINGS_MANGLED,
        SERVER_SETTINGS_DEMANGLED
    )
}

/// Extracts ServerSettings feature toggles and their normalized C++ types.
///
/// Returns a sorted `BTreeMap<String, String>` mapping kebab-case feature names
/// to their normalized canonical C++ types.
pub fn extract_server_settings_features(
    pe: &PeImage,
    rtti: &RttiEngine,
) -> Result<BTreeMap<String, String>> {
    let result = extract_server_settings(pe, rtti)?;
    Ok(result.features)
}

/// Full extraction of ServerSettings, returning the initializer RVA and features map.
pub fn extract_server_settings(
    pe: &PeImage,
    rtti: &RttiEngine,
) -> Result<ServerSettingsFeatures> {
    let (model_name, _vtable_rva) = locate_server_settings(rtti)?;
    let source = PeModelResolutionSource::new(pe, rtti);
    extract_server_settings_from_source_with_model(source, model_name)
}

/// Extracts ServerSettings features from any model resolution source (e.g., for mock/synthetic tests).
pub fn extract_server_settings_from_source<S: ModelResolutionSource>(
    source: S,
) -> Result<ServerSettingsFeatures> {
    extract_server_settings_from_source_with_model(source, SERVER_SETTINGS_DEMANGLED)
}

/// Extracts features for a specific model from any model resolution source.
pub fn extract_server_settings_from_source_with_model<S: ModelResolutionSource>(
    source: S,
    model_name: &str,
) -> Result<ServerSettingsFeatures> {
    let mut resolver = ModelResolver::new(source);
    let resolved = resolver.resolve_model(model_name);

    let initializer_rva = match &resolved.offset {
        Some(offset_str) => {
            let hex_str = offset_str.trim_start_matches("0x");
            u32::from_str_radix(hex_str, 16).unwrap_or(0)
        }
        None => {
            bail!("No initializer function found for model '{model_name}'");
        }
    };

    if resolved.fields.is_empty() {
        bail!(
            "No field registrations extracted for model '{model_name}' from initializer 0x{initializer_rva:x}"
        );
    }

    let mut features = BTreeMap::new();
    for field in resolved.fields {
        let canonical_type = normalize_type(&field.field_type.full);
        features.insert(field.name, canonical_type);
    }

    Ok(ServerSettingsFeatures {
        model_name: model_name.to_string(),
        initializer_rva,
        features,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extractor::FieldCandidate;
    use crate::rtti::ClassHierarchy;
    use crate::type_parser::decompose_type;
    use std::collections::{HashMap, HashSet};

    #[derive(Clone, Default)]
    struct MockSource {
        vtables: HashMap<String, u32>,
        funcs: HashMap<u32, Vec<u32>>,
        lengths: HashMap<u32, u32>,
        fields: HashMap<u32, Vec<FieldCandidate>>,
        qualified: HashSet<u32>,
        hierarchy: ClassHierarchy,
    }

    impl MockSource {
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
    }

    impl ModelResolutionSource for MockSource {
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
            Ok(self.fields.get(&func_rva).cloned().unwrap_or_default())
        }

        fn owner_is_base_of_model(&self, owner_type: &str, model_type: &str) -> bool {
            self.hierarchy.is_base_of(owner_type, model_type)
        }

        fn base_models_of(&self, model_type: &str) -> Vec<String> {
            self.hierarchy.bases_of(model_type)
        }
    }

    fn make_field(name: &str, raw_type: &str, owner: &str, func_rva: u32) -> FieldCandidate {
        FieldCandidate {
            name: name.to_string(),
            field_type: decompose_type(raw_type),
            required: false,
            owner_type: Some(owner.to_string()),
            function_rva: func_rva,
            name_source: "string_literal".to_string(),
            type_source: "serializable_member".to_string(),
            rejection_reason: None,
        }
    }

    #[test]
    fn test_synthetic_candidate_selection_and_normalization() {
        let owner = SERVER_SETTINGS_DEMANGLED;
        let copy_ctor_rva = 0x4dbce0;
        let init_func_rva = 0x4dea20;

        let mock = MockSource::default()
            .with_model(owner, 0x180ffb8, vec![copy_ctor_rva, init_func_rva])
            .with_func(copy_ctor_rva, 120, vec![])
            .with_func(
                init_func_rva,
                12616,
                vec![
                    make_field(
                        "reactions-menu",
                        "class std::optional<class std::vector<class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> > > >",
                        owner,
                        init_func_rva,
                    ),
                    make_field(
                        "account-nickname-enabled",
                        "class std::optional<bool>",
                        owner,
                        init_func_rva,
                    ),
                    make_field(
                        "video-msg-config",
                        "class std::optional<struct Api::OneMe::Types::VideoMessageConfig>",
                        owner,
                        init_func_rva,
                    ),
                    make_field(
                        "channels-enabled",
                        "class std::optional<bool>",
                        owner,
                        init_func_rva,
                    ),
                    make_field(
                        "file-upload-max-size",
                        "class std::optional<__int64>",
                        owner,
                        init_func_rva,
                    ),
                    make_field(
                        "max-msg-length",
                        "class std::optional<int>",
                        owner,
                        init_func_rva,
                    ),
                ],
            );

        let result = extract_server_settings_from_source(mock)
            .expect("Synthetic extraction must succeed");

        // Asserts candidate evaluation selects 0x4dea20 over copy constructor 0x4dbce0
        assert_eq!(result.initializer_rva, init_func_rva);
        assert_eq!(result.features.len(), 6);

        // Asserts normalized types
        assert_eq!(
            result.features.get("reactions-menu").map(String::as_str),
            Some("std::optional<std::vector<std::string>>")
        );
        assert_eq!(
            result.features.get("account-nickname-enabled").map(String::as_str),
            Some("std::optional<bool>")
        );
        assert_eq!(
            result.features.get("video-msg-config").map(String::as_str),
            Some("std::optional<Api::OneMe::Types::VideoMessageConfig>")
        );
        assert_eq!(
            result.features.get("channels-enabled").map(String::as_str),
            Some("std::optional<bool>")
        );
        assert_eq!(
            result.features.get("file-upload-max-size").map(String::as_str),
            Some("std::optional<int64_t>")
        );
        assert_eq!(
            result.features.get("max-msg-length").map(String::as_str),
            Some("std::optional<int32_t>")
        );

        // Asserts lexicographical sorting
        let keys: Vec<&str> = result.features.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec![
                "account-nickname-enabled",
                "channels-enabled",
                "file-upload-max-size",
                "max-msg-length",
                "reactions-menu",
                "video-msg-config",
            ]
        );
    }

    #[test]
    fn test_synthetic_model_not_found() {
        let mock = MockSource::default();
        let err = extract_server_settings_from_source(mock)
            .expect_err("Must fail when model not found");
        assert!(err.to_string().contains("No initializer function found"));
    }

    #[test]
    fn test_synthetic_no_fields_extracted() {
        let owner = SERVER_SETTINGS_DEMANGLED;
        let copy_ctor_rva = 0x4dbce0;

        let mock = MockSource::default()
            .with_model(owner, 0x180ffb8, vec![copy_ctor_rva])
            .with_func(copy_ctor_rva, 120, vec![]);

        let err = extract_server_settings_from_source(mock)
            .expect_err("Must fail when candidate has 0 fields");
        assert!(err.to_string().contains("No field registrations extracted"));
    }
}
