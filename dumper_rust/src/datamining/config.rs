use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Default minimum number of top-level keys required to identify a JSON object as the configuration block.
pub const DEFAULT_MIN_KEYS: usize = 20;

/// Represents a candidate configuration JSON object extracted from binary data.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigCandidate {
    /// Number of top-level keys in the JSON dictionary.
    pub key_count: usize,
    /// Byte offset where the opening brace `{` was found in the input binary.
    pub offset: usize,
    /// Byte offset immediately following the matching closing brace `}`.
    pub end_offset: usize,
    /// Raw unparsed JSON string slice.
    pub raw_json: String,
    /// Parsed serde_json Value representing the configuration object.
    pub value: serde_json::Value,
}

/// Scans forward from `start` (which must point to a `{` byte) until the matching balanced `}`.
///
/// Accounts for nested braces and string literals, including escape sequences (`\"` and `\\`).
/// Returns a tuple `(raw_json_str, end_offset)` where `end_offset` is the index immediately
/// following the matching closing brace, or `None` if the braces are unbalanced, the string is
/// unterminated, or the slice is not valid UTF-8.
pub fn try_extract_balanced(data: &[u8], start: usize) -> Option<(&str, usize)> {
    if start >= data.len() || data[start] != b'{' {
        return None;
    }

    let mut depth: usize = 0;
    let mut in_string = false;
    let mut i = start;
    let n = data.len();

    while i < n {
        let b = data[i];
        if in_string {
            if b == b'\\' {
                // Escaped character: skip this backslash and the byte directly following it.
                if i + 1 >= n {
                    return None;
                }
                i += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
        } else {
            if b == b'"' {
                in_string = true;
            } else if b == b'{' {
                depth += 1;
            } else if b == b'}' {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth == 0 {
                    let end_idx = i + 1;
                    let slice = &data[start..end_idx];
                    return std::str::from_utf8(slice).ok().map(|s| (s, end_idx));
                }
            }
        }
        i += 1;
    }

    None
}

/// Scans binary data for candidate JSON objects with at least `min_keys` keys.
///
/// If multiple candidates are found, logs a warning and selects the candidate with the maximum
/// number of keys. Returns an error if no valid JSON dictionary candidate is found.
pub fn extract_config_candidate(
    data: &[u8],
    min_keys: usize,
) -> Result<ConfigCandidate> {
    let mut candidates = Vec::new();
    let n = data.len();
    let mut i = 0;

    while i < n {
        if data[i] != b'{' {
            match memchr::memchr(b'{', &data[i..]) {
                Some(offset) => i += offset,
                None => break,
            }
        }

        if let Some((blob_str, end_idx)) = try_extract_balanced(data, i) {
            match serde_json::from_str::<serde_json::Value>(blob_str) {
                Ok(serde_json::Value::Object(map)) if map.len() >= min_keys => {
                    let key_count = map.len();
                    candidates.push(ConfigCandidate {
                        key_count,
                        offset: i,
                        end_offset: end_idx,
                        raw_json: blob_str.to_string(),
                        value: serde_json::Value::Object(map),
                    });
                    // Skip ahead past the found blob to avoid scanning inside the candidate
                    i = end_idx;
                    continue;
                }
                _ => {}
            }
        }

        i += 1;
    }

    if candidates.is_empty() {
        anyhow::bail!(
            "no JSON config blob with >= {} keys found in binary",
            min_keys
        );
    }

    // Sort descending by key_count, tie-break by earlier offset
    candidates.sort_by(|a, b| {
        b.key_count
            .cmp(&a.key_count)
            .then_with(|| a.offset.cmp(&b.offset))
    });

    if candidates.len() > 1 {
        let summary: Vec<String> = candidates
            .iter()
            .map(|c| format!("{}@0x{:x}", c.key_count, c.offset))
            .collect();
        eprintln!(
            "warning: multiple JSON candidates found ({}); picked largest ({} keys @0x{:x})",
            summary.join(", "),
            candidates[0].key_count,
            candidates[0].offset
        );
    }

    Ok(candidates.remove(0))
}

/// Extracts the raw JSON string of the largest configuration dictionary from binary data.
pub fn extract_config_blob(data: &[u8], min_keys: usize) -> Result<String> {
    let candidate = extract_config_candidate(data, min_keys)?;
    Ok(candidate.raw_json)
}

/// Extracts the parsed JSON Value of the largest configuration dictionary from binary data.
pub fn extract_config_value(data: &[u8], min_keys: usize) -> Result<serde_json::Value> {
    let candidate = extract_config_candidate(data, min_keys)?;
    Ok(candidate.value)
}

/// Convenience function extracting the configuration Value with `DEFAULT_MIN_KEYS` (20).
pub fn extract_config(data: &[u8]) -> Result<serde_json::Value> {
    extract_config_value(data, DEFAULT_MIN_KEYS)
}

/// Extracts the configuration Value from a DLL or binary file on disk.
pub fn extract_config_from_file<P: AsRef<Path>>(path: P) -> Result<serde_json::Value> {
    let path = path.as_ref();
    let data = fs::read(path)
        .with_context(|| format!("Failed to read DLL file at {:?}", path))?;
    extract_config(&data)
}

/// Derives the expected `*.config.dll` path from a target `*.core.dll` or generic DLL path.
///
/// If `path` is `core.dll`, returns `config.dll`.
/// If `path` is `config.dll` or ends with `.config.dll`, preserves the name.
/// If `path` ends with `.core.dll`, replaces `.core.dll` with `.config.dll`.
/// If `path` ends with `.dll` (and not `.config.dll`), replaces `.dll` with `.config.dll`.
/// Otherwise appends `.config.dll`.
pub fn derive_config_path(core_path: &Path) -> PathBuf {
    let parent = core_path.parent().unwrap_or_else(|| Path::new(""));
    let file_name = match core_path.file_name().and_then(|f| f.to_str()) {
        Some(name) => name,
        None => return core_path.with_extension("config.dll"),
    };

    let lower = file_name.to_lowercase();
    let new_file_name = if lower == "config.dll" || lower.ends_with(".config.dll") {
        file_name.to_string()
    } else if lower == "core.dll" {
        "config.dll".to_string()
    } else if lower.ends_with(".core.dll") {
        format!("{}.config.dll", &file_name[..file_name.len() - ".core.dll".len()])
    } else if lower.ends_with(".dll") {
        format!("{}.config.dll", &file_name[..file_name.len() - ".dll".len()])
    } else {
        format!("{}.config.dll", file_name)
    };

    if parent.as_os_str().is_empty() {
        PathBuf::from(new_file_name)
    } else {
        parent.join(new_file_name)
    }
}

/// Discovers `*.config.dll` or `config.dll` for a given target binary path.
///
/// 1. If an explicit path override is provided, returns that path directly.
/// 2. If the derived path exists on disk, returns it.
/// 3. Checks if `config.dll` exists in the parent directory of `core_dll_path`.
/// 4. If any file ending in `.config.dll` exists in the parent directory, returns the first matching candidate.
/// 5. Checks the current working directory for `CM_FP_Unspecified.config.dll` or `config.dll` as a fallback.
pub fn discover_config_dll(
    core_dll_path: &Path,
    explicit_override: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(explicit) = explicit_override {
        return Some(explicit.to_path_buf());
    }

    let derived = derive_config_path(core_dll_path);
    if derived.is_file() {
        return Some(derived);
    }

    let parent = core_dll_path
        .parent()
        .map(|p| if p.as_os_str().is_empty() { Path::new(".") } else { p })
        .unwrap_or_else(|| Path::new("."));

    // Check directly for config.dll in parent
    let config_plain = parent.join("config.dll");
    if config_plain.is_file() {
        return Some(config_plain);
    }

    if let Ok(entries) = fs::read_dir(parent) {
        let mut config_files = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    let lower = name.to_lowercase();
                    if lower == "config.dll" || lower.ends_with(".config.dll") {
                        config_files.push(path);
                    }
                }
            }
        }
        if !config_files.is_empty() {
            config_files.sort();
            return Some(config_files.remove(0));
        }
    }

    for fallback_name in &["CM_FP_Unspecified.config.dll", "config.dll"] {
        let fallback = PathBuf::from(fallback_name);
        if fallback.is_file() {
            return Some(fallback);
        }
    }

    None
}

/// Formats a JSON value into a pretty string with 2-space indentation and a trailing newline.
pub fn format_config_json<T: serde::Serialize>(value: &T) -> Result<String> {
    let mut buf = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"  ");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    value.serialize(&mut ser)?;
    let mut s = String::from_utf8(buf)?;
    s.push('\n');
    Ok(s)
}

/// Emits the standalone `config.json` file to the specified path.
pub fn emit_config_json<P: AsRef<Path>, T: serde::Serialize>(value: &T, path: P) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create parent directory {:?}", parent))?;
    }
    let formatted = format_config_json(value)?;
    fs::write(path, formatted)
        .with_context(|| format!("Failed to write config.json to {:?}", path))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nested_objects_and_arrays() {
        let mut obj = serde_json::Map::new();
        for i in 1..=18 {
            obj.insert(format!("key_{i:02}"), serde_json::json!(i));
        }
        obj.insert(
            "nested_obj".to_string(),
            serde_json::json!({
                "sub_a": 100,
                "sub_b": { "deep": [1, 2, 3] }
            }),
        );
        obj.insert(
            "nested_array".to_string(),
            serde_json::json!([
                {"item": "first"},
                {"item": "second", "tags": ["a", "b"]}
            ]),
        );
        let root = serde_json::Value::Object(obj);
        let json_text = serde_json::to_string(&root).unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(b"HEADER_PADDING\x00\x01\x02");
        data.extend_from_slice(json_text.as_bytes());
        data.extend_from_slice(b"\x00\xFFTRAILER");

        let candidate = extract_config_candidate(&data, 20).expect("Must extract candidate");
        assert_eq!(candidate.key_count, 20);
        assert_eq!(
            candidate.value["nested_obj"]["sub_b"]["deep"],
            serde_json::json!([1, 2, 3])
        );
        assert_eq!(
            candidate.value["nested_array"][1]["tags"],
            serde_json::json!(["a", "b"])
        );
    }

    #[test]
    fn test_string_escapes_and_embedded_braces() {
        let mut obj = serde_json::Map::new();
        for i in 1..=17 {
            obj.insert(format!("item_{i:02}"), serde_json::json!(format!("val_{i}")));
        }
        obj.insert(
            "brace_val".to_string(),
            serde_json::json!("string with { opening and } closing braces"),
        );
        obj.insert(
            "quote_val".to_string(),
            serde_json::json!("string with \\\"escaped\\\" quotes and backslash \\\\"),
        );
        obj.insert(
            "complex_val".to_string(),
            serde_json::json!("combo: { \\\"nested\\\": true, \\\"brackets\\\": [1, 2] }"),
        );
        let root = serde_json::Value::Object(obj);
        let json_text = serde_json::to_string(&root).unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(b"\xaa\xbb\xcc");
        data.extend_from_slice(json_text.as_bytes());
        data.extend_from_slice(b"\xdd\xee\xff");

        let candidate = extract_config_candidate(&data, 20).expect("Must parse escapes");
        assert_eq!(candidate.key_count, 20);
        assert_eq!(
            candidate.value["brace_val"].as_str().unwrap(),
            "string with { opening and } closing braces"
        );
        assert_eq!(
            candidate.value["quote_val"].as_str().unwrap(),
            "string with \\\"escaped\\\" quotes and backslash \\\\"
        );
    }

    #[test]
    fn test_preceding_and_trailing_binary_padding_and_garbage() {
        let mut obj = serde_json::Map::new();
        for i in 1..=22 {
            obj.insert(format!("k_{i}"), serde_json::json!(i * 10));
        }
        let json_text = serde_json::to_string_pretty(&serde_json::Value::Object(obj)).unwrap();

        let mut data = Vec::new();
        // Malformed opening braces and binary garbage
        data.extend_from_slice(b"{ unclosed malformed { JSON garbage: 123, \x00\x01\x02");
        data.extend_from_slice(b"\x90\x90\x00\x00\x0c\x3c"); // simulate Qt resource header
        let valid_offset = data.len();
        data.extend_from_slice(json_text.as_bytes());
        let end_offset = data.len();
        // Trailing garbage including small valid JSON
        data.extend_from_slice(b"\x00\x00{ \"small\": 1 }\x00\xff");

        let candidate = extract_config_candidate(&data, 20).expect("Must skip garbage and find config");
        assert_eq!(candidate.offset, valid_offset);
        assert_eq!(candidate.end_offset, end_offset);
        assert_eq!(candidate.key_count, 22);
        assert_eq!(candidate.value["k_1"], 10);
        assert_eq!(candidate.value["k_22"], 220);
    }

    #[test]
    fn test_rejection_fewer_than_min_keys() {
        let small_json = b"{ \"a\": 1, \"b\": 2, \"c\": 3 }";
        let res = extract_config_candidate(small_json, 20);
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains(">= 20 keys"));
    }

    #[test]
    fn test_candidate_selection_max_keys() {
        let mut obj1 = serde_json::Map::new();
        for i in 1..=20 {
            obj1.insert(format!("obj1_k{i}"), serde_json::json!(i));
        }
        let str1 = serde_json::to_string(&serde_json::Value::Object(obj1)).unwrap();

        let mut obj2 = serde_json::Map::new();
        for i in 1..=25 {
            obj2.insert(format!("obj2_k{i}"), serde_json::json!(i));
        }
        let str2 = serde_json::to_string(&serde_json::Value::Object(obj2)).unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(b"GARBAGE_1");
        data.extend_from_slice(str1.as_bytes());
        data.extend_from_slice(b"GARBAGE_2");
        data.extend_from_slice(str2.as_bytes());
        data.extend_from_slice(b"GARBAGE_3");

        let candidate = extract_config_candidate(&data, 20).expect("Must extract candidate");
        assert_eq!(candidate.key_count, 25);
        assert!(candidate.value.get("obj2_k25").is_some());
    }

    #[test]
    fn test_derive_and_discover_config_path() {
        // Core DLL suffix replacement
        let p1 = Path::new("D:/games/app/CM_FP_Unspecified.core.dll");
        assert_eq!(
            derive_config_path(p1),
            PathBuf::from("D:/games/app/CM_FP_Unspecified.config.dll")
        );

        // Plain DLL replacement
        let p2 = Path::new("C:/test/client.dll");
        assert_eq!(
            derive_config_path(p2),
            PathBuf::from("C:/test/client.config.dll")
        );

        // Already config dll
        let p3 = Path::new("C:/test/client.config.dll");
        assert_eq!(
            derive_config_path(p3),
            PathBuf::from("C:/test/client.config.dll")
        );

        // Standalone core.dll to config.dll
        let p4 = Path::new("C:/test/core.dll");
        assert_eq!(
            derive_config_path(p4),
            PathBuf::from("C:/test/config.dll")
        );

        // Standalone config.dll preserves config.dll
        let p5 = Path::new("C:/test/config.dll");
        assert_eq!(
            derive_config_path(p5),
            PathBuf::from("C:/test/config.dll")
        );

        // Explicit override priority in discover
        let explicit = Path::new("custom/my_config.dll");
        let discovered = discover_config_dll(p1, Some(explicit));
        assert_eq!(discovered, Some(PathBuf::from("custom/my_config.dll")));
    }

    #[test]
    fn test_format_and_emit_config_json() {
        let val = serde_json::json!({
            "alpha": "val_a",
            "beta": 123
        });
        let formatted = format_config_json(&val).unwrap();
        assert!(formatted.ends_with('\n'), "Must have trailing newline");
        assert!(formatted.contains("  \"alpha\": \"val_a\""), "Must have 2-space indentation");

        let temp_dir = std::env::temp_dir().join("test_config_emit_dir");
        let target_file = temp_dir.join("test_config.json");
        emit_config_json(&val, &target_file).unwrap();

        let read_back = fs::read_to_string(&target_file).unwrap();
        assert_eq!(read_back, formatted);
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
