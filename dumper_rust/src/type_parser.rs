use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecomposedType {
    pub full: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub ident: Option<String>,
    pub optional: bool,
    pub array: bool,
    #[serde(default)]
    pub bytes: bool,
    pub map: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub map_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub map_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub map_key_type: Option<Box<DecomposedType>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub map_value_type: Option<Box<DecomposedType>>,
    pub polymorphic: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub polymorphic_base: Option<String>,
}

const QUALIFIERS: &[&str] = &[
    "class ",
    "struct ",
    "enum ",
    "union ",
    "const ",
    "volatile ",
];

pub fn strip_qualifiers(mut s: &str) -> &str {
    s = s.trim();
    let mut changed = true;
    while changed {
        changed = false;
        for pfx in QUALIFIERS {
            if s.starts_with(pfx) {
                s = s[pfx.len()..].trim();
                changed = true;
                break;
            }
        }
    }
    s
}

pub fn strip_all_qualifiers(s: &str) -> String {
    let s = s.trim();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < s.len() {
        let at_token_boundary = match out.chars().last() {
            None => true,
            Some(prev) => !prev.is_ascii_alphanumeric() && prev != '_' && prev != ':',
        };
        if at_token_boundary {
            let mut stripped_any = false;
            loop {
                let rest = &s[i..];
                let mut matched = false;
                for pfx in QUALIFIERS {
                    if rest.starts_with(pfx) {
                        i += pfx.len();
                        while i < bytes.len() && bytes[i] == b' ' {
                            i += 1;
                        }
                        matched = true;
                        stripped_any = true;
                        break;
                    }
                }
                if !matched {
                    break;
                }
            }
            if stripped_any {
                continue;
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

pub fn extract_template_args(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                if depth == 0 {
                    let part = s[start..i].trim();
                    if !part.is_empty() {
                        args.push(part.to_string());
                    }
                    return args;
                }
                depth -= 1;
            }
            ',' => {
                if depth == 0 {
                    let part = s[start..i].trim();
                    if !part.is_empty() {
                        args.push(part.to_string());
                    }
                    start = i + 1;
                }
            }
            _ => {}
        }
    }
    let tail = s[start..].trim();
    if !tail.is_empty() {
        args.push(tail.to_string());
    }
    args
}

pub fn extract_inner_template(s: &str, prefix: &str) -> Option<String> {
    let stripped = strip_qualifiers(s);
    let pfx = format!("{}<", prefix);
    if !stripped.starts_with(&pfx) {
        return None;
    }
    let rest = &stripped[pfx.len()..];
    let mut depth = 0;
    for (i, c) in rest.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                if depth == 0 {
                    return Some(rest[..i].trim().to_string());
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    None
}

pub fn normalize_primitive(s: &str) -> &str {
    match s {
        "int" => "int32_t",
        "__int64" | "long long" => "int64_t",
        "short" => "int16_t",
        "signed char" => "char",
        "unsigned int" => "uint32_t",
        "unsigned __int64" | "unsigned long long" => "uint64_t",
        "unsigned short" => "uint16_t",
        "unsigned char" => "uint8_t",
        other => other,
    }
}

pub fn normalize_type(raw: &str) -> String {
    let cleaned = strip_all_qualifiers(raw);
    let s = cleaned.as_str();
    if s.is_empty() {
        return String::new();
    }
    if !s.contains('<') {
        return normalize_primitive(s).to_string();
    }

    if s.starts_with("std::basic_string<") {
        return "std::string".to_string();
    }
    if s.starts_with("std::basic_string_view<") {
        return "std::string_view".to_string();
    }

    let idx = match s.find('<') {
        Some(i) => i,
        None => return s.to_string(),
    };

    let tpl_name = s[..idx].trim();
    let rest = &s[idx + 1..];

    let mut depth = 0;
    let mut close = None;
    for (i, c) in rest.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                if depth == 0 {
                    close = Some(i);
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
    }

    let close_idx = match close {
        Some(i) => i,
        None => return s.to_string(),
    };

    let inner = &rest[..close_idx];
    let args = extract_template_args(inner);
    let norm_args: Vec<String> = args.iter().map(|a| normalize_type(a)).collect();

    match tpl_name {
        "Utilities::StrongTypedef" => norm_args
            .first()
            .cloned()
            .unwrap_or_else(|| tpl_name.to_string()),
        "std::optional" | "std::vector" | "std::shared_ptr" | "std::unique_ptr" => {
            if let Some(first) = norm_args.first() {
                format!("{}<{}>", tpl_name, first)
            } else {
                tpl_name.to_string()
            }
        }
        "std::map" | "std::unordered_map" => {
            if norm_args.len() >= 2 {
                format!("{}<{}, {}>", tpl_name, norm_args[0], norm_args[1])
            } else {
                tpl_name.to_string()
            }
        }
        "Api::OneMe::Types::Polymorphic" => {
            if let Some(first) = norm_args.first() {
                format!("Api::OneMe::Types::Polymorphic<{}>", first)
            } else {
                tpl_name.to_string()
            }
        }
        _ => {
            format!("{}<{}>", tpl_name, norm_args.join(", "))
        }
    }
}

pub fn is_primitive_or_builtin_type(name: &str) -> bool {
    matches!(
        name,
        "bool"
            | "char"
            | "signed char"
            | "unsigned char"
            | "int8_t"
            | "uint8_t"
            | "int16_t"
            | "uint16_t"
            | "int32_t"
            | "uint32_t"
            | "int64_t"
            | "uint64_t"
            | "int"
            | "unsigned int"
            | "short"
            | "unsigned short"
            | "__int64"
            | "unsigned __int64"
            | "long long"
            | "unsigned long long"
            | "float"
            | "double"
            | "void"
            | "size_t"
            | "ptrdiff_t"
            | "std::string"
            | "std::string_view"
            | "std::byte"
    ) || name.starts_with("std::")
}

pub fn is_empty_endpoint_type(name: &str) -> bool {
    let trimmed = strip_qualifiers(name);
    if trimmed.is_empty() {
        return true;
    }
    let kind = trimmed.rsplit("::").next().unwrap_or(trimmed);
    matches!(
        kind,
        "EmptyResponse" | "EmptyParameters" | "NoParameters" | "EmptyData"
    )
}

const NAMESPACE_PREFIXES: &[&str] = &[
    "Api::OneMe::Packets::Events::",
    "Api::OneMe::Packets::",
    "Api::OneMe::Events::",
    "Api::OneMe::Types::",
    "Api::OneMe::",
    "Auth::OneMe::",
];

fn segment_to_pascal_case(seg: &str) -> String {
    let seg = seg.trim();
    if seg.is_empty() {
        return String::new();
    }
    if seg.contains('_') || seg.contains('-') {
        seg.split(['_', '-'])
            .filter(|part| !part.is_empty())
            .map(|part| {
                let mut chars = part.chars();
                match chars.next() {
                    Some(first) => {
                        let mut out = String::with_capacity(part.len());
                        out.push(first.to_ascii_uppercase());
                        out.push_str(chars.as_str());
                        out
                    }
                    None => String::new(),
                }
            })
            .collect()
    } else {
        let mut chars = seg.chars();
        match chars.next() {
            Some(first) if first.is_ascii_lowercase() => {
                let mut out = String::with_capacity(seg.len());
                out.push(first.to_ascii_uppercase());
                out.push_str(chars.as_str());
                out
            }
            _ => seg.to_string(),
        }
    }
}

fn cpp_to_ident_impl(cpp_name: &str, collapse_duplicates: bool) -> String {
    let cleaned = strip_all_qualifiers(cpp_name);
    let s = cleaned.as_str();
    if s.is_empty() {
        return String::new();
    }

    if s == "Api::OneMe::Types::Log::LogEventParams" {
        return "LogLogEventParams".to_string();
    }

    if let Some(idx) = s.find('<') {
        let base = &s[..idx];
        let rest = &s[idx + 1..];
        let mut depth = 0;
        let mut close = None;
        for (i, c) in rest.char_indices() {
            match c {
                '<' => depth += 1,
                '>' => {
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        if let Some(close_idx) = close {
            let inner = &rest[..close_idx];
            let args = extract_template_args(inner);
            let base_ident = cpp_to_ident_impl(base, collapse_duplicates);
            let args_ident: String = args
                .iter()
                .map(|a| cpp_to_ident_impl(a, collapse_duplicates))
                .collect();
            let tail = rest[close_idx + 1..].trim().trim_start_matches("::");
            let tail_ident = if tail.is_empty() {
                String::new()
            } else {
                cpp_to_ident_impl(tail, collapse_duplicates)
            };
            return format!("{base_ident}{args_ident}{tail_ident}");
        }
    }

    let mut body = s;
    for pfx in NAMESPACE_PREFIXES {
        if let Some(stripped) = body.strip_prefix(pfx) {
            body = stripped;
            break;
        }
    }

    let raw_segments: Vec<String> = body
        .split("::")
        .map(|seg| seg.trim())
        .filter(|seg| !seg.is_empty() && *seg != "OneMe")
        .map(segment_to_pascal_case)
        .filter(|seg| !seg.is_empty())
        .collect();

    if !collapse_duplicates {
        return raw_segments.join("");
    }

    let mut collapsed: Vec<String> = Vec::with_capacity(raw_segments.len());
    for seg in raw_segments {
        if let Some(prev) = collapsed.last_mut() {
            if seg == *prev {
                continue;
            }
            if seg.starts_with(prev.as_str()) {
                if let Some(next_ch) = seg[prev.len()..].chars().next() {
                    if next_ch.is_ascii_uppercase() || next_ch.is_ascii_digit() {
                        *prev = seg;
                        continue;
                    }
                }
            }
        }
        collapsed.push(seg);
    }

    collapsed.join("")
}

pub fn cpp_to_ident(cpp_name: &str) -> String {
    cpp_to_ident_impl(cpp_name, true)
}

pub fn cpp_to_ident_uncollapsed(cpp_name: &str) -> String {
    cpp_to_ident_impl(cpp_name, false)
}

fn strip_operation_suffixes(cpp_name: &str) -> String {
    let cleaned = strip_all_qualifiers(cpp_name);
    let mut s = cleaned.as_str();
    for suffix in &["::Parameters", "::Payload", "::Response", "::Request"] {
        if let Some(stripped) = s.strip_suffix(suffix) {
            s = stripped;
            break;
        }
    }
    for sub_suffix in &["::Common", "::StickerSet", "::AnimojiSet"] {
        if let Some(stripped) = s.strip_suffix(sub_suffix) {
            s = stripped;
            break;
        }
    }
    s.to_string()
}

fn derive_operation_from_endpoints(
    primary: &str,
    secondary: &str,
    fallback_prefix: &str,
    opcode: u32,
) -> (String, String) {
    let source = if !is_empty_endpoint_type(primary) {
        Some(primary)
    } else if !is_empty_endpoint_type(secondary) {
        Some(secondary)
    } else {
        None
    };

    if let Some(src) = source {
        let op_name = strip_operation_suffixes(src);
        let op_ident = cpp_to_ident(&op_name);
        (op_name, op_ident)
    } else {
        (
            format!("{fallback_prefix}::Opcode{opcode}"),
            format!("Opcode{opcode}"),
        )
    }
}

pub fn derive_packet_operation(opcode: u32, req_name: &str, resp_name: &str) -> (String, String) {
    derive_operation_from_endpoints(req_name, resp_name, "Api::OneMe::Packets", opcode)
}

pub fn derive_event_operation(
    opcode: u32,
    existing_name: Option<&str>,
    req_name: &str,
    resp_name: &str,
) -> (String, String) {
    if let Some(n) = existing_name {
        let cleaned = strip_all_qualifiers(n);
        if !cleaned.is_empty() {
            return (cleaned.clone(), cpp_to_ident(&cleaned));
        }
    }

    derive_operation_from_endpoints(resp_name, req_name, "Api::OneMe::Packets::Events", opcode)
}

pub fn qualify_endpoint_ident(parent_ident: &str, endpoint_cpp_name: &str) -> String {
    let desc_ident = cpp_to_ident(endpoint_cpp_name);
    if matches!(
        desc_ident.as_str(),
        "Parameters" | "Payload" | "Response" | "Request"
    ) && !parent_ident.is_empty()
    {
        format!("{parent_ident}{desc_ident}")
    } else {
        desc_ident
    }
}

pub fn extract_polymorphic_base(s: &str) -> Option<String> {
    let idx = s.find("Polymorphic<")?;
    let inner = &s[idx + "Polymorphic<".len()..];
    let args = extract_template_args(inner);
    let first = args.first()?;
    Some(normalize_type(first))
}

pub fn decompose_type(raw_type: &str) -> DecomposedType {
    let full = normalize_type(raw_type);
    let poly_base = extract_polymorphic_base(&full);

    let mut result = DecomposedType {
        full: full.clone(),
        name: Some(full.clone()),
        ident: None,
        optional: false,
        array: false,
        bytes: false,
        map: false,
        map_key: None,
        map_value: None,
        map_key_type: None,
        map_value_type: None,
        polymorphic: poly_base.is_some(),
        polymorphic_base: poly_base.clone(),
    };

    let mut current = full;
    for _ in 0..6 {
        let stripped = strip_qualifiers(&current);

        if stripped.starts_with("std::optional<") {
            if let Some(inner) = extract_inner_template(stripped, "std::optional") {
                result.optional = true;
                current = inner;
                continue;
            }
        }

        if stripped.starts_with("std::vector<") {
            if let Some(inner) = extract_inner_template(stripped, "std::vector") {
                result.array = true;
                current = inner;
                continue;
            }
        }

        if stripped.starts_with("std::shared_ptr<") {
            if let Some(inner) = extract_inner_template(stripped, "std::shared_ptr") {
                current = inner;
                continue;
            }
        }

        if stripped.starts_with("std::unique_ptr<") {
            if let Some(inner) = extract_inner_template(stripped, "std::unique_ptr") {
                current = inner;
                continue;
            }
        }

        if stripped.starts_with("Utilities::StrongTypedef<") {
            if let Some(inner) = extract_inner_template(stripped, "Utilities::StrongTypedef") {
                current = inner;
                continue;
            }
        }

        if stripped.starts_with("std::map<") || stripped.starts_with("std::unordered_map<") {
            let pfx = if stripped.starts_with("std::map<") {
                "std::map"
            } else {
                "std::unordered_map"
            };
            if let Some(inner) = extract_inner_template(stripped, pfx) {
                let args = extract_template_args(&inner);
                if args.len() >= 2 {
                    let key_norm = normalize_type(&args[0]);
                    let val_norm = normalize_type(&args[1]);
                    result.map = true;
                    result.map_key = Some(key_norm.clone());
                    result.map_value = Some(val_norm.clone());
                    result.map_key_type = Some(Box::new(decompose_type(&key_norm)));
                    result.map_value_type = Some(Box::new(decompose_type(&val_norm)));
                    result.name = None;
                    result.ident = None;
                    result.polymorphic = false;
                    result.polymorphic_base = None;
                    return result;
                }
            }
        }

        break;
    }

    if let Some(base) = poly_base {
        result.name = Some(base);
    } else {
        let norm = normalize_type(&current);
        result.name = if norm.is_empty() { None } else { Some(norm) };
    }

    result.bytes = result.array && matches!(result.name.as_deref(), Some("std::byte" | "char"));
    if let Some(ref leaf) = result.name {
        if !is_primitive_or_builtin_type(leaf) && !is_empty_endpoint_type(leaf) {
            let id = cpp_to_ident(leaf);
            if !id.is_empty() {
                result.ident = Some(id);
            }
        }
    }

    result
}
