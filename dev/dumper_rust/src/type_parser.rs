use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecomposedType {
    pub full: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub optional: bool,
    pub array: bool,
    pub map: bool,
    pub map_key: Option<String>,
    pub map_value: Option<String>,
    pub polymorphic: bool,
    pub polymorphic_base: Option<String>,
}

const QUALIFIERS: &[&str] = &["class ", "struct ", "enum ", "const ", "volatile "];

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
    let s = strip_qualifiers(raw);
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

    let tpl_name = strip_qualifiers(&s[..idx]);
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
        optional: false,
        array: false,
        map: false,
        map_key: None,
        map_value: None,
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
                    result.map = true;
                    result.map_key = Some(normalize_type(&args[0]));
                    result.map_value = Some(normalize_type(&args[1]));
                    result.name = None;
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

    result
}
