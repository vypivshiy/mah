use crate::pe::PeImage;
use anyhow::Result;
use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct ClassHierarchy {
    pub base_to_derived: HashMap<String, Vec<String>>,
}

impl ClassHierarchy {
    pub fn derived_of(&self, base: &str) -> Option<&[String]> {
        self.base_to_derived.get(base).map(|v| v.as_slice())
    }
}

#[derive(Debug, Clone)]
pub struct TypeDescriptor {
    pub rva: u32,
    pub mangled_name: String,
    pub demangled_name: String,
}

#[derive(Debug, Clone, Copy)]
pub struct CompleteObjectLocator {
    pub rva: u32,
    pub signature: u32,
    pub offset: u32,
    pub cd_offset: u32,
    pub p_type_descriptor: u32,
    pub p_class_descriptor: u32,
    pub p_self: u32,
}

pub struct RttiEngine {
    pub type_descriptors: HashMap<u32, TypeDescriptor>,
    pub vtable_to_type: HashMap<u32, String>,
    pub type_to_vtable: HashMap<String, u32>,
    pub smember_vtables: HashMap<u32, String>,
    pub hierarchy: ClassHierarchy,
}

impl RttiEngine {
    pub fn build(pe: &PeImage) -> Result<Self> {
        let mut type_descriptors = HashMap::new();

        // 1. Scan .data and .rdata for TypeDescriptors
        for sec_name in &[".data", ".rdata"] {
            if let (Some(sec_data), Some(sec_info)) = (pe.section_data(sec_name), pe.section_by_name(sec_name)) {
                let mut pos = 0;
                while pos + 4 <= sec_data.len() {
                    let b = &sec_data[pos..pos + 4];
                    if b == b".?AV" || b == b".?AU" {
                        let string_rva = sec_info.virtual_address + pos as u32;
                        if string_rva >= 16 {
                            let td_rva = string_rva - 16;
                            if let Some(mangled) = pe.read_cstring(string_rva) {
                                if mangled.len() >= 4 && (mangled.starts_with(".?AV") || mangled.starts_with(".?AU")) {
                                    let demangled = demangle_type_name(mangled);
                                    type_descriptors.insert(
                                        td_rva,
                                        TypeDescriptor {
                                            rva: td_rva,
                                            mangled_name: mangled.to_string(),
                                            demangled_name: demangled,
                                        },
                                    );
                                }
                            }
                        }
                    }
                    pos += 1;
                }
            }
        }

        // 2. Scan .rdata for CompleteObjectLocators
        let mut col_map = HashMap::new();
        if let (Some(rdata), Some(rdata_sec)) = (pe.section_data(".rdata"), pe.section_by_name(".rdata")) {
            let mut pos = 0;
            while pos + 24 <= rdata.len() {
                let chunk = &rdata[pos..pos + 24];
                let sig = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
                let p_self = u32::from_le_bytes(chunk[20..24].try_into().unwrap());
                let col_rva = rdata_sec.virtual_address + pos as u32;

                if sig == 1 && p_self == col_rva {
                    let offset = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
                    let cd_offset = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
                    let p_td = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
                    let p_chd = u32::from_le_bytes(chunk[16..20].try_into().unwrap());

                    if type_descriptors.contains_key(&p_td) {
                        col_map.insert(
                            col_rva,
                            CompleteObjectLocator {
                                rva: col_rva,
                                signature: sig,
                                offset,
                                cd_offset,
                                p_type_descriptor: p_td,
                                p_class_descriptor: p_chd,
                                p_self,
                            },
                        );
                    }
                }
                pos += 4;
            }
        }

        // 3. Scan .rdata for pointers to CompleteObjectLocator (Vtable entry - 8)
        let mut vtable_to_type = HashMap::new();
        let mut type_to_vtable = HashMap::new();
        let mut smember_vtables = HashMap::new();

        if let (Some(rdata), Some(rdata_sec)) = (pe.section_data(".rdata"), pe.section_by_name(".rdata")) {
            let mut pos = 0;
            while pos + 8 <= rdata.len() {
                let ptr = u64::from_le_bytes(rdata[pos..pos + 8].try_into().unwrap());
                if ptr >= pe.image_base {
                    let target_rva = (ptr - pe.image_base) as u32;
                    if let Some(col) = col_map.get(&target_rva) {
                        if let Some(td) = type_descriptors.get(&col.p_type_descriptor) {
                            let vtable_rva = rdata_sec.virtual_address + pos as u32 + 8;
                            let demangled = &td.demangled_name;
                            vtable_to_type.insert(vtable_rva, demangled.clone());
                            type_to_vtable.entry(demangled.clone()).or_insert(vtable_rva);

                            if let Some(inner_t) = extract_smember_type(demangled, &td.mangled_name) {
                                smember_vtables.insert(vtable_rva, inner_t);
                            }
                        }
                    }
                }
                pos += 8;
            }
        }

        // 4. Build class hierarchy from ClassHierarchyDescriptor
        let mut hierarchy = ClassHierarchy::default();
        for col in col_map.values() {
            if col.p_class_descriptor == 0 {
                continue;
            }
            let derived_td = match type_descriptors.get(&col.p_type_descriptor) {
                Some(t) => t,
                None => continue,
            };

            // Read _RTTIClassHierarchyDescriptor
            // struct { u32 signature; u32 attributes; u32 num_base_classes; u32 p_base_class_array; }
            if let Some(chd_bytes) = pe.slice_at_rva(col.p_class_descriptor, 16) {
                let num_base_classes = u32::from_le_bytes(chd_bytes[8..12].try_into().unwrap());
                let p_base_class_array = u32::from_le_bytes(chd_bytes[12..16].try_into().unwrap());

                if p_base_class_array != 0 && num_base_classes > 1 && num_base_classes < 100 {
                    let bca_len = (num_base_classes as usize) * 4;
                    if let Some(bca_bytes) = pe.slice_at_rva(p_base_class_array, bca_len) {
                        for i in 0..num_base_classes as usize {
                            let bcd_rva = u32::from_le_bytes(
                                bca_bytes[i * 4..(i + 1) * 4].try_into().unwrap(),
                            );
                            if let Some(bcd_bytes) = pe.slice_at_rva(bcd_rva, 4) {
                                let base_td_rva =
                                    u32::from_le_bytes(bcd_bytes[0..4].try_into().unwrap());
                                if let Some(base_td) = type_descriptors.get(&base_td_rva) {
                                    if base_td.demangled_name != derived_td.demangled_name {
                                        let list = hierarchy
                                            .base_to_derived
                                            .entry(base_td.demangled_name.clone())
                                            .or_default();
                                        if !list.contains(&derived_td.demangled_name) {
                                            list.push(derived_td.demangled_name.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(RttiEngine {
            type_descriptors,
            vtable_to_type,
            type_to_vtable,
            smember_vtables,
            hierarchy,
        })
    }
}

pub fn demangle_type_name(mangled: &str) -> String {
    if mangled.len() < 4 {
        return mangled.to_string();
    }
    // Convert .?AV... to ??_R0?AV...@8
    let r0_symbol = format!("??_R0{}@8", &mangled[1..]);
    if let Ok(dem) = msvc_demangler::demangle(&r0_symbol, msvc_demangler::DemangleFlags::COMPLETE) {
        clean_demangled_rtti_name(&dem)
    } else {
        // Fallback: strip .?AV / .?AU and reverse @ separated components
        let inner = &mangled[4..];
        let parts: Vec<&str> = inner.trim_end_matches('@').split('@').collect();
        let reversed: Vec<&str> = parts.into_iter().rev().collect();
        reversed.join("::")
    }
}

pub fn clean_demangled_rtti_name(s: &str) -> String {
    let mut clean = s;
    // Strip trailing ::`RTTI Type Descriptor'
    if let Some(pos) = clean.rfind("::`RTTI Type Descriptor'") {
        clean = &clean[..pos];
    }
    // Strip leading struct/class/union/enum
    for prefix in &["class ", "struct ", "union ", "enum "] {
        if clean.starts_with(prefix) {
            clean = &clean[prefix.len()..];
            break;
        }
    }
    // Normalize basic_string (both with and without leading class qualifier)
    let clean_str = clean.replace(
        "class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> >",
        "std::string",
    );
    let clean_str = clean_str.replace(
        "std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> >",
        "std::string",
    );
    let clean_str = clean_str.replace(
        "class std::basic_string_view<char,struct std::char_traits<char> >",
        "std::string_view",
    );
    clean_str.replace(
        "std::basic_string_view<char,struct std::char_traits<char> >",
        "std::string_view",
    )
}

pub fn extract_smember_type(demangled: &str, mangled: &str) -> Option<String> {
    if let Some(start) = demangled.find("SerializableMember<") {
        // Skip ISerializableMember
        if start == 0 || !demangled[..start].ends_with('I') {
            let inner = &demangled[start + "SerializableMember<".len()..];
            if let Some(first_arg) = extract_first_template_argument(inner) {
                let cleaned = clean_demangled_rtti_name(&first_arg);
                if !cleaned.contains("SerializedType") && !cleaned.contains("ISerializableMember") {
                    return Some(cleaned);
                }
            }
        }
    }
    if let Some(pos) = mangled.find("?$SerializableMember@") {
        // Skip ?$ISerializableMember@
        if pos == 0 || !mangled[..pos].ends_with('I') {
            let inner = &mangled[pos + "?$SerializableMember@".len()..];
            // Format as RTTI TypeDescriptor symbol
            let r0_symbol = format!("??_R0{}@8", inner);
            if let Ok(dem) = msvc_demangler::demangle(&r0_symbol, msvc_demangler::DemangleFlags::COMPLETE) {
                let cleaned = clean_demangled_rtti_name(&dem);
                if !cleaned.contains("SerializedType") && !cleaned.contains("ISerializableMember") {
                    return Some(cleaned);
                }
            }
        }
    }
    None
}

pub fn extract_first_template_argument(s: &str) -> Option<String> {
    let mut depth = 0;
    let mut end = 0;
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                if depth == 0 {
                    end = i;
                    break;
                }
                depth -= 1;
            }
            ',' => {
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }
    if end > 0 {
        Some(s[..end].trim().to_string())
    } else {
        None
    }
}
