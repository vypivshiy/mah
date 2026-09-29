use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

use crate::pe::PeImage;

/// Form of the static 24-byte record in `.rdata`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EnumTableForm {
    /// Form A: `std::pair<std::string_view, uint64_t>` (8 bytes ptr, 8 bytes len, 8 bytes val)
    FormA,
    /// Form B: `std::pair<uint64_t, std::string_view>` (8 bytes val, 8 bytes ptr, 8 bytes len)
    FormB,
}

/// A raw entry parsed from a 24-byte record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEnumEntry {
    pub name: String,
    pub value: u64,
}

/// A contiguous run of valid 24-byte records discovered in `.rdata`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEnumTable {
    pub form: EnumTableForm,
    pub rva_start: u32,
    pub rva_end: u32,
    pub entries: Vec<RawEnumEntry>,
}

/// A categorized domain enum table with unique name-to-value mappings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredEnumTable {
    pub category: String,
    pub form: EnumTableForm,
    pub rva_start: u32,
    pub rva_end: u32,
    pub entries: BTreeMap<String, u64>,
}

/// Typed enum catalog mapping category name -> (string key -> numeric ID).
pub type StaticEnumCatalog = BTreeMap<String, BTreeMap<String, u64>>;

/// Maximum string length for an enum identifier.
pub const MAX_ENUM_STRING_LEN: usize = 256;

/// Maximum plausible numeric value for an enum identifier in tables.
pub const MAX_ENUM_VALUE: u64 = 100_000;

/// Resolves an in-image string literal by virtual address (VA) and length.
pub fn resolve_pe_string<'a>(pe: &'a PeImage<'a>, va: u64, len: usize) -> Option<String> {
    if len == 0 || len > MAX_ENUM_STRING_LEN || va < pe.image_base {
        return None;
    }
    let rva = (va - pe.image_base) as u64;
    if rva > u32::MAX as u64 {
        return None;
    }
    let slice = pe.slice_at_rva(rva as u32, len)?;
    if is_valid_enum_string_bytes(slice) {
        String::from_utf8(slice.to_vec()).ok()
    } else {
        None
    }
}

/// Checks whether a byte slice contains valid printable ASCII enum identifier characters.
#[inline]
pub fn is_valid_enum_string_bytes(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > MAX_ENUM_STRING_LEN {
        return false;
    }
    bytes.iter().all(|&b| b >= 0x20 && b <= 0x7E)
}

/// Creates a string resolver for a synthetic memory buffer.
pub fn create_buffer_string_resolver<'a>(
    buffer: &'a [u8],
    buffer_rva: u32,
    image_base: u64,
) -> impl Fn(u64, usize) -> Option<String> + 'a {
    move |va: u64, len: usize| {
        if len == 0 || len > MAX_ENUM_STRING_LEN || va < image_base {
            return None;
        }
        let rva = (va - image_base) as u64;
        let buf_start = buffer_rva as u64;
        let buf_end = buf_start + buffer.len() as u64;
        if rva < buf_start || rva + (len as u64) > buf_end {
            return None;
        }
        let offset = (rva - buf_start) as usize;
        let slice = &buffer[offset..offset + len];
        if is_valid_enum_string_bytes(slice) {
            String::from_utf8(slice.to_vec()).ok()
        } else {
            None
        }
    }
}

/// Scans a contiguous sequence of 24-byte records starting at `offset` for a given form.
pub fn scan_table_at<F>(
    data: &[u8],
    offset: usize,
    rdata_rva: u32,
    form: EnumTableForm,
    resolver: &F,
) -> Option<RawEnumTable>
where
    F: Fn(u64, usize) -> Option<String>,
{
    let mut entries = Vec::new();
    let mut curr = offset;

    while curr + 24 <= data.len() {
        let chunk = &data[curr..curr + 24];
        let v0 = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let v1 = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        let v2 = u64::from_le_bytes(chunk[16..24].try_into().unwrap());

        let (str_ptr, str_len, value) = match form {
            EnumTableForm::FormA => (v0, v1 as usize, v2),
            EnumTableForm::FormB => (v1, v2 as usize, v0),
        };

        if value >= MAX_ENUM_VALUE {
            break;
        }

        if str_len == 0 || str_len > MAX_ENUM_STRING_LEN {
            break;
        }

        let name = match resolver(str_ptr, str_len) {
            Some(s) => s,
            None => break,
        };

        entries.push(RawEnumEntry { name, value });
        curr += 24;
    }

    if entries.is_empty() {
        None
    } else {
        Some(RawEnumTable {
            form,
            rva_start: rdata_rva + offset as u32,
            rva_end: rdata_rva + curr as u32,
            entries,
        })
    }
}

/// Default domain categorizer mapping recognized tables to canonical categories.
pub fn default_categorizer(entries: &[(String, u64)], form: EnumTableForm) -> Option<String> {
    match form {
        EnumTableForm::FormA => {
            // ServerErrorCodes: e.g. call.blocked -> 6, privacy.violation -> 5
            let has_call_blocked = entries.iter().any(|(k, v)| k == "call.blocked" && *v == 6);
            let has_privacy_violation = entries.iter().any(|(k, v)| k == "privacy.violation" && *v == 5);
            let has_known_names = entries.iter().any(|(k, _)| {
                k == "call.blocked"
                    || k == "privacy.violation"
                    || k == "user.blocked"
                    || k == "not.chat.participant"
                    || k == "wait.for.admin"
            });
            let mostly_dot_keys = entries.len() >= 3
                && entries.iter().filter(|(k, _)| k.contains('.') && !k.contains('/')).count() * 2 >= entries.len();

            if has_call_blocked || has_privacy_violation || (has_known_names && mostly_dot_keys) {
                return Some("ServerErrorCodes".to_string());
            }
        }
        EnumTableForm::FormB => {
            // UserSettings: e.g. userSettings/showReadmark -> 0, notifications/..., statistic/...
            let has_user_settings_show = entries.iter().any(|(k, v)| k == "userSettings/showReadmark" && *v == 0);
            let has_user_settings_keys = entries.iter().any(|(k, _)| k.starts_with("userSettings/"));
            if has_user_settings_show || has_user_settings_keys {
                return Some("UserSettings".to_string());
            }

            // CallProblems: e.g. AUDIO_FREEZES -> 1, USERS_FREEZES -> 10
            let has_audio_freezes = entries.iter().any(|(k, v)| k == "AUDIO_FREEZES" && *v == 1);
            let has_users_freezes = entries.iter().any(|(k, v)| k == "USERS_FREEZES" && *v == 10);
            let has_call_problems_keys = entries.iter().any(|(k, _)| {
                k == "AUDIO_FREEZES"
                    || k == "VIDEO_FREEZES"
                    || k == "AUDIO_QUALITY"
                    || k == "VOICE_COMMUNICATION_PROBLEM"
            });
            if has_audio_freezes || has_users_freezes || has_call_problems_keys {
                return Some("CallProblems".to_string());
            }
        }
    }
    None
}

/// Scans raw memory buffer representing `.rdata` and discovers categorized enum tables.
pub fn extract_static_enum_tables_from_buffer<F, C>(
    rdata: &[u8],
    rdata_rva: u32,
    _image_base: u64,
    resolve_string: F,
    categorizer: C,
) -> Vec<DiscoveredEnumTable>
where
    F: Fn(u64, usize) -> Option<String>,
    C: Fn(&[(String, u64)], EnumTableForm) -> Option<String>,
{
    let mut discovered = Vec::new();
    let mut off = 0;

    while off + 24 <= rdata.len() {
        let mut matched = None;

        for &form in &[EnumTableForm::FormA, EnumTableForm::FormB] {
            if let Some(table) = scan_table_at(rdata, off, rdata_rva, form, &resolve_string) {
                if table.entries.len() >= 3 {
                    let entry_tuples: Vec<(String, u64)> = table
                        .entries
                        .iter()
                        .map(|e| (e.name.clone(), e.value))
                        .collect();
                    if let Some(category) = categorizer(&entry_tuples, form) {
                        let mut entries_map = BTreeMap::new();
                        for e in table.entries {
                            entries_map.insert(e.name, e.value);
                        }
                        matched = Some((
                            DiscoveredEnumTable {
                                category,
                                form,
                                rva_start: table.rva_start,
                                rva_end: table.rva_end,
                                entries: entries_map,
                            },
                            (table.rva_end - rdata_rva) as usize,
                        ));
                        break;
                    }
                }
            }
        }

        if let Some((table, end_offset)) = matched {
            discovered.push(table);
            off = end_offset;
        } else {
            off += 8;
        }
    }

    discovered
}

/// Discovers categorized static enum tables in a parsed PE image.
pub fn extract_static_enum_tables(pe: &PeImage) -> Vec<DiscoveredEnumTable> {
    let rdata_sec = match pe.section_by_name(".rdata") {
        Some(s) => s,
        None => return Vec::new(),
    };
    let rdata_data = match pe.section_data(".rdata") {
        Some(d) => d,
        None => return Vec::new(),
    };
    let rdata_rva = rdata_sec.virtual_address;
    let image_base = pe.image_base;

    let resolver = |va: u64, len: usize| resolve_pe_string(pe, va, len);

    extract_static_enum_tables_from_buffer(
        rdata_data,
        rdata_rva,
        image_base,
        resolver,
        default_categorizer,
    )
}

/// Extracts static enum tables and populates a typed catalog: category -> (identifier -> integer ID).
pub fn extract_static_enums(pe: &PeImage) -> StaticEnumCatalog {
    let tables = extract_static_enum_tables(pe);
    let mut catalog = BTreeMap::new();
    for table in tables {
        catalog.insert(table.category, table.entries);
    }
    catalog
}

/// Extracts static enum tables from a raw buffer into a typed catalog using custom categorizer.
pub fn extract_static_enums_from_buffer<F, C>(
    rdata: &[u8],
    rdata_rva: u32,
    image_base: u64,
    resolve_string: F,
    categorizer: C,
) -> StaticEnumCatalog
where
    F: Fn(u64, usize) -> Option<String>,
    C: Fn(&[(String, u64)], EnumTableForm) -> Option<String>,
{
    let tables = extract_static_enum_tables_from_buffer(
        rdata,
        rdata_rva,
        image_base,
        resolve_string,
        categorizer,
    );
    let mut catalog = BTreeMap::new();
    for table in tables {
        catalog.insert(table.category, table.entries);
    }
    catalog
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthetic_form_a_server_error_codes() {
        let image_base = 0x180000000u64;
        let rdata_rva = 0x1000u32;
        let mut buffer = vec![0u8; 1024];

        // Place string literals at offset 0x00
        let s1 = b"call.blocked\0";
        let s2 = b"privacy.violation\0";
        let s3 = b"limit.reached\0";

        let s1_off = 0x00;
        let s2_off = s1_off + s1.len();
        let s3_off = s2_off + s2.len();

        buffer[s1_off..s1_off + s1.len()].copy_from_slice(s1);
        buffer[s2_off..s2_off + s2.len()].copy_from_slice(s2);
        buffer[s3_off..s3_off + s3.len()].copy_from_slice(s3);

        let s1_va = image_base + rdata_rva as u64 + s1_off as u64;
        let s2_va = image_base + rdata_rva as u64 + s2_off as u64;
        let s3_va = image_base + rdata_rva as u64 + s3_off as u64;

        // Place Form A table at offset 0x80 (24-byte records: ptr, len, val)
        let table_off = 0x80;
        let entries = [
            (s1_va, (s1.len() - 1) as u64, 6u64),
            (s2_va, (s2.len() - 1) as u64, 5u64),
            (s3_va, (s3.len() - 1) as u64, 7u64),
        ];

        for (i, &(ptr, len, val)) in entries.iter().enumerate() {
            let entry_off = table_off + i * 24;
            buffer[entry_off..entry_off + 8].copy_from_slice(&ptr.to_le_bytes());
            buffer[entry_off + 8..entry_off + 16].copy_from_slice(&len.to_le_bytes());
            buffer[entry_off + 16..entry_off + 24].copy_from_slice(&val.to_le_bytes());
        }

        // Test scan_table_at
        let resolver = create_buffer_string_resolver(&buffer, rdata_rva, image_base);
        let raw_table = scan_table_at(&buffer, table_off, rdata_rva, EnumTableForm::FormA, &resolver)
            .expect("Should discover raw Form A table");

        assert_eq!(raw_table.form, EnumTableForm::FormA);
        assert_eq!(raw_table.rva_start, rdata_rva + table_off as u32);
        assert_eq!(raw_table.rva_end, rdata_rva + table_off as u32 + 3 * 24);
        assert_eq!(raw_table.entries.len(), 3);
        assert_eq!(raw_table.entries[0].name, "call.blocked");
        assert_eq!(raw_table.entries[0].value, 6);
        assert_eq!(raw_table.entries[1].name, "privacy.violation");
        assert_eq!(raw_table.entries[1].value, 5);
        assert_eq!(raw_table.entries[2].name, "limit.reached");
        assert_eq!(raw_table.entries[2].value, 7);

        // Test categorized extraction
        let catalog = extract_static_enums_from_buffer(
            &buffer,
            rdata_rva,
            image_base,
            resolver,
            default_categorizer,
        );

        assert_eq!(catalog.len(), 1);
        let errors = catalog.get("ServerErrorCodes").expect("ServerErrorCodes must be present");
        assert_eq!(errors.get("call.blocked"), Some(&6));
        assert_eq!(errors.get("privacy.violation"), Some(&5));
        assert_eq!(errors.get("limit.reached"), Some(&7));
    }

    #[test]
    fn test_synthetic_form_b_user_settings_and_call_problems() {
        let image_base = 0x180000000u64;
        let rdata_rva = 0x2000u32;
        let mut buffer = vec![0u8; 2048];

        // Strings for UserSettings
        let us1 = b"userSettings/showReadmark\0";
        let us2 = b"userSettings/incomingCall\0";
        let us3 = b"userSettings/chatInvite\0";

        let us1_off = 0x00;
        let us2_off = us1_off + us1.len();
        let us3_off = us2_off + us2.len();
        buffer[us1_off..us1_off + us1.len()].copy_from_slice(us1);
        buffer[us2_off..us2_off + us2.len()].copy_from_slice(us2);
        buffer[us3_off..us3_off + us3.len()].copy_from_slice(us3);

        let us1_va = image_base + rdata_rva as u64 + us1_off as u64;
        let us2_va = image_base + rdata_rva as u64 + us2_off as u64;
        let us3_va = image_base + rdata_rva as u64 + us3_off as u64;

        // Strings for CallProblems
        let cp1 = b"AUDIO_FREEZES\0";
        let cp2 = b"AUDIO_CALL_INTERRUPTION\0";
        let cp3 = b"USERS_FREEZES\0";

        let cp1_off = 0x100;
        let cp2_off = cp1_off + cp1.len();
        let cp3_off = cp2_off + cp2.len();
        buffer[cp1_off..cp1_off + cp1.len()].copy_from_slice(cp1);
        buffer[cp2_off..cp2_off + cp2.len()].copy_from_slice(cp2);
        buffer[cp3_off..cp3_off + cp3.len()].copy_from_slice(cp3);

        let cp1_va = image_base + rdata_rva as u64 + cp1_off as u64;
        let cp2_va = image_base + rdata_rva as u64 + cp2_off as u64;
        let cp3_va = image_base + rdata_rva as u64 + cp3_off as u64;

        // Table 1 (UserSettings, Form B at 0x200): val, ptr, len
        let us_table_off = 0x200;
        let us_entries = [
            (0u64, us1_va, (us1.len() - 1) as u64),
            (1u64, us2_va, (us2.len() - 1) as u64),
            (2u64, us3_va, (us3.len() - 1) as u64),
        ];
        for (i, &(val, ptr, len)) in us_entries.iter().enumerate() {
            let entry_off = us_table_off + i * 24;
            buffer[entry_off..entry_off + 8].copy_from_slice(&val.to_le_bytes());
            buffer[entry_off + 8..entry_off + 16].copy_from_slice(&ptr.to_le_bytes());
            buffer[entry_off + 16..entry_off + 24].copy_from_slice(&len.to_le_bytes());
        }

        // Table 2 (CallProblems, Form B at 0x300): val, ptr, len
        let cp_table_off = 0x300;
        let cp_entries = [
            (1u64, cp1_va, (cp1.len() - 1) as u64),
            (2u64, cp2_va, (cp2.len() - 1) as u64),
            (10u64, cp3_va, (cp3.len() - 1) as u64),
        ];
        for (i, &(val, ptr, len)) in cp_entries.iter().enumerate() {
            let entry_off = cp_table_off + i * 24;
            buffer[entry_off..entry_off + 8].copy_from_slice(&val.to_le_bytes());
            buffer[entry_off + 8..entry_off + 16].copy_from_slice(&ptr.to_le_bytes());
            buffer[entry_off + 16..entry_off + 24].copy_from_slice(&len.to_le_bytes());
        }

        let resolver = create_buffer_string_resolver(&buffer, rdata_rva, image_base);
        let catalog = extract_static_enums_from_buffer(
            &buffer,
            rdata_rva,
            image_base,
            resolver,
            default_categorizer,
        );

        assert_eq!(catalog.len(), 2);

        let user_settings = catalog.get("UserSettings").expect("UserSettings category");
        assert_eq!(user_settings.get("userSettings/showReadmark"), Some(&0));
        assert_eq!(user_settings.get("userSettings/incomingCall"), Some(&1));
        assert_eq!(user_settings.get("userSettings/chatInvite"), Some(&2));

        let call_problems = catalog.get("CallProblems").expect("CallProblems category");
        assert_eq!(call_problems.get("AUDIO_FREEZES"), Some(&1));
        assert_eq!(call_problems.get("AUDIO_CALL_INTERRUPTION"), Some(&2));
        assert_eq!(call_problems.get("USERS_FREEZES"), Some(&10));
    }

    #[test]
    fn test_string_pointer_validation_and_rejection() {
        let image_base = 0x180000000u64;
        let rdata_rva = 0x1000u32;
        let mut buffer = vec![0u8; 512];

        // Valid string at offset 0
        let s = b"valid.identifier\0";
        buffer[..s.len()].copy_from_slice(s);
        let valid_va = image_base + rdata_rva as u64;

        // Non-ASCII / control bytes at offset 0x50
        let bad_bytes = b"bad\x01string\0";
        buffer[0x50..0x50 + bad_bytes.len()].copy_from_slice(bad_bytes);
        let bad_va = image_base + rdata_rva as u64 + 0x50;

        let resolver = create_buffer_string_resolver(&buffer, rdata_rva, image_base);

        // 1. Valid pointer
        assert_eq!(
            resolver(valid_va, s.len() - 1),
            Some("valid.identifier".to_string())
        );

        // 2. Out of bounds pointer
        assert_eq!(resolver(valid_va + 99999, 10), None);

        // 3. Null pointer (0)
        assert_eq!(resolver(0, 10), None);

        // 4. Below image base
        assert_eq!(resolver(0x1000, 10), None);

        // 5. Zero length
        assert_eq!(resolver(valid_va, 0), None);

        // 6. Excessive length (> 256)
        assert_eq!(resolver(valid_va, 300), None);

        // 7. Non-ASCII / control bytes
        assert_eq!(resolver(bad_va, bad_bytes.len() - 1), None);
    }

    #[test]
    fn test_table_boundary_detection_stops_on_padding() {
        let image_base = 0x180000000u64;
        let rdata_rva = 0x1000u32;
        let mut buffer = vec![0u8; 512];

        let s1 = b"call.blocked\0";
        let s2 = b"privacy.violation\0";
        let s3 = b"limit.reached\0";

        buffer[0..s1.len()].copy_from_slice(s1);
        buffer[20..20 + s2.len()].copy_from_slice(s2);
        buffer[40..40 + s3.len()].copy_from_slice(s3);

        let va1 = image_base + rdata_rva as u64;
        let va2 = image_base + rdata_rva as u64 + 20;
        let va3 = image_base + rdata_rva as u64 + 40;

        let table_off = 0x60;
        let entries = [
            (va1, (s1.len() - 1) as u64, 6u64),
            (va2, (s2.len() - 1) as u64, 5u64),
            (va3, (s3.len() - 1) as u64, 7u64),
        ];
        for (i, &(ptr, len, val)) in entries.iter().enumerate() {
            let entry_off = table_off + i * 24;
            buffer[entry_off..entry_off + 8].copy_from_slice(&ptr.to_le_bytes());
            buffer[entry_off + 8..entry_off + 16].copy_from_slice(&len.to_le_bytes());
            buffer[entry_off + 16..entry_off + 24].copy_from_slice(&val.to_le_bytes());
        }

        // Buffer after 3 entries is zeroes (padding)
        let resolver = create_buffer_string_resolver(&buffer, rdata_rva, image_base);
        let table = scan_table_at(&buffer, table_off, rdata_rva, EnumTableForm::FormA, &resolver)
            .expect("table");

        assert_eq!(table.entries.len(), 3);
        assert_eq!(table.rva_start, rdata_rva + table_off as u32);
        assert_eq!(table.rva_end, rdata_rva + table_off as u32 + 3 * 24);
    }

    #[test]
    fn test_phantom_disambiguation_does_not_categorize_shifted_table() {
        let image_base = 0x180000000u64;
        let rdata_rva = 0x1000u32;
        let mut buffer = vec![0u8; 1024];

        let s1 = b"call.blocked\0";
        let s2 = b"privacy.violation\0";
        let s3 = b"limit.reached\0";

        buffer[0..s1.len()].copy_from_slice(s1);
        buffer[20..20 + s2.len()].copy_from_slice(s2);
        buffer[40..40 + s3.len()].copy_from_slice(s3);

        let va1 = image_base + rdata_rva as u64;
        let va2 = image_base + rdata_rva as u64 + 20;
        let va3 = image_base + rdata_rva as u64 + 40;

        // Precede table with 8 bytes of zero at 0x78
        // Form A table starts at 0x80:
        let table_off = 0x80;
        let entries = [
            (va1, (s1.len() - 1) as u64, 6u64),
            (va2, (s2.len() - 1) as u64, 5u64),
            (va3, (s3.len() - 1) as u64, 7u64),
        ];
        for (i, &(ptr, len, val)) in entries.iter().enumerate() {
            let entry_off = table_off + i * 24;
            buffer[entry_off..entry_off + 8].copy_from_slice(&ptr.to_le_bytes());
            buffer[entry_off + 8..entry_off + 16].copy_from_slice(&len.to_le_bytes());
            buffer[entry_off + 16..entry_off + 24].copy_from_slice(&val.to_le_bytes());
        }

        let resolver = create_buffer_string_resolver(&buffer, rdata_rva, image_base);

        // At 0x78 (offset - 8), Form B can parse 2 entries:
        // [0, va1, len1], [6, va2, len2]
        // But ServerErrorCodes requires Form A!
        let discovered = extract_static_enum_tables_from_buffer(
            &buffer,
            rdata_rva,
            image_base,
            resolver,
            default_categorizer,
        );

        // Exactly ONE table discovered at 0x80 (Form A), not phantom at 0x78
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].category, "ServerErrorCodes");
        assert_eq!(discovered[0].form, EnumTableForm::FormA);
        assert_eq!(discovered[0].rva_start, rdata_rva + 0x80);
    }
}
