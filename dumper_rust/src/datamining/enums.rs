use std::collections::{BTreeMap, HashMap};
use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};

use crate::pe::PeImage;

/// Form of the static 24-byte record in `.rdata`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EnumTableForm {
    /// String key first: `std::pair<std::string_view, uint64_t>` (8 bytes ptr, 8 bytes len, 8 bytes val)
    StringKeyFirst,
    /// Value first: `std::pair<uint64_t, std::string_view>` (8 bytes val, 8 bytes ptr, 8 bytes len)
    ValueFirst,
}

impl EnumTableForm {
    pub const ALL: [Self; 2] = [Self::StringKeyFirst, Self::ValueFirst];

    /// Extracts (str_ptr, str_len, value) from the 3 64-bit words of a 24-byte record.
    #[inline]
    pub fn parse_record(self, v0: u64, v1: u64, v2: u64) -> (u64, usize, u64) {
        match self {
            Self::StringKeyFirst => (v0, v1 as usize, v2),
            Self::ValueFirst => (v1, v2 as usize, v0),
        }
    }
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub defaults: BTreeMap<String, serde_json::Value>,
}

/// Typed enum catalog mapping category name -> (string key -> numeric ID).
pub type StaticEnumCatalog = BTreeMap<String, BTreeMap<String, u64>>;

/// Typed catalog mapping UserSettings string key -> default JSON value.
pub type UserSettingsDefaultsCatalog = BTreeMap<String, serde_json::Value>;

/// Maximum string length for an enum identifier.
pub const MAX_ENUM_STRING_LEN: usize = 256;

/// Maximum plausible numeric value for an enum identifier in tables.
pub const MAX_ENUM_VALUE: u64 = 100_000;

/// Resolves an in-image string literal by virtual address (VA) and length.
pub fn resolve_pe_string<'a>(pe: &'a PeImage<'a>, va: u64, len: usize) -> Option<String> {
    if len == 0 || len > MAX_ENUM_STRING_LEN || va < pe.image_base {
        return None;
    }
    let rva = va - pe.image_base;
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
    bytes.iter().all(|&b| (0x20..=0x7E).contains(&b))
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
        let rva = va - image_base;
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

        let (str_ptr, str_len, value) = form.parse_record(v0, v1, v2);

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

fn categorize_server_error_codes(entries: &[(String, u64)]) -> bool {
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

    has_call_blocked || has_privacy_violation || (has_known_names && mostly_dot_keys)
}

fn categorize_user_settings(entries: &[(String, u64)]) -> bool {
    // UserSettings: e.g. userSettings/showReadmark -> 0, notifications/..., statistic/...
    let has_user_settings_show = entries.iter().any(|(k, v)| k == "userSettings/showReadmark" && *v == 0);
    let has_user_settings_keys = entries.iter().any(|(k, _)| k.starts_with("userSettings/"));
    has_user_settings_show || has_user_settings_keys
}

fn categorize_call_problems(entries: &[(String, u64)]) -> bool {
    // CallProblems: e.g. AUDIO_FREEZES -> 1, USERS_FREEZES -> 10
    let has_audio_freezes = entries.iter().any(|(k, v)| k == "AUDIO_FREEZES" && *v == 1);
    let has_users_freezes = entries.iter().any(|(k, v)| k == "USERS_FREEZES" && *v == 10);
    let has_call_problems_keys = entries.iter().any(|(k, _)| {
        k == "AUDIO_FREEZES"
            || k == "VIDEO_FREEZES"
            || k == "AUDIO_QUALITY"
            || k == "VOICE_COMMUNICATION_PROBLEM"
    });
    has_audio_freezes || has_users_freezes || has_call_problems_keys
}

/// Default domain categorizer mapping recognized tables to canonical categories.
pub fn default_categorizer(entries: &[(String, u64)], form: EnumTableForm) -> Option<String> {
    match form {
        EnumTableForm::StringKeyFirst => {
            if categorize_server_error_codes(entries) {
                Some("ServerErrorCodes".to_string())
            } else {
                None
            }
        }
        EnumTableForm::ValueFirst => {
            if categorize_user_settings(entries) {
                Some("UserSettings".to_string())
            } else if categorize_call_problems(entries) {
                Some("CallProblems".to_string())
            } else {
                None
            }
        }
    }
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

        for &form in &EnumTableForm::ALL {
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
                                defaults: BTreeMap::new(),
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

/// Resolves an in-image UTF-8 string literal (without control characters) by VA and length.
pub fn resolve_pe_utf8_string(pe: &PeImage, va: u64, len: usize) -> Option<String> {
    if len == 0 || len > MAX_ENUM_STRING_LEN || va < pe.image_base {
        return None;
    }
    let rva = va - pe.image_base;
    if rva > u32::MAX as u64 {
        return None;
    }
    let slice = pe.slice_at_rva(rva as u32, len)?;
    let s = std::str::from_utf8(slice).ok()?;
    if s.chars().all(|c| !c.is_control()) {
        Some(s.to_string())
    } else {
        None
    }
}

/// Classification of a `UserSettings` helper constructor's default value behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperDefaultKind {
    /// Entry constructor sets `has_value = 0` (`std::nullopt`).
    None,
    /// Entry constructor sets `variant_tag = tag` (`+0x68`) and `has_value = 1` (`+0x70`).
    Variant(u8),
}

#[derive(Debug, Clone, Copy)]
enum InitRegVal {
    Va(u64),
    Imm(u64),
    StackPtr(Register, i64),
}

#[derive(Debug, Clone)]
struct PendingInlinedEntry {
    name: String,
    value: u64,
    base: Register,
    entry_disp: i64,
}

#[inline]
fn is_immediate_op(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

#[inline]
fn insn_immediate_u64(insn: &Instruction) -> u64 {
    match insn.op1_kind() {
        OpKind::Immediate8 => insn.immediate8() as u64,
        OpKind::Immediate16 => insn.immediate16() as u64,
        OpKind::Immediate32 => insn.immediate32() as u64,
        OpKind::Immediate64 => insn.immediate64(),
        OpKind::Immediate8to16 => insn.immediate8to16() as i64 as u64,
        OpKind::Immediate8to32 => insn.immediate8to32() as i64 as u64,
        OpKind::Immediate8to64 => insn.immediate8to64() as u64,
        OpKind::Immediate32to64 => insn.immediate32to64() as u64,
        _ => 0,
    }
}

#[inline]
fn variant_default_to_json(tag: u8, raw_val: u64) -> Option<serde_json::Value> {
    match tag {
        5 => Some(serde_json::Value::Bool((raw_val & 0xFF) != 0)),
        2 | 3 | 4 => Some(serde_json::Value::Number((raw_val as i64).into())),
        _ => None,
    }
}

/// Classifies a `UserSettings` entry constructor helper function by inspecting its stores to `+0x68` and `+0x70`.
pub fn classify_user_settings_helper_ctor(pe: &PeImage, mut target_va: u64) -> Option<HelperDefaultKind> {
    for _ in 0..3 {
        if target_va < pe.image_base {
            return None;
        }
        let rva = (target_va - pe.image_base) as u32;
        let slice = pe.slice_at_rva(rva, 16)?;
        let mut dec = Decoder::with_ip(64, slice, target_va, DecoderOptions::NONE);
        if !dec.can_decode() {
            return None;
        }
        let insn = dec.decode();
        if insn.mnemonic() == Mnemonic::Jmp && insn.op0_kind() == OpKind::NearBranch64 {
            target_va = insn.near_branch64();
        } else {
            break;
        }
    }

    if target_va < pe.image_base {
        return None;
    }
    let rva = (target_va - pe.image_base) as u32;
    let slice = pe.slice_at_rva(rva, 128)?;
    let mut dec = Decoder::with_ip(64, slice, target_va, DecoderOptions::NONE);

    let mut tag_68: Option<u8> = None;
    let mut has_70: Option<u8> = None;
    let mut count = 0;

    while dec.can_decode() && count < 40 {
        let insn = dec.decode();
        count += 1;

        if insn.mnemonic() == Mnemonic::Mov
            && insn.op0_kind() == OpKind::Memory
            && is_immediate_op(insn.op1_kind())
        {
            let disp = insn.memory_displacement64() as i64;
            let imm = (insn_immediate_u64(&insn) & 0xFF) as u8;
            if disp == 0x68 {
                tag_68 = Some(imm);
            } else if disp == 0x70 {
                has_70 = Some(imm);
            }
        } else if insn.mnemonic() == Mnemonic::Ret {
            break;
        }
    }

    match (has_70, tag_68) {
        (Some(0), _) => Some(HelperDefaultKind::None),
        (Some(1), Some(tag)) => Some(HelperDefaultKind::Variant(tag)),
        _ => None,
    }
}

/// Decodes an x86-64 initializer function constructing `UserSettings` descriptors (120-byte records)
/// and returns `(name, numeric_id, optional_default_value)` tuples.
pub fn extract_user_settings_from_initializer_code<F, H>(
    code: &[u8],
    func_va: u64,
    resolve_string: F,
    classify_helper: H,
) -> Vec<(String, u64, Option<serde_json::Value>)>
where
    F: Fn(u64, usize) -> Option<String>,
    H: Fn(u64) -> Option<HelperDefaultKind>,
{
    let mut decoder = Decoder::with_ip(64, code, func_va, DecoderOptions::NONE);
    let mut reg_val: HashMap<Register, InitRegVal> = HashMap::new();
    let mut stack_qword: HashMap<(Register, i64), u64> = HashMap::new();
    let mut stack_byte: HashMap<(Register, i64), u8> = HashMap::new();
    let mut pending_inlined: Option<PendingInlinedEntry> = None;
    let mut results: Vec<(String, u64, Option<serde_json::Value>)> = Vec::new();

    let finalize_pending = |pending: PendingInlinedEntry,
                            stack_byte: &HashMap<(Register, i64), u8>,
                            stack_qword: &HashMap<(Register, i64), u64>,
                            results: &mut Vec<(String, u64, Option<serde_json::Value>)>| {
        let has_val = stack_byte
            .get(&(pending.base, pending.entry_disp + 0x70))
            .copied()
            .unwrap_or(0);
        let default_val = if has_val == 1 {
            let tag = stack_byte
                .get(&(pending.base, pending.entry_disp + 0x68))
                .copied()
                .unwrap_or(0);
            let raw = stack_qword
                .get(&(pending.base, pending.entry_disp + 0x28))
                .copied()
                .or_else(|| {
                    stack_byte
                        .get(&(pending.base, pending.entry_disp + 0x28))
                        .map(|&b| b as u64)
                })
                .unwrap_or(0);
            variant_default_to_json(tag, raw)
        } else {
            None
        };
        if !results.iter().any(|(k, _, _)| k == &pending.name) {
            results.push((pending.name, pending.value, default_val));
        }
    };

    while decoder.can_decode() {
        let mut insn = Instruction::default();
        decoder.decode_out(&mut insn);

        match insn.mnemonic() {
            Mnemonic::Lea => {
                let dest = insn.op0_register().full_register();
                if insn.op1_kind() == OpKind::Memory {
                    let base = insn.memory_base();
                    if base == Register::RIP {
                        reg_val.insert(dest, InitRegVal::Va(insn.memory_displacement64()));
                    } else if base == Register::RSP || base == Register::RBP {
                        reg_val.insert(
                            dest,
                            InitRegVal::StackPtr(base, insn.memory_displacement64() as i64),
                        );
                    } else {
                        reg_val.remove(&dest);
                    }
                } else {
                    reg_val.remove(&dest);
                }
            }
            Mnemonic::Mov | Mnemonic::Movzx => {
                if insn.op0_kind() == OpKind::Register {
                    let dest = insn.op0_register().full_register();
                    if insn.op1_kind() == OpKind::Register {
                        let src = insn.op1_register().full_register();
                        if let Some(&val) = reg_val.get(&src) {
                            reg_val.insert(dest, val);
                        } else {
                            reg_val.remove(&dest);
                        }
                    } else if is_immediate_op(insn.op1_kind()) {
                        reg_val.insert(dest, InitRegVal::Imm(insn_immediate_u64(&insn)));
                    } else {
                        reg_val.remove(&dest);
                    }
                } else if insn.op0_kind() == OpKind::Memory {
                    let base = insn.memory_base();
                    if base == Register::RSP || base == Register::RBP {
                        let disp = insn.memory_displacement64() as i64;
                        if insn.op1_kind() == OpKind::Register {
                            let src = insn.op1_register().full_register();
                            match reg_val.get(&src).copied() {
                                Some(InitRegVal::Va(va)) => {
                                    stack_qword.insert((base, disp), va);
                                }
                                Some(InitRegVal::Imm(v)) => {
                                    stack_qword.insert((base, disp), v);
                                    stack_byte.insert((base, disp), (v & 0xFF) as u8);
                                }
                                _ => {}
                            }
                        } else if is_immediate_op(insn.op1_kind()) {
                            let imm = insn_immediate_u64(&insn);
                            let mem_size = insn.memory_size();
                            if mem_size == MemorySize::UInt8
                                || mem_size == MemorySize::Int8
                                || insn.op1_kind() == OpKind::Immediate8
                            {
                                stack_byte.insert((base, disp), (imm & 0xFF) as u8);
                            } else {
                                stack_qword.insert((base, disp), imm);
                                stack_byte.insert((base, disp), (imm & 0xFF) as u8);
                            }
                        }
                    }
                }
            }
            Mnemonic::Xor | Mnemonic::Sub => {
                if insn.op0_kind() == OpKind::Register
                    && insn.op1_kind() == OpKind::Register
                    && insn.op0_register() == insn.op1_register()
                {
                    let dest = insn.op0_register().full_register();
                    reg_val.insert(dest, InitRegVal::Imm(0));
                } else if insn.op0_kind() == OpKind::Register {
                    reg_val.remove(&insn.op0_register().full_register());
                }
            }
            Mnemonic::Call => {
                if let Some(pending) = pending_inlined.take() {
                    finalize_pending(pending, &stack_byte, &stack_qword, &mut results);
                }

                let rcx_val = reg_val.get(&Register::RCX).copied();
                let rdx_val = reg_val.get(&Register::RDX).copied();
                let r8_val = reg_val.get(&Register::R8).copied();
                let r9_val = reg_val.get(&Register::R9).copied();

                match (rcx_val, rdx_val, r8_val) {
                    // Form 1: helper ctor `ctor(rcx = &entry, edx = id, r8 = &string_view, [r9 = default_val])`
                    (
                        Some(InitRegVal::StackPtr(_, _)),
                        Some(InitRegVal::Imm(id)),
                        Some(InitRegVal::StackPtr(sv_base, sv_disp)),
                    ) if id < MAX_ENUM_VALUE => {
                        if let (Some(&str_va), Some(&str_len)) = (
                            stack_qword.get(&(sv_base, sv_disp)),
                            stack_qword.get(&(sv_base, sv_disp + 8)),
                        ) {
                            if let Some(name) = resolve_string(str_va, str_len as usize) {
                                let default_val = if insn.op0_kind() == OpKind::NearBranch64 {
                                    match classify_helper(insn.near_branch64()) {
                                        Some(HelperDefaultKind::Variant(tag)) => {
                                            if let Some(InitRegVal::Imm(raw)) = r9_val {
                                                variant_default_to_json(tag, raw)
                                            } else {
                                                None
                                            }
                                        }
                                        _ => None,
                                    }
                                } else {
                                    None
                                };
                                if !results.iter().any(|(k, _, _)| k == &name) {
                                    results.push((name, id, default_val));
                                }
                            }
                        }
                    }
                    // Form 2: inlined `std::string::assign(rcx = &entry.key, rdx = str_va, r8 = str_len)`
                    (
                        Some(InitRegVal::StackPtr(e_base, rcx_disp)),
                        Some(InitRegVal::Va(str_va)),
                        Some(InitRegVal::Imm(str_len)),
                    ) => {
                        let entry_disp = rcx_disp - 8;
                        if let Some(&id) = stack_qword.get(&(e_base, entry_disp)) {
                            if id < MAX_ENUM_VALUE {
                                if let Some(name) = resolve_string(str_va, str_len as usize) {
                                    pending_inlined = Some(PendingInlinedEntry {
                                        name,
                                        value: id,
                                        base: e_base,
                                        entry_disp,
                                    });
                                }
                            }
                        }
                    }
                    _ => {}
                }

                for volatile in [
                    Register::RAX,
                    Register::RCX,
                    Register::RDX,
                    Register::R8,
                    Register::R9,
                    Register::R10,
                    Register::R11,
                ] {
                    reg_val.remove(&volatile);
                }
            }
            _ => {}
        }
    }

    if let Some(pending) = pending_inlined.take() {
        finalize_pending(pending, &stack_byte, &stack_qword, &mut results);
    }

    results
}

/// Locates and extracts the runtime-initialized `UserSettings` descriptor table (26.38.0+)
/// from the `.text` initializer function referencing `"userSettings/showReadmark"`.
pub fn extract_dynamic_user_settings_table(pe: &PeImage) -> Option<DiscoveredEnumTable> {
    const ANCHOR: &[u8] = b"userSettings/showReadmark\0";

    let rdata_sec = pe.section_by_name(".rdata")?;
    let rdata_data = pe.section_data(".rdata")?;
    let anchor_off = rdata_data
        .windows(ANCHOR.len())
        .position(|w| w == ANCHOR)?;
    let anchor_rva = rdata_sec.virtual_address + anchor_off as u32;

    let text_sec = pe.section_by_name(".text")?;
    let text_data = pe.section_data(".text")?;
    let text_rva = text_sec.virtual_address;

    let mut ref_insn_rva = None;
    if text_data.len() >= 7 {
        for i in 0..=(text_data.len() - 7) {
            if text_data[i + 1] == 0x8D && (text_data[i + 2] & 0xC7) == 0x05 {
                let disp = i32::from_le_bytes(text_data[i + 3..i + 7].try_into().unwrap());
                let next_rva = (text_rva + i as u32 + 7) as i64;
                if next_rva + (disp as i64) == anchor_rva as i64 {
                    ref_insn_rva = Some(text_rva + i as u32);
                    break;
                }
            }
        }
    }

    let insn_rva = ref_insn_rva?;
    let func = pe.find_function(insn_rva)?;
    let func_len = (func.end_address - func.begin_address) as usize;
    let code = pe.slice_at_rva(func.begin_address, func_len)?;

    let extracted = extract_user_settings_from_initializer_code(
        code,
        pe.image_base + func.begin_address as u64,
        |va, len| resolve_pe_utf8_string(pe, va, len),
        |target_va| classify_user_settings_helper_ctor(pe, target_va),
    );

    if extracted.len() < 3 {
        return None;
    }

    let entry_tuples: Vec<(String, u64)> = extracted
        .iter()
        .map(|(k, v, _)| (k.clone(), *v))
        .collect();
    if !categorize_user_settings(&entry_tuples) {
        return None;
    }

    let mut entries = BTreeMap::new();
    let mut defaults = BTreeMap::new();
    for (name, val, def) in extracted {
        if let Some(d) = def {
            defaults.insert(name.clone(), d);
        }
        entries.insert(name, val);
    }

    Some(DiscoveredEnumTable {
        category: "UserSettings".to_string(),
        form: EnumTableForm::ValueFirst,
        rva_start: func.begin_address,
        rva_end: func.end_address,
        entries,
        defaults,
    })
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

    let mut tables = extract_static_enum_tables_from_buffer(
        rdata_data,
        rdata_rva,
        image_base,
        resolver,
        default_categorizer,
    );

    if !tables.iter().any(|t| t.category == "UserSettings") {
        if let Some(us_table) = extract_dynamic_user_settings_table(pe) {
            tables.push(us_table);
        }
    }

    tables
}

/// Extracts default values for `UserSettings` entries when present in the binary.
pub fn extract_user_settings_defaults(pe: &PeImage) -> UserSettingsDefaultsCatalog {
    extract_static_enum_tables(pe)
        .into_iter()
        .find(|t| t.category == "UserSettings")
        .map(|t| t.defaults)
        .unwrap_or_default()
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
        let raw_table = scan_table_at(&buffer, table_off, rdata_rva, EnumTableForm::StringKeyFirst, &resolver)
            .expect("Should discover raw Form A table");

        assert_eq!(raw_table.form, EnumTableForm::StringKeyFirst);
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
        let table = scan_table_at(&buffer, table_off, rdata_rva, EnumTableForm::StringKeyFirst, &resolver)
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
        // But ServerErrorCodes requires StringKeyFirst!
        let discovered = extract_static_enum_tables_from_buffer(
            &buffer,
            rdata_rva,
            image_base,
            resolver,
            default_categorizer,
        );

        // Exactly ONE table discovered at 0x80 (StringKeyFirst), not phantom at 0x78
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].category, "ServerErrorCodes");
        assert_eq!(discovered[0].form, EnumTableForm::StringKeyFirst);
        assert_eq!(discovered[0].rva_start, rdata_rva + 0x80);
    }

    #[test]
    fn test_extract_user_settings_from_initializer_code_both_forms_and_defaults() {
        let mut strings: HashMap<u64, String> = HashMap::new();
        strings.insert(0x1819f4878, "userSettings/showReadmark".to_string());
        strings.insert(0x1819f48f0, "userSettings/safeMode".to_string());
        strings.insert(0x1819f4ce8, "notifications/channelCommentsLevel".to_string());
        strings.insert(
            0x1819f4d80,
            "channelTools/\u{0441}hannelHubBotLastSeenVersion".to_string(),
        );

        let base_ip = 0x1813635fau64;
        let mut buf: Vec<u8> = Vec::new();

        let push_lea_rip = |buf: &mut Vec<u8>, reg_opcode: [u8; 3], target_va: u64| {
            let next_ip = base_ip + buf.len() as u64 + 7;
            let disp = (target_va as i64 - next_ip as i64) as i32;
            buf.extend_from_slice(&reg_opcode);
            buf.extend_from_slice(&disp.to_le_bytes());
        };
        let push_call = |buf: &mut Vec<u8>, target_va: u64| {
            let next_ip = base_ip + buf.len() as u64 + 5;
            let disp = (target_va as i64 - next_ip as i64) as i32;
            buf.push(0xe8);
            buf.extend_from_slice(&disp.to_le_bytes());
        };

        // 1) Entry 0 (Form 1, no default): id=0, str=0x1819f4878, len=0x19, call 0x180040ec6
        push_lea_rip(&mut buf, [0x48, 0x8d, 0x05], 0x1819f4878); // lea rax, [rip+...]
        buf.extend_from_slice(&[
            0x48, 0x89, 0x44, 0x24, 0x20,                         // mov [rsp+0x20], rax
            0x48, 0xc7, 0x44, 0x24, 0x28, 0x19, 0x00, 0x00, 0x00, // mov qword ptr [rsp+0x28], 0x19
            0x4c, 0x8d, 0x44, 0x24, 0x20,                         // lea r8, [rsp+0x20]
            0x33, 0xd2,                                           // xor edx, edx
            0x48, 0x8d, 0x4c, 0x24, 0x40,                         // lea rcx, [rsp+0x40]
        ]);
        push_call(&mut buf, 0x180040ec6);

        // 2) Entry 4 (Form 2, inlined with bool default = false):
        buf.extend_from_slice(&[
            0x48, 0xc7, 0x85, 0x20, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, // mov qword ptr [rbp+0x120], 4
            0x41, 0xb8, 0x15, 0x00, 0x00, 0x00,                               // mov r8d, 0x15
        ]);
        push_lea_rip(&mut buf, [0x48, 0x8d, 0x15], 0x1819f48f0); // lea rdx, [rip+...]
        buf.extend_from_slice(&[
            0x48, 0x8d, 0x8d, 0x28, 0x01, 0x00, 0x00, // lea rcx, [rbp+0x128]
        ]);
        push_call(&mut buf, 0x18001d9f8);
        buf.extend_from_slice(&[
            0xc6, 0x85, 0x48, 0x01, 0x00, 0x00, 0x00, // mov byte ptr [rbp+0x148], 0
            0xc6, 0x85, 0x88, 0x01, 0x00, 0x00, 0x05, // mov byte ptr [rbp+0x188], 5
            0xc6, 0x85, 0x90, 0x01, 0x00, 0x00, 0x01, // mov byte ptr [rbp+0x190], 1
        ]);

        // 3) Entry 24 (Form 1, int64 default = 0):
        push_lea_rip(&mut buf, [0x48, 0x8d, 0x05], 0x1819f4ce8); // lea rax, [rip+...]
        buf.extend_from_slice(&[
            0x48, 0x89, 0x44, 0x24, 0x20,                         // mov [rsp+0x20], rax
            0x48, 0xc7, 0x44, 0x24, 0x28, 0x22, 0x00, 0x00, 0x00, // mov qword ptr [rsp+0x28], 0x22
            0x45, 0x33, 0xc9,                                     // xor r9d, r9d
            0x4c, 0x8d, 0x44, 0x24, 0x20,                         // lea r8, [rsp+0x20]
            0xba, 0x18, 0x00, 0x00, 0x00,                         // mov edx, 0x18
            0x48, 0x8d, 0x8d, 0x80, 0x0a, 0x00, 0x00,             // lea rcx, [rbp+0xa80]
        ]);
        push_call(&mut buf, 0x18009318a);

        // 4) Entry 28 (Form 1, no default, UTF-8 key):
        push_lea_rip(&mut buf, [0x48, 0x8d, 0x05], 0x1819f4d80); // lea rax, [rip+...]
        buf.extend_from_slice(&[
            0x48, 0x89, 0x44, 0x24, 0x20,
            0x48, 0xc7, 0x44, 0x24, 0x28, 0x2a, 0x00, 0x00, 0x00,
            0x4c, 0x8d, 0x44, 0x24, 0x20,
            0xba, 0x1c, 0x00, 0x00, 0x00,
            0x48, 0x8d, 0x8d, 0x60, 0x0c, 0x00, 0x00,
        ]);
        push_call(&mut buf, 0x180040ec6);

        let extracted = extract_user_settings_from_initializer_code(
            &buf,
            0x1813635fa,
            |va, len| {
                strings.get(&va).and_then(|s| {
                    if s.len() == len {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
            },
            |target| match target {
                0x180040ec6 => Some(HelperDefaultKind::None),
                0x18009318a => Some(HelperDefaultKind::Variant(3)),
                _ => None,
            },
        );

        assert_eq!(extracted.len(), 4);
        assert_eq!(
            extracted[0],
            ("userSettings/showReadmark".to_string(), 0, None)
        );
        assert_eq!(
            extracted[1],
            (
                "userSettings/safeMode".to_string(),
                4,
                Some(serde_json::json!(false))
            )
        );
        assert_eq!(
            extracted[2],
            (
                "notifications/channelCommentsLevel".to_string(),
                24,
                Some(serde_json::json!(0))
            )
        );
        assert_eq!(
            extracted[3],
            (
                "channelTools/\u{0441}hannelHubBotLastSeenVersion".to_string(),
                28,
                None
            )
        );
    }
}
