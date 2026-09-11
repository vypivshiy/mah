use anyhow::{Context, Result};
use goblin::pe::PE;

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub pointer_to_raw_data: u32,
    pub size_of_raw_data: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}

impl RuntimeFunction {
    #[inline]
    pub fn len(&self) -> u32 {
        self.end_address.saturating_sub(self.begin_address)
    }
}

pub struct PeImage<'a> {
    pub raw: &'a [u8],
    pub image_base: u64,
    pub sections: Vec<SectionInfo>,
    pub pdata: Vec<RuntimeFunction>,
}

impl<'a> PeImage<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let pe = PE::parse(bytes).context("Failed to parse PE file via goblin")?;

        let opt_hdr = pe
            .header
            .optional_header
            .context("Optional header is missing")?;
        let image_base = opt_hdr.windows_fields.image_base;

        let mut sections = Vec::with_capacity(pe.sections.len());
        for s in &pe.sections {
            let raw_name = s.name().unwrap_or_default();
            sections.push(SectionInfo {
                name: raw_name.to_string(),
                virtual_address: s.virtual_address,
                virtual_size: s.virtual_size,
                pointer_to_raw_data: s.pointer_to_raw_data,
                size_of_raw_data: s.size_of_raw_data,
            });
        }

        // Parse .pdata (RUNTIME_FUNCTION array)
        let mut pdata = Vec::new();
        let pdata_sec = sections.iter().find(|s| s.name == ".pdata");
        if let Some(sec) = pdata_sec {
            let start = sec.pointer_to_raw_data as usize;
            let end = start + sec.size_of_raw_data as usize;
            if end <= bytes.len() {
                let pdata_bytes = &bytes[start..end];
                let count = pdata_bytes.len() / 12;
                pdata.reserve(count);
                for chunk in pdata_bytes.chunks_exact(12) {
                    let begin = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
                    let end_addr = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
                    let unwind = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
                    if begin != 0 || end_addr != 0 {
                        pdata.push(RuntimeFunction {
                            begin_address: begin,
                            end_address: end_addr,
                            unwind_info_address: unwind,
                        });
                    }
                }
            }
        }

        Ok(PeImage {
            raw: bytes,
            image_base,
            sections,
            pdata,
        })
    }

    #[inline]
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for s in &self.sections {
            let size = s.virtual_size.max(s.size_of_raw_data);
            if rva >= s.virtual_address && rva < s.virtual_address + size {
                let offset_in_sec = rva - s.virtual_address;
                if offset_in_sec < s.size_of_raw_data {
                    return Some((s.pointer_to_raw_data + offset_in_sec) as usize);
                }
            }
        }
        None
    }

    #[inline]
    pub fn offset_to_rva(&self, offset: usize) -> Option<u32> {
        let off32 = offset as u32;
        for s in &self.sections {
            if off32 >= s.pointer_to_raw_data && off32 < s.pointer_to_raw_data + s.size_of_raw_data {
                return Some(s.virtual_address + (off32 - s.pointer_to_raw_data));
            }
        }
        None
    }

    #[inline]
    pub fn slice_at_rva(&self, rva: u32, len: usize) -> Option<&'a [u8]> {
        let offset = self.rva_to_offset(rva)?;
        let end = offset.checked_add(len)?;
        if end <= self.raw.len() {
            Some(&self.raw[offset..end])
        } else {
            None
        }
    }

    pub fn read_cstring(&self, rva: u32) -> Option<&'a str> {
        let offset = self.rva_to_offset(rva)?;
        let rest = &self.raw[offset..];
        let null_idx = memchr::memchr(b'\0', rest)?;
        std::str::from_utf8(&rest[..null_idx]).ok()
    }

    pub fn section_by_name(&self, name: &str) -> Option<&SectionInfo> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn section_data(&self, name: &str) -> Option<&'a [u8]> {
        let s = self.section_by_name(name)?;
        let start = s.pointer_to_raw_data as usize;
        let end = start + s.size_of_raw_data as usize;
        if end <= self.raw.len() {
            Some(&self.raw[start..end])
        } else {
            None
        }
    }

    pub fn find_function(&self, rva: u32) -> Option<&RuntimeFunction> {
        let idx = self.pdata.binary_search_by(|f| {
            if rva < f.begin_address {
                std::cmp::Ordering::Greater
            } else if rva >= f.end_address {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }).ok()?;
        Some(&self.pdata[idx])
    }
}
