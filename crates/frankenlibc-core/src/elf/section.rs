//! ELF64 section header parsing.
//!
//! Section headers describe the file's sections for linking and debugging.

use super::{ElfError, ElfResult};

/// Section header type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    /// Inactive section
    Null,
    /// Program data
    Progbits,
    /// Symbol table
    Symtab,
    /// String table
    Strtab,
    /// Relocation with addends
    Rela,
    /// Symbol hash table
    Hash,
    /// Dynamic linking information
    Dynamic,
    /// Notes
    Note,
    /// Uninitialized data (BSS)
    Nobits,
    /// Relocation without addends
    Rel,
    /// Reserved
    Shlib,
    /// Dynamic linker symbol table
    Dynsym,
    /// Array of constructors
    InitArray,
    /// Array of destructors
    FiniArray,
    /// Array of pre-constructors
    PreinitArray,
    /// Section group
    Group,
    /// Extended symbol table index
    SymtabShndx,
    /// GNU hash table
    GnuHash,
    /// GNU version definition
    GnuVerdef,
    /// GNU version requirements
    GnuVerneed,
    /// GNU version symbol table
    GnuVersym,
    /// Unknown type
    Unknown(u32),
}

impl From<u32> for SectionType {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::Null,
            1 => Self::Progbits,
            2 => Self::Symtab,
            3 => Self::Strtab,
            4 => Self::Rela,
            5 => Self::Hash,
            6 => Self::Dynamic,
            7 => Self::Note,
            8 => Self::Nobits,
            9 => Self::Rel,
            10 => Self::Shlib,
            11 => Self::Dynsym,
            14 => Self::InitArray,
            15 => Self::FiniArray,
            16 => Self::PreinitArray,
            17 => Self::Group,
            18 => Self::SymtabShndx,
            0x6fff_fff6 => Self::GnuHash,
            0x6fff_fffd => Self::GnuVerdef,
            0x6fff_fffe => Self::GnuVerneed,
            0x6fff_ffff => Self::GnuVersym,
            other => Self::Unknown(other),
        }
    }
}

/// Section header flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionFlags(pub u64);

impl SectionFlags {
    /// Writable
    pub const SHF_WRITE: u64 = 0x1;
    /// Occupies memory during execution
    pub const SHF_ALLOC: u64 = 0x2;
    /// Executable
    pub const SHF_EXECINSTR: u64 = 0x4;
    /// Might be merged
    pub const SHF_MERGE: u64 = 0x10;
    /// Contains null-terminated strings
    pub const SHF_STRINGS: u64 = 0x20;
    /// Section holds index
    pub const SHF_INFO_LINK: u64 = 0x40;
    /// Preserve link order
    pub const SHF_LINK_ORDER: u64 = 0x80;
    /// OS-specific handling required
    pub const SHF_OS_NONCONFORMING: u64 = 0x100;
    /// Section is member of a group
    pub const SHF_GROUP: u64 = 0x200;
    /// Thread-local storage
    pub const SHF_TLS: u64 = 0x400;

    pub fn is_writable(self) -> bool {
        self.0 & Self::SHF_WRITE != 0
    }

    pub fn is_allocated(self) -> bool {
        self.0 & Self::SHF_ALLOC != 0
    }

    pub fn is_executable(self) -> bool {
        self.0 & Self::SHF_EXECINSTR != 0
    }

    pub fn is_tls(self) -> bool {
        self.0 & Self::SHF_TLS != 0
    }
}

/// ELF64 section header.
#[derive(Debug, Clone, Copy)]
pub struct Elf64SectionHeader {
    /// Section name (index into string table)
    pub sh_name: u32,
    /// Section type
    pub sh_type: SectionType,
    /// Section flags
    pub sh_flags: SectionFlags,
    /// Virtual address in memory
    pub sh_addr: u64,
    /// Offset in file
    pub sh_offset: u64,
    /// Size in bytes
    pub sh_size: u64,
    /// Link to another section
    pub sh_link: u32,
    /// Additional section information
    pub sh_info: u32,
    /// Section alignment
    pub sh_addralign: u64,
    /// Entry size if section holds table
    pub sh_entsize: u64,
}

impl Elf64SectionHeader {
    /// Size of an ELF64 section header in bytes.
    pub const SIZE: usize = 64;

    /// Parse a section header from a byte slice.
    pub fn parse(data: &[u8]) -> ElfResult<Self> {
        if data.len() < Self::SIZE {
            return Err(ElfError::BufferTooSmall {
                needed: Self::SIZE,
                available: data.len(),
            });
        }

        let sh_name = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let sh_type = SectionType::from(u32::from_le_bytes([data[4], data[5], data[6], data[7]]));
        let sh_flags = SectionFlags(u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]));
        let sh_addr = u64::from_le_bytes([
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]);
        let sh_offset = u64::from_le_bytes([
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        ]);
        let sh_size = u64::from_le_bytes([
            data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
        ]);
        let sh_link = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);
        let sh_info = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
        let sh_addralign = u64::from_le_bytes([
            data[48], data[49], data[50], data[51], data[52], data[53], data[54], data[55],
        ]);
        let sh_entsize = u64::from_le_bytes([
            data[56], data[57], data[58], data[59], data[60], data[61], data[62], data[63],
        ]);

        Ok(Self {
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
        })
    }

    /// Check if this is a symbol table section.
    pub fn is_symtab(&self) -> bool {
        matches!(self.sh_type, SectionType::Symtab | SectionType::Dynsym)
    }

    /// Check if this is a relocation section.
    pub fn is_rela(&self) -> bool {
        matches!(self.sh_type, SectionType::Rela)
    }

    /// Check if this is a string table section.
    pub fn is_strtab(&self) -> bool {
        matches!(self.sh_type, SectionType::Strtab)
    }

    /// Check if this is a hash table section.
    pub fn is_hash(&self) -> bool {
        matches!(self.sh_type, SectionType::Hash | SectionType::GnuHash)
    }

    /// Check if this is the dynamic section.
    pub fn is_dynamic(&self) -> bool {
        matches!(self.sh_type, SectionType::Dynamic)
    }
}

/// Parse all section headers from an ELF file.
pub fn parse_section_headers(
    data: &[u8],
    shoff: u64,
    shentsize: u16,
    shnum: u16,
) -> ElfResult<Vec<Elf64SectionHeader>> {
    let shoff = usize::try_from(shoff).map_err(|_| ElfError::InvalidOffset {
        kind: "section header table",
        offset: shoff,
    })?;
    let shentsize = usize::from(shentsize);
    let shnum = usize::from(shnum);

    // Validate the stride before allocation or parsing. Otherwise a zero or
    // undersized entry can reuse the same bytes as many overlapping headers,
    // or read beyond the table extent that was checked below.
    if shnum != 0 && shentsize < Elf64SectionHeader::SIZE {
        return Err(ElfError::InvalidOffset {
            kind: "section header entry size",
            offset: shentsize as u64,
        });
    }

    // Validate bounds
    let end_offset = shoff
        .checked_add(
            shentsize
                .checked_mul(shnum)
                .ok_or(ElfError::InvalidOffset {
                    kind: "section header table",
                    offset: shoff as u64,
                })?,
        )
        .ok_or(ElfError::InvalidOffset {
            kind: "section header table",
            offset: shoff as u64,
        })?;

    if end_offset > data.len() {
        return Err(ElfError::BufferTooSmall {
            needed: end_offset,
            available: data.len(),
        });
    }

    let mut headers = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let offset = shoff + i * shentsize;
        // The checked table extent and minimum stride prove this record fits.
        let header = Elf64SectionHeader::parse(&data[offset..offset + Elf64SectionHeader::SIZE])?;
        headers.push(header);
    }

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_type_conversion() {
        assert!(matches!(SectionType::from(0), SectionType::Null));
        assert!(matches!(SectionType::from(1), SectionType::Progbits));
        assert!(matches!(SectionType::from(2), SectionType::Symtab));
        assert!(matches!(SectionType::from(11), SectionType::Dynsym));
        assert!(matches!(
            SectionType::from(0x6fff_fff6),
            SectionType::GnuHash
        ));
        assert!(matches!(
            SectionType::from(99999),
            SectionType::Unknown(99999)
        ));
    }

    #[test]
    fn test_section_flags() {
        let flags = SectionFlags(SectionFlags::SHF_ALLOC | SectionFlags::SHF_EXECINSTR);
        assert!(flags.is_allocated());
        assert!(flags.is_executable());
        assert!(!flags.is_writable());
        assert!(!flags.is_tls());
    }

    #[test]
    fn table_rejects_every_undersized_stride() {
        // Extra file bytes must not turn an undersized table record into a
        // valid header by letting its parser read outside that record.
        let data = [0u8; Elf64SectionHeader::SIZE * 2];
        for stride in 0..Elf64SectionHeader::SIZE as u16 {
            assert!(
                matches!(
                    parse_section_headers(&data, 0, stride, 1),
                    Err(ElfError::InvalidOffset {
                        kind: "section header entry size",
                        ..
                    })
                ),
                "stride={stride}"
            );
        }
        assert!(parse_section_headers(&data, 0, 0, u16::MAX).is_err());
    }

    #[test]
    fn table_rejects_overflow_and_truncated_extents() {
        let data = [0u8; Elf64SectionHeader::SIZE];
        let stride = Elf64SectionHeader::SIZE as u16;
        for offset in [u64::MAX, u64::MAX - 8, 1u64 << 32] {
            assert!(parse_section_headers(&data, offset, stride, 1).is_err());
        }
        assert!(parse_section_headers(&data, 0, stride, 2).is_err());
        assert!(parse_section_headers(&data, 1, stride, 1).is_err());
        assert!(parse_section_headers(&data[..data.len() - 1], 0, stride, 1).is_err());
    }

    #[test]
    fn table_preserves_empty_and_exact_size_records() {
        assert!(parse_section_headers(&[], 0, 0, 0).unwrap().is_empty());
        let data = [0u8; Elf64SectionHeader::SIZE * 2];
        let headers = parse_section_headers(&data, 0, Elf64SectionHeader::SIZE as u16, 2).unwrap();
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn table_respects_offset_and_padded_stride() {
        let offset = 7usize;
        let stride = Elf64SectionHeader::SIZE + 8;
        let mut data = vec![0xff; offset + 2 * stride];
        data[offset..offset + Elf64SectionHeader::SIZE].fill(0);
        data[offset + stride..offset + stride + Elf64SectionHeader::SIZE].fill(0);
        data[offset..offset + 4].copy_from_slice(&1u32.to_le_bytes());
        data[offset + stride..offset + stride + 4].copy_from_slice(&2u32.to_le_bytes());
        let headers = parse_section_headers(&data, offset as u64, stride as u16, 2).unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].sh_name, 1);
        assert_eq!(headers[1].sh_name, 2);
    }
}
