//! ELF64 program header parsing.
//!
//! Program headers describe segments used for loading the executable.

use super::{ElfError, ElfResult};

/// Program header type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramType {
    /// Unused entry
    Null,
    /// Loadable segment
    Load,
    /// Dynamic linking information
    Dynamic,
    /// Interpreter path
    Interp,
    /// Auxiliary information
    Note,
    /// Reserved (unused)
    Shlib,
    /// Program header table
    Phdr,
    /// Thread-local storage template
    Tls,
    /// GNU stack permissions
    GnuStack,
    /// GNU relocation read-only
    GnuRelro,
    /// GNU property
    GnuProperty,
    /// GNU exception handling
    GnuEhFrame,
    /// Unknown type
    Unknown(u32),
}

impl From<u32> for ProgramType {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::Null,
            1 => Self::Load,
            2 => Self::Dynamic,
            3 => Self::Interp,
            4 => Self::Note,
            5 => Self::Shlib,
            6 => Self::Phdr,
            7 => Self::Tls,
            0x6474_e550 => Self::GnuEhFrame,
            0x6474_e551 => Self::GnuStack,
            0x6474_e552 => Self::GnuRelro,
            0x6474_e553 => Self::GnuProperty,
            other => Self::Unknown(other),
        }
    }
}

/// Program header flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramFlags(pub u32);

impl ProgramFlags {
    /// Execute permission
    pub const PF_X: u32 = 0x1;
    /// Write permission
    pub const PF_W: u32 = 0x2;
    /// Read permission
    pub const PF_R: u32 = 0x4;

    /// Check if executable.
    pub fn is_executable(self) -> bool {
        self.0 & Self::PF_X != 0
    }

    /// Check if writable.
    pub fn is_writable(self) -> bool {
        self.0 & Self::PF_W != 0
    }

    /// Check if readable.
    pub fn is_readable(self) -> bool {
        self.0 & Self::PF_R != 0
    }

    /// Convert to mmap protection flags.
    ///
    /// Returns a bitmask suitable for mmap's prot argument:
    /// - 0x1 = PROT_READ
    /// - 0x2 = PROT_WRITE
    /// - 0x4 = PROT_EXEC
    pub fn to_mmap_prot(self) -> i32 {
        const PROT_READ: i32 = 0x1;
        const PROT_WRITE: i32 = 0x2;
        const PROT_EXEC: i32 = 0x4;

        let mut prot = 0i32;
        if self.is_readable() {
            prot |= PROT_READ;
        }
        if self.is_writable() {
            prot |= PROT_WRITE;
        }
        if self.is_executable() {
            prot |= PROT_EXEC;
        }
        prot
    }
}

/// ELF64 program header.
#[derive(Debug, Clone, Copy)]
pub struct Elf64ProgramHeader {
    /// Segment type
    pub p_type: ProgramType,
    /// Segment flags
    pub p_flags: ProgramFlags,
    /// File offset of segment
    pub p_offset: u64,
    /// Virtual address in memory
    pub p_vaddr: u64,
    /// Physical address (usually same as vaddr)
    pub p_paddr: u64,
    /// Size in file
    pub p_filesz: u64,
    /// Size in memory (may be larger than filesz for BSS)
    pub p_memsz: u64,
    /// Alignment (must be power of 2)
    pub p_align: u64,
}

impl Elf64ProgramHeader {
    /// Size of an ELF64 program header in bytes.
    pub const SIZE: usize = 56;

    /// Parse a program header from a byte slice.
    pub fn parse(data: &[u8]) -> ElfResult<Self> {
        if data.len() < Self::SIZE {
            return Err(ElfError::BufferTooSmall {
                needed: Self::SIZE,
                available: data.len(),
            });
        }

        let p_type = ProgramType::from(u32::from_le_bytes([data[0], data[1], data[2], data[3]]));
        let p_flags = ProgramFlags(u32::from_le_bytes([data[4], data[5], data[6], data[7]]));
        let p_offset = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        let p_vaddr = u64::from_le_bytes([
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]);
        let p_paddr = u64::from_le_bytes([
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        ]);
        let p_filesz = u64::from_le_bytes([
            data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
        ]);
        let p_memsz = u64::from_le_bytes([
            data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47],
        ]);
        let p_align = u64::from_le_bytes([
            data[48], data[49], data[50], data[51], data[52], data[53], data[54], data[55],
        ]);

        Ok(Self {
            p_type,
            p_flags,
            p_offset,
            p_vaddr,
            p_paddr,
            p_filesz,
            p_memsz,
            p_align,
        })
    }

    /// Check if this is a loadable segment.
    pub fn is_load(&self) -> bool {
        matches!(self.p_type, ProgramType::Load)
    }

    /// Check if this is the dynamic segment.
    pub fn is_dynamic(&self) -> bool {
        matches!(self.p_type, ProgramType::Dynamic)
    }

    /// Check if this is the interpreter segment.
    pub fn is_interp(&self) -> bool {
        matches!(self.p_type, ProgramType::Interp)
    }

    /// Check if this is the TLS segment.
    pub fn is_tls(&self) -> bool {
        matches!(self.p_type, ProgramType::Tls)
    }

    /// Check if this is the GNU_RELRO segment.
    pub fn is_relro(&self) -> bool {
        matches!(self.p_type, ProgramType::GnuRelro)
    }

    /// Get the BSS size (memory size beyond file size).
    pub fn bss_size(&self) -> u64 {
        self.p_memsz.saturating_sub(self.p_filesz)
    }

    /// Check alignment validity.
    pub fn is_valid_alignment(&self) -> bool {
        self.p_align == 0 || self.p_align.is_power_of_two()
    }
}

/// Parse all program headers from an ELF file.
pub fn parse_program_headers(
    data: &[u8],
    phoff: u64,
    phentsize: u16,
    phnum: u16,
) -> ElfResult<Vec<Elf64ProgramHeader>> {
    let phoff = usize::try_from(phoff).map_err(|_| ElfError::InvalidOffset {
        kind: "program header table",
        offset: phoff,
    })?;
    let phentsize = usize::from(phentsize);
    let phnum = usize::from(phnum);

    // Validate the stride before allocation or parsing. Otherwise a zero or
    // undersized entry can reuse the same bytes as many overlapping headers,
    // or read beyond the table extent that was checked below.
    if phnum != 0 && phentsize < Elf64ProgramHeader::SIZE {
        return Err(ElfError::InvalidOffset {
            kind: "program header entry size",
            offset: phentsize as u64,
        });
    }

    // Validate bounds
    let end_offset = phoff
        .checked_add(
            phentsize
                .checked_mul(phnum)
                .ok_or(ElfError::InvalidOffset {
                    kind: "program header table",
                    offset: phoff as u64,
                })?,
        )
        .ok_or(ElfError::InvalidOffset {
            kind: "program header table",
            offset: phoff as u64,
        })?;

    if end_offset > data.len() {
        return Err(ElfError::BufferTooSmall {
            needed: end_offset,
            available: data.len(),
        });
    }

    let mut headers = Vec::with_capacity(phnum);
    for i in 0..phnum {
        let offset = phoff + i * phentsize;
        // The checked table extent and minimum stride prove this record fits.
        let header = Elf64ProgramHeader::parse(&data[offset..offset + Elf64ProgramHeader::SIZE])?;
        headers.push(header);
    }

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_load_header() -> [u8; 56] {
        let mut header = [0u8; 56];
        // p_type = PT_LOAD (1)
        header[0] = 1;
        // p_flags = PF_R | PF_X (5)
        header[4] = 5;
        // p_offset = 0x1000
        header[8] = 0x00;
        header[9] = 0x10;
        // p_vaddr = 0x400000
        header[16] = 0x00;
        header[17] = 0x00;
        header[18] = 0x40;
        // p_filesz = 0x2000
        header[32] = 0x00;
        header[33] = 0x20;
        // p_memsz = 0x3000
        header[40] = 0x00;
        header[41] = 0x30;
        // p_align = 0x1000
        header[48] = 0x00;
        header[49] = 0x10;
        header
    }

    #[test]
    fn test_parse_load_header() {
        let data = make_load_header();
        let header = Elf64ProgramHeader::parse(&data).unwrap();

        assert!(header.is_load());
        assert!(header.p_flags.is_readable());
        assert!(header.p_flags.is_executable());
        assert!(!header.p_flags.is_writable());
        assert_eq!(header.p_offset, 0x1000);
        assert_eq!(header.p_vaddr, 0x400000);
        assert_eq!(header.p_filesz, 0x2000);
        assert_eq!(header.p_memsz, 0x3000);
        assert_eq!(header.bss_size(), 0x1000);
        assert!(header.is_valid_alignment());
    }

    #[test]
    fn test_program_flags() {
        let flags = ProgramFlags(ProgramFlags::PF_R | ProgramFlags::PF_W);
        assert!(flags.is_readable());
        assert!(flags.is_writable());
        assert!(!flags.is_executable());

        let prot = flags.to_mmap_prot();
        // PROT_READ = 0x1, PROT_WRITE = 0x2
        assert_eq!(prot, 0x1 | 0x2);
    }

    #[test]
    fn test_program_type_conversion() {
        assert!(matches!(ProgramType::from(0), ProgramType::Null));
        assert!(matches!(ProgramType::from(1), ProgramType::Load));
        assert!(matches!(ProgramType::from(2), ProgramType::Dynamic));
        assert!(matches!(ProgramType::from(3), ProgramType::Interp));
        assert!(matches!(
            ProgramType::from(0x6474_e552),
            ProgramType::GnuRelro
        ));
        assert!(matches!(ProgramType::from(999), ProgramType::Unknown(999)));
    }

    #[test]
    fn table_rejects_every_undersized_stride() {
        // Extra file bytes must not turn an undersized table record into a
        // valid header by letting its parser read outside that record.
        let data = [0u8; Elf64ProgramHeader::SIZE * 2];
        for stride in 0..Elf64ProgramHeader::SIZE as u16 {
            assert!(
                matches!(
                    parse_program_headers(&data, 0, stride, 1),
                    Err(ElfError::InvalidOffset {
                        kind: "program header entry size",
                        ..
                    })
                ),
                "stride={stride}"
            );
        }
        assert!(parse_program_headers(&data, 0, 0, u16::MAX).is_err());
    }

    #[test]
    fn table_rejects_overflow_and_truncated_extents() {
        let data = [0u8; Elf64ProgramHeader::SIZE];
        let stride = Elf64ProgramHeader::SIZE as u16;
        for offset in [u64::MAX, u64::MAX - 8, 1u64 << 32] {
            assert!(parse_program_headers(&data, offset, stride, 1).is_err());
        }
        assert!(parse_program_headers(&data, 0, stride, 2).is_err());
        assert!(parse_program_headers(&data, 1, stride, 1).is_err());
        assert!(parse_program_headers(&data[..data.len() - 1], 0, stride, 1).is_err());
    }

    #[test]
    fn table_preserves_empty_and_exact_size_records() {
        assert!(parse_program_headers(&[], 0, 0, 0).unwrap().is_empty());
        let data = [0u8; Elf64ProgramHeader::SIZE * 2];
        let headers = parse_program_headers(&data, 0, Elf64ProgramHeader::SIZE as u16, 2).unwrap();
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn table_respects_offset_and_padded_stride() {
        let offset = 7usize;
        let stride = Elf64ProgramHeader::SIZE + 8;
        let mut data = vec![0xff; offset + 2 * stride];
        data[offset..offset + Elf64ProgramHeader::SIZE].fill(0);
        data[offset + stride..offset + stride + Elf64ProgramHeader::SIZE].fill(0);
        data[offset..offset + 4].copy_from_slice(&1u32.to_le_bytes());
        data[offset + stride..offset + stride + 4].copy_from_slice(&2u32.to_le_bytes());
        let headers = parse_program_headers(&data, offset as u64, stride as u16, 2).unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].p_type, ProgramType::Load);
        assert_eq!(headers[1].p_type, ProgramType::Dynamic);
    }
}
