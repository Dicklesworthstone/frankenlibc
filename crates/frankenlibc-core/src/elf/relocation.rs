//! ELF64 relocation parsing and application.
//!
//! This module handles RELA relocations (with explicit addends) for x86_64.
//!
//! # Current Scope
//!
//! Implemented relocations:
//! - `R_X86_64_NONE` (0): No action
//! - `R_X86_64_64` (1): S + A (64-bit absolute)
//! - `R_X86_64_PC32` (2): S + A - P (32-bit PC-relative)
//! - `R_X86_64_PLT32` (4): L + A - P (32-bit PLT-relative)
//! - `R_X86_64_GLOB_DAT` (6): S (GOT entry)
//! - `R_X86_64_JUMP_SLOT` (7): S (PLT entry)
//! - `R_X86_64_RELATIVE` (8): B + A (base-relative)
//! - `R_X86_64_32`, `R_X86_64_32S`, `R_X86_64_16`, `R_X86_64_PC16`,
//!   `R_X86_64_8`, `R_X86_64_PC8`: fixed-width checked forms
//!
//! Handled by the loader rather than this pure computation helper:
//! - `R_X86_64_IRELATIVE` (37): resolver-mediated IFUNC relocation
//! - `DT_RELR`: compressed relative relocation targets
//!
//! Deferred/unsupported:
//! - `R_X86_64_COPY` (5): Memory copy at runtime
//! - TLS relocations

use super::{ElfError, ElfResult, RelocationSupport};

/// x86_64 relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationType {
    /// No relocation
    None,
    /// Direct 64-bit (S + A)
    R64,
    /// PC-relative 32-bit signed (S + A - P)
    Pc32,
    /// GOT entry 32-bit (G + GOT + A)
    Got32,
    /// PLT entry 32-bit (L + A - P)
    Plt32,
    /// Runtime copy (deferred)
    Copy,
    /// Create GOT entry (S)
    GlobDat,
    /// Create PLT entry (S)
    JumpSlot,
    /// Base-relative (B + A)
    Relative,
    /// 32-bit GOT PC-relative
    Gotpcrel,
    /// Direct 32-bit zero-extended
    R32,
    /// Direct 32-bit sign-extended
    R32S,
    /// Direct 16-bit zero-extended
    R16,
    /// PC-relative 16-bit
    Pc16,
    /// Direct 8-bit sign-extended
    R8,
    /// PC-relative 8-bit
    Pc8,
    /// TLS module ID (deferred)
    DtpMod64,
    /// TLS offset (deferred)
    DtpOff64,
    /// TLS offset (deferred)
    TpOff64,
    /// TLS PC-relative (deferred)
    TlsGd,
    /// TLS local-dynamic (deferred)
    TlsLd,
    /// Indirect function (deferred)
    IRelative,
    /// Unknown relocation type
    Unknown(u32),
}

impl From<u32> for RelocationType {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::R64,
            2 => Self::Pc32,
            3 => Self::Got32,
            4 => Self::Plt32,
            5 => Self::Copy,
            6 => Self::GlobDat,
            7 => Self::JumpSlot,
            8 => Self::Relative,
            9 => Self::Gotpcrel,
            10 => Self::R32,
            11 => Self::R32S,
            12 => Self::R16,
            13 => Self::Pc16,
            14 => Self::R8,
            15 => Self::Pc8,
            16 => Self::DtpMod64,
            17 => Self::DtpOff64,
            18 => Self::TpOff64,
            19 => Self::TlsGd,
            20 => Self::TlsLd,
            37 => Self::IRelative,
            other => Self::Unknown(other),
        }
    }
}

impl RelocationType {
    /// Convert to the raw u32 value.
    pub fn to_u32(self) -> u32 {
        match self {
            Self::None => 0,
            Self::R64 => 1,
            Self::Pc32 => 2,
            Self::Got32 => 3,
            Self::Plt32 => 4,
            Self::Copy => 5,
            Self::GlobDat => 6,
            Self::JumpSlot => 7,
            Self::Relative => 8,
            Self::Gotpcrel => 9,
            Self::R32 => 10,
            Self::R32S => 11,
            Self::R16 => 12,
            Self::Pc16 => 13,
            Self::R8 => 14,
            Self::Pc8 => 15,
            Self::DtpMod64 => 16,
            Self::DtpOff64 => 17,
            Self::TpOff64 => 18,
            Self::TlsGd => 19,
            Self::TlsLd => 20,
            Self::IRelative => 37,
            Self::Unknown(v) => v,
        }
    }

    /// Get the support classification for this relocation type.
    pub fn support(&self) -> RelocationSupport {
        match self {
            Self::None
            | Self::R64
            | Self::Pc32
            | Self::Plt32
            | Self::GlobDat
            | Self::JumpSlot
            | Self::Relative
            | Self::R32
            | Self::R32S
            | Self::R16
            | Self::Pc16
            | Self::R8
            | Self::Pc8
            | Self::IRelative => RelocationSupport::Implemented,
            Self::Copy => RelocationSupport::Stub,
            Self::DtpMod64 | Self::DtpOff64 | Self::TpOff64 | Self::TlsGd | Self::TlsLd => {
                RelocationSupport::Unsupported
            }
            _ => RelocationSupport::Unsupported,
        }
    }

    /// Check if this relocation type is supported in phase 1.
    pub fn is_supported(&self) -> bool {
        matches!(self.support(), RelocationSupport::Implemented)
    }

    /// Check if this is a TLS relocation.
    pub fn is_tls(&self) -> bool {
        matches!(
            self,
            Self::DtpMod64 | Self::DtpOff64 | Self::TpOff64 | Self::TlsGd | Self::TlsLd
        )
    }
}

/// ELF64 RELA relocation entry.
#[derive(Debug, Clone, Copy)]
pub struct Elf64Rela {
    /// Address where relocation applies
    pub r_offset: u64,
    /// Relocation type and symbol index
    pub r_info: u64,
    /// Constant addend
    pub r_addend: i64,
}

impl Elf64Rela {
    /// Size of an ELF64 RELA entry in bytes.
    pub const SIZE: usize = 24;

    /// Parse a RELA entry from a byte slice.
    pub fn parse(data: &[u8]) -> ElfResult<Self> {
        if data.len() < Self::SIZE {
            return Err(ElfError::BufferTooSmall {
                needed: Self::SIZE,
                available: data.len(),
            });
        }

        let r_offset = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let r_info = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        let r_addend = i64::from_le_bytes([
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]);

        Ok(Self {
            r_offset,
            r_info,
            r_addend,
        })
    }

    /// Get the relocation type.
    pub fn reloc_type(&self) -> RelocationType {
        RelocationType::from((self.r_info & 0xffff_ffff) as u32)
    }

    /// Get the symbol index.
    pub fn symbol_index(&self) -> u32 {
        (self.r_info >> 32) as u32
    }
}

/// Result of applying a relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationResult {
    /// Relocation applied successfully
    Applied,
    /// Relocation skipped (R_X86_64_NONE)
    Skipped,
    /// Relocation deferred (e.g., COPY)
    Deferred,
    /// Symbol not found
    SymbolNotFound,
    /// Unsupported relocation type
    Unsupported(u32),
    /// Overflow during relocation computation
    Overflow,
}

/// Context for relocation application.
#[derive(Debug, Clone, Copy)]
pub struct RelocationContext {
    /// Base address where object is loaded
    pub base: u64,
    /// GOT base address (if available)
    pub got: Option<u64>,
}

impl RelocationContext {
    /// Create a new relocation context.
    pub fn new(base: u64) -> Self {
        Self { base, got: None }
    }

    /// Set the GOT base address.
    pub fn with_got(mut self, got: u64) -> Self {
        self.got = Some(got);
        self
    }
}

/// Compute the relocation value for a given relocation.
///
/// # Arguments
///
/// * `reloc` - The relocation entry
/// * `symbol_value` - The resolved symbol value (S)
/// * `ctx` - The relocation context (base address, GOT, etc.)
///
/// # Returns
///
/// The computed value to write at the relocation target, or an error.
pub fn compute_relocation(
    reloc: &Elf64Rela,
    symbol_value: u64,
    ctx: &RelocationContext,
) -> Result<(u64, usize), RelocationResult> {
    let rtype = reloc.reloc_type();
    let s = symbol_value;
    let a = reloc.r_addend;
    let b = ctx.base;
    let p = checked_u64_add(b, reloc.r_offset)?;

    match rtype {
        RelocationType::None => Err(RelocationResult::Skipped),

        // S + A (64-bit absolute)
        RelocationType::R64 => {
            let value = unsigned_value(s, a, 64)?;
            Ok((value, 8))
        }

        // S + A - P (32-bit PC-relative)
        RelocationType::Pc32 => {
            let value = pc_relative_value(s, a, p, 32)?;
            Ok((value, 4))
        }

        // L + A - P. In this core model the resolver supplies L as symbol_value.
        RelocationType::Plt32 => {
            let value = pc_relative_value(s, a, p, 32)?;
            Ok((value, 4))
        }

        // S (GOT entry)
        RelocationType::GlobDat => Ok((s, 8)),

        // S (PLT entry)
        RelocationType::JumpSlot => Ok((s, 8)),

        // B + A (base-relative)
        RelocationType::Relative => {
            let value = b.wrapping_add(a as u64);
            Ok((value, 8))
        }

        RelocationType::R32 => {
            let value = unsigned_value(s, a, 32)?;
            Ok((value, 4))
        }

        RelocationType::R32S => {
            let value = signed_value(s, a, 32)?;
            Ok((value, 4))
        }

        RelocationType::R16 => {
            let value = unsigned_value(s, a, 16)?;
            Ok((value, 2))
        }

        RelocationType::Pc16 => {
            let value = pc_relative_value(s, a, p, 16)?;
            Ok((value, 2))
        }

        RelocationType::R8 => {
            let value = signed_value(s, a, 8)?;
            Ok((value, 1))
        }

        RelocationType::Pc8 => {
            let value = pc_relative_value(s, a, p, 8)?;
            Ok((value, 1))
        }

        RelocationType::Copy => Err(RelocationResult::Deferred),

        RelocationType::IRelative => Err(RelocationResult::Unsupported(rtype.to_u32())),

        _ if rtype.is_tls() => Err(RelocationResult::Unsupported(rtype.to_u32())),

        RelocationType::Unknown(t) => Err(RelocationResult::Unsupported(t)),

        _ => Err(RelocationResult::Unsupported(rtype.to_u32())),
    }
}

fn checked_u64_add(lhs: u64, rhs: u64) -> Result<u64, RelocationResult> {
    lhs.checked_add(rhs).ok_or(RelocationResult::Overflow)
}

fn addend_sum(lhs: u64, rhs: i64) -> i128 {
    i128::from(lhs) + i128::from(rhs)
}

fn unsigned_value(lhs: u64, rhs: i64, bits: u32) -> Result<u64, RelocationResult> {
    let value = addend_sum(lhs, rhs);
    if value < 0 || value > unsigned_max(bits) {
        return Err(RelocationResult::Overflow);
    }
    Ok(value as u64)
}

fn signed_value(lhs: u64, rhs: i64, bits: u32) -> Result<u64, RelocationResult> {
    let value = addend_sum(lhs, rhs);
    let min = -(1i128 << (bits - 1));
    let max = (1i128 << (bits - 1)) - 1;
    if value < min || value > max {
        return Err(RelocationResult::Overflow);
    }
    Ok(low_bits(value, bits))
}

fn pc_relative_value(lhs: u64, rhs: i64, place: u64, bits: u32) -> Result<u64, RelocationResult> {
    let value = addend_sum(lhs, rhs) - i128::from(place);
    let min = -(1i128 << (bits - 1));
    let max = (1i128 << (bits - 1)) - 1;
    if value < min || value > max {
        return Err(RelocationResult::Overflow);
    }
    Ok(low_bits(value, bits))
}

fn unsigned_max(bits: u32) -> i128 {
    (1i128 << bits) - 1
}

fn low_bits(value: i128, bits: u32) -> u64 {
    let mask = (1u128 << bits) - 1;
    (value as u128 & mask) as u64
}

/// Parse all RELA entries from a relocation section.
pub fn parse_relocations(data: &[u8], offset: u64, size: u64) -> ElfResult<Vec<Elf64Rela>> {
    let offset = usize::try_from(offset).map_err(|_| ElfError::InvalidOffset {
        kind: "relocation section",
        offset,
    })?;
    let size = usize::try_from(size).map_err(|_| ElfError::InvalidOffset {
        kind: "relocation section size",
        offset: size,
    })?;

    let end = offset.checked_add(size).ok_or(ElfError::InvalidOffset {
        kind: "relocation section",
        offset: offset as u64,
    })?;

    if end > data.len() {
        return Err(ElfError::BufferTooSmall {
            needed: end,
            available: data.len(),
        });
    }

    if size % Elf64Rela::SIZE != 0 {
        return Err(ElfError::InvalidOffset {
            kind: "relocation section size",
            offset: size as u64,
        });
    }

    let count = size / Elf64Rela::SIZE;
    let mut relocs = Vec::with_capacity(count);

    for i in 0..count {
        let rel_offset = offset + i * Elf64Rela::SIZE;
        let reloc = Elf64Rela::parse(&data[rel_offset..])?;
        relocs.push(reloc);
    }

    Ok(relocs)
}

/// Parse raw `DT_RELR`/`.relr.dyn` entries from an ELF byte range.
pub fn parse_relr_entries(data: &[u8], offset: u64, size: u64) -> ElfResult<Vec<u64>> {
    let offset = usize::try_from(offset).map_err(|_| ElfError::InvalidOffset {
        kind: "RELR section",
        offset,
    })?;
    let size = usize::try_from(size).map_err(|_| ElfError::InvalidOffset {
        kind: "RELR section size",
        offset: size,
    })?;

    let end = offset.checked_add(size).ok_or(ElfError::InvalidOffset {
        kind: "RELR section",
        offset: offset as u64,
    })?;
    if end > data.len() {
        return Err(ElfError::BufferTooSmall {
            needed: end,
            available: data.len(),
        });
    }
    if size % 8 != 0 {
        return Err(ElfError::InvalidOffset {
            kind: "RELR section size",
            offset: size as u64,
        });
    }

    Ok(data[offset..end]
        .chunks_exact(8)
        .map(|chunk| {
            u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ])
        })
        .collect())
}

/// Expand compressed `DT_RELR` entries into relative relocation target offsets.
pub fn expand_relr_entries(entries: &[u64]) -> ElfResult<Vec<u64>> {
    let mut targets = Vec::new();
    let mut cursor = None;

    for &entry in entries {
        if entry & 1 == 0 {
            targets.push(entry);
            cursor = Some(entry.checked_add(8).ok_or(ElfError::InvalidOffset {
                kind: "RELR cursor",
                offset: entry,
            })?);
            continue;
        }

        let start = cursor.ok_or(ElfError::InvalidOffset {
            kind: "RELR bitmap without base",
            offset: entry,
        })?;
        for bit in 1..64 {
            if entry & (1u64 << bit) != 0 {
                let delta = ((bit - 1) as u64)
                    .checked_mul(8)
                    .ok_or(ElfError::InvalidOffset {
                        kind: "RELR bitmap delta",
                        offset: entry,
                    })?;
                targets.push(start.checked_add(delta).ok_or(ElfError::InvalidOffset {
                    kind: "RELR bitmap target",
                    offset: start,
                })?);
            }
        }
        cursor = Some(start.checked_add(63 * 8).ok_or(ElfError::InvalidOffset {
            kind: "RELR cursor",
            offset: start,
        })?);
    }

    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_relative_reloc(offset: u64, addend: i64) -> [u8; 24] {
        let mut data = [0u8; 24];
        // r_offset
        data[0..8].copy_from_slice(&offset.to_le_bytes());
        // r_info: type = RELATIVE (8), symbol = 0
        let r_info: u64 = 8;
        data[8..16].copy_from_slice(&r_info.to_le_bytes());
        // r_addend
        data[16..24].copy_from_slice(&addend.to_le_bytes());
        data
    }

    fn make_glob_dat_reloc(offset: u64, symbol_idx: u32) -> [u8; 24] {
        let mut data = [0u8; 24];
        // r_offset
        data[0..8].copy_from_slice(&offset.to_le_bytes());
        // r_info: type = GLOB_DAT (6), symbol index
        let r_info: u64 = ((symbol_idx as u64) << 32) | 6;
        data[8..16].copy_from_slice(&r_info.to_le_bytes());
        data
    }

    fn make_reloc(
        offset: u64,
        symbol_idx: u32,
        reloc_type: RelocationType,
        addend: i64,
    ) -> Elf64Rela {
        Elf64Rela {
            r_offset: offset,
            r_info: ((symbol_idx as u64) << 32) | reloc_type.to_u32() as u64,
            r_addend: addend,
        }
    }

    #[test]
    fn test_parse_relative_reloc() {
        let data = make_relative_reloc(0x1000, 0x2000);
        let reloc = Elf64Rela::parse(&data).unwrap();

        assert_eq!(reloc.r_offset, 0x1000);
        assert_eq!(reloc.r_addend, 0x2000);
        assert!(matches!(reloc.reloc_type(), RelocationType::Relative));
        assert_eq!(reloc.symbol_index(), 0);
    }

    #[test]
    fn test_parse_glob_dat_reloc() {
        let data = make_glob_dat_reloc(0x3000, 42);
        let reloc = Elf64Rela::parse(&data).unwrap();

        assert_eq!(reloc.r_offset, 0x3000);
        assert!(matches!(reloc.reloc_type(), RelocationType::GlobDat));
        assert_eq!(reloc.symbol_index(), 42);
    }

    #[test]
    fn test_compute_relative() {
        let data = make_relative_reloc(0x1000, 0x2000);
        let reloc = Elf64Rela::parse(&data).unwrap();
        let ctx = RelocationContext::new(0x7f00_0000_0000);

        let (value, size) = compute_relocation(&reloc, 0, &ctx).unwrap();
        assert_eq!(size, 8);
        assert_eq!(value, 0x7f00_0000_0000 + 0x2000);
    }

    #[test]
    fn test_compute_glob_dat() {
        let data = make_glob_dat_reloc(0x3000, 1);
        let reloc = Elf64Rela::parse(&data).unwrap();
        let ctx = RelocationContext::new(0x7f00_0000_0000);

        let symbol_value = 0x7f00_0001_0000;
        let (value, size) = compute_relocation(&reloc, symbol_value, &ctx).unwrap();
        assert_eq!(size, 8);
        assert_eq!(value, symbol_value);
    }

    #[test]
    fn compute_r64_rejects_overflow() {
        let reloc = make_reloc(0, 0, RelocationType::R64, 1);
        let ctx = RelocationContext::new(0);
        assert_eq!(
            compute_relocation(&reloc, u64::MAX, &ctx),
            Err(RelocationResult::Overflow)
        );
    }

    #[test]
    fn compute_pc32_and_plt32_write_twos_complement_values() {
        let ctx = RelocationContext::new(0x1000);
        let pc32 = make_reloc(0x20, 1, RelocationType::Pc32, -4);
        let (value, size) = compute_relocation(&pc32, 0x1010, &ctx).unwrap();
        assert_eq!(size, 4);
        assert_eq!(value, 0xffff_ffec);

        let plt32 = make_reloc(0x20, 1, RelocationType::Plt32, -4);
        let (value, size) = compute_relocation(&plt32, 0x1028, &ctx).unwrap();
        assert_eq!(size, 4);
        assert_eq!(value, 4);
    }

    #[test]
    fn compute_fixed_width_relocations_check_target_ranges() {
        let ctx = RelocationContext::new(0x1000);

        let r32 = make_reloc(0, 0, RelocationType::R32, 1);
        assert_eq!(
            compute_relocation(&r32, u32::MAX as u64 - 1, &ctx).unwrap(),
            (u32::MAX as u64, 4)
        );

        let r32s = make_reloc(0, 0, RelocationType::R32S, -1);
        assert_eq!(
            compute_relocation(&r32s, 0, &ctx).unwrap(),
            (0xffff_ffff, 4)
        );

        let r16 = make_reloc(0, 0, RelocationType::R16, 0);
        assert_eq!(compute_relocation(&r16, 0xffff, &ctx).unwrap(), (0xffff, 2));

        let pc16 = make_reloc(0x20, 0, RelocationType::Pc16, 0);
        assert_eq!(
            compute_relocation(&pc16, 0x1010, &ctx).unwrap(),
            (0xfff0, 2)
        );

        let r8 = make_reloc(0, 0, RelocationType::R8, -1);
        assert_eq!(compute_relocation(&r8, 0, &ctx).unwrap(), (0xff, 1));

        let pc8 = make_reloc(0x20, 0, RelocationType::Pc8, 0);
        assert_eq!(compute_relocation(&pc8, 0x101f, &ctx).unwrap(), (0xff, 1));

        let overflow = make_reloc(0, 0, RelocationType::R16, 0);
        assert_eq!(
            compute_relocation(&overflow, 0x1_0000, &ctx),
            Err(RelocationResult::Overflow)
        );
    }

    #[test]
    fn copy_and_irelative_have_deterministic_non_write_results() {
        let ctx = RelocationContext::new(0x1000);
        let copy = make_reloc(0, 1, RelocationType::Copy, 0);
        let irelative = make_reloc(0, 0, RelocationType::IRelative, 0x20);

        assert_eq!(
            compute_relocation(&copy, 0x2000, &ctx),
            Err(RelocationResult::Deferred)
        );
        assert_eq!(
            compute_relocation(&irelative, 0, &ctx),
            Err(RelocationResult::Unsupported(37))
        );
    }

    #[test]
    fn parse_relocations_rejects_overflowing_range_without_panicking() {
        let err = parse_relocations(&[], usize::MAX as u64, 1).unwrap_err();
        assert!(matches!(
            err,
            ElfError::InvalidOffset {
                kind: "relocation section",
                ..
            }
        ));
    }

    #[test]
    fn parse_relocations_rejects_partial_entry() {
        let data = [0u8; Elf64Rela::SIZE + 1];
        let err = parse_relocations(&data, 0, data.len() as u64).unwrap_err();
        assert!(matches!(
            err,
            ElfError::InvalidOffset {
                kind: "relocation section size",
                ..
            }
        ));
    }

    #[test]
    fn parse_and_expand_relr_entries() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        data.extend_from_slice(&0b1011u64.to_le_bytes());

        let entries = parse_relr_entries(&data, 0, data.len() as u64).unwrap();
        assert_eq!(entries, vec![0x1000, 0b1011]);

        let targets = expand_relr_entries(&entries).unwrap();
        assert_eq!(targets, vec![0x1000, 0x1008, 0x1018]);
    }

    #[test]
    fn parse_relr_entries_rejects_partial_entry_and_leading_bitmap() {
        let err = parse_relr_entries(&[0; 9], 0, 9).unwrap_err();
        assert!(matches!(
            err,
            ElfError::InvalidOffset {
                kind: "RELR section size",
                ..
            }
        ));

        let err = expand_relr_entries(&[0b11]).unwrap_err();
        assert!(matches!(
            err,
            ElfError::InvalidOffset {
                kind: "RELR bitmap without base",
                ..
            }
        ));
    }

    #[test]
    fn test_relocation_type_support() {
        assert!(RelocationType::None.is_supported());
        assert!(RelocationType::R64.is_supported());
        assert!(RelocationType::Pc32.is_supported());
        assert!(RelocationType::Plt32.is_supported());
        assert!(RelocationType::GlobDat.is_supported());
        assert!(RelocationType::JumpSlot.is_supported());
        assert!(RelocationType::Relative.is_supported());
        assert!(RelocationType::IRelative.is_supported());

        assert!(!RelocationType::Copy.is_supported());
        assert!(!RelocationType::DtpMod64.is_supported());
    }

    #[test]
    fn test_tls_relocation_detection() {
        assert!(RelocationType::DtpMod64.is_tls());
        assert!(RelocationType::DtpOff64.is_tls());
        assert!(RelocationType::TpOff64.is_tls());
        assert!(!RelocationType::R64.is_tls());
        assert!(!RelocationType::Relative.is_tls());
    }
}
