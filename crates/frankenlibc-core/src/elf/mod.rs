//! ELF (Executable and Linkable Format) parsing and relocation.
//!
//! This module provides a clean-room Rust implementation of ELF64 parsing,
//! symbol lookup, and relocation application for x86_64 Linux.
//!
//! # Design Principles
//!
//! 1. **Spec-first**: Derived from ELF64 specification, not glibc source
//! 2. **Safe by construction**: No raw pointer arithmetic outside explicit validation
//! 3. **Formally structured**: Type-safe enums for all classification fields
//! 4. **Phase 1 scope**: Non-IFUNC relocations only; IFUNC support deferred
//!
//! # Supported Relocation Types (Phase 1)
//!
//! - `R_X86_64_NONE` (0): No relocation
//! - `R_X86_64_64` (1): Direct 64-bit absolute
//! - `R_X86_64_PC32` (2): PC-relative 32-bit signed
//! - `R_X86_64_GLOB_DAT` (6): Create GOT entry
//! - `R_X86_64_JUMP_SLOT` (7): Create PLT entry
//! - `R_X86_64_RELATIVE` (8): Adjust by program base
//! - `R_X86_64_COPY` (5): Copy symbol at runtime (deferred)
//!
//! # Unsupported (Explicitly Tracked)
//!
//! - IFUNC relocations (`R_X86_64_IRELATIVE`)
//! - TLS relocations (`R_X86_64_DTPMOD64`, `R_X86_64_DTPOFF64`, etc.)
//! - Architecture-specific variants (non-x86_64)

pub mod hash;
pub mod header;
pub mod loader;
pub mod program;
pub mod relocation;
pub mod section;
pub mod symbol;

pub use hash::{ElfHashTable, GnuHashTable, elf_hash, gnu_hash};
pub use header::{Elf64Header, ElfClass, ElfData, ElfMachine, ElfOsAbi, ElfType};
pub use loader::{ElfLoader, LoadedObject, NullSymbolLookup, RelocationStats, SymbolLookup};
pub use program::{Elf64ProgramHeader, ProgramFlags, ProgramType};
pub use relocation::{Elf64Rela, RelocationResult, RelocationType};
pub use section::{Elf64SectionHeader, SectionFlags, SectionType};
pub use symbol::{Elf64Symbol, SymbolBinding, SymbolType, SymbolVisibility};

/// ELF magic bytes: "\x7fELF"
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Size of ELF identification array
pub const EI_NIDENT: usize = 16;

/// Error type for ELF parsing operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfError {
    /// Invalid ELF magic bytes
    InvalidMagic,
    /// Unsupported ELF class (not ELF64)
    UnsupportedClass(u8),
    /// Unsupported data encoding (not little-endian)
    UnsupportedEncoding(u8),
    /// Unsupported machine type (not x86_64)
    UnsupportedMachine(u16),
    /// Invalid section/program header offset
    InvalidOffset { kind: &'static str, offset: u64 },
    /// Buffer too small for requested operation
    BufferTooSmall { needed: usize, available: usize },
    /// Invalid string table index
    InvalidStringIndex(u32),
    /// Symbol not found during lookup
    SymbolNotFound { name: &'static str },
    /// Unsupported relocation type
    UnsupportedRelocation(u32),
    /// Relocation overflow (value doesn't fit in target)
    RelocationOverflow { reloc_type: u32, value: u64 },
    /// Invalid symbol index in relocation
    InvalidSymbolIndex(u32),
    /// Version mismatch during symbol resolution
    VersionMismatch {
        symbol: &'static str,
        required: u16,
        found: u16,
    },
}

impl core::fmt::Display for ElfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid ELF magic"),
            Self::UnsupportedClass(c) => write!(f, "unsupported ELF class: {c}"),
            Self::UnsupportedEncoding(e) => write!(f, "unsupported data encoding: {e}"),
            Self::UnsupportedMachine(m) => write!(f, "unsupported machine type: {m}"),
            Self::InvalidOffset { kind, offset } => {
                write!(f, "invalid {kind} offset: {offset:#x}")
            }
            Self::BufferTooSmall { needed, available } => {
                write!(f, "buffer too small: need {needed}, have {available}")
            }
            Self::InvalidStringIndex(idx) => write!(f, "invalid string index: {idx}"),
            Self::SymbolNotFound { name } => write!(f, "symbol not found: {name}"),
            Self::UnsupportedRelocation(r) => write!(f, "unsupported relocation type: {r}"),
            Self::RelocationOverflow { reloc_type, value } => {
                write!(
                    f,
                    "relocation overflow: type {reloc_type}, value {value:#x}"
                )
            }
            Self::InvalidSymbolIndex(idx) => write!(f, "invalid symbol index: {idx}"),
            Self::VersionMismatch {
                symbol,
                required,
                found,
            } => {
                write!(
                    f,
                    "version mismatch for {symbol}: required {required}, found {found}"
                )
            }
        }
    }
}

/// Result type for ELF operations.
pub type ElfResult<T> = Result<T, ElfError>;

/// Support classification for relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationSupport {
    /// Fully implemented in phase 1
    Implemented,
    /// Documented stub with deterministic behavior
    Stub,
    /// Explicitly unsupported, returns error
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elf_magic() {
        assert_eq!(ELF_MAGIC, [0x7f, 0x45, 0x4c, 0x46]);
    }

    #[test]
    fn test_error_display() {
        let err = ElfError::InvalidMagic;
        assert_eq!(format!("{err}"), "invalid ELF magic");

        let err = ElfError::UnsupportedMachine(0x3e);
        assert_eq!(format!("{err}"), "unsupported machine type: 62");
    }
}
