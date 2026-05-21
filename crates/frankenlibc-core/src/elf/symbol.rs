//! ELF64 symbol table parsing.
//!
//! Symbols represent named entities (functions, variables) in an ELF file.

use super::{ElfError, ElfResult};

/// Symbol binding (scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SymbolBinding {
    /// Local (not visible outside object file)
    Local = 0,
    /// Global (visible everywhere)
    Global = 1,
    /// Weak (like global, but may be overridden)
    Weak = 2,
    /// Unknown binding
    Unknown(u8),
}

impl From<u8> for SymbolBinding {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Local,
            1 => Self::Global,
            2 => Self::Weak,
            other => Self::Unknown(other),
        }
    }
}

/// Symbol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SymbolType {
    /// Unspecified type
    NoType = 0,
    /// Data object (variable)
    Object = 1,
    /// Function
    Func = 2,
    /// Section
    Section = 3,
    /// Source file name
    File = 4,
    /// Common symbol
    Common = 5,
    /// TLS data object
    Tls = 6,
    /// Indirect function (GNU extension)
    IFunc = 10,
    /// Unknown type
    Unknown(u8),
}

impl From<u8> for SymbolType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::NoType,
            1 => Self::Object,
            2 => Self::Func,
            3 => Self::Section,
            4 => Self::File,
            5 => Self::Common,
            6 => Self::Tls,
            10 => Self::IFunc,
            other => Self::Unknown(other),
        }
    }
}

/// Symbol visibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SymbolVisibility {
    /// Default visibility (binding determines visibility)
    Default = 0,
    /// Internal (processor-specific)
    Internal = 1,
    /// Hidden (not exported)
    Hidden = 2,
    /// Protected (exported but not preemptible)
    Protected = 3,
}

impl From<u8> for SymbolVisibility {
    fn from(value: u8) -> Self {
        match value & 0x3 {
            0 => Self::Default,
            1 => Self::Internal,
            2 => Self::Hidden,
            3 => Self::Protected,
            _ => unreachable!(),
        }
    }
}

/// Special section indices.
pub mod section_index {
    /// Undefined symbol
    pub const SHN_UNDEF: u16 = 0;
    /// Absolute value
    pub const SHN_ABS: u16 = 0xfff1;
    /// Common symbol
    pub const SHN_COMMON: u16 = 0xfff2;
}

/// ELF64 symbol table entry.
#[derive(Debug, Clone, Copy)]
pub struct Elf64Symbol {
    /// Symbol name (index into string table)
    pub st_name: u32,
    /// Symbol info (type and binding)
    pub st_info: u8,
    /// Symbol visibility
    pub st_other: u8,
    /// Section index
    pub st_shndx: u16,
    /// Symbol value (address)
    pub st_value: u64,
    /// Symbol size
    pub st_size: u64,
}

impl Elf64Symbol {
    /// Size of an ELF64 symbol entry in bytes.
    pub const SIZE: usize = 24;

    /// Parse a symbol from a byte slice.
    pub fn parse(data: &[u8]) -> ElfResult<Self> {
        if data.len() < Self::SIZE {
            return Err(ElfError::BufferTooSmall {
                needed: Self::SIZE,
                available: data.len(),
            });
        }

        let st_name = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let st_info = data[4];
        let st_other = data[5];
        let st_shndx = u16::from_le_bytes([data[6], data[7]]);
        let st_value = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        let st_size = u64::from_le_bytes([
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]);

        Ok(Self {
            st_name,
            st_info,
            st_other,
            st_shndx,
            st_value,
            st_size,
        })
    }

    /// Get the symbol binding.
    pub fn binding(&self) -> SymbolBinding {
        SymbolBinding::from(self.st_info >> 4)
    }

    /// Get the symbol type.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::from(self.st_info & 0xf)
    }

    /// Get the symbol visibility.
    pub fn visibility(&self) -> SymbolVisibility {
        SymbolVisibility::from(self.st_other)
    }

    /// Check if this is an undefined symbol.
    pub fn is_undefined(&self) -> bool {
        self.st_shndx == section_index::SHN_UNDEF
    }

    /// Check if this is a function symbol.
    pub fn is_function(&self) -> bool {
        matches!(self.symbol_type(), SymbolType::Func)
    }

    /// Check if this is an object (data) symbol.
    pub fn is_object(&self) -> bool {
        matches!(self.symbol_type(), SymbolType::Object)
    }

    /// Check if this is an IFUNC (indirect function) symbol.
    pub fn is_ifunc(&self) -> bool {
        matches!(self.symbol_type(), SymbolType::IFunc)
    }

    /// Check if this is a TLS symbol.
    pub fn is_tls(&self) -> bool {
        matches!(self.symbol_type(), SymbolType::Tls)
    }

    /// Check if this is a global symbol.
    pub fn is_global(&self) -> bool {
        matches!(self.binding(), SymbolBinding::Global)
    }

    /// Check if this is a weak symbol.
    pub fn is_weak(&self) -> bool {
        matches!(self.binding(), SymbolBinding::Weak)
    }

    /// Check if this is a local symbol.
    pub fn is_local(&self) -> bool {
        matches!(self.binding(), SymbolBinding::Local)
    }

    /// Check if this symbol is hidden.
    pub fn is_hidden(&self) -> bool {
        matches!(self.visibility(), SymbolVisibility::Hidden)
    }

    /// Check if this symbol is defined (has a value).
    pub fn is_defined(&self) -> bool {
        !self.is_undefined() && self.st_shndx != section_index::SHN_COMMON
    }
}

/// Parse all symbols from a symbol table section.
pub fn parse_symbols(data: &[u8], offset: u64, size: u64) -> ElfResult<Vec<Elf64Symbol>> {
    let offset = usize::try_from(offset).map_err(|_| ElfError::InvalidOffset {
        kind: "symbol table",
        offset,
    })?;
    let size = usize::try_from(size).map_err(|_| ElfError::InvalidOffset {
        kind: "symbol table size",
        offset: size,
    })?;

    let end = offset.checked_add(size).ok_or(ElfError::InvalidOffset {
        kind: "symbol table",
        offset: offset as u64,
    })?;

    if end > data.len() {
        return Err(ElfError::BufferTooSmall {
            needed: end,
            available: data.len(),
        });
    }

    if size % Elf64Symbol::SIZE != 0 {
        return Err(ElfError::InvalidOffset {
            kind: "symbol table size",
            offset: size as u64,
        });
    }

    let count = size / Elf64Symbol::SIZE;
    let mut symbols = Vec::with_capacity(count);

    for i in 0..count {
        let sym_offset = offset + i * Elf64Symbol::SIZE;
        let symbol = Elf64Symbol::parse(&data[sym_offset..])?;
        symbols.push(symbol);
    }

    Ok(symbols)
}

/// Get a string from a string table.
pub fn get_string(strtab: &[u8], index: u32) -> ElfResult<&str> {
    let index = index as usize;
    if index >= strtab.len() {
        return Err(ElfError::InvalidStringIndex(index as u32));
    }

    // Find null terminator
    let end = strtab[index..]
        .iter()
        .position(|&b| b == 0)
        .ok_or(ElfError::InvalidStringIndex(index as u32))?;

    core::str::from_utf8(&strtab[index..index + end])
        .map_err(|_| ElfError::InvalidStringIndex(index as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_global_func_symbol() -> [u8; 24] {
        let mut sym = [0u8; 24];
        // st_name = 0x10
        sym[0] = 0x10;
        // st_info = GLOBAL (1 << 4) | FUNC (2) = 0x12
        sym[4] = 0x12;
        // st_other = DEFAULT visibility
        sym[5] = 0;
        // st_shndx = 1 (defined in section 1)
        sym[6] = 1;
        // st_value = 0x1000
        sym[8] = 0x00;
        sym[9] = 0x10;
        // st_size = 0x100
        sym[16] = 0x00;
        sym[17] = 0x01;
        sym
    }

    #[test]
    fn test_parse_symbol() {
        let data = make_global_func_symbol();
        let sym = Elf64Symbol::parse(&data).unwrap();

        assert_eq!(sym.st_name, 0x10);
        assert!(sym.is_function());
        assert!(sym.is_global());
        assert!(!sym.is_undefined());
        assert!(sym.is_defined());
        assert_eq!(sym.st_value, 0x1000);
        assert_eq!(sym.st_size, 0x100);
        assert!(matches!(sym.visibility(), SymbolVisibility::Default));
    }

    #[test]
    fn test_undefined_symbol() {
        let mut data = make_global_func_symbol();
        data[6] = 0; // SHN_UNDEF
        data[7] = 0;
        let sym = Elf64Symbol::parse(&data).unwrap();

        assert!(sym.is_undefined());
        assert!(!sym.is_defined());
    }

    #[test]
    fn test_weak_symbol() {
        let mut data = make_global_func_symbol();
        data[4] = 0x22; // WEAK (2 << 4) | FUNC (2)
        let sym = Elf64Symbol::parse(&data).unwrap();

        assert!(sym.is_weak());
        assert!(!sym.is_global());
    }

    #[test]
    fn test_get_string() {
        let strtab = b"\0hello\0world\0";
        assert_eq!(get_string(strtab, 1).unwrap(), "hello");
        assert_eq!(get_string(strtab, 7).unwrap(), "world");
        assert!(get_string(strtab, 100).is_err());
    }

    #[test]
    fn parse_symbols_rejects_overflowing_range_without_panicking() {
        let err = parse_symbols(&[], usize::MAX as u64, 1).unwrap_err();
        assert!(matches!(
            err,
            ElfError::InvalidOffset {
                kind: "symbol table",
                ..
            }
        ));
    }

    #[test]
    fn parse_symbols_rejects_partial_entry() {
        let data = [0u8; Elf64Symbol::SIZE + 1];
        let err = parse_symbols(&data, 0, data.len() as u64).unwrap_err();
        assert!(matches!(
            err,
            ElfError::InvalidOffset {
                kind: "symbol table size",
                ..
            }
        ));
    }

    #[test]
    fn test_symbol_binding_conversion() {
        assert!(matches!(SymbolBinding::from(0), SymbolBinding::Local));
        assert!(matches!(SymbolBinding::from(1), SymbolBinding::Global));
        assert!(matches!(SymbolBinding::from(2), SymbolBinding::Weak));
        assert!(matches!(
            SymbolBinding::from(99),
            SymbolBinding::Unknown(99)
        ));
    }

    #[test]
    fn test_symbol_type_conversion() {
        assert!(matches!(SymbolType::from(0), SymbolType::NoType));
        assert!(matches!(SymbolType::from(1), SymbolType::Object));
        assert!(matches!(SymbolType::from(2), SymbolType::Func));
        assert!(matches!(SymbolType::from(10), SymbolType::IFunc));
        assert!(matches!(SymbolType::from(99), SymbolType::Unknown(99)));
    }
}
