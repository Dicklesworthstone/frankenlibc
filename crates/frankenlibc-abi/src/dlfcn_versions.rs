//! GNU symbol versions for the native link map.
//!
//! Read the runtime tables, not section headers. Keep version visibility apart
//! from ELF symbol visibility: foo@OLD is available to dlvsym but is not the
//! public dlsym default. Unversioned relocations additionally retain GNU's
//! version-index-2 compatibility rule. No function or IFUNC is executed here.

use std::collections::BTreeMap;

use frankenlibc_core::elf::hash::elf_hash;
use frankenlibc_core::elf::{Elf64Symbol, LoadedObject, ProgramType};

const VERSYM: i64 = 0x6fff_fff0;
const VERDEF: i64 = 0x6fff_fffc;
const VERDEFNUM: i64 = 0x6fff_fffd;
const VERNEED: i64 = 0x6fff_fffe;
const VERNEEDNUM: i64 = 0x6fff_ffff;

#[derive(Clone, Copy, Debug)]
pub(super) enum Lookup {
    Public,
    Relocation { hidden: bool },
}

#[derive(Debug)]
pub(super) struct RequiredVersion {
    pub(super) name: String,
    pub(super) hash: u32,
    pub(super) weak: bool,
}

#[derive(Debug)]
pub(super) struct Requirement {
    pub(super) library: String,
    pub(super) versions: Vec<RequiredVersion>,
}

#[derive(Debug, Default)]
pub(super) struct Table {
    versioned: bool,
    has_definitions: bool,
    raw: Vec<u16>,
    names: BTreeMap<u16, String>,
    hidden_requests: BTreeMap<u16, bool>,
    symbols: BTreeMap<String, Vec<usize>>,
    pub(super) definitions: BTreeMap<String, u32>,
    pub(super) requirements: Vec<Requirement>,
}

fn bytes_at(bytes: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
    bytes.get(offset..offset.checked_add(size)?)
}

fn word(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes_at(bytes, offset, 2)?.try_into().ok()?))
}

fn dword(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes_at(bytes, offset, 4)?.try_into().ok()?))
}

fn string(bytes: &[u8], offset: u32) -> Option<&str> {
    let bytes = bytes.get(usize::try_from(offset).ok()?..)?;
    std::str::from_utf8(bytes.get(..bytes.iter().position(|&byte| byte == 0)?)?).ok()
}

struct Image<'a> {
    bytes: &'a [u8],
    object: &'a LoadedObject,
}

impl<'a> Image<'a> {
    fn tail(&self, address: u64) -> Option<(u64, &'a [u8])> {
        let mut found: Option<(u64, &'a [u8])> = None;
        for header in self.object.program_headers.iter().filter(|header| header.is_load()) {
            let Some(delta) = address.checked_sub(header.p_vaddr) else { continue; };
            if delta >= header.p_filesz { continue; }
            let offset = header.p_offset.checked_add(delta)?;
            let bytes = bytes_at(self.bytes, usize::try_from(offset).ok()?,
                usize::try_from(header.p_filesz - delta).ok()?)?;
            if let Some((previous_offset, previous)) = found {
                if offset != previous_offset { return None; }
                if previous.len() >= bytes.len() { continue; }
            }
            found = Some((offset, bytes));
        }
        found
    }

    fn span(&self, address: u64, size: usize) -> Option<&'a [u8]> {
        self.tail(address)?.1.get(..size)
    }

    fn dynamic(&self) -> Option<BTreeMap<i64, u64>> {
        let mut headers = self.object.program_headers.iter()
            .filter(|header| header.p_type == ProgramType::Dynamic);
        let Some(header) = headers.next() else { return Some(BTreeMap::new()); };
        if headers.next().is_some() || header.p_filesz > header.p_memsz { return None; }
        let (offset, bytes) = self.tail(header.p_vaddr)?;
        if offset != header.p_offset { return None; }
        let size = usize::try_from(header.p_filesz).ok()?;
        if size % 16 != 0 { return None; }
        let mut tags = BTreeMap::new();
        for entry in bytes.get(..size)?.chunks_exact(16) {
            let tag = i64::from_le_bytes(entry[..8].try_into().ok()?);
            let value = u64::from_le_bytes(entry[8..].try_into().ok()?);
            if tag == 0 { return Some(tags); }
            if matches!(tag, 5 | 10 | VERSYM | VERDEF | VERDEFNUM | VERNEED | VERNEEDNUM) {
                if tags.insert(tag, value).is_some_and(|old| old != value) { return None; }
            }
        }
        None
    }

    fn records(&self, tags: &BTreeMap<i64, u64>, address: i64, count: i64, width: usize)
        -> Option<(&'a [u8], usize)>
    {
        match (tags.get(&address), tags.get(&count)) {
            (None, None) => Some((&[], 0)),
            (Some(_), Some(0)) => Some((&[], 0)),
            (Some(&address), Some(&count)) => {
                let bytes = self.tail(address)?.1;
                let count = usize::try_from(count).ok()?;
                (count <= bytes.len() / width).then_some((bytes, count))
            }
            _ => None,
        }
    }
}

/// One relative-offset record, with its auxiliaries confined before the next
/// record. Counts and forward-only offsets bound both nested walks.
fn record(bytes: &[u8], offset: usize, width: usize, next_field: usize, last: bool)
    -> Option<(&[u8], usize)>
{
    let header = bytes_at(bytes, offset, width)?;
    let next = usize::try_from(dword(header, next_field)?).ok()?;
    if last != (next == 0) || (next != 0 && next < width) { return None; }
    let end = if next == 0 { bytes.len() } else { offset.checked_add(next)? };
    Some((bytes.get(offset..end)?, end))
}

fn insert_name(names: &mut BTreeMap<u16, String>, index: u16, name: &str) -> Option<()> {
    if index == 0 || name.is_empty() { return None; }
    if names.insert(index, name.to_owned()).is_some_and(|old| old != name) { return None; }
    Some(())
}

impl Table {
    pub(super) fn parse(bytes: &[u8], object: &LoadedObject) -> Option<Self> {
        let image = Image { bytes, object };
        let tags = image.dynamic()?;
        let mut table = Self { has_definitions: tags.contains_key(&VERDEF), ..Self::default() };
        let mut names = BTreeMap::new();
        let has_records = tags.contains_key(&VERDEF) || tags.contains_key(&VERNEED)
            || tags.contains_key(&VERSYM);
        let strings = if has_records {
            image.span(*tags.get(&5)?, usize::try_from(*tags.get(&10)?).ok()?)?
        } else { &[] };
        let (definitions, count) = image.records(&tags, VERDEF, VERDEFNUM, 20)?;
        let mut offset = 0;
        for ordinal in 0..count {
            let (definition, next) = record(definitions, offset, 20, 16, ordinal + 1 == count)?;
            if word(definition, 0)? != 1 { return None; }
            let index = word(definition, 4)?;
            if index & 0x8000 != 0 { return None; }
            let count = usize::from(word(definition, 6)?);
            let mut aux = usize::try_from(dword(definition, 12)?).ok()?;
            if count == 0 || count > definition.len() / 8 || aux < 20 { return None; }
            for ordinal in 0..count {
                let (entry, next_aux) = record(definition, aux, 8, 4, ordinal + 1 == count)?;
                let name = string(strings, dword(entry, 0)?)?;
                if ordinal == 0 {
                    let hash = dword(definition, 8)?;
                    if hash != elf_hash(name.as_bytes()) { return None; }
                    insert_name(&mut names, index, name)?;
                    if table.definitions.insert(name.to_owned(), hash).is_some() { return None; }
                }
                aux = next_aux;
            }
            offset = next;
        }
        let (requirements, count) = image.records(&tags, VERNEED, VERNEEDNUM, 16)?;
        let mut offset = 0;
        for ordinal in 0..count {
            let (requirement, next) = record(requirements, offset, 16, 12, ordinal + 1 == count)?;
            if word(requirement, 0)? != 1 { return None; }
            let count = usize::from(word(requirement, 2)?);
            let library = string(strings, dword(requirement, 4)?)?;
            if library.is_empty() { return None; }
            let mut required = Requirement { library: library.to_owned(), versions: Vec::new() };
            let mut aux = usize::try_from(dword(requirement, 8)?).ok()?;
            if count == 0 || count > requirement.len() / 16 || aux < 16 { return None; }
            for ordinal in 0..count {
                let (entry, next_aux) = record(requirement, aux, 16, 12, ordinal + 1 == count)?;
                let raw = word(entry, 6)?;
                let index = raw & 0x7fff;
                if index <= 1 { return None; }
                let name = string(strings, dword(entry, 8)?)?;
                let hash = dword(entry, 0)?;
                if hash != elf_hash(name.as_bytes()) { return None; }
                insert_name(&mut names, index, name)?;
                let hidden = raw & 0x8000 != 0;
                if table.hidden_requests.insert(index, hidden).is_some_and(|old| old != hidden) {
                    return None;
                }
                required.versions.push(RequiredVersion {
                    name: name.to_owned(), hash, weak: word(entry, 4)? & 2 != 0,
                });
                aux = next_aux;
            }
            table.requirements.push(required);
            offset = next;
        }
        if let Some(&address) = tags.get(&VERSYM) {
            table.versioned = true;
            let bytes = image.span(address, object.dynsym.len().checked_mul(2)?)?;
            for entry in bytes.chunks_exact(2) {
                let raw = u16::from_le_bytes(entry.try_into().ok()?);
                let index = raw & 0x7fff;
                table.raw.push(raw);
                if index > 1 && !names.contains_key(&index) { return None; }
            }
        }
        table.names = names;
        for (index, symbol) in object.dynsym.iter().enumerate() {
            if !symbol.is_defined() || symbol.is_local() || matches!(symbol.st_other & 3, 1 | 2) {
                continue;
            }
            let name = object.symbol_name(symbol)?;
            if !name.is_empty() {
                table.symbols.entry(name.to_owned()).or_default().push(index);
            }
        }
        Some(table)
    }

    /// GNU permits a truly unversioned replacement provider. A provider with
    /// VERDEF, however, must advertise every strong requested version even if
    /// no relocation in the consumer currently refers to it. Weak requirements
    /// do not make an otherwise compatible load fail.
    pub(super) fn satisfies(&self, requirement: &Requirement) -> bool {
        !self.has_definitions || requirement.versions.iter().all(|required| {
            required.weak || self.definitions.get(&required.name) == Some(&required.hash)
        })
    }

    pub(super) fn name(&self, index: usize) -> Option<&str> {
        let index = self.raw.get(index)? & 0x7fff;
        (index > 1).then(|| self.names.get(&index).map(String::as_str)).flatten()
    }

    pub(super) fn relocation(&self, index: usize) -> Lookup {
        let hidden = self.raw.get(index).and_then(|raw| self.hidden_requests.get(&(raw & 0x7fff)))
            .copied().unwrap_or(false);
        Lookup::Relocation { hidden }
    }

    pub(super) fn lookup<'a>(&self, object: &'a LoadedObject, name: &str,
        requested: Option<&str>, mode: Lookup) -> Option<&'a Elf64Symbol>
    {
        let mut fallback = None;
        let mut ambiguous = false;
        for &slot in self.symbols.get(name)? {
            let symbol = object.dynsym.get(slot)?;
            // Unversioned providers can interpose versioned imports and are
            // accepted by dlvsym. Do not confuse them with index 1 in a DSO
            // that *does* have a version table.
            if !self.versioned { return Some(symbol); }
            let raw = *self.raw.get(slot)?;
            let index = raw & 0x7fff;
            if index == 0 { continue; }
            if let Some(requested) = requested {
                if self.name(slot).unwrap_or("") == requested { return Some(symbol); }
                if !matches!(mode, Lookup::Relocation { hidden: false }) || index != 1 || raw & 0x8000 != 0 {
                    continue;
                }
            } else {
                let compatibility = matches!(mode, Lookup::Relocation { .. }) && index == 2;
                if compatibility || (index == 1 && raw & 0x8000 == 0) { return Some(symbol); }
                if raw & 0x8000 != 0 { continue; }
            }
            // GNU accepts a unique public version when no exact/base match
            // exists. Never choose one arbitrarily when a malformed table
            // exposes more than one public version of the same name.
            ambiguous |= fallback.is_some();
            fallback = Some(symbol);
        }
        if ambiguous { None } else { fallback }
    }
}
