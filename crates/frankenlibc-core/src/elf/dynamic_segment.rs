//! Runtime ELF metadata for objects without a section-header table.
//!
//! Dynamic addresses are virtual addresses, not file offsets. Every table is
//! translated through a file-backed PT_LOAD range before it is inspected or
//! allocated. Hash tables bound dynsym; neither neighbouring table addresses
//! nor relocation symbol indexes are used to guess its length.
//!
//! Layouts: System V gABI Dynamic Linking; LSB Symbol Versioning. This module
//! does not implement a second relocation engine: it feeds the existing safe
//! symbol, hash, RELA and RELR parsers and the existing native loader.

use std::collections::BTreeMap;

use super::{
    Elf64Header, Elf64ProgramHeader, ElfError, ElfHashTable, ElfResult, GnuHashTable,
    LoadedObject, ProgramType, TlsSegment, expand_relr_entries, get_string,
    parse_relocations, parse_relr_entries, parse_symbols,
};

const DT_NEEDED: i64 = 1;
const DT_PLTRELSZ: i64 = 2;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_INIT: i64 = 12;
const DT_FINI: i64 = 13;
const DT_SONAME: i64 = 14;
const DT_REL: i64 = 17;
const DT_RELSZ: i64 = 18;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const DT_INIT_ARRAY: i64 = 25;
const DT_FINI_ARRAY: i64 = 26;
const DT_INIT_ARRAYSZ: i64 = 27;
const DT_FINI_ARRAYSZ: i64 = 28;
const DT_RELRSZ: i64 = 35;
const DT_RELR: i64 = 36;
const DT_RELRENT: i64 = 37;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_VERSYM: i64 = 0x6fff_fff0;
const DT_VERDEF: i64 = 0x6fff_fffc;
const DT_VERDEFNUM: i64 = 0x6fff_fffd;
const DT_VERNEED: i64 = 0x6fff_fffe;
const DT_VERNEEDNUM: i64 = 0x6fff_ffff;

fn invalid(kind: &'static str, offset: u64) -> ElfError {
    ElfError::InvalidOffset { kind, offset }
}

fn add(a: u64, b: u64) -> ElfResult<u64> {
    a.checked_add(b).ok_or_else(|| invalid("dynamic range overflow", a))
}

fn mul(a: u64, b: u64) -> ElfResult<u64> {
    a.checked_mul(b).ok_or_else(|| invalid("dynamic size overflow", a))
}

fn slice(bytes: &[u8], offset: u64, size: u64) -> ElfResult<&[u8]> {
    let end = add(offset, size)?;
    let start = usize::try_from(offset).map_err(|_| invalid("dynamic file range", offset))?;
    let end = usize::try_from(end).map_err(|_| invalid("dynamic file range", end))?;
    bytes.get(start..end).ok_or_else(|| invalid("dynamic file range", offset))
}

fn u16_at(bytes: &[u8], offset: u64) -> ElfResult<u16> {
    let bytes = slice(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(bytes: &[u8], offset: u64) -> ElfResult<u32> {
    let bytes = slice(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

struct Image<'a> {
    bytes: &'a [u8],
    headers: &'a [Elf64ProgramHeader],
}

impl<'a> Image<'a> {
    /// Return the file-backed suffix starting at a virtual address. Ambiguous
    /// overlapping mappings with different translations are invalid; a BSS
    /// address must never be interpreted as an on-disk table.
    fn tail(&self, address: u64) -> ElfResult<(u64, &'a [u8])> {
        let mut found: Option<(u64, &'a [u8])> = None;
        for header in self.headers.iter().filter(|header| header.is_load()) {
            let Some(delta) = address.checked_sub(header.p_vaddr) else { continue; };
            if delta >= header.p_filesz { continue; }
            let offset = add(header.p_offset, delta)?;
            let bytes = slice(self.bytes, offset, header.p_filesz - delta)?;
            if let Some((previous, previous_bytes)) = found {
                if previous != offset {
                    return Err(invalid("ambiguous dynamic mapping", address));
                }
                if previous_bytes.len() >= bytes.len() { continue; }
            }
            found = Some((offset, bytes));
        }
        found.ok_or_else(|| invalid("unmapped dynamic address", address))
    }

    fn table(&self, address: u64, size: u64) -> ElfResult<(u64, &'a [u8])> {
        let (offset, bytes) = self.tail(address)?;
        Ok((offset, slice(bytes, 0, size)?))
    }
}

struct Tags {
    single: BTreeMap<i64, u64>,
    needed: Vec<u64>,
}

impl Tags {
    fn parse(bytes: &[u8]) -> ElfResult<Self> {
        if !bytes.len().is_multiple_of(16) {
            return Err(invalid("PT_DYNAMIC entry size", bytes.len() as u64));
        }
        let mut result = Self { single: BTreeMap::new(), needed: Vec::new() };
        for entry in bytes.chunks_exact(16) {
            let tag = i64::from_le_bytes(entry[..8].try_into().map_err(|_| invalid("dynamic tag", 0))?);
            let value = u64::from_le_bytes(entry[8..].try_into().map_err(|_| invalid("dynamic value", 0))?);
            if tag == 0 { return Ok(result); }
            if tag == DT_NEEDED {
                result.needed.push(value);
            } else if matches!(tag,
                DT_PLTRELSZ | DT_HASH | DT_STRTAB | DT_SYMTAB | DT_RELA | DT_RELASZ |
                DT_RELAENT | DT_STRSZ | DT_SYMENT | DT_INIT | DT_FINI | DT_SONAME |
                DT_REL | DT_RELSZ | DT_PLTREL | DT_JMPREL | DT_INIT_ARRAY |
                DT_FINI_ARRAY | DT_INIT_ARRAYSZ | DT_FINI_ARRAYSZ | DT_RELRSZ |
                DT_RELR | DT_RELRENT | DT_GNU_HASH | DT_VERSYM | DT_VERDEF |
                DT_VERDEFNUM | DT_VERNEED | DT_VERNEEDNUM)
            {
                if let Some(previous) = result.single.insert(tag, value) {
                    if previous != value { return Err(invalid("conflicting dynamic tag", tag as u64)); }
                }
            }
        }
        Err(invalid("unterminated PT_DYNAMIC", bytes.len() as u64))
    }

    fn get(&self, tag: i64) -> Option<u64> {
        self.single.get(&tag).copied()
    }

    fn required(&self, tag: i64) -> ElfResult<u64> {
        self.get(tag).ok_or_else(|| invalid("missing dynamic tag", tag as u64))
    }

    fn region(&self, pointer: i64, size: i64, width: u64) -> ElfResult<Option<(u64, u64)>> {
        match (self.get(pointer), self.get(size)) {
            (None, None) => Ok(None),
            (Some(_), Some(0)) | (None, Some(0)) => Ok(None),
            (Some(address), Some(length)) if length.is_multiple_of(width) => Ok(Some((address, length))),
            _ => Err(invalid("invalid dynamic table description", pointer as u64)),
        }
    }
}

fn name(strings: &[u8], offset: u64) -> ElfResult<String> {
    let index = u32::try_from(offset).map_err(|_| invalid("dynamic string index", offset))?;
    get_string(strings, index).map(str::to_owned)
}

/// DT_HASH carries the complete dynamic-symbol count in nchain.
fn sysv_hash(image: &Image<'_>, address: u64) -> ElfResult<(ElfHashTable, u64)> {
    let (_, bytes) = image.tail(address)?;
    let buckets = u64::from(u32_at(bytes, 0)?);
    let count = u64::from(u32_at(bytes, 4)?);
    if buckets == 0 || count == 0 { return Err(invalid("empty DT_HASH", address)); }
    let length = add(8, mul(add(buckets, count)?, 4)?)?;
    let bytes = slice(bytes, 0, length)?;
    // Invalid chain indexes must not reach the existing lookup implementation.
    for word in bytes[8..].chunks_exact(4) {
        let index = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        if u64::from(index) >= count { return Err(invalid("DT_HASH symbol index", u64::from(index))); }
    }
    let table = ElfHashTable::parse(bytes).ok_or_else(|| invalid("DT_HASH", address))?;
    Ok((table, count))
}

/// GNU hash stores all unhashed symbols before symoffset. The last nonempty
/// bucket's terminated chain determines the end of dynsym. Scan only that
/// chain, not every bucket's suffix (which would allow quadratic work).
fn gnu_hash(image: &Image<'_>, address: u64) -> ElfResult<(GnuHashTable, u64)> {
    let (_, bytes) = image.tail(address)?;
    let buckets = u64::from(u32_at(bytes, 0)?);
    let first = u64::from(u32_at(bytes, 4)?);
    let bloom_words = u64::from(u32_at(bytes, 8)?);
    let shift = u32_at(bytes, 12)?;
    if buckets == 0 || first == 0 || !bloom_words.is_power_of_two() || shift >= 32 {
        return Err(invalid("DT_GNU_HASH header", address));
    }
    let bucket_start = add(16, mul(bloom_words, 8)?)?;
    let chain_start = add(bucket_start, mul(buckets, 4)?)?;
    let bucket_bytes = slice(bytes, bucket_start, mul(buckets, 4)?)?;
    let mut highest = 0u64;
    for bucket in bucket_bytes.chunks_exact(4) {
        let index = u64::from(u32::from_le_bytes([bucket[0], bucket[1], bucket[2], bucket[3]]));
        if index != 0 && index < first { return Err(invalid("DT_GNU_HASH bucket", index)); }
        highest = highest.max(index);
    }
    let mut count = first;
    if highest != 0 {
        let mut index = highest;
        loop {
            let offset = add(chain_start, mul(index - first, 4)?)?;
            let chain = u32_at(bytes, offset)?;
            index = add(index, 1)?;
            if chain & 1 != 0 { count = index; break; }
        }
    }
    let length = add(chain_start, mul(count - first, 4)?)?;
    let table = GnuHashTable::parse(slice(bytes, 0, length)?)
        .ok_or_else(|| invalid("DT_GNU_HASH", address))?;
    Ok((table, count))
}

fn word_array(image: &Image<'_>, tags: &Tags, pointer: i64, size: i64) -> ElfResult<Vec<u64>> {
    let Some((address, size)) = tags.region(pointer, size, 8)? else { return Ok(Vec::new()); };
    let (_, bytes) = image.table(address, size)?;
    Ok(bytes.chunks_exact(8).map(|word| {
        u64::from_le_bytes([word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7]])
    }).collect())
}

fn version_name(map: &mut BTreeMap<u16, String>, index: u16, value: String) -> ElfResult<()> {
    let index = index & 0x7fff;
    if let Some(previous) = map.insert(index, value.clone()) {
        if previous != value { return Err(invalid("conflicting symbol version", u64::from(index))); }
    }
    Ok(())
}

fn next_record(offset: u64, next: u32, remaining: u64, minimum: u64) -> ElfResult<u64> {
    if remaining == 0 {
        if next != 0 { return Err(invalid("version record count", offset)); }
        Ok(offset)
    } else if u64::from(next) >= minimum {
        add(offset, u64::from(next))
    } else {
        Err(invalid("version record chain", offset))
    }
}

fn versions(image: &Image<'_>, tags: &Tags, strings: &[u8], count: usize) -> ElfResult<Vec<Option<String>>> {
    let mut names = BTreeMap::new();
    for (pointer_tag, count_tag, definition) in [(DT_VERDEF, DT_VERDEFNUM, true), (DT_VERNEED, DT_VERNEEDNUM, false)] {
        let Some((address, records)) = tags.region(pointer_tag, count_tag, 1)? else { continue; };
        let (_, bytes) = image.tail(address)?;
        let record_size = if definition { 20 } else { 16 };
        if records > bytes.len() as u64 / record_size { return Err(invalid("version record count", records)); }
        let mut offset = 0;
        let mut auxiliary_budget = bytes.len() as u64 / 8;
        for record in 0..records {
            let current = slice(bytes, offset, record_size)?;
            if u16_at(current, 0)? != 1 { return Err(invalid("symbol version revision", offset)); }
            let auxiliary_count = u64::from(u16_at(current, if definition { 6 } else { 2 })?);
            let auxiliary_size = if definition { 8 } else { 16 };
            if auxiliary_count == 0 || auxiliary_count > bytes.len() as u64 / auxiliary_size {
                return Err(invalid("version auxiliary count", auxiliary_count));
            }
            auxiliary_budget = auxiliary_budget.checked_sub(auxiliary_count)
                .ok_or_else(|| invalid("excessive version auxiliary traversal", auxiliary_count))?;
            if !definition { name(strings, u64::from(u32_at(current, 4)?))?; }
            let auxiliary_relative = u64::from(u32_at(current, if definition { 12 } else { 8 })?);
            if auxiliary_relative < record_size { return Err(invalid("version auxiliary offset", offset)); }
            let mut auxiliary = add(offset, auxiliary_relative)?;
            for item in 0..auxiliary_count {
                let aux = slice(bytes, auxiliary, auxiliary_size)?;
                let value = name(strings, u64::from(u32_at(aux, if definition { 0 } else { 8 })?))?;
                if !definition || item == 0 {
                    let index = if definition { u16_at(current, 4)? } else { u16_at(aux, 6)? };
                    version_name(&mut names, index, value)?;
                }
                auxiliary = next_record(auxiliary, u32_at(aux, if definition { 4 } else { 12 })?,
                    auxiliary_count - item - 1, auxiliary_size)?;
            }
            offset = next_record(offset, u32_at(current, if definition { 16 } else { 12 })?,
                records - record - 1, record_size)?;
        }
    }
    let mut result = vec![None; count];
    if let Some(address) = tags.get(DT_VERSYM) {
        let (_, bytes) = image.table(address, mul(count as u64, 2)?)?;
        for (slot, word) in result.iter_mut().zip(bytes.chunks_exact(2)) {
            let index = u16::from_le_bytes([word[0], word[1]]) & 0x7fff;
            if index > 1 {
                *slot = Some(names.get(&index).ok_or_else(|| invalid("undefined symbol version", u64::from(index)))?.clone());
            }
        }
    } else if !names.is_empty() {
        return Err(invalid("missing DT_VERSYM", 0));
    }
    Ok(result)
}

pub(super) fn parse(
    bytes: &[u8], header: &Elf64Header, headers: &[Elf64ProgramHeader],
    dynamic: &Elf64ProgramHeader, base: u64,
) -> ElfResult<LoadedObject> {
    if headers.iter().filter(|header| header.p_type == ProgramType::Dynamic).count() != 1 {
        return Err(invalid("multiple PT_DYNAMIC segments", dynamic.p_offset));
    }
    let image = Image { bytes, headers };
    let (offset, table) = image.table(dynamic.p_vaddr, dynamic.p_filesz)?;
    if offset != dynamic.p_offset { return Err(invalid("PT_DYNAMIC file translation", offset)); }
    let tags = Tags::parse(table)?;
    // The existing x86-64 engine accepts explicit-addend RELA and packed RELR,
    // not implicit-addend REL. Never accept such an object unrelocated.
    if tags.get(DT_RELSZ).unwrap_or(0) != 0 || (tags.get(DT_REL).is_some() && tags.get(DT_RELSZ).is_none()) {
        return Err(invalid("unsupported DT_REL table", DT_REL as u64));
    }
    let dynstr = match tags.region(DT_STRTAB, DT_STRSZ, 1)? {
        Some((address, size)) => image.table(address, size)?.1.to_vec(),
        None => Vec::new(),
    };
    let sysv = tags.get(DT_HASH).map(|address| sysv_hash(&image, address)).transpose()?;
    let gnu = tags.get(DT_GNU_HASH).map(|address| gnu_hash(&image, address)).transpose()?;
    if let (Some((_, sysv_count)), Some((_, gnu_count))) = (&sysv, &gnu) {
        if gnu_count > sysv_count { return Err(invalid("inconsistent dynamic hash counts", *gnu_count)); }
    }
    let symbol_count = sysv.as_ref().map(|(_, count)| *count)
        .or_else(|| gnu.as_ref().map(|(_, count)| *count));
    let dynsym = match (tags.get(DT_SYMTAB), symbol_count) {
        (Some(address), Some(count)) if tags.required(DT_SYMENT)? == 24 => {
            let (offset, _) = image.table(address, mul(count, 24)?)?;
            parse_symbols(bytes, offset, mul(count, 24)?)?
        }
        (None, None) => Vec::new(),
        _ => return Err(invalid("dynamic symbol table description", DT_SYMTAB as u64)),
    };
    for symbol in &dynsym { get_string(&dynstr, symbol.st_name)?; }
    let symbol_versions = versions(&image, &tags, &dynstr, dynsym.len())?;
    let dynamic_rela = tags.region(DT_RELA, DT_RELASZ, 24)?;
    let plt_rela = tags.region(DT_JMPREL, DT_PLTRELSZ, 24)?;
    if (dynamic_rela.is_some() && tags.get(DT_RELAENT) != Some(24))
        || (plt_rela.is_some() && tags.get(DT_PLTREL) != Some(DT_RELA as u64))
        || tags.get(DT_RELAENT).is_some_and(|size| size != 24)
    { return Err(invalid("dynamic RELA entry size or type", DT_RELA as u64)); }
    let read_rela = |region: Option<(u64, u64)>| -> ElfResult<Vec<super::Elf64Rela>> {
        match region {
            Some((address, size)) => parse_relocations(bytes, image.table(address, size)?.0, size),
            None => Ok(Vec::new()),
        }
    };
    let mut rela_dyn = read_rela(dynamic_rela)?;
    let rela_plt = read_rela(plt_rela)?;
    // DT_JMPREL may be a subset of DT_RELA. Keep each relocation in exactly
    // one table so eager application is not duplicated and lazy PLT stays lazy.
    if let (Some((start, size)), Some((plt, plt_size))) = (dynamic_rela, plt_rela) {
        let end = add(start, size)?;
        let plt_end = add(plt, plt_size)?;
        if start < plt_end && plt < end {
            if plt < start || plt_end > end || !(plt - start).is_multiple_of(24) {
                return Err(invalid("overlapping dynamic relocation tables", plt));
            }
            let first = usize::try_from((plt - start) / 24).map_err(|_| invalid("PLT index", plt))?;
            let last = usize::try_from((plt_end - start) / 24).map_err(|_| invalid("PLT index", plt_end))?;
            rela_dyn.drain(first..last);
        }
    }
    let relr_dyn = match tags.region(DT_RELR, DT_RELRSZ, 8)? {
        Some((address, size)) => {
            if tags.get(DT_RELRENT) != Some(8) { return Err(invalid("DT_RELRENT", address)); }
            expand_relr_entries(&parse_relr_entries(bytes, image.table(address, size)?.0, size)?)?
        }
        None => Vec::new(),
    };
    let needed_libraries = tags.needed.iter().map(|&offset| name(&dynstr, offset)).collect::<ElfResult<Vec<_>>>()?;
    let soname = tags.get(DT_SONAME).map(|offset| name(&dynstr, offset)).transpose()?;
    let runtime = |tag| tags.get(tag).filter(|&value| value != 0).map(|value| add(base, value)).transpose();
    let relro = headers.iter().find(|header| header.is_relro());
    let relro_start = relro.map(|header| add(base, header.p_vaddr)).transpose()?;
    if let Some(header) = relro { add(add(base, header.p_vaddr)?, header.p_memsz)?; }
    Ok(LoadedObject {
        base,
        entry: (header.e_entry != 0).then(|| add(base, header.e_entry)).transpose()?,
        program_headers: headers.to_vec(),
        section_headers: Vec::new(),
        dynsym, dynstr,
        gnu_hash: gnu.map(|(table, _)| table),
        elf_hash: sysv.map(|(table, _)| table),
        soname, needed_libraries, symbol_versions, rela_dyn, rela_plt, relr_dyn,
        legacy_init: runtime(DT_INIT)?,
        legacy_fini: runtime(DT_FINI)?,
        init_array: word_array(&image, &tags, DT_INIT_ARRAY, DT_INIT_ARRAYSZ)?,
        fini_array: word_array(&image, &tags, DT_FINI_ARRAY, DT_FINI_ARRAYSZ)?,
        relro_start,
        relro_size: relro.map_or(0, |header| header.p_memsz),
        tls_segment: headers.iter().find(|header| header.is_tls()).map(|header| TlsSegment {
            vaddr: header.p_vaddr, filesz: header.p_filesz, memsz: header.p_memsz,
            align: header.p_align, file_offset: header.p_offset,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn fixture() -> (Vec<u8>, Vec<Elf64ProgramHeader>) {
        let mut bytes = vec![0u8; 1024];
        put32(&mut bytes, 64, 1); // PT_LOAD
        put32(&mut bytes, 68, 6); // PF_R | PF_W
        put64(&mut bytes, 80, 0x4000);
        put64(&mut bytes, 96, 1024);
        put64(&mut bytes, 104, 2048); // BSS is not a source of runtime tables.
        put64(&mut bytes, 112, 4096);
        let headers = super::super::parse_program_headers(&bytes, 64, 56, 1).unwrap();
        (bytes, headers)
    }

    fn entries(values: &[(i64, u64)]) -> Vec<u8> {
        values.iter().flat_map(|&(tag, value)| {
            tag.to_le_bytes().into_iter().chain(value.to_le_bytes())
        }).collect()
    }

    #[test]
    fn dynamic_addresses_are_translated_and_bss_is_not_file_backed() {
        let (bytes, headers) = fixture();
        let image = Image { bytes: &bytes, headers: &headers };
        assert_eq!(image.table(0x4180, 16).unwrap().0, 0x180);
        assert!(image.table(0x4400, 8).is_err());
        assert!(image.table(0x43fc, 8).is_err());
        assert!(image.table(u64::MAX, 8).is_err());
        assert!(image.table(0x4180, u64::MAX).is_err());
    }

    #[test]
    fn dynamic_tags_require_complete_entries_and_a_terminator() {
        assert!(Tags::parse(&[0; 15]).is_err());
        assert!(Tags::parse(&entries(&[(DT_STRTAB, 0x4200)])).is_err());
        let tags = Tags::parse(&entries(&[(DT_NEEDED, 3), (DT_NEEDED, 1), (0, 0), (DT_NEEDED, 99)])).unwrap();
        assert_eq!(tags.needed, [3, 1]);
    }

    #[test]
    fn conflicting_singletons_and_incomplete_tables_are_rejected() {
        assert!(Tags::parse(&entries(&[(DT_SYMENT, 24), (DT_SYMENT, 8), (0, 0)])).is_err());
        let tags = Tags::parse(&entries(&[(DT_RELA, 0x4200), (0, 0)])).unwrap();
        assert!(tags.region(DT_RELA, DT_RELASZ, 24).is_err());
        let tags = Tags::parse(&entries(&[(DT_RELA, 0x4200), (DT_RELASZ, 25), (0, 0)])).unwrap();
        assert!(tags.region(DT_RELA, DT_RELASZ, 24).is_err());
    }

    #[test]
    fn sysv_count_is_checked_against_the_mapped_file_before_allocation() {
        let (mut bytes, headers) = fixture();
        put32(&mut bytes, 256, 1);
        put32(&mut bytes, 260, 2);
        put32(&mut bytes, 264, 1);
        let image = Image { bytes: &bytes, headers: &headers };
        assert_eq!(sysv_hash(&image, 0x4100).unwrap().1, 2);
        put32(&mut bytes, 260, u32::MAX);
        assert!(sysv_hash(&Image { bytes: &bytes, headers: &headers }, 0x4100).is_err());
    }

    fn gnu_fixture(bytes: &mut [u8], highest: u32) {
        put32(bytes, 256, 1); // bucket count
        put32(bytes, 260, 1); // first hashed symbol
        put32(bytes, 264, 1); // bloom word count
        put32(bytes, 268, 5); // shift
        put64(bytes, 272, u64::MAX);
        put32(bytes, 280, highest);
        put32(bytes, 284, 0x1234);
        put32(bytes, 288, 0x1235); // symbol two terminates the last chain
    }

    #[test]
    fn gnu_hash_bounds_symbols_without_a_section_size() {
        let (mut bytes, headers) = fixture();
        gnu_fixture(&mut bytes, 1);
        assert_eq!(gnu_hash(&Image { bytes: &bytes, headers: &headers }, 0x4100).unwrap().1, 3);
        put32(&mut bytes, 280, 0);
        assert_eq!(gnu_hash(&Image { bytes: &bytes, headers: &headers }, 0x4100).unwrap().1, 1);
    }

    #[test]
    fn gnu_hash_rejects_out_of_range_buckets_and_unterminated_chains() {
        let (mut bytes, headers) = fixture();
        gnu_fixture(&mut bytes, u32::MAX);
        assert!(gnu_hash(&Image { bytes: &bytes, headers: &headers }, 0x4100).is_err());
        put32(&mut bytes, 280, 1);
        put32(&mut bytes, 288, 0);
        assert!(gnu_hash(&Image { bytes: &bytes, headers: &headers }, 0x4100).is_err());
        put32(&mut bytes, 288, 1);
        put32(&mut bytes, 268, 32);
        assert!(gnu_hash(&Image { bytes: &bytes, headers: &headers }, 0x4100).is_err());
        put32(&mut bytes, 268, 5);
        put32(&mut bytes, 264, 0);
        assert!(gnu_hash(&Image { bytes: &bytes, headers: &headers }, 0x4100).is_err());
    }

    #[test]
    fn version_indexes_require_complete_linked_records_and_known_names() {
        let (mut bytes, headers) = fixture();
        bytes[256..258].copy_from_slice(&1u16.to_le_bytes()); // revision
        bytes[260..262].copy_from_slice(&2u16.to_le_bytes()); // version index
        bytes[262..264].copy_from_slice(&1u16.to_le_bytes()); // aux count
        put32(&mut bytes, 268, 20); // first auxiliary record
        put32(&mut bytes, 276, 1); // name offset
        bytes[514..516].copy_from_slice(&2u16.to_le_bytes()); // dynsym[1]
        let tags = Tags::parse(&entries(&[(DT_VERDEF, 0x4100), (DT_VERDEFNUM, 1), (DT_VERSYM, 0x4200), (0, 0)])).unwrap();
        let parsed = versions(&Image { bytes: &bytes, headers: &headers }, &tags, b"\0FIXTURE_1.0\0", 2).unwrap();
        assert_eq!(parsed, [None, Some("FIXTURE_1.0".to_owned())]);
        bytes[514..516].copy_from_slice(&3u16.to_le_bytes());
        assert!(versions(&Image { bytes: &bytes, headers: &headers }, &tags, b"\0FIXTURE_1.0\0", 2).is_err());
        bytes[514..516].copy_from_slice(&2u16.to_le_bytes());
        put32(&mut bytes, 268, 0);
        assert!(versions(&Image { bytes: &bytes, headers: &headers }, &tags, b"\0FIXTURE_1.0\0", 2).is_err());
    }
}
