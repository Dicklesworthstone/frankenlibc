//! Bounded, byte-preserving decoder for the system ldconfig cache.
//!
//! The old, new (1.1), and combined compatibility layouts are supported.
//! Layout constants follow the on-disk declarations in glibc's
//! sysdeps/generic/dl-cache.h and ldconfig.h, not its lookup implementation.
//! The native ELF ABI, validated glibc-hwcaps extension names, and the entry's
//! ISA requirement all participate in selection. Supported variants precede
//! baseline entries independently of file order. Legacy capability directories
//! remain excluded: their entry format discards the required ISA metadata.

use std::ffi::OsStr;
use std::ops::Range;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

#[path = "dlfcn_hwcaps.rs"]
pub(super) mod hwcaps;
use hwcaps::Capabilities;

pub(super) const MAX_CACHE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CACHE_ENTRIES: usize = 131_072;
const MAX_STRING_BYTES: usize = 4096;
const MAX_MATCHES: usize = 256;
const OLD_MAGIC: &[u8] = b"ld.so-1.7.0";
const NEW_MAGIC: &[u8] = b"glibc-ld.so.cache1.1";
const OLD_HEADER: usize = 16;
const NEW_HEADER: usize = 48;
const OLD_ENTRY: usize = 12;
const NEW_ENTRY: usize = 24;
const EXTENSION_MAGIC: u32 = 0xeaa4_2174;
const HWCAP_EXTENSION: u64 = 1 << 62;
const ISA_INDEX_MASK: u64 = 0x3ff;
const BASELINE_RANK: usize = 3;

#[derive(Debug)]
struct Layout {
    entries: Range<usize>,
    entry_size: usize,
    strings: Range<usize>,
    string_base: usize,
    hwcaps: Option<Range<usize>>,
}

/// An immutable snapshot for one native load operation. No borrowed mmap or
/// global mutable cache survives replacement of /etc/ld.so.cache by ldconfig.
#[derive(Debug)]
pub(super) struct Cache {
    bytes: Vec<u8>,
    layout: Layout,
}

fn word(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn entry_end(start: usize, count: usize, size: usize) -> Option<usize> {
    if count > MAX_CACHE_ENTRIES {
        return None;
    }
    start.checked_add(count.checked_mul(size)?)
}

fn new_layout(bytes: &[u8], base: usize) -> Option<Layout> {
    let header_end = base.checked_add(NEW_HEADER)?;
    let header = bytes.get(base..header_end)?;
    if !header.starts_with(NEW_MAGIC) {
        return None;
    }
    let endian = header[28] & 3;
    let native_endian = if cfg!(target_endian = "little") { 2 } else { 3 };
    // Zero denotes a writer predating the endianness field. The other header
    // flag bits are reserved and must not affect compatibility.
    if endian != 0 && endian != native_endian {
        return None;
    }
    let count = usize::try_from(word(header, 20)?).ok()?;
    let end = entry_end(header_end, count, NEW_ENTRY)?;
    let strings_end = end.checked_add(usize::try_from(word(header, 24)?).ok()?)?;
    bytes.get(end..strings_end)?;
    Some(Layout {
        entries: header_end..end,
        entry_size: NEW_ENTRY,
        strings: end..strings_end,
        // New-format offsets are relative to the new header, including when
        // that header is embedded after the old-format entry table.
        string_base: base,
        // Extension offsets are absolute FILE offsets, unlike entry strings.
        // A malformed optional extension disables only capability entries.
        hwcaps: hwcaps_extension(bytes, word(header, 32)?, strings_end),
    })
}

/// Decode only the on-disk extension directory, without trusting its counts,
/// ranges, flags or string indices. No allocation is driven by extension data.
fn hwcaps_extension(bytes: &[u8], offset: u32, strings_end: usize) -> Option<Range<usize>> {
    let offset = usize::try_from(offset).ok()?;
    if offset == 0 || offset % 4 != 0 || offset < strings_end {
        return None;
    }
    if word(bytes, offset)? != EXTENSION_MAGIC {
        return None;
    }
    let count = usize::try_from(word(bytes, offset.checked_add(4)?)?).ok()?;
    let start = offset.checked_add(8)?;
    let end = start.checked_add(count.checked_mul(16)?)?;
    let sections = bytes.get(start..end)?;
    let mut hwcaps = None;
    for section in sections.chunks_exact(16) {
        let begin = usize::try_from(word(section, 8)?).ok()?;
        let length = usize::try_from(word(section, 12)?).ok()?;
        let limit = begin.checked_add(length)?;
        bytes.get(begin..limit)?;
        if word(section, 0)? == 1 {
            // Reject ambiguous duplicate tables and unknown semantics rather
            // than interpreting arbitrary metadata as a capability grant.
            if hwcaps.is_some()
                || word(section, 4)? != 0
                || begin % 4 != 0
                || length == 0
                || length % 4 != 0
                || begin < strings_end
                || (begin < end && offset < limit)
            {
                return None;
            }
            hwcaps = Some(begin..limit);
        }
    }
    hwcaps
}

fn layout(bytes: &[u8]) -> Option<Layout> {
    if bytes.len() > MAX_CACHE_BYTES {
        return None;
    }
    if bytes.starts_with(b"glibc-ld.so.cache") {
        return new_layout(bytes, 0);
    }
    if !bytes.starts_with(OLD_MAGIC) {
        return None;
    }
    let count = usize::try_from(word(bytes, 12)?).ok()?;
    let end = entry_end(OLD_HEADER, count, OLD_ENTRY)?;
    bytes.get(OLD_HEADER..end)?;
    let aligned = end.checked_add(7)? & !7;
    if bytes
        .get(aligned..)
        .is_some_and(|tail| tail.starts_with(b"glibc-ld.so.cache"))
    {
        // Never fall back to the less expressive old table when an embedded
        // new table is present but malformed or foreign-endian.
        return new_layout(bytes, aligned);
    }
    Some(Layout {
        entries: OLD_HEADER..end,
        entry_size: OLD_ENTRY,
        strings: end..bytes.len(),
        string_base: end,
        hwcaps: None,
    })
}

pub(super) const fn native_flags() -> u32 {
    if cfg!(target_arch = "x86_64") {
        0x0303 // FLAG_X8664_LIB64 | FLAG_ELF_LIBC6; not i386 or x32.
    } else if cfg!(target_arch = "aarch64") {
        0x0a03 // FLAG_AARCH64_LIB64 | FLAG_ELF_LIBC6.
    } else {
        u32::MAX // The native loader does not support other ELF ABIs yet.
    }
}

impl Cache {
    pub(super) fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        let layout = layout(&bytes)?;
        Some(Self { bytes, layout })
    }

    fn string(&self, offset: u32) -> Option<&[u8]> {
        let start = self
            .layout
            .string_base
            .checked_add(usize::try_from(offset).ok()?)?;
        if !self.layout.strings.contains(&start) {
            return None;
        }
        let tail = self.bytes.get(start..self.layout.strings.end)?;
        let end = tail
            .iter()
            .take(MAX_STRING_BYTES)
            .position(|byte| *byte == 0)?;
        Some(&tail[..end])
    }

    fn capability_rank(&self, entry: &[u8], capabilities: Capabilities) -> Option<usize> {
        if self.layout.entry_size != NEW_ENTRY {
            return Some(BASELINE_RANK);
        }
        let bits = u64::from_ne_bytes(entry.get(16..24)?.try_into().ok()?);
        if bits == 0 {
            return Some(BASELINE_RANK);
        }
        if (bits >> 32) & !ISA_INDEX_MASK != HWCAP_EXTENSION >> 32 {
            return None;
        }
        let range = self.layout.hwcaps.as_ref()?;
        let index = usize::try_from(bits as u32).ok()?;
        let offset = index.checked_mul(4)?;
        // Slice the section FIRST: an out-of-range index cannot borrow a word
        // from another extension or from the rest of the cache file.
        let name = self.string(word(self.bytes.get(range.clone())?, offset)?)?;
        capabilities.rank(name, ((bits >> 32) & ISA_INDEX_MASK) as u32)
    }

    pub(super) fn candidates(&self, name: &[u8]) -> Vec<PathBuf> {
        self.candidates_with_capabilities(name, Capabilities::detect())
    }

    pub(super) fn candidates_with_capabilities(
        &self,
        name: &[u8],
        capabilities: Capabilities,
    ) -> Vec<PathBuf> {
        let mut result: Vec<(usize, PathBuf)> = Vec::new();
        if name.is_empty()
            || name.len() >= MAX_STRING_BYTES
            || name.contains(&0)
            || name.contains(&b'/')
        {
            return Vec::new();
        }
        for entry in self.bytes[self.layout.entries.clone()].chunks_exact(self.layout.entry_size) {
            if word(entry, 0) != Some(native_flags()) {
                continue;
            }
            let Some(key) = word(entry, 4).and_then(|offset| self.string(offset)) else {
                continue;
            };
            if key != name {
                continue;
            }
            let Some(value) = word(entry, 8).and_then(|offset| self.string(offset)) else {
                continue;
            };
            // Do not turn a malformed cache into a current-directory search.
            if !value.starts_with(b"/") {
                continue;
            }
            let Some(rank) = self.capability_rank(entry, capabilities) else {
                continue;
            };
            let path = PathBuf::from(OsStr::from_bytes(value));
            // A directory name alone does not establish ISA eligibility.
            // In particular, old caches discard the hwcap field entirely.
            if rank == BASELINE_RANK
                && path
                    .components()
                    .any(|part| part.as_os_str() == OsStr::new("glibc-hwcaps"))
            {
                continue;
            }
            if let Some(index) = result.iter().position(|(_, previous)| previous == &path) {
                if result[index].0 <= rank {
                    continue;
                }
                result.remove(index);
            }
            // Stable priority insertion preserves cache order for equal ranks.
            // Keep scanning after reaching the bound: a better variant can
            // occur after hundreds of baseline entries in an unsorted cache.
            let index = result.partition_point(|(previous, _)| *previous <= rank);
            if index < MAX_MATCHES {
                result.insert(index, (rank, path));
                if result.len() > MAX_MATCHES {
                    result.pop();
                }
            }
        }
        result.into_iter().map(|(_, path)| path).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn put(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }

    fn fixture(entries: &[(&[u8], &[u8], u32, u64)], modern: bool) -> Vec<u8> {
        let header = if modern { NEW_HEADER } else { OLD_HEADER };
        let size = if modern { NEW_ENTRY } else { OLD_ENTRY };
        let start = header + size * entries.len();
        let mut bytes = vec![0; start];
        let magic = if modern { NEW_MAGIC } else { OLD_MAGIC };
        bytes[..magic.len()].copy_from_slice(magic);
        put(
            &mut bytes,
            if modern { 20 } else { 12 },
            entries.len() as u32,
        );
        for (i, &(key, value, flags, hwcap)) in entries.iter().enumerate() {
            let offset = header + size * i;
            let key_offset = if modern {
                bytes.len()
            } else {
                bytes.len() - start
            };
            bytes.extend_from_slice(key);
            bytes.push(0);
            let value_offset = if modern {
                bytes.len()
            } else {
                bytes.len() - start
            };
            bytes.extend_from_slice(value);
            bytes.push(0);
            put(&mut bytes, offset, flags);
            put(&mut bytes, offset + 4, key_offset as u32);
            put(&mut bytes, offset + 8, value_offset as u32);
            if modern {
                bytes[offset + 16..offset + 24].copy_from_slice(&hwcap.to_ne_bytes());
            }
        }
        if modern {
            let length = (bytes.len() - start) as u32;
            put(&mut bytes, 24, length);
            bytes[28] = if cfg!(target_endian = "little") { 2 } else { 3 };
        }
        bytes
    }

    fn sample(modern: bool) -> Vec<u8> {
        fixture(
            &[(b"libx.so", b"/opt/vendor/libx.so", native_flags(), 0)],
            modern,
        )
    }

    #[test]
    fn modern_and_legacy_offsets_are_distinct_and_supported() {
        for modern in [true, false] {
            let cache = Cache::from_bytes(sample(modern)).unwrap();
            assert_eq!(
                cache.candidates(b"libx.so"),
                vec![PathBuf::from("/opt/vendor/libx.so")]
            );
            assert!(cache.candidates(b"missing.so").is_empty());
        }
    }

    #[test]
    fn compatibility_cache_uses_aligned_embedded_header() {
        for count in [0, 1, 2, 3] {
            let end = OLD_HEADER + count * OLD_ENTRY;
            let aligned = (end + 7) & !7;
            let mut bytes = vec![0; aligned];
            bytes[..OLD_MAGIC.len()].copy_from_slice(OLD_MAGIC);
            put(&mut bytes, 12, count as u32);
            bytes.extend_from_slice(&sample(true));
            let cache = Cache::from_bytes(bytes).unwrap();
            assert_eq!(
                cache.candidates(b"libx.so"),
                vec![PathBuf::from("/opt/vendor/libx.so")]
            );
        }
    }

    #[test]
    fn foreign_abi_hwcap_and_duplicate_entries_are_not_selected() {
        let bytes = fixture(
            &[
                (b"libx.so", b"/wrong/libx.so", 0x0803, 0),
                (b"libx.so", b"/fast/libx.so", native_flags(), 1 << 62),
                (b"libx.so", b"/legacy-hwcap/libx.so", native_flags(), 1),
                (b"libx.so", b"/baseline/libx.so", native_flags(), 0),
                (b"libx.so", b"/baseline/libx.so", native_flags(), 0),
            ],
            true,
        );
        assert_eq!(
            Cache::from_bytes(bytes).unwrap().candidates(b"libx.so"),
            vec![PathBuf::from("/baseline/libx.so")]
        );
    }

    #[test]
    fn legacy_capability_directories_are_not_mistaken_for_baseline_dsos() {
        for modern in [true, false] {
            let bytes = fixture(
                &[
                    (
                        b"libx.so",
                        b"/opt/glibc-hwcaps/x86-64-v3/libx.so",
                        native_flags(),
                        0,
                    ),
                    (b"libx.so", b"/opt/libx.so", native_flags(), 0),
                ],
                modern,
            );
            assert_eq!(
                Cache::from_bytes(bytes).unwrap().candidates(b"libx.so"),
                vec![PathBuf::from("/opt/libx.so")]
            );
        }
    }

    #[test]
    fn non_utf8_paths_and_suffix_shared_strings_survive() {
        let path = b"/opt/\xff/libx.so";
        let mut bytes = fixture(&[(b"unused", path, native_flags(), 0)], true);
        let value = word(&bytes, NEW_HEADER + 8).unwrap();
        put(
            &mut bytes,
            NEW_HEADER + 4,
            value + (path.len() - b"libx.so".len()) as u32,
        );
        let cache = Cache::from_bytes(bytes).unwrap();
        assert_eq!(cache.candidates(b"libx.so")[0].as_os_str().as_bytes(), path);
    }

    #[test]
    fn invalid_foreign_and_unknown_endian_headers() {
        let sample = sample(true);
        for flag in [0, 4, sample[28], sample[28] | 0x80] {
            let mut bytes = sample.clone();
            bytes[28] = flag;
            assert!(Cache::from_bytes(bytes).is_some());
        }
        for flag in [1, if cfg!(target_endian = "little") { 3 } else { 2 }] {
            let mut bytes = sample.clone();
            bytes[28] = flag;
            assert!(Cache::from_bytes(bytes).is_none());
        }
    }

    #[test]
    fn every_modern_truncation_and_oversized_count_is_rejected() {
        let bytes = sample(true);
        for end in 0..bytes.len() {
            assert!(
                Cache::from_bytes(bytes[..end].to_vec()).is_none(),
                "length {end}"
            );
        }
        for modern in [true, false] {
            let mut bytes = sample(modern);
            put(&mut bytes, if modern { 20 } else { 12 }, u32::MAX);
            assert!(Cache::from_bytes(bytes).is_none());
        }
    }

    #[test]
    fn invalid_offsets_cannot_escape_the_string_table() {
        for field in [NEW_HEADER + 4, NEW_HEADER + 8] {
            for value in [0, NEW_HEADER as u32, u32::MAX] {
                let mut bytes = sample(true);
                put(&mut bytes, field, value);
                assert!(
                    Cache::from_bytes(bytes)
                        .unwrap()
                        .candidates(b"libx.so")
                        .is_empty()
                );
            }
        }
    }

    #[test]
    fn string_terminators_in_extension_bytes_are_not_accepted() {
        let mut bytes = sample(true);
        *bytes.last_mut().unwrap() = b'x';
        bytes.extend_from_slice(&[0; 64]);
        assert!(
            Cache::from_bytes(bytes)
                .unwrap()
                .candidates(b"libx.so")
                .is_empty()
        );
    }

    #[test]
    fn relative_paths_empty_and_path_bearing_queries_are_rejected() {
        let bytes = fixture(
            &[(b"libx.so", b"relative/libx.so", native_flags(), 0)],
            true,
        );
        assert!(
            Cache::from_bytes(bytes)
                .unwrap()
                .candidates(b"libx.so")
                .is_empty()
        );
        let cache = Cache::from_bytes(sample(true)).unwrap();
        for name in [b"".as_slice(), b"./libx.so", b"libx.so\0suffix"] {
            assert!(cache.candidates(name).is_empty());
        }
    }

    #[test]
    fn malformed_compatibility_header_is_not_downgraded_to_legacy() {
        let mut bytes = vec![0; OLD_HEADER];
        bytes[..OLD_MAGIC.len()].copy_from_slice(OLD_MAGIC);
        let mut modern = sample(true);
        modern[18] = b'9';
        bytes.extend_from_slice(&modern);
        assert!(Cache::from_bytes(bytes).is_none());
    }

    #[test]
    fn cache_size_string_length_and_result_count_are_bounded() {
        assert!(Cache::from_bytes(vec![0; MAX_CACHE_BYTES + 1]).is_none());
        let long_path = vec![b'/'; MAX_STRING_BYTES];
        let bytes = fixture(&[(b"libx.so", &long_path, native_flags(), 0)], true);
        assert!(
            Cache::from_bytes(bytes)
                .unwrap()
                .candidates(b"libx.so")
                .is_empty()
        );
        let paths: Vec<_> = (0..MAX_MATCHES + 1)
            .map(|i| format!("/opt/{i}/libx.so"))
            .collect();
        let entries: Vec<_> = paths
            .iter()
            .map(|path| (b"libx.so".as_slice(), path.as_bytes(), native_flags(), 0))
            .collect();
        let cache = Cache::from_bytes(fixture(&entries, true)).unwrap();
        assert_eq!(cache.candidates(b"libx.so").len(), MAX_MATCHES);
    }

    #[test]
    fn malformed_bytes_never_panic() {
        let seed = sample(true);
        for offset in 0..seed.len() {
            for value in [0, 1, 0x7f, 0x80, 0xff] {
                let mut bytes = seed.clone();
                bytes[offset] = value;
                if let Some(cache) = Cache::from_bytes(bytes) {
                    let _ = cache.candidates(b"libx.so");
                }
            }
        }
    }

    fn with_hwcaps(mut bytes: Vec<u8>, names: &[&[u8]]) -> Vec<u8> {
        let mut offsets = Vec::new();
        for name in names {
            offsets.push(bytes.len() as u32);
            bytes.extend_from_slice(name);
            bytes.push(0);
        }
        let strings_start = NEW_HEADER + word(&bytes, 20).unwrap() as usize * NEW_ENTRY;
        let strings_len = (bytes.len() - strings_start) as u32;
        put(&mut bytes, 24, strings_len);
        let extension = (bytes.len() + 3) & !3;
        let data = extension + 8 + 16;
        bytes.resize(data + 4 * names.len(), 0);
        put(&mut bytes, 32, extension as u32);
        put(&mut bytes, extension, EXTENSION_MAGIC);
        put(&mut bytes, extension + 4, 1);
        put(&mut bytes, extension + 8, 1);
        put(&mut bytes, extension + 16, data as u32);
        put(&mut bytes, extension + 20, (4 * names.len()) as u32);
        for (i, offset) in offsets.into_iter().enumerate() {
            put(&mut bytes, data + i * 4, offset);
        }
        bytes
    }

    fn variants() -> Vec<u8> {
        with_hwcaps(
            fixture(
                &[
                    (b"libx.so", b"/baseline/libx.so", native_flags(), 0),
                    (b"libx.so", b"/v2/libx.so", native_flags(), HWCAP_EXTENSION),
                    (
                        b"libx.so",
                        b"/v3/libx.so",
                        native_flags(),
                        HWCAP_EXTENSION | 1 | (2 << 32),
                    ),
                    (
                        b"libx.so",
                        b"/v4/libx.so",
                        native_flags(),
                        HWCAP_EXTENSION | 2 | (3 << 32),
                    ),
                ],
                true,
            ),
            &[b"x86-64-v2", b"x86-64-v3", b"x86-64-v4"],
        )
    }

    #[test]
    fn supported_variants_precede_baseline_independently_of_cache_order() {
        let cache = Cache::from_bytes(variants()).unwrap();
        for level in 1..=4 {
            let mut expected: Vec<_> = (2..=level)
                .rev()
                .map(|n| PathBuf::from(format!("/v{n}/libx.so")))
                .collect();
            expected.push(PathBuf::from("/baseline/libx.so"));
            assert_eq!(
                cache.candidates_with_capabilities(b"libx.so", Capabilities::for_x86_level(level)),
                expected
            );
        }
        assert_eq!(
            cache.candidates_with_capabilities(b"libx.so", Capabilities::default()),
            vec![PathBuf::from("/baseline/libx.so")]
        );
    }

    #[test]
    fn hwcaps_only_library_is_resolvable_without_baseline() {
        let bytes = with_hwcaps(
            fixture(
                &[(
                    b"libx.so",
                    b"/opt/glibc-hwcaps/x86-64-v2/libx.so",
                    native_flags(),
                    HWCAP_EXTENSION,
                )],
                true,
            ),
            &[b"x86-64-v2"],
        );
        let cache = Cache::from_bytes(bytes).unwrap();
        assert!(
            cache
                .candidates_with_capabilities(b"libx.so", Capabilities::for_x86_level(1))
                .is_empty()
        );
        assert_eq!(
            cache.candidates_with_capabilities(b"libx.so", Capabilities::for_x86_level(2)),
            vec![PathBuf::from("/opt/glibc-hwcaps/x86-64-v2/libx.so")]
        );
    }

    #[test]
    fn unknown_names_flags_indices_and_stronger_isa_are_not_capabilities() {
        for (name, flags) in [
            (b"x86-64-v9".as_slice(), HWCAP_EXTENSION),
            (b"../x86-64-v2", HWCAP_EXTENSION),
            (b"x86-64-v2", HWCAP_EXTENSION | 1),
            (b"x86-64-v2", HWCAP_EXTENSION | u64::from(u32::MAX)),
            (b"x86-64-v2", HWCAP_EXTENSION | (3 << 32)),
            (b"x86-64-v2", HWCAP_EXTENSION | (1023 << 32)),
            (b"x86-64-v2", HWCAP_EXTENSION | (1 << 63)),
            (b"x86-64-v2", 1),
        ] {
            let bytes = with_hwcaps(
                fixture(
                    &[
                        (b"libx.so", b"/candidate/libx.so", native_flags(), flags),
                        (b"libx.so", b"/baseline/libx.so", native_flags(), 0),
                    ],
                    true,
                ),
                &[name],
            );
            let cache = Cache::from_bytes(bytes).unwrap();
            assert_eq!(
                cache.candidates_with_capabilities(b"libx.so", Capabilities::for_x86_level(3)),
                vec![PathBuf::from("/baseline/libx.so")],
                "name {name:?}, flags {flags:#x}"
            );
        }
    }

    #[test]
    fn compatibility_extensions_use_absolute_file_offsets() {
        for count in [0, 1, 2, 3] {
            let base = (OLD_HEADER + count * OLD_ENTRY + 7) & !7;
            let mut modern = variants();
            let extension = word(&modern, 32).unwrap() as usize;
            let data = word(&modern, extension + 16).unwrap() as usize;
            put(&mut modern, 32, (extension + base) as u32);
            put(&mut modern, extension + 16, (data + base) as u32);
            let mut bytes = vec![0; base];
            bytes[..OLD_MAGIC.len()].copy_from_slice(OLD_MAGIC);
            put(&mut bytes, 12, count as u32);
            bytes.extend_from_slice(&modern);
            let cache = Cache::from_bytes(bytes).unwrap();
            assert_eq!(
                cache.candidates_with_capabilities(b"libx.so", Capabilities::for_x86_level(3)),
                vec![
                    PathBuf::from("/v3/libx.so"),
                    PathBuf::from("/v2/libx.so"),
                    PathBuf::from("/baseline/libx.so"),
                ]
            );
        }
    }

    #[test]
    fn malformed_optional_extensions_do_not_remove_the_baseline() {
        let seed = variants();
        let extension = word(&seed, 32).unwrap() as usize;
        for (offset, value) in [
            (32, 0),
            (32, 1),
            (32, NEW_HEADER as u32),
            (32, u32::MAX),
            (extension, 0),
            (extension + 4, u32::MAX),
            (extension + 12, 1), // unknown section flags
            (extension + 16, 0),
            (extension + 16, extension as u32),
            (extension + 16, u32::MAX),
            (extension + 20, 0),
            (extension + 20, 3),
            (extension + 20, u32::MAX),
        ] {
            let mut bytes = seed.clone();
            put(&mut bytes, offset, value);
            let cache = Cache::from_bytes(bytes).unwrap();
            assert_eq!(
                cache.candidates_with_capabilities(b"libx.so", Capabilities::for_x86_level(4)),
                vec![PathBuf::from("/baseline/libx.so")],
                "offset {offset}, value {value}"
            );
        }
        let strings_end = NEW_HEADER + 4 * NEW_ENTRY + word(&seed, 24).unwrap() as usize;
        for end in strings_end..seed.len() {
            let cache = Cache::from_bytes(seed[..end].to_vec()).unwrap();
            assert_eq!(
                cache.candidates_with_capabilities(b"libx.so", Capabilities::for_x86_level(4)),
                vec![PathBuf::from("/baseline/libx.so")],
                "length {end}"
            );
        }
    }

    #[test]
    fn extension_name_indices_cannot_escape_the_string_table() {
        let seed = with_hwcaps(
            fixture(
                &[
                    (
                        b"libx.so",
                        b"/candidate/libx.so",
                        native_flags(),
                        HWCAP_EXTENSION,
                    ),
                    (b"libx.so", b"/baseline/libx.so", native_flags(), 0),
                ],
                true,
            ),
            &[b"x86-64-v2"],
        );
        let extension = word(&seed, 32).unwrap() as usize;
        let data = word(&seed, extension + 16).unwrap() as usize;
        for value in [0, NEW_HEADER as u32, extension as u32, u32::MAX] {
            let mut bytes = seed.clone();
            put(&mut bytes, data, value);
            let cache = Cache::from_bytes(bytes).unwrap();
            assert_eq!(
                cache.candidates_with_capabilities(b"libx.so", Capabilities::for_x86_level(4)),
                vec![PathBuf::from("/baseline/libx.so")]
            );
        }
    }

    #[test]
    fn capability_ranking_is_stable_deduplicated_and_bounded() {
        let paths: Vec<_> = (0..MAX_MATCHES + 1)
            .map(|i| format!("/baseline/{i}/libx.so"))
            .collect();
        let mut entries: Vec<_> = paths
            .iter()
            .map(|path| (b"libx.so".as_slice(), path.as_bytes(), native_flags(), 0))
            .collect();
        entries.push((
            b"libx.so",
            b"/first/libx.so",
            native_flags(),
            HWCAP_EXTENSION,
        ));
        entries.push((
            b"libx.so",
            b"/first/libx.so",
            native_flags(),
            HWCAP_EXTENSION,
        ));
        entries.push((
            b"libx.so",
            b"/second/libx.so",
            native_flags(),
            HWCAP_EXTENSION,
        ));
        let bytes = with_hwcaps(fixture(&entries, true), &[b"x86-64-v3"]);
        let paths = Cache::from_bytes(bytes)
            .unwrap()
            .candidates_with_capabilities(b"libx.so", Capabilities::for_x86_level(3));
        assert_eq!(paths.len(), MAX_MATCHES);
        assert_eq!(paths[0], Path::new("/first/libx.so"));
        assert_eq!(paths[1], Path::new("/second/libx.so"));
        assert_eq!(paths[2], Path::new("/baseline/0/libx.so"));
    }

    #[test]
    fn all_extension_byte_mutations_are_bounded_and_preserve_baseline() {
        let seed = variants();
        let extension = word(&seed, 32).unwrap() as usize;
        for offset in extension..seed.len() {
            for value in [0, 1, 0x7f, 0x80, 0xff] {
                let mut bytes = seed.clone();
                bytes[offset] = value;
                let cache = Cache::from_bytes(bytes).unwrap();
                let paths =
                    cache.candidates_with_capabilities(b"libx.so", Capabilities::for_x86_level(4));
                assert!(paths.contains(&PathBuf::from("/baseline/libx.so")));
                assert!(paths.len() <= 4);
            }
        }
    }
}
