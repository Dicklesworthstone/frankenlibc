//! ELF hash table algorithms.
//!
//! Two hash algorithms are used in ELF dynamic linking:
//! - ELF hash (System V): Original, simpler, slower
//! - GNU hash: Bloom filter + faster hash, now standard
//!
//! Both are implemented here for symbol lookup acceleration.

use super::symbol::{Elf64Symbol, get_string};

/// Compute the ELF (System V) hash for a symbol name.
///
/// This is the original ELF hash algorithm from the System V ABI.
/// It produces a 32-bit hash value.
///
/// # Algorithm
///
/// ```text
/// h = 0
/// for each byte c in name:
///     h = (h << 4) + c
///     g = h & 0xf0000000
///     if g != 0:
///         h ^= g >> 24
///     h &= ~g
/// return h
/// ```
pub fn elf_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &c in name {
        h = h.wrapping_shl(4).wrapping_add(c as u32);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// Compute the GNU hash for a symbol name.
///
/// This is the newer hash algorithm used by GNU ld for faster symbol lookup.
/// It uses a djb2-style hash function.
///
/// # Algorithm
///
/// ```text
/// h = 5381
/// for each byte c in name:
///     h = h * 33 + c
/// return h
/// ```
pub fn gnu_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &c in name {
        h = h.wrapping_mul(33).wrapping_add(c as u32);
    }
    h
}

/// GNU hash table header structure.
///
/// The GNU hash table uses a bloom filter for fast negative lookups
/// and a hash-bucketed symbol table for positive lookups.
#[derive(Debug, Clone, Copy)]
pub struct GnuHashHeader {
    /// Number of hash buckets
    pub nbuckets: u32,
    /// Index of first symbol in dynsym that is hashed
    pub symoffset: u32,
    /// Number of words in bloom filter
    pub bloom_size: u32,
    /// Bloom filter shift count
    pub bloom_shift: u32,
}

impl GnuHashHeader {
    /// Size of the GNU hash header in bytes.
    pub const SIZE: usize = 16;

    /// Parse a GNU hash header from a byte slice.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        Some(Self {
            nbuckets: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            symoffset: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            bloom_size: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            bloom_shift: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        })
    }

    /// Calculate the total size of the hash table (header + bloom + buckets).
    ///
    /// This excludes the variable-length chain array. Saturates if the size
    /// cannot be represented on the current platform; parsing checks it exactly.
    pub fn header_and_bloom_and_buckets_size(&self) -> usize {
        Self::SIZE
            .saturating_add((self.bloom_size as usize).saturating_mul(8))
            .saturating_add((self.nbuckets as usize).saturating_mul(4))
    }
}

/// GNU hash table for symbol lookup.
#[derive(Debug, Clone)]
pub struct GnuHashTable {
    /// Header information
    pub header: GnuHashHeader,
    /// Bloom filter words (64-bit each on ELF64)
    bloom: Vec<u64>,
    /// Hash buckets
    buckets: Vec<u32>,
    /// Hash chains (starts at symoffset)
    chains: Vec<u32>,
}

impl GnuHashTable {
    /// Parse a GNU hash table from a byte slice.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let header = GnuHashHeader::parse(data)?;

        // These values control division, shifts, and allocation below. Reject
        // invalid metadata before using it, including in debug/checked builds.
        if header.nbuckets == 0
            || !header.bloom_size.is_power_of_two()
            || header.bloom_shift >= u32::BITS
        {
            return None;
        }

        let bloom_start = GnuHashHeader::SIZE;
        let bloom_size_bytes = usize::try_from(header.bloom_size).ok()?.checked_mul(8)?;
        let buckets_start = bloom_start.checked_add(bloom_size_bytes)?;
        let buckets_size_bytes = usize::try_from(header.nbuckets).ok()?.checked_mul(4)?;
        let chains_start = buckets_start.checked_add(buckets_size_bytes)?;

        // Validate we have enough data for at least the fixed parts
        if data.len() < chains_start {
            return None;
        }

        // Parse bloom filter
        let bloom_data = &data[bloom_start..bloom_start + bloom_size_bytes];
        let bloom = parse_u64_words(bloom_data)?;

        // Parse buckets
        let buckets_data = &data[buckets_start..buckets_start + buckets_size_bytes];
        let buckets = parse_u32_words(buckets_data)?;

        // Chains extend to end of section (variable length)
        let chains = parse_u32_words(&data[chains_start..])?;

        // Zero denotes an empty bucket, even when symoffset is zero. Every
        // nonempty bucket must refer to a chain word that is actually present.
        for &bucket in &buckets {
            if bucket != 0 {
                let chain_index = usize::try_from(bucket.checked_sub(header.symoffset)?).ok()?;
                chains.get(chain_index)?;
            }
        }

        Some(Self {
            header,
            bloom,
            buckets,
            chains,
        })
    }

    /// Check if a symbol might exist using the bloom filter.
    ///
    /// Returns `false` if the symbol definitely doesn't exist.
    /// Returns `true` if it might exist (requires bucket lookup to confirm).
    pub fn bloom_check(&self, hash: u32) -> bool {
        // The header is public and can be changed after parsing, so do not
        // rely solely on parse-time validation to make the shift safe.
        if self.bloom.is_empty() || self.header.bloom_shift >= u32::BITS {
            return false;
        }

        let word_idx = (hash / 64) as usize % self.bloom.len();
        let bit1 = 1u64 << (hash % 64);
        let bit2 = 1u64 << ((hash >> self.header.bloom_shift) % 64);

        let word = self.bloom[word_idx];
        (word & bit1 != 0) && (word & bit2 != 0)
    }

    /// Look up a symbol by name and return its dynsym index.
    pub fn lookup(&self, name: &[u8], dynsym: &[Elf64Symbol], dynstr: &[u8]) -> Option<u32> {
        if self.header.nbuckets == 0 || self.buckets.is_empty() {
            return None;
        }

        let hash = gnu_hash(name);
        if !self.bloom_check(hash) {
            return None;
        }

        let bucket_idx = (hash % self.header.nbuckets) as usize;
        let mut sym_idx = *self.buckets.get(bucket_idx)?;
        if sym_idx == 0 || sym_idx < self.header.symoffset {
            return None;
        }

        loop {
            if sym_idx as usize >= dynsym.len() {
                return None;
            }
            let chain_idx = sym_idx.checked_sub(self.header.symoffset)? as usize;
            let chain = *self.chains.get(chain_idx)?;
            if (chain | 1) == (hash | 1)
                && symbol_name_matches(dynsym, dynstr, sym_idx as usize, name)
            {
                return Some(sym_idx);
            }
            if chain & 1 != 0 {
                break;
            }
            sym_idx = sym_idx.checked_add(1)?;
        }

        None
    }
}

/// ELF (System V) hash table for symbol lookup.
#[derive(Debug, Clone)]
pub struct ElfHashTable {
    /// Number of buckets
    nbucket: u32,
    /// Number of chain entries
    nchain: u32,
    /// Bucket array
    buckets: Vec<u32>,
    /// Chain array
    chains: Vec<u32>,
}

impl ElfHashTable {
    /// Parse an ELF hash table from a byte slice.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        let nbucket = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let nchain = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        let buckets_start = 8usize;
        let buckets_size = usize::try_from(nbucket).ok()?.checked_mul(4)?;
        let chains_size = usize::try_from(nchain).ok()?.checked_mul(4)?;
        let buckets_end = buckets_start.checked_add(buckets_size)?;
        let chains_end = buckets_end.checked_add(chains_size)?;
        if data.len() < chains_end {
            return None;
        }
        let buckets = parse_u32_words(&data[buckets_start..buckets_end])?;
        let chains = parse_u32_words(&data[buckets_end..chains_end])?;

        Some(Self {
            nbucket,
            nchain,
            buckets,
            chains,
        })
    }

    /// Look up a symbol by name hash.
    ///
    /// Returns the symbol index if found, or None if not found.
    pub fn lookup(
        &self,
        hash: u32,
        name: &[u8],
        dynsym: &[Elf64Symbol],
        dynstr: &[u8],
    ) -> Option<u32> {
        if self.buckets.is_empty() || self.nbucket == 0 {
            return None;
        }

        let bucket_idx = hash % self.nbucket;
        let mut sym_idx = *self.buckets.get(bucket_idx as usize)?;

        // A valid chain visits each non-null symbol at most once. Bound the
        // walk by the available symbol/chain entries so corrupt self-links or
        // multi-node cycles cannot hang the loader. No per-lookup allocation.
        let max_steps = self.chains.len().min(dynsym.len());
        for _ in 0..max_steps {
            if sym_idx == 0 || sym_idx >= self.nchain || sym_idx as usize >= dynsym.len() {
                return None;
            }
            if symbol_name_matches(dynsym, dynstr, sym_idx as usize, name) {
                return Some(sym_idx);
            }
            sym_idx = *self.chains.get(sym_idx as usize)?;
        }

        None
    }
}

fn parse_u32_words(data: &[u8]) -> Option<Vec<u32>> {
    if !data.len().is_multiple_of(4) {
        return None;
    }

    let mut words = Vec::with_capacity(data.len() / 4);
    for &chunk in data.as_chunks::<4>().0 {
        words.push(u32::from_le_bytes(chunk));
    }
    Some(words)
}

fn parse_u64_words(data: &[u8]) -> Option<Vec<u64>> {
    if !data.len().is_multiple_of(8) {
        return None;
    }

    let mut words = Vec::with_capacity(data.len() / 8);
    for &chunk in data.as_chunks::<8>().0 {
        words.push(u64::from_le_bytes(chunk));
    }
    Some(words)
}

fn symbol_name_matches(dynsym: &[Elf64Symbol], dynstr: &[u8], sym_idx: usize, name: &[u8]) -> bool {
    dynsym
        .get(sym_idx)
        .and_then(|sym| get_string(dynstr, sym.st_name).ok())
        .is_some_and(|sym_name| sym_name.as_bytes() == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_parsers_reject_every_partial_word() {
        let data = [
            1, 2, 3, 4, 5, 6, 7, 8, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        ];
        let words32 = [0x0403_0201, 0x0807_0605, 0xccdd_eeff, 0x8899_aabb];
        let words64 = [0x0807_0605_0403_0201, 0x8899_aabb_ccdd_eeff];
        for len in 0..=data.len() {
            let expected32 = if len.is_multiple_of(4) {
                Some(words32[..len / 4].to_vec())
            } else {
                None
            };
            let expected64 = if len.is_multiple_of(8) {
                Some(words64[..len / 8].to_vec())
            } else {
                None
            };
            assert_eq!(parse_u32_words(&data[..len]), expected32, "len={len}");
            assert_eq!(parse_u64_words(&data[..len]), expected64, "len={len}");
        }
    }

    #[test]
    fn test_elf_hash() {
        // Computed test vectors
        assert_eq!(elf_hash(b""), 0);
        assert_eq!(elf_hash(b"printf"), 0x077905a6);
        assert_eq!(elf_hash(b"malloc"), 0x07383353);
        assert_eq!(elf_hash(b"strlen"), 0x07ab92be);
    }

    #[test]
    fn test_gnu_hash() {
        // GNU hash test vectors
        assert_eq!(gnu_hash(b""), 5381);
        // printf: djb2("printf") = computed
        let h = gnu_hash(b"printf");
        assert!(h != 0);

        // Verify determinism
        assert_eq!(gnu_hash(b"malloc"), gnu_hash(b"malloc"));
    }

    #[test]
    fn test_gnu_hash_header_parse() {
        let mut data = [0u8; 32];
        // nbuckets = 10
        data[0..4].copy_from_slice(&10u32.to_le_bytes());
        // symoffset = 1
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        // bloom_size = 2
        data[8..12].copy_from_slice(&2u32.to_le_bytes());
        // bloom_shift = 6
        data[12..16].copy_from_slice(&6u32.to_le_bytes());

        let header = GnuHashHeader::parse(&data).unwrap();
        assert_eq!(header.nbuckets, 10);
        assert_eq!(header.symoffset, 1);
        assert_eq!(header.bloom_size, 2);
        assert_eq!(header.bloom_shift, 6);
    }

    #[test]
    fn test_elf_hash_table_lookup() {
        let name = b"foo";
        let hash = elf_hash(name);
        let bucket_idx = (hash % 4) as usize;

        let mut data = vec![0u8; 8 + 4 * 4 + 2 * 4];
        data[0..4].copy_from_slice(&4u32.to_le_bytes());
        data[4..8].copy_from_slice(&2u32.to_le_bytes());

        let buckets_start = 8;
        let mut buckets = [0u32; 4];
        buckets[bucket_idx] = 1;
        for (i, bucket) in buckets.into_iter().enumerate() {
            let start = buckets_start + i * 4;
            data[start..start + 4].copy_from_slice(&bucket.to_le_bytes());
        }

        let chains_start = buckets_start + 4 * 4;
        data[chains_start + 4..chains_start + 8].copy_from_slice(&0u32.to_le_bytes());

        let table = ElfHashTable::parse(&data).unwrap();
        let dynsym = vec![
            Elf64Symbol {
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
            Elf64Symbol {
                st_name: 1,
                st_info: 0x12,
                st_other: 0,
                st_shndx: 1,
                st_value: 0x1000,
                st_size: 0,
            },
        ];
        let dynstr = b"\0foo\0";

        assert_eq!(table.lookup(hash, name, &dynsym, dynstr), Some(1));
        assert_eq!(table.lookup(hash, b"bar", &dynsym, dynstr), None);
    }

    #[test]
    fn test_gnu_hash_table_lookup() {
        let name = b"foo";
        let hash = gnu_hash(name);
        let bloom_word = (1u64 << (hash % 64)) | (1u64 << ((hash >> 5) % 64));

        let mut data = vec![0u8; 16 + 8 + 4 + 4];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        data[12..16].copy_from_slice(&5u32.to_le_bytes());
        data[16..24].copy_from_slice(&bloom_word.to_le_bytes());
        data[24..28].copy_from_slice(&1u32.to_le_bytes());
        data[28..32].copy_from_slice(&(hash | 1).to_le_bytes());

        let table = GnuHashTable::parse(&data).unwrap();
        let dynsym = vec![
            Elf64Symbol {
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            },
            Elf64Symbol {
                st_name: 1,
                st_info: 0x12,
                st_other: 0,
                st_shndx: 1,
                st_value: 0x1000,
                st_size: 0,
            },
        ];
        let dynstr = b"\0foo\0";

        assert_eq!(table.lookup(name, &dynsym, dynstr), Some(1));
        assert_eq!(table.lookup(b"bar", &dynsym, dynstr), None);
    }

    #[test]
    fn test_elf_hash_collision_resistance() {
        // Verify different strings produce different hashes (mostly)
        let h1 = elf_hash(b"foo");
        let h2 = elf_hash(b"bar");
        let h3 = elf_hash(b"baz");
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
        assert_ne!(h1, h3);
    }

    fn symbol(name_offset: u32) -> Elf64Symbol {
        Elf64Symbol {
            st_name: name_offset,
            st_info: 0x12,
            st_other: 0,
            st_shndx: 1,
            st_value: 0x1000,
            st_size: 0,
        }
    }

    fn sysv_table(chains: &[u32]) -> ElfHashTable {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&(chains.len() as u32).to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        for chain in chains {
            data.extend_from_slice(&chain.to_le_bytes());
        }
        ElfHashTable::parse(&data).unwrap()
    }

    fn gnu_table_bytes(shift: u32) -> Vec<u8> {
        let mut data = Vec::new();
        for word in [1u32, 1, 1, shift] {
            data.extend_from_slice(&word.to_le_bytes());
        }
        // An all-ones bloom word makes positive and negative lookups walk
        // the chain, independently of the selected valid shift.
        data.extend_from_slice(&u64::MAX.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&(gnu_hash(b"foo") | 1).to_le_bytes());
        data
    }

    #[test]
    fn sysv_cyclic_chains_terminate() {
        let dynsym = [symbol(0), symbol(1), symbol(5), symbol(9)];
        for chains in [vec![0, 1], vec![0, 2, 1], vec![0, 2, 3, 2]] {
            let table = sysv_table(&chains);
            assert_eq!(
                table.lookup(0, b"missing", &dynsym, b"\0foo\0bar\0baz\0"),
                None
            );
            assert_eq!(
                table.lookup(0, b"foo", &dynsym, b"\0foo\0bar\0baz\0"),
                Some(1)
            );
        }
    }

    #[test]
    fn sysv_walk_preserves_long_chain_hits_and_rejects_bad_indexes() {
        let dynsym = [symbol(0), symbol(1), symbol(5), symbol(9)];
        let dynstr = b"\0foo\0bar\0baz\0";
        let table = sysv_table(&[0, 2, 3, 0]);
        assert_eq!(table.lookup(0, b"baz", &dynsym, dynstr), Some(3));
        assert_eq!(table.lookup(0, b"missing", &dynsym, dynstr), None);
        assert_eq!(table.lookup(0, b"baz", &dynsym[..2], dynstr), None);
        assert_eq!(table.lookup(0, b"baz", &[], dynstr), None);
        let table = sysv_table(&[0, u32::MAX]);
        assert_eq!(table.lookup(0, b"missing", &dynsym, dynstr), None);
    }

    #[test]
    fn hash_parsers_reject_unrepresentable_or_truncated_counts() {
        let mut sysv = vec![0xff; 8];
        assert!(ElfHashTable::parse(&sysv).is_none());
        sysv[..4].copy_from_slice(&1u32.to_le_bytes());
        assert!(ElfHashTable::parse(&sysv).is_none());
        let mut gnu = gnu_table_bytes(5);
        gnu[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(GnuHashTable::parse(&gnu).is_none());
        gnu[..4].copy_from_slice(&1u32.to_le_bytes());
        gnu[8..12].copy_from_slice(&(1u32 << 31).to_le_bytes());
        assert!(GnuHashTable::parse(&gnu).is_none());
    }

    #[test]
    fn gnu_rejects_invalid_bloom_metadata() {
        for shift in [32, 64, u32::MAX] {
            assert!(GnuHashTable::parse(&gnu_table_bytes(shift)).is_none());
        }
        for size in [0u32, 3] {
            let mut data = gnu_table_bytes(5);
            data[8..12].copy_from_slice(&size.to_le_bytes());
            assert!(GnuHashTable::parse(&data).is_none());
        }
        let mut data = gnu_table_bytes(5);
        data[..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(GnuHashTable::parse(&data).is_none());
    }

    #[test]
    fn gnu_lookup_handles_all_valid_shifts_and_mutated_header() {
        let dynsym = [symbol(0), symbol(1)];
        for shift in 0..u32::BITS {
            let mut table = GnuHashTable::parse(&gnu_table_bytes(shift)).unwrap();
            assert_eq!(table.lookup(b"foo", &dynsym, b"\0foo\0"), Some(1));
            table.header.bloom_shift = u32::MAX;
            assert!(!table.bloom_check(gnu_hash(b"foo")));
            assert_eq!(table.lookup(b"foo", &dynsym, b"\0foo\0"), None);
        }
    }

    #[test]
    fn gnu_rejects_truncated_and_out_of_range_buckets() {
        let data = gnu_table_bytes(5);
        for len in 0..data.len() {
            assert!(GnuHashTable::parse(&data[..len]).is_none(), "len={len}");
        }
        let mut data = data;
        data[24..28].copy_from_slice(&2u32.to_le_bytes());
        assert!(GnuHashTable::parse(&data).is_none());
        data[24..28].copy_from_slice(&1u32.to_le_bytes());
        data[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert!(GnuHashTable::parse(&data).is_none());
    }

    #[test]
    fn gnu_empty_bucket_never_resolves_the_null_symbol() {
        let mut data = gnu_table_bytes(5);
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        data[24..28].copy_from_slice(&0u32.to_le_bytes());
        let table = GnuHashTable::parse(&data).unwrap();
        // Even a name/hash collision at dynsym[0] cannot make an empty
        // bucket look populated.
        assert_eq!(table.lookup(b"foo", &[symbol(1)], b"\0foo\0"), None);
    }

    #[test]
    fn gnu_unterminated_chain_and_short_symbol_table_terminate() {
        let mut data = gnu_table_bytes(5);
        data[28..32].copy_from_slice(&(gnu_hash(b"foo") & !1).to_le_bytes());
        let table = GnuHashTable::parse(&data).unwrap();
        let dynsym = [symbol(0), symbol(1)];
        assert_eq!(table.lookup(b"missing", &dynsym, b"\0foo\0"), None);
        assert_eq!(table.lookup(b"foo", &dynsym[..1], b"\0foo\0"), None);
    }
}
