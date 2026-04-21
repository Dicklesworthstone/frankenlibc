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
    /// Note: This doesn't include the chain array which has variable length.
    pub fn header_and_bloom_and_buckets_size(&self) -> usize {
        Self::SIZE + (self.bloom_size as usize * 8) + (self.nbuckets as usize * 4)
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

        // Calculate offsets
        let bloom_start = GnuHashHeader::SIZE;
        let bloom_size_bytes = header.bloom_size as usize * 8;
        let buckets_start = bloom_start + bloom_size_bytes;
        let buckets_size_bytes = header.nbuckets as usize * 4;
        let chains_start = buckets_start + buckets_size_bytes;

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
        if self.bloom.is_empty() {
            return true; // No bloom filter, can't exclude
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
        if sym_idx < self.header.symoffset {
            return None;
        }

        loop {
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

        let required_size = 8 + (nbucket as usize + nchain as usize) * 4;
        if data.len() < required_size {
            return None;
        }

        let buckets_start = 8;
        let buckets_end = buckets_start + nbucket as usize * 4;
        let chains_end = buckets_end + nchain as usize * 4;
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

        while sym_idx != 0 {
            if sym_idx as usize >= self.nchain as usize {
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
    for chunk in data.chunks_exact(4) {
        words.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    Some(words)
}

fn parse_u64_words(data: &[u8]) -> Option<Vec<u64>> {
    if !data.len().is_multiple_of(8) {
        return None;
    }

    let mut words = Vec::with_capacity(data.len() / 8);
    for chunk in data.chunks_exact(8) {
        words.push(u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]));
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
}
