//! Multi-level collation over glibc's compiled `LC_COLLATE` tables.
//!
//! The compiled category (see [`super::data`]) carries, for multibyte
//! strings:
//!
//! * `NRULES` (item 0): the number of levels; 0 means plain byte order.
//! * `RULESETS` (item 1): `nrules` flag bytes per ruleset
//!   (`1` forward, `2` backward, `4` position).
//! * `TABLEMB` (item 2): 256 `i32`s indexed by a string's first byte. A
//!   non-negative value is the character's entry; a negative one points into
//!   `EXTRAMB` at a list of longer byte sequences (and ranges) starting with
//!   that byte.
//! * `WEIGHTMB` (item 3): per entry, for each level, a length byte followed by
//!   that many weight bytes.
//! * `EXTRAMB` (item 4) / `INDIRECTMB` (item 5): the multi-byte sequence lists
//!   and range offset tables.
//!
//! An entry is `(ruleset << 24) | weight_index`. Comparison runs level by
//! level: each string becomes a stream of weight *sequences*; runs of
//! characters whose ruleset is backward at this level are replayed in
//! reverse; zero-length sequences are ignorable and, on a position level,
//! the count of them before a sequence matters; a partially compared
//! sequence carries its rest into the next comparison; a string that ends
//! first sorts first. Strings equal at every level compare equal.
//!
//! Measured against glibc 2.43 `strcoll` under en_US.UTF-8: identical on
//! 30k random letter strings, 30k random punctuation/digit strings, and all
//! but 18 of 200k mixed strings (Latin, accents, CJK, digits, punctuation).
//! The residue is one glibc quirk: a backward-ruleset run (digits,
//! punctuation) that contains an ignorable character before a following
//! character, e.g. glibc orders `0-a` before `-0a` although its own
//! `strxfrm` keys order them the other way (244 of the 115,600 pairs of
//! all strings of length <= 4 over `{0 _ a -}`). Not reproduced.
//!
//! All table reads are bounds-checked: the data comes from files.

use super::data::CategoryBlob;

const SORT_BACKWARD: u8 = 2;
const SORT_POSITION: u8 = 4;

/// The multibyte collation tables of one locale.
#[derive(Clone, Copy, Debug)]
pub struct CollateTables<'a> {
    nrules: usize,
    rulesets: &'a [u8],
    table: &'a [u8],
    weights: &'a [u8],
    extra: &'a [u8],
    indirect: &'a [u8],
    /// `COLLSEQMB` (item 16): one byte per byte value.
    collseq_mb: &'a [u8],
    /// `COLLSEQWC` (item 17): a wide character's collation-sequence value.
    collseq_wc: &'a [u8],
}

fn slice_between<'a>(blob: &CategoryBlob<'a>, item: usize, next: usize) -> Option<&'a [u8]> {
    let start = blob.offset(item)?;
    let end = blob.offset(next).unwrap_or(blob.bytes().len());
    blob.bytes().get(start..end.max(start))
}

fn i32_at(bytes: &[u8], index: usize) -> Option<i32> {
    let at = index.checked_mul(4)?;
    let b = bytes.get(at..at + 4)?;
    Some(i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

impl<'a> CollateTables<'a> {
    /// Extract the tables from an `LC_COLLATE` blob. `None` when the blob
    /// has no rules (byte order) or is malformed.
    pub fn from_blob(blob: &CategoryBlob<'a>) -> Option<Self> {
        let nrules = blob.word(0)? as usize;
        if nrules == 0 {
            return None;
        }
        let rulesets = slice_between(blob, 1, 2)?;
        let table = slice_between(blob, 2, 3)?;
        if table.len() < 256 * 4 {
            return None;
        }
        Some(Self {
            nrules,
            rulesets,
            table,
            weights: slice_between(blob, 3, 4)?,
            extra: slice_between(blob, 4, 5)?,
            indirect: slice_between(blob, 5, 6)?,
            collseq_mb: slice_between(blob, 16, 17).unwrap_or(&[]),
            collseq_wc: slice_between(blob, 17, 18).unwrap_or(&[]),
        })
    }

    /// The single-byte `COLLSEQMB` value of `byte`. glibc's regcomp orders a
    /// collating-symbol range endpoint (`[[.a.]-z]`) by this table even in a
    /// multibyte locale, where its small values fall below every
    /// [`collation_seq`](Self::collation_seq) of a letter.
    pub fn collation_seq_byte(&self, byte: u8) -> Option<u32> {
        self.collseq_mb
            .get(usize::from(byte))
            .map(|&v| u32::from(v))
    }

    /// The collation-sequence value of the wide character `wc`, which orders
    /// bracket ranges in regex and fnmatch (en_US: `[a-z]` holds à, é and ß
    /// but not `B`). `None` when the locale assigns `wc` no value.
    ///
    /// `COLLSEQWC` is a three-level table of `u32`s: a header `shift1, bound,
    /// shift2, mask2, mask3`, then `bound` first-level byte offsets of
    /// second-level tables (0: absent), whose entries are byte offsets of
    /// third-level tables of values.
    pub fn collation_seq(&self, wc: u32) -> Option<u32> {
        let t = self.collseq_wc;
        let word = |at: usize| i32_at_unaligned(t, at).map(|v| v as u32);
        let shift1 = word(0)?;
        let index1 = wc.checked_shr(shift1)? as usize;
        if index1 >= word(4)? as usize {
            return None;
        }
        let lookup1 = word(4 * (5 + index1))? as usize;
        if lookup1 == 0 {
            return None;
        }
        let index2 = (wc.checked_shr(word(8)?)? & word(12)?) as usize;
        let lookup2 = word(lookup1 + 4 * index2)? as usize;
        if lookup2 == 0 {
            return None;
        }
        let index3 = (wc & word(16)?) as usize;
        word(lookup2 + 4 * index3).filter(|&v| v != u32::MAX)
    }

    /// Look up the entry for the character at the start of `s`, returning
    /// it and the number of bytes consumed.
    fn find_index(&self, s: &[u8]) -> Option<(i32, usize)> {
        let first = *s.first()?;
        let i = i32_at(self.table, usize::from(first))?;
        if i >= 0 {
            return Some((i, 1));
        }
        // A list of longer sequences starting with `first`.
        let rest = &s[1..];
        let mut cp = usize::try_from(-(i as i64)).ok()?;
        loop {
            let idx = i32_at_unaligned(self.extra, cp)?;
            cp += 4;
            let nhere = usize::from(*self.extra.get(cp)?);
            cp += 1;
            let seq = self.extra.get(cp..cp + nhere)?;
            if idx >= 0 {
                // A single sequence; the list ends with a zero-length entry
                // standing for `first` alone.
                if rest.len() >= nhere && &rest[..nhere] == seq {
                    return Some((idx, 1 + nhere));
                }
                cp = align4(cp + nhere);
            } else {
                // A range [seq, end] of equal-length sequences.
                let end = self.extra.get(cp + nhere..cp + 2 * nhere)?;
                let n = nhere.min(rest.len());
                let cmp_lo = rest[..n].cmp(&seq[..n]);
                let in_range = rest.len() >= nhere
                    && cmp_lo != std::cmp::Ordering::Less
                    && rest[..nhere] <= *end;
                if !in_range {
                    cp = align4(cp + 2 * nhere);
                    continue;
                }
                // Offset of `rest` within the range, big-endian over the
                // differing bytes.
                let mut k = 0;
                while k < nhere && rest[k] == seq[k] {
                    k += 1;
                }
                // Per-byte differences are signed: a later byte may be
                // below the range start's byte at that position.
                let mut offset: i64 = 0;
                while k < nhere {
                    offset = (offset << 8) + i64::from(rest[k]) - i64::from(seq[k]);
                    k += 1;
                }
                let at = usize::try_from(-i64::from(idx) + offset).ok()?;
                return Some((i32_at(self.indirect, at)?, 1 + nhere));
            }
        }
    }

    /// The equivalence-class key of `s` when it is exactly one collating
    /// element: its ruleset and level-0 weights. Two characters are in the
    /// same `[=c=]` class iff their keys are equal, as glibc's regex and
    /// fnmatch decide it (so `a`, `A` and `à` share a class in en_US, and every
    /// ignorable character has the empty key). `None` for no entry.
    pub fn equivalence_key(&self, s: &[u8]) -> Option<(u32, &'a [u8])> {
        let (key, used) = self.leading_equivalence_key(s)?;
        (used == s.len()).then_some(key)
    }

    /// The equivalence-class key of the collating element at the start of
    /// `s`, and its length in bytes.
    pub fn leading_equivalence_key(&self, s: &[u8]) -> Option<((u32, &'a [u8]), usize)> {
        let (entry, used) = self.find_index(s)?;
        if entry == 0 {
            return None;
        }
        let e = entry as u32;
        Some((
            (e >> 24, self.level_weights((e & 0x00ff_ffff) as usize, 0)),
            used,
        ))
    }

    /// The entries of every character of `s` (stopping at NUL), as
    /// `(ruleset, weight_index)`.
    fn entries(&self, s: &[u8]) -> Vec<(usize, usize)> {
        let mut out = Vec::with_capacity(s.len());
        let mut pos = 0;
        while pos < s.len() && s[pos] != 0 {
            match self.find_index(&s[pos..]) {
                Some((entry, used)) => {
                    let e = entry as u32;
                    out.push(((e >> 24) as usize, (e & 0x00ff_ffff) as usize));
                    pos += used.max(1);
                }
                None => pos += 1,
            }
        }
        out
    }

    fn rule_flags(&self, ruleset: usize, pass: usize) -> u8 {
        self.rulesets
            .get(ruleset * self.nrules + pass)
            .copied()
            .unwrap_or(1)
    }

    /// The level-`pass` weights of the entry at `base`.
    fn level_weights(&self, base: usize, pass: usize) -> &'a [u8] {
        let mut idx = base;
        for _ in 0..pass {
            let Some(&len) = self.weights.get(idx) else {
                return &[];
            };
            idx += usize::from(len) + 1;
        }
        let Some(&len) = self.weights.get(idx) else {
            return &[];
        };
        self.weights
            .get(idx + 1..idx + 1 + usize::from(len))
            .unwrap_or(&[])
    }

    /// The weight sequences of one string at level `pass`, in comparison
    /// order: runs of characters whose ruleset is backward at this level are
    /// reversed. Empty sequences are ignorable.
    fn emitted(&self, entries: &[(usize, usize)], pass: usize) -> Vec<&'a [u8]> {
        let mut out = Vec::with_capacity(entries.len());
        let mut i = 0;
        while i < entries.len() {
            if self.rule_flags(entries[i].0, pass) & SORT_BACKWARD != 0 {
                let mut j = i;
                while j < entries.len() && self.rule_flags(entries[j].0, pass) & SORT_BACKWARD != 0
                {
                    j += 1;
                }
                for k in (i..j).rev() {
                    out.push(self.level_weights(entries[k].1, pass));
                }
                i = j;
            } else {
                out.push(self.level_weights(entries[i].1, pass));
                i += 1;
            }
        }
        out
    }

    /// `strcoll` for two NUL-free byte strings (sign is what matters).
    pub fn compare(&self, s1: &[u8], s2: &[u8]) -> i32 {
        if s1.is_empty() || s2.is_empty() {
            return i32::from(!s1.is_empty()) - i32::from(!s2.is_empty());
        }
        let e1 = self.entries(s1);
        let e2 = self.entries(s2);
        let mut rule = 0usize;
        for pass in 0..self.nrules {
            let position = self.rule_flags(rule, pass) & SORT_POSITION != 0;
            let mut a = Stream::new(self.emitted(&e1, pass));
            let mut b = Stream::new(self.emitted(&e2, pass));
            loop {
                a.next_seq();
                b.next_seq();
                if a.cur.is_empty() || b.cur.is_empty() {
                    if a.cur.len() == b.cur.len() {
                        break;
                    }
                    return if a.cur.is_empty() { -1 } else { 1 };
                }
                if position && a.val != b.val {
                    return if a.val > b.val { 1 } else { -1 };
                }
                let common = a.cur.len().min(b.cur.len());
                if let Some(k) = (0..common).find(|&k| a.cur[k] != b.cur[k]) {
                    return i32::from(a.cur[k]) - i32::from(b.cur[k]);
                }
                a.cur = &a.cur[common..];
                b.cur = &b.cur[common..];
                if position && a.cur.len() != b.cur.len() {
                    return a.cur.len() as i32 - b.cur.len() as i32;
                }
            }
            rule = e1.first().map_or(0, |e| e.0);
        }
        0
    }
}

impl<'a> CollateTables<'a> {
    /// `strxfrm`'s sort key: each level's weights in comparison order,
    /// levels separated by `0x01`; on a position level every weight
    /// sequence is preceded by its count byte (1 + ignorables skipped).
    pub fn sort_key(&self, s: &[u8]) -> Vec<u8> {
        if s.is_empty() {
            return Vec::new();
        }
        let entries = self.entries(s);
        let mut key = Vec::new();
        let mut rule = 0usize;
        let mut last_level_start = 0;
        for pass in 0..self.nrules {
            if pass > 0 {
                key.push(1);
            }
            last_level_start = key.len();
            let position = self.rule_flags(rule, pass) & SORT_POSITION != 0;
            let mut val: u8 = 0;
            for seq in self.emitted(&entries, pass) {
                val = val.wrapping_add(1);
                if seq.is_empty() {
                    continue;
                }
                if position {
                    key.push(val);
                }
                key.extend_from_slice(seq);
                val = 0;
            }
            rule = entries.first().map_or(0, |e| e.0);
        }
        // glibc drops the separator before a last level that has no weights.
        if self.nrules > 1 && key.len() == last_level_start {
            key.pop();
        }
        key
    }
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn i32_at_unaligned(bytes: &[u8], at: usize) -> Option<i32> {
    let b = bytes.get(at..at + 4)?;
    Some(i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

/// One string's weight-sequence stream at one level.
struct Stream<'a> {
    seqs: Vec<&'a [u8]>,
    next: usize,
    /// The unconsumed rest of the current sequence (empty = none / end).
    cur: &'a [u8],
    /// 1 + the ignorable sequences skipped to reach `cur`; 0 when `cur` is
    /// the remainder of a partially compared sequence.
    val: usize,
}

impl<'a> Stream<'a> {
    fn new(seqs: Vec<&'a [u8]>) -> Self {
        Self {
            seqs,
            next: 0,
            cur: &[],
            val: 0,
        }
    }

    fn next_seq(&mut self) {
        if !self.cur.is_empty() {
            self.val = 0;
            return;
        }
        let mut val = 0;
        while self.cur.is_empty() {
            val += 1;
            let Some(seq) = self.seqs.get(self.next) else {
                break;
            };
            self.cur = seq;
            self.next += 1;
        }
        self.val = val;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locale::data::LocaleArchive;

    fn en_us<'a>(archive: &'a [u8]) -> Option<CollateTables<'a>> {
        let archive = LocaleArchive::parse(archive)?;
        let blobs = archive.find(b"en_US.utf8")?;
        CollateTables::from_blob(&blobs[3]?)
    }

    #[test]
    fn en_us_orders_like_glibc_if_installed() {
        let Ok(bytes) = std::fs::read("/usr/lib/locale/locale-archive") else {
            return;
        };
        let Some(t) = en_us(&bytes) else {
            return;
        };
        // Case is a tertiary difference; letters dominate.
        assert!(t.compare(b"apple", b"Banana") < 0);
        assert!(t.compare(b"apple", b"Apple") < 0);
        assert!(t.compare("éclair".as_bytes(), b"eclair") > 0);
        assert!(t.compare(b"abc", b"abc") == 0);
        assert!(t.compare(b"", b"a") < 0);
        assert!(t.compare(b"a", b"ab") < 0);
        // strxfrm keys, byte-identical to glibc 2.43's.
        assert_eq!(t.sort_key(b"a"), [0x51, 1, 2, 1, 2, 1, 1, 0xe2, 0x94, 0x92]);
        assert_eq!(t.sort_key("中".as_bytes()), [0xe3, 0xaa, 0xaa, 1, 1]);
        assert_eq!(t.sort_key(b"-"), [1, 1, 1, 1, 0xc7, 0x9c]);
        assert!(t.sort_key(b"").is_empty());
    }
}
