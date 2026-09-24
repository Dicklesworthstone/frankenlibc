//! Compiled locale data: glibc's `locale-archive` and per-category files.
//!
//! Named locales (`en_US.UTF-8`, ...) are installed as compiled binary data,
//! either packed in `/usr/lib/locale/locale-archive` or unpacked as
//! `/usr/lib/locale/<name>/LC_<CATEGORY>` files. Both hold the same
//! per-category *blobs*:
//!
//! ```text
//! u32 magic            0x20031115 ^ category (LC_CTYPE, LC_COLLATE: own values)
//! u32 nstrings
//! u32 offset[nstrings] item i lives at blob + offset[i]
//! ...item data...
//! ```
//!
//! An `nl_item` is `(category << 16) | index`, so `nl_langinfo(item)` is
//! simply "the NUL-terminated string at `blob + offset[index]`", and numeric
//! items are the `u32`/byte at that offset.
//!
//! The archive is a header of `u32` fields
//!
//! ```text
//! magic 0xde020109, serial,
//! namehash_offset, namehash_used, namehash_size,
//! string_offset, string_used, string_size,
//! locrectab_offset, locrectab_used, locrectab_size,
//! sumhash_offset, sumhash_used, sumhash_size
//! ```
//!
//! with a name table of `{hashval, name_offset, locrec_offset}` entries
//! (`name_offset == 0` = empty slot) and locale records of `u32 refs` plus
//! 13 `{offset, len}` category slots indexed by category number (slot 6,
//! `LC_ALL`, spans the small categories and is not a blob).
//!
//! Every access is bounds-checked: the data is read from files, so a
//! truncated or hostile file yields `None`, never a panic or an
//! out-of-range read.

/// Number of category slots in a locale record (categories 0..=12).
pub const CATEGORY_SLOTS: usize = 13;

const ARCHIVE_MAGIC: u32 = 0xde02_0109;
const CTYPE_MAGIC: u32 = 0x2009_0720;
const COLLATE_MAGIC: u32 = 0x2005_1017;

/// The magic a blob of `category` must carry.
fn blob_magic(category: usize) -> u32 {
    match category {
        0 => CTYPE_MAGIC,
        3 => COLLATE_MAGIC,
        c => 0x2003_1115 ^ c as u32,
    }
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

/// One compiled category.
#[derive(Clone, Copy, Debug)]
pub struct CategoryBlob<'a> {
    bytes: &'a [u8],
    nstrings: usize,
}

impl<'a> CategoryBlob<'a> {
    /// Validate `bytes` as the blob of `category`.
    pub fn parse(category: usize, bytes: &'a [u8]) -> Option<Self> {
        if read_u32(bytes, 0)? != blob_magic(category) {
            return None;
        }
        let nstrings = read_u32(bytes, 4)? as usize;
        let table_end = 8usize.checked_add(nstrings.checked_mul(4)?)?;
        if table_end > bytes.len() {
            return None;
        }
        Some(Self { bytes, nstrings })
    }

    /// The whole blob.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Number of items.
    pub fn len(&self) -> usize {
        self.nstrings
    }

    /// Whether the blob has no items.
    pub fn is_empty(&self) -> bool {
        self.nstrings == 0
    }

    /// Byte offset of item `index` within the blob.
    pub fn offset(&self, index: usize) -> Option<usize> {
        if index >= self.nstrings {
            return None;
        }
        let off = read_u32(self.bytes, 8 + index * 4)? as usize;
        (off < self.bytes.len()).then_some(off)
    }

    /// Item `index` as a NUL-terminated string (without the NUL).
    pub fn string(&self, index: usize) -> Option<&'a [u8]> {
        let off = self.offset(index)?;
        let rest = &self.bytes[off..];
        let end = rest.iter().position(|&b| b == 0)?;
        Some(&rest[..end])
    }

    /// Item `index` as a `u32` word.
    pub fn word(&self, index: usize) -> Option<u32> {
        read_u32(self.bytes, self.offset(index)?)
    }

    /// Item `index` as a single byte (glibc's `char`-valued items).
    pub fn byte(&self, index: usize) -> Option<u8> {
        self.bytes.get(self.offset(index)?).copied()
    }
}

/// A parsed `locale-archive`.
#[derive(Clone, Copy, Debug)]
pub struct LocaleArchive<'a> {
    bytes: &'a [u8],
}

impl<'a> LocaleArchive<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        (read_u32(bytes, 0)? == ARCHIVE_MAGIC && bytes.len() >= 56).then_some(Self { bytes })
    }

    fn header(&self, field: usize) -> Option<usize> {
        read_u32(self.bytes, field * 4).map(|v| v as usize)
    }

    fn cstr_at(&self, at: usize) -> Option<&'a [u8]> {
        let rest = self.bytes.get(at..)?;
        let end = rest.iter().position(|&b| b == 0)?;
        Some(&rest[..end])
    }

    /// Names of the locales in the archive.
    pub fn names(&self) -> Vec<&'a [u8]> {
        let mut out = Vec::new();
        let (Some(off), Some(size)) = (self.header(2), self.header(4)) else {
            return out;
        };
        for i in 0..size {
            let entry = off + i * 12;
            let Some(name_off) = read_u32(self.bytes, entry + 4) else {
                break;
            };
            if name_off != 0
                && let Some(name) = self.cstr_at(name_off as usize)
            {
                out.push(name);
            }
        }
        out
    }

    /// The category blobs of locale `name` (exact match), indexed by
    /// category number; `LC_ALL`'s slot is always `None`.
    pub fn find(&self, name: &[u8]) -> Option<[Option<CategoryBlob<'a>>; CATEGORY_SLOTS]> {
        let off = self.header(2)?;
        let size = self.header(4)?;
        for i in 0..size {
            let entry = off.checked_add(i.checked_mul(12)?)?;
            let name_off = read_u32(self.bytes, entry + 4)? as usize;
            if name_off == 0 || self.cstr_at(name_off)? != name {
                continue;
            }
            let rec = read_u32(self.bytes, entry + 8)? as usize;
            let mut blobs = [None; CATEGORY_SLOTS];
            for (cat, slot) in blobs.iter_mut().enumerate() {
                if cat == 6 {
                    continue;
                }
                let at = rec + 4 + cat * 8;
                let b_off = read_u32(self.bytes, at)? as usize;
                let b_len = read_u32(self.bytes, at + 4)? as usize;
                let bytes = self.bytes.get(b_off..b_off.checked_add(b_len)?)?;
                *slot = CategoryBlob::parse(cat, bytes);
            }
            return Some(blobs);
        }
        None
    }
}

/// glibc's codeset normalization for locale names: keep only letters
/// (lower-cased) and digits; an all-digit result gets an `iso` prefix.
/// `UTF-8` -> `utf8`, `ISO-8859-1` -> `iso88591`, `8859-1` -> `iso88591`.
pub fn normalize_codeset(codeset: &[u8]) -> Vec<u8> {
    let kept: Vec<u8> = codeset
        .iter()
        .filter(|b| b.is_ascii_alphanumeric())
        .map(u8::to_ascii_lowercase)
        .collect();
    if !kept.is_empty() && kept.iter().all(u8::is_ascii_digit) {
        let mut out = b"iso".to_vec();
        out.extend_from_slice(&kept);
        return out;
    }
    kept
}

/// Names to try for a requested locale, most specific first: the name as
/// given, then with its codeset normalized (`en_US.UTF-8` -> `en_US.utf8`).
/// Modifiers (`@euro`) are kept in place.
pub fn name_candidates(name: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![name.to_vec()];
    if let Some(dot) = name.iter().position(|&b| b == b'.') {
        let rest = &name[dot + 1..];
        let (codeset, modifier) = match rest.iter().position(|&b| b == b'@') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, &[][..]),
        };
        let mut normalized = name[..=dot].to_vec();
        normalized.extend_from_slice(&normalize_codeset(codeset));
        normalized.extend_from_slice(modifier);
        if normalized != name {
            out.push(normalized);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codeset_normalization_matches_glibc() {
        assert_eq!(normalize_codeset(b"UTF-8"), b"utf8");
        assert_eq!(normalize_codeset(b"ISO-8859-15"), b"iso885915");
        assert_eq!(normalize_codeset(b"8859-1"), b"iso88591");
        assert_eq!(
            name_candidates(b"de_DE.UTF-8@euro"),
            [b"de_DE.UTF-8@euro".to_vec(), b"de_DE.utf8@euro".to_vec()]
        );
        assert_eq!(name_candidates(b"en_US.utf8"), [b"en_US.utf8".to_vec()]);
    }

    #[test]
    fn blob_parsing_rejects_bad_input() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&(0x2003_1115u32 ^ 1).to_ne_bytes());
        blob.extend_from_slice(&2u32.to_ne_bytes());
        blob.extend_from_slice(&16u32.to_ne_bytes());
        blob.extend_from_slice(&18u32.to_ne_bytes());
        blob.extend_from_slice(b".\0,\0");
        let b = CategoryBlob::parse(1, &blob).expect("valid");
        assert_eq!(b.string(0), Some(&b"."[..]));
        assert_eq!(b.string(1), Some(&b","[..]));
        assert_eq!(b.string(2), None);
        assert!(
            CategoryBlob::parse(2, &blob).is_none(),
            "wrong magic for LC_TIME"
        );
        assert!(
            CategoryBlob::parse(1, &blob[..10]).is_none(),
            "truncated table"
        );
        assert!(LocaleArchive::parse(b"garbage").is_none());
    }

    #[test]
    fn system_archive_en_us_if_present() {
        let Ok(bytes) = std::fs::read("/usr/lib/locale/locale-archive") else {
            return;
        };
        let archive = LocaleArchive::parse(&bytes).expect("archive magic");
        if !archive.names().contains(&&b"en_US.utf8"[..]) {
            return;
        }
        let blobs = archive.find(b"en_US.utf8").expect("en_US.utf8");
        let time = blobs[2].expect("LC_TIME");
        // D_T_FMT is nl_item 0x20028.
        assert_eq!(time.string(0x28), Some(&b"%a %d %b %Y %r %Z"[..]));
        let numeric = blobs[1].expect("LC_NUMERIC");
        assert_eq!(numeric.string(0), Some(&b"."[..]));
        assert_eq!(numeric.string(1), Some(&b","[..]));
        // CODESET is nl_item 14 (LC_CTYPE).
        assert_eq!(blobs[0].expect("LC_CTYPE").string(14), Some(&b"UTF-8"[..]));
    }
}
