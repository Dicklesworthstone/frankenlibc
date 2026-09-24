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

/// Wide-character class names, in the order [`CtypeTables`] indexes them.
pub const WIDE_CLASSES: [&[u8]; 12] = [
    b"upper", b"lower", b"alpha", b"digit", b"xdigit", b"space", b"print", b"graph", b"blank",
    b"cntrl", b"punct", b"alnum",
];

/// The wide-character tables of an `LC_CTYPE` blob: one bitmap table per
/// class, the `toupper`/`tolower` delta maps and the `wcwidth` byte table,
/// all in glibc's three-level format (a header of `shift1, bound, shift2,
/// mask2, mask3`, then level-1 offsets; a zero offset means "absent").
#[derive(Clone, Copy, Debug)]
pub struct CtypeTables<'a> {
    classes: [&'a [u8]; 12],
    toupper: &'a [u8],
    tolower: &'a [u8],
    width: &'a [u8],
}

/// Item `index` of `blob` up to the next item's offset (or the blob end).
fn item_slice<'a>(blob: &CategoryBlob<'a>, index: usize) -> Option<&'a [u8]> {
    let start = blob.offset(index)?;
    let end = blob
        .offset(index + 1)
        .filter(|&e| e >= start)
        .unwrap_or(blob.bytes().len());
    blob.bytes().get(start..end)
}

/// Position of `name` in a NUL-separated name list (ended by an empty name).
fn name_index(list: &[u8], name: &[u8]) -> Option<usize> {
    list.split(|&b| b == 0)
        .take_while(|n| !n.is_empty())
        .position(|n| n == name)
}

impl<'a> CtypeTables<'a> {
    /// LC_CTYPE items: 10 CLASS_NAMES, 11 MAP_NAMES, 12 WIDTH,
    /// 17 CLASS_OFFSET, 18 MAP_OFFSET.
    pub fn from_blob(blob: &CategoryBlob<'a>) -> Option<Self> {
        let class_names = item_slice(blob, 10)?;
        let map_names = item_slice(blob, 11)?;
        let class_offset = blob.word(17)? as usize;
        let map_offset = blob.word(18)? as usize;
        let mut classes: [&'a [u8]; 12] = [&[]; 12];
        for (slot, name) in classes.iter_mut().zip(WIDE_CLASSES) {
            *slot = item_slice(blob, class_offset + name_index(class_names, name)?)?;
        }
        Some(Self {
            classes,
            toupper: item_slice(blob, map_offset + name_index(map_names, b"toupper")?)?,
            tolower: item_slice(blob, map_offset + name_index(map_names, b"tolower")?)?,
            width: item_slice(blob, 12)?,
        })
    }

    /// Whether `wc` is in class `class` (index into [`WIDE_CLASSES`]).
    pub fn is_class(&self, class: usize, wc: u32) -> bool {
        let Some(table) = self.classes.get(class) else {
            return false;
        };
        match leaf(table, wc, 5) {
            Some((leaf_off, index)) => read_u32(table, leaf_off + index * 4)
                .is_some_and(|word| (word >> (wc & 0x1f)) & 1 != 0),
            None => false,
        }
    }

    fn map(table: &[u8], wc: u32) -> u32 {
        match leaf(table, wc, 0) {
            Some((leaf_off, index)) => {
                read_u32(table, leaf_off + index * 4).map_or(wc, |delta| wc.wrapping_add(delta))
            }
            None => wc,
        }
    }

    pub fn to_upper(&self, wc: u32) -> u32 {
        Self::map(self.toupper, wc)
    }

    pub fn to_lower(&self, wc: u32) -> u32 {
        Self::map(self.tolower, wc)
    }

    /// `wcwidth`: the table byte, 0xff (and absent) meaning -1.
    pub fn width(&self, wc: u32) -> i32 {
        match leaf(self.width, wc, 0) {
            Some((leaf_off, index)) => match self.width.get(leaf_off + index) {
                Some(&0xff) | None => -1,
                Some(&w) => i32::from(w),
            },
            None => -1,
        }
    }
}

/// Walk levels 1 and 2 of a three-level table; returns the level-3 block
/// offset and the index within it (`(wc >> shift3) & mask3`).
fn leaf(table: &[u8], wc: u32, shift3: u32) -> Option<(usize, usize)> {
    let shift1 = read_u32(table, 0)?;
    let bound = read_u32(table, 4)?;
    let index1 = wc.checked_shr(shift1).unwrap_or(0);
    if index1 >= bound {
        return None;
    }
    let lookup1 = read_u32(table, 20 + index1 as usize * 4)? as usize;
    if lookup1 == 0 {
        return None;
    }
    let shift2 = read_u32(table, 8)?;
    let mask2 = read_u32(table, 12)?;
    let index2 = (wc.checked_shr(shift2).unwrap_or(0) & mask2) as usize;
    let lookup2 = read_u32(table, lookup1 + index2 * 4)? as usize;
    if lookup2 == 0 {
        return None;
    }
    let mask3 = read_u32(table, 16)?;
    Some((
        lookup2,
        (wc.checked_shr(shift3).unwrap_or(0) & mask3) as usize,
    ))
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
    fn ctype_tables_from_c_utf8_if_present() {
        let Ok(bytes) = std::fs::read("/usr/lib/locale/C.utf8/LC_CTYPE") else {
            return;
        };
        let blob = CategoryBlob::parse(0, &bytes).expect("LC_CTYPE");
        let t = CtypeTables::from_blob(&blob).expect("tables");
        let alpha = 2;
        assert!(
            t.is_class(alpha, 'a' as u32) && t.is_class(alpha, 0xE9) && t.is_class(alpha, 0x4E00)
        );
        assert!(!t.is_class(alpha, '1' as u32));
        assert_eq!(t.to_upper(0xE9), 0xC9);
        assert_eq!(t.to_lower('A' as u32), 'a' as u32);
        assert_eq!(t.width('a' as u32), 1);
        assert_eq!(t.width(0x4E00), 2);
        assert_eq!(t.width(0x0301), 0);
        assert_eq!(t.width(0x07), -1);
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
