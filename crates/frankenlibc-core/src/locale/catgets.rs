//! GNU `<nl_types.h>` catgets binary catalog parser.
//!
//! Pure-safe Rust port of the byte-level logic that previously lived
//! inline in frankenlibc-abi/src/locale_abi.rs::parse_catalog_bytes /
//! MessageCatalog. The abi keeps responsibility for the `nl_catd`
//! descriptor allocator, global registry, fallback path for
//! catopen-failure cases, and the `*const c_char` boundary; this
//! module produces and consumes byte slices only.
//!
//! Binary format (GNU catalog with magic `0x9604_08de`):
//!   - 3-word header: `magic`, `plane_size`, `plane_depth`
//!   - first hash plane: `plane_size * plane_depth * 3` words —
//!     each slot is `(stored_set, msg_id, string_offset)`
//!   - second hash plane: same size as the first (overflow chain)
//!   - strings blob: NUL-terminated message bodies
//!
//! Lookup: `idx = ((set_id+1) * msg_id) % plane_size`, then walk up
//! to `plane_depth` slots forward looking for the matching
//! `(stored_set, msg_id)` pair. The string offset indexes the strings
//! blob.

/// GNU catalog magic number (little-endian on disk).
pub const CATGETS_MAGIC: u32 = 0x9604_08de;

/// Number of `u32` words in the catalog header.
pub const CATALOG_HEADER_WORDS: usize = 3;

/// Number of `u32` words in each hash-plane slot
/// (`stored_set`, `msg_id`, `string_offset`).
pub const CATALOG_SLOT_WORDS: usize = 3;

/// Why [`parse_catalog_bytes`] could not produce a [`MessageCatalog`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogParseError {
    /// The first header word is present but does not match the catalog
    /// magic in either byte order.
    InvalidMagic,
    /// Fewer than the three required header words are present.
    TruncatedHeader,
    /// `plane_size` or `plane_depth` is zero — the catalog has no
    /// addressable slots.
    ZeroPlane,
    /// Computing the table footprint from `plane_size * plane_depth *
    /// 3 * 4` overflowed `usize`.
    ArithmeticOverflow,
    /// The buffer ends before the two hash tables and strings blob are
    /// fully addressable.
    TruncatedTable,
    /// One of the slot string offsets points past the strings blob,
    /// or the largest referenced string is not NUL-terminated.
    MissingNul,
}

/// Parsed GNU catgets message catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageCatalog {
    pub plane_size: usize,
    pub plane_depth: usize,
    pub table: Box<[u32]>,
    pub strings: Box<[u8]>,
}

impl MessageCatalog {
    /// Look up a message by `(set_id, msg_id)` and return its byte
    /// offset within the strings blob, if present.
    ///
    /// `set_id == 0` is the canonical "no set" identifier; it is
    /// stored as `1` on disk to preserve a 0-as-empty-slot sentinel.
    /// Negative `msg_id` values cannot be encoded.
    pub fn message_offset(&self, set_id: i32, msg_id: i32) -> Option<usize> {
        let stored_set = set_id.checked_add(1)?;
        if stored_set <= 0 || msg_id < 0 {
            return None;
        }

        let stored_set = stored_set as usize;
        let msg_id = msg_id as usize;
        let stride = self.plane_size.checked_mul(CATALOG_SLOT_WORDS)?;
        let mut idx = ((stored_set.checked_mul(msg_id)?) % self.plane_size) * CATALOG_SLOT_WORDS;

        for _ in 0..self.plane_depth {
            if idx + 2 >= self.table.len() {
                return None;
            }
            if self.table[idx] == stored_set as u32 && self.table[idx + 1] == msg_id as u32 {
                let offset = self.table[idx + 2] as usize;
                if offset >= self.strings.len() {
                    return None;
                }
                return Some(offset);
            }
            idx = idx.checked_add(stride)?;
        }

        None
    }

    /// Look up a message and return the NUL-terminated body as a
    /// borrowed byte slice excluding the NUL itself. Returns `None`
    /// when the message is absent or the strings blob is malformed
    /// (no NUL after the offset).
    pub fn message_bytes(&self, set_id: i32, msg_id: i32) -> Option<&[u8]> {
        let offset = self.message_offset(set_id, msg_id)?;
        let tail = &self.strings[offset..];
        let nul = tail.iter().position(|&b| b == 0)?;
        Some(&tail[..nul])
    }
}

fn catalog_word(bytes: &[u8], offset: usize, swapped_header: bool) -> Option<u32> {
    let chunk: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(if swapped_header {
        u32::from_be_bytes(chunk)
    } else {
        u32::from_le_bytes(chunk)
    })
}

/// Parse a GNU catgets binary catalog from `bytes`.
///
/// Header detection is bidirectional: the catalog magic is matched
/// against both little-endian and big-endian readings of the first
/// word. `plane_size` and `plane_depth` are then read with the
/// detected endianness; the two hash planes are read as little-endian
/// `u32` words (matching glibc — the second-plane endianness is not
/// renegotiated by the swapped header).
pub fn parse_catalog_bytes(bytes: Vec<u8>) -> Result<MessageCatalog, CatalogParseError> {
    let header_len = CATALOG_HEADER_WORDS * core::mem::size_of::<u32>();
    if bytes.len() < header_len {
        return Err(CatalogParseError::TruncatedHeader);
    }

    let magic_le = catalog_word(&bytes, 0, false).ok_or(CatalogParseError::TruncatedHeader)?;
    let swapped_header = if magic_le == CATGETS_MAGIC {
        false
    } else if catalog_word(&bytes, 0, true).ok_or(CatalogParseError::TruncatedHeader)?
        == CATGETS_MAGIC
    {
        true
    } else {
        return Err(CatalogParseError::InvalidMagic);
    };

    let plane_size =
        catalog_word(&bytes, 4, swapped_header).ok_or(CatalogParseError::TruncatedHeader)? as usize;
    let plane_depth =
        catalog_word(&bytes, 8, swapped_header).ok_or(CatalogParseError::TruncatedHeader)? as usize;
    if plane_size == 0 || plane_depth == 0 {
        return Err(CatalogParseError::ZeroPlane);
    }

    let table_words = plane_size
        .checked_mul(plane_depth)
        .and_then(|count| count.checked_mul(CATALOG_SLOT_WORDS))
        .ok_or(CatalogParseError::ArithmeticOverflow)?;
    let table_bytes = table_words
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or(CatalogParseError::ArithmeticOverflow)?;
    let first_table_end = header_len
        .checked_add(table_bytes)
        .ok_or(CatalogParseError::ArithmeticOverflow)?;
    let strings_offset = first_table_end
        .checked_add(table_bytes)
        .ok_or(CatalogParseError::ArithmeticOverflow)?;
    if strings_offset >= bytes.len() {
        return Err(CatalogParseError::TruncatedTable);
    }

    let first_table = bytes
        .get(header_len..first_table_end)
        .ok_or(CatalogParseError::TruncatedTable)?;
    let mut table = Vec::with_capacity(table_words);
    for chunk in first_table.chunks_exact(4) {
        let word: [u8; 4] = chunk
            .try_into()
            .map_err(|_| CatalogParseError::TruncatedTable)?;
        table.push(u32::from_le_bytes(word));
    }
    if table.len() != table_words {
        return Err(CatalogParseError::TruncatedTable);
    }

    let strings = bytes[strings_offset..].to_vec().into_boxed_slice();
    let max_offset = table
        .iter()
        .skip(2)
        .step_by(CATALOG_SLOT_WORDS)
        .copied()
        .max()
        .unwrap_or(0) as usize;
    if max_offset >= strings.len() || !strings[max_offset..].contains(&0) {
        return Err(CatalogParseError::MissingNul);
    }

    Ok(MessageCatalog {
        plane_size,
        plane_depth,
        table: table.into_boxed_slice(),
        strings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal catalog with `plane_size` slots and `plane_depth`
    /// hash chains, populated with the supplied
    /// `(set_id, msg_id, string)` entries placed at the canonical hash
    /// position. Pads the strings blob with the supplied messages
    /// concatenated and NUL-terminated.
    fn build_catalog(
        plane_size: usize,
        plane_depth: usize,
        entries: &[(i32, i32, &[u8])],
    ) -> Vec<u8> {
        let header_words = CATALOG_HEADER_WORDS;
        let table_words = plane_size * plane_depth * CATALOG_SLOT_WORDS;
        let total_table_bytes = table_words * 4;
        let header_bytes = header_words * 4;

        let mut out = Vec::new();
        // Header.
        out.extend_from_slice(&CATGETS_MAGIC.to_le_bytes());
        out.extend_from_slice(&(plane_size as u32).to_le_bytes());
        out.extend_from_slice(&(plane_depth as u32).to_le_bytes());

        // Two zero-initialized hash planes.
        let mut planes = vec![0u32; table_words];

        // Build the strings blob and slot table.
        let mut strings: Vec<u8> = Vec::new();
        for (set_id, msg_id, body) in entries {
            let offset = strings.len();
            strings.extend_from_slice(body);
            strings.push(0);

            let stored_set = (set_id + 1) as u32;
            let msg_id_u = *msg_id as u32;
            let mut idx =
                ((stored_set as usize * *msg_id as usize) % plane_size) * CATALOG_SLOT_WORDS;
            // Walk plane_depth slots forward for collision chain.
            for _ in 0..plane_depth {
                if planes[idx] == 0 && planes[idx + 1] == 0 {
                    planes[idx] = stored_set;
                    planes[idx + 1] = msg_id_u;
                    planes[idx + 2] = offset as u32;
                    break;
                }
                idx += plane_size * CATALOG_SLOT_WORDS;
            }
        }
        // Serialize first plane (parser only reads first plane LE).
        for &w in &planes {
            out.extend_from_slice(&w.to_le_bytes());
        }
        // Second plane (zeros, but the parser walks in-table only).
        out.extend(core::iter::repeat_n(0u8, total_table_bytes));
        // Strings blob (must be non-empty per parse contract).
        if strings.is_empty() {
            strings.push(0);
        }
        out.extend_from_slice(&strings);

        debug_assert!(out.len() >= header_bytes);
        out
    }

    #[test]
    fn parse_minimal_catalog_with_one_message() {
        let bytes = build_catalog(4, 2, &[(0, 1, b"hello")]);
        let cat = parse_catalog_bytes(bytes).unwrap();
        assert_eq!(cat.plane_size, 4);
        assert_eq!(cat.plane_depth, 2);
        assert_eq!(cat.message_bytes(0, 1), Some(&b"hello"[..]));
    }

    #[test]
    fn parse_rejects_invalid_magic() {
        let mut bytes = build_catalog(2, 1, &[(0, 1, b"x")]);
        bytes[0] ^= 0xFF;
        assert_eq!(
            parse_catalog_bytes(bytes),
            Err(CatalogParseError::InvalidMagic)
        );
    }

    #[test]
    fn parse_accepts_be_swapped_magic() {
        // Build a normal catalog, then byte-swap the first 12 header bytes
        // (3 u32s) so all three header words read as big-endian.
        let mut bytes = build_catalog(2, 1, &[(0, 1, b"x")]);
        for chunk in bytes[..12].chunks_exact_mut(4) {
            chunk.reverse();
        }
        let cat = parse_catalog_bytes(bytes).unwrap();
        // Header reads remain consistent (plane_size==2, plane_depth==1)
        // but the table words are still little-endian per glibc.
        assert_eq!(cat.plane_size, 2);
        assert_eq!(cat.plane_depth, 1);
    }

    #[test]
    fn parse_rejects_zero_plane_size() {
        let mut bytes = build_catalog(2, 1, &[(0, 1, b"x")]);
        bytes[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_catalog_bytes(bytes),
            Err(CatalogParseError::ZeroPlane)
        );
    }

    #[test]
    fn parse_rejects_zero_plane_depth() {
        let mut bytes = build_catalog(2, 1, &[(0, 1, b"x")]);
        bytes[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_catalog_bytes(bytes),
            Err(CatalogParseError::ZeroPlane)
        );
    }

    #[test]
    fn parse_rejects_overflow_planes() {
        let mut bytes = build_catalog(2, 1, &[(0, 1, b"x")]);
        bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            parse_catalog_bytes(bytes),
            Err(CatalogParseError::ArithmeticOverflow)
        );
    }

    #[test]
    fn parse_rejects_truncated_table() {
        let bytes = build_catalog(2, 1, &[(0, 1, b"x")]);
        let truncated = bytes[..24].to_vec();
        assert_eq!(
            parse_catalog_bytes(truncated),
            Err(CatalogParseError::TruncatedTable)
        );
    }

    #[test]
    fn parse_rejects_truncated_header() {
        let mut bytes = vec![0u8; 8];
        bytes[..4].copy_from_slice(&CATGETS_MAGIC.to_le_bytes());
        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            parse_catalog_bytes(bytes),
            Err(CatalogParseError::TruncatedHeader)
        );
    }

    #[test]
    fn parse_header_only_returns_truncated_table() {
        let mut bytes = vec![0u8; 12];
        bytes[..4].copy_from_slice(&CATGETS_MAGIC.to_le_bytes());
        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            parse_catalog_bytes(bytes),
            Err(CatalogParseError::TruncatedTable)
        );
    }

    #[test]
    fn lookup_returns_none_for_missing_message() {
        let bytes = build_catalog(4, 2, &[(0, 1, b"hello")]);
        let cat = parse_catalog_bytes(bytes).unwrap();
        assert_eq!(cat.message_bytes(0, 99), None);
        assert_eq!(cat.message_bytes(5, 1), None);
    }

    #[test]
    fn lookup_returns_none_for_negative_msg_id() {
        let bytes = build_catalog(4, 2, &[(0, 1, b"hello")]);
        let cat = parse_catalog_bytes(bytes).unwrap();
        assert_eq!(cat.message_bytes(0, -1), None);
    }

    #[test]
    fn lookup_handles_collision_chain_via_plane_depth() {
        // Two messages whose hash slots collide; second gets placed in
        // the next plane_depth slot. Lookup should walk past the first.
        // With plane_size=2 and msg_ids 1 and 3 + set_id 0 (stored 1):
        //   slot(set=1, msg=1) = 1*1 % 2 = 1
        //   slot(set=1, msg=3) = 1*3 % 2 = 1   (collision)
        let bytes = build_catalog(2, 2, &[(0, 1, b"first"), (0, 3, b"third")]);
        let cat = parse_catalog_bytes(bytes).unwrap();
        assert_eq!(cat.message_bytes(0, 1), Some(&b"first"[..]));
        assert_eq!(cat.message_bytes(0, 3), Some(&b"third"[..]));
    }

    #[test]
    fn message_offset_returns_blob_index() {
        // message_offset is the strings-blob byte index, useful for
        // FFI callers that need to compute a pointer.
        let bytes = build_catalog(4, 2, &[(0, 1, b"hi")]);
        let cat = parse_catalog_bytes(bytes).unwrap();
        let off = cat.message_offset(0, 1).unwrap();
        assert!(off < cat.strings.len());
        // The strings blob should contain "hi\0" starting at off.
        assert_eq!(&cat.strings[off..off + 3], b"hi\0");
    }

    #[test]
    fn message_bytes_excludes_nul_terminator() {
        let bytes = build_catalog(4, 2, &[(0, 1, b"x"), (0, 2, b"longer message")]);
        let cat = parse_catalog_bytes(bytes).unwrap();
        let body = cat.message_bytes(0, 2).unwrap();
        assert_eq!(body, b"longer message");
        assert!(!body.contains(&0));
    }

    #[test]
    fn parse_rejects_table_offset_past_strings_blob() {
        let mut bytes = build_catalog(2, 1, &[(0, 1, b"x")]);
        // Point one slot's offset past the strings blob length.
        // The first plane lives right after the header (12-byte header).
        // Slot for set=1, msg=1 is at hash idx 1 = plane offset 1*3 = 3 words = 12 bytes
        // into the plane, plus 12-byte header = 24..36.  Offset is the third word of
        // that slot at byte 24+8 = 32..36.
        let bad_offset: u32 = 0xDEAD_BEEF;
        bytes[32..36].copy_from_slice(&bad_offset.to_le_bytes());
        assert_eq!(
            parse_catalog_bytes(bytes),
            Err(CatalogParseError::MissingNul)
        );
    }
}
