//! Directory entry operations — types and parser.
//!
//! Implements `<dirent.h>` pure-logic helpers. Actual syscall invocations
//! (`opendir`, `readdir`, `closedir`) live in the ABI crate.
//! This module provides the `parse_dirent64` buffer parser.

/// A single directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Inode number.
    pub d_ino: u64,
    /// Offset to the next `linux_dirent64` structure.
    pub d_off: i64,
    /// File type (`DT_REG`, `DT_DIR`, etc.).
    pub d_type: u8,
    /// Entry name (without NUL terminator).
    pub d_name: Vec<u8>,
}

/// Parse a single `linux_dirent64` record from a raw buffer.
///
/// Layout of `linux_dirent64`:
/// ```text
///   offset 0:  d_ino    (u64, 8 bytes)
///   offset 8:  d_off    (i64, 8 bytes)
///   offset 16: d_reclen (u16, 2 bytes)
///   offset 18: d_type   (u8,  1 byte)
///   offset 19: d_name   (NUL-terminated, variable)
/// ```
///
/// Returns `Some((entry, next_offset))` on success, `None` if buffer too small.
pub fn parse_dirent64(buffer: &[u8], offset: usize) -> Option<(DirEntry, usize)> {
    // Minimum header: 8 + 8 + 2 + 1 + 1 = 20 bytes (1 byte name + NUL)
    if offset + 20 > buffer.len() {
        return None;
    }

    let buf = &buffer[offset..];

    let d_ino = u64::from_ne_bytes(buf[0..8].try_into().ok()?);
    let d_off = i64::from_ne_bytes(buf[8..16].try_into().ok()?);
    let d_reclen = u16::from_ne_bytes(buf[16..18].try_into().ok()?) as usize;
    let d_type = buf[18];

    if d_reclen < 20 || offset + d_reclen > buffer.len() {
        return None;
    }

    // d_name starts at byte 19, NUL-terminated within reclen
    let name_area = &buf[19..d_reclen];
    let name_len = name_area
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_area.len());
    let d_name = name_area[..name_len].to_vec();

    Some((
        DirEntry {
            d_ino,
            d_off,
            d_type,
            d_name,
        },
        offset + d_reclen,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dirent64(d_ino: u64, d_off: i64, d_type: u8, name: &[u8]) -> Vec<u8> {
        // d_reclen must be at least 19 + name.len() + 1 (NUL), rounded up to 8
        let min_len = 19 + name.len() + 1;
        let reclen = (min_len + 7) & !7; // align to 8
        let mut buf = vec![0u8; reclen];
        buf[0..8].copy_from_slice(&d_ino.to_ne_bytes());
        buf[8..16].copy_from_slice(&d_off.to_ne_bytes());
        buf[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
        buf[18] = d_type;
        buf[19..19 + name.len()].copy_from_slice(name);
        // NUL already zero-filled
        buf
    }

    #[test]
    fn parse_single_entry() {
        let buf = make_dirent64(12345, 100, 8, b"hello.txt");
        let (entry, next) = parse_dirent64(&buf, 0).unwrap();
        assert_eq!(entry.d_ino, 12345);
        assert_eq!(entry.d_off, 100);
        assert_eq!(entry.d_type, 8);
        assert_eq!(entry.d_name, b"hello.txt");
        assert_eq!(next, buf.len());
    }

    #[test]
    fn parse_two_entries() {
        let e1 = make_dirent64(1, 10, 4, b".");
        let e2 = make_dirent64(2, 20, 4, b"..");
        let mut buf = e1.clone();
        buf.extend_from_slice(&e2);

        let (entry1, off1) = parse_dirent64(&buf, 0).unwrap();
        assert_eq!(entry1.d_ino, 1);
        assert_eq!(entry1.d_off, 10);
        assert_eq!(entry1.d_name, b".");

        let (entry2, off2) = parse_dirent64(&buf, off1).unwrap();
        assert_eq!(entry2.d_ino, 2);
        assert_eq!(entry2.d_off, 20);
        assert_eq!(entry2.d_name, b"..");

        assert!(parse_dirent64(&buf, off2).is_none());
    }

    #[test]
    fn parse_empty_buffer() {
        assert!(parse_dirent64(&[], 0).is_none());
    }

    #[test]
    fn parse_truncated_buffer() {
        // Less than minimum header
        let buf = vec![0u8; 10];
        assert!(parse_dirent64(&buf, 0).is_none());
    }

    #[test]
    fn parse_invalid_reclen() {
        let mut buf = make_dirent64(1, 0, 4, b"test");
        // Set reclen to something larger than buffer
        let bad_reclen = (buf.len() as u16) + 100;
        buf[16..18].copy_from_slice(&bad_reclen.to_ne_bytes());
        assert!(parse_dirent64(&buf, 0).is_none());
    }
}
