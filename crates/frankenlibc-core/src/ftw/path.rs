//! POSIX `<ftw.h>` data types + path helpers.
//!
//! `WalkType` and the bits in `WalkFlags` are bit-compatible with
//! glibc's `<ftw.h>` constants so the abi layer can pass through
//! the user's `c_int` flag word unchanged and translate the
//! resulting `WalkType` to the matching POSIX `FTW_*` integer.

/// Per-entry classification passed to the user's visit callback.
///
/// Numeric values match the POSIX `FTW_*` constants exactly:
///   FTW_F   = 0  regular file
///   FTW_D   = 1  directory (pre-order, default)
///   FTW_DNR = 2  directory we couldn't open / read
///   FTW_NS  = 3  stat() failed
///   FTW_SL  = 4  symbolic link (only when [`WalkFlags::PHYSICAL`])
///   FTW_DP  = 5  directory (post-order, only when [`WalkFlags::DEPTH`])
///   FTW_SLN = 6  dangling symlink (only when [`WalkFlags::PHYSICAL`])
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum WalkType {
    File = 0,
    Dir = 1,
    DirNoRead = 2,
    StatFailed = 3,
    Symlink = 4,
    DirPostOrder = 5,
    DanglingSymlink = 6,
}

impl WalkType {
    /// Underlying integer matching POSIX `FTW_*`.
    pub const fn as_c_int(self) -> i32 {
        self as i32
    }
}

/// Flag bits, matching glibc `<ftw.h>`:
///   FTW_PHYS  = 1   don't follow symlinks
///   FTW_MOUNT = 2   stay on the same filesystem (compare st_dev)
///   FTW_CHDIR = 4   chdir into each directory before recursing
///   FTW_DEPTH = 8   visit a directory after its contents (post-order)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WalkFlags {
    bits: u32,
}

impl WalkFlags {
    pub const NONE: WalkFlags = WalkFlags { bits: 0 };
    pub const PHYSICAL: WalkFlags = WalkFlags { bits: 1 };
    pub const MOUNT: WalkFlags = WalkFlags { bits: 2 };
    pub const CHDIR: WalkFlags = WalkFlags { bits: 4 };
    pub const DEPTH: WalkFlags = WalkFlags { bits: 8 };

    pub const fn from_bits(b: u32) -> Self {
        WalkFlags { bits: b }
    }

    pub const fn bits(self) -> u32 {
        self.bits
    }

    pub const fn contains(self, other: WalkFlags) -> bool {
        (self.bits & other.bits) == other.bits
    }
}

impl core::ops::BitOr for WalkFlags {
    type Output = WalkFlags;
    fn bitor(self, rhs: WalkFlags) -> WalkFlags {
        WalkFlags {
            bits: self.bits | rhs.bits,
        }
    }
}

impl core::ops::BitOrAssign for WalkFlags {
    fn bitor_assign(&mut self, rhs: WalkFlags) {
        self.bits |= rhs.bits;
    }
}

/// Build a child path from a parent and a directory entry name.
///
/// If `parent` ends in `/`, doesn't insert another (avoids `//foo`).
/// If `parent` is empty, the result is just `name`.
///
/// Result is a fresh `Vec<u8>` (no NUL terminator — caller appends if
/// needed for the C ABI).
pub fn build_child_path(parent: &[u8], name: &[u8]) -> Vec<u8> {
    if parent.is_empty() {
        return name.to_vec();
    }
    let needs_slash = !parent.ends_with(b"/");
    let mut out = Vec::with_capacity(parent.len() + 1 + name.len());
    out.extend_from_slice(parent);
    if needs_slash {
        out.push(b'/');
    }
    out.extend_from_slice(name);
    out
}

/// Index in `path` of the basename component (the byte after the last
/// `/`, or 0 if there is none). Mirrors POSIX `FTW.base`.
pub fn base_offset_of(path: &[u8]) -> usize {
    match path.iter().rposition(|&b| b == b'/') {
        Some(i) => i + 1,
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walktype_numeric_layout_matches_posix() {
        assert_eq!(WalkType::File.as_c_int(), 0);
        assert_eq!(WalkType::Dir.as_c_int(), 1);
        assert_eq!(WalkType::DirNoRead.as_c_int(), 2);
        assert_eq!(WalkType::StatFailed.as_c_int(), 3);
        assert_eq!(WalkType::Symlink.as_c_int(), 4);
        assert_eq!(WalkType::DirPostOrder.as_c_int(), 5);
        assert_eq!(WalkType::DanglingSymlink.as_c_int(), 6);
    }

    #[test]
    fn walkflags_bits_match_posix() {
        assert_eq!(WalkFlags::PHYSICAL.bits(), 1);
        assert_eq!(WalkFlags::MOUNT.bits(), 2);
        assert_eq!(WalkFlags::CHDIR.bits(), 4);
        assert_eq!(WalkFlags::DEPTH.bits(), 8);
    }

    #[test]
    fn walkflags_or_combines() {
        let f = WalkFlags::PHYSICAL | WalkFlags::DEPTH;
        assert!(f.contains(WalkFlags::PHYSICAL));
        assert!(f.contains(WalkFlags::DEPTH));
        assert!(!f.contains(WalkFlags::MOUNT));
        assert_eq!(f.bits(), 9);
    }

    #[test]
    fn walkflags_or_assign() {
        let mut f = WalkFlags::PHYSICAL;
        f |= WalkFlags::DEPTH;
        assert!(f.contains(WalkFlags::DEPTH));
    }

    #[test]
    fn walkflags_from_bits_round_trip() {
        let f = WalkFlags::from_bits(0b1011);
        assert!(f.contains(WalkFlags::PHYSICAL));
        assert!(f.contains(WalkFlags::MOUNT));
        assert!(f.contains(WalkFlags::DEPTH));
        assert!(!f.contains(WalkFlags::CHDIR));
    }

    #[test]
    fn build_child_path_simple() {
        assert_eq!(build_child_path(b"/tmp", b"a.txt"), b"/tmp/a.txt");
        assert_eq!(build_child_path(b"foo/bar", b"baz"), b"foo/bar/baz");
    }

    #[test]
    fn build_child_path_parent_with_trailing_slash() {
        // No double-slash
        assert_eq!(build_child_path(b"/tmp/", b"a.txt"), b"/tmp/a.txt");
    }

    #[test]
    fn build_child_path_empty_parent() {
        assert_eq!(build_child_path(b"", b"a.txt"), b"a.txt");
    }

    #[test]
    fn build_child_path_empty_name() {
        // Parent with no name = just parent + '/'
        assert_eq!(build_child_path(b"/tmp", b""), b"/tmp/");
    }

    #[test]
    fn base_offset_simple() {
        assert_eq!(base_offset_of(b"/tmp/a.txt"), 5);
        assert_eq!(base_offset_of(b"a.txt"), 0);
        assert_eq!(base_offset_of(b"/a"), 1);
    }

    #[test]
    fn base_offset_root() {
        // For "/", base is offset 1 (past the slash, empty basename)
        assert_eq!(base_offset_of(b"/"), 1);
    }

    #[test]
    fn base_offset_nested() {
        assert_eq!(base_offset_of(b"a/b/c/d"), 6);
    }

    #[test]
    fn base_offset_trailing_slash() {
        // "foo/" has base just past the trailing slash (empty)
        assert_eq!(base_offset_of(b"foo/"), 4);
    }
}
