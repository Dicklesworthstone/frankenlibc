//! BSD `strmode` — render a POSIX mode_t as an `ls -l`-style string.
//!
//! This module owns the byte-level formatting that `strmode(3)` does;
//! the FFI shim in `frankenlibc-abi::string_abi` owns the C ABI
//! (writing 11 bytes + trailing NUL into the caller's buffer).
//!
//! ## Output format (11 bytes)
//!
//! Position 0:  file type
//!     `-` regular   `d` directory   `l` symlink   `c` char device
//!     `b` block     `p` fifo/pipe   `s` socket    `w` whiteout (BSD)
//!     `D` door (Solaris carryover; we recognize but never emit on Linux)
//!     `?` unknown
//!
//! Positions 1–3:  owner permissions
//! Positions 4–6:  group permissions
//! Positions 7–9:  other permissions
//!     `r` / `-`     read
//!     `w` / `-`     write
//!     `x` / `-` plus suid/sgid/sticky overlay:
//!         owner-x:   `s` if setuid+x, `S` if setuid w/o x, `x`/`-` else
//!         group-x:   `s` if setgid+x, `S` if setgid w/o x, `x`/`-` else
//!         other-x:   `t` if sticky+x, `T` if sticky w/o x, `x`/`-` else
//!
//! Position 10: trailing space (matches BSD strmode for ACL/extended-attr
//!              indicator slot — `+` in some implementations, space here
//!              since we don't track ACLs).
//!
//! No NUL terminator. The C wrapper appends one to satisfy the
//! `char buf[12]` convention of `strmode(mode_t mode, char *p)`.
//!
//! ## Constants (POSIX)
//!
//! These follow the POSIX 1003.1 numeric values, which are the same
//! across glibc, musl, and BSD. We hard-code them rather than pulling
//! `libc::*` to keep `frankenlibc-core` libc-free.

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFREG: u32 = 0o100000;
const S_IFIFO: u32 = 0o010000;
const S_IFLNK: u32 = 0o120000;
const S_IFSOCK: u32 = 0o140000;
const S_IFWHT: u32 = 0o160000; // BSD whiteout (rare)

const S_ISUID: u32 = 0o004000;
const S_ISGID: u32 = 0o002000;
const S_ISVTX: u32 = 0o001000; // sticky

const S_IRUSR: u32 = 0o000400;
const S_IWUSR: u32 = 0o000200;
const S_IXUSR: u32 = 0o000100;
const S_IRGRP: u32 = 0o000040;
const S_IWGRP: u32 = 0o000020;
const S_IXGRP: u32 = 0o000010;
const S_IROTH: u32 = 0o000004;
const S_IWOTH: u32 = 0o000002;
const S_IXOTH: u32 = 0o000001;

/// Format `mode` (a POSIX `mode_t`, widened to `u32`) into the 11-byte
/// `ls -l` representation. Returns the bytes; callers (specifically
/// the C ABI shim) are responsible for any trailing NUL.
pub fn strmode_bytes(mode: u32) -> [u8; 11] {
    let mut out = [b'-'; 11];

    // Position 0: file type.
    out[0] = match mode & S_IFMT {
        S_IFDIR => b'd',
        S_IFCHR => b'c',
        S_IFBLK => b'b',
        S_IFREG => b'-',
        S_IFLNK => b'l',
        S_IFSOCK => b's',
        S_IFIFO => b'p',
        S_IFWHT => b'w',
        // 0 (no type bits set) is treated as unknown rather than
        // regular so callers can distinguish a zeroed `mode` from a
        // legitimate regular-file mode.
        0 => b'?',
        _ => b'?',
    };

    // Owner triple.
    out[1] = if mode & S_IRUSR != 0 { b'r' } else { b'-' };
    out[2] = if mode & S_IWUSR != 0 { b'w' } else { b'-' };
    out[3] = match (mode & S_ISUID != 0, mode & S_IXUSR != 0) {
        (true, true) => b's',
        (true, false) => b'S',
        (false, true) => b'x',
        (false, false) => b'-',
    };

    // Group triple.
    out[4] = if mode & S_IRGRP != 0 { b'r' } else { b'-' };
    out[5] = if mode & S_IWGRP != 0 { b'w' } else { b'-' };
    out[6] = match (mode & S_ISGID != 0, mode & S_IXGRP != 0) {
        (true, true) => b's',
        (true, false) => b'S',
        (false, true) => b'x',
        (false, false) => b'-',
    };

    // Other triple.
    out[7] = if mode & S_IROTH != 0 { b'r' } else { b'-' };
    out[8] = if mode & S_IWOTH != 0 { b'w' } else { b'-' };
    out[9] = match (mode & S_ISVTX != 0, mode & S_IXOTH != 0) {
        (true, true) => b't',
        (true, false) => b'T',
        (false, true) => b'x',
        (false, false) => b'-',
    };

    // Position 10: ACL / extended-attribute slot. BSD writes a space
    // when there are no extended attributes; glibc/util-linux emit `+`
    // when an ACL is attached. We have no ACL access from this layer
    // so unconditionally emit a space, matching the BSD default.
    out[10] = b' ';

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(mode: u32) -> String {
        String::from_utf8(strmode_bytes(mode).to_vec()).unwrap()
    }

    // ---- file types ----

    #[test]
    fn regular_file_no_perms() {
        assert_eq!(s(S_IFREG), "----------\u{20}");
    }

    #[test]
    fn directory_full_perms() {
        // 0755 directory: drwxr-xr-x + space.
        let mode = S_IFDIR | 0o755;
        assert_eq!(s(mode), "drwxr-xr-x ");
    }

    #[test]
    fn symlink_perms() {
        let mode = S_IFLNK | 0o777;
        assert_eq!(s(mode), "lrwxrwxrwx ");
    }

    #[test]
    fn char_device() {
        assert_eq!(s(S_IFCHR | 0o600), "crw------- ");
    }

    #[test]
    fn block_device() {
        assert_eq!(s(S_IFBLK | 0o660), "brw-rw---- ");
    }

    #[test]
    fn fifo() {
        assert_eq!(s(S_IFIFO | 0o644), "prw-r--r-- ");
    }

    #[test]
    fn socket() {
        assert_eq!(s(S_IFSOCK | 0o755), "srwxr-xr-x ");
    }

    #[test]
    fn whiteout_bsd() {
        assert_eq!(s(S_IFWHT | 0o644), "wrw-r--r-- ");
    }

    #[test]
    fn zero_mode_is_unknown_type() {
        // Distinguish a zeroed mode from a real regular file: emit `?`.
        assert_eq!(s(0), "?--------- ");
    }

    #[test]
    fn unknown_high_bits_render_question_mark() {
        // S_IFMT bits set to a non-canonical value.
        let mode = 0o030000 | 0o644;
        assert_eq!(s(mode), "?rw-r--r-- ");
    }

    // ---- permission bits ----

    #[test]
    fn rwx_for_all() {
        assert_eq!(s(S_IFREG | 0o777), "-rwxrwxrwx ");
    }

    #[test]
    fn no_perms() {
        assert_eq!(s(S_IFREG), "---------- ");
    }

    #[test]
    fn owner_read_only() {
        assert_eq!(s(S_IFREG | 0o400), "-r-------- ");
    }

    #[test]
    fn owner_write_only() {
        assert_eq!(s(S_IFREG | 0o200), "--w------- ");
    }

    #[test]
    fn owner_exec_only() {
        assert_eq!(s(S_IFREG | 0o100), "---x------ ");
    }

    #[test]
    fn group_perms() {
        assert_eq!(s(S_IFREG | 0o070), "----rwx--- ");
    }

    #[test]
    fn other_perms() {
        assert_eq!(s(S_IFREG | 0o007), "-------rwx ");
    }

    // ---- setuid / setgid / sticky overlays ----

    #[test]
    fn setuid_with_owner_exec_lowercase_s() {
        // 04755 → -rwsr-xr-x
        assert_eq!(s(S_IFREG | 0o4755), "-rwsr-xr-x ");
    }

    #[test]
    fn setuid_without_owner_exec_uppercase_s() {
        // 04644 → -rwSr--r-- (capital S: setuid set, exec not)
        assert_eq!(s(S_IFREG | 0o4644), "-rwSr--r-- ");
    }

    #[test]
    fn setgid_with_group_exec_lowercase_s() {
        // 02755 → -rwxr-sr-x
        assert_eq!(s(S_IFREG | 0o2755), "-rwxr-sr-x ");
    }

    #[test]
    fn setgid_without_group_exec_uppercase_s() {
        // 02644 → -rw-r-Sr--
        assert_eq!(s(S_IFREG | 0o2644), "-rw-r-Sr-- ");
    }

    #[test]
    fn sticky_with_other_exec_lowercase_t() {
        // 01755 → -rwxr-xr-t   (the classic /tmp permissions w/o x for owner)
        // Pick 01777 to match real /tmp.
        let mode = S_IFDIR | 0o1777;
        assert_eq!(s(mode), "drwxrwxrwt ");
    }

    #[test]
    fn sticky_without_other_exec_uppercase_t() {
        // 01644 → -rw-r--r-T (capital T: sticky set, no other-x)
        assert_eq!(s(S_IFREG | 0o1644), "-rw-r--r-T ");
    }

    #[test]
    fn all_three_special_bits_at_once() {
        // 07755 (suid+sgid+sticky, all-x) → -rwsr-sr-t
        assert_eq!(s(S_IFREG | 0o7755), "-rwsr-sr-t ");
    }

    #[test]
    fn all_three_special_bits_no_x() {
        // 07644 (suid+sgid+sticky, no exec at all) → -rwSr-Sr-T
        assert_eq!(s(S_IFREG | 0o7644), "-rwSr-Sr-T ");
    }

    // ---- exhaustive bit-position coverage ----

    #[test]
    fn each_perm_bit_in_isolation() {
        let cases: &[(u32, &str)] = &[
            (S_IRUSR, "-r-------- "),
            (S_IWUSR, "--w------- "),
            (S_IXUSR, "---x------ "),
            (S_IRGRP, "----r----- "),
            (S_IWGRP, "-----w---- "),
            (S_IXGRP, "------x--- "),
            (S_IROTH, "-------r-- "),
            (S_IWOTH, "--------w- "),
            (S_IXOTH, "---------x "),
        ];
        for &(bit, want) in cases {
            assert_eq!(s(S_IFREG | bit), want, "bit {bit:#o}");
        }
    }

    #[test]
    fn output_is_always_11_bytes() {
        // Spot-check across a handful of modes; the type signature
        // already guarantees length=11 but assert that the printable
        // ASCII representation has no surprises.
        for &mode in &[
            0u32,
            S_IFREG | 0o644,
            S_IFDIR | 0o755,
            S_IFLNK | 0o777,
            S_IFREG | 0o7777,
            S_IFCHR,
            S_IFBLK,
            0xffff_ffff,
        ] {
            let bytes = strmode_bytes(mode);
            assert_eq!(bytes.len(), 11);
            // All bytes are printable ASCII (or space).
            for &b in &bytes {
                assert!(
                    b.is_ascii_graphic() || b == b' ',
                    "non-printable byte {b:#x} in strmode({mode:#o})"
                );
            }
        }
    }

    #[test]
    fn trailing_slot_is_space() {
        // Position 10 is the BSD/ACL slot; we always emit a space.
        for &mode in &[0u32, S_IFREG | 0o644, S_IFDIR | 0o7777, 0xffff_ffff] {
            let bytes = strmode_bytes(mode);
            assert_eq!(bytes[10], b' ', "slot 10 must be space for {mode:#o}");
        }
    }
}
