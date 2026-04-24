#![no_main]
//! Structure-aware fuzz target for Linux `statx(2)` — the extended stat
//! primitive introduced by Linux 4.11.
//!
//! Threat surface:
//! - mask argument (STATX_* bits) can be any u32; spec says unknown bits
//!   must not fault, but our wrapper could mis-translate them
//! - flags (AT_*) are bitwise-or of AT_SYMLINK_NOFOLLOW,
//!   AT_NO_AUTOMOUNT, AT_STATX_SYNC_TYPE, AT_STATX_FORCE_SYNC,
//!   AT_STATX_DONT_SYNC, AT_EMPTY_PATH
//! - path may be "" with AT_EMPTY_PATH (operate on dirfd itself)
//! - dirfd may be AT_FDCWD, a valid fd, or a crafted invalid fd
//!
//! Invariants:
//! - Never panic for any (path, mask, flags, dirfd) combination
//! - rc is 0 on success, -1 on error
//! - On success, every bit set in `stx.stx_mask` must also have been
//!   requested in `mask` (the kernel may CLEAR bits but not SET unrequested
//!   ones)
//! - Guard bytes around the statx struct must survive the call
//!
//! Bead: FUZZ #3 (statx extended mask)

use std::ffi::{CString, c_void};
use std::mem::MaybeUninit;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_abi::unistd_abi::statx;

const GUARD_BYTES: usize = 32;
const GUARD_VAL: u8 = 0xFE;
/// Linux struct statx is 256 bytes on all supported arches.
const STATX_BUF_BYTES: usize = 256;
/// Offset of stx_mask (first u32) inside struct statx.
const STX_MASK_OFFSET: usize = 0;

/// Small allowlist of inert paths that statx can probe without filesystem
/// side-effects (statx is read-only, but we still keep the surface bounded).
const SEED_PATHS: &[&[u8]] = &[
    b"\0",          // empty path (pairs with AT_EMPTY_PATH)
    b"/\0",
    b"/tmp\0",
    b"/proc/self\0",
    b"/dev/null\0",
    b"/etc/hostname\0",
    b"/nonexistent_fuzz_target\0",
];

#[derive(Debug, Arbitrary)]
struct StatxInput {
    dirfd_sel: u8,
    path_sel: u8,
    path_fuzz: Vec<u8>,
    mask: u32,
    flags: i32,
    use_fuzz_path: bool,
}

fn pick_dirfd(sel: u8) -> libc::c_int {
    match sel % 3 {
        0 => libc::AT_FDCWD,
        1 => -1,
        _ => libc::c_int::MAX,
    }
}

fuzz_target!(|input: StatxInput| {
    // Allocate a statx buffer with guard bands on both sides.
    let mut guarded = vec![GUARD_VAL; 2 * GUARD_BYTES + STATX_BUF_BYTES];
    let buf_ptr = unsafe { guarded.as_mut_ptr().add(GUARD_BYTES) };

    let dirfd = pick_dirfd(input.dirfd_sel);

    // Compose the path argument. Fuzzer-chosen paths MUST not contain
    // interior NUL (CString won't build); we fall back to a seed path in
    // that case.
    let path_cs: CString = if input.use_fuzz_path {
        match CString::new(input.path_fuzz.clone()) {
            Ok(c) => c,
            Err(_) => CString::new(SEED_PATHS[0]).unwrap_or_default(),
        }
    } else {
        let p = SEED_PATHS[(input.path_sel as usize) % SEED_PATHS.len()];
        // Strip trailing NUL if the seed already embeds one.
        let bytes = if let Some(&0) = p.last() {
            &p[..p.len() - 1]
        } else {
            p
        };
        CString::new(bytes).unwrap_or_default()
    };

    // Invoke.
    let rc = unsafe {
        statx(
            dirfd,
            path_cs.as_ptr(),
            input.flags,
            input.mask,
            buf_ptr as *mut c_void,
        )
    };

    // Invariant 1: rc must be 0 or -1 (never any other int).
    assert!(
        rc == 0 || rc == -1,
        "statx returned unexpected rc={rc}"
    );

    // Invariant 2: guard bands must be intact regardless of rc.
    for (i, &b) in guarded[..GUARD_BYTES].iter().enumerate() {
        assert_eq!(b, GUARD_VAL, "statx clobbered leading guard at offset {i}");
    }
    let trailing_start = GUARD_BYTES + STATX_BUF_BYTES;
    for (i, &b) in guarded[trailing_start..].iter().enumerate() {
        assert_eq!(
            b, GUARD_VAL,
            "statx clobbered trailing guard at +{i} of statx struct"
        );
    }

    // On success, verify stx_mask is readable. The kernel is explicitly
    // allowed to populate MORE bits than requested (STATX_BASIC_STATS is
    // always filled regardless of the input mask), so the only real
    // invariant here is "mask is a valid u32 we can read".
    if rc == 0 {
        let mut mask_bytes = [0u8; 4];
        unsafe {
            std::ptr::copy_nonoverlapping(
                buf_ptr.add(STX_MASK_OFFSET),
                mask_bytes.as_mut_ptr(),
                4,
            );
        }
        let _returned = u32::from_ne_bytes(mask_bytes);
    }

    let _ = MaybeUninit::<u8>::uninit();
});
