#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc group_member oracle + raw memory ABI

//! Differential coverage for `group_member` and `wmempcpy` (bd-ii5lvv).
//!
//! Both are GNU `<string.h>`/`<unistd.h>` extensions that had zero direct test
//! coverage. `group_member(gid)` returns non-zero iff the calling process is a
//! member of `gid` (its effective gid or any supplementary group); fl reads the
//! real group set via getgroups (it previously had a hard-coded 64-group cap
//! that silently truncated membership). `wmempcpy` copies `n` wide chars and
//! returns `dest + n` — the mempcpy-family end-pointer contract. These gates
//! pin both against the host glibc / their exact contract.

use std::ffi::c_int;

unsafe extern "C" {
    // Bind the host glibc symbols directly (GNU extensions, not in the libc crate).
    fn group_member(gid: libc::gid_t) -> c_int;
    fn wmempcpy(dest: *mut libc::wchar_t, src: *const libc::wchar_t, n: libc::size_t)
    -> *mut libc::wchar_t;
}

fn fl_group_member(gid: libc::gid_t) -> c_int {
    unsafe { frankenlibc_abi::glibc_internal_abi::group_member(gid as u32) }
}

/// glibc returns non-zero (not necessarily 1) for membership; compare as bools.
fn agrees(gid: libc::gid_t) -> bool {
    let g = unsafe { group_member(gid) } != 0;
    let f = fl_group_member(gid) != 0;
    g == f
}

#[test]
fn group_member_matches_glibc_for_real_group_set() {
    // Effective gid: must be a member.
    let egid = unsafe { libc::getegid() };
    assert_eq!(fl_group_member(egid) != 0, true, "egid must be a member");
    assert!(agrees(egid), "egid membership disagrees with glibc");

    // Every supplementary group the process actually belongs to.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    assert!(n >= 0, "getgroups count failed");
    let mut groups = vec![0 as libc::gid_t; n as usize];
    let got = unsafe { libc::getgroups(n, groups.as_mut_ptr()) };
    assert!(got >= 0, "getgroups fill failed");
    groups.truncate(got as usize);
    for &g in &groups {
        assert!(
            fl_group_member(g) != 0,
            "member gid {g} reported as non-member by fl"
        );
        assert!(agrees(g), "member gid {g} disagrees with glibc");
    }

    // A spread of gids the process is (almost certainly) NOT a member of,
    // including boundary values. Whatever glibc reports, fl must match.
    let members: std::collections::HashSet<libc::gid_t> =
        groups.iter().copied().chain(std::iter::once(egid)).collect();
    for cand in [0u32, 1, 2, 12345, 65533, 65534, 99999, 0x7fff_ffff, 0xffff_ffff] {
        if members.contains(&cand) {
            continue;
        }
        assert!(agrees(cand), "non-member gid {cand} disagrees with glibc");
    }
}

#[test]
fn wmempcpy_copies_and_returns_end_pointer() {
    let src: Vec<libc::wchar_t> = (0..16).map(|i| (1000 + i) as libc::wchar_t).collect();
    let mut dst = vec![0 as libc::wchar_t; 16];

    for n in [0usize, 1, 5, 16] {
        dst.iter_mut().for_each(|w| *w = -1);
        let ret = unsafe { wmempcpy(dst.as_mut_ptr(), src.as_ptr(), n) };
        // Return value is exactly dest + n (the mempcpy-family contract).
        assert_eq!(
            ret,
            unsafe { dst.as_mut_ptr().add(n) },
            "wmempcpy(n={n}) must return dest+n"
        );
        // The first n wide chars are copied; the rest untouched.
        assert_eq!(&dst[..n], &src[..n], "wmempcpy(n={n}) content mismatch");
        assert!(
            dst[n..].iter().all(|&w| w == -1),
            "wmempcpy(n={n}) overwrote past n"
        );
    }
}
