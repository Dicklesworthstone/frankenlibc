#![cfg(target_os = "linux")]

//! Integration tests for `<grp.h>` ABI entrypoints.
//!
//! Tests cover: getgrnam, getgrgid, setgrent, endgrent, getgrent,
//! getgrnam_r, getgrgid_r, getgrent_r.
//!
//! Uses the "root" group (gid=0) which exists on all Linux systems.

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::grp_abi::*;
use frankenlibc_abi::malloc_abi::{free, malloc, malloc_known_remaining_for_tests};
use frankenlibc_abi::unistd_abi::{
    _nss_files_endgrent, _nss_files_getgrent_r, _nss_files_getgrgid_r, _nss_files_getgrnam_r,
    _nss_files_initgroups_dyn, _nss_files_setgrent,
};
use frankenlibc_core::errno;

static SEQ: AtomicU64 = AtomicU64::new(0);
static GROUP_ENV_LOCK: Mutex<()> = Mutex::new(());

fn temp_group_path() -> std::path::PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "frankenlibc-grp-test-{}-{seq}.txt",
        std::process::id()
    ))
}

fn with_group_path(path: &std::path::Path, f: impl FnOnce()) {
    let _guard = GROUP_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: Serialized by GROUP_ENV_LOCK.
    unsafe { std::env::set_var("FRANKENLIBC_GROUP_PATH", path) };
    f();
    // SAFETY: Serialized by GROUP_ENV_LOCK.
    unsafe { std::env::remove_var("FRANKENLIBC_GROUP_PATH") };
}

fn with_group_file(content: &[u8], f: impl FnOnce()) {
    let _guard = GROUP_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = temp_group_path();
    std::fs::write(&path, content).expect("write temp group");
    // SAFETY: Serialized by GROUP_ENV_LOCK.
    unsafe { std::env::set_var("FRANKENLIBC_GROUP_PATH", &path) };
    f();
    // SAFETY: Serialized by GROUP_ENV_LOCK.
    unsafe { std::env::remove_var("FRANKENLIBC_GROUP_PATH") };
    let _ = std::fs::remove_file(&path);
}

fn with_group_lock<T>(f: impl FnOnce() -> T) -> T {
    let _guard = GROUP_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

#[test]
fn nss_files_initgroups_grows_and_preserves_prefix_and_duplicate_gids() {
    with_group_file(
        b"# comment\nmalformed\nbase:x:3100:alice\nstaff:x:3101:alice,alice,bob\nagain:x:3101:alice\nother:x:3102:bob,alice\nnear:x:3103:alicex,bobalice\n",
        || {
            // SAFETY: the array comes from the same allocator used by the
            // provider; all scalar slots and the input string are live.
            unsafe {
                let mut groups = malloc(2 * std::mem::size_of::<libc::gid_t>())
                    .cast::<libc::gid_t>();
                assert!(!groups.is_null());
                *groups = 7777;
                *groups.add(1) = 3101;
                let mut count = 2;
                let mut capacity = 2;
                let mut error = 717;
                *__errno_location() = 718;
                assert_eq!(
                    _nss_files_initgroups_dyn(
                        c"alice".as_ptr(),
                        3100,
                        &mut count,
                        &mut capacity,
                        &mut groups,
                        -1,
                        &mut error,
                    ),
                    1
                );
                assert_eq!((count, capacity, error), (5, 8, 717));
                assert_eq!(*__errno_location(), 718);
                assert_eq!(
                    std::slice::from_raw_parts(groups, count as usize),
                    &[7777, 3101, 3101, 3101, 3102]
                );
                free(groups.cast());
            }
        },
    );
}

#[test]
fn nss_files_initgroups_honors_limits_and_zero_capacity() {
    with_group_file(b"a:x:21:alice\nb:x:22:alice\nc:x:23:alice\n", || {
        // SAFETY: zero-capacity arrays begin as null; the provider allocates
        // them before use, and every resulting allocation is freed below.
        unsafe {
            for (limit, expected) in [
                (-1, &[21, 22, 23][..]),
                (0, &[21, 22, 23][..]),
                (1, &[21][..]),
                (2, &[21, 22][..]),
            ] {
                let mut groups = std::ptr::null_mut();
                let mut count = 0;
                let mut capacity = 0;
                let mut error = 717;
                assert_eq!(
                    _nss_files_initgroups_dyn(
                        c"alice".as_ptr(),
                        0,
                        &mut count,
                        &mut capacity,
                        &mut groups,
                        limit,
                        &mut error,
                    ),
                    1
                );
                assert_eq!(error, 717);
                assert_eq!(
                    std::slice::from_raw_parts(groups, count as usize),
                    expected
                );
                assert!(count <= capacity);
                if limit > 0 {
                    assert!(count <= limit);
                }
                free(groups.cast());
            }
        }
    });
}

#[test]
fn nss_files_initgroups_miss_and_full_limit_preserve_outputs() {
    with_group_file(b"a:x:21:alice\n", || {
        // SAFETY: each no-append case keeps a caller-owned one-element array.
        unsafe {
            for (user, base, limit) in [
                (c"missing", 0, -1),
                (c"alice", 21, -1),
                (c"alice", 0, 1),
            ] {
                let mut groups = malloc(std::mem::size_of::<libc::gid_t>())
                    .cast::<libc::gid_t>();
                assert!(!groups.is_null());
                *groups = 918;
                let original = groups;
                let mut count = 1;
                let mut capacity = 1;
                let mut error = 717;
                *__errno_location() = 718;
                assert_eq!(
                    _nss_files_initgroups_dyn(
                        user.as_ptr(),
                        base,
                        &mut count,
                        &mut capacity,
                        &mut groups,
                        limit,
                        &mut error,
                    ),
                    0
                );
                assert_eq!((count, capacity, error), (1, 1, 717));
                assert_eq!(*__errno_location(), 718);
                assert_eq!(groups, original);
                assert_eq!(*groups, 918);
                free(groups.cast());
            }
        }
    });
}

#[test]
fn nss_files_initgroups_reports_missing_file_without_losing_prefix() {
    let path = temp_group_path();
    assert!(!path.exists());
    with_group_path(&path, || {
        // SAFETY: the fixture path is missing and all output slots are valid.
        unsafe {
            let mut groups = malloc(std::mem::size_of::<libc::gid_t>())
                .cast::<libc::gid_t>();
            assert!(!groups.is_null());
            *groups = 918;
            let original = groups;
            let mut count = 1;
            let mut capacity = 1;
            let mut error = 717;
            assert_eq!(
                _nss_files_initgroups_dyn(
                    c"alice".as_ptr(),
                    0,
                    &mut count,
                    &mut capacity,
                    &mut groups,
                    -1,
                    &mut error,
                ),
                -1
            );
            assert_eq!((count, capacity, error), (1, 1, libc::ENOENT));
            assert_eq!(groups, original);
            assert_eq!(*groups, 918);
            free(groups.cast());
        }
    });
}

#[test]
fn nss_files_initgroups_rejects_invalid_array_state_before_writing() {
    with_group_file(b"a:x:21:alice\n", || {
        // SAFETY: all real storage is valid. Invalid counts and a deliberately
        // overstated tracked capacity must be rejected without dereferencing
        // beyond that storage.
        unsafe {
            let mut groups = malloc(std::mem::size_of::<libc::gid_t>())
                .cast::<libc::gid_t>();
            assert!(!groups.is_null());
            assert_known_short(groups.cast(), 2 * std::mem::size_of::<libc::gid_t>());
            *groups = 918;
            let original = groups;
            for (mut count, mut capacity) in [
                (-1, 1),
                (2, 1),
                (0, -1),
                (0, libc::c_long::MAX),
                (0, 2),
            ] {
                let old_state = (count, capacity);
                let mut error = 717;
                assert_eq!(
                    _nss_files_initgroups_dyn(
                        c"alice".as_ptr(),
                        0,
                        &mut count,
                        &mut capacity,
                        &mut groups,
                        -1,
                        &mut error,
                    ),
                    -1
                );
                assert_eq!(error, libc::EINVAL);
                assert_eq!((count, capacity), old_state);
                assert_eq!(groups, original);
                assert_eq!(*groups, 918);
            }
            let mut count = 0;
            let mut capacity = 1;
            let mut error = 717;
            assert_eq!(
                _nss_files_initgroups_dyn(
                    c"alice".as_ptr(),
                    0,
                    std::ptr::null_mut(),
                    &mut capacity,
                    &mut groups,
                    -1,
                    &mut error,
                ),
                -1
            );
            assert_eq!(error, libc::EINVAL);
            assert_eq!(
                _nss_files_initgroups_dyn(
                    std::ptr::null(),
                    0,
                    &mut count,
                    &mut capacity,
                    &mut groups,
                    -1,
                    &mut error,
                ),
                -1
            );
            assert_eq!(error, libc::EINVAL);
            assert_eq!(*groups, 918);
            free(groups.cast());
        }
    });
}

#[test]
fn nss_files_initgroups_matches_independent_host_provider() {
    type Initgroups = unsafe extern "C" fn(
        *const c_char,
        libc::gid_t,
        *mut libc::c_long,
        *mut libc::c_long,
        *mut *mut libc::gid_t,
        libc::c_long,
        *mut libc::c_int,
    ) -> libc::c_int;
    type Allocate = unsafe extern "C" fn(usize) -> *mut c_void;
    type Release = unsafe extern "C" fn(*mut c_void);

    unsafe fn run(
        provider: Initgroups,
        allocate: Allocate,
        release: Release,
        user: &CStr,
        base: libc::gid_t,
        limit: libc::c_long,
    ) -> (libc::c_int, libc::c_long, libc::c_int, Vec<libc::gid_t>) {
        // SAFETY: allocator/releaser pairs belong to the provider being tested.
        let mut groups = unsafe { allocate(std::mem::size_of::<libc::gid_t>()) }
            .cast::<libc::gid_t>();
        assert!(!groups.is_null());
        let mut count = 1;
        let mut capacity = 1;
        let mut error = 717;
        // SAFETY: every slot is initialized and the array is realloc-compatible.
        let status = unsafe {
            *groups = 918;
            provider(
                user.as_ptr(),
                base,
                &mut count,
                &mut capacity,
                &mut groups,
                limit,
                &mut error,
            )
        };
        assert!(count >= 1 && count <= capacity);
        assert!(!groups.is_null());
        // SAFETY: the successful call retains all count initialized entries.
        let values = unsafe { std::slice::from_raw_parts(groups, count as usize) }.to_vec();
        // SAFETY: use the allocator's paired releaser after copying the result.
        unsafe { release(groups.cast()) };
        (status, count, error, values)
    }

    with_group_path(std::path::Path::new("/etc/group"), || {
        // SAFETY: the helper resolves these exact C prototypes in host libc
        // and rejects a pointer resolving to FrankenLibC's own implementation.
        let host: Initgroups = unsafe {
            dlsym_oracle::host_fn(
                c"_nss_files_initgroups_dyn",
                _nss_files_initgroups_dyn as *const (),
            )
        };
        let host_malloc: Allocate =
            unsafe { dlsym_oracle::host_fn(c"malloc", malloc as *const ()) };
        let host_free: Release =
            unsafe { dlsym_oracle::host_fn(c"free", free as *const ()) };
        let content = std::fs::read("/etc/group").expect("read host group oracle");
        let mut users = std::collections::BTreeSet::new();
        users.insert(b"frankenlibc-nss-no-such-member".to_vec());
        // Select real membership inputs independently of the native parser.
        // The missing-member case is always executed, even on minimal hosts.
        for line in content.split(|&byte| byte == b'\n') {
            if let Some(members) = line.splitn(4, |&byte| byte == b':').nth(3) {
                for member in members.split(|&byte| byte == b',') {
                    if !member.is_empty() && !member.contains(&0) {
                        users.insert(member.to_vec());
                    }
                }
            }
        }
        let mut comparisons = 0;
        let mut positive_host_cases = 0;
        for user in users {
            let user = CString::new(user).unwrap();
            for base in [0, libc::gid_t::MAX] {
                for limit in [-1, 0, 1, 2] {
                    // SAFETY: both providers get equivalent independent arrays.
                    let expected = unsafe {
                        run(host, host_malloc, host_free, &user, base, limit)
                    };
                    let actual = unsafe {
                        run(_nss_files_initgroups_dyn, malloc, free, &user, base, limit)
                    };
                    assert_eq!(actual, expected, "user={user:?} base={base} limit={limit}");
                    comparisons += 1;
                    positive_host_cases += usize::from(expected.0 == 1);
                }
            }
        }
        assert!(comparisons >= 8, "the oracle must execute real cases");
        eprintln!(
            "NSS initgroups host comparisons={comparisons} positive_host_cases={positive_host_cases}"
        );
    });
}

#[test]
fn nss_files_group_lookup_packs_members_and_preserves_miss_errnop() {
    with_group_file(b"staff:x:3100:alice,bob\nempty:x:3101:\n", || {
        let mut group: libc::group = unsafe { std::mem::zeroed() };
        let mut buffer = [0u8; 513];
        let mut err = 717;
        // SAFETY: writable caller storage, deliberately using an unaligned
        // byte-buffer base to exercise alignment of the member-pointer array.
        unsafe {
            assert_eq!(
                _nss_files_getgrnam_r(
                    c"staff".as_ptr(),
                    (&raw mut group).cast(),
                    buffer.as_mut_ptr().add(1).cast(),
                    buffer.len() - 1,
                    &mut err,
                ),
                1
            );
            assert_eq!(err, 717);
            assert_eq!(group.gr_gid, 3100);
            assert_eq!(CStr::from_ptr(group.gr_name).to_bytes(), b"staff");
            assert_eq!(CStr::from_ptr(*group.gr_mem).to_bytes(), b"alice");
            assert_eq!(CStr::from_ptr(*group.gr_mem.add(1)).to_bytes(), b"bob");
            assert!((*group.gr_mem.add(2)).is_null());
            assert_eq!(
                (group.gr_mem as usize) % std::mem::align_of::<*mut c_char>(),
                0
            );
            assert_eq!(
                _nss_files_getgrgid_r(
                    3101,
                    (&raw mut group).cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut err,
                ),
                1
            );
            assert_eq!(err, 717);
            assert_eq!(CStr::from_ptr(group.gr_name).to_bytes(), b"empty");
            assert!((*group.gr_mem).is_null());
            assert_eq!(
                _nss_files_getgrnam_r(
                    c"absent".as_ptr(),
                    (&raw mut group).cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut err,
                ),
                0
            );
            assert_eq!(err, 717);
            buffer.fill(0xa5);
            assert_eq!(
                _nss_files_getgrgid_r(
                    9999,
                    (&raw mut group).cast(),
                    buffer.as_mut_ptr().cast(),
                    1,
                    &mut err,
                ),
                -2
            );
            assert_eq!(err, libc::ERANGE);
            assert!(buffer.iter().all(|&byte| byte == 0xa5));
            _nss_files_endgrent();
        }
    });
}

#[test]
fn nss_files_group_erange_errno_tracks_reader_and_member_vector() {
    with_group_file(b"root:x:0:\n", || {
        let mut group: libc::group = unsafe { std::mem::zeroed() };
        let mut words = [0usize; 32];
        let pointer_size = std::mem::size_of::<*mut c_char>();
        // SAFETY: the aligned allocation has ample space for every tested
        // offset; all result and error slots remain live throughout the call.
        unsafe {
            for offset in 0..pointer_size {
                let buffer = words.as_mut_ptr().cast::<c_char>().add(offset);
                // GNU reserves two member pointers after the raw line's NUL.
                let required =
                    (11 + offset).next_multiple_of(pointer_size) - offset + 2 * pointer_size;
                for capacity in [0, 1, 2, 11, 12, required - 1, required, 64] {
                    for kind in 0..5 {
                        if kind == 4 {
                            assert_eq!(_nss_files_setgrent(0), 1);
                        }
                        let mut err = 717;
                        *__errno_location() = 718;
                        let status = match kind {
                            0 | 1 => _nss_files_getgrnam_r(
                                if kind == 0 { c"root" } else { c"absent" }.as_ptr(),
                                (&raw mut group).cast(),
                                buffer,
                                capacity,
                                &mut err,
                            ),
                            2 | 3 => _nss_files_getgrgid_r(
                                if kind == 2 { 0 } else { libc::gid_t::MAX },
                                (&raw mut group).cast(),
                                buffer,
                                capacity,
                                &mut err,
                            ),
                            _ => _nss_files_getgrent_r(
                                (&raw mut group).cast(),
                                buffer,
                                capacity,
                                &mut err,
                            ),
                        };
                        let actual_errno = *__errno_location();
                        let expected = if capacity < required {
                            (
                                -2,
                                libc::ERANGE,
                                if capacity < 2 { 718 } else { libc::ERANGE },
                            )
                        } else {
                            (if kind == 1 || kind == 3 { 0 } else { 1 }, 717, 718)
                        };
                        assert_eq!(
                            (status, err, actual_errno),
                            expected,
                            "group kind={kind} capacity={capacity} offset={offset}"
                        );
                    }
                }
            }
            *__errno_location() = 718;
            assert_eq!(
                _nss_files_getgrgid_r(
                    0,
                    (&raw mut group).cast(),
                    words.as_mut_ptr().cast(),
                    1,
                    __errno_location()
                ),
                -2
            );
            assert_eq!(*__errno_location(), libc::ERANGE);
            _nss_files_endgrent();
        }
    });
}

#[test]
fn nss_files_group_enumeration_retries_and_rewinds() {
    with_group_file(
        b"# ignored\nmalformed\nstaff:x:3100:alice,bob\nempty:x:3101:\n",
        || {
            let mut group: libc::group = unsafe { std::mem::zeroed() };
            let mut buffer = [0u8; 512];
            let mut err = 717;
            // SAFETY: result, byte buffer and errno pointers are writable.
            unsafe {
                assert_eq!(_nss_files_setgrent(0), 1);
                assert_eq!(
                    _nss_files_getgrent_r(
                        (&raw mut group).cast(),
                        buffer.as_mut_ptr().cast(),
                        1,
                        &mut err,
                    ),
                    -2
                );
                assert_eq!(err, libc::ERANGE);
                for name in [b"staff".as_slice(), b"empty"] {
                    err = 717;
                    assert_eq!(
                        _nss_files_getgrent_r(
                            (&raw mut group).cast(),
                            buffer.as_mut_ptr().cast(),
                            buffer.len(),
                            &mut err,
                        ),
                        1
                    );
                    assert_eq!(err, 717);
                    assert_eq!(CStr::from_ptr(group.gr_name).to_bytes(), name);
                }
                assert_eq!(
                    _nss_files_getgrent_r(
                        (&raw mut group).cast(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        &mut err,
                    ),
                    0
                );
                assert_eq!(err, 717, "EOF must preserve the caller's errnop");
                assert_eq!(_nss_files_setgrent(1), 1);
                assert_eq!(
                    _nss_files_getgrent_r(
                        (&raw mut group).cast(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        &mut err,
                    ),
                    1
                );
                assert_eq!(CStr::from_ptr(group.gr_name).to_bytes(), b"staff");
                assert_eq!(_nss_files_endgrent(), 1);
            }
        },
    );
}

#[test]
fn nss_files_group_enumeration_preserves_nis_fields_and_scanned_lines() {
    let records = b"+only\n# a long skipped comment exceeding 24 bytes\nu:x:7:\n# tail\n";
    with_group_file(records, || {
        let mut group: libc::group = unsafe { std::mem::zeroed() };
        let mut words = [0usize; 64];
        let buffer = words.as_mut_ptr().cast::<c_char>();
        let mut err = 717;
        // SAFETY: `words` gives a pointer-aligned, live writable byte buffer.
        unsafe {
            assert_eq!(_nss_files_setgrent(0), 1);
            for (capacity, expected) in [(23, -2), (24, 1)] {
                assert_eq!(
                    _nss_files_getgrent_r((&raw mut group).cast(), buffer, capacity, &mut err),
                    expected
                );
            }
            assert_eq!(CStr::from_ptr(group.gr_name).to_bytes(), b"+only");
            assert!(group.gr_passwd.is_null());
            assert!(!group.gr_mem.is_null());
            assert!((*group.gr_mem).is_null());
            for (capacity, expected) in [(24, -2), (512, 1)] {
                assert_eq!(
                    _nss_files_getgrent_r((&raw mut group).cast(), buffer, capacity, &mut err),
                    expected
                );
            }
            assert_eq!(CStr::from_ptr(group.gr_name).to_bytes(), b"u");
            for (capacity, expected) in [(1, -2), (512, 0), (0, -2), (1, -2), (2, -2), (3, 0)] {
                err = 717;
                *__errno_location() = 718;
                assert_eq!(
                    _nss_files_getgrent_r((&raw mut group).cast(), buffer, capacity, &mut err),
                    expected
                );
                assert_eq!(err, if expected == -2 { libc::ERANGE } else { 717 });
                assert_eq!(
                    *__errno_location(),
                    if capacity == 2 { libc::ERANGE } else { 718 }
                );
            }
            _nss_files_endgrent();
        }
    });
}

#[test]
fn nss_files_group_reports_unavailable_backend_separately_from_miss() {
    let path = temp_group_path();
    assert!(!path.exists());
    with_group_path(&path, || {
        let mut group: libc::group = unsafe { std::mem::zeroed() };
        let mut buffer = [0u8; 512];
        let mut err = 717;
        // SAFETY: fixture path is private and all result slots are writable.
        unsafe {
            assert_eq!(_nss_files_setgrent(0), -1);
            assert_eq!(
                _nss_files_getgrnam_r(
                    c"root".as_ptr(),
                    (&raw mut group).cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut err,
                ),
                -1
            );
            assert_eq!(err, libc::ENOENT);
            err = 717;
            assert_eq!(
                _nss_files_getgrent_r(
                    (&raw mut group).cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut err,
                ),
                -1
            );
            assert_eq!(err, libc::ENOENT);
            _nss_files_endgrent();
        }
    });
}

unsafe fn tracked_zeroed_bytes(len: usize) -> *mut c_void {
    assert!(len > 0);
    let raw = unsafe { malloc(len) };
    assert!(!raw.is_null());
    unsafe { std::ptr::write_bytes(raw.cast::<u8>(), 0, len) };
    raw
}

fn assert_known_short(raw: *const c_void, required: usize) {
    let remaining = malloc_known_remaining_for_tests(raw).unwrap_or(usize::MAX);
    assert_ne!(
        remaining,
        usize::MAX,
        "test allocation should be tracked by malloc metadata"
    );
    assert!(
        remaining < required,
        "test allocation should expose {remaining} tracked bytes, less than required {required}"
    );
}

unsafe fn free_tracked(raw: *mut c_void) {
    unsafe { free(raw) };
}

unsafe fn fill_tracked_bytes(raw: *mut c_void, len: usize, value: u8) {
    unsafe { std::ptr::write_bytes(raw.cast::<u8>(), value, len) };
}

unsafe fn assert_tracked_bytes_eq(raw: *const c_void, len: usize, expected: u8) {
    let bytes = unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), len) };
    assert!(
        bytes.iter().all(|&byte| byte == expected),
        "tracked bytes should remain untouched"
    );
}

// ===========================================================================
// getgrnam / getgrgid
// ===========================================================================

#[test]
fn getgrnam_root() {
    with_group_lock(|| {
        let name = CString::new("root").unwrap();
        let grp = unsafe { getgrnam(name.as_ptr()) };
        assert!(!grp.is_null(), "getgrnam(root) should succeed");
        let gr = unsafe { &*grp };
        assert_eq!(gr.gr_gid, 0, "root group should have gid=0");
        let gr_name = unsafe { CStr::from_ptr(gr.gr_name) };
        assert_eq!(gr_name.to_str().unwrap(), "root");
    });
}

#[test]
fn getgrgid_zero() {
    with_group_lock(|| {
        let grp = unsafe { getgrgid(0) };
        assert!(!grp.is_null(), "getgrgid(0) should succeed");
        let gr = unsafe { &*grp };
        assert_eq!(gr.gr_gid, 0);
        let gr_name = unsafe { CStr::from_ptr(gr.gr_name) };
        assert_eq!(gr_name.to_str().unwrap(), "root");
    });
}

#[test]
fn getgrgid_hot_lookup_reuses_tls_result_and_invalidates_on_reload() {
    with_group_file(b"daemon:x:0:\nroot:x:0:\nusers:x:100:alice\n", || {
        let first = unsafe { getgrgid(0) };
        assert!(!first.is_null());
        let first_name = unsafe { CStr::from_ptr((*first).gr_name) };
        assert_eq!(
            first_name.to_bytes(),
            b"daemon",
            "duplicate gids must preserve first-match semantics"
        );

        let second = unsafe { getgrgid(0) };
        assert_eq!(
            second, first,
            "repeated same-gid lookup should reuse the TLS group result"
        );

        let path = std::env::var_os("FRANKENLIBC_GROUP_PATH").expect("group path should be set");
        std::fs::write(&path, b"root:x:0:\nusers:x:100:alice\nextra:x:101:\n")
            .expect("rewrite temp group");

        let updated = unsafe { getgrgid(0) };
        assert!(!updated.is_null());
        let updated_name = unsafe { CStr::from_ptr((*updated).gr_name) };
        assert_eq!(
            updated_name.to_bytes(),
            b"root",
            "file reload must invalidate the hot gid lookup"
        );
    });
}

#[test]
fn getgrnam_nonexistent() {
    with_group_lock(|| {
        let name = CString::new("nonexistent_group_xyz_99999").unwrap();
        let grp = unsafe { getgrnam(name.as_ptr()) };
        assert!(grp.is_null(), "nonexistent group should return null");
    });
}

#[test]
fn getgrgid_nonexistent() {
    with_group_lock(|| {
        // Use a very high gid unlikely to exist
        let grp = unsafe { getgrgid(99999) };
        assert!(grp.is_null(), "nonexistent gid should return null");
    });
}

#[test]
fn getgrnam_getgrgid_accept_signed_numeric_fields_like_glibc() {
    // Previously asserted that `plus:x:+27:root` was ignored. Measured against
    // live glibc 2.42 with the fixture bind-mounted over /etc/group:
    //     getgrnam("plusgid") -> NON-NULL gid=1001
    // glibc parses the gid with strtoul, which consumes a leading sign, so the
    // row resolves. fl agreed with glibc and the arm failed anyway. The rule
    // this was reaching for applies to the NAME field -- see
    // `getgrnam_skips_nis_compat_prefixed_name_rows`.
    let fixture = b"plus:x:+27:root\nvalid:x:28:root\n";
    with_group_file(fixture, || {
        let plus = CString::new("plus").unwrap();
        let g = unsafe { getgrnam(plus.as_ptr()) };
        assert!(!g.is_null(), "glibc accepts a '+' in the gid field");
        assert_eq!(unsafe { (*g).gr_gid }, 27, "the sign is consumed, not kept");

        let grp = unsafe { getgrgid(28) };
        assert!(
            !grp.is_null(),
            "ordinary unsigned gid row should still match"
        );
        let gr_name = unsafe { CStr::from_ptr((*grp).gr_name) };
        assert_eq!(gr_name.to_bytes(), b"valid");
    });
}

/// glibc's files backend SKIPS a group row whose NAME begins with `+` or `-`.
///
/// Measured against live glibc 2.42 (same probe shape as the passwd side): the
/// entry is unreachable under both the `+name` and bare `name` spellings.
/// NEGATIVE CASE: stripping the sign instead of dropping the row resolves one of
/// the two lookups and fails here.
#[test]
fn getgrnam_skips_nis_compat_prefixed_name_rows() {
    let fixture = b"+nisgrp:x:40:root\n-minusgrp:x:41:root\nvalidg:x:42:root\n";
    with_group_file(fixture, || {
        for name in ["+nisgrp", "nisgrp", "-minusgrp", "minusgrp"] {
            let c = CString::new(name).unwrap();
            assert!(
                unsafe { getgrnam(c.as_ptr()) }.is_null(),
                "glibc's files backend drops NIS-compat rows; {name} must not resolve"
            );
        }
        assert!(
            unsafe { getgrgid(40) }.is_null(),
            "a dropped NIS row must not be reachable by gid either"
        );

        let grp = unsafe { getgrgid(42) };
        assert!(!grp.is_null(), "the ordinary row is still kept");
        let gr_name = unsafe { CStr::from_ptr((*grp).gr_name) };
        assert_eq!(gr_name.to_bytes(), b"validg");
    });
}

#[test]
fn getgrnam_null_returns_null() {
    with_group_lock(|| {
        let grp = unsafe { getgrnam(std::ptr::null()) };
        assert!(grp.is_null());
    });
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn getgrnam_rejects_unterminated_name() {
    with_group_lock(|| unsafe {
        let name = malloc(4).cast::<u8>();
        assert!(!name.is_null());
        std::ptr::copy_nonoverlapping(b"root".as_ptr(), name, 4);
        let grp = getgrnam(name.cast());
        free(name.cast());
        assert!(grp.is_null(), "unterminated getgrnam name should fail");
    });
}

#[test]
fn getgrnam_missing_backend_sets_errno() {
    let missing = temp_group_path();
    with_group_path(&missing, || {
        let name = CString::new("root").unwrap();
        unsafe { *__errno_location() = 0 };
        let grp = unsafe { getgrnam(name.as_ptr()) };
        assert!(grp.is_null());
        assert_eq!(unsafe { *__errno_location() }, errno::ENOENT);
    });
}

// ===========================================================================
// setgrent / getgrent / endgrent
// ===========================================================================

/// All non-reentrant group iteration tests run in a single function
/// because they share thread-local state.
#[test]
fn group_iteration() {
    with_group_lock(|| {
        // --- setgrent + getgrent ---
        unsafe { setgrent() };

        let first = unsafe { getgrent() };
        assert!(!first.is_null(), "first getgrent should return an entry");
        let first_name = unsafe { CStr::from_ptr((*first).gr_name) }
            .to_str()
            .unwrap()
            .to_string();

        // Read a few more
        let mut count = 1;
        loop {
            let ent = unsafe { getgrent() };
            if ent.is_null() {
                break;
            }
            count += 1;
            if count > 100 {
                break; // Safety limit
            }
        }
        assert!(count >= 1, "should enumerate at least 1 group");

        // --- endgrent ---
        unsafe { endgrent() };

        // --- setgrent rewinds ---
        unsafe { setgrent() };
        let rewound = unsafe { getgrent() };
        assert!(!rewound.is_null(), "getgrent after setgrent should work");
        let rewound_name = unsafe { CStr::from_ptr((*rewound).gr_name) }
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(
            first_name, rewound_name,
            "setgrent should rewind to the first entry"
        );

        unsafe { endgrent() };
    });
}

// ===========================================================================
// getgrnam_r / getgrgid_r (reentrant)
// ===========================================================================

#[test]
fn getgrnam_r_root() {
    with_group_lock(|| {
        let name = CString::new("root").unwrap();
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe {
            getgrnam_r(
                name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0, "getgrnam_r(root) should succeed");
        assert!(!result.is_null());
        assert_eq!(grp.gr_gid, 0);
    });
}

#[test]
fn getgrgid_r_zero() {
    with_group_lock(|| {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc =
            unsafe { getgrgid_r(0, &mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
        assert_eq!(rc, 0, "getgrgid_r(0) should succeed");
        assert!(!result.is_null());
        let name = unsafe { CStr::from_ptr(grp.gr_name) };
        assert_eq!(name.to_str().unwrap(), "root");
    });
}

#[test]
fn getgrnam_r_nonexistent() {
    with_group_lock(|| {
        let name = CString::new("nonexistent_grp_abc_777").unwrap();
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe {
            getgrnam_r(
                name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        // Per POSIX: returns 0 and sets result to NULL for not found
        assert_eq!(rc, 0);
        assert!(result.is_null(), "nonexistent group should set result=NULL");
    });
}

#[test]
fn getgrnam_r_small_buffer() {
    with_group_lock(|| {
        let name = CString::new("root").unwrap();
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1]; // Intentionally too small
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe {
            getgrnam_r(
                name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        // Should return ERANGE when buffer is too small
        assert_eq!(rc, libc::ERANGE, "tiny buffer should return ERANGE");
        assert!(result.is_null());
    });
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn getgrnam_r_rejects_tracked_buffer_shorter_than_claimed() {
    with_group_file(GROUP_FIXTURE, || unsafe {
        let name = CString::new("root").unwrap();
        let mut grp: libc::group = std::mem::zeroed();
        let raw = tracked_zeroed_bytes(2);
        assert_known_short(raw, 3);
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = getgrnam_r(
            name.as_ptr(),
            &mut grp,
            raw.cast::<c_char>(),
            1024,
            &mut result,
        );

        assert_eq!(rc, libc::ERANGE);
        assert!(result.is_null());
        free_tracked(raw);
    });
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn getgrgid_r_rejects_tracked_short_result_slot_before_write() {
    with_group_file(GROUP_FIXTURE, || unsafe {
        let mut grp: libc::group = std::mem::zeroed();
        let mut buf = vec![0u8; 1024];
        let raw_len = std::mem::size_of::<*mut libc::group>() - 1;
        let raw = tracked_zeroed_bytes(raw_len);
        fill_tracked_bytes(raw, raw_len, 0xA5);
        assert_known_short(raw, std::mem::size_of::<*mut libc::group>());

        let rc = getgrgid_r(
            0,
            &mut grp,
            buf.as_mut_ptr().cast(),
            buf.len(),
            raw.cast::<*mut libc::group>(),
        );

        assert_eq!(rc, libc::EINVAL);
        assert_tracked_bytes_eq(raw, raw_len, 0xA5);
        free_tracked(raw);
    });
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn getgrgid_r_rejects_tracked_misaligned_result_slot_before_write() {
    with_group_file(GROUP_FIXTURE, || unsafe {
        let mut grp: libc::group = std::mem::zeroed();
        let mut buf = vec![0u8; 1024];
        let raw_len = std::mem::size_of::<*mut libc::group>() + 1;
        let raw = tracked_zeroed_bytes(raw_len);
        fill_tracked_bytes(raw, raw_len, 0xA5);
        let result = raw.cast::<u8>().add(1).cast::<*mut libc::group>();
        assert_ne!(
            (result as usize) % std::mem::align_of::<*mut libc::group>(),
            0
        );

        let rc = getgrgid_r(0, &mut grp, buf.as_mut_ptr().cast(), buf.len(), result);

        assert_eq!(rc, libc::EINVAL);
        assert_tracked_bytes_eq(raw, raw_len, 0xA5);
        free_tracked(raw);
    });
}

#[test]
fn getgrgid_r_clears_result_before_rejecting_tracked_short_group_slot() {
    with_group_file(GROUP_FIXTURE, || unsafe {
        let raw = tracked_zeroed_bytes(std::mem::size_of::<libc::group>() - 1);
        assert_known_short(raw, std::mem::size_of::<libc::group>());
        let mut buf = vec![0u8; 1024];
        let mut result = std::ptr::NonNull::<libc::group>::dangling().as_ptr();

        let rc = getgrgid_r(
            0,
            raw.cast::<libc::group>(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        );

        assert_eq!(rc, libc::EINVAL);
        assert!(result.is_null());
        free_tracked(raw);
    });
}

#[test]
fn getgrgid_r_clears_result_before_rejecting_tracked_misaligned_group_slot() {
    with_group_file(GROUP_FIXTURE, || unsafe {
        let raw = tracked_zeroed_bytes(std::mem::size_of::<libc::group>() + 1);
        let grp = raw.cast::<u8>().add(1).cast::<libc::group>();
        assert_ne!((grp as usize) % std::mem::align_of::<libc::group>(), 0);
        let mut buf = vec![0u8; 1024];
        let mut result = std::ptr::NonNull::<libc::group>::dangling().as_ptr();

        let rc = getgrgid_r(0, grp, buf.as_mut_ptr().cast(), buf.len(), &mut result);

        assert_eq!(rc, libc::EINVAL);
        assert!(result.is_null());
        free_tracked(raw);
    });
}

#[test]
fn getgrnam_r_missing_backend_returns_errno() {
    let missing = temp_group_path();
    with_group_path(&missing, || {
        let name = CString::new("root").unwrap();
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe {
            getgrnam_r(
                name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, libc::ENOENT);
        assert!(result.is_null());
    });
}

// ===========================================================================
// getgrent_r (reentrant iteration)
// ===========================================================================

#[test]
fn getgrent_r_basic() {
    with_group_lock(|| {
        unsafe { setgrent() };

        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 4096];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe { getgrent_r(&mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
        assert_eq!(rc, 0, "getgrent_r should succeed");
        assert!(!result.is_null());

        let name = unsafe { CStr::from_ptr(grp.gr_name) };
        assert!(
            !name.to_str().unwrap().is_empty(),
            "group name should not be empty"
        );

        unsafe { endgrent() };
    });
}

#[test]
fn getgrent_r_erange_does_not_advance_cursor() {
    with_group_file(GROUP_FIXTURE, || {
        unsafe { setgrent() };

        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut tiny = [0u8; 1];
        let mut result: *mut libc::group = std::ptr::null_mut();
        let rc = unsafe { getgrent_r(&mut grp, tiny.as_mut_ptr().cast(), tiny.len(), &mut result) };
        assert_eq!(rc, libc::ERANGE);
        assert!(result.is_null());

        let mut retry_buf = vec![0u8; 1024];
        let rc = unsafe {
            getgrent_r(
                &mut grp,
                retry_buf.as_mut_ptr().cast(),
                retry_buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0);
        assert!(!result.is_null());
        let name = unsafe { CStr::from_ptr(grp.gr_name) };
        assert_eq!(name.to_bytes(), b"root");

        unsafe { endgrent() };
    });
}

#[test]
fn getgrnam_r_aligns_member_pointer_array_for_misaligned_buffer() {
    with_group_file(GROUP_FIXTURE, || unsafe {
        let name = CString::new("root").unwrap();
        let mut grp: libc::group = std::mem::zeroed();
        let raw = tracked_zeroed_bytes(1025);
        let misaligned = raw.cast::<u8>().add(1).cast::<c_char>();
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = getgrnam_r(name.as_ptr(), &mut grp, misaligned, 1024, &mut result);

        assert_eq!(rc, 0);
        assert!(!result.is_null());
        assert_eq!(
            (grp.gr_mem as usize) % std::mem::align_of::<*mut c_char>(),
            0
        );
        let first_member = *grp.gr_mem;
        assert!(!first_member.is_null());
        assert_eq!(CStr::from_ptr(first_member).to_bytes(), b"root");
        free_tracked(raw);
    });
}

#[test]
fn getgrent_r_iterates_all() {
    with_group_lock(|| {
        unsafe { setgrent() };

        let mut count = 0;
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 4096];
        let mut result: *mut libc::group = std::ptr::null_mut();

        loop {
            let rc =
                unsafe { getgrent_r(&mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
            if rc != 0 || result.is_null() {
                break;
            }
            count += 1;
            if count > 200 {
                break; // Safety limit
            }
        }
        assert!(
            count >= 1,
            "should enumerate at least 1 group via getgrent_r"
        );

        unsafe { endgrent() };
    });
}

// ===========================================================================
// Additional getgrnam / getgrgid edge cases
// ===========================================================================

#[test]
fn getgrnam_empty_string() {
    with_group_lock(|| {
        let name = CString::new("").unwrap();
        let grp = unsafe { getgrnam(name.as_ptr()) };
        assert!(grp.is_null(), "empty group name should return null");
    });
}

#[test]
fn getgrgid_root_has_passwd_field() {
    with_group_lock(|| {
        let grp = unsafe { getgrgid(0) };
        if !grp.is_null() {
            let gr = unsafe { &*grp };
            // gr_passwd should be a valid pointer (may be empty string or "x")
            assert!(!gr.gr_passwd.is_null(), "gr_passwd should not be null");
        }
    });
}

#[test]
fn getgrgid_root_has_members_field() {
    with_group_lock(|| {
        let grp = unsafe { getgrgid(0) };
        if !grp.is_null() {
            let gr = unsafe { &*grp };
            // gr_mem should be a valid pointer (possibly pointing to NULL terminator)
            assert!(!gr.gr_mem.is_null(), "gr_mem should not be null");
        }
    });
}

#[test]
fn getgrnam_r_null_name_returns_not_found() {
    with_group_lock(|| {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe {
            getgrnam_r(
                std::ptr::null(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        // Should handle null name gracefully
        assert!(result.is_null() || rc != 0);
    });
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn getgrnam_r_rejects_unterminated_name() {
    with_group_lock(|| unsafe {
        let name = malloc(4).cast::<u8>();
        assert!(!name.is_null());
        std::ptr::copy_nonoverlapping(b"root".as_ptr(), name, 4);
        let mut grp: libc::group = std::mem::zeroed();
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = getgrnam_r(
            name.cast(),
            &mut grp,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        );
        free(name.cast());
        assert_eq!(rc, libc::EINVAL);
        assert!(result.is_null());
    });
}

#[test]
fn getgrgid_r_nonexistent() {
    with_group_lock(|| {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe {
            getgrgid_r(
                99999,
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0);
        assert!(result.is_null(), "nonexistent gid should set result=NULL");
    });
}

#[test]
fn getgrgid_r_small_buffer() {
    with_group_lock(|| {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1]; // Intentionally too small
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc =
            unsafe { getgrgid_r(0, &mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
        assert_eq!(rc, libc::ERANGE, "tiny buffer should return ERANGE");
        assert!(result.is_null());
    });
}

// ===========================================================================
// Consistency checks
// ===========================================================================

#[test]
fn getgrnam_getgrgid_consistent() {
    with_group_lock(|| {
        // Look up "root" by name, then by its gid, verify they match
        let name = CString::new("root").unwrap();
        let by_name = unsafe { getgrnam(name.as_ptr()) };
        if by_name.is_null() {
            return; // Skip if root group not available
        }
        let gid = unsafe { (*by_name).gr_gid };

        let by_gid = unsafe { getgrgid(gid) };
        assert!(!by_gid.is_null());

        let name1 = unsafe { CStr::from_ptr((*by_name).gr_name) }
            .to_str()
            .unwrap();
        let name2 = unsafe { CStr::from_ptr((*by_gid).gr_name) }
            .to_str()
            .unwrap();
        assert_eq!(name1, name2, "name lookup and gid lookup should agree");
    });
}

#[test]
fn non_reentrant_group_storage_is_thread_local() {
    with_group_file(GROUP_FIXTURE, || {
        unsafe { endgrent() };
        let name = CString::new("root").unwrap();
        let main_entry = unsafe { getgrnam(name.as_ptr()) };
        assert!(
            !main_entry.is_null(),
            "main thread getgrnam(root) should succeed"
        );
        let main_ptr = main_entry as usize;

        let worker_ptr = std::thread::spawn(|| {
            let name = CString::new("users").unwrap();
            let entry = unsafe { getgrnam(name.as_ptr()) };
            assert!(
                !entry.is_null(),
                "worker thread getgrnam(users) should succeed"
            );
            let group = unsafe { &*entry };
            let name = unsafe { CStr::from_ptr(group.gr_name) };
            assert_eq!(name.to_bytes(), b"users");
            entry as usize
        })
        .join()
        .expect("worker thread should complete");

        assert_ne!(
            main_ptr, worker_ptr,
            "non-reentrant group storage must be isolated per thread"
        );
        let main_after = unsafe { &*main_entry };
        let main_name = unsafe { CStr::from_ptr(main_after.gr_name) };
        assert_eq!(
            main_name.to_bytes(),
            b"root",
            "worker lookup must not overwrite main thread group storage"
        );

        unsafe { endgrent() };
    });
}

#[test]
fn getgrnam_r_getgrgid_r_consistent() {
    with_group_lock(|| {
        let name_str = CString::new("root").unwrap();

        let mut grp1: libc::group = unsafe { std::mem::zeroed() };
        let mut buf1 = vec![0u8; 4096];
        let mut result1: *mut libc::group = std::ptr::null_mut();
        let rc1 = unsafe {
            getgrnam_r(
                name_str.as_ptr(),
                &mut grp1,
                buf1.as_mut_ptr().cast(),
                buf1.len(),
                &mut result1,
            )
        };
        if rc1 != 0 || result1.is_null() {
            return; // Skip
        }

        let gid = grp1.gr_gid;

        let mut grp2: libc::group = unsafe { std::mem::zeroed() };
        let mut buf2 = vec![0u8; 4096];
        let mut result2: *mut libc::group = std::ptr::null_mut();
        let rc2 = unsafe {
            getgrgid_r(
                gid,
                &mut grp2,
                buf2.as_mut_ptr().cast(),
                buf2.len(),
                &mut result2,
            )
        };
        assert_eq!(rc2, 0);
        assert!(!result2.is_null());
        assert_eq!(grp1.gr_gid, grp2.gr_gid);
    });
}

// ===========================================================================
// Double setgrent/endgrent
// ===========================================================================

#[test]
fn double_setgrent_safe() {
    with_group_lock(|| unsafe {
        setgrent();
        setgrent(); // Double call should not crash
        endgrent();
    });
}

#[test]
fn double_endgrent_safe() {
    with_group_lock(|| unsafe {
        setgrent();
        endgrent();
        endgrent(); // Double call should not crash
    });
}

#[test]
fn endgrent_without_setgrent() {
    with_group_lock(|| {
        // Should not crash
        unsafe { endgrent() };
    });
}

// ===========================================================================
// Iteration count consistency
// ===========================================================================

#[test]
fn group_iteration_count_consistent() {
    with_group_lock(|| {
        // Two iterations should produce the same count
        unsafe { setgrent() };
        let mut count1 = 0;
        loop {
            let ent = unsafe { getgrent() };
            if ent.is_null() {
                break;
            }
            count1 += 1;
            if count1 > 500 {
                break;
            }
        }
        unsafe { endgrent() };

        unsafe { setgrent() };
        let mut count2 = 0;
        loop {
            let ent = unsafe { getgrent() };
            if ent.is_null() {
                break;
            }
            count2 += 1;
            if count2 > 500 {
                break;
            }
        }
        unsafe { endgrent() };

        assert_eq!(
            count1, count2,
            "two iterations should produce the same count"
        );
    });
}

// ===========================================================================
// Reentrant lookups from multiple threads
// ===========================================================================

#[test]
fn getgrnam_r_concurrent_lookups() {
    with_group_lock(|| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    let name = std::ffi::CString::new("root").unwrap();
                    let mut grp: libc::group = unsafe { std::mem::zeroed() };
                    let mut buf = vec![0u8; 4096];
                    let mut result: *mut libc::group = std::ptr::null_mut();

                    let rc = unsafe {
                        getgrnam_r(
                            name.as_ptr(),
                            &mut grp,
                            buf.as_mut_ptr().cast(),
                            buf.len(),
                            &mut result,
                        )
                    };
                    assert_eq!(rc, 0);
                    assert!(!result.is_null());
                    assert_eq!(grp.gr_gid, 0);
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    });
}

#[test]
fn getgrgid_r_concurrent_lookups() {
    with_group_lock(|| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    let mut grp: libc::group = unsafe { std::mem::zeroed() };
                    let mut buf = vec![0u8; 4096];
                    let mut result: *mut libc::group = std::ptr::null_mut();

                    let rc = unsafe {
                        getgrgid_r(0, &mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut result)
                    };
                    assert_eq!(rc, 0);
                    assert!(!result.is_null());
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    });
}

// ===========================================================================
// getgrnam_r with adequately large buffer
// ===========================================================================

#[test]
fn getgrnam_r_large_buffer() {
    with_group_lock(|| {
        let name = CString::new("root").unwrap();
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 65536]; // 64KB — plenty
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe {
            getgrnam_r(
                name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0);
        assert!(!result.is_null());
        assert_eq!(grp.gr_gid, 0);
    });
}

// ===========================================================================
// Strict/Hardened Mode Tests (bd-x2sq)
// ===========================================================================

/// Static mutex for mode env var manipulation (process-global).
static MODE_ENV_LOCK: Mutex<()> = Mutex::new(());

/// Test fixture for group entries (group_name:password:gid:members).
const GROUP_FIXTURE: &[u8] = b"root:x:0:root\nusers:x:100:alice,bob\nadmins:x:999:alice\n";

fn with_mode(mode: &str, f: impl FnOnce()) {
    let _guard = MODE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: Serialized by MODE_ENV_LOCK.
    unsafe { std::env::set_var("FRANKENLIBC_MODE", mode) };
    f();
    // SAFETY: Same as above.
    unsafe { std::env::remove_var("FRANKENLIBC_MODE") };
}

fn with_mode_and_group(mode: &str, group_content: &[u8], f: impl FnOnce()) {
    let _mode_guard = MODE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _group_guard = GROUP_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let path = temp_group_path();
    std::fs::write(&path, group_content).expect("write temp group");

    // SAFETY: Serialized by both locks.
    unsafe {
        std::env::set_var("FRANKENLIBC_MODE", mode);
        std::env::set_var("FRANKENLIBC_GROUP_PATH", &path);
    }
    f();
    // SAFETY: Same as above.
    unsafe {
        std::env::remove_var("FRANKENLIBC_MODE");
        std::env::remove_var("FRANKENLIBC_GROUP_PATH");
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn strict_mode_getgrnam_returns_null_for_invalid() {
    with_mode_and_group("strict", GROUP_FIXTURE, || {
        let name = CString::new("nonexistent_group_strict_test").unwrap();
        let grp = unsafe { getgrnam(name.as_ptr()) };
        assert!(
            grp.is_null(),
            "strict mode: getgrnam for nonexistent group should return null"
        );
    });
}

#[test]
fn strict_mode_getgrgid_returns_null_for_invalid_gid() {
    with_mode_and_group("strict", GROUP_FIXTURE, || {
        let grp = unsafe { getgrgid(99999) };
        assert!(
            grp.is_null(),
            "strict mode: getgrgid for nonexistent gid should return null"
        );
    });
}

#[test]
fn hardened_mode_getgrnam_returns_null_for_invalid() {
    with_mode_and_group("hardened", GROUP_FIXTURE, || {
        let name = CString::new("nonexistent_group_hardened_test").unwrap();
        let grp = unsafe { getgrnam(name.as_ptr()) };
        // In hardened mode, invalid lookups still return null (no healing for missing entries).
        assert!(
            grp.is_null(),
            "hardened mode: getgrnam for nonexistent group should return null"
        );
    });
}

#[test]
fn hardened_mode_getgrgid_returns_null_for_invalid_gid() {
    with_mode_and_group("hardened", GROUP_FIXTURE, || {
        let grp = unsafe { getgrgid(99999) };
        // In hardened mode, invalid lookups still return null.
        assert!(
            grp.is_null(),
            "hardened mode: getgrgid for nonexistent gid should return null"
        );
    });
}

#[test]
fn strict_mode_getgrnam_null_input_returns_null() {
    with_mode("strict", || {
        let grp = unsafe { getgrnam(std::ptr::null()) };
        assert!(
            grp.is_null(),
            "strict mode: getgrnam(null) should return null"
        );
    });
}

#[test]
fn hardened_mode_getgrnam_null_input_returns_null() {
    with_mode("hardened", || {
        let grp = unsafe { getgrnam(std::ptr::null()) };
        assert!(
            grp.is_null(),
            "hardened mode: getgrnam(null) should return null"
        );
    });
}

#[test]
fn strict_mode_grent_iteration_works() {
    with_mode_and_group("strict", GROUP_FIXTURE, || {
        unsafe { setgrent() };
        let mut count = 0;
        loop {
            let grp = unsafe { getgrent() };
            if grp.is_null() {
                break;
            }
            count += 1;
            assert!(
                count <= 10,
                "strict mode: grent iteration should not infinite loop"
            );
        }
        unsafe { endgrent() };
        assert_eq!(count, 3, "strict mode: fixture has 3 entries");
    });
}

#[test]
fn hardened_mode_grent_iteration_works() {
    with_mode_and_group("hardened", GROUP_FIXTURE, || {
        unsafe { setgrent() };
        let mut count = 0;
        loop {
            let grp = unsafe { getgrent() };
            if grp.is_null() {
                break;
            }
            count += 1;
            assert!(
                count <= 10,
                "hardened mode: grent iteration should not infinite loop"
            );
        }
        unsafe { endgrent() };
        assert_eq!(count, 3, "hardened mode: fixture has 3 entries");
    });
}

// ---------------------------------------------------------------------------
// gid_from_group / group_from_gid (BSD libutil pwcache)
// ---------------------------------------------------------------------------

#[test]
fn gid_from_group_resolves_known_name() {
    with_mode_and_group("strict", GROUP_FIXTURE, || {
        let name = CString::new("users").unwrap();
        let mut gid: libc::gid_t = u32::MAX;
        let rc = unsafe { gid_from_group(name.as_ptr(), &mut gid) };
        assert_eq!(rc, 0);
        assert_eq!(gid, 100);
    });
}

#[test]
fn gid_from_group_returns_minus_one_for_unknown() {
    with_mode_and_group("strict", GROUP_FIXTURE, || {
        let name = CString::new("nosuchgroup").unwrap();
        let mut gid: libc::gid_t = 999;
        let rc = unsafe { gid_from_group(name.as_ptr(), &mut gid) };
        assert_eq!(rc, -1);
        assert_eq!(gid, 999, "gid output must be untouched on failure");
    });
}

#[test]
fn gid_from_group_null_name_is_error() {
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { gid_from_group(std::ptr::null(), &mut gid) };
    assert_eq!(rc, -1);
}

#[test]
fn gid_from_group_null_gid_pointer_skips_write() {
    with_mode_and_group("strict", GROUP_FIXTURE, || {
        let name = CString::new("admins").unwrap();
        let rc = unsafe { gid_from_group(name.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(rc, 0, "lookup must still succeed with NULL gid pointer");
    });
}

#[test]
fn group_from_gid_resolves_known_gid() {
    with_mode_and_group("strict", GROUP_FIXTURE, || {
        let p = unsafe { group_from_gid(100, 0) };
        assert!(!p.is_null());
        let bytes = unsafe { CStr::from_ptr(p).to_bytes() };
        assert_eq!(bytes, b"users");
    });
}

#[test]
fn group_from_gid_unknown_returns_null_when_nogroup_zero() {
    with_mode_and_group("strict", GROUP_FIXTURE, || {
        let p = unsafe { group_from_gid(99999, 0) };
        assert!(p.is_null(), "missing gid + nogroup=0 must return NULL");
    });
}

#[test]
fn group_from_gid_unknown_with_nogroup_returns_decimal_string() {
    with_mode_and_group("strict", GROUP_FIXTURE, || {
        let p = unsafe { group_from_gid(424242, 1) };
        assert!(
            !p.is_null(),
            "nogroup=1 must always return a non-NULL pointer"
        );
        let bytes = unsafe { CStr::from_ptr(p).to_bytes() };
        assert_eq!(bytes, b"424242");
    });
}

#[test]
fn group_from_gid_zero_with_nogroup_renders_zero() {
    let no_root: &[u8] = b"users:x:100:alice,bob\nadmins:x:999:alice\n";
    with_mode_and_group("strict", no_root, || {
        let p = unsafe { group_from_gid(0, 1) };
        assert!(!p.is_null());
        let bytes = unsafe { CStr::from_ptr(p).to_bytes() };
        assert_eq!(bytes, b"0");
    });
}

// ---------------------------------------------------------------------------
// bd-xh08pf burn-down: grp_abi's two inline `#[cfg(test)]` tests never compiled.
//
// crates/frankenlibc-abi/src/lib.rs declares the module `#[cfg(not(test))]`, so
// an inline `#[cfg(test)]` block inside it is dead by construction — the two
// cfgs are mutually exclusive and it built in neither configuration. Both tests
// are reconstructed here against the PUBLIC entry points rather than relocated,
// because what they reached for — GrpStorage::new_with_path, cache_metrics(),
// iter_idx, entries_generation — is module-private, and widening the ABI surface
// to make internal counters reachable would be a worse trade than asserting the
// behaviour those counters exist to produce.
//
// What is kept is the OBSERVABLE claim of each: a rebuilt cache reflects the new
// file and restarts iteration, and malformed and comment lines are skipped
// rather than counted as entries. What is dropped is the internal telemetry
// (hit/miss/reload/invalidation counts), which has no public surface and no
// caller-visible consequence beyond the two behaviours asserted here.
// ---------------------------------------------------------------------------

/// Malformed and comment lines are skipped, not surfaced as entries.
///
/// The stranded `grp_rebuild_entries_records_parse_stats_after_invalidation`
/// asserted this through `last_parse_stats`; the caller-visible form is simply
/// that iteration yields only the well-formed entries.
#[test]
fn getgrent_skips_malformed_and_comment_lines() {
    with_group_file(
        b"root:x:0:\nmalformed\n#comment\nusers:x:100:alice,bob\n",
        || {
            // SAFETY: single-threaded under GROUP_ENV_LOCK; the iteration is closed
            // by endgrent below.
            unsafe { setgrent() };
            let mut names = Vec::new();
            loop {
                // SAFETY: iteration continues until getgrent reports NULL.
                let entry = unsafe { getgrent() };
                if entry.is_null() {
                    break;
                }
                // SAFETY: a non-NULL entry points at valid thread-local storage.
                let name = unsafe { CStr::from_ptr((*entry).gr_name) };
                names.push(name.to_bytes().to_vec());
            }
            // SAFETY: closes the iteration opened above.
            unsafe { endgrent() };

            assert_eq!(
                names,
                vec![b"root".to_vec(), b"users".to_vec()],
                "a malformed line and a comment must be skipped, leaving only the two \
             well-formed entries"
            );
        },
    );
}

/// A group file rewritten MID-ITERATION restarts the enumeration.
///
/// The stranded `grp_cache_refresh_tracks_hits_and_reloads` asserted this
/// through `iter_idx == 0` after invalidation. The caller-visible form has to
/// avoid `endgrent`/`setgrent` around the rewrite — those reset the index on
/// their own, so a test that brackets the rewrite with them passes even when
/// invalidation does NOT reset iteration, and proves only that the file was
/// re-read (which `getgrgid_hot_lookup_reuses_tls_result_and_invalidates_on_reload`
/// already covers). Verified by mutation: deleting the `iter_idx = 0` in the
/// invalidation path leaves the bracketed form green and fails this one.
#[test]
fn getgrent_restarts_when_the_group_file_changes_mid_iteration() {
    with_group_file(b"root:x:0:\nusers:x:100:alice\n", || {
        // SAFETY: single-threaded under GROUP_ENV_LOCK.
        unsafe { setgrent() };
        // SAFETY: first entry of the original file.
        let first = unsafe { getgrent() };
        assert!(!first.is_null(), "iteration should yield the first entry");
        // SAFETY: non-NULL entry points at valid thread-local storage.
        let first_name = unsafe { CStr::from_ptr((*first).gr_name) }
            .to_bytes()
            .to_vec();
        assert_eq!(first_name, b"root".to_vec());

        // Rewrite WITHOUT closing the enumeration: the next getgrent must see
        // the invalidation, not resume at the stale index.
        let path = std::env::var_os("FRANKENLIBC_GROUP_PATH").expect("group path should be set");
        std::fs::write(&path, b"wheel:x:10:carol\nusers:x:101:alice,bob\n")
            .expect("rewrite temp group");

        // SAFETY: continues the same enumeration across the rewrite.
        let after = unsafe { getgrent() };
        assert!(
            !after.is_null(),
            "iteration should continue after the rewrite"
        );
        // SAFETY: non-NULL entry.
        let after_name = unsafe { CStr::from_ptr((*after).gr_name) }
            .to_bytes()
            .to_vec();
        // SAFETY: closes the enumeration.
        unsafe { endgrent() };

        assert_eq!(
            after_name,
            b"wheel".to_vec(),
            "a mid-iteration rewrite must restart the enumeration at the new file's \
             first entry, not resume at the old index (which would yield \"users\")"
        );
    });
}
