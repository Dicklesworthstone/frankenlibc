#![cfg(target_os = "linux")]

//! Integration tests for `<pwd.h>` and shadow password ABI entrypoints.
//!
//! Uses `FRANKENLIBC_PASSWD_PATH` env var to point at test fixture files
//! instead of the real /etc/passwd.

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::malloc_abi::{free, malloc, malloc_known_remaining_for_tests};
use frankenlibc_abi::pwd_abi::{
    endpwent, getpwent, getpwnam, getpwnam_r, getpwuid, getpwuid_r, setpwent,
};
use frankenlibc_abi::unistd_abi::{
    _nss_files_endpwent, _nss_files_endspent, _nss_files_getpwent_r, _nss_files_getpwnam_r,
    _nss_files_getpwuid_r, _nss_files_getspent_r, _nss_files_getspnam_r, _nss_files_setpwent,
    _nss_files_setspent,
};
use frankenlibc_core::errno;

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Mutex to serialize tests that manipulate the FRANKENLIBC_PASSWD_PATH env var,
/// since env var manipulation is process-global and not thread-safe.
static PASSWD_ENV_LOCK: Mutex<()> = Mutex::new(());
static GSHADOW_ENV_LOCK: Mutex<()> = Mutex::new(());
#[cfg(debug_assertions)]
static PASSWORD_LOCK_TEST_LOCK: Mutex<()> = Mutex::new(());

fn temp_passwd_path() -> std::path::PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "frankenlibc-pwd-test-{}-{seq}.txt",
        std::process::id()
    ))
}

fn gshadow_fixture_path() -> std::path::PathBuf {
    let mut root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.join("tests/conformance/fixtures/gshadow_sample.txt")
}

fn missing_gshadow_path() -> std::path::PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "frankenlibc-gshadow-missing-{}-{seq}.txt",
        std::process::id()
    ))
}

fn with_missing_gshadow_file(f: impl FnOnce()) {
    let _guard = GSHADOW_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = missing_gshadow_path();
    assert!(
        !path.exists(),
        "missing gshadow fixture path unexpectedly exists: {}",
        path.display()
    );

    // SAFETY: Serialized by GSHADOW_ENV_LOCK.
    unsafe {
        std::env::set_var("FRANKENLIBC_GSHADOW_PATH", &path);
        frankenlibc_abi::pwd_abi::setsgent();
    }
    f();
    // SAFETY: Same as above.
    unsafe {
        frankenlibc_abi::pwd_abi::endsgent();
        std::env::remove_var("FRANKENLIBC_GSHADOW_PATH");
    }
}

fn with_passwd_file(content: &[u8], f: impl FnOnce()) {
    let _guard = PASSWD_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = temp_passwd_path();
    std::fs::write(&path, content).expect("write temp passwd");
    // SAFETY: Serialized by PASSWD_ENV_LOCK — only one test thread at a time.
    unsafe { std::env::set_var("FRANKENLIBC_PASSWD_PATH", &path) };
    f();
    // SAFETY: Same as above.
    unsafe { std::env::remove_var("FRANKENLIBC_PASSWD_PATH") };
    let _ = std::fs::remove_file(&path);
}

fn with_passwd_path(path: &std::path::Path, f: impl FnOnce()) {
    let _guard = PASSWD_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: Serialized by PASSWD_ENV_LOCK.
    unsafe { std::env::set_var("FRANKENLIBC_PASSWD_PATH", path) };
    f();
    // SAFETY: Serialized by PASSWD_ENV_LOCK.
    unsafe { std::env::remove_var("FRANKENLIBC_PASSWD_PATH") };
}

const FIXTURE: &[u8] =
    b"root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/sh\nbob:x:1001:1001:Bob:/home/bob:/bin/zsh\n";

fn native_identity_child(name: &str) -> bool {
    const CHILD: &str = "FRANKENLIBC_NATIVE_IDENTITY_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return false;
    }
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "frankenlibc-native-identity-{}-{seq}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    for (file, variable, content) in [
        (
            "passwd",
            "FRANKENLIBC_PASSWD_PATH",
            "creator:x:4101:4201:Creator:/creator:/bin/sh\nworker:x:4102:4202:Worker:/worker:/bin/sh\n",
        ),
        (
            "group",
            "FRANKENLIBC_GROUP_PATH",
            "creator:x:4201:creator\nworker:x:4202:worker,other\n",
        ),
        (
            "shadow",
            "FRANKENLIBC_SHADOW_PATH",
            "creator:!:19001:0:99999:7:::\nworker:!!:19002:0:99999:7:::\n",
        ),
        (
            "gshadow",
            "FRANKENLIBC_GSHADOW_PATH",
            "creator:!:creator:creator\nworker:!!:worker:worker,other\n",
        ),
    ] {
        let path = directory.join(file);
        std::fs::write(&path, content).unwrap();
        command.env(variable, path);
    }
    let mut child = command
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start isolated native identity test");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut timed_out = false;
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            timed_out = true;
            let _ = child.kill();
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !timed_out && output.status.success() && stdout.contains("1 passed;"),
        "native identity child timeout={timed_out} status={}\n{stdout}\n{stderr}",
        output.status
    );
    true
}

fn run_native_identity_worker(
    worker: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    argument: *mut c_void,
) -> usize {
    use frankenlibc_abi::pthread_abi;
    struct RestoreBackend(bool);
    impl Drop for RestoreBackend {
        fn drop(&mut self) {
            pthread_abi::pthread_threading_restore_for_tests(self.0);
        }
    }
    let _restore = RestoreBackend(pthread_abi::pthread_threading_swap_force_native_for_tests());
    let mut thread = 0;
    // SAFETY: the argument remains live until the matching join below.
    assert_eq!(
        unsafe { pthread_abi::pthread_create(&mut thread, ptr::null(), Some(worker), argument) },
        0
    );
    let mut result = ptr::null_mut();
    // SAFETY: this is the live joinable native thread just created.
    assert_eq!(unsafe { pthread_abi::pthread_join(thread, &mut result) }, 0);
    result as usize
}

#[test]
fn identity_native_tls_preserves_records_and_pending_enumeration() {
    use frankenlibc_abi::{grp_abi, pwd_abi};
    if native_identity_child("identity_native_tls_preserves_records_and_pending_enumeration") {
        return;
    }
    unsafe extern "C" fn enumerate(argument: *mut c_void) -> *mut c_void {
        if frankenlibc_core::pthread::thread::current_thread_handle().is_none() {
            return 1usize as *mut c_void;
        }
        // SAFETY: the creator supplies four live address values through join.
        // Every native result is inspected before this worker's TLS teardown.
        unsafe {
            let creator = &*argument.cast::<[usize; 4]>();
            let pwd = getpwent();
            if pwd.is_null()
                || pwd as usize == creator[0]
                || CStr::from_ptr((*pwd).pw_name).to_bytes() != b"creator"
            {
                return 2usize as *mut c_void;
            }
            let grp = grp_abi::getgrent();
            if grp.is_null()
                || grp as usize == creator[1]
                || CStr::from_ptr((*grp).gr_name).to_bytes() != b"creator"
            {
                return 3usize as *mut c_void;
            }
            let shadow = pwd_abi::getspent().cast::<libc::spwd>();
            if shadow.is_null()
                || shadow as usize == creator[2]
                || CStr::from_ptr((*shadow).sp_namp).to_bytes() != b"creator"
            {
                return 4usize as *mut c_void;
            }
            let gshadow = pwd_abi::getsgent().cast::<TestSgrp>();
            if gshadow.is_null()
                || gshadow as usize == creator[3]
                || CStr::from_ptr((*gshadow).sg_namp).to_bytes() != b"creator"
            {
                return 5usize as *mut c_void;
            }
            let pwd = getpwent();
            let grp = grp_abi::getgrent();
            let shadow = pwd_abi::getspent().cast::<libc::spwd>();
            let gshadow = pwd_abi::getsgent().cast::<TestSgrp>();
            if pwd.is_null() || CStr::from_ptr((*pwd).pw_name).to_bytes() != b"worker" {
                return 6usize as *mut c_void;
            }
            if grp.is_null() || CStr::from_ptr((*grp).gr_name).to_bytes() != b"worker" {
                return 7usize as *mut c_void;
            }
            if shadow.is_null() || CStr::from_ptr((*shadow).sp_namp).to_bytes() != b"worker" {
                return 8usize as *mut c_void;
            }
            if gshadow.is_null() || CStr::from_ptr((*gshadow).sg_namp).to_bytes() != b"worker" {
                return 9usize as *mut c_void;
            }
            endpwent();
            grp_abi::endgrent();
            pwd_abi::endspent();
            pwd_abi::endsgent();
        }
        ptr::null_mut()
    }
    // Two native files sources exercise the NSS cursor and ERANGE pending
    // entry in addition to each files cache. No installed NSS module is used.
    for database in [c"passwd", c"group", c"shadow"] {
        assert_eq!(
            unsafe {
                frankenlibc_abi::glibc_internal_abi::__nss_configure_lookup(
                    database.as_ptr(),
                    c"files files".as_ptr(),
                )
            },
            0
        );
    }
    // SAFETY: these fixtures belong to this isolated child. Caller storage
    // stays live until all reentrant calls and native workers have completed.
    unsafe {
        setpwent();
        grp_abi::setgrent();
        pwd_abi::setspent();
        pwd_abi::setsgent();
        let pwd = getpwent();
        let grp = grp_abi::getgrent();
        let shadow = pwd_abi::getspent().cast::<libc::spwd>();
        let gshadow = pwd_abi::getsgent().cast::<TestSgrp>();
        assert!(!pwd.is_null() && !grp.is_null() && !shadow.is_null() && !gshadow.is_null());
        let mut creator = [
            pwd as usize,
            grp as usize,
            shadow as usize,
            gshadow as usize,
        ];
        let mut pwd_out = std::mem::zeroed::<libc::passwd>();
        let mut grp_out = std::mem::zeroed::<libc::group>();
        let mut shadow_out = std::mem::zeroed::<libc::spwd>();
        let mut gshadow_out = std::mem::zeroed::<TestSgrp>();
        let mut pwd_result = ptr::null_mut();
        let mut grp_result = ptr::null_mut();
        let mut shadow_result = ptr::null_mut();
        let mut gshadow_result = ptr::null_mut();
        let mut buffer = [0 as c_char; 512];
        assert_eq!(
            pwd_abi::getpwent_r(&mut pwd_out, buffer.as_mut_ptr(), 1, &mut pwd_result),
            libc::ERANGE
        );
        assert_eq!(
            grp_abi::getgrent_r(&mut grp_out, buffer.as_mut_ptr(), 1, &mut grp_result),
            libc::ERANGE
        );
        assert_eq!(
            pwd_abi::getspent_r(
                (&raw mut shadow_out).cast(),
                buffer.as_mut_ptr(),
                1,
                &mut shadow_result,
            ),
            libc::ERANGE
        );
        assert_eq!(
            pwd_abi::getsgent_r(
                (&raw mut gshadow_out).cast(),
                buffer.as_mut_ptr(),
                1,
                &mut gshadow_result,
            ),
            libc::ERANGE
        );
        assert!(pwd_result.is_null() && grp_result.is_null());
        assert!(shadow_result.is_null() && gshadow_result.is_null());
        for _ in 0..3 {
            assert_eq!(
                run_native_identity_worker(enumerate, (&raw mut creator).cast()),
                0
            );
            assert_eq!(CStr::from_ptr((*pwd).pw_name).to_bytes(), b"creator");
            assert_eq!(CStr::from_ptr((*grp).gr_name).to_bytes(), b"creator");
            assert_eq!(CStr::from_ptr((*shadow).sp_namp).to_bytes(), b"creator");
            assert_eq!(CStr::from_ptr((*gshadow).sg_namp).to_bytes(), b"creator");
        }
        let next = getpwent();
        assert_eq!(next, pwd, "hosted passwd storage must not migrate");
        assert_eq!(CStr::from_ptr((*next).pw_name).to_bytes(), b"worker");
        let next = grp_abi::getgrent();
        assert_eq!(next, grp, "hosted group storage must not migrate");
        assert_eq!(CStr::from_ptr((*next).gr_name).to_bytes(), b"worker");
        let next = pwd_abi::getspent().cast::<libc::spwd>();
        assert_eq!(next, shadow, "hosted shadow storage must not migrate");
        assert_eq!(CStr::from_ptr((*next).sp_namp).to_bytes(), b"worker");
        let next = pwd_abi::getsgent().cast::<TestSgrp>();
        assert_eq!(next, gshadow, "hosted gshadow storage must not migrate");
        assert_eq!(CStr::from_ptr((*next).sg_namp).to_bytes(), b"worker");

        // Each NSS iterator was already at the end of its first files source
        // when ERANGE retained worker. Only the second source may remain.
        // A native worker's end*ent must not rewind the creator's bare cursor,
        // replaying the first source and inventing two additional records.
        for expected in [b"creator".as_slice(), b"worker".as_slice()] {
            let pwd = getpwent();
            let grp = grp_abi::getgrent();
            let shadow = pwd_abi::getspent().cast::<libc::spwd>();
            assert!(!pwd.is_null() && !grp.is_null() && !shadow.is_null());
            assert_eq!(CStr::from_ptr((*pwd).pw_name).to_bytes(), expected);
            assert_eq!(CStr::from_ptr((*grp).gr_name).to_bytes(), expected);
            assert_eq!(CStr::from_ptr((*shadow).sp_namp).to_bytes(), expected);
        }
        assert_eq!(
            (
                getpwent().is_null(),
                grp_abi::getgrent().is_null(),
                pwd_abi::getspent().is_null(),
            ),
            (true, true, true),
            "native end*ent must not rewind the creator's passwd/group/shadow NSS cursors"
        );
        assert!(pwd_abi::getsgent().is_null());
        endpwent();
        grp_abi::endgrent();
        pwd_abi::endspent();
        pwd_abi::endsgent();
    }
}

unsafe fn identity_record_named(record: *mut c_void, name: &[u8]) -> bool {
    // SAFETY: each public record layout begins with its name pointer. The
    // caller keeps the record and strings alive until this comparison ends.
    !record.is_null()
        && unsafe { CStr::from_ptr(record.cast::<*mut c_char>().read()).to_bytes() == name }
}

unsafe fn identity_next(database: usize) -> *mut c_void {
    use frankenlibc_abi::{grp_abi, pwd_abi};
    // SAFETY: each result belongs to the caller and is consumed before reuse.
    unsafe {
        match database {
            0 => getpwent().cast(),
            1 => grp_abi::getgrent().cast(),
            2 => pwd_abi::getspent(),
            3 => pwd_abi::getsgent(),
            _ => unreachable!(),
        }
    }
}

fn identity_reentrant(
    database: usize,
    lookup: Option<&CStr>,
    capacity: usize,
    expected: Option<&[u8]>,
) -> (i32, bool) {
    use std::mem::{align_of, size_of};

    use frankenlibc_abi::{grp_abi, pwd_abi};
    const {
        assert!(size_of::<libc::passwd>() <= size_of::<AlignedShadowStorage>());
        assert!(size_of::<libc::group>() <= size_of::<AlignedShadowStorage>());
        assert!(size_of::<libc::spwd>() <= size_of::<AlignedShadowStorage>());
        assert!(size_of::<TestSgrp>() <= size_of::<AlignedShadowStorage>());
        assert!(align_of::<libc::passwd>() <= align_of::<AlignedShadowStorage>());
        assert!(align_of::<libc::group>() <= align_of::<AlignedShadowStorage>());
        assert!(align_of::<libc::spwd>() <= align_of::<AlignedShadowStorage>());
        assert!(align_of::<TestSgrp>() <= align_of::<AlignedShadowStorage>());
    }
    let mut record = AlignedShadowStorage::zeroed();
    let mut buffer = [0 as c_char; 512];
    let mut result: *mut c_void = ptr::null_mut();
    assert!(capacity <= buffer.len());
    let out = record.as_mut_void();
    // SAFETY: size and alignment for each record are checked above. The record,
    // buffer and result slot remain alive until its returned name is consumed.
    let rc = unsafe {
        let buf = buffer.as_mut_ptr();
        match (database, lookup) {
            (0, Some(name)) => getpwnam_r(
                name.as_ptr(),
                out.cast(),
                buf,
                capacity,
                (&raw mut result).cast(),
            ),
            (1, Some(name)) => grp_abi::getgrnam_r(
                name.as_ptr(),
                out.cast(),
                buf,
                capacity,
                (&raw mut result).cast(),
            ),
            (2, Some(name)) => pwd_abi::getspnam_r(name.as_ptr(), out, buf, capacity, &mut result),
            (3, Some(name)) => pwd_abi::getsgnam_r(name.as_ptr(), out, buf, capacity, &mut result),
            (0, None) => pwd_abi::getpwent_r(out.cast(), buf, capacity, (&raw mut result).cast()),
            (1, None) => grp_abi::getgrent_r(out.cast(), buf, capacity, (&raw mut result).cast()),
            (2, None) => pwd_abi::getspent_r(out, buf, capacity, &mut result),
            (3, None) => pwd_abi::getsgent_r(out, buf, capacity, &mut result),
            _ => unreachable!(),
        }
    };
    let matches = match expected {
        Some(name) => result == out && unsafe { identity_record_named(result, name) },
        None => result.is_null(),
    };
    (rc, matches)
}

fn configure_native_identity_sources() {
    for database in [c"passwd", c"group", c"shadow"] {
        // SAFETY: each caller runs in its own isolated test process.
        assert_eq!(
            unsafe {
                frankenlibc_abi::glibc_internal_abi::__nss_configure_lookup(
                    database.as_ptr(),
                    c"files files".as_ptr(),
                )
            },
            0
        );
    }
}

#[test]
#[cfg(debug_assertions)]
fn identity_native_tls_reentrant_lookups_ignore_creator_borrows() {
    use frankenlibc_abi::{grp_abi, pwd_abi};
    if native_identity_child("identity_native_tls_reentrant_lookups_ignore_creator_borrows") {
        return;
    }
    configure_native_identity_sources();
    unsafe extern "C" fn worker(_: *mut c_void) -> *mut c_void {
        if frankenlibc_core::pthread::thread::current_thread_handle().is_none() {
            return 1usize as *mut c_void;
        }
        for database in 0..4 {
            for _ in 0..2 {
                if identity_reentrant(database, Some(c"worker"), 512, Some(b"worker")) != (0, true)
                {
                    return (2 + database) as *mut c_void;
                }
            }
            if identity_reentrant(database, None, 512, Some(b"creator")) != (0, true) {
                return (6 + database) as *mut c_void;
            }
        }
        ptr::null_mut()
    }
    let result = pwd_abi::with_identity_cache_borrows_for_tests(|| {
        grp_abi::with_group_cache_borrows_for_tests(|| {
            run_native_identity_worker(worker, ptr::null_mut())
        })
    });
    assert_eq!(
        result, 0,
        "native reentrant account access shared creator caches"
    );
}

#[test]
fn identity_native_tls_preserves_pending_records_across_fork() {
    if native_identity_child("identity_native_tls_preserves_pending_records_across_fork") {
        return;
    }
    configure_native_identity_sources();
    fn consume_pending_and_tail(addresses: &[usize; 4]) -> usize {
        for database in 0..4 {
            if identity_reentrant(database, None, 512, Some(b"worker")) != (0, true) {
                return 20 + database;
            }
            if database != 3 {
                // Exactly the second files source remains. Its nonreentrant
                // results must still use the pre-fork caller's storage.
                for (index, name) in [b"creator".as_slice(), b"worker"].into_iter().enumerate() {
                    let record = unsafe { identity_next(database) };
                    if record as usize != addresses[database]
                        || !unsafe { identity_record_named(record, name) }
                    {
                        return 30 + 2 * database + index;
                    }
                }
            } else {
                let record = unsafe { frankenlibc_abi::pwd_abi::getsgnam(c"worker".as_ptr()) };
                if record as usize != addresses[database]
                    || !unsafe { identity_record_named(record, b"worker") }
                {
                    return 36;
                }
            }
            if !unsafe { identity_next(database) }.is_null() {
                return 40 + database;
            }
        }
        0
    }
    unsafe extern "C" fn worker(_: *mut c_void) -> *mut c_void {
        if frankenlibc_core::pthread::thread::current_thread_handle().is_none() {
            return 1usize as *mut c_void;
        }
        let mut addresses = [0usize; 4];
        for (database, address) in addresses.iter_mut().enumerate() {
            let record = unsafe { identity_next(database) };
            if !unsafe { identity_record_named(record, b"creator") } {
                return (2 + database) as *mut c_void;
            }
            *address = record as usize;
            if identity_reentrant(database, None, 1, None) != (libc::ERANGE, true) {
                return (6 + database) as *mut c_void;
            }
        }
        // SAFETY: the child inspects only inherited caller-owned records and
        // exits without returning through the parent's native thread entry.
        let pid = unsafe { frankenlibc_abi::process_abi::fork() };
        if pid < 0 {
            return 10usize as *mut c_void;
        }
        if pid == 0 {
            unsafe { libc::alarm(10) };
            let result = consume_pending_and_tail(&addresses);
            unsafe { libc::_exit(result as i32) };
        }
        let mut status = 0;
        let waited = unsafe { frankenlibc_abi::process_abi::waitpid(pid, &mut status, 0) };
        if waited != pid || !libc::WIFEXITED(status) {
            return 11usize as *mut c_void;
        }
        let child_result = libc::WEXITSTATUS(status);
        if child_result != 0 {
            return (100 + child_result as usize) as *mut c_void;
        }
        // Child-side adoption must not change the parent's pending records.
        consume_pending_and_tail(&addresses) as *mut c_void
    }
    assert_eq!(
        run_native_identity_worker(worker, ptr::null_mut()),
        0,
        "fork lost native identity ownership, pending records, or source position"
    );
}

#[test]
fn nss_files_passwd_lookup_returns_records_and_preserves_miss_errnop() {
    with_passwd_file(FIXTURE, || {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buffer = [0u8; 512];
        let mut err = 717;
        // SAFETY: each output is writable and the buffer remains live while
        // its borrowed passwd strings are inspected.
        unsafe {
            assert_eq!(
                _nss_files_getpwnam_r(
                    c"alice".as_ptr(),
                    (&raw mut pwd).cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut err,
                ),
                1
            );
            assert_eq!(err, 717);
            assert_eq!(CStr::from_ptr(pwd.pw_name).to_bytes(), b"alice");
            assert_eq!(pwd.pw_uid, 1000);
            assert_eq!(CStr::from_ptr(pwd.pw_dir).to_bytes(), b"/home/alice");
            assert_eq!(
                _nss_files_getpwuid_r(
                    1001,
                    (&raw mut pwd).cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut err,
                ),
                1
            );
            assert_eq!(err, 717);
            assert_eq!(CStr::from_ptr(pwd.pw_name).to_bytes(), b"bob");
            assert_eq!(
                _nss_files_getpwnam_r(
                    c"absent".as_ptr(),
                    (&raw mut pwd).cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut err,
                ),
                0
            );
            assert_eq!(err, 717, "a plain miss must not manufacture ENOENT");
            buffer.fill(0xa5);
            assert_eq!(
                _nss_files_getpwuid_r(
                    9999,
                    (&raw mut pwd).cast(),
                    buffer.as_mut_ptr().cast(),
                    1,
                    &mut err,
                ),
                -2,
                "scanned records can require ERANGE even before a key matches"
            );
            assert_eq!(err, libc::ERANGE);
            assert!(buffer.iter().all(|&byte| byte == 0xa5));
            _nss_files_endpwent();
        }
    });
}

#[test]
fn nss_files_passwd_erange_errno_tracks_reader_stage() {
    with_passwd_file(b"root:x:0:0:root:/root:/bin/bash\n", || {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut bytes = [0u8; 128];
        // SAFETY: all record, string and error slots are live caller storage.
        unsafe {
            for offset in [0, 1, 7] {
                let buffer = bytes.as_mut_ptr().add(offset).cast();
                for capacity in [0, 1, 2, 31, 32, 33, 34, 64] {
                    for kind in 0..5 {
                        if kind == 4 {
                            assert_eq!(_nss_files_setpwent(0), 1);
                        }
                        let mut err = 717;
                        *__errno_location() = 718;
                        let status = match kind {
                            0 | 1 => _nss_files_getpwnam_r(
                                if kind == 0 { c"root" } else { c"absent" }.as_ptr(),
                                (&raw mut pwd).cast(),
                                buffer,
                                capacity,
                                &mut err,
                            ),
                            2 | 3 => _nss_files_getpwuid_r(
                                if kind == 2 { 0 } else { libc::uid_t::MAX },
                                (&raw mut pwd).cast(),
                                buffer,
                                capacity,
                                &mut err,
                            ),
                            _ => _nss_files_getpwent_r(
                                (&raw mut pwd).cast(),
                                buffer,
                                capacity,
                                &mut err,
                            ),
                        };
                        let actual_errno = *__errno_location();
                        let expected = if capacity < 34 {
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
                            "passwd kind={kind} capacity={capacity} offset={offset}"
                        );
                    }
                }
            }
            // Publishing errnop must still work when it aliases global errno.
            *__errno_location() = 718;
            assert_eq!(
                _nss_files_getpwuid_r(
                    0,
                    (&raw mut pwd).cast(),
                    bytes.as_mut_ptr().cast(),
                    1,
                    __errno_location()
                ),
                -2
            );
            assert_eq!(*__errno_location(), libc::ERANGE);
            _nss_files_endpwent();
        }
    });
}

#[test]
fn nss_files_passwd_enumeration_retries_and_rewinds() {
    with_passwd_file(FIXTURE, || {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buffer = [0u8; 512];
        let mut err = 717;
        // SAFETY: result, buffer and errno pointers are live writable storage.
        unsafe {
            assert_eq!(_nss_files_setpwent(0), 1);
            assert_eq!(
                _nss_files_getpwent_r(
                    (&raw mut pwd).cast(),
                    buffer.as_mut_ptr().cast(),
                    1,
                    &mut err,
                ),
                -2
            );
            assert_eq!(err, libc::ERANGE);
            assert_eq!(
                _nss_files_getpwent_r(
                    (&raw mut pwd).cast(),
                    buffer.as_mut_ptr().cast(),
                    33,
                    &mut err,
                ),
                -2,
                "the first raw passwd record requires 34 bytes, not just its packed strings"
            );
            for name in [b"root".as_slice(), b"alice", b"bob"] {
                err = 717;
                assert_eq!(
                    _nss_files_getpwent_r(
                        (&raw mut pwd).cast(),
                        buffer.as_mut_ptr().cast(),
                        if name == b"root" { 34 } else { buffer.len() },
                        &mut err,
                    ),
                    1
                );
                assert_eq!(err, 717);
                assert_eq!(CStr::from_ptr(pwd.pw_name).to_bytes(), name);
            }
            assert_eq!(
                _nss_files_getpwent_r(
                    (&raw mut pwd).cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut err,
                ),
                0
            );
            assert_eq!(err, 717, "EOF is not a backend I/O error");
            assert_eq!(_nss_files_setpwent(1), 1);
            assert_eq!(
                _nss_files_getpwent_r(
                    (&raw mut pwd).cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut err,
                ),
                1
            );
            assert_eq!(CStr::from_ptr(pwd.pw_name).to_bytes(), b"root");
            assert_eq!(_nss_files_endpwent(), 1);
            assert_eq!(
                _nss_files_getpwent_r(
                    (&raw mut pwd).cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut err,
                ),
                1
            );
            assert_eq!(CStr::from_ptr(pwd.pw_name).to_bytes(), b"root");
            _nss_files_endpwent();
        }
    });
}

#[test]
fn nss_files_passwd_enumeration_preserves_nis_null_fields_and_scanned_lines() {
    let records = b"+only\n# a long skipped comment\nu:x:7:8:g:d:s\n# tail\n";
    with_passwd_file(records, || {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buffer = [0u8; 512];
        let mut err = 717;
        // SAFETY: all results stay within the live caller buffer.
        unsafe {
            assert_eq!(_nss_files_setpwent(0), 1);
            for (capacity, expected) in [(7, -2), (8, 1)] {
                assert_eq!(
                    _nss_files_getpwent_r(
                        (&raw mut pwd).cast(),
                        buffer.as_mut_ptr().cast(),
                        capacity,
                        &mut err,
                    ),
                    expected
                );
            }
            assert_eq!(CStr::from_ptr(pwd.pw_name).to_bytes(), b"+only");
            assert!(pwd.pw_passwd.is_null());
            assert!(pwd.pw_gecos.is_null());
            assert!(pwd.pw_dir.is_null());
            assert!(pwd.pw_shell.is_null());
            for (capacity, expected) in [(16, -2), (512, 1)] {
                assert_eq!(
                    _nss_files_getpwent_r(
                        (&raw mut pwd).cast(),
                        buffer.as_mut_ptr().cast(),
                        capacity,
                        &mut err,
                    ),
                    expected,
                    "even skipped lines must fit the files parser's input buffer"
                );
            }
            assert_eq!(CStr::from_ptr(pwd.pw_name).to_bytes(), b"u");
            for (capacity, expected) in [(1, -2), (512, 0), (0, -2), (1, -2), (2, -2), (3, 0)] {
                err = 717;
                *__errno_location() = 718;
                assert_eq!(
                    _nss_files_getpwent_r(
                        (&raw mut pwd).cast(),
                        buffer.as_mut_ptr().cast(),
                        capacity,
                        &mut err,
                    ),
                    expected,
                    "consumed EOF still requires the files reader's minimum buffer"
                );
                assert_eq!(err, if expected == -2 { libc::ERANGE } else { 717 });
                assert_eq!(
                    *__errno_location(),
                    if capacity == 2 { libc::ERANGE } else { 718 }
                );
            }
            _nss_files_endpwent();
        }
    });
}

#[test]
fn nss_files_passwd_reports_unavailable_backend_separately_from_miss() {
    let path = temp_passwd_path();
    assert!(!path.exists());
    with_passwd_path(&path, || {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buffer = [0u8; 512];
        let mut err = 717;
        // SAFETY: output pointers are valid, and the fixture deliberately
        // names a nonexistent private file, never a system database.
        unsafe {
            assert_eq!(_nss_files_setpwent(0), -1);
            assert_eq!(
                _nss_files_getpwnam_r(
                    c"root".as_ptr(),
                    (&raw mut pwd).cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut err,
                ),
                -1
            );
            assert_eq!(err, libc::ENOENT);
            err = 717;
            assert_eq!(
                _nss_files_getpwent_r(
                    (&raw mut pwd).cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut err,
                ),
                -1
            );
            assert_eq!(err, libc::ENOENT);
            _nss_files_endpwent();
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

#[repr(align(8))]
struct AlignedShadowStorage([u8; 256]);

impl AlignedShadowStorage {
    fn zeroed() -> Self {
        Self([0; 256])
    }

    fn as_mut_void(&mut self) -> *mut c_void {
        self.0.as_mut_ptr().cast()
    }
}

// ---------------------------------------------------------------------------
// getpwnam
// ---------------------------------------------------------------------------

#[test]
fn getpwnam_finds_root() {
    with_passwd_file(FIXTURE, || {
        let name = CString::new("root").unwrap();
        let pw = unsafe { getpwnam(name.as_ptr()) };
        assert!(!pw.is_null(), "getpwnam(root) should find root");
        let pw_ref = unsafe { &*pw };
        assert_eq!(pw_ref.pw_uid, 0);
        assert_eq!(pw_ref.pw_gid, 0);
        let pw_name = unsafe { CStr::from_ptr(pw_ref.pw_name) };
        assert_eq!(pw_name.to_bytes(), b"root");
    });
}

#[test]
fn getpwnam_finds_alice() {
    with_passwd_file(FIXTURE, || {
        let name = CString::new("alice").unwrap();
        let pw = unsafe { getpwnam(name.as_ptr()) };
        assert!(!pw.is_null());
        let pw_ref = unsafe { &*pw };
        assert_eq!(pw_ref.pw_uid, 1000);
        let gecos = unsafe { CStr::from_ptr(pw_ref.pw_gecos) };
        assert_eq!(gecos.to_bytes(), b"Alice");
    });
}

#[test]
fn getpwnam_not_found() {
    with_passwd_file(FIXTURE, || {
        let name = CString::new("nonexistent").unwrap();
        let pw = unsafe { getpwnam(name.as_ptr()) };
        assert!(
            pw.is_null(),
            "getpwnam for nonexistent user should return null"
        );
    });
}

#[test]
fn getpwnam_null_returns_null() {
    let pw = unsafe { getpwnam(ptr::null()) };
    assert!(pw.is_null());
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn getpwnam_rejects_unterminated_name() {
    with_passwd_file(FIXTURE, || unsafe {
        let name = malloc(4).cast::<u8>();
        assert!(!name.is_null());
        std::ptr::copy_nonoverlapping(b"root".as_ptr(), name, 4);
        let pw = getpwnam(name.cast());
        free(name.cast());
        assert!(pw.is_null(), "unterminated getpwnam name should fail");
    });
}

#[test]
fn getpwnam_missing_backend_sets_errno() {
    let missing = temp_passwd_path();
    with_passwd_path(&missing, || {
        let name = CString::new("root").unwrap();
        unsafe { *__errno_location() = 0 };
        let pw = unsafe { getpwnam(name.as_ptr()) };
        assert!(pw.is_null());
        assert_eq!(unsafe { *__errno_location() }, errno::ENOENT);
    });
}

#[test]
fn non_reentrant_passwd_storage_is_thread_local() {
    with_passwd_file(FIXTURE, || {
        unsafe { endpwent() };
        let name = CString::new("root").unwrap();
        let main_entry = unsafe { getpwnam(name.as_ptr()) };
        assert!(
            !main_entry.is_null(),
            "main thread getpwnam(root) should succeed"
        );
        let main_ptr = main_entry as usize;

        let worker_ptr = std::thread::spawn(|| {
            let name = CString::new("alice").unwrap();
            let entry = unsafe { getpwnam(name.as_ptr()) };
            assert!(
                !entry.is_null(),
                "worker thread getpwnam(alice) should succeed"
            );
            let passwd = unsafe { &*entry };
            let name = unsafe { CStr::from_ptr(passwd.pw_name) };
            assert_eq!(name.to_bytes(), b"alice");
            entry as usize
        })
        .join()
        .expect("worker thread should complete");

        assert_ne!(
            main_ptr, worker_ptr,
            "non-reentrant passwd storage must be isolated per thread"
        );
        let main_after = unsafe { &*main_entry };
        let main_name = unsafe { CStr::from_ptr(main_after.pw_name) };
        assert_eq!(
            main_name.to_bytes(),
            b"root",
            "worker lookup must not overwrite main thread passwd storage"
        );

        unsafe { endpwent() };
    });
}

// ---------------------------------------------------------------------------
// getpwuid
// ---------------------------------------------------------------------------

#[test]
fn getpwuid_finds_by_uid() {
    with_passwd_file(FIXTURE, || {
        let pw = unsafe { getpwuid(1001) };
        assert!(!pw.is_null(), "getpwuid(1001) should find bob");
        let pw_ref = unsafe { &*pw };
        let pw_name = unsafe { CStr::from_ptr(pw_ref.pw_name) };
        assert_eq!(pw_name.to_bytes(), b"bob");
        let shell = unsafe { CStr::from_ptr(pw_ref.pw_shell) };
        assert_eq!(shell.to_bytes(), b"/bin/zsh");
    });
}

#[test]
fn getpwuid_refreshes_cached_uid_after_backend_change() {
    let _guard = PASSWD_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = temp_passwd_path();
    std::fs::write(
        &path,
        b"root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
    )
    .expect("write initial temp passwd");

    unsafe { std::env::set_var("FRANKENLIBC_PASSWD_PATH", &path) };

    let first = unsafe { getpwuid(1000) };
    assert!(!first.is_null());
    let first_dir = unsafe { CStr::from_ptr((*first).pw_dir) };
    assert_eq!(first_dir.to_bytes(), b"/home/alice");

    std::fs::write(
        &path,
        b"root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000:Alice:/srv/alice:/bin/zsh\n",
    )
    .expect("rewrite temp passwd");

    let second = unsafe { getpwuid(1000) };
    assert!(!second.is_null());
    let second_dir = unsafe { CStr::from_ptr((*second).pw_dir) };
    assert_eq!(second_dir.to_bytes(), b"/srv/alice");

    unsafe {
        endpwent();
        std::env::remove_var("FRANKENLIBC_PASSWD_PATH");
    }
}

#[test]
fn getpwuid_not_found() {
    with_passwd_file(FIXTURE, || {
        let pw = unsafe { getpwuid(9999) };
        assert!(pw.is_null());
    });
}

/// A `+` in a NUMERIC field is ACCEPTED, because glibc parses those with
/// `strtoul`, which consumes a leading sign.
///
/// This arm previously asserted the opposite -- that `plusuid:x:+1000:...` was
/// ignored -- and it was simply wrong about the incumbent. Measured against live
/// glibc 2.42 with the fixture bind-mounted over `/etc/passwd`:
///
/// ```text
/// getpwnam("plusuid") -> NON-NULL uid=1000 gid=1000
/// getpwnam("plusgid") -> NON-NULL uid=1001 gid=1001
/// ```
///
/// fl agreed with glibc and the arm failed anyway. The rule the arm was reaching
/// for is real but lives somewhere else: it is the NAME field, not the numeric
/// fields, that makes glibc skip a row (see
/// `getpwnam_skips_nis_compat_prefixed_name_rows`).
#[test]
fn getpwnam_getpwuid_accept_signed_numeric_fields_like_glibc() {
    let fixture = b"\
plusuid:x:+1000:1000:Plus:/home/plus:/bin/sh
plusgid:x:1001:+1001:PlusGid:/home/plusgid:/bin/sh
valid:x:1002:1002:Valid:/home/valid:/bin/sh
";
    with_passwd_file(fixture, || {
        let plusuid = CString::new("plusuid").unwrap();
        let plusgid = CString::new("plusgid").unwrap();

        let a = unsafe { getpwnam(plusuid.as_ptr()) };
        assert!(!a.is_null(), "glibc accepts a '+' in the uid field");
        assert_eq!(
            unsafe { (*a).pw_uid },
            1000,
            "the sign is consumed, not kept"
        );

        let b = unsafe { getpwnam(plusgid.as_ptr()) };
        assert!(!b.is_null(), "glibc accepts a '+' in the gid field");
        assert_eq!(
            unsafe { (*b).pw_gid },
            1001,
            "the sign is consumed, not kept"
        );

        let pw = unsafe { getpwuid(1002) };
        assert!(!pw.is_null(), "ordinary unsigned row should still match");
        let pw_name = unsafe { CStr::from_ptr((*pw).pw_name) };
        assert_eq!(pw_name.to_bytes(), b"valid");
    });
}

/// glibc's files backend SKIPS a row whose NAME begins with `+` or `-`.
///
/// Those are NIS/compat markers, and the plain `files` service drops the line
/// entirely -- the entry is unreachable under BOTH spellings. Measured against
/// live glibc 2.42 with the fixture bind-mounted over `/etc/passwd`:
///
/// ```text
/// getpwnam("+nisrow")   -> NULL
/// getpwnam("nisrow")    -> NULL     (not reachable with the sign stripped either)
/// getpwnam("-minusrow") -> NULL
/// getpwnam("minusrow")  -> NULL
/// getpwnam("valid")     -> NON-NULL uid=1002
/// ```
///
/// This is the rule the old signed-uid arm was groping for, asserted where it
/// actually applies. NEGATIVE CASE: an implementation that merely strips the
/// sign, or that only skips the exact `+name` spelling, still resolves one of
/// the two lookups and fails here.
#[test]
fn getpwnam_skips_nis_compat_prefixed_name_rows() {
    let fixture = b"\
+nisrow:x:1000:1000:Nis:/home/nis:/bin/sh
-minusrow:x:1001:1001:Minus:/home/m:/bin/sh
valid:x:1002:1002:Valid:/home/valid:/bin/sh
";
    with_passwd_file(fixture, || {
        for name in ["+nisrow", "nisrow", "-minusrow", "minusrow"] {
            let c = CString::new(name).unwrap();
            assert!(
                unsafe { getpwnam(c.as_ptr()) }.is_null(),
                "glibc's files backend drops NIS-compat rows; {name} must not resolve"
            );
        }
        assert!(
            unsafe { getpwuid(1000) }.is_null(),
            "a dropped NIS row must not be reachable by uid either"
        );

        let pw = unsafe { getpwuid(1002) };
        assert!(!pw.is_null(), "the ordinary row is still kept");
        let pw_name = unsafe { CStr::from_ptr((*pw).pw_name) };
        assert_eq!(pw_name.to_bytes(), b"valid");
    });
}

// ---------------------------------------------------------------------------
// getpwnam_r (reentrant)
// ---------------------------------------------------------------------------

#[test]
fn getpwnam_r_succeeds() {
    with_passwd_file(FIXTURE, || {
        let name = CString::new("alice").unwrap();
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = unsafe {
            getpwnam_r(
                name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0);
        assert!(!result.is_null());
        assert_eq!(pwd.pw_uid, 1000);
    });
}

#[test]
fn getpwnam_r_not_found() {
    with_passwd_file(FIXTURE, || {
        let name = CString::new("nobody_here").unwrap();
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = unsafe {
            getpwnam_r(
                name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0);
        assert!(result.is_null(), "result should be null when not found");
    });
}

#[test]
fn getpwnam_r_buffer_too_small() {
    with_passwd_file(FIXTURE, || {
        let name = CString::new("root").unwrap();
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = [0u8; 2]; // Too small
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = unsafe {
            getpwnam_r(
                name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, libc::ERANGE, "should return ERANGE for small buffer");
        assert!(result.is_null());
    });
}

#[test]
fn getpwnam_r_null_args_returns_einval() {
    let rc = unsafe {
        getpwnam_r(
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        )
    };
    assert_eq!(rc, libc::EINVAL);
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn getpwnam_r_rejects_unterminated_name() {
    with_passwd_file(FIXTURE, || unsafe {
        let name = malloc(5).cast::<u8>();
        assert!(!name.is_null());
        std::ptr::copy_nonoverlapping(b"alice".as_ptr(), name, 5);
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = getpwnam_r(
            name.cast(),
            &mut pwd,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        );
        free(name.cast());
        assert_eq!(rc, libc::EINVAL);
        assert!(result.is_null());
    });
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn getpwnam_r_rejects_tracked_buffer_shorter_than_claimed() {
    with_passwd_file(FIXTURE, || unsafe {
        let name = CString::new("root").unwrap();
        let mut pwd: libc::passwd = std::mem::zeroed();
        let raw = tracked_zeroed_bytes(2);
        assert_known_short(raw, 3);
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = getpwnam_r(
            name.as_ptr(),
            &mut pwd,
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
fn getpwuid_r_rejects_tracked_short_result_slot_before_write() {
    with_passwd_file(FIXTURE, || unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0u8; 1024];
        let raw_len = std::mem::size_of::<*mut libc::passwd>() - 1;
        let raw = tracked_zeroed_bytes(raw_len);
        fill_tracked_bytes(raw, raw_len, 0xA5);
        assert_known_short(raw, std::mem::size_of::<*mut libc::passwd>());

        let rc = getpwuid_r(
            0,
            &mut pwd,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            raw.cast::<*mut libc::passwd>(),
        );

        assert_eq!(rc, libc::EINVAL);
        assert_tracked_bytes_eq(raw, raw_len, 0xA5);
        free_tracked(raw);
    });
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn getpwuid_r_rejects_tracked_misaligned_result_slot_before_write() {
    with_passwd_file(FIXTURE, || unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0u8; 1024];
        let raw_len = std::mem::size_of::<*mut libc::passwd>() + 1;
        let raw = tracked_zeroed_bytes(raw_len);
        fill_tracked_bytes(raw, raw_len, 0xA5);
        let result = raw.cast::<u8>().add(1).cast::<*mut libc::passwd>();
        assert_ne!(
            (result as usize) % std::mem::align_of::<*mut libc::passwd>(),
            0
        );

        let rc = getpwuid_r(
            0,
            &mut pwd,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            result,
        );

        assert_eq!(rc, libc::EINVAL);
        assert_tracked_bytes_eq(raw, raw_len, 0xA5);
        free_tracked(raw);
    });
}

#[test]
fn getpwuid_r_clears_result_before_rejecting_tracked_short_passwd_slot() {
    with_passwd_file(FIXTURE, || unsafe {
        let raw = tracked_zeroed_bytes(std::mem::size_of::<libc::passwd>() - 1);
        assert_known_short(raw, std::mem::size_of::<libc::passwd>());
        let mut buf = vec![0u8; 1024];
        let mut result = std::ptr::NonNull::<libc::passwd>::dangling().as_ptr();

        let rc = getpwuid_r(
            0,
            raw.cast::<libc::passwd>(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        );

        assert_eq!(rc, libc::EINVAL);
        assert!(result.is_null());
        free_tracked(raw);
    });
}

#[test]
fn getpwuid_r_clears_result_before_rejecting_tracked_misaligned_passwd_slot() {
    with_passwd_file(FIXTURE, || unsafe {
        let raw = tracked_zeroed_bytes(std::mem::size_of::<libc::passwd>() + 1);
        let pwd = raw.cast::<u8>().add(1).cast::<libc::passwd>();
        assert_ne!((pwd as usize) % std::mem::align_of::<libc::passwd>(), 0);
        let mut buf = vec![0u8; 1024];
        let mut result = std::ptr::NonNull::<libc::passwd>::dangling().as_ptr();

        let rc = getpwuid_r(
            0,
            pwd,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        );

        assert_eq!(rc, libc::EINVAL);
        assert!(result.is_null());
        free_tracked(raw);
    });
}

#[test]
fn getpwnam_r_missing_backend_returns_errno() {
    let missing = temp_passwd_path();
    with_passwd_path(&missing, || {
        let name = CString::new("root").unwrap();
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = unsafe {
            getpwnam_r(
                name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, libc::ENOENT);
        assert!(result.is_null());
    });
}

// ---------------------------------------------------------------------------
// getpwuid_r (reentrant)
// ---------------------------------------------------------------------------

#[test]
fn getpwuid_r_succeeds() {
    with_passwd_file(FIXTURE, || {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = unsafe {
            getpwuid_r(
                0,
                &mut pwd,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0);
        assert!(!result.is_null());
        let pw_name = unsafe { CStr::from_ptr(pwd.pw_name) };
        assert_eq!(pw_name.to_bytes(), b"root");
    });
}

// ---------------------------------------------------------------------------
// setpwent / getpwent / endpwent (iteration)
// ---------------------------------------------------------------------------

#[test]
fn pwent_iteration() {
    with_passwd_file(FIXTURE, || {
        unsafe { setpwent() };

        let mut names = Vec::new();
        loop {
            let pw = unsafe { getpwent() };
            if pw.is_null() {
                break;
            }
            let pw_ref = unsafe { &*pw };
            let name = unsafe { CStr::from_ptr(pw_ref.pw_name) };
            names.push(name.to_bytes().to_vec());
        }

        unsafe { endpwent() };

        assert_eq!(names.len(), 3);
        assert_eq!(&names[0], b"root");
        assert_eq!(&names[1], b"alice");
        assert_eq!(&names[2], b"bob");
    });
}

#[test]
fn setpwent_rewinds_cursor() {
    with_passwd_file(FIXTURE, || {
        unsafe { setpwent() };
        let _ = unsafe { getpwent() }; // skip first

        unsafe { setpwent() };
        let pw = unsafe { getpwent() };
        assert!(!pw.is_null());
        let name = unsafe { CStr::from_ptr((*pw).pw_name) };
        assert_eq!(
            name.to_bytes(),
            b"root",
            "setpwent should rewind to first entry"
        );

        unsafe { endpwent() };
    });
}

// ---------------------------------------------------------------------------
// gshadow missing backend
// ---------------------------------------------------------------------------

#[test]
fn gshadow_missing_backend_returns_null_or_enoent() {
    use frankenlibc_abi::pwd_abi::{endsgent, getsgent, getsgnam, setsgent};

    with_missing_gshadow_file(|| {
        unsafe { setsgent() };
        let ptr = unsafe { getsgent() };
        assert!(
            ptr.is_null(),
            "getsgent should return null for missing backend"
        );

        let name = CString::new("root").unwrap();
        let ptr = unsafe { getsgnam(name.as_ptr()) };
        assert!(
            ptr.is_null(),
            "getsgnam should return null for missing backend"
        );

        unsafe { endsgent() };
    });
}

// ---------------------------------------------------------------------------
// lckpwdf / ulckpwdf
// ---------------------------------------------------------------------------

#[test]
#[cfg(debug_assertions)]
fn lckpwdf_creates_private_cloexec_lock_and_excludes_other_processes() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    use frankenlibc_abi::pwd_abi::{lckpwdf_at_for_tests, ulckpwdf};

    let _guard = PASSWORD_LOCK_TEST_LOCK.lock().unwrap();
    let path = temp_passwd_path();
    assert!(!path.exists());
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    unsafe { *__errno_location() = 731 };
    assert_eq!(unsafe { ulckpwdf() }, -1, "no lock is owned yet");
    assert_eq!(unsafe { *__errno_location() }, 731);

    assert_eq!(lckpwdf_at_for_tests(&c_path), 0);
    assert_eq!(unsafe { *__errno_location() }, 731);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let lock_fd = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .find_map(|entry| {
            (std::fs::read_link(entry.path()).ok().as_ref() == Some(&path))
                .then(|| entry.file_name().to_str().unwrap().parse::<i32>().unwrap())
        })
        .expect("the password lock owns an open file descriptor");
    let descriptor_flags = unsafe { libc::fcntl(lock_fd, libc::F_GETFD) };
    assert!(descriptor_flags >= 0);
    assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);

    unsafe { *__errno_location() = 732 };
    assert_eq!(
        lckpwdf_at_for_tests(&c_path),
        -1,
        "duplicate lock must fail"
    );
    assert_eq!(unsafe { *__errno_location() }, 732);
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["lckpwdf_external_process_probe", "--exact", "--nocapture"])
        .env("FRANKENLIBC_PASSWORD_LOCK_PROBE", &path)
        .env("FRANKENLIBC_PASSWORD_LOCK_EXPECT_BUSY", "1")
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "child lock probe failed: {}{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );

    unsafe { *__errno_location() = 732 };
    assert_eq!(unsafe { ulckpwdf() }, 0);
    assert_eq!(unsafe { *__errno_location() }, 732);
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["lckpwdf_external_process_probe", "--exact", "--nocapture"])
        .env("FRANKENLIBC_PASSWORD_LOCK_PROBE", &path)
        .env("FRANKENLIBC_PASSWORD_LOCK_EXPECT_BUSY", "0")
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "released lock remained held: {}{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    unsafe { *__errno_location() = 733 };
    assert_eq!(unsafe { ulckpwdf() }, -1);
    assert_eq!(unsafe { *__errno_location() }, 733);

    std::fs::write(&path, b"existing lock-file contents\n").unwrap();
    assert_eq!(lckpwdf_at_for_tests(&c_path), 0);
    assert_eq!(unsafe { ulckpwdf() }, 0);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"existing lock-file contents\n"
    );
}

#[test]
#[cfg(debug_assertions)]
fn lckpwdf_external_process_probe() {
    use std::os::fd::AsRawFd;

    let Some(path) = std::env::var_os("FRANKENLIBC_PASSWORD_LOCK_PROBE") else {
        return;
    };
    let expected_busy = std::env::var("FRANKENLIBC_PASSWORD_LOCK_EXPECT_BUSY").unwrap() == "1";
    let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    // A nonempty range beyond EOF must conflict with a whole-file record lock.
    let lock = libc::flock {
        l_type: libc::F_WRLCK as _,
        l_whence: libc::SEEK_SET as _,
        l_start: 4096,
        l_len: 1,
        l_pid: 0,
    };
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) };
    if expected_busy {
        assert_eq!(rc, -1);
        assert!(matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN | libc::EACCES)
        ));
    } else {
        assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    }
}

#[test]
#[cfg(debug_assertions)]
fn lckpwdf_open_failure_preserves_error_and_allows_retry() {
    use std::os::unix::ffi::OsStrExt;

    use frankenlibc_abi::pwd_abi::{lckpwdf_at_for_tests, ulckpwdf};

    let _guard = PASSWORD_LOCK_TEST_LOCK.lock().unwrap();
    let path = temp_passwd_path();
    let absent_parent = path.join(".pwd.lock");
    let missing = CString::new(absent_parent.as_os_str().as_bytes()).unwrap();
    assert_eq!(lckpwdf_at_for_tests(&missing), -1);
    assert_eq!(unsafe { *__errno_location() }, libc::ENOENT);
    unsafe { *__errno_location() = 734 };
    assert_eq!(unsafe { ulckpwdf() }, -1, "open failure cannot own a lock");
    assert_eq!(unsafe { *__errno_location() }, 734);

    let good = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(lckpwdf_at_for_tests(&good), 0);
    assert_eq!(unsafe { ulckpwdf() }, 0);
}

// ---------------------------------------------------------------------------
// getpwent_r (reentrant iteration)
// ---------------------------------------------------------------------------

#[test]
fn getpwent_r_iterates_all_entries() {
    use frankenlibc_abi::pwd_abi::getpwent_r;

    with_passwd_file(FIXTURE, || {
        unsafe { setpwent() };

        let mut count = 0;
        loop {
            let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
            let mut buf = vec![0u8; 1024];
            let mut result: *mut libc::passwd = ptr::null_mut();

            let rc = unsafe {
                getpwent_r(
                    &mut pwd,
                    buf.as_mut_ptr() as *mut c_char,
                    buf.len(),
                    &mut result,
                )
            };
            if result.is_null() {
                break;
            }
            assert_eq!(rc, 0);
            count += 1;
        }

        unsafe { endpwent() };
        assert_eq!(count, 3, "should iterate all 3 entries");
    });
}

#[test]
fn getpwent_r_null_args() {
    use frankenlibc_abi::pwd_abi::getpwent_r;

    let rc = unsafe { getpwent_r(ptr::null_mut(), ptr::null_mut(), 0, ptr::null_mut()) };
    assert_eq!(rc, libc::EINVAL, "null args should return EINVAL");
}

#[test]
fn getpwent_r_erange_does_not_advance_cursor() {
    use frankenlibc_abi::pwd_abi::getpwent_r;

    with_passwd_file(FIXTURE, || {
        unsafe { setpwent() };

        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut tiny = [0u8; 1];
        let mut result: *mut libc::passwd = ptr::null_mut();
        let rc = unsafe {
            getpwent_r(
                &mut pwd,
                tiny.as_mut_ptr() as *mut c_char,
                tiny.len(),
                &mut result,
            )
        };
        assert_eq!(rc, libc::ERANGE);
        assert!(result.is_null());

        let mut retry_buf = vec![0u8; 1024];
        let rc = unsafe {
            getpwent_r(
                &mut pwd,
                retry_buf.as_mut_ptr() as *mut c_char,
                retry_buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0);
        assert!(!result.is_null());
        let name = unsafe { CStr::from_ptr(pwd.pw_name) };
        assert_eq!(name.to_bytes(), b"root");

        unsafe { endpwent() };
    });
}

// ---------------------------------------------------------------------------
// getpwuid_r — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn getpwuid_r_not_found() {
    with_passwd_file(FIXTURE, || {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = unsafe {
            getpwuid_r(
                99999,
                &mut pwd,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0);
        assert!(result.is_null(), "nonexistent uid should yield null result");
    });
}

#[test]
fn getpwuid_r_buffer_too_small() {
    with_passwd_file(FIXTURE, || {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = [0u8; 2];
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = unsafe {
            getpwuid_r(
                0,
                &mut pwd,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, libc::ERANGE, "small buffer should return ERANGE");
        assert!(result.is_null());
    });
}

// ---------------------------------------------------------------------------
// getpwnam / getpwuid — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn getpwnam_checks_all_fields() {
    with_passwd_file(FIXTURE, || {
        let name = CString::new("bob").unwrap();
        let pw = unsafe { getpwnam(name.as_ptr()) };
        assert!(!pw.is_null());
        let pw_ref = unsafe { &*pw };
        assert_eq!(pw_ref.pw_uid, 1001);
        assert_eq!(pw_ref.pw_gid, 1001);
        let pw_dir = unsafe { CStr::from_ptr(pw_ref.pw_dir) };
        assert_eq!(pw_dir.to_bytes(), b"/home/bob");
        let pw_shell = unsafe { CStr::from_ptr(pw_ref.pw_shell) };
        assert_eq!(pw_shell.to_bytes(), b"/bin/zsh");
        let pw_gecos = unsafe { CStr::from_ptr(pw_ref.pw_gecos) };
        assert_eq!(pw_gecos.to_bytes(), b"Bob");
    });
}

#[test]
fn getpwuid_checks_home_dir() {
    with_passwd_file(FIXTURE, || {
        let pw = unsafe { getpwuid(1000) };
        assert!(!pw.is_null());
        let pw_ref = unsafe { &*pw };
        let dir = unsafe { CStr::from_ptr(pw_ref.pw_dir) };
        assert_eq!(dir.to_bytes(), b"/home/alice");
    });
}

// ---------------------------------------------------------------------------
// shadow password ABI (getspnam, getspnam_r, getspent, getspent_r)
// ---------------------------------------------------------------------------

#[test]
fn getspnam_returns_null_for_absent_user() {
    use frankenlibc_abi::pwd_abi::getspnam;
    let name = CString::new("frankenlibc_shadow_absent_user_9f3b2a").unwrap();
    let sp = unsafe { getspnam(name.as_ptr()) };
    assert!(sp.is_null(), "getspnam should return null for not found");
}

#[test]
fn getspnam_r_returns_null_for_absent_user() {
    use frankenlibc_abi::pwd_abi::getspnam_r;
    let name = CString::new("frankenlibc_shadow_absent_user_9f3b2a").unwrap();
    let mut spwd_storage = AlignedShadowStorage::zeroed();
    let mut buf = vec![0u8; 1024];
    let mut result: *mut c_void = ptr::null_mut();

    let rc = unsafe {
        getspnam_r(
            name.as_ptr(),
            spwd_storage.as_mut_void(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        )
    };
    assert!(result.is_null(), "getspnam_r result should be null");
    // rc may be 0 (not found), ENOENT, or EACCES (no /etc/shadow access)
    assert!(
        rc == 0 || rc == libc::ENOENT || rc == libc::EACCES,
        "unexpected rc: {rc}"
    );
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn getspnam_r_rejects_tracked_short_result_slot_before_write() {
    use frankenlibc_abi::pwd_abi::getspnam_r;
    let name = CString::new("root").unwrap();
    unsafe {
        let mut spwd_storage = AlignedShadowStorage::zeroed();
        let mut buf = vec![0u8; 1024];
        let raw_len = std::mem::size_of::<*mut c_void>() - 1;
        let raw = tracked_zeroed_bytes(raw_len);
        fill_tracked_bytes(raw, raw_len, 0xA5);
        assert_known_short(raw, std::mem::size_of::<*mut c_void>());

        let rc = getspnam_r(
            name.as_ptr(),
            spwd_storage.as_mut_void(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            raw.cast::<*mut c_void>(),
        );

        assert_eq!(rc, libc::EINVAL);
        assert_tracked_bytes_eq(raw, raw_len, 0xA5);
        free_tracked(raw);
    }
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn getspnam_r_rejects_tracked_misaligned_result_slot_before_write() {
    use frankenlibc_abi::pwd_abi::getspnam_r;
    let name = CString::new("root").unwrap();
    unsafe {
        let mut spwd_storage = AlignedShadowStorage::zeroed();
        let mut buf = vec![0u8; 1024];
        let raw_len = std::mem::size_of::<*mut c_void>() + 1;
        let raw = tracked_zeroed_bytes(raw_len);
        fill_tracked_bytes(raw, raw_len, 0xA5);
        let result = raw.cast::<u8>().add(1).cast::<*mut c_void>();
        assert_ne!((result as usize) % std::mem::align_of::<*mut c_void>(), 0);

        let rc = getspnam_r(
            name.as_ptr(),
            spwd_storage.as_mut_void(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            result,
        );

        assert_eq!(rc, libc::EINVAL);
        assert_tracked_bytes_eq(raw, raw_len, 0xA5);
        free_tracked(raw);
    }
}

#[test]
fn getspnam_r_clears_result_before_rejecting_tracked_short_spwd_slot() {
    use frankenlibc_abi::pwd_abi::getspnam_r;
    let name = CString::new("root").unwrap();
    unsafe {
        let raw = tracked_zeroed_bytes(std::mem::size_of::<*mut c_void>() - 1);
        assert_known_short(raw, std::mem::size_of::<*mut c_void>());
        let mut buf = vec![0u8; 1024];
        let mut result = std::ptr::NonNull::<c_void>::dangling().as_ptr();

        let rc = getspnam_r(
            name.as_ptr(),
            raw,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        );

        assert_eq!(rc, libc::EINVAL);
        assert!(result.is_null());
        free_tracked(raw);
    }
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn getspnam_r_rejects_unterminated_name() {
    use frankenlibc_abi::pwd_abi::getspnam_r;
    unsafe {
        let name = malloc(4).cast::<u8>();
        assert!(!name.is_null());
        std::ptr::copy_nonoverlapping(b"root".as_ptr(), name, 4);
        let mut spwd_storage = AlignedShadowStorage::zeroed();
        let mut buf = vec![0u8; 1024];
        let mut result: *mut c_void = ptr::null_mut();

        let rc = getspnam_r(
            name.cast(),
            spwd_storage.as_mut_void(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        );
        free(name.cast());
        assert_eq!(rc, libc::EINVAL);
        assert!(result.is_null());
    }
}

/// First `getspent_r` of a fresh enumeration, from fl or from host glibc:
/// (return code, first login name). No `setspent` first -- glibc starts an
/// enumeration implicitly (bd-nss-modules: fl used to return NULL/ENOENT
/// here whenever setspent had not been called, readable /etc/shadow or not).
fn first_shadow_entry(host: bool) -> (i32, Option<Vec<u8>>) {
    let mut storage = AlignedShadowStorage::zeroed();
    let mut buf = vec![0u8; 4096];
    let mut result: *mut c_void = ptr::null_mut();
    let rc = unsafe {
        if host {
            libc::getspent_r(
                storage.as_mut_void().cast(),
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                (&mut result as *mut *mut c_void).cast(),
            )
        } else {
            frankenlibc_abi::pwd_abi::getspent_r(
                storage.as_mut_void(),
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            )
        }
    };
    let name = (!result.is_null()).then(|| {
        // SAFETY: on success the first field is the login-name C string.
        let name_ptr = unsafe { *(result as *const *const c_char) };
        unsafe { CStr::from_ptr(name_ptr) }.to_bytes().to_vec()
    });
    unsafe {
        if host {
            libc::endspent();
        } else {
            frankenlibc_abi::pwd_abi::endspent();
        }
    }
    (rc, name)
}

#[test]
fn getspent_r_without_setspent_matches_host_glibc() {
    assert_eq!(first_shadow_entry(false), first_shadow_entry(true));
}

#[test]
fn getspent_without_setspent_matches_host_glibc() {
    use frankenlibc_abi::pwd_abi::{endspent, getspent};
    let fl = unsafe { getspent() };
    let fl_name = (!fl.is_null()).then(|| {
        let name_ptr = unsafe { *(fl as *const *const c_char) };
        unsafe { CStr::from_ptr(name_ptr) }.to_bytes().to_vec()
    });
    endspent();
    let host = unsafe { libc::getspent() };
    let host_name = (!host.is_null()).then(|| {
        unsafe { CStr::from_ptr((*host).sp_namp) }
            .to_bytes()
            .to_vec()
    });
    unsafe { libc::endspent() };
    assert_eq!(fl_name, host_name);
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn getspent_r_rejects_tracked_short_result_slot_before_write() {
    use frankenlibc_abi::pwd_abi::getspent_r;
    unsafe {
        let mut spwd_storage = AlignedShadowStorage::zeroed();
        let mut buf = vec![0u8; 1024];
        let raw_len = std::mem::size_of::<*mut c_void>() - 1;
        let raw = tracked_zeroed_bytes(raw_len);
        fill_tracked_bytes(raw, raw_len, 0xA5);
        assert_known_short(raw, std::mem::size_of::<*mut c_void>());

        let rc = getspent_r(
            spwd_storage.as_mut_void(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            raw.cast::<*mut c_void>(),
        );

        assert_eq!(rc, libc::EINVAL);
        assert_tracked_bytes_eq(raw, raw_len, 0xA5);
        free_tracked(raw);
    }
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn getspent_r_rejects_tracked_misaligned_result_slot_before_write() {
    use frankenlibc_abi::pwd_abi::getspent_r;
    unsafe {
        let mut spwd_storage = AlignedShadowStorage::zeroed();
        let mut buf = vec![0u8; 1024];
        let raw_len = std::mem::size_of::<*mut c_void>() + 1;
        let raw = tracked_zeroed_bytes(raw_len);
        fill_tracked_bytes(raw, raw_len, 0xA5);
        let result = raw.cast::<u8>().add(1).cast::<*mut c_void>();
        assert_ne!((result as usize) % std::mem::align_of::<*mut c_void>(), 0);

        let rc = getspent_r(
            spwd_storage.as_mut_void(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            result,
        );

        assert_eq!(rc, libc::EINVAL);
        assert_tracked_bytes_eq(raw, raw_len, 0xA5);
        free_tracked(raw);
    }
}

#[test]
fn getspent_r_clears_result_before_rejecting_tracked_misaligned_spwd_slot() {
    use frankenlibc_abi::pwd_abi::getspent_r;
    unsafe {
        let raw = tracked_zeroed_bytes(256);
        let spbuf = raw.cast::<u8>().add(1).cast::<c_void>();
        assert_ne!((spbuf as usize) % std::mem::align_of::<*mut c_void>(), 0);
        let mut buf = vec![0u8; 1024];
        let mut result = std::ptr::NonNull::<c_void>::dangling().as_ptr();

        let rc = getspent_r(
            spbuf,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        );

        assert_eq!(rc, libc::EINVAL);
        assert!(result.is_null());
        free_tracked(raw);
    }
}

// ---------------------------------------------------------------------------
// gshadow missing backend — additional (getsgent_r, getsgnam_r, fgetsgent, etc.)
// ---------------------------------------------------------------------------

#[test]
fn getsgent_r_returns_enoent_for_missing_backend() {
    use frankenlibc_abi::pwd_abi::getsgent_r;
    // sgrp is not in the libc crate; use the local C-layout type.
    let mut buf = vec![0u8; 512];
    // getsgent_r takes (struct sgrp*, char*, size_t, struct sgrp**) → int.
    let mut sgrp_storage = std::mem::MaybeUninit::<TestSgrp>::uninit();
    let mut result_ptr: *mut u8 = ptr::null_mut();

    with_missing_gshadow_file(|| {
        let rc = unsafe {
            getsgent_r(
                sgrp_storage.as_mut_ptr() as *mut _,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result_ptr as *mut *mut u8 as *mut *mut _,
            )
        };
        assert!(
            result_ptr.is_null(),
            "getsgent_r result should be null for missing backend"
        );
        assert_eq!(rc, libc::ENOENT, "unexpected rc: {rc}");
    });
}

#[test]
fn getsgnam_r_returns_enoent_for_missing_backend() {
    use frankenlibc_abi::pwd_abi::getsgnam_r;
    let name = CString::new("root").unwrap();
    let mut sgrp_storage = std::mem::MaybeUninit::<TestSgrp>::uninit();
    let mut buf = vec![0u8; 512];
    let mut result_ptr: *mut u8 = ptr::null_mut();

    with_missing_gshadow_file(|| {
        let rc = unsafe {
            getsgnam_r(
                name.as_ptr(),
                sgrp_storage.as_mut_ptr() as *mut _,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result_ptr as *mut *mut u8 as *mut *mut _,
            )
        };
        assert!(
            result_ptr.is_null(),
            "getsgnam_r result should be null for missing backend"
        );
        assert_eq!(rc, libc::ENOENT, "unexpected rc: {rc}");
    });
}

#[test]
fn fgetsgent_null_stream_returns_null() {
    use frankenlibc_abi::pwd_abi::fgetsgent;
    let result = unsafe { fgetsgent(ptr::null_mut()) };
    assert!(result.is_null(), "fgetsgent(null) should return null");
}

#[test]
fn fgetsgent_r_null_stream_returns_error() {
    use frankenlibc_abi::pwd_abi::fgetsgent_r;
    let mut sgrp_storage = std::mem::MaybeUninit::<TestSgrp>::uninit();
    let mut buf = vec![0u8; 512];
    let mut result_ptr: *mut u8 = ptr::null_mut();

    let rc = unsafe {
        fgetsgent_r(
            ptr::null_mut(),
            sgrp_storage.as_mut_ptr() as *mut _,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result_ptr as *mut *mut u8 as *mut *mut _,
        )
    };
    assert!(result_ptr.is_null());
    assert_ne!(rc, 0, "fgetsgent_r with null stream should fail");
}

#[test]
fn sgetsgent_null_returns_null() {
    use frankenlibc_abi::pwd_abi::sgetsgent;
    let result = unsafe { sgetsgent(ptr::null()) };
    assert!(result.is_null(), "sgetsgent(null) should return null");
}

#[repr(C)]
struct TestSgrp {
    sg_namp: *mut c_char,
    sg_passwd: *mut c_char,
    sg_adm: *mut *mut c_char,
    sg_mem: *mut *mut c_char,
}

fn assert_gshadow_caller_storage(entry: &TestSgrp, buffer: *mut c_char, capacity: usize) {
    let start = buffer as usize;
    let end = start + capacity;
    let check_string = |value: *mut c_char| {
        let address = value as usize;
        assert!(
            address >= start && address < end,
            "string escapes caller buffer"
        );
        let remaining = unsafe { std::slice::from_raw_parts(value.cast::<u8>(), end - address) };
        assert!(remaining.contains(&0), "string lacks a bounded terminator");
    };
    check_string(entry.sg_namp);
    check_string(entry.sg_passwd);
    for table in [entry.sg_adm, entry.sg_mem] {
        let address = table as usize;
        assert_eq!(address % std::mem::align_of::<*mut c_char>(), 0);
        assert!(
            address >= start && address < end,
            "list escapes caller buffer"
        );
        let slots = (end - address) / std::mem::size_of::<*mut c_char>();
        let mut terminated = false;
        for index in 0..slots {
            let value = unsafe { *table.add(index) };
            if value.is_null() {
                terminated = true;
                break;
            }
            check_string(value);
        }
        assert!(terminated, "list lacks a bounded NULL terminator");
    }
}

#[test]
fn gshadow_string_result_ownership_alignment_and_retry_boundaries() {
    use frankenlibc_abi::pwd_abi::sgetsgent_r;

    let line = c"team:!:a,b:m,n";
    for offset in 0..8 {
        let mut bytes = [0xa5u8; 256];
        let buffer = unsafe { bytes.as_mut_ptr().add(16 + offset).cast::<c_char>() };
        let text_end = line.to_bytes_with_nul().len();
        let alignment = std::mem::align_of::<*mut c_char>();
        let padding = (buffer as usize + text_end).wrapping_neg() & (alignment - 1);
        let minimum = text_end + padding + 7 * std::mem::size_of::<*mut c_char>();
        for capacity in [1, minimum - 1, minimum] {
            bytes.fill(0xa5);
            let mut entry = std::mem::MaybeUninit::<TestSgrp>::uninit();
            let sentinel = ptr::dangling_mut::<c_void>();
            let mut result = sentinel;
            unsafe { *__errno_location() = 717 };
            let rc = unsafe {
                sgetsgent_r(
                    line.as_ptr(),
                    entry.as_mut_ptr().cast(),
                    buffer,
                    capacity,
                    &mut result,
                )
            };
            assert!(bytes[..16 + offset].iter().all(|&byte| byte == 0xa5));
            assert!(
                bytes[16 + offset + capacity..]
                    .iter()
                    .all(|&byte| byte == 0xa5)
            );
            if capacity < minimum {
                assert_eq!(rc, libc::ERANGE);
                assert_eq!(unsafe { *__errno_location() }, libc::ERANGE);
                assert_eq!(
                    result,
                    if capacity == 1 {
                        sentinel
                    } else {
                        ptr::null_mut()
                    }
                );
                continue;
            }
            assert_eq!(rc, 0);
            assert_eq!(unsafe { *__errno_location() }, 717);
            assert_eq!(
                result,
                entry.as_mut_ptr().cast(),
                "must return the supplied sgrp"
            );
            let entry = unsafe { entry.assume_init() };
            assert_gshadow_caller_storage(&entry, buffer, capacity);
            unsafe {
                assert_eq!(CStr::from_ptr(entry.sg_namp).to_bytes(), b"team");
                assert_eq!(CStr::from_ptr(*entry.sg_adm.add(1)).to_bytes(), b"b");
                assert_eq!(CStr::from_ptr(*entry.sg_mem.add(1)).to_bytes(), b"n");
            }
        }
    }
    for line in [c"", c":::", c"g"] {
        let mut entry = std::mem::MaybeUninit::<TestSgrp>::uninit();
        let mut buffer = [0u8; 128];
        let mut result = ptr::null_mut();
        assert_eq!(
            unsafe {
                sgetsgent_r(
                    line.as_ptr(),
                    entry.as_mut_ptr().cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut result,
                )
            },
            0
        );
        let entry = unsafe { entry.assume_init() };
        assert_gshadow_caller_storage(&entry, buffer.as_mut_ptr().cast(), buffer.len());
        assert!(
            unsafe { CStr::from_ptr(entry.sg_passwd) }
                .to_bytes()
                .is_empty()
        );
        assert!(unsafe { *entry.sg_adm }.is_null());
        assert!(unsafe { *entry.sg_mem }.is_null());
    }
}

#[test]
fn gshadow_stream_long_records_retry_and_eof() {
    use frankenlibc_abi::pwd_abi::{fgetsgent, fgetsgent_r};
    use frankenlibc_abi::stdio_abi::{fclose, feof, fmemopen, fseeko, ftello};

    let name = "g".repeat(5000);
    let mut image = format!("# comment\n{name}:!:alice,bob:carol,dave\nlast:!::\n").into_bytes();
    let stream = unsafe { fmemopen(image.as_mut_ptr().cast(), image.len(), c"r".as_ptr()) };
    assert!(!stream.is_null());
    struct Close(*mut c_void);
    impl Drop for Close {
        fn drop(&mut self) {
            unsafe { fclose(self.0) };
        }
    }
    let _close = Close(stream);
    let mut entry = std::mem::MaybeUninit::<TestSgrp>::uninit();
    let mut buffer = vec![0u8; 16384];
    let mut result = ptr::null_mut();
    assert_eq!(
        unsafe {
            fgetsgent_r(
                stream,
                entry.as_mut_ptr().cast(),
                buffer.as_mut_ptr().cast(),
                64,
                &mut result,
            )
        },
        libc::ERANGE
    );
    assert!(result.is_null());
    assert_eq!(
        unsafe { ftello(stream) },
        10,
        "retry must retain the long record"
    );
    unsafe { *__errno_location() = 717 };
    assert_eq!(
        unsafe {
            fgetsgent_r(
                stream,
                entry.as_mut_ptr().cast(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        },
        0
    );
    assert_eq!(unsafe { *__errno_location() }, 717);
    assert_eq!(result, entry.as_mut_ptr().cast());
    let value = unsafe { entry.assume_init_ref() };
    assert_gshadow_caller_storage(value, buffer.as_mut_ptr().cast(), buffer.len());
    assert_eq!(
        unsafe { CStr::from_ptr(value.sg_namp) }.to_bytes(),
        name.as_bytes()
    );
    assert_eq!(unsafe { fseeko(stream, 0, libc::SEEK_SET) }, 0);
    let answer = unsafe { fgetsgent(stream).cast::<TestSgrp>() };
    assert!(!answer.is_null());
    assert_eq!(
        unsafe { CStr::from_ptr((*answer).sg_namp) }.to_bytes(),
        name.as_bytes(),
        "nonreentrant answers must grow beyond 4096 bytes"
    );
    let last = unsafe { fgetsgent(stream).cast::<TestSgrp>() };
    assert!(!last.is_null());
    assert_eq!(
        unsafe { CStr::from_ptr((*last).sg_namp) }.to_bytes(),
        b"last"
    );
    assert!(unsafe { fgetsgent(stream) }.is_null());
    assert_eq!(unsafe { *__errno_location() }, libc::ENOENT);
    assert_ne!(unsafe { feof(stream) }, 0);
}

#[test]
fn gshadow_files_provider_preserves_retry_and_lookup_cursor() {
    use frankenlibc_abi::pwd_abi::getsgent_r;
    use frankenlibc_abi::unistd_abi::{
        _nss_files_getsgent_r, _nss_files_getsgnam_r, _nss_files_setsgent,
    };

    with_mode_and_gshadow_fixture("strict", || {
        let mut entry = std::mem::MaybeUninit::<TestSgrp>::uninit();
        let mut buffer = [0u8; 512];
        let mut result = ptr::null_mut();
        let mut error = 717;
        assert_eq!(
            unsafe {
                getsgent_r(
                    entry.as_mut_ptr().cast(),
                    buffer.as_mut_ptr().cast(),
                    1,
                    &mut result,
                )
            },
            libc::ERANGE
        );
        assert!(result.is_null());
        assert_eq!(
            unsafe {
                _nss_files_getsgent_r(
                    entry.as_mut_ptr().cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut error,
                )
            },
            1
        );
        assert_eq!(error, 717);
        assert_eq!(
            unsafe { CStr::from_ptr(entry.assume_init_ref().sg_namp) }.to_bytes(),
            b"wheel"
        );
        assert_eq!(
            unsafe {
                _nss_files_getsgnam_r(
                    c"ops".as_ptr(),
                    entry.as_mut_ptr().cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut error,
                )
            },
            1
        );
        assert_eq!(error, 717);
        assert_eq!(
            unsafe {
                getsgent_r(
                    entry.as_mut_ptr().cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut result,
                )
            },
            0
        );
        assert_eq!(result, entry.as_mut_ptr().cast());
        assert_eq!(
            unsafe { CStr::from_ptr(entry.assume_init_ref().sg_namp) }.to_bytes(),
            b"ops",
            "keyed lookup must not advance enumeration"
        );
        assert_eq!(
            unsafe {
                getsgent_r(
                    entry.as_mut_ptr().cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut result,
                )
            },
            libc::ENOENT
        );
        assert!(result.is_null());
        assert_eq!(
            unsafe {
                _nss_files_getsgent_r(
                    entry.as_mut_ptr().cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut error,
                )
            },
            0
        );
        assert_eq!(error, 717);
        assert_eq!(unsafe { _nss_files_setsgent(0) }, 1);
        assert_eq!(
            unsafe {
                _nss_files_getsgent_r(
                    entry.as_mut_ptr().cast(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut error,
                )
            },
            1
        );
        assert_eq!(
            unsafe { CStr::from_ptr(entry.assume_init_ref().sg_namp) }.to_bytes(),
            b"wheel"
        );
    });
}

fn assert_gshadow_files_backend_iterates_and_looks_up(mode: &str) {
    with_mode_and_gshadow_fixture(mode, || {
        let first = unsafe { frankenlibc_abi::pwd_abi::getsgent() };
        assert!(!first.is_null(), "{mode}: getsgent should return first row");
        let first = unsafe { &*(first.cast::<TestSgrp>()) };
        assert_eq!(
            unsafe { CStr::from_ptr(first.sg_namp) }.to_bytes(),
            b"wheel"
        );
        let first_member = unsafe { *first.sg_mem };
        assert_eq!(unsafe { CStr::from_ptr(first_member) }.to_bytes(), b"root");

        let name = CString::new("ops").unwrap();
        let looked_up = unsafe { frankenlibc_abi::pwd_abi::getsgnam(name.as_ptr()) };
        assert!(
            !looked_up.is_null(),
            "{mode}: getsgnam(ops) should find fixture row"
        );
        let looked_up = unsafe { &*(looked_up.cast::<TestSgrp>()) };
        assert_eq!(
            unsafe { CStr::from_ptr(looked_up.sg_namp) }.to_bytes(),
            b"ops"
        );
        let admin = unsafe { *looked_up.sg_adm };
        assert_eq!(unsafe { CStr::from_ptr(admin) }.to_bytes(), b"alice");
        let member0 = unsafe { *looked_up.sg_mem };
        let member1 = unsafe { *looked_up.sg_mem.add(1) };
        let member2 = unsafe { *looked_up.sg_mem.add(2) };
        assert_eq!(unsafe { CStr::from_ptr(member0) }.to_bytes(), b"bob");
        assert_eq!(unsafe { CStr::from_ptr(member1) }.to_bytes(), b"carol");
        assert!(member2.is_null(), "{mode}: member list must terminate");
    });
}

#[test]
fn strict_mode_gshadow_files_backend_iterates_and_looks_up() {
    assert_gshadow_files_backend_iterates_and_looks_up("strict");
}

#[test]
fn hardened_mode_gshadow_files_backend_iterates_and_looks_up() {
    assert_gshadow_files_backend_iterates_and_looks_up("hardened");
}

#[test]
fn sgetsgent_valid_line_returns_static_sgrp() {
    use frankenlibc_abi::pwd_abi::sgetsgent;
    let line = CString::new("wheel:!:root:root,daemon").unwrap();
    let result = unsafe { sgetsgent(line.as_ptr()) };
    assert!(!result.is_null(), "sgetsgent(valid) should return sgrp");

    let sgrp = unsafe { &*(result.cast::<TestSgrp>()) };
    assert_eq!(unsafe { CStr::from_ptr(sgrp.sg_namp) }.to_bytes(), b"wheel");
    assert_eq!(unsafe { CStr::from_ptr(sgrp.sg_passwd) }.to_bytes(), b"!");

    let adm0 = unsafe { *sgrp.sg_adm };
    let adm1 = unsafe { *sgrp.sg_adm.add(1) };
    assert_eq!(unsafe { CStr::from_ptr(adm0) }.to_bytes(), b"root");
    assert!(adm1.is_null(), "admin list must be null-terminated");

    let mem0 = unsafe { *sgrp.sg_mem };
    let mem1 = unsafe { *sgrp.sg_mem.add(1) };
    let mem2 = unsafe { *sgrp.sg_mem.add(2) };
    assert_eq!(unsafe { CStr::from_ptr(mem0) }.to_bytes(), b"root");
    assert_eq!(unsafe { CStr::from_ptr(mem1) }.to_bytes(), b"daemon");
    assert!(mem2.is_null(), "member list must be null-terminated");
}

#[test]
fn sgetsgent_r_null_returns_error() {
    use frankenlibc_abi::pwd_abi::sgetsgent_r;
    let mut sgrp_storage = std::mem::MaybeUninit::<TestSgrp>::uninit();
    let mut buf = vec![0u8; 512];
    let mut result_ptr: *mut u8 = ptr::null_mut();

    let rc = unsafe {
        sgetsgent_r(
            ptr::null(),
            sgrp_storage.as_mut_ptr() as *mut _,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result_ptr as *mut *mut u8 as *mut *mut _,
        )
    };
    assert!(result_ptr.is_null());
    assert_ne!(rc, 0, "sgetsgent_r with null string should fail");
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn sgetsgent_r_rejects_unterminated_string() {
    use frankenlibc_abi::pwd_abi::sgetsgent_r;
    unsafe {
        let line = b"wheel:!:root";
        let unterminated = malloc(line.len()).cast::<u8>();
        assert!(!unterminated.is_null());
        std::ptr::copy_nonoverlapping(line.as_ptr(), unterminated, line.len());
        let mut sgrp_storage = std::mem::MaybeUninit::<TestSgrp>::uninit();
        let mut buf = vec![0u8; 512];
        let mut result_ptr: *mut u8 = ptr::null_mut();

        let rc = sgetsgent_r(
            unterminated.cast(),
            sgrp_storage.as_mut_ptr() as *mut _,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result_ptr as *mut *mut u8 as *mut *mut _,
        );
        free(unterminated.cast());
        assert_eq!(rc, libc::EINVAL);
        assert!(result_ptr.is_null());
    }
}

#[test]
fn putsgent_null_returns_error() {
    use frankenlibc_abi::pwd_abi::putsgent;
    let rc = unsafe { putsgent(ptr::null(), ptr::null_mut()) };
    assert_eq!(rc, -1, "putsgent with null args should fail");
}

// ---------------------------------------------------------------------------
// Strict/Hardened Mode Tests (bd-x2sq)
// ---------------------------------------------------------------------------

/// Static mutex for mode env var manipulation (process-global).
static MODE_ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_mode(mode: &str, f: impl FnOnce()) {
    let _guard = MODE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: Serialized by MODE_ENV_LOCK.
    unsafe { std::env::set_var("FRANKENLIBC_MODE", mode) };
    f();
    // SAFETY: Same as above.
    unsafe { std::env::remove_var("FRANKENLIBC_MODE") };
}

fn with_mode_and_passwd(mode: &str, passwd_content: &[u8], f: impl FnOnce()) {
    let _mode_guard = MODE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _passwd_guard = PASSWD_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let path = temp_passwd_path();
    std::fs::write(&path, passwd_content).expect("write temp passwd");

    // SAFETY: Serialized by both locks.
    unsafe {
        std::env::set_var("FRANKENLIBC_MODE", mode);
        std::env::set_var("FRANKENLIBC_PASSWD_PATH", &path);
    }
    f();
    // SAFETY: Same as above.
    unsafe {
        std::env::remove_var("FRANKENLIBC_MODE");
        std::env::remove_var("FRANKENLIBC_PASSWD_PATH");
    }
    let _ = std::fs::remove_file(&path);
}

fn with_mode_and_gshadow_fixture(mode: &str, f: impl FnOnce()) {
    let _mode_guard = MODE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _gshadow_guard = GSHADOW_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = gshadow_fixture_path();
    assert!(
        path.exists(),
        "gshadow fixture missing at {}",
        path.display()
    );

    // SAFETY: Serialized by both locks.
    unsafe {
        std::env::set_var("FRANKENLIBC_MODE", mode);
        std::env::set_var("FRANKENLIBC_GSHADOW_PATH", &path);
        frankenlibc_abi::pwd_abi::setsgent();
    }
    f();
    // SAFETY: Same as above.
    unsafe {
        frankenlibc_abi::pwd_abi::endsgent();
        std::env::remove_var("FRANKENLIBC_GSHADOW_PATH");
        std::env::remove_var("FRANKENLIBC_MODE");
    }
}

#[test]
fn strict_mode_getpwnam_returns_null_for_invalid() {
    with_mode_and_passwd("strict", FIXTURE, || {
        let name = CString::new("nonexistent_user_strict_test").unwrap();
        let pw = unsafe { getpwnam(name.as_ptr()) };
        assert!(
            pw.is_null(),
            "strict mode: getpwnam for nonexistent user should return null"
        );
    });
}

#[test]
fn strict_mode_getpwuid_returns_null_for_invalid_uid() {
    with_mode_and_passwd("strict", FIXTURE, || {
        let pw = unsafe { getpwuid(99999) };
        assert!(
            pw.is_null(),
            "strict mode: getpwuid for nonexistent uid should return null"
        );
    });
}

#[test]
fn hardened_mode_getpwnam_returns_null_for_invalid() {
    with_mode_and_passwd("hardened", FIXTURE, || {
        let name = CString::new("nonexistent_user_hardened_test").unwrap();
        let pw = unsafe { getpwnam(name.as_ptr()) };
        // In hardened mode, invalid lookups still return null (no healing for missing entries).
        assert!(
            pw.is_null(),
            "hardened mode: getpwnam for nonexistent user should return null"
        );
    });
}

#[test]
fn hardened_mode_getpwuid_returns_null_for_invalid_uid() {
    with_mode_and_passwd("hardened", FIXTURE, || {
        let pw = unsafe { getpwuid(99999) };
        // In hardened mode, invalid lookups still return null.
        assert!(
            pw.is_null(),
            "hardened mode: getpwuid for nonexistent uid should return null"
        );
    });
}

#[test]
fn strict_mode_getpwnam_null_input_returns_null() {
    with_mode("strict", || {
        let pw = unsafe { getpwnam(ptr::null()) };
        assert!(
            pw.is_null(),
            "strict mode: getpwnam(null) should return null"
        );
    });
}

#[test]
fn hardened_mode_getpwnam_null_input_returns_null() {
    with_mode("hardened", || {
        let pw = unsafe { getpwnam(ptr::null()) };
        assert!(
            pw.is_null(),
            "hardened mode: getpwnam(null) should return null"
        );
    });
}

#[test]
fn strict_mode_pwent_iteration_works() {
    with_mode_and_passwd("strict", FIXTURE, || {
        unsafe { setpwent() };
        let mut count = 0;
        loop {
            let pw = unsafe { getpwent() };
            if pw.is_null() {
                break;
            }
            count += 1;
            assert!(
                count <= 10,
                "strict mode: pwent iteration should not infinite loop"
            );
        }
        unsafe { endpwent() };
        assert_eq!(count, 3, "strict mode: fixture has 3 entries");
    });
}

#[test]
fn hardened_mode_pwent_iteration_works() {
    with_mode_and_passwd("hardened", FIXTURE, || {
        unsafe { setpwent() };
        let mut count = 0;
        loop {
            let pw = unsafe { getpwent() };
            if pw.is_null() {
                break;
            }
            count += 1;
            assert!(
                count <= 10,
                "hardened mode: pwent iteration should not infinite loop"
            );
        }
        unsafe { endpwent() };
        assert_eq!(count, 3, "hardened mode: fixture has 3 entries");
    });
}

// ---------------------------------------------------------------------------
// uid_from_user / user_from_uid (BSD libutil pwcache)
// ---------------------------------------------------------------------------

#[test]
fn uid_from_user_resolves_known_name() {
    use frankenlibc_abi::pwd_abi::uid_from_user;
    with_passwd_file(FIXTURE, || {
        let name = CString::new("alice").unwrap();
        let mut uid: libc::uid_t = u32::MAX;
        let rc = unsafe { uid_from_user(name.as_ptr(), &mut uid) };
        assert_eq!(rc, 0);
        assert_eq!(uid, 1000);
    });
}

#[test]
fn uid_from_user_returns_minus_one_for_unknown() {
    use frankenlibc_abi::pwd_abi::uid_from_user;
    with_passwd_file(FIXTURE, || {
        let name = CString::new("nosuchuser").unwrap();
        let mut uid: libc::uid_t = 999;
        let rc = unsafe { uid_from_user(name.as_ptr(), &mut uid) };
        assert_eq!(rc, -1);
        assert_eq!(uid, 999, "uid output must be untouched on failure");
    });
}

#[test]
fn uid_from_user_null_name_is_error() {
    use frankenlibc_abi::pwd_abi::uid_from_user;
    let mut uid: libc::uid_t = 0;
    let rc = unsafe { uid_from_user(ptr::null(), &mut uid) };
    assert_eq!(rc, -1);
}

#[test]
fn uid_from_user_null_uid_pointer_skips_write() {
    use frankenlibc_abi::pwd_abi::uid_from_user;
    with_passwd_file(FIXTURE, || {
        let name = CString::new("bob").unwrap();
        let rc = unsafe { uid_from_user(name.as_ptr(), ptr::null_mut()) };
        assert_eq!(rc, 0, "lookup must still succeed with NULL uid pointer");
    });
}

#[test]
fn user_from_uid_resolves_known_uid() {
    use frankenlibc_abi::pwd_abi::user_from_uid;
    with_passwd_file(FIXTURE, || {
        let p = unsafe { user_from_uid(1000, 0) };
        assert!(!p.is_null());
        let bytes = unsafe { CStr::from_ptr(p).to_bytes() };
        assert_eq!(bytes, b"alice");
    });
}

#[test]
fn user_from_uid_unknown_returns_null_when_nouser_zero() {
    use frankenlibc_abi::pwd_abi::user_from_uid;
    with_passwd_file(FIXTURE, || {
        let p = unsafe { user_from_uid(99999, 0) };
        assert!(p.is_null(), "missing uid + nouser=0 must return NULL");
    });
}

#[test]
fn user_from_uid_unknown_with_nouser_returns_decimal_string() {
    use frankenlibc_abi::pwd_abi::user_from_uid;
    with_passwd_file(FIXTURE, || {
        let p = unsafe { user_from_uid(424242, 1) };
        assert!(
            !p.is_null(),
            "nouser=1 must always return a non-NULL pointer"
        );
        let bytes = unsafe { CStr::from_ptr(p).to_bytes() };
        assert_eq!(bytes, b"424242");
    });
}

#[test]
fn user_from_uid_zero_with_nouser_renders_zero() {
    use frankenlibc_abi::pwd_abi::user_from_uid;
    // Use a fixture that does NOT have uid=0 so the fallback path triggers.
    let no_root: &[u8] =
        b"alice:x:1000:1000:Alice:/home/alice:/bin/sh\nbob:x:1001:1001:Bob:/home/bob:/bin/zsh\n";
    with_passwd_file(no_root, || {
        let p = unsafe { user_from_uid(0, 1) };
        assert!(!p.is_null());
        let bytes = unsafe { CStr::from_ptr(p).to_bytes() };
        assert_eq!(bytes, b"0");
    });
}

// Shadow fixtures run in a fresh process so their backend override cannot
// change another test's host-shadow oracle or process-level runtime mode.
fn with_shadow_fixture(test: &str, content: Option<&[u8]>, run: impl FnOnce()) {
    if std::env::var("FRANKENLIBC_SHADOW_TEST_CHILD").as_deref() == Ok(test) {
        run();
        return;
    }
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "frankenlibc-shadow-test-{}-{seq}-{test}",
        std::process::id()
    ));
    assert!(!path.exists());
    if let Some(content) = content {
        std::fs::write(&path, content).expect("write isolated shadow fixture");
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env("FRANKENLIBC_SHADOW_TEST_CHILD", test)
        .env("FRANKENLIBC_SHADOW_PATH", &path)
        .output()
        .expect("run isolated shadow test");
    assert!(
        output.status.success(),
        "shadow child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed; 0 failed;"),
        "the shadow child must execute exactly one test"
    );
}

const SHADOW_FIXTURE: &[u8] =
    b"# comment\nmalformed\nalpha:!:19000:0:99999:7:::\nbeta:\xffhash:1:2:3:4:5:6:7\n";

#[test]
fn nss_files_shadow_lookup_preserves_fields_and_error_contracts() {
    with_shadow_fixture(
        "nss_files_shadow_lookup_preserves_fields_and_error_contracts",
        Some(SHADOW_FIXTURE),
        || {
            // SAFETY: every output slot is live, aligned caller storage.
            unsafe {
                let mut entry: libc::spwd = std::mem::zeroed();
                let mut buffer = [0xa5u8; 256];
                let mut error = 717;
                *__errno_location() = 718;
                assert_eq!(
                    _nss_files_getspnam_r(
                        c"beta".as_ptr(),
                        (&raw mut entry).cast(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        &mut error,
                    ),
                    1
                );
                assert_eq!((error, *__errno_location()), (717, 718));
                assert_eq!(CStr::from_ptr(entry.sp_namp).to_bytes(), b"beta");
                assert_eq!(CStr::from_ptr(entry.sp_pwdp).to_bytes(), b"\xffhash");
                assert_eq!(
                    (
                        entry.sp_lstchg,
                        entry.sp_min,
                        entry.sp_max,
                        entry.sp_warn,
                        entry.sp_inact,
                        entry.sp_expire,
                        entry.sp_flag
                    ),
                    (1, 2, 3, 4, 5, 6, 7)
                );
                assert_eq!(
                    _nss_files_getspnam_r(
                        c"missing".as_ptr(),
                        (&raw mut entry).cast(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        &mut error,
                    ),
                    0
                );
                assert_eq!((error, *__errno_location()), (717, 718));
                for capacity in [0, 1, 2, 8] {
                    buffer.fill(0xa5);
                    error = 717;
                    *__errno_location() = 718;
                    assert_eq!(
                        _nss_files_getspnam_r(
                            c"missing".as_ptr(),
                            (&raw mut entry).cast(),
                            buffer.as_mut_ptr().cast(),
                            capacity,
                            &mut error,
                        ),
                        -2
                    );
                    assert_eq!(error, libc::ERANGE);
                    assert_eq!(
                        *__errno_location(),
                        if capacity < 2 { 718 } else { libc::ERANGE }
                    );
                    assert!(buffer.iter().all(|&byte| byte == 0xa5));
                }
                assert_eq!(
                    _nss_files_getspnam_r(
                        c"alpha".as_ptr(),
                        (&raw mut entry).cast(),
                        buffer.as_mut_ptr().cast(),
                        1,
                        __errno_location(),
                    ),
                    -2
                );
                assert_eq!(*__errno_location(), libc::ERANGE);
                _nss_files_endspent();
            }
        },
    );
}

#[test]
fn nss_files_shadow_enumeration_retries_rewinds_and_keeps_lookup_separate() {
    const RECORDS: &[u8] = b"alpha:!:1:2:3:4:5:6:7\nbeta:*:::::::\n";
    const FIRST: &[u8] = b"alpha:!:1:2:3:4:5:6:7\n";
    with_shadow_fixture(
        "nss_files_shadow_enumeration_retries_rewinds_and_keeps_lookup_separate",
        Some(RECORDS),
        || {
            // SAFETY: all record, buffer and errno pointers remain valid.
            unsafe {
                let mut entry: libc::spwd = std::mem::zeroed();
                let mut buffer = [0xa5u8; 256];
                let mut error = 717;
                *__errno_location() = 718;
                assert_eq!(_nss_files_setspent(1), 1);
                assert_eq!(*__errno_location(), 718);
                for capacity in [0, 1, 2, FIRST.len() + 1] {
                    assert_eq!(
                        _nss_files_getspent_r(
                            (&raw mut entry).cast(),
                            buffer.as_mut_ptr().cast(),
                            capacity,
                            &mut error,
                        ),
                        -2
                    );
                    assert_eq!(error, libc::ERANGE);
                    assert!(buffer.iter().all(|&byte| byte == 0xa5));
                }
                assert_eq!(
                    _nss_files_getspent_r(
                        (&raw mut entry).cast(),
                        buffer.as_mut_ptr().cast(),
                        FIRST.len() + 2,
                        &mut error,
                    ),
                    1
                );
                assert_eq!(CStr::from_ptr(entry.sp_namp).to_bytes(), b"alpha");
                assert_eq!(
                    _nss_files_getspnam_r(
                        c"alpha".as_ptr(),
                        (&raw mut entry).cast(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        &mut error,
                    ),
                    1
                );
                assert_eq!(
                    _nss_files_getspent_r(
                        (&raw mut entry).cast(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        &mut error,
                    ),
                    1
                );
                assert_eq!(CStr::from_ptr(entry.sp_namp).to_bytes(), b"beta");
                assert_eq!(entry.sp_flag, libc::c_ulong::MAX);
                error = 717;
                *__errno_location() = 718;
                assert_eq!(
                    _nss_files_getspent_r(
                        (&raw mut entry).cast(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        &mut error,
                    ),
                    0
                );
                assert_eq!((error, *__errno_location()), (717, 718));
                // The minimum reader capacity is checked even at EOF.
                assert_eq!(
                    _nss_files_getspent_r(
                        (&raw mut entry).cast(),
                        buffer.as_mut_ptr().cast(),
                        1,
                        &mut error,
                    ),
                    -2
                );
                for explicit_rewind in [true, false] {
                    if explicit_rewind {
                        assert_eq!(_nss_files_setspent(0), 1);
                    } else {
                        assert_eq!(_nss_files_endspent(), 1);
                    }
                    assert_eq!(
                        _nss_files_getspent_r(
                            (&raw mut entry).cast(),
                            buffer.as_mut_ptr().cast(),
                            buffer.len(),
                            &mut error,
                        ),
                        1
                    );
                    assert_eq!(CStr::from_ptr(entry.sp_namp).to_bytes(), b"alpha");
                }
                _nss_files_endspent();
            }
        },
    );
}

#[test]
fn nss_files_shadow_backend_failure_retries_after_file_appears() {
    with_shadow_fixture(
        "nss_files_shadow_backend_failure_retries_after_file_appears",
        None,
        || {
            // SAFETY: outputs are valid even while the backend is unavailable.
            unsafe {
                let mut entry: libc::spwd = std::mem::zeroed();
                let mut buffer = [0u8; 256];
                let mut error = 717;
                assert_eq!(_nss_files_setspent(0), -1);
                assert_eq!(*__errno_location(), libc::ENOENT);
                assert_eq!(
                    _nss_files_getspnam_r(
                        c"alpha".as_ptr(),
                        (&raw mut entry).cast(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        &mut error,
                    ),
                    -1
                );
                assert_eq!(error, libc::ENOENT);
                assert_eq!(
                    _nss_files_getspent_r(
                        (&raw mut entry).cast(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        &mut error,
                    ),
                    -1
                );
                assert_eq!(error, libc::ENOENT);
                let path = std::env::var_os("FRANKENLIBC_SHADOW_PATH").unwrap();
                std::fs::write(path, SHADOW_FIXTURE).unwrap();
                assert_eq!(
                    _nss_files_getspent_r(
                        (&raw mut entry).cast(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        &mut error,
                    ),
                    1
                );
                assert_eq!(CStr::from_ptr(entry.sp_namp).to_bytes(), b"alpha");
                _nss_files_endspent();
            }
        },
    );
}

#[test]
fn nss_files_shadow_public_enumeration_preserves_non_utf8_records() {
    with_shadow_fixture(
        "nss_files_shadow_public_enumeration_preserves_non_utf8_records",
        Some(SHADOW_FIXTURE),
        || {
            use frankenlibc_abi::pwd_abi::{endspent, getspent_r, setspent};
            setspent();
            for expected_name in [b"alpha".as_slice(), b"beta"] {
                // SAFETY: caller-provided record, string and result storage.
                unsafe {
                    let mut entry: libc::spwd = std::mem::zeroed();
                    let mut buffer = [0u8; 256];
                    let mut result = ptr::null_mut();
                    assert_eq!(
                        getspent_r(
                            (&raw mut entry).cast(),
                            buffer.as_mut_ptr().cast(),
                            buffer.len(),
                            &mut result,
                        ),
                        0
                    );
                    assert_eq!(result, (&raw mut entry).cast());
                    assert_eq!(CStr::from_ptr(entry.sp_namp).to_bytes(), expected_name);
                    if expected_name == b"beta" {
                        assert_eq!(CStr::from_ptr(entry.sp_pwdp).to_bytes(), b"\xffhash");
                    }
                }
            }
            endspent();
        },
    );
}

#[test]
fn nss_files_shadow_reader_capacity_matches_host_fgetspent() {
    with_shadow_fixture(
        "nss_files_shadow_reader_capacity_matches_host_fgetspent",
        Some(b""),
        || {
            type HostOpen = unsafe extern "C" fn(*mut c_void, usize, *const c_char) -> *mut c_void;
            type HostClose = unsafe extern "C" fn(*mut c_void) -> libc::c_int;
            type HostRead = unsafe extern "C" fn(
                *mut c_void,
                *mut c_void,
                *mut c_char,
                usize,
                *mut *mut c_void,
            ) -> libc::c_int;
            // Resolve all three operations from host libc so a host FILE
            // never crosses ownership domains. The resolver rejects our own
            // exported definitions instead of allowing a self-comparison.
            let (open, close, read): (HostOpen, HostClose, HostRead) = unsafe {
                (
                    dlsym_oracle::host_fn(
                        c"fmemopen",
                        frankenlibc_abi::stdio_abi::fmemopen as *const (),
                    ),
                    dlsym_oracle::host_fn(
                        c"fclose",
                        frankenlibc_abi::stdio_abi::fclose as *const (),
                    ),
                    dlsym_oracle::host_fn(
                        c"fgetspent_r",
                        frankenlibc_abi::unistd_abi::fgetspent_r as *const (),
                    ),
                )
            };
            let path = std::env::var_os("FRANKENLIBC_SHADOW_PATH").unwrap();
            let cases: &[&[u8]] = &[
                b"",
                b"\n",
                b"# comment\n",
                b"malformed\n",
                b"alpha:!:1:2:3:4:5:6:7\n",
                b"alpha:!:1:2:3:4:5:6:7",
                b"beta:\xffhash:1:2:3:4:5:6:7\n",
                b"# a longer skipped physical line before the record\nalpha:!:1:2:3:4:5:6:7\n",
            ];
            let mut compared = 0;
            for &content in cases {
                std::fs::write(&path, content).unwrap();
                let mut capacities = vec![
                    0,
                    1,
                    2,
                    3,
                    content.len(),
                    content.len() + 1,
                    content.len() + 2,
                    128,
                ];
                capacities.sort_unstable();
                capacities.dedup();
                for capacity in capacities {
                    let mut memory = content.to_vec();
                    memory.push(0);
                    // SAFETY: the backing bytes remain live until the paired
                    // host fclose; an empty stream has a non-null allocation.
                    let stream =
                        unsafe { open(memory.as_mut_ptr().cast(), content.len(), c"r".as_ptr()) };
                    assert!(!stream.is_null(), "host fmemopen failed");
                    // SAFETY: reset only this child's private files cursor.
                    unsafe { _nss_files_endspent() };
                    // The second read proves ERANGE retry and EOF behavior,
                    // independently of our physical-line size calculation.
                    for requested in [capacity, 128] {
                        // SAFETY: spwd contains only integer/pointer fields.
                        let mut host_entry: libc::spwd = unsafe { std::mem::zeroed() };
                        let mut candidate: libc::spwd = unsafe { std::mem::zeroed() };
                        let mut host_buffer = [0u8; 256];
                        let mut candidate_buffer = [0u8; 256];
                        let mut result = ptr::null_mut();
                        let mut error = 717;
                        // SAFETY: both calls receive independent live storage
                        // with sufficient extent for every requested capacity.
                        let expected = unsafe {
                            read(
                                stream,
                                (&raw mut host_entry).cast(),
                                host_buffer.as_mut_ptr().cast(),
                                requested,
                                &mut result,
                            )
                        };
                        let actual = unsafe {
                            _nss_files_getspent_r(
                                (&raw mut candidate).cast(),
                                candidate_buffer.as_mut_ptr().cast(),
                                requested,
                                &mut error,
                            )
                        };
                        let expected_status = match expected {
                            0 => 1,
                            libc::ENOENT => 0,
                            libc::ERANGE => -2,
                            other => panic!("unexpected host fgetspent_r error {other}"),
                        };
                        assert_eq!(
                            actual, expected_status,
                            "shadow reader content={content:?} capacity={requested}"
                        );
                        if expected == 0 {
                            assert!(!result.is_null());
                            // SAFETY: successful readers published terminated
                            // fields in their respective live caller buffers.
                            unsafe {
                                assert_eq!(
                                    CStr::from_ptr(candidate.sp_namp).to_bytes(),
                                    CStr::from_ptr(host_entry.sp_namp).to_bytes()
                                );
                                assert_eq!(
                                    CStr::from_ptr(candidate.sp_pwdp).to_bytes(),
                                    CStr::from_ptr(host_entry.sp_pwdp).to_bytes()
                                );
                            }
                        } else if expected == libc::ERANGE {
                            assert_eq!(error, libc::ERANGE);
                        }
                        compared += 1;
                    }
                    // SAFETY: exactly the host stream returned by open above.
                    assert_eq!(unsafe { close(stream) }, 0);
                }
            }
            assert!(
                compared > 100,
                "host reader comparison must execute its corpus"
            );
            eprintln!("shadow files reader: {compared} independent host comparisons");
            // SAFETY: release only this child's private files cursor.
            unsafe { _nss_files_endspent() };
        },
    );
}

// The private NSS parser ABI is used by native NSS modules. Resolve GNU's
// definitions independently: an exported always-skip body must fail this gate.
type NssAccountParser = unsafe extern "C" fn(
    *mut c_char,
    *mut c_void,
    *mut c_void,
    usize,
    *mut libc::c_int,
) -> libc::c_int;

#[derive(Debug, PartialEq, Eq)]
struct NssParserString {
    offset: usize,
    bytes: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct NssParserList {
    offset: usize,
    names: Vec<NssParserString>,
}

#[derive(Debug, PartialEq, Eq)]
struct NssParserObservation {
    status: libc::c_int,
    error: libc::c_int,
    errno: libc::c_int,
    strings: Vec<Option<NssParserString>>,
    numbers: Vec<i128>,
    lists: Vec<Option<NssParserList>>,
}

fn nss_parser_definitions() -> [(&'static CStr, NssAccountParser); 4] {
    use frankenlibc_abi::unistd_abi;
    [
        (
            c"_nss_files_parse_pwent",
            unistd_abi::_nss_files_parse_pwent,
        ),
        (
            c"_nss_files_parse_grent",
            unistd_abi::_nss_files_parse_grent,
        ),
        (
            c"_nss_files_parse_spent",
            unistd_abi::_nss_files_parse_spent,
        ),
        (
            c"_nss_files_parse_sgent",
            unistd_abi::_nss_files_parse_sgent,
        ),
    ]
}

unsafe fn nss_parser_string_snapshot(
    pointer: *const c_char,
    data: *const u8,
    line_start: usize,
    text_end: usize,
) -> Option<NssParserString> {
    if pointer.is_null() {
        return None;
    }
    let offset = (pointer as usize)
        .checked_sub(data as usize)
        .expect("parser string precedes caller storage");
    assert!(
        (line_start..=text_end).contains(&offset),
        "parser string escaped original text: {offset}, {line_start}..={text_end}"
    );
    // SAFETY: the normalized pointer was checked against this live text
    // extent. Find NUL within it before making the owned observation.
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), text_end - offset + 1) };
    let length = bytes
        .iter()
        .position(|&byte| byte == 0)
        .expect("unterminated parser string");
    Some(NssParserString {
        offset,
        bytes: bytes[..length].to_vec(),
    })
}

unsafe fn nss_parser_list_snapshot(
    pointer: *mut *mut c_char,
    data: *const u8,
    text: *const u8,
    line_start: usize,
    text_end: usize,
    capacity: usize,
) -> Option<NssParserList> {
    if pointer.is_null() {
        return None;
    }
    let offset = (pointer as usize)
        .checked_sub(data as usize)
        .expect("parser list precedes caller storage");
    let width = std::mem::size_of::<*mut c_char>();
    assert_eq!((pointer as usize) % std::mem::align_of::<*mut c_char>(), 0);
    let mut names = Vec::new();
    loop {
        let end = offset + (names.len() + 1) * width;
        assert!(
            end <= capacity,
            "parser pointer array exceeds caller capacity"
        );
        let slot_start = pointer as usize + names.len() * width;
        let slot_end = slot_start + width;
        assert!(
            slot_end <= text as usize + line_start || slot_start > text as usize + text_end,
            "pointer array overlaps original text"
        );
        // SAFETY: this aligned pointer slot is within the supplied allocation
        // and disjoint from the independently bounded original text.
        let name = unsafe { pointer.add(names.len()).read() };
        if name.is_null() {
            break;
        }
        // SAFETY: the string helper validates the original text range.
        names
            .push(unsafe { nss_parser_string_snapshot(name, text, line_start, text_end) }.unwrap());
    }
    Some(NssParserList { offset, names })
}

#[allow(clippy::too_many_arguments)]
fn observe_nss_account_parser(
    parser: NssAccountParser,
    family: usize,
    input: &[u8],
    data_offset: usize,
    line_offset: usize,
    capacity: usize,
    host: bool,
    alias_error: bool,
    external_line: bool,
) -> NssParserObservation {
    #[repr(align(16))]
    struct Storage([u8; 512]);
    let mut backing = Storage([0xa5; 512]);
    let mut separate_text = Storage([0xa5; 512]);
    assert!(data_offset + capacity <= backing.0.len());
    let start = if external_line {
        line_offset
    } else {
        data_offset + line_offset
    };
    let text_storage = if external_line {
        &mut separate_text.0
    } else {
        &mut backing.0
    };
    assert!(start + input.len() < text_storage.len());
    if !external_line {
        assert!(line_offset + input.len() < capacity);
    }
    text_storage[start..start + input.len()].copy_from_slice(input);
    text_storage[start + input.len()] = 0;
    let line = unsafe { text_storage.as_mut_ptr().add(start).cast() };
    let mut output = [0xa5a5_a5a5_a5a5_a5a5u64; 16];
    let mut error = 717;
    // SAFETY: both accessors return initialized per-thread errno slots.
    let errno_slot = unsafe {
        if host {
            libc::__errno_location()
        } else {
            __errno_location()
        }
    };
    // SAFETY: the slots and all parser buffers remain live through observation.
    let status = unsafe {
        *libc::__errno_location() = 619;
        *__errno_location() = 619;
        parser(
            line,
            output.as_mut_ptr().cast(),
            backing.0.as_mut_ptr().add(data_offset).cast(),
            capacity,
            if alias_error { errno_slot } else { &mut error },
        )
    };
    // Capture errno before any assertion or allocation can change it.
    let observed_errno = unsafe { *errno_slot };
    if alias_error {
        error = observed_errno;
    }
    assert!(
        backing.0[data_offset + capacity..]
            .iter()
            .all(|&byte| byte == 0xa5),
        "parser wrote beyond the declared buffer capacity"
    );
    if external_line {
        assert!(
            separate_text.0[..line_offset]
                .iter()
                .all(|&byte| byte == 0xa5)
                && separate_text.0[line_offset + input.len() + 1..]
                    .iter()
                    .all(|&byte| byte == 0xa5),
            "parser wrote outside the independently allocated text"
        );
    }
    let mut observed = NssParserObservation {
        status,
        error,
        errno: observed_errno,
        strings: Vec::new(),
        numbers: Vec::new(),
        lists: Vec::new(),
    };
    if status != 1 {
        return observed;
    }
    let data = unsafe { backing.0.as_ptr().add(data_offset) };
    let text = if external_line {
        separate_text.0.as_ptr()
    } else {
        data
    };
    let text_end = line_offset + input.len();
    let mut string = |pointer| {
        // SAFETY: helper bounds every published string before inspecting it.
        observed
            .strings
            .push(unsafe { nss_parser_string_snapshot(pointer, text, line_offset, text_end) });
    };
    // SAFETY: success must initialize the matching complete ABI record.
    // output is large enough and aligned for all four C structures.
    unsafe {
        match family {
            0 => {
                let record = output.as_ptr().cast::<libc::passwd>().read();
                for pointer in [
                    record.pw_name,
                    record.pw_passwd,
                    record.pw_gecos,
                    record.pw_dir,
                    record.pw_shell,
                ] {
                    string(pointer);
                }
                observed.numbers = vec![record.pw_uid.into(), record.pw_gid.into()];
            }
            1 => {
                let record = output.as_ptr().cast::<libc::group>().read();
                string(record.gr_name);
                string(record.gr_passwd);
                observed.numbers = vec![record.gr_gid.into()];
                observed.lists.push(nss_parser_list_snapshot(
                    record.gr_mem,
                    data,
                    text,
                    line_offset,
                    text_end,
                    capacity,
                ));
            }
            2 => {
                let record = output.as_ptr().cast::<libc::spwd>().read();
                string(record.sp_namp);
                string(record.sp_pwdp);
                observed.numbers = vec![
                    record.sp_lstchg.into(),
                    record.sp_min.into(),
                    record.sp_max.into(),
                    record.sp_warn.into(),
                    record.sp_inact.into(),
                    record.sp_expire.into(),
                    record.sp_flag.into(),
                ];
            }
            3 => {
                let record = output.as_ptr().cast::<TestSgrp>().read();
                string(record.sg_namp);
                string(record.sg_passwd);
                for pointer in [record.sg_adm, record.sg_mem] {
                    observed.lists.push(nss_parser_list_snapshot(
                        pointer,
                        data,
                        text,
                        line_offset,
                        text_end,
                        capacity,
                    ));
                }
            }
            _ => unreachable!(),
        }
    }
    observed
}

#[test]
fn nss_account_parser_records_match_gnu_and_upstream_numeric_contract() {
    let corpora: [&[&[u8]]; 4] = [
        &[
            b"alice:x:1000:1001:Name:/home/a:/bin/sh",
            b"a:x:1:2",
            b"a:x:\x0b+1:\x0c2:g:d:s",
            b":x:0:0:::",
            b"  a:x:1:2:g:d:s",
            b"#a:x:1:2:g:d:s",
            b"a:x:1:2:g:d:s:tail",
            b"a:x:1:2:g:d:s\r\n",
            b"a:x:1:2:g:d:s\nignored",
            b"+alice",
            b"+alice:",
            b"+alice::::::",
            b"a:x::2",
            b"invalid",
            b"",
            b"a:x:4294967295:2:g:d:s",
            b"a:x:-18446744073709551615:2:g:d:s",
        ],
        &[
            b"crew:x:1000:alice,bob",
            b"crew:x:1000",
            b"crew:x:1000:",
            b"crew:x:1000: a, b ,c",
            b"crew:x:1000:\x0ba,\x0cb",
            b"crew:x:1000:a,,b,",
            b"crew:x:1000: , ,a, ,b, ",
            b"crew:x:1000:a b,c\td",
            b"crew:x:1000:a\r\n",
            b"crew:x:1000:a\nignored",
            b"+crew",
            b"+crew:",
            b"+crew:::",
            b"+crew::",
            b"invalid",
            b"",
            b"crew:x:4294967295:a",
        ],
        &[
            b"alice:!:18000:0:99999:7:::",
            b"alice:!:::::::",
            b"alice:!:1:2:3",
            b"alice:!:1:2:3:",
            b"alice:!:1:2:3: \t",
            b"alice:!:1:2:3: \t:5:6:7",
            b"alice:!:1:2:3:4:5:6",
            b"alice:!:1:2:3:4:5:6:7",
            b"alice:!:\x0b1:2:3:4:5:6:7",
            b"alice:!:1:2:3:4:5:6:7\nignored",
            b"+alice",
            b"+alice:",
            b"+alice:::::",
            b"alice:!",
            b"alice:!:1:2:3:4",
            b"alice:!:1:2:3:4:5",
            b"alice:!:2147483648:2:3:4:5:6:7",
            b"alice:!:4294967295:2:3:4:5:6:7",
            b"alice:!:1:2:3:4:5:6:7#tail",
            b"alice:!:1:2:3:4:5:6:7\r\n",
        ],
        &[
            b"crew:!:alice:bob,carl",
            b"crew:!::",
            b"crew:!: a, b :c,d",
            b"crew:!:a,,b:,c,,d,",
            b"crew:!:\x0ba:\x0cb",
            b"crew:!:a:b:c",
            b"crew:!:a:b\r\n",
            b"crew:!:a:b\nignored",
            b"+crew",
            b"",
            b"crew",
            b"crew:",
            b"crew:!",
            b"crew:!:",
            b"  crew:!:a:b",
            b"#crew:!:a:b",
        ],
    ];
    let mut comparisons = 0;
    for (family, ((symbol, candidate), inputs)) in nss_parser_definitions()
        .into_iter()
        .zip(corpora)
        .enumerate()
    {
        // SAFETY: the independently resolved symbol has this exact NSS ABI.
        let host: NssAccountParser =
            unsafe { dlsym_oracle::host_fn(symbol, candidate as *const ()) };
        for &input in inputs {
            for data_offset in 0..8 {
                for line_offset in [0, 3] {
                    let expected = observe_nss_account_parser(
                        host,
                        family,
                        input,
                        data_offset,
                        line_offset,
                        384,
                        true,
                        false,
                        false,
                    );
                    let actual = observe_nss_account_parser(
                        candidate,
                        family,
                        input,
                        data_offset,
                        line_offset,
                        384,
                        false,
                        false,
                        false,
                    );
                    assert_eq!(
                        actual, expected,
                        "{symbol:?}, input={input:?}, data_offset={data_offset}, line_offset={line_offset}"
                    );
                    comparisons += 1;
                }
            }
        }
    }
    assert!(comparisons > 500);
    eprintln!("NSS account parser records: {comparisons} independent GNU comparisons");

    // Upstream GNU files-parse.c strtou32 saturates to UINT32_MAX after
    // strtoul, including signed unsigned-long conversion. The Debian
    // 2.41-12+deb13u4 host instead rejects values with high 32 bits set.
    // Pin the upstream contract explicitly for these inputs; all ordinary
    // records above still compare complete results against the independent
    // GNU provider. Keep overflow errno distinct from 32-bit saturation.
    let numeric_cases: &[(usize, &[u8], &[i128], libc::c_int)] = &[
        (0, b"a:x:-1:2:g:d:s", &[4294967295, 2], 619),
        (0, b"a:x:4294967296:2:g:d:s", &[4294967295, 2], 619),
        (
            0,
            b"a:x:18446744073709551615:2:g:d:s",
            &[4294967295, 2],
            619,
        ),
        (
            0,
            b"a:x:18446744073709551616:2:g:d:s",
            &[4294967295, 2],
            libc::ERANGE,
        ),
        (
            0,
            b"a:x:999999999999999999999999999999:2:g:d:s",
            &[4294967295, 2],
            libc::ERANGE,
        ),
        (0, b"a:x:1:-1:g:d:s", &[1, 4294967295], 619),
        (1, b"crew:x:-1:a", &[4294967295], 619),
        (1, b"crew:x:4294967296:a", &[4294967295], 619),
        (
            1,
            b"crew:x:18446744073709551616:a",
            &[4294967295],
            libc::ERANGE,
        ),
        (2, b"alice:!:-1:2:3:4:5:6:7", &[-1, 2, 3, 4, 5, 6, 7], 619),
        (
            2,
            b"alice:!:4294967296:2:3:4:5:6:7",
            &[-1, 2, 3, 4, 5, 6, 7],
            619,
        ),
        (
            2,
            b"alice:!:999999999999999999999999999:2:3:4:5:6:7",
            &[-1, 2, 3, 4, 5, 6, 7],
            libc::ERANGE,
        ),
        (
            2,
            b"alice:!:1:2:3:4:5:6:-1",
            &[1, 2, 3, 4, 5, 6, 4294967295],
            619,
        ),
        (
            2,
            b"alice:!:1:2:3:4:5:6:4294967296",
            &[1, 2, 3, 4, 5, 6, 4294967295],
            619,
        ),
        (
            2,
            b"alice:!:1:2:3:4:5:6:18446744073709551616",
            &[1, 2, 3, 4, 5, 6, 4294967295],
            libc::ERANGE,
        ),
    ];
    let definitions = nss_parser_definitions();
    for &(family, input, numbers, expected_errno) in numeric_cases {
        let (_, candidate) = definitions[family];
        for alias_error in [false, true] {
            let actual = observe_nss_account_parser(
                candidate,
                family,
                input,
                3,
                2,
                384,
                false,
                alias_error,
                false,
            );
            assert_eq!(actual.status, 1, "upstream numeric record: {input:?}");
            assert_eq!(
                actual.numbers, numbers,
                "upstream numeric fields: {input:?}"
            );
            assert_eq!(actual.errno, expected_errno, "numeric errno: {input:?}");
            assert_eq!(actual.error, if alias_error { expected_errno } else { 717 });
        }
    }
    let (_, passwd) = definitions[0];
    let rejected = observe_nss_account_parser(
        passwd,
        0,
        b"a:x:18446744073709551616x:2:g:d:s",
        0,
        0,
        384,
        false,
        false,
        false,
    );
    assert_eq!(
        (rejected.status, rejected.error, rejected.errno),
        (0, 717, libc::ERANGE)
    );
    eprintln!(
        "NSS account parser numbers: {} explicit upstream-contract cases",
        numeric_cases.len() * 2 + 1
    );
}

#[test]
fn nss_account_parser_pointer_tail_boundaries_and_numeric_overflow() {
    let cases: &[(usize, &[u8])] = &[
        (1, b"g:x:1:"),
        (1, b"g:x:1:a"),
        (1, b"g:x:1:a,b"),
        (1, b"g:x:18446744073709551616:a,b"),
        (1, b"+g"),
        (3, b"g:x:a:b,c"),
        (3, b"g:x::"),
        (3, b"+g"),
    ];
    let definitions = nss_parser_definitions();
    let mut comparisons = 0;
    for &(family, input) in cases {
        let (symbol, candidate) = definitions[family];
        let numeric_overflow = input == b"g:x:18446744073709551616:a,b";
        // This same-width ordinary ID preserves every text/table offset.
        // GNU supplies the independent layout oracle; numeric overflow uses
        // the explicit upstream saturation/errno contract documented above.
        let reference_input: &[u8] = if numeric_overflow {
            b"g:x:00000000000000000001:a,b"
        } else {
            input
        };
        assert_eq!(reference_input.len(), input.len());
        // SAFETY: independently resolved function has the declared parser ABI.
        let host: NssAccountParser =
            unsafe { dlsym_oracle::host_fn(symbol, candidate as *const ()) };
        for data_offset in 0..8 {
            for line_offset in [0, 3] {
                for external_line in [false, true] {
                    let first = if external_line {
                        0
                    } else {
                        line_offset + input.len() + 1
                    };
                    for capacity in first..first + 80 {
                        for alias_error in [false, true] {
                            let mut expected = observe_nss_account_parser(
                                host,
                                family,
                                reference_input,
                                data_offset,
                                line_offset,
                                capacity,
                                true,
                                alias_error,
                                external_line,
                            );
                            if numeric_overflow {
                                assert!(matches!(expected.status, -1 | 1));
                                expected.errno = libc::ERANGE;
                                if alias_error {
                                    expected.error = libc::ERANGE;
                                }
                                if expected.status == 1 {
                                    expected.numbers = vec![i128::from(u32::MAX)];
                                }
                            }
                            let actual = observe_nss_account_parser(
                                candidate,
                                family,
                                input,
                                data_offset,
                                line_offset,
                                capacity,
                                false,
                                alias_error,
                                external_line,
                            );
                            assert_eq!(
                                actual, expected,
                                "{symbol:?}, input={input:?}, offsets={data_offset}/{line_offset}, capacity={capacity}, alias_error={alias_error}, external_line={external_line}"
                            );
                            comparisons += 1;
                        }
                    }
                }
            }
        }
    }
    assert!(comparisons > 10_000);
    eprintln!(
        "NSS account parser capacity boundaries: {comparisons} GNU-layout and explicit-overflow comparisons"
    );
}

#[test]
fn nss_account_parser_rejects_tracked_underallocation_without_writing() {
    use frankenlibc_abi::unistd_abi::_nss_files_parse_grent;
    // SAFETY: the tracked allocation remains live through both calls.
    unsafe {
        let allocation = malloc(24).cast::<u8>();
        assert!(!allocation.is_null());
        let actual_capacity = malloc_known_remaining_for_tests(allocation.cast()).unwrap();
        std::ptr::write_bytes(allocation, 0xa5, actual_capacity);
        let input = b"g:x:1:a,b,c,d,e,f,g,h\0";
        assert!(input.len() <= actual_capacity);
        std::ptr::copy_nonoverlapping(input.as_ptr(), allocation, input.len());
        let mut output: libc::group = std::mem::zeroed();
        let mut error = 717;
        let before = std::slice::from_raw_parts(allocation, actual_capacity).to_vec();
        assert_eq!(
            _nss_files_parse_grent(
                allocation.cast(),
                (&raw mut output).cast(),
                allocation.cast(),
                usize::MAX,
                &mut error,
            ),
            -1
        );
        assert_eq!(error, libc::ERANGE);
        assert_eq!(
            std::slice::from_raw_parts(allocation, actual_capacity),
            before
        );
        assert!(output.gr_name.is_null() && output.gr_mem.is_null());
        std::ptr::write_bytes(allocation, b'x', actual_capacity);
        error = 717;
        assert_eq!(
            _nss_files_parse_grent(
                allocation.cast(),
                (&raw mut output).cast(),
                allocation.cast(),
                actual_capacity,
                &mut error,
            ),
            -1
        );
        assert_eq!(error, libc::ERANGE);
        assert!(
            std::slice::from_raw_parts(allocation, actual_capacity)
                .iter()
                .all(|&byte| byte == b'x')
        );
        free(allocation.cast());
    }
}

// Account-file caches must follow file identity, not only length and mtime.
// Keep these public-ABI regressions grouped for the focused resolver workflow.
#[test]
fn account_file_cache_passwd_atomic_replacement() {
    use std::os::unix::fs::MetadataExt;

    const OLD: &[u8] = b"alice:x:4101:4201:Alice:/alpha:/bin/sh\n";
    const NEW: &[u8] = b"alice:x:4101:4201:Alice:/omega:/bin/sh\n";
    assert_eq!(OLD.len(), NEW.len());
    for by_uid in [true, false] {
        with_passwd_file(OLD, || {
            // SAFETY: the fixture contains this identity and no output escapes.
            let first = unsafe { getpwuid(4101) };
            assert!(!first.is_null());
            assert_eq!(
                unsafe { CStr::from_ptr((*first).pw_dir) }.to_bytes(),
                b"/alpha"
            );

            let path = std::env::var_os("FRANKENLIBC_PASSWD_PATH").unwrap();
            let previous = std::fs::metadata(&path).unwrap();
            let replacement = temp_passwd_path();
            std::fs::write(&replacement, NEW).unwrap();
            std::fs::File::open(&replacement)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(previous.modified().unwrap()))
                .unwrap();
            let next = std::fs::metadata(&replacement).unwrap();
            assert_eq!(previous.len(), next.len());
            assert_eq!(previous.modified().unwrap(), next.modified().unwrap());
            assert_ne!(previous.ino(), next.ino());
            std::fs::rename(&replacement, &path).unwrap();

            // Exercise both the raw-stat uid fast path and the ordinary
            // metadata probe before either path can refresh the other's cache.
            unsafe { *__errno_location() = 719 };
            let entry = unsafe {
                if by_uid {
                    getpwuid(4101)
                } else {
                    getpwnam(c"alice".as_ptr())
                }
            };
            assert!(!entry.is_null());
            assert_eq!(
                unsafe { CStr::from_ptr((*entry).pw_dir) }.to_bytes(),
                b"/omega"
            );
            assert_eq!(unsafe { *__errno_location() }, 719);

            let mut output: libc::passwd = unsafe { std::mem::zeroed() };
            let mut buffer = [0 as c_char; 256];
            let mut result = ptr::null_mut();
            assert_eq!(
                unsafe {
                    getpwuid_r(
                        4101,
                        &mut output,
                        buffer.as_mut_ptr(),
                        buffer.len(),
                        &mut result,
                    )
                },
                0
            );
            assert_eq!(result, &mut output as *mut libc::passwd);
            assert_eq!(
                unsafe { CStr::from_ptr(output.pw_dir) }.to_bytes(),
                b"/omega"
            );

            // An unreadable/missing new image must invalidate the cached uid.
            let retired = temp_passwd_path();
            std::fs::rename(&path, retired).unwrap();
            let mut error = 720;
            assert_eq!(
                unsafe {
                    _nss_files_getpwuid_r(
                        4101,
                        (&raw mut output).cast(),
                        buffer.as_mut_ptr(),
                        buffer.len(),
                        &mut error,
                    )
                },
                -1
            );
            assert_eq!(error, libc::ENOENT);
        });
    }
}

#[test]
fn account_file_cache_passwd_in_place_restored_mtime() {
    use std::os::unix::fs::MetadataExt;

    const OLD: &[u8] = b"alice:x:4101:4201:Alice:/alpha:/bin/sh\n";
    const NEW: &[u8] = b"alice:x:4101:4201:Alice:/omega:/bin/sh\n";
    for by_uid in [true, false] {
        with_passwd_file(OLD, || {
            let first = unsafe { getpwuid(4101) };
            assert!(!first.is_null());
            let path = std::env::var_os("FRANKENLIBC_PASSWD_PATH").unwrap();
            let previous = std::fs::metadata(&path).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                std::fs::write(&path, NEW).unwrap();
                std::fs::File::open(&path)
                    .unwrap()
                    .set_times(std::fs::FileTimes::new().set_modified(previous.modified().unwrap()))
                    .unwrap();
                let next = std::fs::metadata(&path).unwrap();
                assert_eq!(previous.ino(), next.ino());
                assert_eq!(previous.len(), next.len());
                assert_eq!(previous.modified().unwrap(), next.modified().unwrap());
                if (previous.ctime(), previous.ctime_nsec()) != (next.ctime(), next.ctime_nsec()) {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "filesystem ctime did not advance"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let entry = unsafe {
                if by_uid {
                    getpwuid(4101)
                } else {
                    getpwnam(c"alice".as_ptr())
                }
            };
            assert!(!entry.is_null());
            assert_eq!(
                unsafe { CStr::from_ptr((*entry).pw_dir) }.to_bytes(),
                b"/omega"
            );
        });
    }
}

#[test]
fn account_file_cache_passwd_read_replace_race() {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;

    // The existing child runner supplies a hard deadline: a broken reader
    // must not leave this test process stuck in a FIFO open/read or join.
    if native_identity_child("account_file_cache_passwd_read_replace_race") {
        return;
    }
    let path = temp_passwd_path();
    let replacement = temp_passwd_path();
    std::fs::write(&replacement, b"alice:x:4101:4201:Alice:/omega:/bin/sh\n").unwrap();
    let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: cpath is a live terminated pathname; this is a private fixture.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    with_passwd_path(&path, || {
        let writer_path = path.clone();
        let writer = std::thread::spawn(move || {
            let mut fifo = std::fs::OpenOptions::new()
                .write(true)
                .open(&writer_path)
                .unwrap();
            fifo.write_all(b"alice:x:4101:4201:Alice:/alpha:/bin/sh\n")
                .unwrap();
            std::fs::rename(replacement, writer_path).unwrap();
            // EOF is delivered only after the pathname names the new image.
            drop(fifo);
        });
        let first = unsafe { getpwuid(4101) };
        writer.join().unwrap();
        assert!(!first.is_null());
        assert_eq!(
            unsafe { CStr::from_ptr((*first).pw_dir) }.to_bytes(),
            b"/alpha"
        );

        // The old reader must not have cached its bytes under the replacement's
        // pathname metadata. The next lookup must read the regular new file.
        let second = unsafe { getpwuid(4101) };
        assert!(!second.is_null());
        assert_eq!(
            unsafe { CStr::from_ptr((*second).pw_dir) }.to_bytes(),
            b"/omega"
        );
        let mut output: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buffer = [0 as c_char; 256];
        let mut result = ptr::null_mut();
        assert_eq!(
            unsafe {
                getpwnam_r(
                    c"alice".as_ptr(),
                    &mut output,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut result,
                )
            },
            0
        );
        assert_eq!(result, &mut output as *mut libc::passwd);
        assert_eq!(
            unsafe { CStr::from_ptr(output.pw_dir) }.to_bytes(),
            b"/omega"
        );
    });
}
