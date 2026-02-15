use std::ffi::{CStr, CString};
use std::fs;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

const PASSWD_ENV: &str = "FRANKENLIBC_PASSWD_PATH";
const GROUP_ENV: &str = "FRANKENLIBC_GROUP_PATH";

fn temp_path(prefix: &str) -> std::path::PathBuf {
    let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "frankenlibc-{prefix}-{}-{seq}.txt",
        std::process::id()
    ))
}

fn write_file(path: &Path, content: &[u8]) {
    fs::write(path, content).expect("temporary NSS backend file should be writable");
}

fn atomic_replace(path: &Path, content: &[u8]) {
    let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("swap-{seq}.tmp"));
    fs::write(&tmp, content).expect("temporary swap file should be writable");
    fs::rename(&tmp, path).expect("atomic rename should succeed");
}

unsafe fn passwd_name(ptr: *mut libc::passwd) -> String {
    // SAFETY: caller guarantees `ptr` is a valid non-null passwd pointer.
    let c = unsafe { CStr::from_ptr((*ptr).pw_name) };
    c.to_string_lossy().into_owned()
}

unsafe fn group_members(ptr: *mut libc::group) -> Vec<String> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    loop {
        // SAFETY: caller guarantees `ptr` is valid and `gr_mem` is NULL-terminated.
        let mem_ptr = unsafe { *(*ptr).gr_mem.add(idx) };
        if mem_ptr.is_null() {
            break;
        }
        // SAFETY: member pointers are valid C strings per ABI contract.
        let mem = unsafe { CStr::from_ptr(mem_ptr) };
        out.push(mem.to_string_lossy().into_owned());
        idx += 1;
    }
    out
}

#[test]
fn passwd_cache_invalidation_resets_iteration_on_file_change() {
    let _guard = TEST_LOCK.lock().expect("lock should be available");
    let path = temp_path("passwd-cache-policy");

    write_file(
        &path,
        b"root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n",
    );
    // SAFETY: integration tests serialize env mutation via TEST_LOCK.
    unsafe { std::env::set_var(PASSWD_ENV, &path) };

    unsafe {
        frankenlibc_abi::pwd_abi::endpwent();
        frankenlibc_abi::pwd_abi::setpwent();
    }

    let first = unsafe { frankenlibc_abi::pwd_abi::getpwent() };
    assert!(!first.is_null(), "first passwd entry should exist");
    let first_name = unsafe { passwd_name(first) };
    assert_eq!(first_name, "root");

    write_file(
        &path,
        b"carol:x:3000:3000::/home/carol:/bin/sh\nalice:x:2001:2001::/home/alice:/bin/sh\n",
    );

    let second = unsafe { frankenlibc_abi::pwd_abi::getpwent() };
    assert!(!second.is_null(), "cache refresh should provide next entry");
    let second_name = unsafe { passwd_name(second) };
    assert_eq!(
        second_name, "carol",
        "cache invalidation should rebuild iteration from new file"
    );

    unsafe {
        frankenlibc_abi::pwd_abi::endpwent();
        // SAFETY: integration tests serialize env mutation via TEST_LOCK.
        std::env::remove_var(PASSWD_ENV);
    }
    let _ = fs::remove_file(&path);
}

#[test]
fn group_cache_refreshes_lookup_after_file_change() {
    let _guard = TEST_LOCK.lock().expect("lock should be available");
    let path = temp_path("group-cache-policy");

    write_file(&path, b"root:x:0:\ndev:x:100:alice\n");
    // SAFETY: integration tests serialize env mutation via TEST_LOCK.
    unsafe { std::env::set_var(GROUP_ENV, &path) };

    let dev = CString::new("dev").expect("literal has no interior NUL");
    let first = unsafe { frankenlibc_abi::grp_abi::getgrnam(dev.as_ptr()) };
    assert!(!first.is_null(), "group lookup should return an entry");
    let first_gid = unsafe { (*first).gr_gid };
    assert_eq!(first_gid, 100);

    write_file(&path, b"root:x:0:\ndev:x:250:alice,bob\n");

    let second = unsafe { frankenlibc_abi::grp_abi::getgrnam(dev.as_ptr()) };
    assert!(
        !second.is_null(),
        "group lookup should refresh after file change"
    );
    let second_gid = unsafe { (*second).gr_gid };
    assert_eq!(second_gid, 250);

    unsafe {
        frankenlibc_abi::grp_abi::endgrent();
        // SAFETY: integration tests serialize env mutation via TEST_LOCK.
        std::env::remove_var(GROUP_ENV);
    }
    let _ = fs::remove_file(&path);
}

#[test]
fn passwd_reentrant_uses_configured_source_and_erange_contract() {
    let _guard = TEST_LOCK.lock().expect("lock should be available");
    let path = temp_path("passwd-reentrant");

    write_file(
        &path,
        b"root:x:0:0:root:/root:/bin/sh\nalice:x:2001:2001::/home/alice:/bin/bash\n",
    );
    // SAFETY: integration tests serialize env mutation via TEST_LOCK.
    unsafe { std::env::set_var(PASSWD_ENV, &path) };
    unsafe {
        frankenlibc_abi::pwd_abi::endpwent();
        frankenlibc_abi::pwd_abi::setpwent();
    }

    let alice = CString::new("alice").expect("literal has no interior NUL");
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = ptr::null_mut();
    let mut buf = vec![0u8; 256];
    let rc = unsafe {
        frankenlibc_abi::pwd_abi::getpwnam_r(
            alice.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0);
    assert!(!result.is_null(), "lookup should return populated passwd");
    let name = unsafe { CStr::from_ptr(pwd.pw_name) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(name, "alice");
    assert_eq!(pwd.pw_uid, 2001);
    assert_eq!(pwd.pw_gid, 2001);

    let mut tiny_pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut tiny_result: *mut libc::passwd = ptr::null_mut();
    let mut tiny_buf = vec![0u8; 8];
    let tiny_rc = unsafe {
        frankenlibc_abi::pwd_abi::getpwnam_r(
            alice.as_ptr(),
            &mut tiny_pwd,
            tiny_buf.as_mut_ptr().cast(),
            tiny_buf.len(),
            &mut tiny_result,
        )
    };
    assert_eq!(tiny_rc, libc::ERANGE);
    assert!(
        tiny_result.is_null(),
        "ERANGE path must leave result as NULL"
    );

    let missing = CString::new("missing-user").expect("literal has no interior NUL");
    let mut miss_pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut miss_result: *mut libc::passwd = ptr::null_mut();
    let mut miss_buf = vec![0u8; 128];
    let missing_rc = unsafe {
        frankenlibc_abi::pwd_abi::getpwnam_r(
            missing.as_ptr(),
            &mut miss_pwd,
            miss_buf.as_mut_ptr().cast(),
            miss_buf.len(),
            &mut miss_result,
        )
    };
    assert_eq!(missing_rc, 0);
    assert!(
        miss_result.is_null(),
        "not-found contract should return 0 with NULL result"
    );

    let mut uid_pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut uid_result: *mut libc::passwd = ptr::null_mut();
    let mut uid_buf = vec![0u8; 256];
    let uid_rc = unsafe {
        frankenlibc_abi::pwd_abi::getpwuid_r(
            2001,
            &mut uid_pwd,
            uid_buf.as_mut_ptr().cast(),
            uid_buf.len(),
            &mut uid_result,
        )
    };
    assert_eq!(uid_rc, 0);
    assert!(!uid_result.is_null());
    let uid_name = unsafe { CStr::from_ptr(uid_pwd.pw_name) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(uid_name, "alice");

    unsafe {
        frankenlibc_abi::pwd_abi::endpwent();
        // SAFETY: integration tests serialize env mutation via TEST_LOCK.
        std::env::remove_var(PASSWD_ENV);
    }
    let _ = fs::remove_file(&path);
}

#[test]
fn group_reentrant_uses_configured_source_members_and_erange_contract() {
    let _guard = TEST_LOCK.lock().expect("lock should be available");
    let path = temp_path("group-reentrant");

    write_file(&path, b"root:x:0:\ndev:x:250:alice,bob\n");
    // SAFETY: integration tests serialize env mutation via TEST_LOCK.
    unsafe { std::env::set_var(GROUP_ENV, &path) };
    unsafe {
        frankenlibc_abi::grp_abi::endgrent();
        frankenlibc_abi::grp_abi::setgrent();
    }

    let dev = CString::new("dev").expect("literal has no interior NUL");
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = ptr::null_mut();
    let mut buf = vec![0u8; 256];
    let rc = unsafe {
        frankenlibc_abi::grp_abi::getgrnam_r(
            dev.as_ptr(),
            &mut grp,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0);
    assert!(!result.is_null());
    assert_eq!(grp.gr_gid, 250);
    let members = unsafe { group_members(result) };
    assert_eq!(members, vec!["alice".to_string(), "bob".to_string()]);

    let mut tiny_grp: libc::group = unsafe { std::mem::zeroed() };
    let mut tiny_result: *mut libc::group = ptr::null_mut();
    let mut tiny_buf = vec![0u8; 8];
    let tiny_rc = unsafe {
        frankenlibc_abi::grp_abi::getgrnam_r(
            dev.as_ptr(),
            &mut tiny_grp,
            tiny_buf.as_mut_ptr().cast(),
            tiny_buf.len(),
            &mut tiny_result,
        )
    };
    assert_eq!(tiny_rc, libc::ERANGE);
    assert!(
        tiny_result.is_null(),
        "ERANGE path must leave result as NULL"
    );

    let mut gid_grp: libc::group = unsafe { std::mem::zeroed() };
    let mut gid_result: *mut libc::group = ptr::null_mut();
    let mut gid_buf = vec![0u8; 256];
    let gid_rc = unsafe {
        frankenlibc_abi::grp_abi::getgrgid_r(
            250,
            &mut gid_grp,
            gid_buf.as_mut_ptr().cast(),
            gid_buf.len(),
            &mut gid_result,
        )
    };
    assert_eq!(gid_rc, 0);
    assert!(!gid_result.is_null());
    let gid_name = unsafe { CStr::from_ptr(gid_grp.gr_name) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(gid_name, "dev");

    let mut miss_grp: libc::group = unsafe { std::mem::zeroed() };
    let mut miss_result: *mut libc::group = ptr::null_mut();
    let mut miss_buf = vec![0u8; 128];
    let miss_rc = unsafe {
        frankenlibc_abi::grp_abi::getgrgid_r(
            777_777,
            &mut miss_grp,
            miss_buf.as_mut_ptr().cast(),
            miss_buf.len(),
            &mut miss_result,
        )
    };
    assert_eq!(miss_rc, 0);
    assert!(
        miss_result.is_null(),
        "not-found contract should return 0 with NULL result"
    );

    unsafe {
        frankenlibc_abi::grp_abi::endgrent();
        // SAFETY: integration tests serialize env mutation via TEST_LOCK.
        std::env::remove_var(GROUP_ENV);
    }
    let _ = fs::remove_file(&path);
}

#[test]
fn passwd_concurrent_lookup_coherence_under_file_churn() {
    let _guard = TEST_LOCK.lock().expect("lock should be available");
    let path = temp_path("passwd-concurrency");
    let variant_a: &[u8] =
        b"root:x:0:0:root:/root:/bin/sh\nalice:x:1001:1001::/home/alice:/bin/sh\n";
    let variant_b: &[u8] =
        b"root:x:0:0:root:/root:/bin/sh\nalice:x:2002:2002::/home/alice:/bin/bash\n";
    write_file(&path, variant_a);
    // SAFETY: integration tests serialize env mutation via TEST_LOCK.
    unsafe { std::env::set_var(PASSWD_ENV, &path) };
    unsafe { frankenlibc_abi::pwd_abi::endpwent() };

    let errors = Arc::new(AtomicUsize::new(0));
    let path_for_writer = path.clone();
    let writer = std::thread::spawn(move || {
        for i in 0..200 {
            let payload = if i % 2 == 0 { variant_a } else { variant_b };
            atomic_replace(&path_for_writer, payload);
        }
    });

    let mut readers = Vec::new();
    for _ in 0..4 {
        let err_reader = Arc::clone(&errors);
        readers.push(std::thread::spawn(move || {
            let name = CString::new("alice").expect("literal has no interior NUL");
            for _ in 0..800 {
                let entry = unsafe { frankenlibc_abi::pwd_abi::getpwnam(name.as_ptr()) };
                if entry.is_null() {
                    err_reader.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let uid = unsafe { (*entry).pw_uid };
                if uid != 1001 && uid != 2002 {
                    err_reader.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    writer.join().expect("writer thread should join");
    for reader in readers {
        reader.join().expect("reader thread should join");
    }
    assert_eq!(
        errors.load(Ordering::Relaxed),
        0,
        "all lookups should return coherent passwd uid variants only"
    );

    unsafe {
        frankenlibc_abi::pwd_abi::endpwent();
        // SAFETY: integration tests serialize env mutation via TEST_LOCK.
        std::env::remove_var(PASSWD_ENV);
    }
    let _ = fs::remove_file(&path);
}

#[test]
fn group_concurrent_lookup_coherence_under_file_churn() {
    let _guard = TEST_LOCK.lock().expect("lock should be available");
    let path = temp_path("group-concurrency");
    let variant_a: &[u8] = b"root:x:0:\ndev:x:250:alice,bob\n";
    let variant_b: &[u8] = b"root:x:0:\ndev:x:450:alice,bob\n";
    write_file(&path, variant_a);
    // SAFETY: integration tests serialize env mutation via TEST_LOCK.
    unsafe { std::env::set_var(GROUP_ENV, &path) };
    unsafe { frankenlibc_abi::grp_abi::endgrent() };

    let errors = Arc::new(AtomicUsize::new(0));
    let path_for_writer = path.clone();
    let writer = std::thread::spawn(move || {
        for i in 0..200 {
            let payload = if i % 2 == 0 { variant_a } else { variant_b };
            atomic_replace(&path_for_writer, payload);
        }
    });

    let mut readers = Vec::new();
    for _ in 0..4 {
        let err_reader = Arc::clone(&errors);
        readers.push(std::thread::spawn(move || {
            let name = CString::new("dev").expect("literal has no interior NUL");
            for _ in 0..800 {
                let entry = unsafe { frankenlibc_abi::grp_abi::getgrnam(name.as_ptr()) };
                if entry.is_null() {
                    err_reader.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let gid = unsafe { (*entry).gr_gid };
                if gid != 250 && gid != 450 {
                    err_reader.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    writer.join().expect("writer thread should join");
    for reader in readers {
        reader.join().expect("reader thread should join");
    }
    assert_eq!(
        errors.load(Ordering::Relaxed),
        0,
        "all lookups should return coherent group gid variants only"
    );

    unsafe {
        frankenlibc_abi::grp_abi::endgrent();
        // SAFETY: integration tests serialize env mutation via TEST_LOCK.
        std::env::remove_var(GROUP_ENV);
    }
    let _ = fs::remove_file(&path);
}
