use std::ffi::{CStr, CString};
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

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

unsafe fn passwd_name(ptr: *mut libc::passwd) -> String {
    // SAFETY: caller guarantees `ptr` is a valid non-null passwd pointer.
    let c = unsafe { CStr::from_ptr((*ptr).pw_name) };
    c.to_string_lossy().into_owned()
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
