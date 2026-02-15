#![cfg(target_os = "linux")]

//! Integration tests for pthread thread-specific data (TSD / pthread_key_*).

use std::sync::Mutex;

use frankenlibc_abi::pthread_abi::{pthread_key_create, pthread_key_delete};

#[cfg(target_arch = "x86_64")]
use frankenlibc_abi::pthread_abi::{pthread_getspecific, pthread_setspecific};

static TEST_GUARD: Mutex<()> = Mutex::new(());

#[test]
fn key_create_and_delete_roundtrip() {
    let _guard = TEST_GUARD.lock().unwrap();
    let mut key: libc::pthread_key_t = 0;
    let rc = unsafe { pthread_key_create(&mut key, None) };
    assert_eq!(rc, 0, "pthread_key_create failed");

    let rc = unsafe { pthread_key_delete(key) };
    assert_eq!(rc, 0, "pthread_key_delete failed");
}

#[test]
fn key_create_null_is_einval() {
    let _guard = TEST_GUARD.lock().unwrap();
    let rc = unsafe { pthread_key_create(std::ptr::null_mut(), None) };
    assert_eq!(rc, libc::EINVAL);
}

#[test]
fn key_delete_invalid_is_einval() {
    let _guard = TEST_GUARD.lock().unwrap();
    // Use a very high key index that was never created.
    let rc = unsafe { pthread_key_delete(0xFFFF_FFFF) };
    assert_eq!(rc, libc::EINVAL);
}

#[test]
fn multiple_keys_get_distinct_indices() {
    let _guard = TEST_GUARD.lock().unwrap();
    let mut key1: libc::pthread_key_t = 0;
    let mut key2: libc::pthread_key_t = 0;

    assert_eq!(unsafe { pthread_key_create(&mut key1, None) }, 0);
    assert_eq!(unsafe { pthread_key_create(&mut key2, None) }, 0);
    assert_ne!(key1, key2, "two keys must have distinct indices");

    assert_eq!(unsafe { pthread_key_delete(key1) }, 0);
    assert_eq!(unsafe { pthread_key_delete(key2) }, 0);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn getspecific_returns_null_before_set() {
    let _guard = TEST_GUARD.lock().unwrap();
    let mut key: libc::pthread_key_t = 0;
    assert_eq!(unsafe { pthread_key_create(&mut key, None) }, 0);

    let val = unsafe { pthread_getspecific(key) };
    assert!(val.is_null(), "value should be null before setspecific");

    assert_eq!(unsafe { pthread_key_delete(key) }, 0);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn set_and_get_specific_roundtrip() {
    let _guard = TEST_GUARD.lock().unwrap();
    let mut key: libc::pthread_key_t = 0;
    assert_eq!(unsafe { pthread_key_create(&mut key, None) }, 0);

    let sentinel: usize = 0xDEAD_BEEF;
    let rc = unsafe { pthread_setspecific(key, sentinel as *const std::ffi::c_void) };
    assert_eq!(rc, 0, "pthread_setspecific failed");

    let val = unsafe { pthread_getspecific(key) };
    assert_eq!(
        val as usize, sentinel,
        "pthread_getspecific should return the value set"
    );

    assert_eq!(unsafe { pthread_key_delete(key) }, 0);
}
