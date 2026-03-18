#![cfg(target_os = "linux")]

//! Integration tests for pthread thread-specific data (TSD / pthread_key_*).

use std::ffi::c_void;
use std::sync::{Mutex, Once};

use frankenlibc_abi::pthread_abi::{
    pthread_create, pthread_join, pthread_key_create, pthread_key_delete,
    pthread_threading_force_native_for_tests,
};

#[cfg(target_arch = "x86_64")]
use frankenlibc_abi::pthread_abi::{pthread_getspecific, pthread_setspecific};

static TEST_GUARD: Mutex<()> = Mutex::new(());
static FORCE_NATIVE_ONCE: Once = Once::new();

fn lock_and_force_native() -> std::sync::MutexGuard<'static, ()> {
    let guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    FORCE_NATIVE_ONCE.call_once(pthread_threading_force_native_for_tests);
    guard
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct ThreadTsdCtx {
    key: libc::pthread_key_t,
    value: usize,
    observed_initial: usize,
}

#[cfg(target_arch = "x86_64")]
const TSD_SET_FAILED: usize = usize::MAX;

#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn tsd_roundtrip_start(arg: *mut c_void) -> *mut c_void {
    if arg.is_null() {
        return TSD_SET_FAILED as *mut c_void;
    }
    // SAFETY: caller passes a valid pointer to ThreadTsdCtx for the thread lifetime.
    let ctx = unsafe { &mut *(arg as *mut ThreadTsdCtx) };
    ctx.observed_initial = unsafe { pthread_getspecific(ctx.key) as usize };
    let rc = unsafe { pthread_setspecific(ctx.key, ctx.value as *const c_void) };
    if rc != 0 {
        return TSD_SET_FAILED as *mut c_void;
    }
    unsafe { pthread_getspecific(ctx.key) }
}

#[test]
fn key_create_and_delete_roundtrip() {
    let _guard = lock_and_force_native();
    let mut key: libc::pthread_key_t = 0;
    let rc = unsafe { pthread_key_create(&mut key, None) };
    assert_eq!(rc, 0, "pthread_key_create failed");

    let rc = unsafe { pthread_key_delete(key) };
    assert_eq!(rc, 0, "pthread_key_delete failed");
}

#[test]
fn key_create_null_is_einval() {
    let _guard = lock_and_force_native();
    let rc = unsafe { pthread_key_create(std::ptr::null_mut(), None) };
    assert_eq!(rc, libc::EINVAL);
}

#[test]
fn key_delete_invalid_is_einval() {
    let _guard = lock_and_force_native();
    // Use a very high key index that was never created.
    let rc = unsafe { pthread_key_delete(0xFFFF_FFFF) };
    assert_eq!(rc, libc::EINVAL);
}

#[test]
fn multiple_keys_get_distinct_indices() {
    let _guard = lock_and_force_native();
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
    let _guard = lock_and_force_native();
    let mut key: libc::pthread_key_t = 0;
    assert_eq!(unsafe { pthread_key_create(&mut key, None) }, 0);

    let val = unsafe { pthread_getspecific(key) };
    assert!(val.is_null(), "value should be null before setspecific");

    assert_eq!(unsafe { pthread_key_delete(key) }, 0);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn set_and_get_specific_roundtrip() {
    let _guard = lock_and_force_native();
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

#[cfg(target_arch = "x86_64")]
#[test]
fn tsd_isolated_across_concurrent_threads() {
    let _guard = lock_and_force_native();
    let mut key: libc::pthread_key_t = 0;
    assert_eq!(unsafe { pthread_key_create(&mut key, None) }, 0);

    let mut ctx_a = ThreadTsdCtx {
        key,
        value: 0x1111,
        observed_initial: usize::MAX,
    };
    let mut ctx_b = ThreadTsdCtx {
        key,
        value: 0x2222,
        observed_initial: usize::MAX,
    };

    let mut tid_a: libc::pthread_t = 0;
    let mut tid_b: libc::pthread_t = 0;
    assert_eq!(
        unsafe {
            pthread_create(
                &mut tid_a as *mut libc::pthread_t,
                std::ptr::null(),
                Some(tsd_roundtrip_start),
                (&mut ctx_a as *mut ThreadTsdCtx).cast::<c_void>(),
            )
        },
        0
    );
    assert_eq!(
        unsafe {
            pthread_create(
                &mut tid_b as *mut libc::pthread_t,
                std::ptr::null(),
                Some(tsd_roundtrip_start),
                (&mut ctx_b as *mut ThreadTsdCtx).cast::<c_void>(),
            )
        },
        0
    );

    let mut ret_a: *mut c_void = std::ptr::null_mut();
    let mut ret_b: *mut c_void = std::ptr::null_mut();
    assert_eq!(
        unsafe { pthread_join(tid_a, &mut ret_a as *mut *mut c_void) },
        0
    );
    assert_eq!(
        unsafe { pthread_join(tid_b, &mut ret_b as *mut *mut c_void) },
        0
    );

    assert_ne!(ret_a as usize, TSD_SET_FAILED);
    assert_ne!(ret_b as usize, TSD_SET_FAILED);
    assert_eq!(ret_a as usize, ctx_a.value);
    assert_eq!(ret_b as usize, ctx_b.value);
    assert_eq!(ctx_a.observed_initial, 0);
    assert_eq!(ctx_b.observed_initial, 0);

    let main_value = unsafe { pthread_getspecific(key) };
    assert!(
        main_value.is_null(),
        "main-thread TSD must remain isolated from child values"
    );

    assert_eq!(unsafe { pthread_key_delete(key) }, 0);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn tsd_teardown_keeps_main_thread_clean() {
    let _guard = lock_and_force_native();
    let mut key: libc::pthread_key_t = 0;
    assert_eq!(unsafe { pthread_key_create(&mut key, None) }, 0);

    let mut ctx = ThreadTsdCtx {
        key,
        value: 0x3333,
        observed_initial: usize::MAX,
    };
    let mut tid: libc::pthread_t = 0;
    assert_eq!(
        unsafe {
            pthread_create(
                &mut tid as *mut libc::pthread_t,
                std::ptr::null(),
                Some(tsd_roundtrip_start),
                (&mut ctx as *mut ThreadTsdCtx).cast::<c_void>(),
            )
        },
        0
    );

    let mut retval: *mut c_void = std::ptr::null_mut();
    assert_eq!(
        unsafe { pthread_join(tid, &mut retval as *mut *mut c_void) },
        0
    );
    assert_ne!(retval as usize, TSD_SET_FAILED);
    assert_eq!(retval as usize, ctx.value);
    assert_eq!(ctx.observed_initial, 0);

    let main_value = unsafe { pthread_getspecific(key) };
    assert!(
        main_value.is_null(),
        "main-thread TSD must remain isolated after worker teardown"
    );
    assert_eq!(unsafe { pthread_key_delete(key) }, 0);
}

#[test]
fn key_create_many_keys_are_unique() {
    let _guard = lock_and_force_native();
    const N: usize = 10;
    let mut keys = [0u32; N];

    for key in &mut keys {
        assert_eq!(
            unsafe { pthread_key_create(key as *mut libc::pthread_key_t, None) },
            0
        );
    }

    // All keys must be distinct.
    for i in 0..N {
        for j in (i + 1)..N {
            assert_ne!(keys[i], keys[j], "keys[{i}] and keys[{j}] should differ");
        }
    }

    for &key in &keys {
        assert_eq!(unsafe { pthread_key_delete(key) }, 0);
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn setspecific_overwrite_returns_latest() {
    let _guard = lock_and_force_native();
    let mut key: libc::pthread_key_t = 0;
    assert_eq!(unsafe { pthread_key_create(&mut key, None) }, 0);

    let v1: usize = 0xAAAA;
    let v2: usize = 0xBBBB;
    assert_eq!(unsafe { pthread_setspecific(key, v1 as *const c_void) }, 0);
    assert_eq!(unsafe { pthread_getspecific(key) as usize }, v1);

    // Overwrite with a new value.
    assert_eq!(unsafe { pthread_setspecific(key, v2 as *const c_void) }, 0);
    assert_eq!(
        unsafe { pthread_getspecific(key) as usize },
        v2,
        "getspecific should return the latest value"
    );

    assert_eq!(unsafe { pthread_key_delete(key) }, 0);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn setspecific_null_clears_value() {
    let _guard = lock_and_force_native();
    let mut key: libc::pthread_key_t = 0;
    assert_eq!(unsafe { pthread_key_create(&mut key, None) }, 0);

    let sentinel: usize = 0xCAFE;
    assert_eq!(
        unsafe { pthread_setspecific(key, sentinel as *const c_void) },
        0
    );
    assert_eq!(unsafe { pthread_getspecific(key) as usize }, sentinel);

    // Set to NULL.
    assert_eq!(unsafe { pthread_setspecific(key, std::ptr::null()) }, 0);
    assert!(
        unsafe { pthread_getspecific(key) }.is_null(),
        "setting null should clear the value"
    );

    assert_eq!(unsafe { pthread_key_delete(key) }, 0);
}

#[test]
fn key_delete_twice_is_einval() {
    let _guard = lock_and_force_native();
    let mut key: libc::pthread_key_t = 0;
    assert_eq!(unsafe { pthread_key_create(&mut key, None) }, 0);
    assert_eq!(unsafe { pthread_key_delete(key) }, 0);
    // Deleting a second time should fail.
    assert_eq!(
        unsafe { pthread_key_delete(key) },
        libc::EINVAL,
        "double delete should return EINVAL"
    );
}
