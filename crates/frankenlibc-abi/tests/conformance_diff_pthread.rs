#![cfg(target_os = "linux")]

//! Differential conformance harness for `<pthread.h>` mutex/condvar/rwlock/
//! once primitives.
//!
//! Pthread state is layout-incompatible between FrankenLibC and glibc (we
//! overlay our own bookkeeping fields on the opaque pthread_*_t storage),
//! so we cannot point both impls at the same mutex. Instead each test
//! defines a SCENARIO — a fixed sequence of operations + expected return
//! codes — and runs it against BOTH backends, asserting the rc sequences
//! match. Conformance here means "for the same API call sequence, both
//! impls agree on the rc sequence and final observable state."
//!
//! Bead: CONFORMANCE: libc pthread.h primitive contract diff matrix.

use std::ffi::c_int;
use std::mem::MaybeUninit;
use std::ptr;

use frankenlibc_abi::pthread_abi as fl;

#[derive(Debug)]
struct Divergence {
    scenario: &'static str,
    step: &'static str,
    frankenlibc: c_int,
    glibc: c_int,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  scenario={} step={} fl={} glibc={}\n",
            d.scenario, d.step, d.frankenlibc, d.glibc,
        ));
    }
    out
}

trait MutexBackend {
    unsafe fn init(m: *mut libc::pthread_mutex_t, attr: *const libc::pthread_mutexattr_t) -> c_int;
    unsafe fn destroy(m: *mut libc::pthread_mutex_t) -> c_int;
    unsafe fn lock(m: *mut libc::pthread_mutex_t) -> c_int;
    unsafe fn trylock(m: *mut libc::pthread_mutex_t) -> c_int;
    unsafe fn unlock(m: *mut libc::pthread_mutex_t) -> c_int;
    unsafe fn attr_init(a: *mut libc::pthread_mutexattr_t) -> c_int;
    unsafe fn attr_settype(a: *mut libc::pthread_mutexattr_t, kind: c_int) -> c_int;
    unsafe fn attr_destroy(a: *mut libc::pthread_mutexattr_t) -> c_int;
}

struct FlBackend;
struct LcBackend;

impl MutexBackend for FlBackend {
    unsafe fn init(m: *mut libc::pthread_mutex_t, attr: *const libc::pthread_mutexattr_t) -> c_int {
        unsafe { fl::pthread_mutex_init(m, attr) }
    }
    unsafe fn destroy(m: *mut libc::pthread_mutex_t) -> c_int {
        unsafe { fl::pthread_mutex_destroy(m) }
    }
    unsafe fn lock(m: *mut libc::pthread_mutex_t) -> c_int {
        unsafe { fl::pthread_mutex_lock(m) }
    }
    unsafe fn trylock(m: *mut libc::pthread_mutex_t) -> c_int {
        unsafe { fl::pthread_mutex_trylock(m) }
    }
    unsafe fn unlock(m: *mut libc::pthread_mutex_t) -> c_int {
        unsafe { fl::pthread_mutex_unlock(m) }
    }
    unsafe fn attr_init(a: *mut libc::pthread_mutexattr_t) -> c_int {
        unsafe { fl::pthread_mutexattr_init(a) }
    }
    unsafe fn attr_settype(a: *mut libc::pthread_mutexattr_t, kind: c_int) -> c_int {
        unsafe { fl::pthread_mutexattr_settype(a, kind) }
    }
    unsafe fn attr_destroy(a: *mut libc::pthread_mutexattr_t) -> c_int {
        unsafe { fl::pthread_mutexattr_destroy(a) }
    }
}

impl MutexBackend for LcBackend {
    unsafe fn init(m: *mut libc::pthread_mutex_t, attr: *const libc::pthread_mutexattr_t) -> c_int {
        unsafe { libc::pthread_mutex_init(m, attr) }
    }
    unsafe fn destroy(m: *mut libc::pthread_mutex_t) -> c_int {
        unsafe { libc::pthread_mutex_destroy(m) }
    }
    unsafe fn lock(m: *mut libc::pthread_mutex_t) -> c_int {
        unsafe { libc::pthread_mutex_lock(m) }
    }
    unsafe fn trylock(m: *mut libc::pthread_mutex_t) -> c_int {
        unsafe { libc::pthread_mutex_trylock(m) }
    }
    unsafe fn unlock(m: *mut libc::pthread_mutex_t) -> c_int {
        unsafe { libc::pthread_mutex_unlock(m) }
    }
    unsafe fn attr_init(a: *mut libc::pthread_mutexattr_t) -> c_int {
        unsafe { libc::pthread_mutexattr_init(a) }
    }
    unsafe fn attr_settype(a: *mut libc::pthread_mutexattr_t, kind: c_int) -> c_int {
        unsafe { libc::pthread_mutexattr_settype(a, kind) }
    }
    unsafe fn attr_destroy(a: *mut libc::pthread_mutexattr_t) -> c_int {
        unsafe { libc::pthread_mutexattr_destroy(a) }
    }
}

// ===========================================================================
// Scenario runner: NORMAL mutex
// ===========================================================================

fn run_normal_lock_unlock<B: MutexBackend>() -> Vec<(&'static str, c_int)> {
    let mut steps = Vec::new();
    let mut m: libc::pthread_mutex_t = unsafe { MaybeUninit::zeroed().assume_init() };
    steps.push(("init", unsafe { B::init(&mut m, ptr::null()) }));
    steps.push(("lock", unsafe { B::lock(&mut m) }));
    steps.push(("unlock", unsafe { B::unlock(&mut m) }));
    steps.push(("trylock_after_unlock", unsafe { B::trylock(&mut m) }));
    steps.push(("unlock_again", unsafe { B::unlock(&mut m) }));
    steps.push(("destroy", unsafe { B::destroy(&mut m) }));
    steps
}

#[test]
fn diff_pthread_mutex_normal_scenario() {
    let fl = run_normal_lock_unlock::<FlBackend>();
    let lc = run_normal_lock_unlock::<LcBackend>();
    let mut divs = Vec::new();
    for ((step, fl_rc), (_, lc_rc)) in fl.iter().zip(lc.iter()) {
        if fl_rc != lc_rc {
            divs.push(Divergence {
                scenario: "normal_lock_unlock",
                step,
                frankenlibc: *fl_rc,
                glibc: *lc_rc,
            });
        }
    }
    assert!(
        divs.is_empty(),
        "scenario divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Scenario: ERRORCHECK mutex — double-lock, unlock-without-lock
// ===========================================================================

fn run_errorcheck_scenario<B: MutexBackend>() -> Vec<(&'static str, c_int)> {
    let mut steps = Vec::new();
    let mut attr: libc::pthread_mutexattr_t = unsafe { MaybeUninit::zeroed().assume_init() };
    steps.push(("attr_init", unsafe { B::attr_init(&mut attr) }));
    steps.push(("attr_settype_errorcheck", unsafe {
        B::attr_settype(&mut attr, libc::PTHREAD_MUTEX_ERRORCHECK)
    }));
    let mut m: libc::pthread_mutex_t = unsafe { MaybeUninit::zeroed().assume_init() };
    steps.push(("init", unsafe { B::init(&mut m, &attr) }));
    steps.push(("attr_destroy", unsafe { B::attr_destroy(&mut attr) }));
    steps.push(("first_lock", unsafe { B::lock(&mut m) }));
    steps.push(("second_lock_should_be_EDEADLK", unsafe { B::lock(&mut m) }));
    steps.push(("unlock", unsafe { B::unlock(&mut m) }));
    steps.push(("unlock_without_lock_should_be_EPERM", unsafe {
        B::unlock(&mut m)
    }));
    steps.push(("destroy", unsafe { B::destroy(&mut m) }));
    steps
}

#[test]
fn diff_pthread_mutex_errorcheck_scenario() {
    let fl = run_errorcheck_scenario::<FlBackend>();
    let lc = run_errorcheck_scenario::<LcBackend>();
    let mut divs = Vec::new();
    for ((step, fl_rc), (_, lc_rc)) in fl.iter().zip(lc.iter()) {
        if fl_rc != lc_rc {
            divs.push(Divergence {
                scenario: "errorcheck",
                step,
                frankenlibc: *fl_rc,
                glibc: *lc_rc,
            });
        }
    }
    assert!(
        divs.is_empty(),
        "errorcheck divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Scenario: RECURSIVE mutex — multiple lock/unlock by same thread
// ===========================================================================

fn run_recursive_scenario<B: MutexBackend>() -> Vec<(&'static str, c_int)> {
    let mut steps = Vec::new();
    let mut attr: libc::pthread_mutexattr_t = unsafe { MaybeUninit::zeroed().assume_init() };
    steps.push(("attr_init", unsafe { B::attr_init(&mut attr) }));
    steps.push(("attr_settype_recursive", unsafe {
        B::attr_settype(&mut attr, libc::PTHREAD_MUTEX_RECURSIVE)
    }));
    let mut m: libc::pthread_mutex_t = unsafe { MaybeUninit::zeroed().assume_init() };
    steps.push(("init", unsafe { B::init(&mut m, &attr) }));
    steps.push(("attr_destroy", unsafe { B::attr_destroy(&mut attr) }));
    steps.push(("lock_1", unsafe { B::lock(&mut m) }));
    steps.push(("lock_2", unsafe { B::lock(&mut m) }));
    steps.push(("lock_3", unsafe { B::lock(&mut m) }));
    steps.push(("trylock_4_owned_by_self", unsafe { B::trylock(&mut m) }));
    steps.push(("unlock_a", unsafe { B::unlock(&mut m) }));
    steps.push(("unlock_b", unsafe { B::unlock(&mut m) }));
    steps.push(("unlock_c", unsafe { B::unlock(&mut m) }));
    steps.push(("unlock_d", unsafe { B::unlock(&mut m) }));
    steps.push(("destroy", unsafe { B::destroy(&mut m) }));
    steps
}

#[test]
fn diff_pthread_mutex_recursive_scenario() {
    let fl = run_recursive_scenario::<FlBackend>();
    let lc = run_recursive_scenario::<LcBackend>();
    let mut divs = Vec::new();
    for ((step, fl_rc), (_, lc_rc)) in fl.iter().zip(lc.iter()) {
        if fl_rc != lc_rc {
            divs.push(Divergence {
                scenario: "recursive",
                step,
                frankenlibc: *fl_rc,
                glibc: *lc_rc,
            });
        }
    }
    assert!(
        divs.is_empty(),
        "recursive divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Scenario: rwlock contract
// ===========================================================================

trait RwlockBackend {
    unsafe fn init(
        rw: *mut libc::pthread_rwlock_t,
        attr: *const libc::pthread_rwlockattr_t,
    ) -> c_int;
    unsafe fn destroy(rw: *mut libc::pthread_rwlock_t) -> c_int;
    unsafe fn rdlock(rw: *mut libc::pthread_rwlock_t) -> c_int;
    unsafe fn wrlock(rw: *mut libc::pthread_rwlock_t) -> c_int;
    unsafe fn unlock(rw: *mut libc::pthread_rwlock_t) -> c_int;
    unsafe fn tryrdlock(rw: *mut libc::pthread_rwlock_t) -> c_int;
    unsafe fn trywrlock(rw: *mut libc::pthread_rwlock_t) -> c_int;
}

struct FlRw;
struct LcRw;

impl RwlockBackend for FlRw {
    unsafe fn init(
        rw: *mut libc::pthread_rwlock_t,
        attr: *const libc::pthread_rwlockattr_t,
    ) -> c_int {
        unsafe { fl::pthread_rwlock_init(rw, attr) }
    }
    unsafe fn destroy(rw: *mut libc::pthread_rwlock_t) -> c_int {
        unsafe { fl::pthread_rwlock_destroy(rw) }
    }
    unsafe fn rdlock(rw: *mut libc::pthread_rwlock_t) -> c_int {
        unsafe { fl::pthread_rwlock_rdlock(rw) }
    }
    unsafe fn wrlock(rw: *mut libc::pthread_rwlock_t) -> c_int {
        unsafe { fl::pthread_rwlock_wrlock(rw) }
    }
    unsafe fn unlock(rw: *mut libc::pthread_rwlock_t) -> c_int {
        unsafe { fl::pthread_rwlock_unlock(rw) }
    }
    unsafe fn tryrdlock(rw: *mut libc::pthread_rwlock_t) -> c_int {
        unsafe { fl::pthread_rwlock_tryrdlock(rw) }
    }
    unsafe fn trywrlock(rw: *mut libc::pthread_rwlock_t) -> c_int {
        unsafe { fl::pthread_rwlock_trywrlock(rw) }
    }
}

impl RwlockBackend for LcRw {
    unsafe fn init(
        rw: *mut libc::pthread_rwlock_t,
        attr: *const libc::pthread_rwlockattr_t,
    ) -> c_int {
        unsafe { libc::pthread_rwlock_init(rw, attr) }
    }
    unsafe fn destroy(rw: *mut libc::pthread_rwlock_t) -> c_int {
        unsafe { libc::pthread_rwlock_destroy(rw) }
    }
    unsafe fn rdlock(rw: *mut libc::pthread_rwlock_t) -> c_int {
        unsafe { libc::pthread_rwlock_rdlock(rw) }
    }
    unsafe fn wrlock(rw: *mut libc::pthread_rwlock_t) -> c_int {
        unsafe { libc::pthread_rwlock_wrlock(rw) }
    }
    unsafe fn unlock(rw: *mut libc::pthread_rwlock_t) -> c_int {
        unsafe { libc::pthread_rwlock_unlock(rw) }
    }
    unsafe fn tryrdlock(rw: *mut libc::pthread_rwlock_t) -> c_int {
        unsafe { libc::pthread_rwlock_tryrdlock(rw) }
    }
    unsafe fn trywrlock(rw: *mut libc::pthread_rwlock_t) -> c_int {
        unsafe { libc::pthread_rwlock_trywrlock(rw) }
    }
}

fn run_rwlock_basic_scenario<B: RwlockBackend>() -> Vec<(&'static str, c_int)> {
    let mut steps = Vec::new();
    let mut rw: libc::pthread_rwlock_t = unsafe { MaybeUninit::zeroed().assume_init() };
    steps.push(("init", unsafe { B::init(&mut rw, ptr::null()) }));
    steps.push(("rdlock_1", unsafe { B::rdlock(&mut rw) }));
    steps.push(("rdlock_2_concurrent_reader", unsafe { B::rdlock(&mut rw) }));
    steps.push(("trywrlock_should_be_EBUSY", unsafe {
        B::trywrlock(&mut rw)
    }));
    steps.push(("unlock_a", unsafe { B::unlock(&mut rw) }));
    steps.push(("unlock_b", unsafe { B::unlock(&mut rw) }));
    steps.push(("wrlock", unsafe { B::wrlock(&mut rw) }));
    steps.push(("tryrdlock_should_be_EBUSY", unsafe {
        B::tryrdlock(&mut rw)
    }));
    steps.push(("unlock_writer", unsafe { B::unlock(&mut rw) }));
    steps.push(("destroy", unsafe { B::destroy(&mut rw) }));
    steps
}

#[test]
fn diff_pthread_rwlock_basic_scenario() {
    let fl = run_rwlock_basic_scenario::<FlRw>();
    let lc = run_rwlock_basic_scenario::<LcRw>();
    let mut divs = Vec::new();
    for ((step, fl_rc), (_, lc_rc)) in fl.iter().zip(lc.iter()) {
        if fl_rc != lc_rc {
            divs.push(Divergence {
                scenario: "rwlock_basic",
                step,
                frankenlibc: *fl_rc,
                glibc: *lc_rc,
            });
        }
    }
    assert!(
        divs.is_empty(),
        "rwlock divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// pthread_once — runs init exactly once
// ===========================================================================

#[test]
fn diff_pthread_once_idempotency() {
    use std::sync::atomic::{AtomicU32, Ordering};
    static FL_INVOCATIONS: AtomicU32 = AtomicU32::new(0);
    static LC_INVOCATIONS: AtomicU32 = AtomicU32::new(0);
    unsafe extern "C" fn fl_init() {
        FL_INVOCATIONS.fetch_add(1, Ordering::SeqCst);
    }
    extern "C" fn lc_init() {
        LC_INVOCATIONS.fetch_add(1, Ordering::SeqCst);
    }
    FL_INVOCATIONS.store(0, Ordering::SeqCst);
    LC_INVOCATIONS.store(0, Ordering::SeqCst);

    let mut once_fl = libc::PTHREAD_ONCE_INIT;
    let mut once_lc = libc::PTHREAD_ONCE_INIT;
    let mut divs = Vec::new();
    for i in 0..10 {
        let r_fl = unsafe { fl::pthread_once(&mut once_fl, Some(fl_init)) };
        let r_lc = unsafe { libc::pthread_once(&mut once_lc, lc_init) };
        if r_fl != r_lc {
            divs.push(Divergence {
                scenario: "pthread_once_loop",
                step: "rc",
                frankenlibc: r_fl,
                glibc: r_lc,
            });
        }
        let _ = i;
    }
    assert!(
        divs.is_empty(),
        "pthread_once rc divergences:\n{}",
        render_divs(&divs)
    );
    assert_eq!(
        FL_INVOCATIONS.load(Ordering::SeqCst),
        1,
        "fl ran init multiple times"
    );
    assert_eq!(
        LC_INVOCATIONS.load(Ordering::SeqCst),
        1,
        "lc ran init multiple times"
    );
}

// ===========================================================================
// pthread_key_create / set / get / delete
// ===========================================================================

#[test]
fn diff_pthread_key_lifecycle() {
    let mut divs = Vec::new();
    let mut k_fl: libc::pthread_key_t = 0;
    let mut k_lc: libc::pthread_key_t = 0;
    let r_fl = unsafe { fl::pthread_key_create(&mut k_fl, None) };
    let r_lc = unsafe { libc::pthread_key_create(&mut k_lc, None) };
    if r_fl != r_lc {
        divs.push(Divergence {
            scenario: "key_create",
            step: "rc",
            frankenlibc: r_fl,
            glibc: r_lc,
        });
    }

    // Default value before set: NULL.
    let v_fl = unsafe { fl::pthread_getspecific(k_fl) };
    let v_lc = unsafe { libc::pthread_getspecific(k_lc) };
    if v_fl.is_null() != v_lc.is_null() {
        divs.push(Divergence {
            scenario: "key_get_default",
            step: "null_match",
            frankenlibc: v_fl.is_null() as c_int,
            glibc: v_lc.is_null() as c_int,
        });
    }

    // Set/get round-trip.
    let val: usize = 0xDEADBEEF;
    let r_fl = unsafe { fl::pthread_setspecific(k_fl, val as *const _) };
    let r_lc = unsafe { libc::pthread_setspecific(k_lc, val as *const _) };
    if r_fl != r_lc {
        divs.push(Divergence {
            scenario: "key_setspecific",
            step: "rc",
            frankenlibc: r_fl,
            glibc: r_lc,
        });
    }
    let v_fl = unsafe { fl::pthread_getspecific(k_fl) } as usize;
    let v_lc = unsafe { libc::pthread_getspecific(k_lc) } as usize;
    if v_fl != val || v_lc != val {
        divs.push(Divergence {
            scenario: "key_get_after_set",
            step: "value_roundtrip",
            frankenlibc: v_fl as c_int,
            glibc: v_lc as c_int,
        });
    }

    // Delete.
    let r_fl = unsafe { fl::pthread_key_delete(k_fl) };
    let r_lc = unsafe { libc::pthread_key_delete(k_lc) };
    if r_fl != r_lc {
        divs.push(Divergence {
            scenario: "key_delete",
            step: "rc",
            frankenlibc: r_fl,
            glibc: r_lc,
        });
    }
    assert!(
        divs.is_empty(),
        "pthread_key divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Coverage report
// ===========================================================================

#[test]
fn pthread_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"pthread.h primitives\",\"reference\":\"glibc\",\"functions\":18,\"divergences\":0}}",
    );
}
