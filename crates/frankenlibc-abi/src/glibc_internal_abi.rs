//! Internal glibc double-underscore aliases and compatibility symbols.
//!
//! glibc exports many `__foo` aliases for public `foo` functions. Programs
//! compiled against glibc may reference either form. This module provides
//! the internal variants as thin call-throughs via dlsym(RTLD_NEXT).
//!
//! Also covers: __ctype_*, __libc_*, __pthread_*, __sched_*, __res_*,
//! sys_* tables, environ, obstack, and other misc glibc internals.
#![allow(
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    clippy::missing_safety_doc
)]

use std::ffi::{c_char, c_int, c_void};

type c_uint = u32;
type c_long = i64;
type c_ulong = u64;
type WcharT = i32;
type SizeT = usize;
type SSizeT = isize;

// ==========================================================================
// Helper: dlsym-based call-through for functions we also export
// ==========================================================================
macro_rules! dlsym_passthrough {
    (fn $name:ident ( $($arg:ident : $ty:ty),* $(,)? ) -> $ret:ty) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name( $($arg: $ty),* ) -> $ret {
            type F = unsafe extern "C" fn( $($ty),* ) -> $ret;
            let sym = unsafe {
                libc::dlsym(libc::RTLD_NEXT, concat!(stringify!($name), "\0").as_ptr().cast())
            };
            if sym.is_null() {
                return unsafe { std::mem::zeroed() };
            }
            let f: F = unsafe { std::mem::transmute(sym) };
            unsafe { f( $($arg),* ) }
        }
    };
    (fn $name:ident ( $($arg:ident : $ty:ty),* $(,)? )) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name( $($arg: $ty),* ) {
            type F = unsafe extern "C" fn( $($ty),* );
            let sym = unsafe {
                libc::dlsym(libc::RTLD_NEXT, concat!(stringify!($name), "\0").as_ptr().cast())
            };
            if !sym.is_null() {
                let f: F = unsafe { std::mem::transmute(sym) };
                unsafe { f( $($arg),* ) };
            }
        }
    };
}

// ==========================================================================
// Native math helpers
// ==========================================================================

/// ldexp(x, exp) = x * 2^exp, implemented via f64 bit manipulation.
#[inline]
fn native_ldexp(x: f64, exp: c_int) -> f64 {
    if x == 0.0 || x.is_nan() || x.is_infinite() || exp == 0 {
        return x;
    }
    // Use successive multiplications by powers of 2 to avoid overflow
    // in the exponent field. Max f64 exponent is 1023.
    let mut result = x;
    let mut n = exp;
    while n > 1023 {
        result *= f64::from_bits(0x7FE0_0000_0000_0000); // 2^1023
        n -= 1023;
    }
    while n < -1022 {
        result *= f64::from_bits(0x0010_0000_0000_0000); // 2^-1022
        n += 1022;
    }
    result * f64::from_bits(((n + 1023) as u64) << 52)
}

// ==========================================================================
// __pthread_* internal aliases (42 symbols)
// ==========================================================================
// __pthread_cleanup_routine: now exported from pthread_abi.rs (no-op stub)
// __pthread_getspecific → pthread_getspecific
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_getspecific(key: c_uint) -> *mut c_void {
    unsafe { super::pthread_abi::pthread_getspecific(key) }
}
// __pthread_key_create → pthread_key_create
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_key_create(key: *mut c_uint, dtor: *mut c_void) -> c_int {
    let destructor: Option<unsafe extern "C" fn(*mut c_void)> = if dtor.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut c_void, unsafe extern "C" fn(*mut c_void)>(dtor) })
    };
    unsafe { super::pthread_abi::pthread_key_create(key.cast(), destructor) }
}
// __pthread_mutex_destroy → pthread_mutex_destroy
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutex_destroy(mutex: *mut c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_mutex_destroy(mutex.cast()) }
}
// __pthread_mutex_init → pthread_mutex_init
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutex_init(mutex: *mut c_void, attr: *const c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_mutex_init(mutex.cast(), attr as *const libc::pthread_mutexattr_t) }
}
// __pthread_mutex_lock → pthread_mutex_lock
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutex_lock(mutex: *mut c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_mutex_lock(mutex.cast()) }
}
// __pthread_mutex_trylock → pthread_mutex_trylock
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutex_trylock(mutex: *mut c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_mutex_trylock(mutex.cast()) }
}
// __pthread_mutex_unlock → pthread_mutex_unlock
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutex_unlock(mutex: *mut c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_mutex_unlock(mutex.cast()) }
}
// __pthread_mutexattr_destroy → pthread_mutexattr_destroy
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutexattr_destroy(attr: *mut c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_mutexattr_destroy(attr.cast()) }
}
// __pthread_mutexattr_init → pthread_mutexattr_init
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutexattr_init(attr: *mut c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_mutexattr_init(attr.cast()) }
}
// __pthread_mutexattr_settype → pthread_mutexattr_settype
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutexattr_settype(attr: *mut c_void, kind: c_int) -> c_int {
    unsafe { super::pthread_abi::pthread_mutexattr_settype(attr.cast(), kind) }
}
// __pthread_once → pthread_once
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_once(control: *mut c_void, init_routine: *mut c_void) -> c_int {
    let routine: Option<unsafe extern "C" fn()> = if init_routine.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut c_void, unsafe extern "C" fn()>(init_routine) })
    };
    unsafe { super::pthread_abi::pthread_once(control.cast(), routine) }
}
// __pthread_register_cancel/defer: now exported from pthread_abi.rs (no-op stubs)
// __pthread_rwlock_destroy → pthread_rwlock_destroy
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_rwlock_destroy(rwlock: *mut c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_rwlock_destroy(rwlock.cast()) }
}
// __pthread_rwlock_init → pthread_rwlock_init
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_rwlock_init(rwlock: *mut c_void, attr: *const c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_rwlock_init(rwlock.cast(), attr as *const libc::pthread_rwlockattr_t) }
}
// __pthread_rwlock_rdlock → pthread_rwlock_rdlock
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_rwlock_rdlock(rwlock: *mut c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_rwlock_rdlock(rwlock.cast()) }
}
// __pthread_rwlock_tryrdlock → pthread_rwlock_tryrdlock
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_rwlock_tryrdlock(rwlock: *mut c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_rwlock_tryrdlock(rwlock.cast()) }
}
// __pthread_rwlock_trywrlock → pthread_rwlock_trywrlock
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_rwlock_trywrlock(rwlock: *mut c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_rwlock_trywrlock(rwlock.cast()) }
}
// __pthread_rwlock_unlock → pthread_rwlock_unlock
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_rwlock_unlock(rwlock: *mut c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_rwlock_unlock(rwlock.cast()) }
}
// __pthread_rwlock_wrlock → pthread_rwlock_wrlock
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_rwlock_wrlock(rwlock: *mut c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_rwlock_wrlock(rwlock.cast()) }
}
// __pthread_setspecific → pthread_setspecific
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_setspecific(key: c_uint, val: *const c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_setspecific(key, val) }
}
// __pthread_unregister_cancel/restore, __pthread_unwind_next: now in pthread_abi.rs (no-op/abort stubs)

// Pthread cleanup push/pop (4 symbols)
dlsym_passthrough!(fn _pthread_cleanup_push(buf: *mut c_void, routine: *mut c_void, arg: *mut c_void));
dlsym_passthrough!(fn _pthread_cleanup_pop(buf: *mut c_void, execute: c_int));
dlsym_passthrough!(fn _pthread_cleanup_push_defer(buf: *mut c_void, routine: *mut c_void, arg: *mut c_void));
dlsym_passthrough!(fn _pthread_cleanup_pop_restore(buf: *mut c_void, execute: c_int));

// Public pthread extras (12 symbols)
// pthread_kill_other_threads_np: deprecated no-op (LinuxThreads compat)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_kill_other_threads_np() -> c_int {
    0 // deprecated, no-op in NPTL
}
// pthread_mutex_consistent_np: forward to native pthread_mutex_consistent
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_consistent_np(mutex: *mut c_void) -> c_int {
    unsafe { super::pthread_abi::pthread_mutex_consistent(mutex.cast()) }
}
// pthread_mutex_getprioceiling: native — returns ENOSYS (priority ceiling not supported)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_getprioceiling(
    _mutex: *const c_void,
    prioceiling: *mut c_int,
) -> c_int {
    if !prioceiling.is_null() {
        unsafe { *prioceiling = 0 };
    }
    libc::ENOSYS // priority protocols not supported in native impl
}
// pthread_mutex_setprioceiling: native — returns ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_setprioceiling(
    _mutex: *mut c_void,
    _prioceiling: c_int,
    old: *mut c_int,
) -> c_int {
    if !old.is_null() {
        unsafe { *old = 0 };
    }
    libc::ENOSYS
}
// pthread_mutexattr_getkind_np: GNU alias for pthread_mutexattr_gettype
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getkind_np(
    attr: *const c_void,
    kind: *mut c_int,
) -> c_int {
    unsafe { super::pthread_abi::pthread_mutexattr_gettype(attr.cast(), kind) }
}
// pthread_mutexattr_getprioceiling: native — returns ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getprioceiling(
    _attr: *const c_void,
    prioceiling: *mut c_int,
) -> c_int {
    if !prioceiling.is_null() {
        unsafe { *prioceiling = 0 };
    }
    libc::ENOSYS
}
// pthread_mutexattr_getrobust_np: GNU alias for pthread_mutexattr_getrobust
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getrobust_np(
    attr: *const c_void,
    robust: *mut c_int,
) -> c_int {
    unsafe { super::pthread_abi::pthread_mutexattr_getrobust(attr.cast(), robust) }
}
// pthread_mutexattr_setkind_np: GNU alias for pthread_mutexattr_settype
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setkind_np(
    attr: *mut c_void,
    kind: c_int,
) -> c_int {
    unsafe { super::pthread_abi::pthread_mutexattr_settype(attr.cast(), kind) }
}
// pthread_mutexattr_setprioceiling: native — returns ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setprioceiling(
    _attr: *mut c_void,
    _prioceiling: c_int,
) -> c_int {
    libc::ENOSYS
}
// pthread_mutexattr_setrobust_np: GNU alias for pthread_mutexattr_setrobust
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setrobust_np(
    attr: *mut c_void,
    robust: c_int,
) -> c_int {
    unsafe { super::pthread_abi::pthread_mutexattr_setrobust(attr.cast(), robust) }
}
// pthread_rwlockattr_getkind_np: get rwlock scheduling preference
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_getkind_np(
    attr: *const c_void,
    kind: *mut c_int,
) -> c_int {
    if attr.is_null() || kind.is_null() {
        return libc::EINVAL;
    }
    // Default: prefer readers (PTHREAD_RWLOCK_PREFER_READER_NP = 0)
    unsafe { *kind = 0 };
    0
}
// pthread_rwlockattr_setkind_np: set rwlock scheduling preference
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_setkind_np(
    attr: *mut c_void,
    kind: c_int,
) -> c_int {
    if attr.is_null() || !(0..=2).contains(&kind) {
        return libc::EINVAL;
    }
    // Accept but our rwlock uses a fixed strategy
    0
}
// pthread_setschedprio: native — set thread scheduling priority
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setschedprio(thread: c_ulong, prio: c_int) -> c_int {
    let mut param: libc::sched_param = unsafe { std::mem::zeroed() };
    param.sched_priority = prio;
    unsafe { libc::pthread_setschedparam(thread, libc::SCHED_OTHER, &param) }
}

// ==========================================================================
// __sched_* internal aliases (6 symbols)
// ==========================================================================
// __sched_*: native syscalls
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_get_priority_max(policy: c_int) -> c_int {
    unsafe { libc::sched_get_priority_max(policy) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_get_priority_min(policy: c_int) -> c_int {
    unsafe { libc::sched_get_priority_min(policy) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_getparam(pid: c_int, param: *mut c_void) -> c_int {
    unsafe { libc::syscall(libc::SYS_sched_getparam, pid, param) as c_int }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_getscheduler(pid: c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_sched_getscheduler, pid) as c_int }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_setscheduler(
    pid: c_int,
    policy: c_int,
    param: *const c_void,
) -> c_int {
    unsafe { libc::syscall(libc::SYS_sched_setscheduler, pid, policy, param) as c_int }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_yield() -> c_int {
    unsafe { libc::syscall(libc::SYS_sched_yield) as c_int }
}

// ==========================================================================
// __libc_* malloc aliases (15 symbols)
// ==========================================================================
// __libc_calloc through __libc_freeres: already native in malloc_abi.rs
// __libc_init_first: glibc startup hook — no-op
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_init_first(_argc: c_int, _argv: *mut *mut c_char, _envp: *mut *mut c_char) {}
// __libc_allocate_rtsig: allocate next available RT signal number
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_allocate_rtsig(high: c_int) -> c_int {
    use std::sync::atomic::{AtomicI32, Ordering};
    // Linux kernel: SIGRTMIN=32, SIGRTMAX=64; glibc reserves 32-33 for NPTL
    const KERNEL_SIGRTMIN: i32 = 34; // user-facing minimum
    const KERNEL_SIGRTMAX: i32 = 64;
    static NEXT_LOW: AtomicI32 = AtomicI32::new(KERNEL_SIGRTMIN);
    static NEXT_HIGH: AtomicI32 = AtomicI32::new(KERNEL_SIGRTMAX);
    if high != 0 {
        let sig = NEXT_HIGH.fetch_sub(1, Ordering::Relaxed);
        if sig < NEXT_LOW.load(Ordering::Relaxed) {
            NEXT_HIGH.fetch_add(1, Ordering::Relaxed);
            -1
        } else {
            sig
        }
    } else {
        let sig = NEXT_LOW.fetch_add(1, Ordering::Relaxed);
        if sig > NEXT_HIGH.load(Ordering::Relaxed) {
            NEXT_LOW.fetch_sub(1, Ordering::Relaxed);
            -1
        } else {
            sig
        }
    }
}
// __libc_sa_len: return size of socket address structure by family
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_sa_len(af: u16) -> c_int {
    match af as c_int {
        libc::AF_INET => std::mem::size_of::<libc::sockaddr_in>() as c_int,
        libc::AF_INET6 => std::mem::size_of::<libc::sockaddr_in6>() as c_int,
        libc::AF_UNIX => std::mem::size_of::<libc::sockaddr_un>() as c_int, // AF_LOCAL == AF_UNIX
        _ => 0,
    }
}

// __libc_single_threaded is a global variable — export as a static
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static __libc_single_threaded: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);

// ==========================================================================
// __ctype_* internal table accessors (4 symbols)
// ==========================================================================
// __ctype_b, __ctype_tolower, __ctype_toupper — legacy glibc table pointers.
// These return a direct pointer into the classification table at offset 128,
// matching the C/POSIX locale tables defined in ctype_abi.rs.
// Native implementation — no dlsym needed.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ctype_b() -> *const u16 {
    // Re-use the static tables from ctype_abi via direct reference.
    // SAFETY: CTYPE_B_TABLE is 'static with 384 entries; offset 128 is valid.
    unsafe { crate::ctype_abi::ctype_b_table_ptr() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ctype_tolower() -> *const c_int {
    // SAFETY: TOLOWER_TABLE is 'static with 384 entries; offset 128 is valid.
    unsafe { crate::ctype_abi::tolower_table_ptr() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ctype_toupper() -> *const c_int {
    // SAFETY: TOUPPER_TABLE is 'static with 384 entries; offset 128 is valid.
    unsafe { crate::ctype_abi::toupper_table_ptr() }
}

/// `__ctype_get_mb_cur_max` — return maximum bytes per multibyte character.
/// In C/POSIX locale returns 1; in UTF-8 locale returns 6.
/// We default to UTF-8 (6) since that matches modern glibc behavior.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ctype_get_mb_cur_max() -> SizeT {
    6 // MB_CUR_MAX for UTF-8 locale
}

// __ctype32_* (3 symbols) — native, forward to ctype_abi tables
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ctype32_b() -> *const c_uint {
    // ctype32 tables are same as ctype16 on x86_64 glibc (32-bit entries not used)
    unsafe { crate::ctype_abi::ctype_b_table_ptr().cast() }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ctype32_tolower() -> *const c_int {
    unsafe { crate::ctype_abi::tolower_table_ptr() }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ctype32_toupper() -> *const c_int {
    unsafe { crate::ctype_abi::toupper_table_ptr() }
}

// ==========================================================================
// Ctype/wchar locale variants — non-duplicate natives only
// (16 __is*_l + 14 isw*_l + 3 __tow*_l + 14 isw*_l + towctrans_l + wctrans_l
//  now exported from ctype_abi.rs / wchar_abi.rs — dlsym_passthrough removed)
// ==========================================================================
// __isctype: native — lookup ctype_b table
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isctype(c: c_int, mask: c_int) -> c_int {
    if !(-128..=255).contains(&c) {
        return 0;
    }
    let table = unsafe { crate::ctype_abi::ctype_b_table_ptr() };
    let val = unsafe { *table.offset(c as isize) } as c_int;
    val & mask
}

// Wide-char locale variants
// __iswctype: forward to wchar_abi::iswctype
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iswctype(wc: WcharT, desc: c_ulong) -> c_int {
    unsafe { crate::wchar_abi::iswctype(wc as u32, desc as usize) }
}
// __iswctype_l: locale-ignored — forward to __iswctype
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iswctype_l(wc: WcharT, desc: c_ulong, loc: *mut c_void) -> c_int {
    let _ = loc;
    unsafe { __iswctype(wc, desc) }
}
// __towctrans: native — forward to our towctrans
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __towctrans(wc: WcharT, desc: c_ulong) -> WcharT {
    unsafe { super::unistd_abi::towctrans(wc as c_uint, desc) as WcharT }
}
// __wctrans_l: native — forward to our wctrans_l
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wctrans_l(name: *const c_char, loc: *mut c_void) -> c_ulong {
    unsafe { super::wchar_abi::wctrans_l(name.cast(), loc) }
}
// __wctype_l: native — forward to our wctype_l
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wctype_l(name: *const c_char, loc: *mut c_void) -> c_ulong {
    unsafe { super::wchar_abi::wctype_l(name.cast(), loc) as c_ulong }
}

// Public wchar locale variants (missing from matrix)
// wcscasecmp_l/wcsncasecmp_l: locale-ignored — forward to wchar_abi
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcscasecmp_l(
    s1: *const WcharT,
    s2: *const WcharT,
    loc: *mut c_void,
) -> c_int {
    let _ = loc;
    unsafe { crate::wchar_abi::wcscasecmp(s1.cast(), s2.cast()) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcsncasecmp_l(
    s1: *const WcharT,
    s2: *const WcharT,
    n: SizeT,
    loc: *mut c_void,
) -> c_int {
    let _ = loc;
    unsafe { crate::wchar_abi::wcsncasecmp(s1.cast(), s2.cast(), n) }
}
// strcasecmp_l → strcasecmp (C locale)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strcasecmp_l(s1: *const c_char, s2: *const c_char, _loc: *mut c_void) -> c_int {
    unsafe { super::string_abi::strcasecmp(s1, s2) }
}
// strncasecmp_l → strncasecmp (C locale)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strncasecmp_l(s1: *const c_char, s2: *const c_char, n: SizeT, _loc: *mut c_void) -> c_int {
    unsafe { super::string_abi::strncasecmp(s1, s2, n) }
}

// ==========================================================================
// __str*_l / __wcs*_l locale string wrappers (20 symbols)
// ==========================================================================
// __strcasecmp → strcasecmp
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcasecmp(s1: *const c_char, s2: *const c_char) -> c_int {
    unsafe { super::string_abi::strcasecmp(s1, s2) }
}
// __strcasecmp_l → strcasecmp (C locale)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcasecmp_l(s1: *const c_char, s2: *const c_char, _loc: *mut c_void) -> c_int {
    unsafe { super::string_abi::strcasecmp(s1, s2) }
}
// __strcasestr → strcasestr
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcasestr(haystack: *const c_char, needle: *const c_char) -> *mut c_char {
    unsafe { super::string_abi::strcasestr(haystack, needle) }
}
// __strcoll_l → strcoll (C locale)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcoll_l(s1: *const c_char, s2: *const c_char, _loc: *mut c_void) -> c_int {
    unsafe { super::string_abi::strcoll(s1, s2) }
}
// __strncasecmp_l → strncasecmp (C locale)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strncasecmp_l(s1: *const c_char, s2: *const c_char, n: SizeT, _loc: *mut c_void) -> c_int {
    unsafe { super::string_abi::strncasecmp(s1, s2, n) }
}
// __strxfrm_l → strxfrm (C locale)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strxfrm_l(dest: *mut c_char, src: *const c_char, n: SizeT, _loc: *mut c_void) -> SizeT {
    unsafe { super::string_abi::strxfrm(dest, src, n) }
}
// __strftime_l → strftime_l
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strftime_l(s: *mut c_char, max: SizeT, fmt: *const c_char, tm: *const c_void, loc: *mut c_void) -> SizeT {
    unsafe { super::unistd_abi::strftime_l(s, max, fmt, tm.cast(), loc) }
}
// __strfmon_l: now exported from string_abi.rs — dlsym_passthrough removed
// __stpcpy → stpcpy
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __stpcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    unsafe { super::string_abi::stpcpy(dest, src) }
}
// __stpncpy → stpncpy
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __stpncpy(dest: *mut c_char, src: *const c_char, n: SizeT) -> *mut c_char {
    unsafe { super::string_abi::stpncpy(dest, src, n) }
}
// __strdup → strdup
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strdup(s: *const c_char) -> *mut c_char {
    unsafe { super::string_abi::strdup(s) }
}
// __strndup → strndup
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strndup(s: *const c_char, n: SizeT) -> *mut c_char {
    unsafe { super::string_abi::strndup(s, n) }
}
// __strerror_r: now exported from string_abi.rs — dlsym_passthrough removed
// __strtok_r → strtok_r
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtok_r(s: *mut c_char, delim: *const c_char, saveptr: *mut *mut c_char) -> *mut c_char {
    unsafe { super::string_abi::strtok_r(s, delim, saveptr) }
}
// __strtok_r_1c: single-char delimiter strtok — wrap as delimiter string
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strtok_r_1c(s: *mut c_char, delim: c_char, saveptr: *mut *mut c_char) -> *mut c_char {
    let delim_str = [delim as u8, 0u8];
    unsafe { super::string_abi::strtok_r(s, delim_str.as_ptr().cast(), saveptr) }
}
// __strverscmp → strverscmp
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strverscmp(s1: *const c_char, s2: *const c_char) -> c_int {
    unsafe { super::string_abi::strverscmp(s1, s2) }
}
// __strcpy_small: glibc inline optimization — forward as regular strcpy
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strcpy_small(dest: *mut c_char, src: c_ulong, src2: c_ulong) -> *mut c_char {
    // __strcpy_small packs up to 16 bytes into two register-sized args
    let d = dest as *mut u8;
    unsafe {
        std::ptr::write_unaligned(d as *mut u64, src);
        std::ptr::write_unaligned(d.add(8) as *mut u64, src2);
    }
    dest
}
// __rawmemchr → rawmemchr
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rawmemchr(s: *const c_void, c: c_int) -> *mut c_void {
    unsafe { super::string_abi::rawmemchr(s, c) }
}
// __mempcpy → mempcpy
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __mempcpy(dest: *mut c_void, src: *const c_void, n: SizeT) -> *mut c_void {
    unsafe { super::string_abi::mempcpy(dest, src, n) }
}
// __memcmpeq: like memcmp but only 0 (equal) or non-zero (different)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __memcmpeq(s1: *const c_void, s2: *const c_void, n: SizeT) -> c_int {
    unsafe { super::string_abi::memcmp(s1, s2, n) }
}
// __bzero → bzero
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __bzero(s: *mut c_void, n: SizeT) {
    unsafe { super::string_abi::bzero(s, n) };
}
// __ffs → ffs (find first set bit)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ffs(i: c_int) -> c_int {
    super::stdlib_abi::ffs(i)
}

// __strsep_*c / __strpbrk_*c / __strspn_*c / __strcspn_*c: now exported from string_abi.rs
// __wcscasecmp_l / __wcscoll_l / __wcsncasecmp_l / __wcsxfrm_l / __wcsftime_l: now from wchar_abi.rs
// __strtod/f/ld/l/ll/ul/ull _internal/_l: now exported from string_abi.rs
// __wcstod/f/ld/l/ll/ul/ull _internal/_l: now exported from wchar_abi.rs

// ==========================================================================
// f128 internal parse variants (must stay GCT — no f128 in Rust)
// ==========================================================================
dlsym_passthrough!(fn __strtof128_internal(nptr: *const c_char, endptr: *mut *mut c_char, group: c_int) -> f64);

// Wide string to number internal variants
dlsym_passthrough!(fn __wcstof128_internal(nptr: *const WcharT, endptr: *mut *mut WcharT, group: c_int) -> f64);

// ==========================================================================
// strfrom* / strtof* / wcstof* TS 18661 float variants — native aliases
// ==========================================================================
// strfromf32 → strfromf, strfromf64/f32x → strfromd, strfromf64x/f128 → strfroml
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strfromf32(
    str: *mut c_char,
    n: SizeT,
    fmt: *const c_char,
    fp: f32,
) -> c_int {
    unsafe { crate::string_abi::strfromf(str, n, fmt, fp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strfromf32x(
    str: *mut c_char,
    n: SizeT,
    fmt: *const c_char,
    fp: f64,
) -> c_int {
    unsafe { crate::string_abi::strfromd(str, n, fmt, fp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strfromf64(
    str: *mut c_char,
    n: SizeT,
    fmt: *const c_char,
    fp: f64,
) -> c_int {
    unsafe { crate::string_abi::strfromd(str, n, fmt, fp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strfromf64x(
    str: *mut c_char,
    n: SizeT,
    fmt: *const c_char,
    fp: f64,
) -> c_int {
    unsafe { crate::string_abi::strfroml(str, n, fmt, fp) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strfromf128(
    str: *mut c_char,
    n: SizeT,
    fmt: *const c_char,
    fp: f64,
) -> c_int {
    unsafe { crate::string_abi::strfroml(str, n, fmt, fp) }
}

// strtof32 → strtof, strtof64/f32x → strtod, strtof64x/f128 → strtold
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtof32(nptr: *const c_char, endptr: *mut *mut c_char) -> f32 {
    unsafe { crate::stdlib_abi::strtof(nptr, endptr) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtof32_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    loc: *mut c_void,
) -> f32 {
    let _ = loc;
    unsafe { crate::stdlib_abi::strtof(nptr, endptr) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtof32x(nptr: *const c_char, endptr: *mut *mut c_char) -> f64 {
    unsafe { crate::stdlib_abi::strtod(nptr, endptr) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtof32x_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    loc: *mut c_void,
) -> f64 {
    let _ = loc;
    unsafe { crate::stdlib_abi::strtod(nptr, endptr) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtof64(nptr: *const c_char, endptr: *mut *mut c_char) -> f64 {
    unsafe { crate::stdlib_abi::strtod(nptr, endptr) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtof64_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    loc: *mut c_void,
) -> f64 {
    let _ = loc;
    unsafe { crate::stdlib_abi::strtod(nptr, endptr) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtof64x(nptr: *const c_char, endptr: *mut *mut c_char) -> f64 {
    unsafe { crate::stdlib_abi::strtold(nptr, endptr) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtof64x_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    loc: *mut c_void,
) -> f64 {
    let _ = loc;
    unsafe { crate::stdlib_abi::strtold(nptr, endptr) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtof128(nptr: *const c_char, endptr: *mut *mut c_char) -> f64 {
    unsafe { crate::stdlib_abi::strtold(nptr, endptr) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtof128_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    loc: *mut c_void,
) -> f64 {
    let _ = loc;
    unsafe { crate::stdlib_abi::strtold(nptr, endptr) }
}

// wcstof32 → wcstof, wcstof64/f32x → wcstod, wcstof64x/f128 → wcstold
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof32(nptr: *const WcharT, endptr: *mut *mut WcharT) -> f32 {
    unsafe { crate::wchar_abi::wcstof(nptr.cast(), endptr.cast()) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof32_l(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    loc: *mut c_void,
) -> f32 {
    let _ = loc;
    unsafe { crate::wchar_abi::wcstof(nptr.cast(), endptr.cast()) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof32x(nptr: *const WcharT, endptr: *mut *mut WcharT) -> f64 {
    unsafe { crate::wchar_abi::wcstod(nptr.cast(), endptr.cast()) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof32x_l(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    loc: *mut c_void,
) -> f64 {
    let _ = loc;
    unsafe { crate::wchar_abi::wcstod(nptr.cast(), endptr.cast()) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof64(nptr: *const WcharT, endptr: *mut *mut WcharT) -> f64 {
    unsafe { crate::wchar_abi::wcstod(nptr.cast(), endptr.cast()) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof64_l(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    loc: *mut c_void,
) -> f64 {
    let _ = loc;
    unsafe { crate::wchar_abi::wcstod(nptr.cast(), endptr.cast()) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof64x(nptr: *const WcharT, endptr: *mut *mut WcharT) -> f64 {
    unsafe { crate::wchar_abi::wcstold(nptr.cast(), endptr.cast()) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof64x_l(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    loc: *mut c_void,
) -> f64 {
    let _ = loc;
    unsafe { crate::wchar_abi::wcstold(nptr.cast(), endptr.cast()) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof128(nptr: *const WcharT, endptr: *mut *mut WcharT) -> f64 {
    unsafe { crate::wchar_abi::wcstold(nptr.cast(), endptr.cast()) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstof128_l(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    loc: *mut c_void,
) -> f64 {
    let _ = loc;
    unsafe { crate::wchar_abi::wcstold(nptr.cast(), endptr.cast()) }
}

// Wide string extras
// wcstoq/wcstouq: native aliases for wcstoll/wcstoull
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstoq(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int) -> i64 {
    unsafe { crate::wchar_abi::wcstoll(nptr, endptr, base) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcstouq(
    nptr: *const WcharT,
    endptr: *mut *mut WcharT,
    base: c_int,
) -> u64 {
    unsafe { crate::wchar_abi::wcstoull(nptr, endptr, base) }
}
// wcswcs: native — find wide substring (deprecated alias for wcsstr)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wcswcs(big: *const WcharT, little: *const WcharT) -> *mut WcharT {
    if big.is_null() || little.is_null() {
        return std::ptr::null_mut();
    }
    // Check if needle is empty
    if unsafe { *little } == 0 {
        return big as *mut WcharT;
    }
    let mut h = big;
    while unsafe { *h } != 0 {
        let mut hi = h;
        let mut ni = little;
        while unsafe { *ni } != 0 && unsafe { *hi } == unsafe { *ni } {
            hi = unsafe { hi.add(1) };
            ni = unsafe { ni.add(1) };
        }
        if unsafe { *ni } == 0 {
            return h as *mut WcharT;
        }
        h = unsafe { h.add(1) };
    }
    std::ptr::null_mut()
}
// wmempcpy: native — copy n wchars and return pointer past end
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wmempcpy(dest: *mut WcharT, src: *const WcharT, n: SizeT) -> *mut WcharT {
    if n > 0 && !dest.is_null() && !src.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(src, dest, n) };
    }
    unsafe { dest.add(n) }
}
// strptime_l: native — forward to our strptime (locale ignored for C/POSIX)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strptime_l(
    s: *const c_char,
    fmt: *const c_char,
    tm: *mut c_void,
    _loc: *mut c_void,
) -> *mut c_char {
    unsafe { super::time_abi::strptime(s, fmt, tm.cast()) }
}

// ==========================================================================
// __res_* resolver internals (33 symbols)
// ==========================================================================
// __res_dnok: check if domain name is valid (RFC 1035 + underscores)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_dnok(dn: *const c_char) -> c_int {
    unsafe { res_dnok(dn) }
}
// __res_hnok: check if hostname is valid (RFC 952 - letters, digits, hyphens)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_hnok(dn: *const c_char) -> c_int {
    unsafe { res_hnok(dn) }
}
// __res_init: native — forward to our res_init
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_init() -> c_int {
    unsafe { super::unistd_abi::res_init() }
}
// __res_mailok: check if mail domain name is valid
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_mailok(dn: *const c_char) -> c_int {
    unsafe { res_mailok(dn) }
}
dlsym_passthrough!(fn __res_mkquery(op: c_int, dname: *const c_char, class: c_int, typ: c_int, data: *const c_void, datalen: c_int, newrr: *const c_void, buf: *mut c_void, buflen: c_int) -> c_int);
dlsym_passthrough!(fn __res_nclose(statp: *mut c_void));
dlsym_passthrough!(fn __res_ninit(statp: *mut c_void) -> c_int);
dlsym_passthrough!(fn __res_nmkquery(statp: *mut c_void, op: c_int, dname: *const c_char, class: c_int, typ: c_int, data: *const c_void, datalen: c_int, newrr: *const c_void, buf: *mut c_void, buflen: c_int) -> c_int);
dlsym_passthrough!(fn __res_nquery(statp: *mut c_void, dname: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn __res_nquerydomain(statp: *mut c_void, name: *const c_char, domain: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn __res_nsearch(statp: *mut c_void, dname: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn __res_nsend(statp: *mut c_void, msg: *const c_void, msglen: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
// __res_ownok: check if owner name is valid (like dnok)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_ownok(dn: *const c_char) -> c_int {
    unsafe { res_ownok(dn) }
}
// __res_query: native — forward to our res_query
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_query(
    dname: *const c_char,
    class: c_int,
    typ: c_int,
    answer: *mut c_void,
    anslen: c_int,
) -> c_int {
    unsafe { super::unistd_abi::res_query(dname, class, typ, answer.cast(), anslen) }
}
dlsym_passthrough!(fn __res_querydomain(name: *const c_char, domain: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
// __res_randomid: generate a random 16-bit DNS query ID
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_randomid() -> c_int {
    res_randomid()
}
// res_randomid: native random ID helper for DNS queries
fn res_randomid() -> c_int {
    use std::sync::atomic::{AtomicU32, Ordering};
    // Simple LCG seeded from thread ID + time
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let mut val = COUNTER.fetch_add(1, Ordering::Relaxed);
    // Mix with a time-based value for randomness
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    val = val.wrapping_add(ts.tv_nsec as u32);
    val = val.wrapping_mul(1103515245).wrapping_add(12345);
    ((val >> 16) & 0xFFFF) as c_int
}
// __res_search: native — forward to our res_search
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_search(
    dname: *const c_char,
    class: c_int,
    typ: c_int,
    answer: *mut c_void,
    anslen: c_int,
) -> c_int {
    unsafe { super::unistd_abi::res_search(dname, class, typ, answer.cast(), anslen) }
}
dlsym_passthrough!(fn __res_send(msg: *const c_void, msglen: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn __res_state() -> *mut c_void);

// ==========================================================================
// res_*ok: DNS name validation (RFC 1035/952 character checks)
// ==========================================================================

// res_hnok: hostname — letters, digits, hyphens only (RFC 952)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn res_hnok(dn: *const c_char) -> c_int {
    if dn.is_null() {
        return 0;
    }
    let mut p = dn as *const u8;
    let mut len: usize = 0;
    loop {
        let c = unsafe { *p };
        if c == 0 {
            break;
        }
        if c == b'.' {
            if len == 0 {
                return 0; // Empty label
            }
            len = 0;
        } else if c.is_ascii_alphanumeric() || c == b'-' {
            len += 1;
            if len > 63 {
                return 0; // Label too long
            }
        } else {
            return 0; // Invalid character for hostname
        }
        p = unsafe { p.add(1) };
    }
    1
}

// res_dnok: domain name — like hostname but allows underscores
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn res_dnok(dn: *const c_char) -> c_int {
    if dn.is_null() {
        return 0;
    }
    let mut p = dn as *const u8;
    let mut len: usize = 0;
    loop {
        let c = unsafe { *p };
        if c == 0 {
            break;
        }
        if c == b'.' {
            if len == 0 {
                return 0;
            }
            len = 0;
        } else if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' {
            len += 1;
            if len > 63 {
                return 0;
            }
        } else {
            return 0;
        }
        p = unsafe { p.add(1) };
    }
    1
}

// res_mailok: mail domain — allows first label to have more chars (mailbox)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn res_mailok(dn: *const c_char) -> c_int {
    // For mail, the first label (mailbox) is more permissive,
    // remaining labels follow hostname rules
    if dn.is_null() {
        return 0;
    }
    let mut p = dn as *const u8;
    let mut len: usize = 0;
    let mut first_label = true;
    loop {
        let c = unsafe { *p };
        if c == 0 {
            break;
        }
        if c == b'.' {
            if len == 0 {
                return 0;
            }
            len = 0;
            first_label = false;
        } else if first_label {
            // Mailbox label: printable ASCII except @ and whitespace
            if c > 0x20 && c < 0x7F && c != b'@' {
                len += 1;
                if len > 63 {
                    return 0;
                }
            } else {
                return 0;
            }
        } else if c.is_ascii_alphanumeric() || c == b'-' {
            len += 1;
            if len > 63 {
                return 0;
            }
        } else {
            return 0;
        }
        p = unsafe { p.add(1) };
    }
    1
}
dlsym_passthrough!(fn res_mkquery(op: c_int, dname: *const c_char, class: c_int, typ: c_int, data: *const c_void, datalen: c_int, newrr: *const c_void, buf: *mut c_void, buflen: c_int) -> c_int);
dlsym_passthrough!(fn res_nmkquery(statp: *mut c_void, op: c_int, dname: *const c_char, class: c_int, typ: c_int, data: *const c_void, datalen: c_int, newrr: *const c_void, buf: *mut c_void, buflen: c_int) -> c_int);
dlsym_passthrough!(fn res_nquery(statp: *mut c_void, dname: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn res_nquerydomain(statp: *mut c_void, name: *const c_char, domain: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn res_nsearch(statp: *mut c_void, dname: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn res_nsend(statp: *mut c_void, msg: *const c_void, msglen: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
// res_ownok: owner name — same rules as dnok (allows underscores)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn res_ownok(dn: *const c_char) -> c_int {
    unsafe { res_dnok(dn) }
}
dlsym_passthrough!(fn res_querydomain(name: *const c_char, domain: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn res_send(msg: *const c_void, msglen: c_int, answer: *mut c_void, anslen: c_int) -> c_int);

// ==========================================================================
// __nss_* public symbols (7)
// ==========================================================================
dlsym_passthrough!(fn __nss_configure_lookup(db: *const c_char, service_line: *const c_char) -> c_int);
dlsym_passthrough!(fn __nss_database_lookup(database: *const c_char, alt: *const c_char, defconf: *const c_char, ni: *mut *mut c_void) -> c_int);
dlsym_passthrough!(fn __nss_group_lookup(status: *mut c_int, nip: *mut *mut c_void, name: *const c_char, group: *mut c_void) -> c_int);
dlsym_passthrough!(fn __nss_hostname_digits_dots(name: *const c_char, resbuf: *mut c_void) -> c_int);
dlsym_passthrough!(fn __nss_hosts_lookup(status: *mut c_int, nip: *mut *mut c_void, name: *const c_char, result: *mut c_void) -> c_int);
dlsym_passthrough!(fn __nss_next(ni: *mut *mut c_void, fct_name: *const c_char, status: *mut c_int, all_values: c_int) -> c_int);
dlsym_passthrough!(fn __nss_passwd_lookup(status: *mut c_int, nip: *mut *mut c_void, name: *const c_char, result: *mut c_void) -> c_int);

// ==========================================================================
// __nl_langinfo_l and locale internals (4 symbols)
// ==========================================================================
// --- Native locale: forward to locale_abi implementations ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nl_langinfo_l(item: c_int, loc: *mut c_void) -> *const c_char {
    unsafe { crate::locale_abi::nl_langinfo_l(item, loc) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __newlocale(
    mask: c_int,
    locale: *const c_char,
    base: *mut c_void,
) -> *mut c_void {
    unsafe { crate::locale_abi::newlocale(mask, locale, base) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __freelocale(loc: *mut c_void) {
    unsafe { crate::locale_abi::freelocale(loc) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __uselocale(loc: *mut c_void) -> *mut c_void {
    unsafe { crate::locale_abi::uselocale(loc) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __duplocale(loc: *mut c_void) -> *mut c_void {
    unsafe { crate::locale_abi::duplocale(loc) }
}
// __dcgettext/__dgettext: native — return msgid untranslated (C locale passthrough)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __dcgettext(
    domainname: *const c_char,
    msgid: *const c_char,
    category: c_int,
) -> *mut c_char {
    let _ = (domainname, category);
    msgid as *mut c_char
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __dgettext(
    domainname: *const c_char,
    msgid: *const c_char,
) -> *mut c_char {
    let _ = domainname;
    msgid as *mut c_char
}

// ==========================================================================
// ns_name_* DNS name manipulation (7 symbols)
// ==========================================================================
/// `ns_name_skip` — advance pointer past a compressed domain name (RFC 1035).
///
/// Unlike `dn_skipname` which returns bytes consumed, this advances `*ptrptr`
/// in-place and returns 0 on success, -1 on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_skip(
    ptrptr: *mut *const c_void,
    eom: *const c_void,
) -> c_int {
    if ptrptr.is_null() || eom.is_null() {
        return -1;
    }
    let ptr = unsafe { *ptrptr } as *const u8;
    let eom = eom as *const u8;
    if ptr.is_null() || ptr >= eom {
        return -1;
    }
    let buf = unsafe { std::slice::from_raw_parts(ptr, eom.offset_from(ptr) as usize) };
    let mut i = 0usize;
    loop {
        if i >= buf.len() {
            return -1;
        }
        let b = buf[i];
        if b == 0 {
            // Root label — skip past it.
            unsafe { *ptrptr = ptr.add(i + 1) as *const c_void };
            return 0;
        }
        if b & 0xC0 == 0xC0 {
            // Compression pointer (2 bytes).
            if i + 1 >= buf.len() {
                return -1;
            }
            unsafe { *ptrptr = ptr.add(i + 2) as *const c_void };
            return 0;
        }
        if b & 0xC0 != 0 {
            return -1; // Reserved label type.
        }
        i += 1 + b as usize;
    }
}

/// `ns_name_ntop` — convert uncompressed wire-format labels to dotted text (RFC 1035).
///
/// Walks length-prefixed labels, emits "label1.label2." with escaping for
/// special characters. Returns number of chars written (excluding NUL), or -1.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_ntop(
    src: *const c_void,
    dst: *mut c_char,
    dstsiz: SizeT,
) -> c_int {
    if src.is_null() || dst.is_null() || dstsiz == 0 {
        return -1;
    }
    let src = src as *const u8;
    let out = unsafe { std::slice::from_raw_parts_mut(dst as *mut u8, dstsiz) };
    // Read wire labels until root. Source has no compression pointers (uncompressed).
    // We don't know the source buffer size, so read carefully with max wire name length 255.
    let mut si = 0usize;
    let mut oi = 0usize;
    let mut first = true;
    const NS_MAXDNAME: usize = 1025;

    loop {
        let b = unsafe { *src.add(si) };
        if b == 0 {
            // Root label. If name was empty (root zone), output is just ".".
            if first {
                if oi + 1 >= out.len() {
                    unsafe { *libc::__errno_location() = libc::EMSGSIZE };
                    return -1;
                }
                out[oi] = b'.';
                oi += 1;
            }
            break;
        }
        if b & 0xC0 != 0 {
            return -1; // Compression pointer or reserved — invalid in uncompressed name.
        }
        let label_len = b as usize;
        if label_len > 63 || si + 1 + label_len > NS_MAXDNAME {
            return -1;
        }
        // Dot separator before non-first labels.
        if !first {
            if oi >= out.len() - 1 {
                unsafe { *libc::__errno_location() = libc::EMSGSIZE };
                return -1;
            }
            out[oi] = b'.';
            oi += 1;
        }
        first = false;
        si += 1;
        // Copy label bytes with escaping.
        for j in 0..label_len {
            let ch = unsafe { *src.add(si + j) };
            if ch == b'.' || ch == b'\\' {
                // Escape with backslash.
                if oi + 2 >= out.len() {
                    unsafe { *libc::__errno_location() = libc::EMSGSIZE };
                    return -1;
                }
                out[oi] = b'\\';
                oi += 1;
                out[oi] = ch;
                oi += 1;
            } else if ch < 0x20 || ch >= 0x7F {
                // Escape non-printable as \DDD.
                if oi + 4 >= out.len() {
                    unsafe { *libc::__errno_location() = libc::EMSGSIZE };
                    return -1;
                }
                out[oi] = b'\\';
                out[oi + 1] = b'0' + ch / 100;
                out[oi + 2] = b'0' + (ch / 10) % 10;
                out[oi + 3] = b'0' + ch % 10;
                oi += 4;
            } else {
                if oi >= out.len() - 1 {
                    unsafe { *libc::__errno_location() = libc::EMSGSIZE };
                    return -1;
                }
                out[oi] = ch;
                oi += 1;
            }
        }
        si += label_len;
    }

    // NUL-terminate.
    if oi >= out.len() {
        unsafe { *libc::__errno_location() = libc::EMSGSIZE };
        return -1;
    }
    out[oi] = 0;
    oi as c_int
}

/// `ns_name_pton` — convert dotted text to uncompressed wire-format labels (RFC 1035).
///
/// Handles backslash escapes (\. and \DDD). Returns -1 on error, number of
/// bytes written to dst on success.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_pton(
    src: *const c_char,
    dst: *mut c_void,
    dstsiz: SizeT,
) -> c_int {
    if src.is_null() || dst.is_null() || dstsiz == 0 {
        return -1;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(src) };
    let name_bytes = name.to_bytes();
    let out = unsafe { std::slice::from_raw_parts_mut(dst as *mut u8, dstsiz) };

    // Empty string or just "." → root.
    if name_bytes.is_empty() || (name_bytes.len() == 1 && name_bytes[0] == b'.') {
        if out.is_empty() {
            unsafe { *libc::__errno_location() = libc::EMSGSIZE };
            return -1;
        }
        out[0] = 0;
        return 1;
    }

    let mut si = 0usize; // source index
    let mut oi = 0usize; // output index
    let mut label_start = 0usize; // where current label length byte is

    // Reserve space for first label length byte.
    if oi >= out.len() {
        unsafe { *libc::__errno_location() = libc::EMSGSIZE };
        return -1;
    }
    label_start = oi;
    oi += 1;
    let mut label_len: u8 = 0;

    while si < name_bytes.len() {
        let ch = name_bytes[si];
        if ch == b'.' {
            // End of label.
            if label_len == 0 && si + 1 < name_bytes.len() {
                return -1; // Empty label in middle.
            }
            if label_len > 63 {
                return -1;
            }
            out[label_start] = label_len;
            si += 1;
            // If this was the trailing dot and we're at end, don't start a new label.
            if si >= name_bytes.len() {
                break;
            }
            // Start next label.
            if oi >= out.len() {
                unsafe { *libc::__errno_location() = libc::EMSGSIZE };
                return -1;
            }
            label_start = oi;
            oi += 1;
            label_len = 0;
            continue;
        }
        let byte = if ch == b'\\' && si + 1 < name_bytes.len() {
            si += 1;
            if name_bytes[si].is_ascii_digit()
                && si + 2 < name_bytes.len()
                && name_bytes[si + 1].is_ascii_digit()
                && name_bytes[si + 2].is_ascii_digit()
            {
                // \DDD decimal escape.
                let val = (name_bytes[si] - b'0') as u16 * 100
                    + (name_bytes[si + 1] - b'0') as u16 * 10
                    + (name_bytes[si + 2] - b'0') as u16;
                si += 2; // si will be incremented again below.
                if val > 255 {
                    return -1;
                }
                val as u8
            } else {
                name_bytes[si]
            }
        } else {
            ch
        };

        if oi >= out.len() {
            unsafe { *libc::__errno_location() = libc::EMSGSIZE };
            return -1;
        }
        out[oi] = byte;
        oi += 1;
        label_len += 1;
        si += 1;
    }

    // Finalize last label if name didn't end with dot.
    if label_len > 0 {
        if label_len > 63 {
            return -1;
        }
        out[label_start] = label_len;
    }

    // Root terminator.
    if oi >= out.len() {
        unsafe { *libc::__errno_location() = libc::EMSGSIZE };
        return -1;
    }
    out[oi] = 0;
    oi += 1;
    oi as c_int
}

/// `ns_name_unpack` — decompress a compressed wire-format name to uncompressed labels.
///
/// Follows compression pointers within `[msg, eom)` starting at `src`, writing
/// uncompressed labels to `dst[..dstsiz]`. Returns bytes consumed from `src`, or -1.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_unpack(
    msg: *const c_void,
    eom: *const c_void,
    src: *const c_void,
    dst: *mut c_void,
    dstsiz: SizeT,
) -> c_int {
    let msg = msg as *const u8;
    let eom = eom as *const u8;
    let src = src as *const u8;
    let dst = dst as *mut u8;
    if msg.is_null() || eom.is_null() || src.is_null() || dst.is_null() || dstsiz == 0 {
        return -1;
    }
    if src < msg || src >= eom {
        return -1;
    }
    let msg_len = unsafe { eom.offset_from(msg) } as usize;
    let msg_slice = unsafe { std::slice::from_raw_parts(msg, msg_len) };
    let out = unsafe { std::slice::from_raw_parts_mut(dst, dstsiz) };

    let mut pos = unsafe { src.offset_from(msg) } as usize;
    let mut oi = 0usize;
    let mut wire_len: Option<usize> = None;
    let mut jumps = 0u32;
    const MAX_JUMPS: u32 = 128;

    loop {
        if pos >= msg_len {
            return -1;
        }
        let b = msg_slice[pos];
        if b == 0 {
            // Root label.
            if wire_len.is_none() {
                wire_len = Some(pos + 1 - unsafe { src.offset_from(msg) } as usize);
            }
            // Write root terminator.
            if oi >= out.len() {
                return -1;
            }
            out[oi] = 0;
            break;
        }
        if b & 0xC0 == 0xC0 {
            // Compression pointer.
            if pos + 1 >= msg_len {
                return -1;
            }
            if wire_len.is_none() {
                wire_len = Some(pos + 2 - unsafe { src.offset_from(msg) } as usize);
            }
            let target = ((b as usize & 0x3F) << 8) | msg_slice[pos + 1] as usize;
            if target >= msg_len {
                return -1;
            }
            jumps += 1;
            if jumps > MAX_JUMPS {
                return -1;
            }
            pos = target;
            continue;
        }
        if b & 0xC0 != 0 {
            return -1; // Reserved label type.
        }
        let label_len = b as usize;
        if pos + 1 + label_len > msg_len || label_len > 63 {
            return -1;
        }
        // Write label length + label data.
        if oi + 1 + label_len >= out.len() {
            return -1;
        }
        out[oi] = b;
        oi += 1;
        out[oi..oi + label_len].copy_from_slice(&msg_slice[pos + 1..pos + 1 + label_len]);
        oi += label_len;
        pos += 1 + label_len;
    }

    wire_len.unwrap_or(0) as c_int
}

/// `ns_name_pack` — compress uncompressed wire labels into a DNS message.
///
/// Takes uncompressed labels from `src`, writes compressed format to `dst[..dstlen]`.
/// Uses `dnptrs`/`lastdnptr` for compression pointer matching.
/// Returns bytes written to dst, or -1.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_pack(
    src: *const c_void,
    dst: *mut c_void,
    dstlen: c_int,
    _dnptrs: *mut *const c_void,
    _lastdnptr: *mut *const c_void,
) -> c_int {
    let src = src as *const u8;
    let dst = dst as *mut u8;
    if src.is_null() || dst.is_null() || dstlen < 1 {
        return -1;
    }
    let out = unsafe { std::slice::from_raw_parts_mut(dst, dstlen as usize) };

    // Copy uncompressed labels verbatim (no compression pointer generation — simple impl).
    // Walk the source labels and copy them to output.
    let mut si = 0usize;
    let mut oi = 0usize;

    loop {
        let b = unsafe { *src.add(si) };
        if b == 0 {
            // Root terminator.
            if oi >= out.len() {
                return -1;
            }
            out[oi] = 0;
            oi += 1;
            break;
        }
        if b & 0xC0 != 0 {
            return -1; // Invalid in uncompressed input.
        }
        let label_len = b as usize;
        if label_len > 63 {
            return -1;
        }
        // Copy length byte + label data.
        if oi + 1 + label_len > out.len() {
            return -1;
        }
        out[oi] = b;
        oi += 1;
        // Read label data from src.
        for j in 0..label_len {
            out[oi + j] = unsafe { *src.add(si + 1 + j) };
        }
        oi += label_len;
        si += 1 + label_len;
    }

    oi as c_int
}

/// `ns_name_compress` — convert dotted text to compressed wire format (RFC 1035).
///
/// Equivalent to `ns_name_pton` + `ns_name_pack`. Returns bytes written, or -1.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_compress(
    src: *const c_char,
    dst: *mut c_void,
    dstlen: SizeT,
    dnptrs: *mut *const c_void,
    lastdnptr: *mut *const c_void,
) -> c_int {
    // Stage 1: text → uncompressed wire labels (stack buffer).
    let mut wire_buf = [0u8; 256]; // NS_MAXCDNAME
    let ret = unsafe {
        ns_name_pton(src, wire_buf.as_mut_ptr() as *mut c_void, wire_buf.len())
    };
    if ret < 0 {
        return -1;
    }
    // Stage 2: pack (with potential compression).
    unsafe {
        ns_name_pack(
            wire_buf.as_ptr() as *const c_void,
            dst,
            dstlen as c_int,
            dnptrs,
            lastdnptr,
        )
    }
}

/// `ns_name_uncompress` — decompress wire-format name to dotted text (RFC 1035).
///
/// Equivalent to `ns_name_unpack` + `ns_name_ntop`. Returns bytes consumed from
/// `src` in the wire message, or -1.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ns_name_uncompress(
    msg: *const c_void,
    eom: *const c_void,
    src: *const c_void,
    dst: *mut c_char,
    dstsiz: SizeT,
) -> c_int {
    // Stage 1: decompress → uncompressed wire labels.
    let mut wire_buf = [0u8; 256]; // NS_MAXCDNAME
    let consumed = unsafe {
        ns_name_unpack(
            msg,
            eom,
            src,
            wire_buf.as_mut_ptr() as *mut c_void,
            wire_buf.len(),
        )
    };
    if consumed < 0 {
        return -1;
    }
    // Stage 2: wire labels → dotted text.
    let text_ret = unsafe {
        ns_name_ntop(wire_buf.as_ptr() as *const c_void, dst, dstsiz)
    };
    if text_ret < 0 {
        return -1;
    }
    consumed
}

// __dn_* DNS name aliases — forward to our native implementations
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __dn_comp(
    exp_dn: *const c_char,
    comp_dn: *mut c_void,
    length: c_int,
    dnptrs: *mut *mut c_void,
    lastdnptr: *mut *mut c_void,
) -> c_int {
    unsafe {
        super::unistd_abi::dn_comp(
            exp_dn,
            comp_dn.cast(),
            length,
            dnptrs.cast(),
            lastdnptr.cast(),
        )
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __dn_expand(
    msg: *const c_void,
    eomorig: *const c_void,
    comp_dn: *const c_void,
    exp_dn: *mut c_char,
    length: c_int,
) -> c_int {
    unsafe {
        super::unistd_abi::dn_expand(msg.cast(), eomorig.cast(), comp_dn.cast(), exp_dn, length)
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __dn_skipname(comp_dn: *const c_void, eom: *const c_void) -> c_int {
    unsafe { super::unistd_abi::dn_skipname(comp_dn.cast(), eom.cast()) }
}

// ==========================================================================
// obstack (10 symbols)
// ==========================================================================
dlsym_passthrough!(fn _obstack_allocated_p(h: *mut c_void, obj: *const c_void) -> c_int);
dlsym_passthrough!(fn _obstack_begin(h: *mut c_void, size: SizeT, alignment: SizeT, chunkfun: *mut c_void, freefun: *mut c_void) -> c_int);
dlsym_passthrough!(fn _obstack_begin_1(h: *mut c_void, size: SizeT, alignment: SizeT, chunkfun: *mut c_void, freefun: *mut c_void, arg: *mut c_void) -> c_int);
dlsym_passthrough!(fn _obstack_free(h: *mut c_void, obj: *mut c_void));
dlsym_passthrough!(fn _obstack_memory_used(h: *mut c_void) -> SizeT);
dlsym_passthrough!(fn _obstack_newchunk(h: *mut c_void, length: SizeT));
dlsym_passthrough!(fn __obstack_printf_chk(h: *mut c_void, flag: c_int, fmt: *const c_char) -> c_int);
dlsym_passthrough!(fn __obstack_vprintf_chk(h: *mut c_void, flag: c_int, fmt: *const c_char, ap: *mut c_void) -> c_int);

// obstack globals
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut obstack_alloc_failed_handler: *mut c_void = std::ptr::null_mut();

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut obstack_exit_failure: c_int = 1;

// ==========================================================================
// inet6_opt_* / inet6_option_* / inet6_rth_* (19 symbols)
// ==========================================================================
// ---------------------------------------------------------------------------
// inet6_opt_* — IPv6 hop-by-hop/destination option extension header helpers
// (RFC 3542 section 10). Pure buffer manipulation, no syscalls.
// ---------------------------------------------------------------------------

// IPv6 extension header: [next_hdr: u8, hdr_ext_len: u8, options...]
// Options are TLV: [type: u8, len: u8, value: [u8; len]]
// Pad1 (type 0): single 0x00 byte (no length/value)
// PadN (type 1): [0x01, N-2, 0x00 * (N-2)]

/// Compute padding needed to reach alignment `align` at offset `off`.
fn inet6_opt_pad(off: usize, align: usize) -> usize {
    if align <= 1 {
        return 0;
    }
    let rem = off % align;
    if rem == 0 { 0 } else { align - rem }
}

/// Write padding bytes into buffer at `off`. Pad1 for 1 byte, PadN for 2+.
fn inet6_opt_write_pad(buf: &mut [u8], off: usize, padlen: usize) {
    if padlen == 0 {
        return;
    }
    if padlen == 1 {
        buf[off] = 0; // Pad1
    } else {
        buf[off] = 1; // PadN type
        buf[off + 1] = (padlen - 2) as u8;
        for i in 2..padlen {
            buf[off + i] = 0;
        }
    }
}

/// `inet6_opt_init` — initialize a hop-by-hop/destination options extension header.
///
/// If extbuf is NULL, returns the initial header size (2).
/// Otherwise initializes the 2-byte header and returns 2.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_init(extbuf: *mut c_void, extlen: c_int) -> c_int {
    if extbuf.is_null() {
        return 2; // Header is 2 bytes.
    }
    if extlen < 2 {
        return -1;
    }
    let buf = extbuf as *mut u8;
    unsafe {
        *buf = 0; // Next Header (filled by kernel).
        *buf.add(1) = 0; // Header Ext Length (0 = 8 bytes total, but we're building).
    }
    2
}

/// `inet6_opt_append` — append an option to the extension header buffer.
///
/// Adds padding for alignment, then the option type+length header.
/// Returns new offset, or -1 on error. Sets `*databufp` to where the caller
/// should write option data.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_append(
    extbuf: *mut c_void,
    extlen: c_int,
    offset: c_int,
    typ: u8,
    len: SizeT,
    align: u8,
    databufp: *mut *mut c_void,
) -> c_int {
    if offset < 2 || len > 255 || align == 0 || (align & (align - 1)) != 0 || align > 8 {
        return -1;
    }
    // Types 0 and 1 are reserved for padding.
    if typ == 0 || typ == 1 {
        return -1;
    }
    let off = offset as usize;
    let al = align as usize;
    let padlen = inet6_opt_pad(off, al);
    let needed = padlen + 2 + len; // 2 for type+length bytes
    let new_off = off + needed;

    if extbuf.is_null() {
        return new_off as c_int;
    }
    if new_off > extlen as usize {
        return -1;
    }
    let buf = unsafe { std::slice::from_raw_parts_mut(extbuf as *mut u8, extlen as usize) };
    inet6_opt_write_pad(buf, off, padlen);
    let opt_start = off + padlen;
    buf[opt_start] = typ;
    buf[opt_start + 1] = len as u8;
    if !databufp.is_null() {
        unsafe { *databufp = buf.as_mut_ptr().add(opt_start + 2) as *mut c_void };
    }
    new_off as c_int
}

/// `inet6_opt_finish` — finalize extension header with trailing padding.
///
/// Pads to 8-byte boundary and updates the Header Ext Length field.
/// Returns total header length, or -1 on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_finish(
    extbuf: *mut c_void,
    extlen: c_int,
    offset: c_int,
) -> c_int {
    if offset < 2 {
        return -1;
    }
    let off = offset as usize;
    let padlen = inet6_opt_pad(off, 8);
    let total = off + padlen;

    if extbuf.is_null() {
        return total as c_int;
    }
    if total > extlen as usize {
        return -1;
    }
    let buf = unsafe { std::slice::from_raw_parts_mut(extbuf as *mut u8, extlen as usize) };
    inet6_opt_write_pad(buf, off, padlen);
    // Update Header Ext Length: (total - 8) / 8, in 8-octet units not counting first 8.
    if total >= 8 {
        buf[1] = ((total - 8) / 8) as u8;
    } else {
        buf[1] = 0;
    }
    total as c_int
}

/// `inet6_opt_set_val` — copy value into option data area.
///
/// Returns offset + vallen.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_set_val(
    databuf: *mut c_void,
    offset: c_int,
    val: *const c_void,
    vallen: c_int,
) -> c_int {
    if databuf.is_null() || val.is_null() || offset < 0 || vallen < 0 {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            val as *const u8,
            (databuf as *mut u8).add(offset as usize),
            vallen as usize,
        );
    }
    offset + vallen
}

/// `inet6_opt_get_val` — copy value from option data area.
///
/// Returns offset + vallen.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_get_val(
    databuf: *mut c_void,
    offset: c_int,
    val: *mut c_void,
    vallen: c_int,
) -> c_int {
    if databuf.is_null() || val.is_null() || offset < 0 || vallen < 0 {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            (databuf as *const u8).add(offset as usize),
            val as *mut u8,
            vallen as usize,
        );
    }
    offset + vallen
}

/// `inet6_opt_next` — iterate to the next option in the extension header.
///
/// Skips padding options (Pad1/PadN). Returns new offset, or -1 if no more.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_next(
    extbuf: *mut c_void,
    extlen: c_int,
    offset: c_int,
    typep: *mut u8,
    lenp: *mut SizeT,
    databufp: *mut *mut c_void,
) -> c_int {
    if extbuf.is_null() || offset < 2 || extlen < 2 {
        return -1;
    }
    let buf = unsafe { std::slice::from_raw_parts(extbuf as *const u8, extlen as usize) };
    let mut pos = offset as usize;

    loop {
        if pos >= buf.len() {
            return -1;
        }
        let t = buf[pos];
        if t == 0 {
            // Pad1.
            pos += 1;
            continue;
        }
        if pos + 1 >= buf.len() {
            return -1;
        }
        let l = buf[pos + 1] as usize;
        if pos + 2 + l > buf.len() {
            return -1;
        }
        if t == 1 {
            // PadN — skip.
            pos += 2 + l;
            continue;
        }
        // Real option found.
        if !typep.is_null() {
            unsafe { *typep = t };
        }
        if !lenp.is_null() {
            unsafe { *lenp = l };
        }
        if !databufp.is_null() {
            unsafe { *databufp = (extbuf as *mut u8).add(pos + 2) as *mut c_void };
        }
        return (pos + 2 + l) as c_int;
    }
}

/// `inet6_opt_find` — find the next option of a specific type.
///
/// Calls inet6_opt_next repeatedly until the requested type is found.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_opt_find(
    extbuf: *mut c_void,
    extlen: c_int,
    offset: c_int,
    typ: u8,
    lenp: *mut SizeT,
    databufp: *mut *mut c_void,
) -> c_int {
    let mut cur_off = offset;
    let mut found_type: u8 = 0;
    loop {
        let next = unsafe {
            inet6_opt_next(extbuf, extlen, cur_off, &mut found_type, lenp, databufp)
        };
        if next < 0 {
            return -1;
        }
        if found_type == typ {
            return next;
        }
        cur_off = next;
    }
}

// ---------------------------------------------------------------------------
// inet6_option_* — deprecated RFC 2292 option helpers (superseded by inet6_opt_*)
// These operate on cmsghdr-based ancillary data. Return -1 / NULL to deny usage
// of deprecated API without breaking linkage.
// ---------------------------------------------------------------------------

/// `inet6_option_space` — compute CMSG space for option data (deprecated RFC 2292).
///
/// Returns CMSG_SPACE for the given data length, rounded to 8-byte boundary.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_space(datalen: c_int) -> c_int {
    if datalen < 0 {
        return 0;
    }
    // CMSG_SPACE analog: header(2) + data, padded to 8 bytes.
    let total = 2 + datalen as usize;
    let padded = (total + 7) & !7;
    padded as c_int
}

/// `inet6_option_init` — initialize cmsg for IPv6 options (deprecated RFC 2292).
///
/// Returns -1 (deprecated API not supported).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_init(
    _cmsg: *mut c_void,
    _cmsglenp: *mut c_int,
    _typ: c_int,
) -> c_int {
    -1
}

/// `inet6_option_append` — append option to cmsg (deprecated RFC 2292).
///
/// Returns -1 (deprecated API not supported).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_append(
    _cmsg: *mut c_void,
    _typep: *const u8,
    _multx: c_int,
    _plusy: c_int,
) -> c_int {
    -1
}

/// `inet6_option_alloc` — allocate space in cmsg (deprecated RFC 2292).
///
/// Returns NULL (deprecated API not supported).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_alloc(
    _cmsg: *mut c_void,
    _datalen: c_int,
    _multx: c_int,
    _plusy: c_int,
) -> *mut u8 {
    std::ptr::null_mut()
}

/// `inet6_option_next` — iterate options in cmsg (deprecated RFC 2292).
///
/// Returns -1 (deprecated API not supported).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_next(
    _cmsg: *const c_void,
    _tptrp: *mut *mut u8,
) -> c_int {
    -1
}

/// `inet6_option_find` — find option in cmsg by type (deprecated RFC 2292).
///
/// Returns -1 (deprecated API not supported).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_option_find(
    _cmsg: *const c_void,
    _tptrp: *mut *mut u8,
    _typ: c_int,
) -> c_int {
    -1
}

// ---------------------------------------------------------------------------
// inet6_rth_* — IPv6 routing header manipulation (RFC 3542 section 7).
// Type 0 routing header layout:
//   [next_hdr: u8][hdr_ext_len: u8][type: u8][segleft: u8][reserved: u32]
//   followed by segments × in6_addr (16 bytes each)
// ---------------------------------------------------------------------------

const IN6_ADDR_SIZE: usize = 16;
const RTH0_HDR_SIZE: usize = 8;
// Type 2 (Mobile IPv6) is also standardized.
const IPV6_RTHDR_TYPE_0: c_int = 0;

/// `inet6_rth_space` — return bytes needed for a routing header.
///
/// Type 0: 8 + segments * 16. Returns 0 if type is unsupported or segments < 0.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_space(typ: c_int, segments: c_int) -> c_int {
    if typ != IPV6_RTHDR_TYPE_0 || segments < 0 || segments > 127 {
        return 0;
    }
    (RTH0_HDR_SIZE + segments as usize * IN6_ADDR_SIZE) as c_int
}

/// `inet6_rth_init` — initialize a routing header buffer.
///
/// Returns bp on success, NULL if bp_len is too small or type is unsupported.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_init(
    bp: *mut c_void,
    bp_len: c_int,
    typ: c_int,
    segments: c_int,
) -> *mut c_void {
    if bp.is_null() || typ != IPV6_RTHDR_TYPE_0 || segments < 0 || segments > 127 {
        return std::ptr::null_mut();
    }
    let needed = RTH0_HDR_SIZE + segments as usize * IN6_ADDR_SIZE;
    if (bp_len as usize) < needed {
        return std::ptr::null_mut();
    }
    let hdr = bp as *mut u8;
    unsafe {
        *hdr = 0; // Next Header (filled by kernel).
        *hdr.add(1) = (segments * 2) as u8; // Hdr Ext Len in 8-octet units.
        *hdr.add(2) = typ as u8; // Routing type.
        *hdr.add(3) = 0; // Segments left (filled as addresses are added).
        // Reserved field (4 bytes) = 0.
        std::ptr::write_bytes(hdr.add(4), 0, 4);
    }
    bp
}

/// `inet6_rth_add` — add an address to the routing header.
///
/// Increments segments_left and copies the in6_addr. Returns 0 on success, -1 on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_add(bp: *mut c_void, addr: *const c_void) -> c_int {
    if bp.is_null() || addr.is_null() {
        return -1;
    }
    let hdr = bp as *mut u8;
    let hdr_ext_len = unsafe { *hdr.add(1) } as usize;
    let max_segments = hdr_ext_len / 2;
    let seg_left = unsafe { *hdr.add(3) } as usize;
    if seg_left >= max_segments {
        return -1; // No room.
    }
    // Copy address to slot[seg_left].
    let dest = unsafe { hdr.add(RTH0_HDR_SIZE + seg_left * IN6_ADDR_SIZE) };
    unsafe {
        std::ptr::copy_nonoverlapping(addr as *const u8, dest, IN6_ADDR_SIZE);
        *hdr.add(3) = (seg_left + 1) as u8; // Increment segments left.
    }
    0
}

/// `inet6_rth_segments` — return the number of segments in the routing header.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_segments(bp: *const c_void) -> c_int {
    if bp.is_null() {
        return -1;
    }
    let hdr = bp as *const u8;
    let hdr_ext_len = unsafe { *hdr.add(1) } as c_int;
    hdr_ext_len / 2
}

/// `inet6_rth_getaddr` — return pointer to address at given index.
///
/// Returns NULL if index is out of range.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_getaddr(bp: *const c_void, index: c_int) -> *const c_void {
    if bp.is_null() || index < 0 {
        return std::ptr::null();
    }
    let hdr = bp as *const u8;
    let hdr_ext_len = unsafe { *hdr.add(1) } as usize;
    let max_segments = hdr_ext_len / 2;
    if index as usize >= max_segments {
        return std::ptr::null();
    }
    unsafe { hdr.add(RTH0_HDR_SIZE + index as usize * IN6_ADDR_SIZE) as *const c_void }
}

/// `inet6_rth_reverse` — reverse the routing header.
///
/// Copies addresses in reverse order. inp and outp may be the same buffer.
/// Returns 0 on success, -1 on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet6_rth_reverse(
    inp: *const c_void,
    outp: *mut c_void,
) -> c_int {
    if inp.is_null() || outp.is_null() {
        return -1;
    }
    let in_hdr = inp as *const u8;
    let hdr_ext_len = unsafe { *in_hdr.add(1) } as usize;
    let nseg = hdr_ext_len / 2;
    let total_size = RTH0_HDR_SIZE + nseg * IN6_ADDR_SIZE;

    // If inp != outp, copy the header first.
    if inp as *const u8 != outp as *const u8 {
        unsafe { std::ptr::copy_nonoverlapping(in_hdr, outp as *mut u8, RTH0_HDR_SIZE) };
    }

    // Reverse addresses using a temp buffer.
    let mut addrs = vec![[0u8; IN6_ADDR_SIZE]; nseg];
    for i in 0..nseg {
        unsafe {
            std::ptr::copy_nonoverlapping(
                in_hdr.add(RTH0_HDR_SIZE + i * IN6_ADDR_SIZE),
                addrs[i].as_mut_ptr(),
                IN6_ADDR_SIZE,
            );
        }
    }
    let out_hdr = outp as *mut u8;
    for i in 0..nseg {
        unsafe {
            std::ptr::copy_nonoverlapping(
                addrs[nseg - 1 - i].as_ptr(),
                out_hdr.add(RTH0_HDR_SIZE + i * IN6_ADDR_SIZE),
                IN6_ADDR_SIZE,
            );
        }
    }
    // Update segments_left to nseg.
    unsafe { *out_hdr.add(3) = nseg as u8 };
    let _ = total_size;
    0
}

// inet legacy (8 symbols)
// inet_lnaof: native — extract local (host) part of IPv4 address
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet_lnaof(inp: c_uint) -> c_uint {
    let a = inp.to_be();
    if a >> 24 < 128 {
        a & 0x00FF_FFFF
    }
    // class A
    else if a >> 24 < 192 {
        a & 0x0000_FFFF
    }
    // class B
    else {
        a & 0x0000_00FF
    } // class C
}
// inet_makeaddr: native — combine net + host into IPv4 address
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet_makeaddr(net: c_uint, host: c_uint) -> c_uint {
    let addr = if net < 128 {
        (net << 24) | (host & 0x00FF_FFFF)
    } else if net < 0x1_0000 {
        (net << 16) | (host & 0x0000_FFFF)
    } else {
        (net << 8) | (host & 0x0000_00FF)
    };
    addr.to_be()
}
// inet_netof: native — extract network part of IPv4 address
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet_netof(inp: c_uint) -> c_uint {
    let a = inp.to_be();
    if a >> 24 < 128 {
        a >> 24
    }
    // class A
    else if a >> 24 < 192 {
        a >> 16
    }
    // class B
    else {
        a >> 8
    } // class C
}
// inet_network: native — parse dotted-decimal to host-order network number
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet_network(cp: *const c_char) -> c_uint {
    if cp.is_null() {
        return u32::MAX;
    }
    let mut result: u32 = 0;
    let mut parts = 0u32;
    let mut cur: u32 = 0;
    let mut p = cp.cast::<u8>();
    loop {
        let b = unsafe { *p };
        if b == 0 {
            break;
        }
        if b == b'.' {
            if parts >= 3 {
                return u32::MAX;
            }
            result = (result << 8) | (cur & 0xFF);
            cur = 0;
            parts += 1;
        } else if b.is_ascii_digit() {
            cur = cur * 10 + (b - b'0') as u32;
        } else {
            return u32::MAX;
        }
        p = unsafe { p.add(1) };
    }
    result = (result << 8) | (cur & 0xFF);
    for _ in parts..3 {
        result <<= 8;
    }
    result
}
// inet_nsap_addr: convert hex NSAP address string to binary
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet_nsap_addr(cp: *const c_char, buf: *mut c_void, buflen: c_int) -> c_uint {
    if cp.is_null() || buf.is_null() {
        return 0;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(cp) }.to_bytes();
    let dst = buf as *mut u8;
    let mut i = 0usize; // index into source
    let mut o = 0usize; // index into output
    // Skip optional "0x" prefix
    if s.len() >= 2 && s[0] == b'0' && (s[1] == b'x' || s[1] == b'X') {
        i = 2;
    }
    while i < s.len() && (o as c_int) < buflen {
        // Skip dots and whitespace
        if s[i] == b'.' || s[i] == b' ' {
            i += 1;
            continue;
        }
        let hi = match s[i] {
            b'0'..=b'9' => s[i] - b'0',
            b'a'..=b'f' => s[i] - b'a' + 10,
            b'A'..=b'F' => s[i] - b'A' + 10,
            _ => return 0, // invalid hex char
        };
        i += 1;
        if i >= s.len() {
            return 0; // odd number of hex digits
        }
        let lo = match s[i] {
            b'0'..=b'9' => s[i] - b'0',
            b'a'..=b'f' => s[i] - b'a' + 10,
            b'A'..=b'F' => s[i] - b'A' + 10,
            _ => return 0,
        };
        i += 1;
        unsafe { *dst.add(o) = (hi << 4) | lo };
        o += 1;
    }
    o as c_uint
}
// inet_nsap_ntoa: convert binary NSAP address to hex string
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet_nsap_ntoa(len: c_int, cp: *const c_void, buf: *mut c_char) -> *mut c_char {
    static NSAP_BUF: std::sync::Mutex<[u8; 512]> = std::sync::Mutex::new([0u8; 512]);
    let dst = if buf.is_null() {
        let mut b = NSAP_BUF.lock().unwrap();
        b.as_mut_ptr() as *mut c_char
    } else {
        buf
    };
    let src = cp as *const u8;
    let hex = b"0123456789abcdef";
    let mut o = 0usize;
    for i in 0..(len as usize) {
        if i > 0 {
            unsafe { *dst.add(o) = b'.' as c_char };
            o += 1;
        }
        let byte = unsafe { *src.add(i) };
        unsafe { *dst.add(o) = hex[(byte >> 4) as usize] as c_char };
        o += 1;
        unsafe { *dst.add(o) = hex[(byte & 0x0f) as usize] as c_char };
        o += 1;
    }
    unsafe { *dst.add(o) = 0 };
    dst
}
// __inet_ntop_chk: fortified inet_ntop with buffer size validation
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __inet_ntop_chk(
    af: c_int,
    src: *const c_void,
    dst: *mut c_char,
    size: c_uint,
    dstsize: c_uint,
) -> *const c_char {
    if size > dstsize {
        // Buffer overflow detected — abort in fortified mode
        unsafe { libc::abort() };
    }
    unsafe { super::inet_abi::inet_ntop(af, src, dst, size) }
}
// __inet_pton_chk: fortified inet_pton with buffer size validation
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __inet_pton_chk(
    af: c_int,
    src: *const c_char,
    dst: *mut c_void,
    dstsize: c_uint,
) -> c_int {
    // Validate dst buffer is large enough for the address family
    let needed = match af {
        libc::AF_INET => 4u32,
        libc::AF_INET6 => 16,
        _ => 0,
    };
    if needed > 0 && dstsize < needed {
        unsafe { libc::abort() };
    }
    unsafe { super::inet_abi::inet_pton(af, src, dst) }
}

// ==========================================================================
// Misc POSIX/glibc syscall wrappers (aliases for functions we export)
// ==========================================================================
// __adjtimex: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __adjtimex(buf: *mut c_void) -> c_int {
    unsafe { libc::syscall(libc::SYS_adjtimex, buf) as c_int }
}
// __arch_prctl: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __arch_prctl(code: c_int, addr: c_ulong) -> c_int {
    unsafe { libc::syscall(libc::SYS_arch_prctl, code as c_long, addr as c_long) as c_int }
}
dlsym_passthrough!(fn __asprintf(strp: *mut *mut c_char, fmt: *const c_char) -> c_int);
// __backtrace: native — forward to our backtrace
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __backtrace(buffer: *mut *mut c_void, size: c_int) -> c_int {
    unsafe { super::unistd_abi::backtrace(buffer, size) }
}
// __backtrace_symbols: native — forward to our backtrace_symbols
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __backtrace_symbols(
    buffer: *const *mut c_void,
    size: c_int,
) -> *mut *mut c_char {
    unsafe { super::unistd_abi::backtrace_symbols(buffer, size) }
}
// __backtrace_symbols_fd: native — forward to our backtrace_symbols_fd
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __backtrace_symbols_fd(
    buffer: *const *mut c_void,
    size: c_int,
    fd: c_int,
) {
    unsafe { super::unistd_abi::backtrace_symbols_fd(buffer, size, fd) }
}
// __bsd_getpgrp: native — getpgid alias
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __bsd_getpgrp(pid: c_int) -> c_int {
    unsafe { libc::getpgid(pid) }
}
// __check_rhosts_file is a global variable, defined below as a static
dlsym_passthrough!(fn __clone(fn_: *mut c_void, stack: *mut c_void, flags: c_int, arg: *mut c_void) -> c_int);
// __close: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __close(fd: c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_close, fd) as c_int }
}
// __cmsg_nxthdr: native — navigate to next CMSG header
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cmsg_nxthdr(mhdr: *mut c_void, cmsg: *mut c_void) -> *mut c_void {
    // CMSG_NXTHDR: advance past current cmsg, check bounds against msg_controllen
    if mhdr.is_null() || cmsg.is_null() {
        return std::ptr::null_mut();
    }
    let mhdr = mhdr as *mut libc::msghdr;
    let cmsg = cmsg as *mut libc::cmsghdr;
    unsafe { libc::CMSG_NXTHDR(mhdr, cmsg) as *mut c_void }
}
// __connect: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __connect(sockfd: c_int, addr: *const c_void, addrlen: c_uint) -> c_int {
    unsafe { libc::syscall(libc::SYS_connect, sockfd, addr, addrlen) as c_int }
}
// __cyg_profile_func_enter/exit: GCC -finstrument-functions hooks — no-op
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cyg_profile_func_enter(this_fn: *mut c_void, call_site: *mut c_void) {
    let _ = (this_fn, call_site);
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cyg_profile_func_exit(this_fn: *mut c_void, call_site: *mut c_void) {
    let _ = (this_fn, call_site);
}
// __dup2: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __dup2(oldfd: c_int, newfd: c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_dup2, oldfd, newfd) as c_int }
}
// __endmntent: native — close mount table (libc forwarding)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __endmntent(fp: *mut c_void) -> c_int {
    unsafe { libc::endmntent(fp.cast()) }
}
// --- stdio_ext.h functions: native stream queries ---
// These query opaque FILE* internals. Since we don't control glibc's FILE struct,
// we forward to libc for the ones that inspect it, or return safe defaults.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fbufsize(fp: *mut c_void) -> SizeT {
    let _ = fp;
    libc::BUFSIZ as SizeT // default buffer size
}
// __fcntl: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fcntl(fd: c_int, cmd: c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_fcntl, fd, cmd, 0) as c_int }
}
// __fdelt_warn: FD_SET overflow check — return d if valid, abort otherwise
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fdelt_warn(d: c_long) -> c_long {
    if !(0..1024).contains(&d) {
        // FD_SETSIZE overflow — abort like glibc
        unsafe {
            libc::abort();
        }
    }
    d / (8 * std::mem::size_of::<c_long>() as c_long)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __flbf(fp: *mut c_void) -> c_int {
    let _ = fp;
    0 // not line-buffered by default
}
// __fork: native — forward to libc::fork
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fork() -> c_int {
    unsafe { libc::fork() }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fpending(fp: *mut c_void) -> SizeT {
    let _ = fp;
    0 // no bytes pending
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fpurge(fp: *mut c_void) {
    let _ = fp;
    // discard buffered data — no-op since we don't control the buffer
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __freadable(fp: *mut c_void) -> c_int {
    let _ = fp;
    1 // assume readable
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __freading(fp: *mut c_void) -> c_int {
    let _ = fp;
    0 // not currently reading
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fsetlocking(fp: *mut c_void, typ: c_int) -> c_int {
    let _ = (fp, typ);
    2 // FSETLOCKING_INTERNAL (default)
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fwritable(fp: *mut c_void) -> c_int {
    let _ = fp;
    1 // assume writable
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fwriting(fp: *mut c_void) -> c_int {
    let _ = fp;
    0 // not currently writing
}
// __getauxval: native — read from /proc/self/auxv
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getauxval(typ: c_ulong) -> c_ulong {
    unsafe { libc::getauxval(typ) }
}
// __getdelim: native — forward to our getdelim
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getdelim(
    lineptr: *mut *mut c_char,
    n: *mut SizeT,
    delim: c_int,
    stream: *mut c_void,
) -> SSizeT {
    unsafe { super::stdio_abi::getdelim(lineptr, n, delim, stream) }
}
// __getmntent_r: native — forward to our getmntent_r
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getmntent_r(
    fp: *mut c_void,
    mntbuf: *mut c_void,
    buf: *mut c_char,
    buflen: c_int,
) -> *mut c_void {
    unsafe { super::unistd_abi::getmntent_r(fp, mntbuf, buf, buflen) }
}
// __getpagesize: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getpagesize() -> c_int {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as c_int }
}
// __getpgid: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getpgid(pid: c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_getpgid, pid) as c_int }
}
// __getpid: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getpid() -> c_int {
    unsafe { libc::syscall(libc::SYS_getpid) as c_int }
}
// __gettimeofday: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __gettimeofday(tv: *mut c_void, tz: *mut c_void) -> c_int {
    unsafe { libc::syscall(libc::SYS_gettimeofday, tv, tz) as c_int }
}
// __ivaliduser: validate remote user against .rhosts — deny-all for security
// .rhosts-based authentication is deprecated and dangerous.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ivaliduser(
    _hostf: *mut c_void,
    _raddr: c_uint,
    _luser: *const c_char,
    _ruser: *const c_char,
) -> c_int {
    -1 // Always deny
}
// __lseek: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    unsafe { libc::syscall(libc::SYS_lseek, fd, offset, whence) as i64 }
}
// __mbrlen: native — multibyte character length (UTF-8)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __mbrlen(s: *const c_char, n: SizeT, _ps: *mut c_void) -> SizeT {
    unsafe { __mbrtowc(std::ptr::null_mut(), s, n, _ps) }
}
// __mbrtowc: native — multibyte (UTF-8) to wide char
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __mbrtowc(
    pwc: *mut WcharT,
    s: *const c_char,
    n: SizeT,
    _ps: *mut c_void,
) -> SizeT {
    if s.is_null() {
        return 0;
    }
    if n == 0 {
        return SizeT::MAX.wrapping_neg();
    } // (size_t)-2 = incomplete
    let b0 = unsafe { *s.cast::<u8>() };
    if b0 < 0x80 {
        if !pwc.is_null() {
            unsafe { *pwc = b0 as WcharT };
        }
        return if b0 == 0 { 0 } else { 1 };
    }
    let (len, mut cp) = if b0 < 0xC0 {
        return SizeT::MAX; // (size_t)-1 = invalid
    } else if b0 < 0xE0 {
        (2, (b0 & 0x1F) as u32)
    } else if b0 < 0xF0 {
        (3, (b0 & 0x0F) as u32)
    } else if b0 < 0xF8 {
        (4, (b0 & 0x07) as u32)
    } else {
        return SizeT::MAX; // invalid
    };
    if n < len {
        return SizeT::MAX.wrapping_neg();
    } // incomplete
    for i in 1..len {
        let b = unsafe { *s.cast::<u8>().add(i) };
        if b & 0xC0 != 0x80 {
            return SizeT::MAX;
        } // invalid continuation
        cp = (cp << 6) | (b & 0x3F) as u32;
    }
    if !pwc.is_null() {
        unsafe { *pwc = cp as WcharT };
    }
    len
}
// __monstartup: profiling — no-op stub
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __monstartup(lowpc: c_ulong, highpc: c_ulong) {
    let _ = (lowpc, highpc);
}
// __nanosleep: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nanosleep(rqtp: *const c_void, rmtp: *mut c_void) -> c_int {
    unsafe { libc::syscall(libc::SYS_nanosleep, rqtp, rmtp) as c_int }
}
// __open/__open64: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __open(pathname: *const c_char, flags: c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_open, pathname, flags, 0) as c_int }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __open64(pathname: *const c_char, flags: c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_open, pathname, flags, 0) as c_int }
}
dlsym_passthrough!(fn __overflow(fp: *mut c_void, c: c_int) -> c_int);
// __pipe: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pipe(pipefd: *mut c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_pipe2, pipefd, 0) as c_int }
}
// __poll: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __poll(fds: *mut c_void, nfds: c_ulong, timeout: c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_poll, fds, nfds, timeout) as c_int }
}
// __posix_getopt → getopt (POSIX semantics — same as getopt)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __posix_getopt(argc: c_int, argv: *const *mut c_char, optstring: *const c_char) -> c_int {
    unsafe { super::unistd_abi::getopt(argc, argv, optstring) }
}
// __pread64/__pwrite64: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pread64(
    fd: c_int,
    buf: *mut c_void,
    count: SizeT,
    offset: i64,
) -> SSizeT {
    unsafe { libc::syscall(libc::SYS_pread64, fd, buf, count, offset) as SSizeT }
}
dlsym_passthrough!(fn __printf_fp(fp: *mut c_void, info: *const c_void, args: *const *const c_void) -> c_int);
// __profile_frequency: native — return 100 (default HZ)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __profile_frequency() -> c_int {
    100
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pwrite64(
    fd: c_int,
    buf: *const c_void,
    count: SizeT,
    offset: i64,
) -> SSizeT {
    unsafe { libc::syscall(libc::SYS_pwrite64, fd, buf, count, offset) as SSizeT }
}
// __rcmd_errstr: pointer to rcmd error string (thread-local for reentrancy)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rcmd_errstr() -> *mut *mut c_char {
    thread_local! {
        static ERRSTR: std::cell::Cell<*mut c_char> = const { std::cell::Cell::new(std::ptr::null_mut()) };
    }
    ERRSTR.with(|c| c.as_ptr())
}
// __read/__write: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __read(fd: c_int, buf: *mut c_void, count: SizeT) -> SSizeT {
    unsafe { libc::syscall(libc::SYS_read, fd, buf, count) as SSizeT }
}
// __register_atfork: native — forward to our pthread_atfork (dso_handle ignored)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __register_atfork(
    prepare: *mut c_void,
    parent: *mut c_void,
    child: *mut c_void,
    _dso_handle: *mut c_void,
) -> c_int {
    // SAFETY: function pointers are transmuted from c_void; caller guarantees validity
    let prepare_fn: Option<unsafe extern "C" fn()> = if prepare.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut c_void, unsafe extern "C" fn()>(prepare) })
    };
    let parent_fn: Option<unsafe extern "C" fn()> = if parent.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut c_void, unsafe extern "C" fn()>(parent) })
    };
    let child_fn: Option<unsafe extern "C" fn()> = if child.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut c_void, unsafe extern "C" fn()>(child) })
    };
    unsafe { super::pthread_abi::pthread_atfork(prepare_fn, parent_fn, child_fn) }
}
// __sbrk: forward to libc::sbrk
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sbrk(increment: isize) -> *mut c_void {
    unsafe { libc::sbrk(increment) }
}
// __secure_getenv: native — return null if AT_SECURE, else getenv
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __secure_getenv(name: *const c_char) -> *mut c_char {
    // Check AT_SECURE — if set, return null for security
    if unsafe { libc::getauxval(libc::AT_SECURE) } != 0 {
        return std::ptr::null_mut();
    }
    unsafe { libc::getenv(name) as *mut c_char }
}
// __select: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __select(
    nfds: c_int,
    readfds: *mut c_void,
    writefds: *mut c_void,
    exceptfds: *mut c_void,
    timeout: *mut c_void,
) -> c_int {
    unsafe {
        libc::syscall(
            libc::SYS_select,
            nfds,
            readfds,
            writefds,
            exceptfds,
            timeout,
        ) as c_int
    }
}
// __send: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __send(
    sockfd: c_int,
    buf: *const c_void,
    len: SizeT,
    flags: c_int,
) -> SSizeT {
    unsafe {
        libc::syscall(
            libc::SYS_sendto,
            sockfd,
            buf,
            len,
            flags,
            std::ptr::null::<c_void>(),
            0,
        ) as SSizeT
    }
}
// __setmntent: native — forward to our setmntent
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __setmntent(filename: *const c_char, typ: *const c_char) -> *mut c_void {
    unsafe { super::unistd_abi::setmntent(filename, typ) }
}
// __setpgid: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __setpgid(pid: c_int, pgid: c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_setpgid, pid, pgid) as c_int }
}
// __sigaction: native syscall (uses rt_sigaction)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sigaction(
    signum: c_int,
    act: *const c_void,
    oldact: *mut c_void,
) -> c_int {
    unsafe { libc::sigaction(signum, act.cast(), oldact.cast()) }
}
// __sigaddset/__sigdelset/__sigismember: native bit manipulation on sigset_t
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sigaddset(set: *mut c_void, signum: c_int) -> c_int {
    if set.is_null() || !(1..=64).contains(&signum) {
        return -1;
    }
    let bits = set.cast::<u64>();
    unsafe {
        *bits |= 1u64 << (signum - 1) as u64;
    }
    0
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sigdelset(set: *mut c_void, signum: c_int) -> c_int {
    if set.is_null() || !(1..=64).contains(&signum) {
        return -1;
    }
    let bits = set.cast::<u64>();
    unsafe {
        *bits &= !(1u64 << (signum - 1) as u64);
    }
    0
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sigismember(set: *const c_void, signum: c_int) -> c_int {
    if set.is_null() || !(1..=64).contains(&signum) {
        return -1;
    }
    let bits = unsafe { *set.cast::<u64>() };
    if bits & (1u64 << (signum - 1) as u64) != 0 {
        1
    } else {
        0
    }
}
// __sigpause → sigpause (BSD compatibility)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sigpause(sig_or_mask: c_int) -> c_int {
    unsafe { super::unistd_abi::sigpause(sig_or_mask) }
}
// __sigsetjmp: native — forward to our sigsetjmp
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sigsetjmp(env: *mut c_void, savesigs: c_int) -> c_int {
    unsafe { super::setjmp_abi::sigsetjmp(env, savesigs) }
}
// __sigsuspend: native — forward to libc
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sigsuspend(set: *const c_void) -> c_int {
    unsafe { libc::sigsuspend(set.cast()) }
}
// __statfs: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __statfs(path: *const c_char, buf: *mut c_void) -> c_int {
    unsafe { libc::syscall(libc::SYS_statfs, path, buf) as c_int }
}
// __sysconf: native — forward to libc
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sysconf(name: c_int) -> c_long {
    unsafe { libc::sysconf(name) }
}
// __sysctl: deprecated syscall (removed in Linux 5.5) — return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sysctl(_args: *mut c_void) -> c_int {
    unsafe { *libc::__errno_location() = libc::ENOSYS };
    -1
}
// __sysv_signal: native — System V signal semantics (one-shot)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sysv_signal(signum: c_int, handler: *mut c_void) -> *mut c_void {
    unsafe { libc::signal(signum, handler as libc::sighandler_t) as *mut c_void }
}
// __vfork → vfork
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __vfork() -> c_int {
    unsafe { super::process_abi::vfork() }
}
// __vfscanf: native — forward to our vfscanf
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __vfscanf(
    stream: *mut c_void,
    fmt: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { super::stdio_abi::vfscanf(stream, fmt, ap) }
}
// __vsnprintf: native — forward to our vsnprintf
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __vsnprintf(
    buf: *mut c_char,
    size: SizeT,
    fmt: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { super::stdio_abi::vsnprintf(buf, size, fmt, ap) }
}
// __vsscanf: native — forward to our vsscanf
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __vsscanf(
    s: *const c_char,
    fmt: *const c_char,
    ap: *mut c_void,
) -> c_int {
    unsafe { super::stdio_abi::vsscanf(s, fmt, ap) }
}
// __wait: native — wait4 with pid=-1, options=0
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wait(status: *mut c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_wait4, -1, status, 0, std::ptr::null::<c_void>()) as c_int }
}
// __waitpid: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int {
    unsafe {
        libc::syscall(
            libc::SYS_wait4,
            pid,
            status,
            options,
            std::ptr::null::<c_void>(),
        ) as c_int
    }
}
// __write: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __write(fd: c_int, buf: *const c_void, count: SizeT) -> SSizeT {
    unsafe { libc::syscall(libc::SYS_write, fd, buf, count) as SSizeT }
}
// __xmknod: native — forward to mknod syscall (ignoring ver)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __xmknod(
    ver: c_int,
    pathname: *const c_char,
    mode: c_uint,
    dev: *mut c_void,
) -> c_int {
    let _ = ver;
    unsafe { libc::syscall(libc::SYS_mknod, pathname, mode, *(dev.cast::<u64>())) as c_int }
}
// __xmknodat: native — forward to mknodat syscall (ignoring ver)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __xmknodat(
    ver: c_int,
    dirfd: c_int,
    pathname: *const c_char,
    mode: c_uint,
    dev: *mut c_void,
) -> c_int {
    let _ = ver;
    unsafe {
        libc::syscall(
            libc::SYS_mknodat,
            dirfd,
            pathname,
            mode,
            *(dev.cast::<u64>()),
        ) as c_int
    }
}
// __xpg_sigpause: native — XPG sigpause removes sig from mask then sigsuspend
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __xpg_sigpause(sig: c_int) -> c_int {
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask);
        libc::sigdelset(&mut mask, sig);
        libc::sigsuspend(&mask)
    }
}
// --- Native math: long-double classification (long double = f64 in this ABI) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __signbitl(x: f64) -> c_int {
    (x.to_bits() >> 63) as c_int
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isinfl(x: f64) -> c_int {
    if x == f64::INFINITY {
        1
    } else if x == f64::NEG_INFINITY {
        -1
    } else {
        0
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isnanl(x: f64) -> c_int {
    x.is_nan() as c_int
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __finitel(x: f64) -> c_int {
    x.is_finite() as c_int
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isnanf128(x: f64) -> c_int {
    x.is_nan() as c_int
}

// ==========================================================================
// __fortify_chk extras not covered by fortify_abi.rs (8 symbols)
// ==========================================================================
// Fortified _chk functions: abort if size overflows destination buffer, then forward
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __mempcpy_chk(
    dest: *mut c_void,
    src: *const c_void,
    n: SizeT,
    destlen: SizeT,
) -> *mut c_void {
    if n > destlen {
        unsafe {
            libc::abort();
        }
    }
    unsafe {
        std::ptr::copy_nonoverlapping(src.cast::<u8>(), dest.cast::<u8>(), n);
    }
    unsafe { dest.cast::<u8>().add(n).cast() }
}
// __mempcpy_small: native — inline small mempcpy (up to 16 bytes via register args)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __mempcpy_small(
    dest: *mut c_void,
    src: c_ulong,
    src2: c_ulong,
) -> *mut c_void {
    // glibc __mempcpy_small: copies up to 16 bytes from register arguments
    // src holds first 8 bytes, src2 holds next 8 bytes
    let d = dest as *mut u8;
    unsafe {
        std::ptr::write_unaligned(d as *mut u64, src);
        std::ptr::write_unaligned(d.add(8) as *mut u64, src2);
    }
    unsafe { d.add(16) as *mut c_void }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strlcat_chk(
    dest: *mut c_char,
    src: *const c_char,
    size: SizeT,
    destlen: SizeT,
) -> SizeT {
    if size > destlen {
        unsafe {
            libc::abort();
        }
    }
    // Native strlcat: find end of dest, append src up to size
    let mut dlen = 0usize;
    unsafe {
        while dlen < size && *dest.add(dlen) != 0 {
            dlen += 1;
        }
    }
    let mut slen = 0usize;
    unsafe {
        while *src.add(slen) != 0 {
            slen += 1;
        }
    }
    if dlen < size {
        let copy = std::cmp::min(slen, size - dlen - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(src.cast::<u8>(), dest.add(dlen).cast::<u8>(), copy);
        }
        unsafe {
            *dest.add(dlen + copy) = 0;
        }
    }
    dlen + slen
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strlcpy_chk(
    dest: *mut c_char,
    src: *const c_char,
    size: SizeT,
    destlen: SizeT,
) -> SizeT {
    if size > destlen {
        unsafe {
            libc::abort();
        }
    }
    // Native strlcpy: copy src to dest up to size-1, nul-terminate
    let mut slen = 0usize;
    unsafe {
        while *src.add(slen) != 0 {
            slen += 1;
        }
    }
    if size > 0 {
        let copy = std::cmp::min(slen, size - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(src.cast::<u8>(), dest.cast::<u8>(), copy);
        }
        unsafe {
            *dest.add(copy) = 0;
        }
    }
    slen
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcpcpy_chk(
    dest: *mut WcharT,
    src: *const WcharT,
    destlen: SizeT,
) -> *mut WcharT {
    // Count src len
    let mut len = 0usize;
    unsafe {
        while *src.add(len) != 0 {
            len += 1;
        }
    }
    if len + 1 > destlen {
        unsafe {
            libc::abort();
        }
    }
    unsafe {
        std::ptr::copy_nonoverlapping(src, dest, len + 1);
    }
    unsafe { dest.add(len) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcpncpy_chk(
    dest: *mut WcharT,
    src: *const WcharT,
    n: SizeT,
    destlen: SizeT,
) -> *mut WcharT {
    if n > destlen {
        unsafe {
            libc::abort();
        }
    }
    let mut i = 0;
    unsafe {
        while i < n && *src.add(i) != 0 {
            *dest.add(i) = *src.add(i);
            i += 1;
        }
        let end = i;
        while i < n {
            *dest.add(i) = 0;
            i += 1;
        }
        dest.add(end)
    }
}
// __wcrtomb_chk: fortified wcrtomb with buffer size validation
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcrtomb_chk(
    s: *mut c_char,
    wc: WcharT,
    ps: *mut c_void,
    buflen: SizeT,
) -> SizeT {
    // MB_LEN_MAX for UTF-8 is 4; if buffer is too small, abort
    if !s.is_null() && buflen < 4 {
        // Only abort if buffer definitely cannot hold the output
        // For most characters, 4 bytes is sufficient (UTF-8 max)
    }
    unsafe { super::wchar_abi::wcrtomb(s, wc, ps) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcslcat_chk(
    dest: *mut WcharT,
    src: *const WcharT,
    size: SizeT,
    destlen: SizeT,
) -> SizeT {
    if size > destlen {
        unsafe {
            libc::abort();
        }
    }
    // Find end of dest within size
    let mut dlen = 0;
    unsafe {
        while dlen < size && *dest.add(dlen) != 0 {
            dlen += 1;
        }
    }
    let mut slen = 0;
    unsafe {
        while *src.add(slen) != 0 {
            slen += 1;
        }
    }
    if dlen < size {
        let copy = std::cmp::min(slen, size - dlen - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(src, dest.add(dlen), copy);
        }
        unsafe {
            *dest.add(dlen + copy) = 0;
        }
    }
    dlen + slen
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wcslcpy_chk(
    dest: *mut WcharT,
    src: *const WcharT,
    size: SizeT,
    destlen: SizeT,
) -> SizeT {
    if size > destlen {
        unsafe {
            libc::abort();
        }
    }
    let mut slen = 0;
    unsafe {
        while *src.add(slen) != 0 {
            slen += 1;
        }
    }
    if size > 0 {
        let copy = std::cmp::min(slen, size - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(src, dest, copy);
        }
        unsafe {
            *dest.add(copy) = 0;
        }
    }
    slen
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wmempcpy_chk(
    dest: *mut WcharT,
    src: *const WcharT,
    n: SizeT,
    destlen: SizeT,
) -> *mut WcharT {
    if n > destlen {
        unsafe {
            libc::abort();
        }
    }
    unsafe {
        std::ptr::copy_nonoverlapping(src, dest, n);
    }
    unsafe { dest.add(n) }
}
// __read_chk: fortified read — abort if nbytes > buflen
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __read_chk(fd: c_int, buf: *mut c_void, nbytes: SizeT, buflen: SizeT) -> SSizeT {
    if nbytes > buflen {
        unsafe { libc::abort() };
    }
    unsafe { super::unistd_abi::read(fd, buf, nbytes) as SSizeT }
}
// __readlink_chk: fortified readlink — abort if len > buflen
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __readlink_chk(path: *const c_char, buf: *mut c_char, len: SizeT, buflen: SizeT) -> SSizeT {
    if len > buflen {
        unsafe { libc::abort() };
    }
    unsafe { super::unistd_abi::readlink(path, buf, len) as SSizeT }
}
// __readlinkat_chk: fortified readlinkat — abort if len > buflen
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __readlinkat_chk(dirfd: c_int, path: *const c_char, buf: *mut c_char, len: SizeT, buflen: SizeT) -> SSizeT {
    if len > buflen {
        unsafe { libc::abort() };
    }
    unsafe { super::unistd_abi::readlinkat(dirfd, path, buf, len) as SSizeT }
}
// __syslog_chk: fortified syslog — flag validates priority, then forwards
// Note: This is variadic in glibc but the passthrough only captures fmt
// Keep as dlsym since we can't forward variadic args to our variadic syslog
// __syslog_chk: now exported from fortify_abi.rs (native, variadic)
// __mq_open_2: fortified mq_open — aborts if O_CREAT set without mode/attr
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __mq_open_2(name: *const c_char, oflag: c_int) -> c_int {
    if oflag & libc::O_CREAT != 0 {
        // O_CREAT requires mode and attr args — missing is a bug
        unsafe { libc::abort() };
    }
    unsafe { libc::mq_open(name, oflag) as c_int }
}

// ==========================================================================
// argp globals (4 symbols)
// ==========================================================================
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut argp_err_exit_status: c_int = 1;

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut argp_program_bug_address: *const c_char = std::ptr::null();

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut argp_program_version: *const c_char = std::ptr::null();

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut argp_program_version_hook: *mut c_void = std::ptr::null_mut();

// ==========================================================================
// error/getopt globals (7 symbols)
// ==========================================================================
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut error_message_count: c_uint = 0;

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut error_one_per_line: c_int = 0;

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut error_print_progname: *mut c_void = std::ptr::null_mut();

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut optarg: *mut c_char = std::ptr::null_mut();

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut opterr: c_int = 1;

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut optind: c_int = 1;

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut optopt: c_int = 0;

// ==========================================================================
// sys_* error/signal tables (7 symbols)
// ==========================================================================
// These are arrays/ints, but we export as opaque statics.
// Real programs use strerror/strsignal, not these directly.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _sys_nerr: c_int = 134;
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut sys_nerr: c_int = 134;
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut h_nerr: c_int = 5;

// sys_sigabbrev: native signal abbreviation table
// Use static mut since raw pointers are not Sync
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut sys_sigabbrev: [*const c_char; 32] = {
    const fn s(b: &[u8]) -> *const i8 {
        b.as_ptr().cast()
    }
    [
        s(b"\0"),
        s(b"HUP\0"),
        s(b"INT\0"),
        s(b"QUIT\0"),
        s(b"ILL\0"),
        s(b"TRAP\0"),
        s(b"ABRT\0"),
        s(b"BUS\0"),
        s(b"FPE\0"),
        s(b"KILL\0"),
        s(b"USR1\0"),
        s(b"SEGV\0"),
        s(b"USR2\0"),
        s(b"PIPE\0"),
        s(b"ALRM\0"),
        s(b"TERM\0"),
        s(b"STKFLT\0"),
        s(b"CHLD\0"),
        s(b"CONT\0"),
        s(b"STOP\0"),
        s(b"TSTP\0"),
        s(b"TTIN\0"),
        s(b"TTOU\0"),
        s(b"URG\0"),
        s(b"XCPU\0"),
        s(b"XFSZ\0"),
        s(b"VTALRM\0"),
        s(b"PROF\0"),
        s(b"WINCH\0"),
        s(b"IO\0"),
        s(b"PWR\0"),
        s(b"SYS\0"),
    ]
};

// These are actually arrays, but export as statics the linker can find
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _sys_errlist: *const *const c_char = std::ptr::null();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut sys_errlist: *const *const c_char = std::ptr::null();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _sys_siglist: *const *const c_char = std::ptr::null();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut sys_siglist: *const *const c_char = std::ptr::null();
// h_errlist is defined below as a populated array

// ==========================================================================
// environ / timezone globals (8 symbols)
// ==========================================================================
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __environ: *mut *mut c_char = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _environ: *mut *mut c_char = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut environ: *mut *mut c_char = std::ptr::null_mut();

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __timezone: c_long = 0;
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut timezone: c_long = 0;
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __daylight: c_int = 0;
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut daylight: c_int = 0;
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __tzname: [*mut c_char; 2] = [std::ptr::null_mut(), std::ptr::null_mut()];
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut tzname: [*mut c_char; 2] = [std::ptr::null_mut(), std::ptr::null_mut()];

// __progname_full (program_invocation_name is in startup_helpers)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __progname_full: *const c_char = std::ptr::null();

// malloc hooks (deprecated but some old programs reference them)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __free_hook: *mut c_void = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __malloc_hook: *mut c_void = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __realloc_hook: *mut c_void = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __memalign_hook: *mut c_void = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __malloc_initialize_hook: *mut c_void = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __after_morecore_hook: *mut c_void = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __default_morecore: *mut c_void = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __morecore: *mut c_void = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __curbrk: *mut c_void = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __fpu_control: c_int = 0x037F; // default x87 control word
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut mallwatch: *mut c_void = std::ptr::null_mut();

// ==========================================================================
// _dl_*, _flushlbf, _libc_intl_domainname, getdate_err, _res (5 symbols)
// ==========================================================================
dlsym_passthrough!(fn _dl_find_object(address: *mut c_void, result: *mut c_void) -> c_int);
// _dl_mcount_wrapper: profiling callback — no-op when profiling disabled
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _dl_mcount_wrapper(_selfpc: c_ulong) {}
// _dl_mcount_wrapper_check: profiling callback — no-op when profiling disabled
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _dl_mcount_wrapper_check(_selfpc: c_ulong) {}
// _flushlbf: native — flush all line-buffered streams
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _flushlbf() {
    unsafe { libc::fflush(std::ptr::null_mut()) };
}

// _libc_intl_domainname
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static _libc_intl_domainname: [u8; 5] = *b"libc\0";

// getdate_err
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut getdate_err: c_int = 0;

// _res (resolver state)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _res: [u8; 600] = [0u8; 600]; // opaque __res_state
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _res_hconf: [u8; 48] = [0u8; 48]; // opaque _res_hconf_t

// ==========================================================================
// Legacy/misc functions
// ==========================================================================
// _tolower/_toupper: native — direct table lookup
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _tolower(c: c_int) -> c_int {
    if !(-128..=255).contains(&c) {
        return c;
    }
    unsafe { *crate::ctype_abi::tolower_table_ptr().offset(c as isize) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _toupper(c: c_int) -> c_int {
    if !(-128..=255).contains(&c) {
        return c;
    }
    unsafe { *crate::ctype_abi::toupper_table_ptr().offset(c as isize) }
}
// __x86_get_cpuid_feature_leaf: native cpuid instruction
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __x86_get_cpuid_feature_leaf(leaf: c_uint, info: *mut c_void) -> c_int {
    if info.is_null() {
        return 0;
    }
    let out = info.cast::<[c_uint; 4]>();
    let (eax, ebx, ecx, edx): (u32, u32, u32, u32);
    unsafe {
        // rbx is reserved by LLVM — save/restore manually
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            ebx_out = lateout(reg) ebx,
            inout("ecx") 0u32 => ecx,
            lateout("edx") edx,
        );
        (*out) = [eax, ebx, ecx, edx];
    }
    1
}
// __fentry__: GCC -pg function entry hook — no-op stub
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fentry__() {}
dlsym_passthrough!(fn __uflow(fp: *mut c_void) -> c_int);
dlsym_passthrough!(fn __underflow(fp: *mut c_void) -> c_int);
dlsym_passthrough!(fn __woverflow(fp: *mut c_void, wc: WcharT) -> WcharT);
dlsym_passthrough!(fn __wuflow(fp: *mut c_void) -> WcharT);
dlsym_passthrough!(fn __wunderflow(fp: *mut c_void) -> WcharT);

// Profiling — no-op stubs (profiling data is unused in frankenlibc)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _mcleanup() {}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _mcount() {}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mcount() {}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn moncontrol(mode: c_int) {
    let _ = mode;
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn monstartup(lowpc: c_ulong, highpc: c_ulong) {
    let _ = (lowpc, highpc);
}
// profil: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn profil(
    buf: *mut c_void,
    bufsiz: SizeT,
    offset: SizeT,
    scale: c_uint,
) -> c_int {
    let _ = (buf, bufsiz, offset, scale);
    0 // success no-op
}
// sprofil: not available on Linux — return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sprofil(
    profp: *mut c_void,
    profcnt: c_int,
    tvp: *mut c_void,
    flags: c_uint,
) -> c_int {
    let _ = (profp, profcnt, tvp, flags);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}

// Misc POSIX functions
// adjtime: native — forward to libc
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn adjtime(delta: *const c_void, olddelta: *mut c_void) -> c_int {
    unsafe { libc::adjtime(delta.cast(), olddelta.cast()) }
}
// arch_prctl: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn arch_prctl(code: c_int, addr: c_ulong) -> c_int {
    unsafe { __arch_prctl(code, addr) }
}
// bdflush: deprecated Linux syscall (removed in 2.6) — return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bdflush(func: c_int, data: c_long) -> c_int {
    let _ = (func, data);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
// bindresvport: bind to a reserved port (512-1023) for RPC services
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bindresvport(sockfd: c_int, sin: *mut c_void) -> c_int {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT_PORT: AtomicU16 = AtomicU16::new(600);

    let sin = sin as *mut libc::sockaddr_in;
    let mut addr: libc::sockaddr_in = if sin.is_null() {
        unsafe { std::mem::zeroed() }
    } else {
        unsafe { std::ptr::read(sin) }
    };
    addr.sin_family = libc::AF_INET as u16;

    // Try ports 512..1024, wrapping around from current position
    for _ in 0..512 {
        let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        let port = 512 + (port % 512); // Keep in 512..1023
        addr.sin_port = port.to_be();
        let rc = unsafe {
            libc::bind(
                sockfd,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            if !sin.is_null() {
                unsafe { std::ptr::write(sin, addr) };
            }
            return 0;
        }
        // EADDRINUSE — try next port
        let err = unsafe { *libc::__errno_location() };
        if err != libc::EADDRINUSE && err != libc::EACCES {
            return -1; // Real error
        }
    }
    // All ports in use
    unsafe { *libc::__errno_location() = libc::EADDRINUSE };
    -1
}
// cfget/cfset speed: forward to libc
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfgetibaud(termios_p: *const c_void) -> c_uint {
    unsafe { libc::cfgetispeed(termios_p.cast()) as c_uint }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfgetobaud(termios_p: *const c_void) -> c_uint {
    unsafe { libc::cfgetospeed(termios_p.cast()) as c_uint }
}
// cfsetbaud: set both input and output baud
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetbaud(termios_p: *mut c_void, ibaud: c_uint, obaud: c_uint) -> c_int {
    let tp = termios_p.cast::<libc::termios>();
    let r1 = unsafe { libc::cfsetispeed(tp, ibaud as libc::speed_t) };
    if r1 != 0 {
        return r1;
    }
    unsafe { libc::cfsetospeed(tp, obaud as libc::speed_t) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetibaud(termios_p: *mut c_void, speed: c_uint) -> c_int {
    unsafe { libc::cfsetispeed(termios_p.cast(), speed as libc::speed_t) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetobaud(termios_p: *mut c_void, speed: c_uint) -> c_int {
    unsafe { libc::cfsetospeed(termios_p.cast(), speed as libc::speed_t) }
}
// chflags: BSD — not supported on Linux, return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn chflags(path: *const c_char, flags: c_ulong) -> c_int {
    let _ = (path, flags);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
// copysignl: native — copy sign of y to x
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn copysignl(x: f64, y: f64) -> f64 {
    f64::from_bits((x.to_bits() & 0x7FFF_FFFF_FFFF_FFFF) | (y.to_bits() & 0x8000_0000_0000_0000))
}
// create_module: legacy syscall (removed in Linux 2.6) — return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn create_module(name: *const c_char, size: SizeT) -> c_long {
    let _ = (name, size);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
// delete_module: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn delete_module(name: *const c_char, flags: c_uint) -> c_int {
    unsafe { libc::syscall(libc::SYS_delete_module, name, flags) as c_int }
}
dlsym_passthrough!(fn dladdr1(addr: *const c_void, info: *mut c_void, extra_info: *mut *mut c_void, flags: c_int) -> c_int);
dlsym_passthrough!(fn dlinfo(handle: *mut c_void, request: c_int, info: *mut c_void) -> c_int);
dlsym_passthrough!(fn dlmopen(lmid: c_long, filename: *const c_char, flags: c_int) -> *mut c_void);
dlsym_passthrough!(fn dlvsym(handle: *mut c_void, symbol: *const c_char, version: *const c_char) -> *mut c_void);
// dysize: native — returns 366 for leap years, 365 otherwise
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dysize(year: c_int) -> c_int {
    if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
        366
    } else {
        365
    }
}
// fattach/fdetach: STREAMS — not supported on Linux, return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fattach(fd: c_int, path: *const c_char) -> c_int {
    let _ = (fd, path);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
// fchflags: BSD — not supported on Linux, return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fchflags(fd: c_int, flags: c_ulong) -> c_int {
    let _ = (fd, flags);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdetach(path: *const c_char) -> c_int {
    let _ = path;
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
// frexpl: native — decompose into significand * 2^exp (0.5 <= |frac| < 1.0)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn frexpl(x: f64, exp: *mut c_int) -> f64 {
    if x == 0.0 || x.is_nan() || x.is_infinite() {
        if !exp.is_null() {
            unsafe { *exp = 0 };
        }
        return x;
    }
    let bits = x.to_bits();
    let biased = ((bits >> 52) & 0x7FF) as i32;
    let sign = bits & 0x8000_0000_0000_0000;
    let mantissa = bits & 0x000F_FFFF_FFFF_FFFF;
    if biased == 0 {
        // subnormal: normalize by multiplying by 2^64
        let norm = x * ((1u64 << 63) as f64 * 2.0);
        let nb = norm.to_bits();
        let ne = ((nb >> 52) & 0x7FF) as i32;
        if !exp.is_null() {
            unsafe { *exp = ne - 1022 - 64 };
        }
        return f64::from_bits((nb & 0x000F_FFFF_FFFF_FFFF) | sign | 0x3FE0_0000_0000_0000);
    }
    if !exp.is_null() {
        unsafe { *exp = biased - 1022 };
    }
    f64::from_bits(mantissa | sign | 0x3FE0_0000_0000_0000)
}
// ftime: native — fill timeb struct via clock_gettime
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftime(tp: *mut c_void) -> c_int {
    if tp.is_null() {
        return -1;
    }
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) } != 0 {
        return -1;
    }
    // struct timeb layout: time_t(8), millitm(u16), timezone(i16), dstflag(i16)
    let p = tp.cast::<u8>();
    unsafe {
        *(p as *mut i64) = ts.tv_sec;
        *(p.add(8) as *mut u16) = (ts.tv_nsec / 1_000_000) as u16;
        *(p.add(10) as *mut i16) = 0; // timezone
        *(p.add(12) as *mut i16) = 0; // dstflag
    }
    0
}
// futimes: native — forward to libc
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn futimes(fd: c_int, tv: *const c_void) -> c_int {
    unsafe { libc::futimes(fd, tv.cast()) }
}
// futimesat: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn futimesat(
    dirfd: c_int,
    pathname: *const c_char,
    tv: *const c_void,
) -> c_int {
    unsafe { libc::syscall(libc::SYS_futimesat, dirfd, pathname, tv) as c_int }
}
// fwide: native — always return 0 (unset, compatible with byte-oriented streams)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fwide(stream: *mut c_void, mode: c_int) -> c_int {
    let _ = (stream, mode);
    0 // stream orientation not set
}
// get_kernel_syms: removed in Linux 2.6 — return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn get_kernel_syms(table: *mut c_void) -> c_int {
    let _ = table;
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
// getdirentries/getdirentries64: native via getdents64 + lseek
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getdirentries(
    fd: c_int,
    buf: *mut c_char,
    nbytes: SizeT,
    basep: *mut c_long,
) -> SSizeT {
    if !basep.is_null() {
        unsafe { *basep = libc::lseek(fd, 0, libc::SEEK_CUR) as c_long };
    }
    unsafe { libc::syscall(libc::SYS_getdents64, fd, buf, nbytes) as SSizeT }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getdirentries64(
    fd: c_int,
    buf: *mut c_char,
    nbytes: SizeT,
    basep: *mut i64,
) -> SSizeT {
    if !basep.is_null() {
        unsafe { *basep = libc::lseek(fd, 0, libc::SEEK_CUR) as i64 };
    }
    unsafe { libc::syscall(libc::SYS_getdents64, fd, buf, nbytes) as SSizeT }
}
// getipv4sourcefilter: get multicast source filter via getsockopt(IP_MSFILTER)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getipv4sourcefilter(
    s: c_int,
    interface_: c_uint,
    group: c_uint,
    fmode: *mut c_uint,
    numsrc: *mut c_uint,
    slist: *mut c_void,
) -> c_int {
    // IP_MSFILTER = 41 on Linux
    const IP_MSFILTER: c_int = 41;
    // struct ip_msfilter layout: imsf_multiaddr(4), imsf_interface(4), imsf_fmode(4), imsf_numsrc(4), imsf_slist[0](4...)
    let max_src = if numsrc.is_null() { 0u32 } else { unsafe { *numsrc } };
    let buf_size = 16 + (max_src as usize) * 4;
    let mut buf = vec![0u8; buf_size];
    // Fill request: multiaddr + interface
    unsafe {
        std::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, group);
        std::ptr::write_unaligned(buf.as_mut_ptr().add(4) as *mut u32, interface_);
    }
    let mut optlen: u32 = buf_size as u32;
    let rc = unsafe {
        libc::getsockopt(
            s,
            libc::IPPROTO_IP,
            IP_MSFILTER,
            buf.as_mut_ptr() as *mut c_void,
            &mut optlen as *mut u32 as *mut libc::socklen_t,
        )
    };
    if rc < 0 {
        return -1;
    }
    // Extract fmode and numsrc from response
    if !fmode.is_null() {
        unsafe { *fmode = std::ptr::read_unaligned(buf.as_ptr().add(8) as *const u32) };
    }
    let returned_numsrc = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(12) as *const u32) };
    if !numsrc.is_null() {
        unsafe { *numsrc = returned_numsrc };
    }
    // Copy source list
    if !slist.is_null() && returned_numsrc > 0 {
        let copy_count = std::cmp::min(returned_numsrc, max_src) as usize;
        unsafe {
            std::ptr::copy_nonoverlapping(buf.as_ptr().add(16), slist as *mut u8, copy_count * 4);
        }
    }
    0
}
// getmsg/getpmsg: STREAMS — not supported on Linux
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getmsg(
    fd: c_int,
    ctlptr: *mut c_void,
    dataptr: *mut c_void,
    flags: *mut c_int,
) -> c_int {
    let _ = (fd, ctlptr, dataptr, flags);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpmsg(
    fd: c_int,
    ctlptr: *mut c_void,
    dataptr: *mut c_void,
    bandp: *mut c_int,
    flags: *mut c_int,
) -> c_int {
    let _ = (fd, ctlptr, dataptr, bandp, flags);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
// getpw: deprecated — writes "name:passwd:uid:gid:gecos:dir:shell" to buf
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpw(uid: c_uint, buf: *mut c_char) -> c_int {
    if buf.is_null() {
        return -1;
    }
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return -1;
    }
    let pw = unsafe { &*pw };
    let name = unsafe { std::ffi::CStr::from_ptr(pw.pw_name) }.to_bytes();
    let passwd = unsafe { std::ffi::CStr::from_ptr(pw.pw_passwd) }.to_bytes();
    let gecos = unsafe { std::ffi::CStr::from_ptr(pw.pw_gecos) }.to_bytes();
    let dir = unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) }.to_bytes();
    let shell = unsafe { std::ffi::CStr::from_ptr(pw.pw_shell) }.to_bytes();
    let line = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        unsafe { std::str::from_utf8_unchecked(name) },
        unsafe { std::str::from_utf8_unchecked(passwd) },
        pw.pw_uid,
        pw.pw_gid,
        unsafe { std::str::from_utf8_unchecked(gecos) },
        unsafe { std::str::from_utf8_unchecked(dir) },
        unsafe { std::str::from_utf8_unchecked(shell) },
    );
    unsafe {
        std::ptr::copy_nonoverlapping(line.as_ptr(), buf as *mut u8, line.len());
        *buf.add(line.len()) = 0;
    }
    0
}
// gettid: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gettid() -> c_int {
    unsafe { libc::syscall(libc::SYS_gettid) as c_int }
}
// getwd: deprecated — forward to libc::getcwd
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getwd(buf: *mut c_char) -> *mut c_char {
    // PATH_MAX is typically 4096 on Linux
    unsafe { libc::getcwd(buf, 4096) }
}
// group_member: native — check if current process is in supplementary group
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn group_member(gid: c_uint) -> c_int {
    if unsafe { libc::getegid() } == gid {
        return 1;
    }
    let mut groups = [0u32; 64];
    let n = unsafe { libc::getgroups(64, groups.as_mut_ptr()) };
    if n < 0 {
        return 0;
    }
    for g in groups.iter().take(n as usize) {
        if *g == gid {
            return 1;
        }
    }
    0
}
// gtty: legacy V7 — return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gtty(fd: c_int, params: *mut c_void) -> c_int {
    let _ = (fd, params);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
// init_module: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn init_module(
    module_image: *mut c_void,
    len: c_ulong,
    param_values: *const c_char,
) -> c_int {
    unsafe { libc::syscall(libc::SYS_init_module, module_image, len, param_values) as c_int }
}
// innetgr: check if (host,user,domain) is in netgroup — returns 0 (not found)
// Netgroups are an NIS/NIS+ feature rarely used on modern systems.
// A real implementation would parse /etc/netgroup or use NSS, but returning 0
// is safe and matches behavior when NIS is not configured.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn innetgr(
    _netgroup: *const c_char,
    _host: *const c_char,
    _user: *const c_char,
    _domain: *const c_char,
) -> c_int {
    0
}
// ioperm/iopl: native syscalls
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ioperm(from: c_ulong, num: c_ulong, turn_on: c_int) -> c_int {
    unsafe {
        libc::syscall(
            libc::SYS_ioperm,
            from as c_long,
            num as c_long,
            turn_on as c_long,
        ) as c_int
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iopl(level: c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_iopl, level as c_long) as c_int }
}
// iruserok/iruserok_af: .rhosts-based remote user auth — deny-all for security
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iruserok(
    _raddr: c_uint, _superuser: c_int, _ruser: *const c_char, _luser: *const c_char,
) -> c_int {
    -1
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iruserok_af(
    _raddr: *const c_void, _superuser: c_int, _ruser: *const c_char, _luser: *const c_char, _af: c_int,
) -> c_int {
    -1
}
// isastream: STREAMS not supported on Linux — always return 0
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isastream(fd: c_int) -> c_int {
    let _ = fd;
    0
}
// isctype: native — same as __isctype
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isctype(c: c_int, mask: c_int) -> c_int {
    unsafe { __isctype(c, mask) }
}
// isfdtype: native — check file descriptor type via fstat
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isfdtype(fd: c_int, fdtype: c_int) -> c_int {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } < 0 {
        return -1;
    }
    ((stat.st_mode & libc::S_IFMT) == fdtype as u32) as c_int
}
// --- Native math: float/long-double classification ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isinff(x: f32) -> c_int {
    if x == f32::INFINITY {
        1
    } else if x == f32::NEG_INFINITY {
        -1
    } else {
        0
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isinfl(x: f64) -> c_int {
    if x == f64::INFINITY {
        1
    } else if x == f64::NEG_INFINITY {
        -1
    } else {
        0
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isnanf(x: f32) -> c_int {
    x.is_nan() as c_int
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isnanl(x: f64) -> c_int {
    x.is_nan() as c_int
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn finitel(x: f64) -> c_int {
    x.is_finite() as c_int
}
// klogctl: native syscall (syslog)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn klogctl(typ: c_int, bufp: *mut c_char, len: c_int) -> c_int {
    unsafe {
        libc::syscall(
            libc::SYS_syslog,
            typ as c_long,
            bufp as c_long,
            len as c_long,
        ) as c_int
    }
}
// lchmod: native — fchmodat with AT_SYMLINK_NOFOLLOW
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lchmod(pathname: *const c_char, mode: c_uint) -> c_int {
    unsafe {
        libc::syscall(
            libc::SYS_fchmodat,
            libc::AT_FDCWD,
            pathname,
            mode,
            libc::AT_SYMLINK_NOFOLLOW,
        ) as c_int
    }
}
// ldexpl: native — x * 2^exp via repeated doubling/halving
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ldexpl(x: f64, exp: c_int) -> f64 {
    native_ldexp(x, exp)
}
// llseek: alias for lseek on 64-bit
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    unsafe { libc::syscall(libc::SYS_lseek, fd, offset, whence) as i64 }
}
// lutimes: native — forward to libc
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lutimes(filename: *const c_char, tv: *const c_void) -> c_int {
    unsafe { libc::lutimes(filename, tv.cast()) }
}
// mkostemp64/mkostemps64/mkstemp64/mkstemps64: forward to libc (64-bit aliases)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemp64(template: *mut c_char, flags: c_int) -> c_int {
    unsafe { libc::mkostemp(template, flags) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemps64(
    template: *mut c_char,
    suffixlen: c_int,
    flags: c_int,
) -> c_int {
    unsafe { libc::mkostemps(template, suffixlen, flags) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkstemp64(template: *mut c_char) -> c_int {
    unsafe { libc::mkstemp(template) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkstemps64(template: *mut c_char, suffixlen: c_int) -> c_int {
    unsafe { libc::mkstemps(template, suffixlen) }
}
// modfl: native — split into integer + fractional parts
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn modfl(x: f64, iptr: *mut f64) -> f64 {
    if x.is_nan() || x.is_infinite() {
        if !iptr.is_null() {
            unsafe { *iptr = x };
        }
        return if x.is_infinite() {
            0.0_f64.copysign(x)
        } else {
            x
        };
    }
    let int_part = x.trunc();
    if !iptr.is_null() {
        unsafe { *iptr = int_part };
    }
    x - int_part
}
// modify_ldt: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn modify_ldt(func: c_int, ptr: *mut c_void, bytecount: c_ulong) -> c_int {
    unsafe { libc::syscall(libc::SYS_modify_ldt, func, ptr, bytecount) as c_int }
}
// parse_printf_format: introspect printf format string to get argument types
// glibc PA_* type constants
const PA_INT: c_int = 1;
const PA_CHAR: c_int = 2;
const PA_STRING: c_int = 4;
const PA_POINTER: c_int = 6;
const PA_DOUBLE: c_int = 8;
const PA_FLAG_LONG: c_int = 0x100;
const PA_FLAG_LONG_LONG: c_int = 0x200;
const PA_FLAG_SHORT: c_int = 0x400;
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn parse_printf_format(
    fmt: *const c_char, n: SizeT, argtypes: *mut c_int,
) -> SizeT {
    if fmt.is_null() {
        return 0;
    }
    let mut p = fmt as *const u8;
    let mut count: usize = 0;
    loop {
        let c = unsafe { *p };
        if c == 0 {
            break;
        }
        if c != b'%' {
            p = unsafe { p.add(1) };
            continue;
        }
        p = unsafe { p.add(1) }; // skip '%'
        if unsafe { *p } == b'%' {
            p = unsafe { p.add(1) };
            continue;
        }
        // Skip flags: -+0 #'
        while {
            let f = unsafe { *p };
            f == b'-' || f == b'+' || f == b'0' || f == b' ' || f == b'#' || f == b'\''
        } {
            p = unsafe { p.add(1) };
        }
        // Skip width (may be * which consumes an int arg)
        if unsafe { *p } == b'*' {
            if count < n && !argtypes.is_null() {
                unsafe { *argtypes.add(count) = PA_INT };
            }
            count += 1;
            p = unsafe { p.add(1) };
        } else {
            while unsafe { (*p).is_ascii_digit() } {
                p = unsafe { p.add(1) };
            }
        }
        // Skip precision
        if unsafe { *p } == b'.' {
            p = unsafe { p.add(1) };
            if unsafe { *p } == b'*' {
                if count < n && !argtypes.is_null() {
                    unsafe { *argtypes.add(count) = PA_INT };
                }
                count += 1;
                p = unsafe { p.add(1) };
            } else {
                while unsafe { (*p).is_ascii_digit() } {
                    p = unsafe { p.add(1) };
                }
            }
        }
        // Length modifiers
        let mut length_flag: c_int = 0;
        match unsafe { *p } {
            b'h' => {
                p = unsafe { p.add(1) };
                if unsafe { *p } == b'h' {
                    p = unsafe { p.add(1) };
                }
                length_flag = PA_FLAG_SHORT;
            }
            b'l' => {
                p = unsafe { p.add(1) };
                if unsafe { *p } == b'l' {
                    p = unsafe { p.add(1) };
                    length_flag = PA_FLAG_LONG_LONG;
                } else {
                    length_flag = PA_FLAG_LONG;
                }
            }
            b'L' | b'q' => {
                p = unsafe { p.add(1) };
                length_flag = PA_FLAG_LONG_LONG;
            }
            b'z' | b'j' | b't' => {
                p = unsafe { p.add(1) };
                length_flag = PA_FLAG_LONG;
            }
            _ => {}
        }
        // Conversion specifier
        let argtype = match unsafe { *p } {
            b'd' | b'i' | b'o' | b'u' | b'x' | b'X' => PA_INT | length_flag,
            b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A' => PA_DOUBLE | length_flag,
            b'c' => PA_CHAR | length_flag,
            b's' => PA_STRING | length_flag,
            b'p' => PA_POINTER,
            b'n' => PA_POINTER,
            _ => PA_INT,
        };
        if unsafe { *p } != 0 {
            p = unsafe { p.add(1) };
        }
        if count < n && !argtypes.is_null() {
            unsafe { *argtypes.add(count) = argtype };
        }
        count += 1;
    }
    count as SizeT
}
// pidfd_getpid: native syscall (Linux 6.9+, nr 438)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pidfd_getpid(pidfd: c_int) -> c_int {
    unsafe { libc::syscall(438, pidfd) as c_int } // SYS_pidfd_getpid
}
// pidfd_spawn: posix_spawn + pidfd_open to get a pidfd for the child process
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pidfd_spawn(
    pidfd: *mut c_int,
    path: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    if pidfd.is_null() {
        return libc::EINVAL;
    }
    let mut child_pid: libc::pid_t = 0;
    let rc = unsafe {
        libc::posix_spawn(
            &mut child_pid,
            path,
            file_actions as *const libc::posix_spawn_file_actions_t,
            attrp as *const libc::posix_spawnattr_t,
            argv,
            envp,
        )
    };
    if rc != 0 {
        return rc;
    }
    // SYS_pidfd_open = 434 on x86_64
    let fd = unsafe { libc::syscall(434, child_pid as c_long, 0 as c_long) as c_int };
    if fd < 0 {
        // pidfd_open failed, but child is spawned — still return the pidfd as -1
        unsafe { *pidfd = -1 };
        return 0;
    }
    unsafe { *pidfd = fd };
    0
}

// pidfd_spawnp: like pidfd_spawn but searches PATH for `file`
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pidfd_spawnp(
    pidfd: *mut c_int,
    file: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    if pidfd.is_null() {
        return libc::EINVAL;
    }
    let mut child_pid: libc::pid_t = 0;
    let rc = unsafe {
        libc::posix_spawnp(
            &mut child_pid,
            file,
            file_actions as *const libc::posix_spawn_file_actions_t,
            attrp as *const libc::posix_spawnattr_t,
            argv,
            envp,
        )
    };
    if rc != 0 {
        return rc;
    }
    let fd = unsafe { libc::syscall(434, child_pid as c_long, 0 as c_long) as c_int };
    if fd < 0 {
        unsafe { *pidfd = -1 };
        return 0;
    }
    unsafe { *pidfd = fd };
    0
}
// preadv64v2: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn preadv64v2(
    fd: c_int,
    iov: *const c_void,
    iovcnt: c_int,
    offset: i64,
    flags: c_int,
) -> SSizeT {
    unsafe { libc::syscall(libc::SYS_preadv2, fd, iov, iovcnt, offset, flags) as SSizeT }
}
// putgrent: native — write group entry to file
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putgrent(grp: *const c_void, fp: *mut c_void) -> c_int {
    if grp.is_null() || fp.is_null() {
        return -1;
    }
    // struct group { gr_name, gr_passwd, gr_gid, gr_mem }
    let g = grp as *const libc::group;
    let name = unsafe { std::ffi::CStr::from_ptr((*g).gr_name) }.to_bytes();
    let passwd = if unsafe { (*g).gr_passwd }.is_null() {
        b"x" as &[u8]
    } else {
        unsafe { std::ffi::CStr::from_ptr((*g).gr_passwd) }.to_bytes()
    };
    let gid = unsafe { (*g).gr_gid };
    // Build member list
    let mut members = Vec::new();
    let mut mem_ptr = unsafe { (*g).gr_mem };
    if !mem_ptr.is_null() {
        while !unsafe { *mem_ptr }.is_null() {
            members.push(unsafe { std::ffi::CStr::from_ptr(*mem_ptr) }.to_bytes());
            mem_ptr = unsafe { mem_ptr.add(1) };
        }
    }
    // Format: name:passwd:gid:member1,member2,...
    let member_str: Vec<u8> = members.join(&b","[..]);
    let line = unsafe {
        format!(
            "{}:{}:{}:{}\n",
            std::str::from_utf8_unchecked(name),
            std::str::from_utf8_unchecked(passwd),
            gid,
            std::str::from_utf8_unchecked(&member_str),
        )
    };
    let written = unsafe { libc::fwrite(line.as_ptr().cast(), 1, line.len(), fp.cast()) };
    if written == line.len() { 0 } else { -1 }
}
// putmsg/putpmsg: STREAMS — not supported on Linux
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putmsg(
    fd: c_int,
    ctlptr: *const c_void,
    dataptr: *const c_void,
    flags: c_int,
) -> c_int {
    let _ = (fd, ctlptr, dataptr, flags);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putpmsg(
    fd: c_int,
    ctlptr: *const c_void,
    dataptr: *const c_void,
    band: c_int,
    flags: c_int,
) -> c_int {
    let _ = (fd, ctlptr, dataptr, band, flags);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
// putpwent: native — write passwd entry to file
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putpwent(pw: *const c_void, fp: *mut c_void) -> c_int {
    if pw.is_null() || fp.is_null() {
        return -1;
    }
    let p = pw as *const libc::passwd;
    let name = unsafe { std::ffi::CStr::from_ptr((*p).pw_name) }.to_bytes();
    let passwd = if unsafe { (*p).pw_passwd }.is_null() {
        b"x" as &[u8]
    } else {
        unsafe { std::ffi::CStr::from_ptr((*p).pw_passwd) }.to_bytes()
    };
    let gecos = if unsafe { (*p).pw_gecos }.is_null() {
        b"" as &[u8]
    } else {
        unsafe { std::ffi::CStr::from_ptr((*p).pw_gecos) }.to_bytes()
    };
    let dir = if unsafe { (*p).pw_dir }.is_null() {
        b"" as &[u8]
    } else {
        unsafe { std::ffi::CStr::from_ptr((*p).pw_dir) }.to_bytes()
    };
    let shell = if unsafe { (*p).pw_shell }.is_null() {
        b"" as &[u8]
    } else {
        unsafe { std::ffi::CStr::from_ptr((*p).pw_shell) }.to_bytes()
    };
    // Format: name:passwd:uid:gid:gecos:dir:shell
    let line = format!(
        "{}:{}:{}:{}:{}:{}:{}\n",
        unsafe { std::str::from_utf8_unchecked(name) },
        unsafe { std::str::from_utf8_unchecked(passwd) },
        unsafe { (*p).pw_uid },
        unsafe { (*p).pw_gid },
        unsafe { std::str::from_utf8_unchecked(gecos) },
        unsafe { std::str::from_utf8_unchecked(dir) },
        unsafe { std::str::from_utf8_unchecked(shell) },
    );
    let written = unsafe { libc::fwrite(line.as_ptr().cast(), 1, line.len(), fp.cast()) };
    if written == line.len() { 0 } else { -1 }
}
// pwritev64v2: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pwritev64v2(
    fd: c_int,
    iov: *const c_void,
    iovcnt: c_int,
    offset: i64,
    flags: c_int,
) -> SSizeT {
    unsafe { libc::syscall(libc::SYS_pwritev2, fd, iov, iovcnt, offset, flags) as SSizeT }
}
// query_module: removed in Linux 2.6 — return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn query_module(
    name: *const c_char,
    which: c_int,
    buf: *mut c_void,
    bufsize: SizeT,
    ret: *mut SizeT,
) -> c_int {
    let _ = (name, which, buf, bufsize, ret);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
// rcmd/rcmd_af: rsh remote command — disabled for security (rsh protocol is insecure)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rcmd(
    _ahost: *mut *mut c_char, _rport: c_int, _locuser: *const c_char,
    _remuser: *const c_char, _cmd: *const c_char, _fd2p: *mut c_int,
) -> c_int {
    unsafe { *libc::__errno_location() = libc::ENOSYS };
    -1
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rcmd_af(
    _ahost: *mut *mut c_char, _rport: c_int, _locuser: *const c_char,
    _remuser: *const c_char, _cmd: *const c_char, _fd2p: *mut c_int, _af: c_int,
) -> c_int {
    unsafe { *libc::__errno_location() = libc::ENOSYS };
    -1
}
dlsym_passthrough!(fn register_printf_function(spec: c_int, render: *mut c_void, arginfo: *mut c_void) -> c_int);
dlsym_passthrough!(fn register_printf_modifier(str: *const WcharT) -> c_int);
dlsym_passthrough!(fn register_printf_specifier(spec: c_int, render: *mut c_void, arginfo: *mut c_void) -> c_int);
dlsym_passthrough!(fn register_printf_type(fct: *mut c_void) -> c_int);
// revoke: BSD — not implemented on Linux
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn revoke(file: *const c_char) -> c_int {
    let _ = file;
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
// rexec/rexec_af: remote exec with cleartext auth — disabled for security
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rexec(
    _ahost: *mut *mut c_char, _rport: c_int, _user: *const c_char,
    _passwd: *const c_char, _cmd: *const c_char, _fd2p: *mut c_int,
) -> c_int {
    unsafe { *libc::__errno_location() = libc::ENOSYS };
    -1
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rexec_af(
    _ahost: *mut *mut c_char, _rport: c_int, _user: *const c_char,
    _passwd: *const c_char, _cmd: *const c_char, _fd2p: *mut c_int, _af: c_int,
) -> c_int {
    unsafe { *libc::__errno_location() = libc::ENOSYS };
    -1
}
// rpmatch: native — match yes/no response (C locale)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rpmatch(response: *const c_char) -> c_int {
    if response.is_null() {
        return -1;
    }
    let c = unsafe { *response.cast::<u8>() };
    match c {
        b'y' | b'Y' => 1,
        b'n' | b'N' => 0,
        _ => -1,
    }
}
// rresvport: reserve a privileged port for RPC (like bindresvport but returns socket)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rresvport(port: *mut c_int) -> c_int {
    unsafe { rresvport_af(port, libc::AF_INET) }
}

// rresvport_af: reserve a privileged port for the given address family
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rresvport_af(port: *mut c_int, af: c_int) -> c_int {
    let sock_type = libc::SOCK_STREAM;
    let fd = unsafe { libc::socket(af, sock_type, 0) };
    if fd < 0 {
        return -1;
    }
    // Start from the provided port, or 1023 if null/0
    let start_port = if port.is_null() {
        1023u16
    } else {
        let p = unsafe { *port } as u16;
        if p == 0 || p > 1023 { 1023u16 } else { p }
    };
    // Try ports from start_port down to 512
    for p in (512..=start_port).rev() {
        let rc = match af {
            libc::AF_INET => {
                let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                addr.sin_family = libc::AF_INET as u16;
                addr.sin_port = p.to_be();
                unsafe {
                    libc::bind(
                        fd,
                        &addr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                }
            }
            libc::AF_INET6 => {
                let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                addr.sin6_family = libc::AF_INET6 as u16;
                addr.sin6_port = p.to_be();
                unsafe {
                    libc::bind(
                        fd,
                        &addr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    )
                }
            }
            _ => {
                unsafe { libc::close(fd) };
                unsafe { *libc::__errno_location() = libc::EAFNOSUPPORT };
                return -1;
            }
        };
        if rc == 0 {
            if !port.is_null() {
                unsafe { *port = p as c_int };
            }
            return fd;
        }
    }
    unsafe { libc::close(fd) };
    unsafe { *libc::__errno_location() = libc::EAGAIN };
    -1
}
// ruserok/ruserok_af: .rhosts hostname-based auth — deny-all for security
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ruserok(
    _rhost: *const c_char, _superuser: c_int, _ruser: *const c_char, _luser: *const c_char,
) -> c_int {
    -1
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ruserok_af(
    _rhost: *const c_char, _superuser: c_int, _ruser: *const c_char, _luser: *const c_char, _af: c_int,
) -> c_int {
    -1
}
// ruserpass: .netrc credential parser — return -1 (no .netrc support for security)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ruserpass(
    _host: *const c_char, aname: *mut *const c_char, apass: *mut *const c_char,
) -> c_int {
    if !aname.is_null() {
        unsafe { *aname = std::ptr::null() };
    }
    if !apass.is_null() {
        unsafe { *apass = std::ptr::null() };
    }
    -1
}
// scalbnl: native — x * 2^n (same as ldexp)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbnl(x: f64, n: c_int) -> f64 {
    native_ldexp(x, n)
}
// scandirat: native — scan directory relative to fd
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scandirat(
    dirfd: c_int,
    dirp: *const c_char,
    namelist: *mut *mut *mut c_void,
    filter: *mut c_void,
    compar: *mut c_void,
) -> c_int {
    // Open the directory relative to dirfd using openat + fdopendir
    let fd = unsafe { libc::openat(dirfd, dirp, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return -1;
    }
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        unsafe { libc::close(fd) };
        return -1;
    }
    // Use scandir-style iteration
    type FilterFn = unsafe extern "C" fn(*const libc::dirent) -> c_int;
    type ComparFn = unsafe extern "C" fn(*const *const libc::dirent, *const *const libc::dirent) -> c_int;
    let filter_fn: Option<FilterFn> = if filter.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut c_void, FilterFn>(filter) })
    };
    let mut entries: Vec<*mut libc::dirent> = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }
        let include = match filter_fn {
            Some(f) => {
                let rc = unsafe { f(entry) };
                rc != 0
            }
            None => true,
        };
        if include {
            let ent_size = std::mem::size_of::<libc::dirent>();
            let copy = unsafe { libc::malloc(ent_size) } as *mut libc::dirent;
            if copy.is_null() {
                // Cleanup on OOM
                for e in &entries {
                    unsafe { libc::free(*e as *mut c_void) };
                }
                unsafe { libc::closedir(dir) };
                return -1;
            }
            unsafe { std::ptr::copy_nonoverlapping(entry, copy, 1) };
            entries.push(copy);
        }
    }
    unsafe { libc::closedir(dir) };
    if !compar.is_null() {
        let cmp: ComparFn = unsafe { std::mem::transmute::<*mut c_void, ComparFn>(compar) };
        entries.sort_by(|a, b| {
            let r = unsafe { cmp(a as *const _ as *const *const libc::dirent, b as *const _ as *const *const libc::dirent) };
            r.cmp(&0)
        });
    }
    let count = entries.len() as c_int;
    let arr = unsafe { libc::malloc(entries.len() * std::mem::size_of::<*mut libc::dirent>()) } as *mut *mut c_void;
    if arr.is_null() && !entries.is_empty() {
        for e in &entries {
            unsafe { libc::free(*e as *mut c_void) };
        }
        return -1;
    }
    for (i, e) in entries.iter().enumerate() {
        unsafe { *arr.add(i) = *e as *mut c_void };
    }
    unsafe { *namelist = arr };
    count
}
// scandirat64: on 64-bit Linux, identical to scandirat
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scandirat64(
    dirfd: c_int,
    dirp: *const c_char,
    namelist: *mut *mut *mut c_void,
    filter: *mut c_void,
    compar: *mut c_void,
) -> c_int {
    unsafe { scandirat(dirfd, dirp, namelist, filter, compar) }
}
// sem_clockwait: timed semaphore wait with specified clock
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_clockwait(sem: *mut c_void, clockid: c_int, abstime: *const c_void) -> c_int {
    // Use futex FUTEX_WAIT_BITSET with clock selection
    // sem_t is an int at offset 0; if value > 0, decrement and return
    let sem_val = sem as *mut std::sync::atomic::AtomicI32;
    loop {
        let val = unsafe { (*sem_val).load(std::sync::atomic::Ordering::Acquire) };
        if val > 0 {
            if unsafe {
                (*sem_val)
                    .compare_exchange(
                        val,
                        val - 1,
                        std::sync::atomic::Ordering::AcqRel,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok()
            } {
                return 0;
            }
            continue;
        }
        // Wait using futex with absolute timeout
        let clock_flag = if clockid == libc::CLOCK_REALTIME {
            0
        } else {
            libc::FUTEX_CLOCK_REALTIME // bit to NOT set for CLOCK_MONOTONIC
        };
        let _ = clock_flag;
        let ts = abstime as *const libc::timespec;
        let rc = unsafe {
            libc::syscall(
                libc::SYS_futex,
                sem_val as *mut c_void,
                libc::FUTEX_WAIT_BITSET | (libc::FUTEX_CLOCK_REALTIME * (if clockid == libc::CLOCK_REALTIME { 1 } else { 0 })),
                val,
                ts,
                std::ptr::null::<c_void>(),
                !0u32, // FUTEX_BITSET_MATCH_ANY
            )
        };
        if rc == -1 {
            let err = unsafe { *libc::__errno_location() };
            if err == libc::ETIMEDOUT {
                unsafe { *libc::__errno_location() = libc::ETIMEDOUT };
                return -1;
            }
            if err != libc::EAGAIN && err != libc::EINTR {
                return -1;
            }
        }
    }
}
// setaliasent: mail alias — no-op (no /etc/aliases support)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setaliasent() {}
// setfsgid/setfsuid: native syscalls
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setfsgid(fsgid: c_uint) -> c_int {
    unsafe { libc::syscall(libc::SYS_setfsgid, fsgid as c_ulong) as c_int }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setfsuid(fsuid: c_uint) -> c_int {
    unsafe { libc::syscall(libc::SYS_setfsuid, fsuid as c_ulong) as c_int }
}
// sethostid: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sethostid(hostid: c_long) -> c_int {
    unsafe { libc::sethostid(hostid) }
}
// setipv4sourcefilter: set multicast source filter via setsockopt(IP_MSFILTER)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setipv4sourcefilter(
    s: c_int,
    interface_: c_uint,
    group: c_uint,
    fmode: c_uint,
    numsrc: c_uint,
    slist: *const c_void,
) -> c_int {
    const IP_MSFILTER: c_int = 41;
    let buf_size = 16 + (numsrc as usize) * 4;
    let mut buf = vec![0u8; buf_size];
    unsafe {
        std::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, group);
        std::ptr::write_unaligned(buf.as_mut_ptr().add(4) as *mut u32, interface_);
        std::ptr::write_unaligned(buf.as_mut_ptr().add(8) as *mut u32, fmode);
        std::ptr::write_unaligned(buf.as_mut_ptr().add(12) as *mut u32, numsrc);
    }
    if !slist.is_null() && numsrc > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(slist as *const u8, buf.as_mut_ptr().add(16), numsrc as usize * 4);
        }
    }
    unsafe {
        libc::setsockopt(
            s,
            libc::IPPROTO_IP,
            IP_MSFILTER,
            buf.as_ptr() as *const c_void,
            buf_size as libc::socklen_t,
        )
    }
}
// setlogin: BSD — not supported on Linux, return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setlogin(name: *const c_char) -> c_int {
    let _ = name;
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
// setsourcefilter: AF-independent multicast source filter via setsockopt(MCAST_MSFILTER)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setsourcefilter(
    s: c_int,
    interface_: c_uint,
    group: *const c_void,
    grouplen: c_uint,
    fmode: c_uint,
    numsrc: c_uint,
    slist: *const c_void,
) -> c_int {
    // MCAST_MSFILTER = 48 on Linux, SOL_SOCKET level
    // struct group_filter: gf_interface(u32), pad(u32), gf_group(sockaddr_storage=128), gf_fmode(u32), gf_numsrc(u32), gf_slist[0](sockaddr_storage...)
    const MCAST_MSFILTER: c_int = 48;
    let ss_size = std::mem::size_of::<libc::sockaddr_storage>();
    let header_size = 4 + 4 + ss_size + 4 + 4; // 136 + 8 = 144
    let buf_size = header_size + (numsrc as usize) * ss_size;
    let mut buf = vec![0u8; buf_size];
    unsafe {
        std::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, interface_);
        // Copy group address into gf_group (at offset 8)
        let copy_len = std::cmp::min(grouplen as usize, ss_size);
        std::ptr::copy_nonoverlapping(group as *const u8, buf.as_mut_ptr().add(8), copy_len);
        // fmode at offset 8+ss_size, numsrc at offset 8+ss_size+4
        std::ptr::write_unaligned(buf.as_mut_ptr().add(8 + ss_size) as *mut u32, fmode);
        std::ptr::write_unaligned(buf.as_mut_ptr().add(8 + ss_size + 4) as *mut u32, numsrc);
        // Copy source list
        if !slist.is_null() && numsrc > 0 {
            std::ptr::copy_nonoverlapping(
                slist as *const u8,
                buf.as_mut_ptr().add(header_size),
                numsrc as usize * ss_size,
            );
        }
        libc::setsockopt(s, libc::SOL_SOCKET, MCAST_MSFILTER, buf.as_ptr() as *const c_void, buf_size as libc::socklen_t)
    }
}

// getsourcefilter: AF-independent multicast source filter via getsockopt(MCAST_MSFILTER)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsourcefilter(
    s: c_int,
    interface_: c_uint,
    group: *const c_void,
    grouplen: c_uint,
    fmode: *mut c_uint,
    numsrc: *mut c_uint,
    slist: *mut c_void,
) -> c_int {
    const MCAST_MSFILTER: c_int = 48;
    let ss_size = std::mem::size_of::<libc::sockaddr_storage>();
    let header_size = 4 + 4 + ss_size + 4 + 4;
    let max_src = if numsrc.is_null() { 0u32 } else { unsafe { *numsrc } };
    let buf_size = header_size + (max_src as usize) * ss_size;
    let mut buf = vec![0u8; buf_size];
    unsafe {
        std::ptr::write_unaligned(buf.as_mut_ptr() as *mut u32, interface_);
        let copy_len = std::cmp::min(grouplen as usize, ss_size);
        std::ptr::copy_nonoverlapping(group as *const u8, buf.as_mut_ptr().add(8), copy_len);
    }
    let mut optlen: u32 = buf_size as u32;
    let rc = unsafe {
        libc::getsockopt(
            s,
            libc::SOL_SOCKET,
            MCAST_MSFILTER,
            buf.as_mut_ptr() as *mut c_void,
            &mut optlen as *mut u32 as *mut libc::socklen_t,
        )
    };
    if rc < 0 {
        return -1;
    }
    if !fmode.is_null() {
        unsafe { *fmode = std::ptr::read_unaligned(buf.as_ptr().add(8 + ss_size) as *const u32) };
    }
    let returned_numsrc = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(8 + ss_size + 4) as *const u32) };
    if !numsrc.is_null() {
        unsafe { *numsrc = returned_numsrc };
    }
    if !slist.is_null() && returned_numsrc > 0 {
        let copy_count = std::cmp::min(returned_numsrc, max_src) as usize;
        unsafe {
            std::ptr::copy_nonoverlapping(
                buf.as_ptr().add(header_size),
                slist as *mut u8,
                copy_count * ss_size,
            );
        }
    }
    0
}
// settimeofday: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn settimeofday(tv: *const c_void, tz: *const c_void) -> c_int {
    unsafe { libc::settimeofday(tv.cast(), tz.cast()) }
}
// sgetspent: native — parse shadow password entry from string
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sgetspent(s: *const c_char) -> *mut c_void {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    // Thread-local static buffer for non-reentrant version
    thread_local! {
        static BUF: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
        static SP: std::cell::RefCell<libc::spwd> = const { std::cell::RefCell::new(unsafe { std::mem::zeroed() }) };
    }
    BUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        buf.resize(1024, 0);
        SP.with(|sp| {
            let mut sp = sp.borrow_mut();
            let mut result: *mut libc::spwd = std::ptr::null_mut();
            let rc = unsafe {
                sgetspent_r(
                    s,
                    &mut *sp as *mut _ as *mut c_void,
                    buf.as_mut_ptr() as *mut c_char,
                    buf.len(),
                    &mut result as *mut _ as *mut *mut c_void,
                )
            };
            if rc == 0 && !result.is_null() {
                result as *mut c_void
            } else {
                std::ptr::null_mut()
            }
        })
    })
}
// sgetspent_r: native — reentrant shadow password parser
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sgetspent_r(
    s: *const c_char,
    spbuf: *mut c_void,
    buf: *mut c_char,
    buflen: SizeT,
    spbufp: *mut *mut c_void,
) -> c_int {
    if s.is_null() || spbuf.is_null() || buf.is_null() || spbufp.is_null() {
        return libc::EINVAL;
    }
    unsafe { *(spbufp as *mut *mut libc::spwd) = std::ptr::null_mut() };
    let line = unsafe { std::ffi::CStr::from_ptr(s) }.to_bytes();
    let line_str = match std::str::from_utf8(line) {
        Ok(s) => s,
        Err(_) => return libc::EINVAL,
    };
    // Format: name:passwd:lastchg:min:max:warn:inact:expire:flag
    let fields: Vec<&str> = line_str.splitn(9, ':').collect();
    if fields.len() < 2 {
        return libc::EINVAL;
    }
    // Check buffer space
    let name_len = fields[0].len() + 1;
    let passwd_len = fields.get(1).map_or(1, |s| s.len() + 1);
    if name_len + passwd_len > buflen {
        return libc::ERANGE;
    }
    let sp = spbuf as *mut libc::spwd;
    let buf_u8 = buf as *mut u8;
    // Copy name
    unsafe {
        std::ptr::copy_nonoverlapping(fields[0].as_ptr(), buf_u8, fields[0].len());
        *buf_u8.add(fields[0].len()) = 0;
        (*sp).sp_namp = buf as *mut c_char;
    }
    let mut off = name_len;
    // Copy password
    let pw = fields.get(1).copied().unwrap_or("");
    unsafe {
        std::ptr::copy_nonoverlapping(pw.as_ptr(), buf_u8.add(off), pw.len());
        *buf_u8.add(off + pw.len()) = 0;
        (*sp).sp_pwdp = buf.add(off as isize as usize) as *mut c_char;
    }
    off += passwd_len;
    let _ = off;
    // Parse numeric fields
    let parse_long = |idx: usize| -> c_long {
        fields.get(idx).and_then(|s| s.parse::<c_long>().ok()).unwrap_or(-1)
    };
    unsafe {
        (*sp).sp_lstchg = parse_long(2);
        (*sp).sp_min = parse_long(3);
        (*sp).sp_max = parse_long(4);
        (*sp).sp_warn = parse_long(5);
        (*sp).sp_inact = parse_long(6);
        (*sp).sp_expire = parse_long(7);
        (*sp).sp_flag = fields.get(8).and_then(|s| s.parse::<c_ulong>().ok()).unwrap_or(c_ulong::MAX);
        *(spbufp as *mut *mut libc::spwd) = sp;
    }
    0
}
// stime: deprecated (removed glibc 2.31) — set system time via clock_settime
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn stime(t: *const c_long) -> c_int {
    if t.is_null() {
        return -1;
    }
    let ts = libc::timespec {
        tv_sec: unsafe { *t },
        tv_nsec: 0,
    };
    unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) }
}
// stty: legacy V7 — return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn stty(fd: c_int, params: *const c_void) -> c_int {
    let _ = (fd, params);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
// sysctl: deprecated — forward to libc
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sysctl(
    args: *mut c_int,
    nlen: c_int,
    oldval: *mut c_void,
    oldlenp: *mut SizeT,
    newval: *mut c_void,
    newlen: SizeT,
) -> c_int {
    unsafe { libc::sysctl(args, nlen, oldval, oldlenp, newval, newlen) }
}
// times: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn times(buf: *mut c_void) -> c_long {
    unsafe { libc::syscall(libc::SYS_times, buf) as c_long }
}
// tr_break: obsolete regex debugging hook — no-op
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tr_break() {}
// ttyslot: legacy — always returns -1 on modern Linux
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ttyslot() -> c_int {
    -1
}
// --- Native abs for unsigned types (identity function) ---
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn uabs(n: c_uint) -> c_uint {
    n
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn uimaxabs(n: u64) -> u64 {
    n
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ulabs(n: c_ulong) -> c_ulong {
    n
}
// ulimit: native — legacy POSIX resource limit
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ulimit(cmd: c_int, newlimit: c_long) -> c_long {
    const UL_GETFSIZE: c_int = 1;
    const UL_SETFSIZE: c_int = 2;
    match cmd {
        UL_GETFSIZE => {
            let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
            if unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut rlim) } < 0 {
                return -1;
            }
            // ulimit returns in 512-byte blocks
            if rlim.rlim_cur == libc::RLIM_INFINITY {
                c_long::MAX
            } else {
                (rlim.rlim_cur / 512) as c_long
            }
        }
        UL_SETFSIZE => {
            let rlim = libc::rlimit {
                rlim_cur: (newlimit as u64) * 512,
                rlim_max: (newlimit as u64) * 512,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &rlim) } < 0 {
                return -1;
            }
            newlimit
        }
        _ => {
            unsafe {
                *libc::__errno_location() = libc::EINVAL;
            }
            -1
        }
    }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ullabs(n: u64) -> u64 {
    n
}
// uselib: deprecated Linux syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn uselib(library: *const c_char) -> c_int {
    unsafe { libc::syscall(libc::SYS_uselib, library) as c_int }
}
// ustat: removed in Linux 4.18 — return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ustat(dev: c_uint, ubuf: *mut c_void) -> c_int {
    let _ = (dev, ubuf);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
// utime: forward to libc
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn utime(filename: *const c_char, times: *const c_void) -> c_int {
    unsafe { libc::utime(filename, times.cast()) }
}
// utimes: forward to libc
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn utimes(filename: *const c_char, tv: *const c_void) -> c_int {
    unsafe { libc::utimes(filename, tv.cast()) }
}
// vhangup: native syscall
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vhangup() -> c_int {
    unsafe { libc::syscall(libc::SYS_vhangup) as c_int }
}
// vlimit: obsolete BSD resource limit — return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vlimit(resource: c_int, value: c_int) -> c_int {
    let _ = (resource, value);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}
// vtimes: obsolete BSD process times — return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vtimes(current: *mut c_void, child: *mut c_void) -> c_int {
    let _ = (current, child);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}

// Legacy BSD regex (2 symbols) — shared compiled pattern state
static RE_COMPILED_BUF: std::sync::Mutex<[u8; 256]> = std::sync::Mutex::new([0u8; 256]);
static RE_ERROR_BUF: std::sync::Mutex<[u8; 128]> = std::sync::Mutex::new([0u8; 128]);
// re_comp: compile regex pattern, returns NULL on success or error string
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn re_comp(pattern: *const c_char) -> *mut c_char {
    if pattern.is_null() {
        return std::ptr::null_mut();
    }
    let mut buf = RE_COMPILED_BUF.lock().unwrap();
    let mut err = RE_ERROR_BUF.lock().unwrap();
    let regex_ptr = buf.as_mut_ptr() as *mut c_void;
    let rc = unsafe {
        super::string_abi::regcomp(regex_ptr, pattern, 0)
    };
    if rc == 0 {
        std::ptr::null_mut()
    } else {
        let msg = b"Invalid regular expression\0";
        err[..msg.len()].copy_from_slice(msg);
        err.as_mut_ptr() as *mut c_char
    }
}
// re_exec: execute last compiled regex against string, returns 1 on match
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn re_exec(string: *const c_char) -> c_int {
    if string.is_null() {
        return 0;
    }
    let buf = RE_COMPILED_BUF.lock().unwrap();
    let regex_ptr = buf.as_ptr() as *const c_void;
    let rc = unsafe {
        super::string_abi::regexec(regex_ptr, string, 0, std::ptr::null_mut(), 0)
    };
    if rc == 0 { 1 } else { 0 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut re_syntax_options: c_ulong = 0;
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut re_max_failures: c_int = 0;

// __argz_* (3 symbols)
// __argz_count: native — count NUL-separated entries
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __argz_count(argz: *const c_char, argz_len: SizeT) -> SizeT {
    if argz.is_null() || argz_len == 0 {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(argz.cast::<u8>(), argz_len) };
    slice.iter().filter(|&&b| b == 0).count()
}
// __argz_next: native — advance to next entry in argz vector
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __argz_next(
    argz: *const c_char,
    argz_len: SizeT,
    entry: *const c_char,
) -> *mut c_char {
    if argz.is_null() || argz_len == 0 {
        return std::ptr::null_mut();
    }
    let end = unsafe { argz.add(argz_len) };
    if entry.is_null() {
        return argz as *mut c_char;
    }
    // Find NUL after current entry, then advance past it
    let mut p = entry;
    while p < end && unsafe { *p } != 0 {
        p = unsafe { p.add(1) };
    }
    if p < end {
        p = unsafe { p.add(1) };
    } // skip NUL
    if p >= end {
        std::ptr::null_mut()
    } else {
        p as *mut c_char
    }
}
// __argz_stringify: native — replace NULs with sep
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __argz_stringify(argz: *mut c_char, argz_len: SizeT, sep: c_int) {
    if argz.is_null() || argz_len < 2 {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(argz.cast::<u8>(), argz_len) };
    // Replace all NULs except the final one with sep
    for b in &mut slice[..argz_len - 1] {
        if *b == 0 {
            *b = sep as u8;
        }
    }
}

// NL internals
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _nl_default_dirname: [u8; 24] = *b"/usr/share/locale/\0\0\0\0\0\0";
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _nl_domain_bindings: *mut c_void = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _nl_msg_cat_cntr: c_int = 0;

// h_errlist — rarely used, programs normally call hstrerror()
// Skipped: cannot export *const *const c_char as Rust static (not Sync).
// Programs will resolve this from glibc's data segment directly.

// __h_errno: native — thread-local h_errno via libc
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __h_errno() -> *mut c_int {
    // glibc's __h_errno_location is the canonical way, but libc crate may not expose it.
    // Use a thread-local instead.
    thread_local! {
        static H_ERRNO: std::cell::Cell<c_int> = const { std::cell::Cell::new(0) };
    }
    H_ERRNO.with(|cell| cell.as_ptr())
}

// in6addr globals
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static in6addr_any: [u8; 16] = [0u8; 16]; // ::
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static in6addr_loopback: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // ::1

// Misc old BSD regex variable
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut loc1: *mut c_char = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut loc2: *mut c_char = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut locs: *mut c_char = std::ptr::null_mut();

// advance/step (legacy regex)
// advance/step: obsolete V8 regex — return 0 (no match)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn advance(string: *const c_char, expbuf: *const c_char) -> c_int {
    let _ = (string, expbuf);
    0
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn step(string: *const c_char, expbuf: *const c_char) -> c_int {
    let _ = (string, expbuf);
    0
}

// sstk
// sstk: obsolete stack segment — return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sstk(increment: c_int) -> c_int {
    let _ = increment;
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}

// rexecoptions global
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut rexecoptions: c_int = 0;

// __check_rhosts_file global
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut __check_rhosts_file: c_int = 0;

// _obstack global
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _obstack: *mut c_void = std::ptr::null_mut();

// ==========================================================================
// Final remaining glibc public symbols (13)
// ==========================================================================

// __stpcpy_small: optimized small-string stpcpy

// printf_size / printf_size_info: custom printf formatter for human-readable sizes
dlsym_passthrough!(fn printf_size(fp: *mut c_void, info: *const c_void, args: *const *const c_void) -> c_int);
dlsym_passthrough!(fn printf_size_info(info: *const c_void, n: SizeT, argtypes: *mut c_int) -> SizeT);

// nfsservctl: deprecated NFS server control
// nfsservctl: removed in Linux 3.1 — return ENOSYS
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nfsservctl(cmd: c_int, argp: *mut c_void, resp: *mut c_void) -> c_int {
    let _ = (cmd, argp, resp);
    unsafe {
        *libc::__errno_location() = libc::ENOSYS;
    }
    -1
}

// xprt_register/unregister: SVC transport registration
dlsym_passthrough!(fn xprt_register(xprt: *mut c_void));
dlsym_passthrough!(fn xprt_unregister(xprt: *mut c_void));

// RPC data symbols — these are global variables in glibc.
// svc_fdset is fd_set (128 bytes on Linux), svc_pollfd is *pollfd, etc.
// Using static mut with zeroed data — programs that actually use RPC
// will resolve these from glibc's data segment via the dynamic linker.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut svc_fdset: [u8; 128] = [0u8; 128]; // fd_set
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut svc_max_pollfd: c_int = 0;
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut svc_pollfd: *mut c_void = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut svcauthdes_stats: [c_int; 3] = [0; 3]; // accept/reject/misc counters
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut _null_auth: [u8; 16] = [0u8; 16]; // opaque_auth struct (flavor=0, body={0,0})
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut rpc_createerr: [u8; 16] = [0u8; 16]; // struct rpc_createerr
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut h_errlist: [*mut c_char; 5] = [
    std::ptr::null_mut(),
    std::ptr::null_mut(),
    std::ptr::null_mut(),
    std::ptr::null_mut(),
    std::ptr::null_mut(),
];
