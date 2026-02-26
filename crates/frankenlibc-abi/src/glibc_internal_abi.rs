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
// __pthread_* internal aliases (42 symbols)
// ==========================================================================
dlsym_passthrough!(fn __pthread_cleanup_routine(arg: *mut c_void));
dlsym_passthrough!(fn __pthread_getspecific(key: c_uint) -> *mut c_void);
dlsym_passthrough!(fn __pthread_key_create(key: *mut c_uint, dtor: *mut c_void) -> c_int);
dlsym_passthrough!(fn __pthread_mutex_destroy(mutex: *mut c_void) -> c_int);
dlsym_passthrough!(fn __pthread_mutex_init(mutex: *mut c_void, attr: *const c_void) -> c_int);
dlsym_passthrough!(fn __pthread_mutex_lock(mutex: *mut c_void) -> c_int);
dlsym_passthrough!(fn __pthread_mutex_trylock(mutex: *mut c_void) -> c_int);
dlsym_passthrough!(fn __pthread_mutex_unlock(mutex: *mut c_void) -> c_int);
dlsym_passthrough!(fn __pthread_mutexattr_destroy(attr: *mut c_void) -> c_int);
dlsym_passthrough!(fn __pthread_mutexattr_init(attr: *mut c_void) -> c_int);
dlsym_passthrough!(fn __pthread_mutexattr_settype(attr: *mut c_void, kind: c_int) -> c_int);
dlsym_passthrough!(fn __pthread_once(control: *mut c_void, init_routine: *mut c_void) -> c_int);
dlsym_passthrough!(fn __pthread_register_cancel(buf: *mut c_void));
dlsym_passthrough!(fn __pthread_register_cancel_defer(buf: *mut c_void));
dlsym_passthrough!(fn __pthread_rwlock_destroy(rwlock: *mut c_void) -> c_int);
dlsym_passthrough!(fn __pthread_rwlock_init(rwlock: *mut c_void, attr: *const c_void) -> c_int);
dlsym_passthrough!(fn __pthread_rwlock_rdlock(rwlock: *mut c_void) -> c_int);
dlsym_passthrough!(fn __pthread_rwlock_tryrdlock(rwlock: *mut c_void) -> c_int);
dlsym_passthrough!(fn __pthread_rwlock_trywrlock(rwlock: *mut c_void) -> c_int);
dlsym_passthrough!(fn __pthread_rwlock_unlock(rwlock: *mut c_void) -> c_int);
dlsym_passthrough!(fn __pthread_rwlock_wrlock(rwlock: *mut c_void) -> c_int);
dlsym_passthrough!(fn __pthread_setspecific(key: c_uint, val: *const c_void) -> c_int);
dlsym_passthrough!(fn __pthread_unregister_cancel(buf: *mut c_void));
dlsym_passthrough!(fn __pthread_unregister_cancel_restore(buf: *mut c_void));
dlsym_passthrough!(fn __pthread_unwind_next(buf: *mut c_void));

// Pthread cleanup push/pop (4 symbols)
dlsym_passthrough!(fn _pthread_cleanup_push(buf: *mut c_void, routine: *mut c_void, arg: *mut c_void));
dlsym_passthrough!(fn _pthread_cleanup_pop(buf: *mut c_void, execute: c_int));
dlsym_passthrough!(fn _pthread_cleanup_push_defer(buf: *mut c_void, routine: *mut c_void, arg: *mut c_void));
dlsym_passthrough!(fn _pthread_cleanup_pop_restore(buf: *mut c_void, execute: c_int));

// Public pthread extras (12 symbols)
dlsym_passthrough!(fn pthread_kill_other_threads_np() -> c_int);
dlsym_passthrough!(fn pthread_mutex_consistent_np(mutex: *mut c_void) -> c_int);
dlsym_passthrough!(fn pthread_mutex_getprioceiling(mutex: *const c_void, prioceiling: *mut c_int) -> c_int);
dlsym_passthrough!(fn pthread_mutex_setprioceiling(mutex: *mut c_void, prioceiling: c_int, old: *mut c_int) -> c_int);
dlsym_passthrough!(fn pthread_mutexattr_getkind_np(attr: *const c_void, kind: *mut c_int) -> c_int);
dlsym_passthrough!(fn pthread_mutexattr_getprioceiling(attr: *const c_void, prioceiling: *mut c_int) -> c_int);
dlsym_passthrough!(fn pthread_mutexattr_getrobust_np(attr: *const c_void, robust: *mut c_int) -> c_int);
dlsym_passthrough!(fn pthread_mutexattr_setkind_np(attr: *mut c_void, kind: c_int) -> c_int);
dlsym_passthrough!(fn pthread_mutexattr_setprioceiling(attr: *mut c_void, prioceiling: c_int) -> c_int);
dlsym_passthrough!(fn pthread_mutexattr_setrobust_np(attr: *mut c_void, robust: c_int) -> c_int);
dlsym_passthrough!(fn pthread_rwlockattr_getkind_np(attr: *const c_void, kind: *mut c_int) -> c_int);
dlsym_passthrough!(fn pthread_rwlockattr_setkind_np(attr: *mut c_void, kind: c_int) -> c_int);
dlsym_passthrough!(fn pthread_setschedprio(thread: c_ulong, prio: c_int) -> c_int);

// ==========================================================================
// __sched_* internal aliases (6 symbols)
// ==========================================================================
dlsym_passthrough!(fn __sched_get_priority_max(policy: c_int) -> c_int);
dlsym_passthrough!(fn __sched_get_priority_min(policy: c_int) -> c_int);
dlsym_passthrough!(fn __sched_getparam(pid: c_int, param: *mut c_void) -> c_int);
dlsym_passthrough!(fn __sched_getscheduler(pid: c_int) -> c_int);
dlsym_passthrough!(fn __sched_setscheduler(pid: c_int, policy: c_int, param: *const c_void) -> c_int);
dlsym_passthrough!(fn __sched_yield() -> c_int);

// ==========================================================================
// __libc_* malloc aliases (15 symbols)
// ==========================================================================
dlsym_passthrough!(fn __libc_calloc(nmemb: SizeT, size: SizeT) -> *mut c_void);
dlsym_passthrough!(fn __libc_free(ptr: *mut c_void));
dlsym_passthrough!(fn __libc_malloc(size: SizeT) -> *mut c_void);
dlsym_passthrough!(fn __libc_mallopt(param: c_int, value: c_int) -> c_int);
dlsym_passthrough!(fn __libc_memalign(alignment: SizeT, size: SizeT) -> *mut c_void);
dlsym_passthrough!(fn __libc_pvalloc(size: SizeT) -> *mut c_void);
dlsym_passthrough!(fn __libc_realloc(ptr: *mut c_void, size: SizeT) -> *mut c_void);
dlsym_passthrough!(fn __libc_valloc(size: SizeT) -> *mut c_void);
dlsym_passthrough!(fn __libc_mallinfo() -> *mut c_void); // returns struct, but opaque for passthrough
dlsym_passthrough!(fn __libc_freeres());
dlsym_passthrough!(fn __libc_init_first(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char));
dlsym_passthrough!(fn __libc_allocate_rtsig(high: c_int) -> c_int);
dlsym_passthrough!(fn __libc_sa_len(af: u16) -> c_int);

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

// __ctype32_* (3 symbols)
dlsym_passthrough!(fn __ctype32_b() -> *const c_uint);
dlsym_passthrough!(fn __ctype32_tolower() -> *const c_int);
dlsym_passthrough!(fn __ctype32_toupper() -> *const c_int);

// ==========================================================================
// __is*_l / __tow*_l double-underscore ctype locale variants (30 symbols)
// ==========================================================================
dlsym_passthrough!(fn __isalnum_l(c: c_int, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __isalpha_l(c: c_int, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __isascii_l(c: c_int, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __isblank_l(c: c_int, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __iscntrl_l(c: c_int, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __isctype(c: c_int, mask: c_int) -> c_int);
dlsym_passthrough!(fn __isdigit_l(c: c_int, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __isgraph_l(c: c_int, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __islower_l(c: c_int, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __isprint_l(c: c_int, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __ispunct_l(c: c_int, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __isspace_l(c: c_int, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __isupper_l(c: c_int, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __isxdigit_l(c: c_int, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __toascii_l(c: c_int, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __tolower_l(c: c_int, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __toupper_l(c: c_int, loc: *mut c_void) -> c_int);

// Wide-char locale variants
dlsym_passthrough!(fn __iswalnum_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __iswalpha_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __iswblank_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __iswcntrl_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __iswctype(wc: WcharT, desc: c_ulong) -> c_int);
dlsym_passthrough!(fn __iswctype_l(wc: WcharT, desc: c_ulong, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __iswdigit_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __iswgraph_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __iswlower_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __iswprint_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __iswpunct_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __iswspace_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __iswupper_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __iswxdigit_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __towctrans(wc: WcharT, desc: c_ulong) -> WcharT);
dlsym_passthrough!(fn __towctrans_l(wc: WcharT, desc: c_ulong, loc: *mut c_void) -> WcharT);
dlsym_passthrough!(fn __towlower_l(wc: WcharT, loc: *mut c_void) -> WcharT);
dlsym_passthrough!(fn __towupper_l(wc: WcharT, loc: *mut c_void) -> WcharT);
dlsym_passthrough!(fn __wctrans_l(name: *const c_char, loc: *mut c_void) -> c_ulong);
dlsym_passthrough!(fn __wctype_l(name: *const c_char, loc: *mut c_void) -> c_ulong);

// Public wchar locale variants (missing from matrix)
dlsym_passthrough!(fn iswalnum_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn iswalpha_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn iswblank_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn iswcntrl_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn iswdigit_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn iswgraph_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn iswlower_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn iswprint_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn iswpunct_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn iswspace_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn iswupper_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn iswxdigit_l(wc: WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn towctrans_l(wc: WcharT, desc: c_ulong, loc: *mut c_void) -> WcharT);
dlsym_passthrough!(fn wctrans_l(name: *const c_char, loc: *mut c_void) -> c_ulong);
dlsym_passthrough!(fn wcscasecmp_l(s1: *const WcharT, s2: *const WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn wcsncasecmp_l(s1: *const WcharT, s2: *const WcharT, n: SizeT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn strcasecmp_l(s1: *const c_char, s2: *const c_char, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn strncasecmp_l(s1: *const c_char, s2: *const c_char, n: SizeT, loc: *mut c_void) -> c_int);

// ==========================================================================
// __str*_l / __wcs*_l locale string wrappers (20 symbols)
// ==========================================================================
dlsym_passthrough!(fn __strcasecmp(s1: *const c_char, s2: *const c_char) -> c_int);
dlsym_passthrough!(fn __strcasecmp_l(s1: *const c_char, s2: *const c_char, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __strcasestr(haystack: *const c_char, needle: *const c_char) -> *mut c_char);
dlsym_passthrough!(fn __strcoll_l(s1: *const c_char, s2: *const c_char, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __strncasecmp_l(s1: *const c_char, s2: *const c_char, n: SizeT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __strxfrm_l(dest: *mut c_char, src: *const c_char, n: SizeT, loc: *mut c_void) -> SizeT);
dlsym_passthrough!(fn __strftime_l(s: *mut c_char, max: SizeT, fmt: *const c_char, tm: *const c_void, loc: *mut c_void) -> SizeT);
dlsym_passthrough!(fn __strfmon_l(s: *mut c_char, maxsize: SizeT, loc: *mut c_void, fmt: *const c_char) -> SSizeT);
dlsym_passthrough!(fn __stpcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char);
dlsym_passthrough!(fn __stpncpy(dest: *mut c_char, src: *const c_char, n: SizeT) -> *mut c_char);
dlsym_passthrough!(fn __strdup(s: *const c_char) -> *mut c_char);
dlsym_passthrough!(fn __strndup(s: *const c_char, n: SizeT) -> *mut c_char);
dlsym_passthrough!(fn __strerror_r(errnum: c_int, buf: *mut c_char, buflen: SizeT) -> *mut c_char);
dlsym_passthrough!(fn __strtok_r(s: *mut c_char, delim: *const c_char, saveptr: *mut *mut c_char) -> *mut c_char);
dlsym_passthrough!(fn __strtok_r_1c(s: *mut c_char, delim: c_char, saveptr: *mut *mut c_char) -> *mut c_char);
dlsym_passthrough!(fn __strverscmp(s1: *const c_char, s2: *const c_char) -> c_int);
dlsym_passthrough!(fn __strcpy_small(dest: *mut c_char, src: c_ulong, src2: c_ulong) -> *mut c_char);
dlsym_passthrough!(fn __rawmemchr(s: *const c_void, c: c_int) -> *mut c_void);
dlsym_passthrough!(fn __mempcpy(dest: *mut c_void, src: *const c_void, n: SizeT) -> *mut c_void);
dlsym_passthrough!(fn __memcmpeq(s1: *const c_void, s2: *const c_void, n: SizeT) -> c_int);
dlsym_passthrough!(fn __bzero(s: *mut c_void, n: SizeT));
dlsym_passthrough!(fn __ffs(i: c_int) -> c_int);

// __strsep variants (4 symbols)
dlsym_passthrough!(fn __strsep_1c(sp: *mut *mut c_char, reject: c_char) -> *mut c_char);
dlsym_passthrough!(fn __strsep_2c(sp: *mut *mut c_char, r1: c_char, r2: c_char) -> *mut c_char);
dlsym_passthrough!(fn __strsep_3c(sp: *mut *mut c_char, r1: c_char, r2: c_char, r3: c_char) -> *mut c_char);
dlsym_passthrough!(fn __strsep_g(sp: *mut *mut c_char, delim: *const c_char) -> *mut c_char);

// __strpbrk / __strspn / __strcspn optimized variants (6 symbols)
dlsym_passthrough!(fn __strpbrk_c2(s: *const c_char, a1: c_int, a2: c_int) -> *mut c_char);
dlsym_passthrough!(fn __strpbrk_c3(s: *const c_char, a1: c_int, a2: c_int, a3: c_int) -> *mut c_char);
dlsym_passthrough!(fn __strspn_c1(s: *const c_char, a1: c_int) -> SizeT);
dlsym_passthrough!(fn __strspn_c2(s: *const c_char, a1: c_int, a2: c_int) -> SizeT);
dlsym_passthrough!(fn __strspn_c3(s: *const c_char, a1: c_int, a2: c_int, a3: c_int) -> SizeT);
dlsym_passthrough!(fn __strcspn_c1(s: *const c_char, a1: c_int) -> SizeT);
dlsym_passthrough!(fn __strcspn_c2(s: *const c_char, a1: c_int, a2: c_int) -> SizeT);
dlsym_passthrough!(fn __strcspn_c3(s: *const c_char, a1: c_int, a2: c_int, a3: c_int) -> SizeT);

// Wide string locale variants
dlsym_passthrough!(fn __wcscasecmp_l(s1: *const WcharT, s2: *const WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __wcscoll_l(s1: *const WcharT, s2: *const WcharT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __wcsncasecmp_l(s1: *const WcharT, s2: *const WcharT, n: SizeT, loc: *mut c_void) -> c_int);
dlsym_passthrough!(fn __wcsxfrm_l(dest: *mut WcharT, src: *const WcharT, n: SizeT, loc: *mut c_void) -> SizeT);
dlsym_passthrough!(fn __wcsftime_l(s: *mut WcharT, max: SizeT, fmt: *const WcharT, tm: *const c_void, loc: *mut c_void) -> SizeT);

// ==========================================================================
// __strtod_*/strtof* internal parse variants (14 symbols)
// ==========================================================================
dlsym_passthrough!(fn __strtod_internal(nptr: *const c_char, endptr: *mut *mut c_char, group: c_int) -> f64);
dlsym_passthrough!(fn __strtod_l(nptr: *const c_char, endptr: *mut *mut c_char, loc: *mut c_void) -> f64);
dlsym_passthrough!(fn __strtof_internal(nptr: *const c_char, endptr: *mut *mut c_char, group: c_int) -> f32);
dlsym_passthrough!(fn __strtof_l(nptr: *const c_char, endptr: *mut *mut c_char, loc: *mut c_void) -> f32);
dlsym_passthrough!(fn __strtold_internal(nptr: *const c_char, endptr: *mut *mut c_char, group: c_int) -> f64);
dlsym_passthrough!(fn __strtold_l(nptr: *const c_char, endptr: *mut *mut c_char, loc: *mut c_void) -> f64);
dlsym_passthrough!(fn __strtol_internal(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int, group: c_int) -> c_long);
dlsym_passthrough!(fn __strtol_l(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int, loc: *mut c_void) -> c_long);
dlsym_passthrough!(fn __strtoll_internal(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int, group: c_int) -> i64);
dlsym_passthrough!(fn __strtoll_l(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int, loc: *mut c_void) -> i64);
dlsym_passthrough!(fn __strtoul_internal(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int, group: c_int) -> c_ulong);
dlsym_passthrough!(fn __strtoul_l(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int, loc: *mut c_void) -> c_ulong);
dlsym_passthrough!(fn __strtoull_internal(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int, group: c_int) -> u64);
dlsym_passthrough!(fn __strtoull_l(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int, loc: *mut c_void) -> u64);
dlsym_passthrough!(fn __strtof128_internal(nptr: *const c_char, endptr: *mut *mut c_char, group: c_int) -> f64);

// Wide string to number internal variants
dlsym_passthrough!(fn __wcstod_internal(nptr: *const WcharT, endptr: *mut *mut WcharT, group: c_int) -> f64);
dlsym_passthrough!(fn __wcstod_l(nptr: *const WcharT, endptr: *mut *mut WcharT, loc: *mut c_void) -> f64);
dlsym_passthrough!(fn __wcstof_internal(nptr: *const WcharT, endptr: *mut *mut WcharT, group: c_int) -> f32);
dlsym_passthrough!(fn __wcstof_l(nptr: *const WcharT, endptr: *mut *mut WcharT, loc: *mut c_void) -> f32);
dlsym_passthrough!(fn __wcstold_internal(nptr: *const WcharT, endptr: *mut *mut WcharT, group: c_int) -> f64);
dlsym_passthrough!(fn __wcstold_l(nptr: *const WcharT, endptr: *mut *mut WcharT, loc: *mut c_void) -> f64);
dlsym_passthrough!(fn __wcstol_internal(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int, group: c_int) -> c_long);
dlsym_passthrough!(fn __wcstol_l(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int, loc: *mut c_void) -> c_long);
dlsym_passthrough!(fn __wcstoll_internal(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int, group: c_int) -> i64);
dlsym_passthrough!(fn __wcstoll_l(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int, loc: *mut c_void) -> i64);
dlsym_passthrough!(fn __wcstoul_internal(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int, group: c_int) -> c_ulong);
dlsym_passthrough!(fn __wcstoul_l(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int, loc: *mut c_void) -> c_ulong);
dlsym_passthrough!(fn __wcstoull_internal(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int, group: c_int) -> u64);
dlsym_passthrough!(fn __wcstoull_l(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int, loc: *mut c_void) -> u64);
dlsym_passthrough!(fn __wcstof128_internal(nptr: *const WcharT, endptr: *mut *mut WcharT, group: c_int) -> f64);

// ==========================================================================
// strfrom* / strtof* / wcstof* TS 18661 float variants (20 symbols)
// ==========================================================================
dlsym_passthrough!(fn strfromf32(str: *mut c_char, n: SizeT, fmt: *const c_char, fp: f32) -> c_int);
dlsym_passthrough!(fn strfromf32x(str: *mut c_char, n: SizeT, fmt: *const c_char, fp: f64) -> c_int);
dlsym_passthrough!(fn strfromf64(str: *mut c_char, n: SizeT, fmt: *const c_char, fp: f64) -> c_int);
dlsym_passthrough!(fn strfromf64x(str: *mut c_char, n: SizeT, fmt: *const c_char, fp: f64) -> c_int);
dlsym_passthrough!(fn strfromf128(str: *mut c_char, n: SizeT, fmt: *const c_char, fp: f64) -> c_int);

dlsym_passthrough!(fn strtof32(nptr: *const c_char, endptr: *mut *mut c_char) -> f32);
dlsym_passthrough!(fn strtof32_l(nptr: *const c_char, endptr: *mut *mut c_char, loc: *mut c_void) -> f32);
dlsym_passthrough!(fn strtof32x(nptr: *const c_char, endptr: *mut *mut c_char) -> f64);
dlsym_passthrough!(fn strtof32x_l(nptr: *const c_char, endptr: *mut *mut c_char, loc: *mut c_void) -> f64);
dlsym_passthrough!(fn strtof64(nptr: *const c_char, endptr: *mut *mut c_char) -> f64);
dlsym_passthrough!(fn strtof64_l(nptr: *const c_char, endptr: *mut *mut c_char, loc: *mut c_void) -> f64);
dlsym_passthrough!(fn strtof64x(nptr: *const c_char, endptr: *mut *mut c_char) -> f64);
dlsym_passthrough!(fn strtof64x_l(nptr: *const c_char, endptr: *mut *mut c_char, loc: *mut c_void) -> f64);
dlsym_passthrough!(fn strtof128(nptr: *const c_char, endptr: *mut *mut c_char) -> f64);
dlsym_passthrough!(fn strtof128_l(nptr: *const c_char, endptr: *mut *mut c_char, loc: *mut c_void) -> f64);

dlsym_passthrough!(fn wcstof32(nptr: *const WcharT, endptr: *mut *mut WcharT) -> f32);
dlsym_passthrough!(fn wcstof32_l(nptr: *const WcharT, endptr: *mut *mut WcharT, loc: *mut c_void) -> f32);
dlsym_passthrough!(fn wcstof32x(nptr: *const WcharT, endptr: *mut *mut WcharT) -> f64);
dlsym_passthrough!(fn wcstof32x_l(nptr: *const WcharT, endptr: *mut *mut WcharT, loc: *mut c_void) -> f64);
dlsym_passthrough!(fn wcstof64(nptr: *const WcharT, endptr: *mut *mut WcharT) -> f64);
dlsym_passthrough!(fn wcstof64_l(nptr: *const WcharT, endptr: *mut *mut WcharT, loc: *mut c_void) -> f64);
dlsym_passthrough!(fn wcstof64x(nptr: *const WcharT, endptr: *mut *mut WcharT) -> f64);
dlsym_passthrough!(fn wcstof64x_l(nptr: *const WcharT, endptr: *mut *mut WcharT, loc: *mut c_void) -> f64);
dlsym_passthrough!(fn wcstof128(nptr: *const WcharT, endptr: *mut *mut WcharT) -> f64);
dlsym_passthrough!(fn wcstof128_l(nptr: *const WcharT, endptr: *mut *mut WcharT, loc: *mut c_void) -> f64);

// Wide string extras
dlsym_passthrough!(fn wcstoq(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int) -> i64);
dlsym_passthrough!(fn wcstouq(nptr: *const WcharT, endptr: *mut *mut WcharT, base: c_int) -> u64);
dlsym_passthrough!(fn wcswcs(big: *const WcharT, little: *const WcharT) -> *mut WcharT);
dlsym_passthrough!(fn wmempcpy(dest: *mut WcharT, src: *const WcharT, n: SizeT) -> *mut WcharT);
dlsym_passthrough!(fn strptime_l(s: *const c_char, fmt: *const c_char, tm: *mut c_void, loc: *mut c_void) -> *mut c_char);

// ==========================================================================
// __res_* resolver internals (33 symbols)
// ==========================================================================
dlsym_passthrough!(fn __res_dnok(dn: *const c_char) -> c_int);
dlsym_passthrough!(fn __res_hnok(dn: *const c_char) -> c_int);
dlsym_passthrough!(fn __res_init() -> c_int);
dlsym_passthrough!(fn __res_mailok(dn: *const c_char) -> c_int);
dlsym_passthrough!(fn __res_mkquery(op: c_int, dname: *const c_char, class: c_int, typ: c_int, data: *const c_void, datalen: c_int, newrr: *const c_void, buf: *mut c_void, buflen: c_int) -> c_int);
dlsym_passthrough!(fn __res_nclose(statp: *mut c_void));
dlsym_passthrough!(fn __res_ninit(statp: *mut c_void) -> c_int);
dlsym_passthrough!(fn __res_nmkquery(statp: *mut c_void, op: c_int, dname: *const c_char, class: c_int, typ: c_int, data: *const c_void, datalen: c_int, newrr: *const c_void, buf: *mut c_void, buflen: c_int) -> c_int);
dlsym_passthrough!(fn __res_nquery(statp: *mut c_void, dname: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn __res_nquerydomain(statp: *mut c_void, name: *const c_char, domain: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn __res_nsearch(statp: *mut c_void, dname: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn __res_nsend(statp: *mut c_void, msg: *const c_void, msglen: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn __res_ownok(dn: *const c_char) -> c_int);
dlsym_passthrough!(fn __res_query(dname: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn __res_querydomain(name: *const c_char, domain: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn __res_randomid() -> c_int);
dlsym_passthrough!(fn __res_search(dname: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn __res_send(msg: *const c_void, msglen: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn __res_state() -> *mut c_void);

// Public res_* aliases
dlsym_passthrough!(fn res_dnok(dn: *const c_char) -> c_int);
dlsym_passthrough!(fn res_hnok(dn: *const c_char) -> c_int);
dlsym_passthrough!(fn res_mailok(dn: *const c_char) -> c_int);
dlsym_passthrough!(fn res_mkquery(op: c_int, dname: *const c_char, class: c_int, typ: c_int, data: *const c_void, datalen: c_int, newrr: *const c_void, buf: *mut c_void, buflen: c_int) -> c_int);
dlsym_passthrough!(fn res_nmkquery(statp: *mut c_void, op: c_int, dname: *const c_char, class: c_int, typ: c_int, data: *const c_void, datalen: c_int, newrr: *const c_void, buf: *mut c_void, buflen: c_int) -> c_int);
dlsym_passthrough!(fn res_nquery(statp: *mut c_void, dname: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn res_nquerydomain(statp: *mut c_void, name: *const c_char, domain: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn res_nsearch(statp: *mut c_void, dname: *const c_char, class: c_int, typ: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn res_nsend(statp: *mut c_void, msg: *const c_void, msglen: c_int, answer: *mut c_void, anslen: c_int) -> c_int);
dlsym_passthrough!(fn res_ownok(dn: *const c_char) -> c_int);
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
dlsym_passthrough!(fn __nl_langinfo_l(item: c_int, loc: *mut c_void) -> *mut c_char);
dlsym_passthrough!(fn __newlocale(mask: c_int, locale: *const c_char, base: *mut c_void) -> *mut c_void);
dlsym_passthrough!(fn __freelocale(loc: *mut c_void));
dlsym_passthrough!(fn __uselocale(loc: *mut c_void) -> *mut c_void);
dlsym_passthrough!(fn __duplocale(loc: *mut c_void) -> *mut c_void);
dlsym_passthrough!(fn __dcgettext(domainname: *const c_char, msgid: *const c_char, category: c_int) -> *mut c_char);
dlsym_passthrough!(fn __dgettext(domainname: *const c_char, msgid: *const c_char) -> *mut c_char);

// ==========================================================================
// ns_name_* DNS name manipulation (7 symbols)
// ==========================================================================
dlsym_passthrough!(fn ns_name_compress(src: *const c_char, dst: *mut c_void, dstlen: SizeT, dnptrs: *mut *const c_void, lastdnptr: *mut *const c_void) -> c_int);
dlsym_passthrough!(fn ns_name_ntop(src: *const c_void, dst: *mut c_char, dstsiz: SizeT) -> c_int);
dlsym_passthrough!(fn ns_name_pack(src: *const c_void, dst: *mut c_void, dstlen: c_int, dnptrs: *mut *const c_void, lastdnptr: *mut *const c_void) -> c_int);
dlsym_passthrough!(fn ns_name_pton(src: *const c_char, dst: *mut c_void, dstsiz: SizeT) -> c_int);
dlsym_passthrough!(fn ns_name_skip(ptrptr: *mut *const c_void, eom: *const c_void) -> c_int);
dlsym_passthrough!(fn ns_name_uncompress(msg: *const c_void, eom: *const c_void, src: *const c_void, dst: *mut c_char, dstsiz: SizeT) -> c_int);
dlsym_passthrough!(fn ns_name_unpack(msg: *const c_void, eom: *const c_void, src: *const c_void, dst: *mut c_void, dstsiz: SizeT) -> c_int);

// __dn_* DNS name aliases
dlsym_passthrough!(fn __dn_comp(exp_dn: *const c_char, comp_dn: *mut c_void, length: c_int, dnptrs: *mut *mut c_void, lastdnptr: *mut *mut c_void) -> c_int);
dlsym_passthrough!(fn __dn_expand(msg: *const c_void, eomorig: *const c_void, comp_dn: *const c_void, exp_dn: *mut c_char, length: c_int) -> c_int);
dlsym_passthrough!(fn __dn_skipname(comp_dn: *const c_void, eom: *const c_void) -> c_int);

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
dlsym_passthrough!(fn inet6_opt_append(extbuf: *mut c_void, extlen: c_int, offset: c_int, typ: u8, len: SizeT, align: u8, databufp: *mut *mut c_void) -> c_int);
dlsym_passthrough!(fn inet6_opt_find(extbuf: *mut c_void, extlen: c_int, offset: c_int, typ: u8, lenp: *mut SizeT, databufp: *mut *mut c_void) -> c_int);
dlsym_passthrough!(fn inet6_opt_finish(extbuf: *mut c_void, extlen: c_int, offset: c_int) -> c_int);
dlsym_passthrough!(fn inet6_opt_get_val(databuf: *mut c_void, offset: c_int, val: *mut c_void, vallen: c_int) -> c_int);
dlsym_passthrough!(fn inet6_opt_init(extbuf: *mut c_void, extlen: c_int) -> c_int);
dlsym_passthrough!(fn inet6_opt_next(extbuf: *mut c_void, extlen: c_int, offset: c_int, typep: *mut u8, lenp: *mut SizeT, databufp: *mut *mut c_void) -> c_int);
dlsym_passthrough!(fn inet6_opt_set_val(databuf: *mut c_void, offset: c_int, val: *const c_void, vallen: c_int) -> c_int);
dlsym_passthrough!(fn inet6_option_alloc(cmsg: *mut c_void, datalen: c_int, multx: c_int, plusy: c_int) -> *mut u8);
dlsym_passthrough!(fn inet6_option_append(cmsg: *mut c_void, typep: *const u8, multx: c_int, plusy: c_int) -> c_int);
dlsym_passthrough!(fn inet6_option_find(cmsg: *const c_void, tptrp: *mut *mut u8, typ: c_int) -> c_int);
dlsym_passthrough!(fn inet6_option_init(cmsg: *mut c_void, cmsglenp: *mut c_int, typ: c_int) -> c_int);
dlsym_passthrough!(fn inet6_option_next(cmsg: *const c_void, tptrp: *mut *mut u8) -> c_int);
dlsym_passthrough!(fn inet6_option_space(datalen: c_int) -> c_int);
dlsym_passthrough!(fn inet6_rth_add(bp: *mut c_void, addr: *const c_void) -> c_int);
dlsym_passthrough!(fn inet6_rth_getaddr(bp: *const c_void, index: c_int) -> *const c_void);
dlsym_passthrough!(fn inet6_rth_init(bp: *mut c_void, bp_len: c_int, typ: c_int, segments: c_int) -> *mut c_void);
dlsym_passthrough!(fn inet6_rth_reverse(inp: *const c_void, outp: *mut c_void) -> c_int);
dlsym_passthrough!(fn inet6_rth_segments(bp: *const c_void) -> c_int);
dlsym_passthrough!(fn inet6_rth_space(typ: c_int, segments: c_int) -> c_int);

// inet legacy (8 symbols)
dlsym_passthrough!(fn inet_lnaof(inp: c_uint) -> c_uint);
dlsym_passthrough!(fn inet_makeaddr(net: c_uint, host: c_uint) -> c_uint);
dlsym_passthrough!(fn inet_netof(inp: c_uint) -> c_uint);
dlsym_passthrough!(fn inet_network(cp: *const c_char) -> c_uint);
dlsym_passthrough!(fn inet_nsap_addr(cp: *const c_char, buf: *mut c_void, buflen: c_int) -> c_uint);
dlsym_passthrough!(fn inet_nsap_ntoa(len: c_int, cp: *const c_void, buf: *mut c_char) -> *mut c_char);
dlsym_passthrough!(fn __inet_ntop_chk(af: c_int, src: *const c_void, dst: *mut c_char, size: c_uint, dstsize: c_uint) -> *const c_char);
dlsym_passthrough!(fn __inet_pton_chk(af: c_int, src: *const c_char, dst: *mut c_void, dstsize: c_uint) -> c_int);

// ==========================================================================
// Misc POSIX/glibc syscall wrappers (aliases for functions we export)
// ==========================================================================
dlsym_passthrough!(fn __adjtimex(buf: *mut c_void) -> c_int);
dlsym_passthrough!(fn __arch_prctl(code: c_int, addr: c_ulong) -> c_int);
dlsym_passthrough!(fn __asprintf(strp: *mut *mut c_char, fmt: *const c_char) -> c_int);
dlsym_passthrough!(fn __assert(assertion: *const c_char, file: *const c_char, line: c_int));
dlsym_passthrough!(fn __assert_fail(assertion: *const c_char, file: *const c_char, line: c_uint, function: *const c_char));
dlsym_passthrough!(fn __assert_perror_fail(errnum: c_int, file: *const c_char, line: c_uint, function: *const c_char));
dlsym_passthrough!(fn __backtrace(buffer: *mut *mut c_void, size: c_int) -> c_int);
dlsym_passthrough!(fn __backtrace_symbols(buffer: *const *mut c_void, size: c_int) -> *mut *mut c_char);
dlsym_passthrough!(fn __backtrace_symbols_fd(buffer: *const *mut c_void, size: c_int, fd: c_int));
dlsym_passthrough!(fn __bsd_getpgrp(pid: c_int) -> c_int);
// __check_rhosts_file is a global variable, defined below as a static
dlsym_passthrough!(fn __clone(fn_: *mut c_void, stack: *mut c_void, flags: c_int, arg: *mut c_void) -> c_int);
dlsym_passthrough!(fn __close(fd: c_int) -> c_int);
dlsym_passthrough!(fn __cmsg_nxthdr(mhdr: *mut c_void, cmsg: *mut c_void) -> *mut c_void);
dlsym_passthrough!(fn __connect(sockfd: c_int, addr: *const c_void, addrlen: c_uint) -> c_int);
dlsym_passthrough!(fn __cxa_at_quick_exit(func: *mut c_void, dso_handle: *mut c_void) -> c_int);
dlsym_passthrough!(fn __cyg_profile_func_enter(this_fn: *mut c_void, call_site: *mut c_void));
dlsym_passthrough!(fn __cyg_profile_func_exit(this_fn: *mut c_void, call_site: *mut c_void));
dlsym_passthrough!(fn __dup2(oldfd: c_int, newfd: c_int) -> c_int);
dlsym_passthrough!(fn __endmntent(fp: *mut c_void) -> c_int);
dlsym_passthrough!(fn __fbufsize(fp: *mut c_void) -> SizeT);
dlsym_passthrough!(fn __fcntl(fd: c_int, cmd: c_int) -> c_int);
dlsym_passthrough!(fn __fdelt_warn(d: c_long) -> c_long);
dlsym_passthrough!(fn __flbf(fp: *mut c_void) -> c_int);
dlsym_passthrough!(fn __fork() -> c_int);
dlsym_passthrough!(fn __fpending(fp: *mut c_void) -> SizeT);
dlsym_passthrough!(fn __fpurge(fp: *mut c_void));
dlsym_passthrough!(fn __freadable(fp: *mut c_void) -> c_int);
dlsym_passthrough!(fn __freading(fp: *mut c_void) -> c_int);
dlsym_passthrough!(fn __fsetlocking(fp: *mut c_void, typ: c_int) -> c_int);
dlsym_passthrough!(fn __fwritable(fp: *mut c_void) -> c_int);
dlsym_passthrough!(fn __fwriting(fp: *mut c_void) -> c_int);
dlsym_passthrough!(fn __getauxval(typ: c_ulong) -> c_ulong);
dlsym_passthrough!(fn __getdelim(lineptr: *mut *mut c_char, n: *mut SizeT, delim: c_int, stream: *mut c_void) -> SSizeT);
dlsym_passthrough!(fn __getmntent_r(fp: *mut c_void, mntbuf: *mut c_void, buf: *mut c_char, buflen: c_int) -> *mut c_void);
dlsym_passthrough!(fn __getpagesize() -> c_int);
dlsym_passthrough!(fn __getpgid(pid: c_int) -> c_int);
dlsym_passthrough!(fn __getpid() -> c_int);
dlsym_passthrough!(fn __gettimeofday(tv: *mut c_void, tz: *mut c_void) -> c_int);
dlsym_passthrough!(fn __gmtime_r(timep: *const c_long, result: *mut c_void) -> *mut c_void);
dlsym_passthrough!(fn __ivaliduser(hostf: *mut c_void, raddr: c_uint, luser: *const c_char, ruser: *const c_char) -> c_int);
dlsym_passthrough!(fn __lseek(fd: c_int, offset: i64, whence: c_int) -> i64);
dlsym_passthrough!(fn __mbrlen(s: *const c_char, n: SizeT, ps: *mut c_void) -> SizeT);
dlsym_passthrough!(fn __mbrtowc(pwc: *mut WcharT, s: *const c_char, n: SizeT, ps: *mut c_void) -> SizeT);
dlsym_passthrough!(fn __monstartup(lowpc: c_ulong, highpc: c_ulong));
dlsym_passthrough!(fn __nanosleep(rqtp: *const c_void, rmtp: *mut c_void) -> c_int);
dlsym_passthrough!(fn __open(pathname: *const c_char, flags: c_int) -> c_int);
dlsym_passthrough!(fn __open64(pathname: *const c_char, flags: c_int) -> c_int);
dlsym_passthrough!(fn __overflow(fp: *mut c_void, c: c_int) -> c_int);
dlsym_passthrough!(fn __pipe(pipefd: *mut c_int) -> c_int);
dlsym_passthrough!(fn __poll(fds: *mut c_void, nfds: c_ulong, timeout: c_int) -> c_int);
dlsym_passthrough!(fn __posix_getopt(argc: c_int, argv: *const *mut c_char, optstring: *const c_char) -> c_int);
dlsym_passthrough!(fn __pread64(fd: c_int, buf: *mut c_void, count: SizeT, offset: i64) -> SSizeT);
dlsym_passthrough!(fn __printf_fp(fp: *mut c_void, info: *const c_void, args: *const *const c_void) -> c_int);
dlsym_passthrough!(fn __profile_frequency() -> c_int);
dlsym_passthrough!(fn __pwrite64(fd: c_int, buf: *const c_void, count: SizeT, offset: i64) -> SSizeT);
dlsym_passthrough!(fn __rcmd_errstr() -> *mut *mut c_char);
dlsym_passthrough!(fn __read(fd: c_int, buf: *mut c_void, count: SizeT) -> SSizeT);
dlsym_passthrough!(fn __register_atfork(prepare: *mut c_void, parent: *mut c_void, child: *mut c_void, dso_handle: *mut c_void) -> c_int);
dlsym_passthrough!(fn __sbrk(increment: isize) -> *mut c_void);
dlsym_passthrough!(fn __secure_getenv(name: *const c_char) -> *mut c_char);
dlsym_passthrough!(fn __select(nfds: c_int, readfds: *mut c_void, writefds: *mut c_void, exceptfds: *mut c_void, timeout: *mut c_void) -> c_int);
dlsym_passthrough!(fn __send(sockfd: c_int, buf: *const c_void, len: SizeT, flags: c_int) -> SSizeT);
dlsym_passthrough!(fn __setmntent(filename: *const c_char, typ: *const c_char) -> *mut c_void);
dlsym_passthrough!(fn __setpgid(pid: c_int, pgid: c_int) -> c_int);
dlsym_passthrough!(fn __sigaction(signum: c_int, act: *const c_void, oldact: *mut c_void) -> c_int);
dlsym_passthrough!(fn __sigaddset(set: *mut c_void, signum: c_int) -> c_int);
dlsym_passthrough!(fn __sigdelset(set: *mut c_void, signum: c_int) -> c_int);
dlsym_passthrough!(fn __sigismember(set: *const c_void, signum: c_int) -> c_int);
dlsym_passthrough!(fn __sigpause(sig_or_mask: c_int) -> c_int);
dlsym_passthrough!(fn __sigsetjmp(env: *mut c_void, savesigs: c_int) -> c_int);
dlsym_passthrough!(fn __sigsuspend(set: *const c_void) -> c_int);
dlsym_passthrough!(fn __statfs(path: *const c_char, buf: *mut c_void) -> c_int);
dlsym_passthrough!(fn __sysconf(name: c_int) -> c_long);
dlsym_passthrough!(fn __sysctl(args: *mut c_void) -> c_int);
dlsym_passthrough!(fn __sysv_signal(signum: c_int, handler: *mut c_void) -> *mut c_void);
dlsym_passthrough!(fn __vfork() -> c_int);
dlsym_passthrough!(fn __vfscanf(stream: *mut c_void, fmt: *const c_char, ap: *mut c_void) -> c_int);
dlsym_passthrough!(fn __vsnprintf(str: *mut c_char, size: SizeT, fmt: *const c_char, ap: *mut c_void) -> c_int);
dlsym_passthrough!(fn __vsscanf(str: *const c_char, fmt: *const c_char, ap: *mut c_void) -> c_int);
dlsym_passthrough!(fn __wait(status: *mut c_int) -> c_int);
dlsym_passthrough!(fn __waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int);
dlsym_passthrough!(fn __write(fd: c_int, buf: *const c_void, count: SizeT) -> SSizeT);
dlsym_passthrough!(fn __xmknod(ver: c_int, pathname: *const c_char, mode: c_uint, dev: *mut c_void) -> c_int);
dlsym_passthrough!(fn __xmknodat(ver: c_int, dirfd: c_int, pathname: *const c_char, mode: c_uint, dev: *mut c_void) -> c_int);
dlsym_passthrough!(fn __xpg_sigpause(sig: c_int) -> c_int);
dlsym_passthrough!(fn __signbitl(x: f64) -> c_int);
dlsym_passthrough!(fn __isinfl(x: f64) -> c_int);
dlsym_passthrough!(fn __isnanl(x: f64) -> c_int);
dlsym_passthrough!(fn __finitel(x: f64) -> c_int);
dlsym_passthrough!(fn __isnanf128(x: f64) -> c_int);

// ==========================================================================
// __fortify_chk extras not covered by fortify_abi.rs (8 symbols)
// ==========================================================================
dlsym_passthrough!(fn __mempcpy_chk(dest: *mut c_void, src: *const c_void, n: SizeT, destlen: SizeT) -> *mut c_void);
dlsym_passthrough!(fn __mempcpy_small(dest: *mut c_void, src: c_ulong, src2: c_ulong) -> *mut c_void);
dlsym_passthrough!(fn __strlcat_chk(dest: *mut c_char, src: *const c_char, size: SizeT, destlen: SizeT) -> SizeT);
dlsym_passthrough!(fn __strlcpy_chk(dest: *mut c_char, src: *const c_char, size: SizeT, destlen: SizeT) -> SizeT);
dlsym_passthrough!(fn __wcpcpy_chk(dest: *mut WcharT, src: *const WcharT, destlen: SizeT) -> *mut WcharT);
dlsym_passthrough!(fn __wcpncpy_chk(dest: *mut WcharT, src: *const WcharT, n: SizeT, destlen: SizeT) -> *mut WcharT);
dlsym_passthrough!(fn __wcrtomb_chk(s: *mut c_char, wc: WcharT, ps: *mut c_void, buflen: SizeT) -> SizeT);
dlsym_passthrough!(fn __wcslcat_chk(dest: *mut WcharT, src: *const WcharT, size: SizeT, destlen: SizeT) -> SizeT);
dlsym_passthrough!(fn __wcslcpy_chk(dest: *mut WcharT, src: *const WcharT, size: SizeT, destlen: SizeT) -> SizeT);
dlsym_passthrough!(fn __wmempcpy_chk(dest: *mut WcharT, src: *const WcharT, n: SizeT, destlen: SizeT) -> *mut WcharT);
dlsym_passthrough!(fn __read_chk(fd: c_int, buf: *mut c_void, nbytes: SizeT, buflen: SizeT) -> SSizeT);
dlsym_passthrough!(fn __readlink_chk(path: *const c_char, buf: *mut c_char, len: SizeT, buflen: SizeT) -> SSizeT);
dlsym_passthrough!(fn __readlinkat_chk(dirfd: c_int, path: *const c_char, buf: *mut c_char, len: SizeT, buflen: SizeT) -> SSizeT);
dlsym_passthrough!(fn __syslog_chk(priority: c_int, flag: c_int, fmt: *const c_char));
dlsym_passthrough!(fn __mq_open_2(name: *const c_char, oflag: c_int) -> c_int);

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

// Pointers to string tables — let glibc's copy be used via RTLD_NEXT
dlsym_passthrough!(fn sys_sigabbrev() -> *const *const c_char);

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
dlsym_passthrough!(fn _dl_mcount_wrapper(selfpc: c_ulong));
dlsym_passthrough!(fn _dl_mcount_wrapper_check(selfpc: c_ulong));
dlsym_passthrough!(fn _flushlbf());

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
dlsym_passthrough!(fn _tolower(c: c_int) -> c_int);
dlsym_passthrough!(fn _toupper(c: c_int) -> c_int);
dlsym_passthrough!(fn __x86_get_cpuid_feature_leaf(leaf: c_uint, info: *mut c_void) -> c_int);
dlsym_passthrough!(fn __fentry__());
dlsym_passthrough!(fn __uflow(fp: *mut c_void) -> c_int);
dlsym_passthrough!(fn __underflow(fp: *mut c_void) -> c_int);
dlsym_passthrough!(fn __woverflow(fp: *mut c_void, wc: WcharT) -> WcharT);
dlsym_passthrough!(fn __wuflow(fp: *mut c_void) -> WcharT);
dlsym_passthrough!(fn __wunderflow(fp: *mut c_void) -> WcharT);

// Profiling
dlsym_passthrough!(fn _mcleanup());
dlsym_passthrough!(fn _mcount());
dlsym_passthrough!(fn mcount());
dlsym_passthrough!(fn moncontrol(mode: c_int));
dlsym_passthrough!(fn monstartup(lowpc: c_ulong, highpc: c_ulong));
dlsym_passthrough!(fn profil(buf: *mut c_void, bufsiz: SizeT, offset: SizeT, scale: c_uint) -> c_int);
dlsym_passthrough!(fn sprofil(profp: *mut c_void, profcnt: c_int, tvp: *mut c_void, flags: c_uint) -> c_int);

// Misc POSIX functions
dlsym_passthrough!(fn adjtime(delta: *const c_void, olddelta: *mut c_void) -> c_int);
dlsym_passthrough!(fn arch_prctl(code: c_int, addr: c_ulong) -> c_int);
dlsym_passthrough!(fn bdflush(func: c_int, data: c_long) -> c_int);
dlsym_passthrough!(fn bindresvport(sockfd: c_int, sin: *mut c_void) -> c_int);
dlsym_passthrough!(fn cfgetibaud(termios_p: *const c_void) -> c_uint);
dlsym_passthrough!(fn cfgetobaud(termios_p: *const c_void) -> c_uint);
dlsym_passthrough!(fn cfsetbaud(termios_p: *mut c_void, ibaud: c_uint, obaud: c_uint) -> c_int);
dlsym_passthrough!(fn cfsetibaud(termios_p: *mut c_void, speed: c_uint) -> c_int);
dlsym_passthrough!(fn cfsetobaud(termios_p: *mut c_void, speed: c_uint) -> c_int);
dlsym_passthrough!(fn chflags(path: *const c_char, flags: c_ulong) -> c_int);
dlsym_passthrough!(fn copysignl(x: f64, y: f64) -> f64);
dlsym_passthrough!(fn create_module(name: *const c_char, size: SizeT) -> c_long);
dlsym_passthrough!(fn delete_module(name: *const c_char, flags: c_uint) -> c_int);
dlsym_passthrough!(fn dladdr1(addr: *const c_void, info: *mut c_void, extra_info: *mut *mut c_void, flags: c_int) -> c_int);
dlsym_passthrough!(fn dlinfo(handle: *mut c_void, request: c_int, info: *mut c_void) -> c_int);
dlsym_passthrough!(fn dlmopen(lmid: c_long, filename: *const c_char, flags: c_int) -> *mut c_void);
dlsym_passthrough!(fn dlvsym(handle: *mut c_void, symbol: *const c_char, version: *const c_char) -> *mut c_void);
dlsym_passthrough!(fn dysize(year: c_int) -> c_int);
dlsym_passthrough!(fn fattach(fd: c_int, path: *const c_char) -> c_int);
dlsym_passthrough!(fn fchflags(fd: c_int, flags: c_ulong) -> c_int);
dlsym_passthrough!(fn fdetach(path: *const c_char) -> c_int);
dlsym_passthrough!(fn frexpl(x: f64, exp: *mut c_int) -> f64);
dlsym_passthrough!(fn ftime(tp: *mut c_void) -> c_int);
dlsym_passthrough!(fn futimes(fd: c_int, tv: *const c_void) -> c_int);
dlsym_passthrough!(fn futimesat(dirfd: c_int, pathname: *const c_char, tv: *const c_void) -> c_int);
dlsym_passthrough!(fn fwide(stream: *mut c_void, mode: c_int) -> c_int);
dlsym_passthrough!(fn get_kernel_syms(table: *mut c_void) -> c_int);
dlsym_passthrough!(fn getdirentries(fd: c_int, buf: *mut c_char, nbytes: SizeT, basep: *mut c_long) -> SSizeT);
dlsym_passthrough!(fn getdirentries64(fd: c_int, buf: *mut c_char, nbytes: SizeT, basep: *mut i64) -> SSizeT);
dlsym_passthrough!(fn getipv4sourcefilter(s: c_int, interface_: c_uint, group: c_uint, fmode: *mut c_uint, numsrc: *mut c_uint, slist: *mut c_void) -> c_int);
dlsym_passthrough!(fn getmsg(fd: c_int, ctlptr: *mut c_void, dataptr: *mut c_void, flags: *mut c_int) -> c_int);
dlsym_passthrough!(fn getpmsg(fd: c_int, ctlptr: *mut c_void, dataptr: *mut c_void, bandp: *mut c_int, flags: *mut c_int) -> c_int);
dlsym_passthrough!(fn getpw(uid: c_uint, buf: *mut c_char) -> c_int);
dlsym_passthrough!(fn gettid() -> c_int);
dlsym_passthrough!(fn getwd(buf: *mut c_char) -> *mut c_char);
dlsym_passthrough!(fn group_member(gid: c_uint) -> c_int);
dlsym_passthrough!(fn gtty(fd: c_int, params: *mut c_void) -> c_int);
dlsym_passthrough!(fn init_module(module_image: *mut c_void, len: c_ulong, param_values: *const c_char) -> c_int);
dlsym_passthrough!(fn innetgr(netgroup: *const c_char, host: *const c_char, user: *const c_char, domain: *const c_char) -> c_int);
dlsym_passthrough!(fn ioperm(from: c_ulong, num: c_ulong, turn_on: c_int) -> c_int);
dlsym_passthrough!(fn iopl(level: c_int) -> c_int);
dlsym_passthrough!(fn iruserok(raddr: c_uint, superuser: c_int, ruser: *const c_char, luser: *const c_char) -> c_int);
dlsym_passthrough!(fn iruserok_af(raddr: *const c_void, superuser: c_int, ruser: *const c_char, luser: *const c_char, af: c_int) -> c_int);
dlsym_passthrough!(fn isastream(fd: c_int) -> c_int);
dlsym_passthrough!(fn isctype(c: c_int, mask: c_int) -> c_int);
dlsym_passthrough!(fn isfdtype(fd: c_int, fdtype: c_int) -> c_int);
dlsym_passthrough!(fn isinff(x: f32) -> c_int);
dlsym_passthrough!(fn isinfl(x: f64) -> c_int);
dlsym_passthrough!(fn isnanf(x: f32) -> c_int);
dlsym_passthrough!(fn isnanl(x: f64) -> c_int);
dlsym_passthrough!(fn finitel(x: f64) -> c_int);
dlsym_passthrough!(fn klogctl(typ: c_int, bufp: *mut c_char, len: c_int) -> c_int);
dlsym_passthrough!(fn lchmod(pathname: *const c_char, mode: c_uint) -> c_int);
dlsym_passthrough!(fn ldexpl(x: f64, exp: c_int) -> f64);
dlsym_passthrough!(fn llseek(fd: c_int, offset: i64, whence: c_int) -> i64);
dlsym_passthrough!(fn lutimes(filename: *const c_char, tv: *const c_void) -> c_int);
dlsym_passthrough!(fn mkostemp64(template: *mut c_char, flags: c_int) -> c_int);
dlsym_passthrough!(fn mkostemps64(template: *mut c_char, suffixlen: c_int, flags: c_int) -> c_int);
dlsym_passthrough!(fn mkstemp64(template: *mut c_char) -> c_int);
dlsym_passthrough!(fn mkstemps64(template: *mut c_char, suffixlen: c_int) -> c_int);
dlsym_passthrough!(fn modfl(x: f64, iptr: *mut f64) -> f64);
dlsym_passthrough!(fn modify_ldt(func: c_int, ptr: *mut c_void, bytecount: c_ulong) -> c_int);
dlsym_passthrough!(fn parse_printf_format(fmt: *const c_char, n: SizeT, argtypes: *mut c_int) -> SizeT);
dlsym_passthrough!(fn pidfd_getpid(pidfd: c_int) -> c_int);
dlsym_passthrough!(fn pidfd_spawn(pidfd: *mut c_int, path: *const c_char, file_actions: *const c_void, attrp: *const c_void, argv: *const *mut c_char, envp: *const *mut c_char) -> c_int);
dlsym_passthrough!(fn pidfd_spawnp(pidfd: *mut c_int, file: *const c_char, file_actions: *const c_void, attrp: *const c_void, argv: *const *mut c_char, envp: *const *mut c_char) -> c_int);
dlsym_passthrough!(fn preadv64v2(fd: c_int, iov: *const c_void, iovcnt: c_int, offset: i64, flags: c_int) -> SSizeT);
dlsym_passthrough!(fn putgrent(grp: *const c_void, fp: *mut c_void) -> c_int);
dlsym_passthrough!(fn putmsg(fd: c_int, ctlptr: *const c_void, dataptr: *const c_void, flags: c_int) -> c_int);
dlsym_passthrough!(fn putpmsg(fd: c_int, ctlptr: *const c_void, dataptr: *const c_void, band: c_int, flags: c_int) -> c_int);
dlsym_passthrough!(fn putpwent(pw: *const c_void, fp: *mut c_void) -> c_int);
dlsym_passthrough!(fn pwritev64v2(fd: c_int, iov: *const c_void, iovcnt: c_int, offset: i64, flags: c_int) -> SSizeT);
dlsym_passthrough!(fn query_module(name: *const c_char, which: c_int, buf: *mut c_void, bufsize: SizeT, ret: *mut SizeT) -> c_int);
dlsym_passthrough!(fn rcmd(ahost: *mut *mut c_char, rport: c_int, locuser: *const c_char, remuser: *const c_char, cmd: *const c_char, fd2p: *mut c_int) -> c_int);
dlsym_passthrough!(fn rcmd_af(ahost: *mut *mut c_char, rport: c_int, locuser: *const c_char, remuser: *const c_char, cmd: *const c_char, fd2p: *mut c_int, af: c_int) -> c_int);
dlsym_passthrough!(fn register_printf_function(spec: c_int, render: *mut c_void, arginfo: *mut c_void) -> c_int);
dlsym_passthrough!(fn register_printf_modifier(str: *const WcharT) -> c_int);
dlsym_passthrough!(fn register_printf_specifier(spec: c_int, render: *mut c_void, arginfo: *mut c_void) -> c_int);
dlsym_passthrough!(fn register_printf_type(fct: *mut c_void) -> c_int);
dlsym_passthrough!(fn revoke(file: *const c_char) -> c_int);
dlsym_passthrough!(fn rexec(ahost: *mut *mut c_char, rport: c_int, user: *const c_char, passwd: *const c_char, cmd: *const c_char, fd2p: *mut c_int) -> c_int);
dlsym_passthrough!(fn rexec_af(ahost: *mut *mut c_char, rport: c_int, user: *const c_char, passwd: *const c_char, cmd: *const c_char, fd2p: *mut c_int, af: c_int) -> c_int);
dlsym_passthrough!(fn rpmatch(response: *const c_char) -> c_int);
dlsym_passthrough!(fn rresvport(port: *mut c_int) -> c_int);
dlsym_passthrough!(fn rresvport_af(port: *mut c_int, af: c_int) -> c_int);
dlsym_passthrough!(fn ruserok(rhost: *const c_char, superuser: c_int, ruser: *const c_char, luser: *const c_char) -> c_int);
dlsym_passthrough!(fn ruserok_af(rhost: *const c_char, superuser: c_int, ruser: *const c_char, luser: *const c_char, af: c_int) -> c_int);
dlsym_passthrough!(fn ruserpass(host: *const c_char, aname: *mut *const c_char, apass: *mut *const c_char) -> c_int);
dlsym_passthrough!(fn scalbnl(x: f64, n: c_int) -> f64);
dlsym_passthrough!(fn scandirat(dirfd: c_int, dirp: *const c_char, namelist: *mut *mut *mut c_void, filter: *mut c_void, compar: *mut c_void) -> c_int);
dlsym_passthrough!(fn scandirat64(dirfd: c_int, dirp: *const c_char, namelist: *mut *mut *mut c_void, filter: *mut c_void, compar: *mut c_void) -> c_int);
dlsym_passthrough!(fn sem_clockwait(sem: *mut c_void, clockid: c_int, abstime: *const c_void) -> c_int);
dlsym_passthrough!(fn setaliasent());
dlsym_passthrough!(fn setfsgid(fsgid: c_uint) -> c_int);
dlsym_passthrough!(fn setfsuid(fsuid: c_uint) -> c_int);
dlsym_passthrough!(fn sethostid(hostid: c_long) -> c_int);
dlsym_passthrough!(fn setipv4sourcefilter(s: c_int, interface_: c_uint, group: c_uint, fmode: c_uint, numsrc: c_uint, slist: *const c_void) -> c_int);
dlsym_passthrough!(fn setlogin(name: *const c_char) -> c_int);
dlsym_passthrough!(fn setsourcefilter(s: c_int, interface_: c_uint, group: *const c_void, grouplen: c_uint, fmode: c_uint, numsrc: c_uint, slist: *const c_void) -> c_int);
dlsym_passthrough!(fn getsourcefilter(s: c_int, interface_: c_uint, group: *const c_void, grouplen: c_uint, fmode: *mut c_uint, numsrc: *mut c_uint, slist: *mut c_void) -> c_int);
dlsym_passthrough!(fn settimeofday(tv: *const c_void, tz: *const c_void) -> c_int);
dlsym_passthrough!(fn sgetspent(s: *const c_char) -> *mut c_void);
dlsym_passthrough!(fn sgetspent_r(s: *const c_char, spbuf: *mut c_void, buf: *mut c_char, buflen: SizeT, spbufp: *mut *mut c_void) -> c_int);
dlsym_passthrough!(fn stime(t: *const c_long) -> c_int);
dlsym_passthrough!(fn stty(fd: c_int, params: *const c_void) -> c_int);
dlsym_passthrough!(fn sysctl(args: *mut c_int, nlen: c_int, oldval: *mut c_void, oldlenp: *mut SizeT, newval: *mut c_void, newlen: SizeT) -> c_int);
dlsym_passthrough!(fn times(buf: *mut c_void) -> c_long);
dlsym_passthrough!(fn tr_break());
dlsym_passthrough!(fn ttyslot() -> c_int);
dlsym_passthrough!(fn uabs(n: c_uint) -> c_uint);
dlsym_passthrough!(fn uimaxabs(n: u64) -> u64);
dlsym_passthrough!(fn ulabs(n: c_ulong) -> c_ulong);
dlsym_passthrough!(fn ulimit(cmd: c_int, newlimit: c_long) -> c_long);
dlsym_passthrough!(fn ullabs(n: u64) -> u64);
dlsym_passthrough!(fn uselib(library: *const c_char) -> c_int);
dlsym_passthrough!(fn ustat(dev: c_uint, ubuf: *mut c_void) -> c_int);
dlsym_passthrough!(fn utime(filename: *const c_char, times: *const c_void) -> c_int);
dlsym_passthrough!(fn utimes(filename: *const c_char, tv: *const c_void) -> c_int);
dlsym_passthrough!(fn vhangup() -> c_int);
dlsym_passthrough!(fn vlimit(resource: c_int, value: c_int) -> c_int);
dlsym_passthrough!(fn vtimes(current: *mut c_void, child: *mut c_void) -> c_int);

// Legacy regex (4 symbols)
dlsym_passthrough!(fn re_comp(pattern: *const c_char) -> *mut c_char);
dlsym_passthrough!(fn re_exec(string: *const c_char) -> c_int);
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut re_syntax_options: c_ulong = 0;
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut re_max_failures: c_int = 0;

// __argz_* (3 symbols)
dlsym_passthrough!(fn __argz_count(argz: *const c_char, argz_len: SizeT) -> SizeT);
dlsym_passthrough!(fn __argz_next(argz: *const c_char, argz_len: SizeT, entry: *const c_char) -> *mut c_char);
dlsym_passthrough!(fn __argz_stringify(argz: *mut c_char, argz_len: SizeT, sep: c_int));

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

// __h_errno (returns thread-local h_errno address)
dlsym_passthrough!(fn __h_errno() -> *mut c_int);

// in6addr globals
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static in6addr_any: [u8; 16] = [0u8; 16]; // ::
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static in6addr_loopback: [u8; 16] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]; // ::1

// Misc old BSD regex variable
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut loc1: *mut c_char = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut loc2: *mut c_char = std::ptr::null_mut();
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static mut locs: *mut c_char = std::ptr::null_mut();

// advance/step (legacy regex)
dlsym_passthrough!(fn advance(string: *const c_char, expbuf: *const c_char) -> c_int);
dlsym_passthrough!(fn step(string: *const c_char, expbuf: *const c_char) -> c_int);

// sstk
dlsym_passthrough!(fn sstk(increment: c_int) -> c_int);

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
dlsym_passthrough!(fn __stpcpy_small(dest: *mut c_char, src: c_ulong, src2: c_ulong, src3: c_ulong, src4: c_ulong) -> *mut c_char);

// printf_size / printf_size_info: custom printf formatter for human-readable sizes
dlsym_passthrough!(fn printf_size(fp: *mut c_void, info: *const c_void, args: *const *const c_void) -> c_int);
dlsym_passthrough!(fn printf_size_info(info: *const c_void, n: SizeT, argtypes: *mut c_int) -> SizeT);

// nfsservctl: deprecated NFS server control
dlsym_passthrough!(fn nfsservctl(cmd: c_int, argp: *mut c_void, resp: *mut c_void) -> c_int);

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
