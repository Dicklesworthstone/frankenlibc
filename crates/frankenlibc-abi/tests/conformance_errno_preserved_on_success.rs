//! Conformance gate: successful libc calls must NOT clobber errno.
//!
//! POSIX/C and glibc guarantee that library functions set errno only on
//! failure; a successful call leaves errno exactly as the caller left it (the
//! caller is responsible for zeroing errno before a call when it intends to
//! inspect it afterward). A wrapper-heavy reimplementation can easily violate
//! this by unconditionally writing errno (e.g. a `set_abi_errno(0)` on a hot
//! success path, or a membrane-routed entry that resets it), which silently
//! breaks the common idiom:
//!
//!     errno = 0; v = strtol(s, ...); if (errno) { ... }   // and code that
//!     relies on errno surviving an intervening successful call.
//!
//! This gate sets a non-zero sentinel, makes a SUCCESSFUL call (valid inputs,
//! no domain/range/parse error), and asserts errno is still the sentinel —
//! across math, stdlib parse/alloc/sort, and string/memory functions, incl.
//! the membrane-routed entries (malloc/realloc/free/qsort/mem*). errno is read
//! from fl's own slot via errno_abi (reliable in-process).
//!
//! Verified: all functions below preserve the sentinel (matches glibc, which
//! leaves errno untouched on these success paths).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::{errno_abi, malloc_abi as mal, math_abi as ma, stdlib_abi as sa, string_abi as stra};
use std::ffi::{c_char, c_int, c_void, CString};
use std::hint::black_box;

const SENTINEL: c_int = 0x5A5A;

fn set_sentinel() {
    unsafe { errno_abi::set_abi_errno(SENTINEL) };
}
fn errno_now() -> c_int {
    unsafe { *errno_abi::__errno_location() }
}

unsafe extern "C" fn cmp_i32(a: *const c_void, b: *const c_void) -> c_int {
    let x = unsafe { *(a as *const i32) };
    let y = unsafe { *(b as *const i32) };
    (x > y) as c_int - (x < y) as c_int
}

#[test]
fn errno_preserved_on_success() {
    let mut violations: Vec<&'static str> = Vec::new();

    macro_rules! check {
        ($label:literal, $call:expr) => {{
            set_sentinel();
            let _ = unsafe { $call };
            if errno_now() != SENTINEL {
                violations.push($label);
            }
        }};
    }

    // --- math (unary/binary success paths, incl. membrane-routed entries) ---
    check!("sin", ma::sin(black_box(0.5)));
    check!("cos", ma::cos(black_box(0.5)));
    check!("tan", ma::tan(black_box(0.5)));
    check!("sqrt", ma::sqrt(black_box(4.0)));
    check!("exp", ma::exp(black_box(1.0)));
    check!("log", ma::log(black_box(2.0)));
    check!("log10", ma::log10(black_box(100.0)));
    check!("pow", ma::pow(black_box(2.0), black_box(10.0)));
    check!("atan2", ma::atan2(black_box(1.0), black_box(1.0)));
    check!("fabs", ma::fabs(black_box(-2.0)));
    check!("floor", ma::floor(black_box(1.5)));
    check!("ceil", ma::ceil(black_box(1.5)));
    check!("tgamma", ma::tgamma(black_box(5.0)));
    check!("hypot", ma::hypot(black_box(3.0), black_box(4.0)));
    check!("sinf", ma::sinf(black_box(0.5)));
    check!("powf", ma::powf(black_box(2.0), black_box(10.0)));

    // --- stdlib: parse / alloc / sort ---
    let c_num = CString::new("123").unwrap();
    let mut endp: *mut c_char = std::ptr::null_mut();
    check!("strtol", sa::strtol(c_num.as_ptr(), &mut endp, 10));
    let c_flt = CString::new("3.14").unwrap();
    let mut endp2: *mut c_char = std::ptr::null_mut();
    check!("strtod", sa::strtod(c_flt.as_ptr(), &mut endp2));
    check!("atoi", sa::atoi(c_num.as_ptr()));
    check!("abs", { sa::abs(black_box(-5)) });
    let block = unsafe { mal::malloc(64) };
    check!("malloc", { black_box(block); 0usize });
    let block2 = unsafe { mal::realloc(block, 128) };
    check!("realloc", { black_box(block2) as usize });
    check!("free", { mal::free(block2); 0usize });
    let mut arr = [5i32, 3, 1, 4, 2];
    check!("qsort", {
        sa::qsort(arr.as_mut_ptr() as *mut c_void, 5, 4, Some(cmp_i32));
        0usize
    });

    // --- string / memory ---
    let hello = CString::new("hello").unwrap();
    check!("strlen", stra::strlen(hello.as_ptr()));
    check!("strchr", stra::strchr(hello.as_ptr(), b'l' as c_int) as usize);
    let abc = CString::new("abc").unwrap();
    let abd = CString::new("abd").unwrap();
    check!("strcmp", stra::strcmp(abc.as_ptr(), abd.as_ptr()));
    let mut dst = [0i8; 8];
    check!("strcpy", stra::strcpy(dst.as_mut_ptr(), abc.as_ptr()) as usize);
    let src = [7u8; 32];
    let mut buf = [0u8; 32];
    check!("memcpy", {
        stra::memcpy(buf.as_mut_ptr() as *mut c_void, src.as_ptr() as *const c_void, 32) as usize
    });
    check!("memmove", {
        stra::memmove(buf.as_mut_ptr() as *mut c_void, src.as_ptr() as *const c_void, 16) as usize
    });
    check!("memset", {
        stra::memset(buf.as_mut_ptr() as *mut c_void, 0, 32) as usize
    });

    assert!(
        violations.is_empty(),
        "these successful calls clobbered errno (POSIX/glibc leave it untouched): {:?}",
        violations
    );
}
