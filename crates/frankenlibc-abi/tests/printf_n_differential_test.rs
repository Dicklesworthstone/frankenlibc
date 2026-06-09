#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc snprintf oracle

//! Differential test for the `%n` conversion (stores the number of bytes written
//! so far) across its length modifiers — `%hhn` (signed char), `%hn` (short),
//! `%n` (int), `%ln` (long), `%lln` (long long) — vs host glibc. Each writes
//! into a sentinel-flanked struct so a wrong store SIZE (e.g. writing an int
//! through a char pointer) is detected as adjacent-byte corruption, and a wrong
//! VALUE is detected directly. Also checks two `%n` in one format.

use std::ffi::CString;

use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn snprintf(s: *mut libc::c_char, n: usize, fmt: *const libc::c_char, ...) -> libc::c_int;
}

#[repr(C)]
struct Guard<T> {
    before: u64,
    val: T,
    after: u64,
}

fn run<T: Copy + Default + std::fmt::Debug + PartialEq>(
    glibc: bool,
    fmt: &str,
    init: T,
) -> (i32, T, bool) {
    let cf = CString::new(fmt).unwrap();
    let mut g = Guard { before: 0xAAAA_AAAA_AAAA_AAAA, val: init, after: 0x5555_5555_5555_5555 };
    let mut buf = [0u8; 64];
    let ret = unsafe {
        if glibc {
            snprintf(buf.as_mut_ptr() as *mut libc::c_char, buf.len(), cf.as_ptr(), &mut g.val as *mut T)
        } else {
            fl::snprintf(buf.as_mut_ptr() as *mut libc::c_char, buf.len(), cf.as_ptr(), &mut g.val as *mut T)
        }
    };
    let intact = g.before == 0xAAAA_AAAA_AAAA_AAAA && g.after == 0x5555_5555_5555_5555;
    (ret, g.val, intact)
}

#[test]
fn printf_n_length_modifiers_match_glibc() {
    let mut fails = Vec::new();

    macro_rules! check {
        ($fmt:expr, $ty:ty) => {{
            let f = run::<$ty>(false, $fmt, <$ty>::default());
            let g = run::<$ty>(true, $fmt, <$ty>::default());
            if f != g {
                fails.push(format!("{}: fl={f:?} glibc={g:?}", $fmt));
            }
        }};
    }

    check!("abcde%hhn", i8);
    check!("abcde%hn", i16);
    check!("abcde%n", i32);
    check!("abcde%ln", i64);
    check!("abcde%lln", i64);
    check!("%n", i32);
    check!("longer string here %n", i32);

    assert!(fails.is_empty(), "printf %n diverged from glibc:\n{}", fails.join("\n"));
}
