#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strtol oracle

//! Randomized differential fuzzer for the integer string-parse family —
//! legacy and C23 `strtol` / `strtoul` / `strtoll` / `strtoull` vs live glibc.
//!
//! The hand-curated `conformance_diff_stdlib_numeric` battery pins ~15 corner
//! inputs; this drives random byte strings (biased toward signs, whitespace,
//! `0x`/`0X`/`0b`/`0B`/`0` prefixes, decimal/hex/base-36 digit alphabets and
//! garbage tails) across every base in 0..=36 plus a few invalid bases, and
//! compares the full observable contract for each engine: return value, the
//! `endptr` consumed-offset, and whether ERANGE was raised (the only errno
//! value POSIX mandates strto* set). 250k cases per signed/unsigned pair.
//!
//! ORACLE CHOICE: ordinary symbols reject C23's `0b`/`0B` prefix, while
//! `__isoc23_*` accepts it for bases0/2. Compare each native entrypoint with
//! the matching GNU symbol. The former C23-only oracle could not establish
//! legacy ABI compatibility. Both modes now see the same250k generated inputs:
//! one million legacy and one million C23 comparisons, with no removed cases.

use std::ffi::CString;

use frankenlibc_abi::errno_abi::__errno_location as fl_errno;
use frankenlibc_abi::isoc_abi as c23;
use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    #[link_name = "strtol"]
    fn legacy_strtol(
        nptr: *const libc::c_char,
        endptr: *mut *mut libc::c_char,
        base: libc::c_int,
    ) -> libc::c_long;
    #[link_name = "strtoul"]
    fn legacy_strtoul(
        nptr: *const libc::c_char,
        endptr: *mut *mut libc::c_char,
        base: libc::c_int,
    ) -> libc::c_ulong;
    #[link_name = "strtoll"]
    fn legacy_strtoll(
        nptr: *const libc::c_char,
        endptr: *mut *mut libc::c_char,
        base: libc::c_int,
    ) -> libc::c_longlong;
    #[link_name = "strtoull"]
    fn legacy_strtoull(
        nptr: *const libc::c_char,
        endptr: *mut *mut libc::c_char,
        base: libc::c_int,
    ) -> libc::c_ulonglong;
    #[link_name = "__isoc23_strtol"]
    fn strtol(
        nptr: *const libc::c_char,
        endptr: *mut *mut libc::c_char,
        base: libc::c_int,
    ) -> libc::c_long;
    #[link_name = "__isoc23_strtoul"]
    fn strtoul(
        nptr: *const libc::c_char,
        endptr: *mut *mut libc::c_char,
        base: libc::c_int,
    ) -> libc::c_ulong;
    #[link_name = "__isoc23_strtoll"]
    fn strtoll(
        nptr: *const libc::c_char,
        endptr: *mut *mut libc::c_char,
        base: libc::c_int,
    ) -> libc::c_longlong;
    #[link_name = "__isoc23_strtoull"]
    fn strtoull(
        nptr: *const libc::c_char,
        endptr: *mut *mut libc::c_char,
        base: libc::c_int,
    ) -> libc::c_ulonglong;
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }
}

/// A weighted alphabet of bytes that matter to strtol parsing. No NUL (the
/// string is NUL-terminated by CString) — an embedded NUL would just be the
/// natural end of string anyway.
fn gen_byte(r: &mut Lcg) -> u8 {
    match r.below(20) {
        0 | 1 => b' ',
        2 => *b"\t\n\r\x0b\x0c".get(r.below(5)).unwrap(),
        3 => {
            if r.below(2) == 0 {
                b'+'
            } else {
                b'-'
            }
        }
        4..=9 => b'0' + r.below(10) as u8, // decimal digits (heavy)
        10 => b'0',                        // extra zeros (prefix bait)
        11 => *b"xXbB".get(r.below(4)).unwrap(), // prefix letters
        12 | 13 => b'a' + r.below(6) as u8, // a-f
        14 => b'A' + r.below(6) as u8,     // A-F
        15 => b'g' + r.below(20) as u8,    // g-z
        16 => b'G' + r.below(20) as u8,    // G-Z
        17 => *b"._,".get(r.below(3)).unwrap(),
        18 => 0x7f,                       // DEL (non-digit)
        _ => (r.next() & 0x7f) as u8 | 1, // arbitrary printable-ish, never NUL
    }
}

fn gen_input(r: &mut Lcg) -> Vec<u8> {
    let len = 1 + r.below(15);
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        v.push(gen_byte(r));
    }
    v
}

fn gen_base(r: &mut Lcg) -> i32 {
    match r.below(10) {
        0 => 0,
        1 => 10,
        2 => 16,
        3 => 8,
        4 => 2,
        5 => *[-1i32, 1, 37, 64, 100].get(r.below(5)).unwrap(), // invalid bases
        _ => r.below(37) as i32,                                // 0..=36
    }
}

fn off(end: *mut libc::c_char, base: *const libc::c_char) -> isize {
    if end.is_null() {
        -1
    } else {
        unsafe { (end as *const libc::c_char).offset_from(base) }
    }
}

#[test]
fn strtol_family_differential_fuzz_vs_glibc() {
    type Signed = unsafe extern "C" fn(
        *const libc::c_char,
        *mut *mut libc::c_char,
        libc::c_int,
    ) -> libc::c_long;
    type Unsigned = unsafe extern "C" fn(
        *const libc::c_char,
        *mut *mut libc::c_char,
        libc::c_int,
    ) -> libc::c_ulong;
    type LongLong = unsafe extern "C" fn(
        *const libc::c_char,
        *mut *mut libc::c_char,
        libc::c_int,
    ) -> libc::c_longlong;
    type ULongLong = unsafe extern "C" fn(
        *const libc::c_char,
        *mut *mut libc::c_char,
        libc::c_int,
    ) -> libc::c_ulonglong;
    let mut r = Lcg(0x5743_2110_d00d_f001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    macro_rules! clear_errno {
        () => {{
            unsafe {
                *fl_errno() = 0;
                *libc::__errno_location() = 0;
            }
        }};
    }

    for _ in 0..250_000 {
        let input = gen_input(&mut r);
        let shown = String::from_utf8_lossy(&input).into_owned();
        let hex: String = input.iter().map(|b| format!("{b:02x} ")).collect();
        let base = gen_base(&mut r);
        let cs = CString::new(input.clone()).unwrap();
        let p = cs.as_ptr();

        // Preserve the original C23 oracle and add the matching legacy arm.
        for (semantic, native, oracle) in [
            ("legacy", fl::strtol as Signed, legacy_strtol as Signed),
            ("C23", c23::__isoc23_strtol as Signed, strtol as Signed),
        ] {
            assert_ne!(native as *const (), oracle as *const ());
            compared += 1;
            let mut fe: *mut libc::c_char = std::ptr::null_mut();
            let mut le: *mut libc::c_char = std::ptr::null_mut();
            clear_errno!();
            let fv = unsafe { native(p, &mut fe, base) };
            let frange = unsafe { *fl_errno() } == libc::ERANGE;
            clear_errno!();
            let lv = unsafe { oracle(p, &mut le, base) };
            let lrange = unsafe { *libc::__errno_location() } == libc::ERANGE;
            if (fv != lv || off(fe, p) != off(le, p) || frange != lrange) && divs.len() < 40 {
                divs.push(format!(
                    "{semantic} strtol({:?} [{}] base={base}: fl=(v={fv}, end=+{}, erange={frange}) glibc=(v={lv}, end=+{}, erange={lrange})",
                    shown, hex, off(fe, p), off(le, p)
                ));
            }
        }

        // strtoll delegates to strtol but exercise the symbol independently.
        for (semantic, native, oracle) in [
            (
                "legacy",
                fl::strtoll as LongLong,
                legacy_strtoll as LongLong,
            ),
            (
                "C23",
                c23::__isoc23_strtoll as LongLong,
                strtoll as LongLong,
            ),
        ] {
            assert_ne!(native as *const (), oracle as *const ());
            compared += 1;
            let mut fe: *mut libc::c_char = std::ptr::null_mut();
            let mut le: *mut libc::c_char = std::ptr::null_mut();
            clear_errno!();
            let fv = unsafe { native(p, &mut fe, base) };
            let frange = unsafe { *fl_errno() } == libc::ERANGE;
            clear_errno!();
            let lv = unsafe { oracle(p, &mut le, base) };
            let lrange = unsafe { *libc::__errno_location() } == libc::ERANGE;
            if (fv != lv || off(fe, p) != off(le, p) || frange != lrange) && divs.len() < 40 {
                divs.push(format!(
                    "{semantic} strtoll({:?} [{}] base={base}: fl=(v={fv}, end=+{}, erange={frange}) glibc=(v={lv}, end=+{}, erange={lrange})",
                    shown, hex, off(fe, p), off(le, p)
                ));
            }
        }

        // --- unsigned: strtoul & strtoull ---
        for (semantic, native, oracle) in [
            (
                "legacy",
                fl::strtoul as Unsigned,
                legacy_strtoul as Unsigned,
            ),
            (
                "C23",
                c23::__isoc23_strtoul as Unsigned,
                strtoul as Unsigned,
            ),
        ] {
            assert_ne!(native as *const (), oracle as *const ());
            compared += 1;
            let mut fe: *mut libc::c_char = std::ptr::null_mut();
            let mut le: *mut libc::c_char = std::ptr::null_mut();
            clear_errno!();
            let fv = unsafe { native(p, &mut fe, base) };
            let frange = unsafe { *fl_errno() } == libc::ERANGE;
            clear_errno!();
            let lv = unsafe { oracle(p, &mut le, base) };
            let lrange = unsafe { *libc::__errno_location() } == libc::ERANGE;
            if (fv != lv || off(fe, p) != off(le, p) || frange != lrange) && divs.len() < 40 {
                divs.push(format!(
                    "{semantic} strtoul({:?} [{}] base={base}: fl=(v={fv}, end=+{}, erange={frange}) glibc=(v={lv}, end=+{}, erange={lrange})",
                    shown, hex, off(fe, p), off(le, p)
                ));
            }
        }
        for (semantic, native, oracle) in [
            (
                "legacy",
                fl::strtoull as ULongLong,
                legacy_strtoull as ULongLong,
            ),
            (
                "C23",
                c23::__isoc23_strtoull as ULongLong,
                strtoull as ULongLong,
            ),
        ] {
            assert_ne!(native as *const (), oracle as *const ());
            compared += 1;
            let mut fe: *mut libc::c_char = std::ptr::null_mut();
            let mut le: *mut libc::c_char = std::ptr::null_mut();
            clear_errno!();
            let fv = unsafe { native(p, &mut fe, base) };
            let frange = unsafe { *fl_errno() } == libc::ERANGE;
            clear_errno!();
            let lv = unsafe { oracle(p, &mut le, base) };
            let lrange = unsafe { *libc::__errno_location() } == libc::ERANGE;
            if (fv != lv || off(fe, p) != off(le, p) || frange != lrange) && divs.len() < 40 {
                divs.push(format!(
                    "{semantic} strtoull({:?} [{}] base={base}: fl=(v={fv}, end=+{}, erange={frange}) glibc=(v={lv}, end=+{}, erange={lrange})",
                    shown, hex, off(fe, p), off(le, p)
                ));
            }
        }
    }

    assert_eq!(compared, 2_000_000);
    assert!(
        divs.is_empty(),
        "strtol family diverged from glibc ({compared} compared):\n{}",
        divs.join("\n")
    );
    eprintln!("strtol family fuzz: {compared} compared, 0 divergences vs host glibc");
}
