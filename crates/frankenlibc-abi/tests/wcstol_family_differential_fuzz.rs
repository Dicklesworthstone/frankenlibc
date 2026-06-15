#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcstol oracle

//! Randomized differential fuzzer for the WIDE integer string-parse family —
//! `wcstol` / `wcstoul` / `wcstoll` / `wcstoull` — vs live host glibc. The
//! narrow `strtol_family_differential_fuzz` is the byte analog; this exercises
//! the separate `wcstol_impl` / `wcstoul_impl` scalar wide path.
//!
//! ORACLE CHOICE: as with the narrow family, fl's plain `wcstol` symbol
//! implements C23 semantics (accepts the `0b`/`0B` prefix), while glibc splits
//! the raw pre-C23 `wcstol@GLIBC_2.2.5` symbol from the C23 `__isoc23_wcstol`.
//! A plain `extern { fn wcstol }` would bind the raw symbol, so we bind the
//! `__isoc23_*` oracles explicitly to match fl's C23-flavored plain symbol.
//!
//! Inputs are NUL-terminated wchar_t (i32) arrays drawn from the ASCII strtol
//! alphabet (signs, whitespace incl. \v/\f, `0x`/`0b`/`0` prefix bait, decimal/
//! hex/base-36 letters and garbage) plus occasional non-ASCII wide chars
//! (full-width digits, Unicode spaces) to confirm fl rejects them as non-digits
//! exactly like glibc's C-locale iswdigit/iswspace. Compares value, endptr
//! offset (in wchar units) and ERANGE across every base in 0..=36 + invalid.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno;
use frankenlibc_abi::wchar_abi as fl;

type Wc = libc::wchar_t; // i32 on Linux

unsafe extern "C" {
    #[link_name = "__isoc23_wcstol"]
    fn wcstol(nptr: *const Wc, endptr: *mut *mut Wc, base: libc::c_int) -> libc::c_long;
    #[link_name = "__isoc23_wcstoul"]
    fn wcstoul(nptr: *const Wc, endptr: *mut *mut Wc, base: libc::c_int) -> libc::c_ulong;
    #[link_name = "__isoc23_wcstoll"]
    fn wcstoll(nptr: *const Wc, endptr: *mut *mut Wc, base: libc::c_int) -> libc::c_longlong;
    #[link_name = "__isoc23_wcstoull"]
    fn wcstoull(nptr: *const Wc, endptr: *mut *mut Wc, base: libc::c_int) -> libc::c_ulonglong;
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

fn gen_wc(r: &mut Lcg) -> Wc {
    let v: u32 = match r.below(22) {
        0 | 1 => b' ' as u32,
        2 => *b"\t\n\r\x0b\x0c".get(r.below(5)).unwrap() as u32,
        3 => {
            if r.below(2) == 0 {
                b'+' as u32
            } else {
                b'-' as u32
            }
        }
        4..=9 => b'0' as u32 + r.below(10) as u32,
        10 => b'0' as u32,
        11 => *b"xXbB".get(r.below(4)).unwrap() as u32,
        12 | 13 => b'a' as u32 + r.below(6) as u32,
        14 => b'A' as u32 + r.below(6) as u32,
        15 => b'g' as u32 + r.below(20) as u32,
        16 => b'G' as u32 + r.below(20) as u32,
        17 => *b"._,".get(r.below(3)).unwrap() as u32,
        18 => (r.next() & 0x7f) as u32 | 1, // arbitrary ASCII, never NUL
        // non-ASCII wide chars: full-width digits/letters + Unicode spaces.
        19 => [0xFF10u32, 0xFF21, 0xFF41, 0x00B2, 0x0660][r.below(5)], // ２ Ａ ａ ² ٠
        20 => [0x00A0u32, 0x2007, 0x2003, 0x3000, 0x205F][r.below(5)], // various spaces
        _ => 1 + (r.next() % 0x10_FFFF) as u32,                        // any codepoint, never NUL
    };
    v as Wc
}

fn gen_input(r: &mut Lcg) -> Vec<Wc> {
    let len = 1 + r.below(15);
    (0..len).map(|_| gen_wc(r)).collect()
}

fn gen_base(r: &mut Lcg) -> i32 {
    match r.below(10) {
        0 => 0,
        1 => 10,
        2 => 16,
        3 => 8,
        4 => 2,
        5 => *[-1i32, 1, 37, 64, 100].get(r.below(5)).unwrap(),
        _ => r.below(37) as i32,
    }
}

fn off(end: *mut Wc, base: *const Wc) -> isize {
    if end.is_null() {
        -1
    } else {
        unsafe { (end as *const Wc).offset_from(base) }
    }
}

#[test]
fn wcstol_family_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x91c2_7f5a_d00d_b007);
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
        let mut input = gen_input(&mut r);
        input.extend(std::iter::once(0)); // NUL terminate
        let base = gen_base(&mut r);
        let p = input.as_ptr();
        let shown: String = input[..input.len() - 1]
            .iter()
            .map(|&c| format!("{c:#x} "))
            .collect();

        macro_rules! check {
            ($name:expr, $fl:path, $lc:path) => {{
                compared += 1;
                let mut fe: *mut Wc = std::ptr::null_mut();
                let mut le: *mut Wc = std::ptr::null_mut();
                clear_errno!();
                let fv = unsafe { $fl(p, &mut fe, base) };
                let frange = unsafe { *fl_errno() } == libc::ERANGE;
                clear_errno!();
                let lv = unsafe { $lc(p, &mut le, base) };
                let lrange = unsafe { *libc::__errno_location() } == libc::ERANGE;
                if (fv as i128 != lv as i128 || off(fe, p) != off(le, p) || frange != lrange)
                    && divs.len() < 40
                {
                    divs.push(format!(
                        "{}([{}] base={base}): fl=(v={fv}, end=+{}, erange={frange}) glibc=(v={lv}, end=+{}, erange={lrange})",
                        $name, shown, off(fe, p), off(le, p)
                    ));
                }
            }};
        }

        check!("wcstol", fl::wcstol, wcstol);
        check!("wcstoll", fl::wcstoll, wcstoll);
        check!("wcstoul", fl::wcstoul, wcstoul);
        check!("wcstoull", fl::wcstoull, wcstoull);
    }

    assert!(
        divs.is_empty(),
        "wcstol family diverged from glibc ({compared} compared):\n{}",
        divs.join("\n")
    );
    eprintln!("wcstol family fuzz: {compared} compared, 0 divergences vs host glibc");
}
