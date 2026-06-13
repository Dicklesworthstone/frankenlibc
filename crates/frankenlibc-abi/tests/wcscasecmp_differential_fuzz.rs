#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcscasecmp/wcsncasecmp oracle

//! Randomized live differential fuzzer for `wcscasecmp` / `wcsncasecmp` vs host
//! glibc under the C locale. Unlike the non-case wide compares (`wcscmp` etc.,
//! which glibc returns as a bare ±1 sign), glibc's case-insensitive wide
//! compares return the ACTUAL difference of the ASCII-case-folded code points
//! (`towlower(c1) - towlower(c2)`), e.g. -32 for U+00C0 vs U+00E0. This asserts
//! fl's EXACT return value (not just its sign) matches glibc over random wide
//! strings mixing ASCII letters, accented/Greek/circled letters (which the C
//! locale does NOT fold) and embedded differences.

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn wcscasecmp(s1: *const libc::wchar_t, s2: *const libc::wchar_t) -> libc::c_int;
    fn wcsncasecmp(s1: *const libc::wchar_t, s2: *const libc::wchar_t, n: usize) -> libc::c_int;
    fn setlocale(category: libc::c_int, locale: *const libc::c_char) -> *const libc::c_char;
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

/// A wide char drawn from a pool where the C locale's ASCII-only folding makes
/// the result interesting: ASCII letters/digits (folded), plus accented/Greek/
/// circled letters and fullwidth forms (NOT folded — their raw difference shows).
fn gen_wc(r: &mut Lcg) -> libc::wchar_t {
    const POOL: &[u32] = &[
        0x41, 0x42, 0x5A, 0x61, 0x62, 0x7A, // A B Z a b z
        0x30, 0x39, 0x20, 0x5F, // 0 9 space _
        0xC0, 0xE0, 0xC1, 0xE1, // À à Á á
        0x391, 0x3B1, 0x3A3, 0x3C3, // Greek Α α Σ σ
        0x24B6, 0x24D0, // circled A a
        0xFF21, 0xFF41, // fullwidth A a
        0x131, 0x130, // dotless i / dotted I
    ];
    POOL[r.below(POOL.len())] as libc::wchar_t
}

fn gen_ws(r: &mut Lcg) -> Vec<libc::wchar_t> {
    let len = r.below(6);
    let mut v: Vec<libc::wchar_t> = (0..len).map(|_| gen_wc(r)).collect();
    v.push(0);
    v
}

#[test]
fn wcscasecmp_differential_fuzz_vs_glibc() {
    unsafe {
        let c = std::ffi::CString::new("C").unwrap();
        setlocale(6 /* LC_ALL */, c.as_ptr());
    }

    let mut r = Lcg(0xca5e_c0de_1337_9a11);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..200_000 {
        let a = gen_ws(&mut r);
        let b = gen_ws(&mut r);

        let fl_c = unsafe { fl::wcscasecmp(a.as_ptr() as *const u32, b.as_ptr() as *const u32) };
        let lc_c = unsafe { wcscasecmp(a.as_ptr(), b.as_ptr()) };
        compared += 1;
        if fl_c != lc_c && divs.len() < 30 {
            divs.push(format!("wcscasecmp({a:?},{b:?}) fl={fl_c} glibc={lc_c}"));
        }

        let n = r.below(7);
        let fl_n =
            unsafe { fl::wcsncasecmp(a.as_ptr() as *const u32, b.as_ptr() as *const u32, n) };
        let lc_n = unsafe { wcsncasecmp(a.as_ptr(), b.as_ptr(), n) };
        compared += 1;
        if fl_n != lc_n && divs.len() < 30 {
            divs.push(format!(
                "wcsncasecmp({a:?},{b:?},{n}) fl={fl_n} glibc={lc_n}"
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "wcscasecmp/wcsncasecmp diverged from glibc ({compared} compared):\n{}",
        divs.join("\n")
    );
    eprintln!("wcscasecmp/wcsncasecmp fuzz: {compared} compared, 0 divergences vs host glibc");
}
