#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcsxfrm/wcscoll oracle

//! Randomized live differential fuzzer for `wcsxfrm` and `wcscoll` vs host glibc
//! under the C locale. The narrow strxfrm/strcoll are fuzzed but the WIDE pair
//! is not, and wcsxfrm reimplements its buffer handling inline. This checks the
//! wcsxfrm return value AND the EXACT destination buffer for a random `n` that
//! straddles the transformed length — including glibc's truncation behavior,
//! where it fills `min(n, len+1)` wide chars and writes a terminating NUL ONLY
//! when it fits (so for `n <= len` the prefix is left UNTERMINATED) — plus the
//! wcscoll sign over random wide strings.

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn wcsxfrm(dest: *mut libc::wchar_t, src: *const libc::wchar_t, n: usize) -> usize;
    fn wcscoll(s1: *const libc::wchar_t, s2: *const libc::wchar_t) -> libc::c_int;
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

fn gen_ws(r: &mut Lcg) -> Vec<libc::wchar_t> {
    const POOL: &[u32] = &[0x61, 0x62, 0x63, 0x41, 0x100, 0x3B1, 0x4E00];
    let len = r.below(10);
    let mut v: Vec<libc::wchar_t> = (0..len)
        .map(|_| POOL[r.below(POOL.len())] as libc::wchar_t)
        .collect();
    v.push(0);
    v
}

#[test]
fn wcsxfrm_wcscoll_differential_fuzz_vs_glibc() {
    unsafe {
        let c = std::ffi::CString::new("C").unwrap();
        setlocale(6 /* LC_ALL */, c.as_ptr());
    }
    let mut r = Lcg(0x7f3c_1a55_de01_4422);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..200_000 {
        let src = gen_ws(&mut r);
        let src_len = src.len() - 1; // excludes NUL

        // wcsxfrm into two independent buffers prefilled with a sentinel; pick n
        // straddling src_len+1 (and occasionally a wild value).
        let n = if r.below(5) == 0 {
            r.below(14)
        } else {
            (src_len + 2).saturating_sub(r.below(4))
        };
        const SENT: libc::wchar_t = 0x7e7e;
        let cap = n.max(1) + 4;
        let mut bf = vec![SENT; cap];
        let mut bg = vec![SENT; cap];
        let rf = unsafe { fl::wcsxfrm(bf.as_mut_ptr(), src.as_ptr(), n) };
        let rg = unsafe { wcsxfrm(bg.as_mut_ptr(), src.as_ptr(), n) };
        compared += 1;
        if (rf != rg || bf != bg) && divs.len() < 30 {
            divs.push(format!(
                "wcsxfrm(src_len={src_len}, n={n}) fl=(ret={rf},buf={:x?}) glibc=(ret={rg},buf={:x?})",
                &bf[..cap.min(8)],
                &bg[..cap.min(8)],
            ));
        }

        // wcscoll sign.
        let s2 = gen_ws(&mut r);
        let cf = unsafe { fl::wcscoll(src.as_ptr(), s2.as_ptr()) };
        let cg = unsafe { wcscoll(src.as_ptr(), s2.as_ptr()) };
        compared += 1;
        if cf.signum() != cg.signum() && divs.len() < 30 {
            divs.push(format!("wcscoll sign: fl={cf} glibc={cg}"));
        }
    }

    assert!(
        divs.is_empty(),
        "wcsxfrm/wcscoll diverged from glibc ({compared} compared):\n{}",
        divs.join("\n")
    );
    eprintln!("wcsxfrm/wcscoll fuzz: {compared} compared, 0 divergences vs host glibc");
}
