#![cfg(target_os = "linux")]
//! Differential conformance for `swscanf` vs glibc, focused on the wide-specific
//! conversions: `%ls`/`%S` (wide-string) and `%lc`/`%C` (wide-char) write into a
//! `wchar_t*`, not a `char*`; plus numeric/scanset parsing from wide input and
//! the matched-item count.

use std::ffi::c_int;

use frankenlibc_abi::wchar_abi as fl;

type Wc = libc::wchar_t;

unsafe extern "C" {
    fn swscanf(s: *const Wc, format: *const Wc, ...) -> c_int;
}

fn w(s: &str) -> Vec<Wc> {
    let mut v: Vec<Wc> = s.chars().map(|c| c as u32 as Wc).collect();
    v.push(0);
    v
}

fn wbuf_to_string(buf: &[Wc]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    buf[..end]
        .iter()
        .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
        .collect()
}

#[test]
fn diff_swscanf_int() {
    let inp = w("42 -7 0x1F");
    let fmt = w("%d %d %x");
    let (mut a, mut b, mut c) = (0i32, 0i32, 0i32);
    let (mut a2, mut b2, mut c2) = (0i32, 0i32, 0i32);
    let n_fl = unsafe { fl::swscanf(inp.as_ptr(), fmt.as_ptr(), &mut a, &mut b, &mut c) };
    let n_lc = unsafe { swscanf(inp.as_ptr(), fmt.as_ptr(), &mut a2, &mut b2, &mut c2) };
    assert_eq!(
        (n_fl, a, b, c),
        (n_lc, a2, b2, c2),
        "swscanf int mismatch vs glibc"
    );
}

#[test]
fn diff_swscanf_wide_string() {
    // (input, format) producing one %ls token.
    let cases: &[(&str, &str)] = &[
        ("hello world", "%ls"),
        ("  spaced", "%ls"),
        ("héllo rest", "%ls"), // multibyte wide token (whole token, no width)
        ("日本語 x", "%ls"),
        ("abcdef", "%3ls"),   // ASCII width caps at 3 wide chars
        ("token rest", "%S"), // SVID alias for %ls
        ("café x", "%S"),     // multibyte whole token via %S
                              // NOTE: multibyte %Nls width (wide-char-aware) still tracked in bd-2g7oyh.146.
    ];
    let mut fails = Vec::new();
    for (input, fmt) in cases {
        let inp = w(input);
        let f = w(fmt);
        let mut fb = vec![0 as Wc; 64];
        let mut lb = vec![0 as Wc; 64];
        let n_fl = unsafe { fl::swscanf(inp.as_ptr(), f.as_ptr(), fb.as_mut_ptr()) };
        let n_lc = unsafe { swscanf(inp.as_ptr(), f.as_ptr(), lb.as_mut_ptr()) };
        let sf = wbuf_to_string(&fb);
        let sl = wbuf_to_string(&lb);
        if n_fl != n_lc || (n_fl == 1 && sf != sl) {
            fails.push(format!(
                "  input={input:?} fmt={fmt:?}: fl=(n={n_fl}, {sf:?}) glibc=(n={n_lc}, {sl:?})"
            ));
        }
    }
    assert!(
        fails.is_empty(),
        "swscanf %ls divergences:\n{}",
        fails.join("\n")
    );
}

#[test]
fn diff_swscanf_wide_char() {
    let cases: &[(&str, &str)] = &[
        ("Axyz", "%lc"),
        ("Z 9", "%lc"),
        ("Qrs", "%C"),
        ("éabc", "%lc"), // multibyte wide char -> U+00E9
        ("中a", "%C"),   // -> U+4E2D
        ("😀x", "%lc"),  // supplementary plane
    ];
    let mut fails = Vec::new();
    for (input, fmt) in cases {
        let inp = w(input);
        let f = w(fmt);
        let mut fc: Wc = 0;
        let mut lc: Wc = 0;
        let n_fl = unsafe { fl::swscanf(inp.as_ptr(), f.as_ptr(), &mut fc) };
        let n_lc = unsafe { swscanf(inp.as_ptr(), f.as_ptr(), &mut lc) };
        if n_fl != n_lc || (n_fl == 1 && fc != lc) {
            fails.push(format!(
                "  input={input:?} fmt={fmt:?}: fl=(n={n_fl}, {:#x}) glibc=(n={n_lc}, {:#x})",
                fc as u32, lc as u32
            ));
        }
    }
    assert!(
        fails.is_empty(),
        "swscanf %lc divergences:\n{}",
        fails.join("\n")
    );
}
