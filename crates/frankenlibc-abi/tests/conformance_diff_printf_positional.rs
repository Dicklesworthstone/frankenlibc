#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use frankenlibc_abi::stdio_abi as fl;
use std::ffi::{CString, c_char, c_int};
unsafe extern "C" {
    fn snprintf(b: *mut c_char, s: usize, f: *const c_char, ...) -> i32;
}
// render with 3 int args + 1 string arg available (callers pick via positional)
fn r_iii(eng: u8, fmt: &CString, a: c_int, b: c_int, c: c_int) -> (String, i32) {
    let mut buf = [0u8; 256];
    let n = if eng == 0 {
        unsafe { fl::snprintf(buf.as_mut_ptr() as *mut c_char, 256, fmt.as_ptr(), a, b, c) }
    } else {
        unsafe { snprintf(buf.as_mut_ptr() as *mut c_char, 256, fmt.as_ptr(), a, b, c) }
    };
    (
        String::from_utf8_lossy(&buf[..n.max(0) as usize]).into_owned(),
        n,
    )
}
#[test]
fn printf_positional_star_parity() {
    // positional + dynamic width/precision via '*'
    let fmts = [
        "%1$d",
        "%2$d %1$d",
        "%3$d-%1$d-%2$d",
        "%1$d %1$d %1$d",
        "%*d",
        "%-*d|",
        "%.*d",
        "%*.*d",
        "%2$*1$d",
        "%3$*2$.*1$d",
        "%1$*2$d",
        "%0*d",
        "%+*d",
        "%*.*x",
        "%2$5d|%1$-5d|",
        "%1$d%%%2$d",
        "%*1$d", // %*1$d is invalid-ish; check both agree
        "[%1$3d][%2$03d][%3$+d]",
    ];
    let mut div = Vec::new();
    let triples = [(5, 42, 7), (3, -1, 100), (0, 8, -250), (10, 2, 0)];
    for fmt in fmts {
        let cf = match CString::new(fmt) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for (a, b, c) in triples {
            let f = r_iii(0, &cf, a, b, c);
            let g = r_iii(1, &cf, a, b, c);
            if f != g {
                div.push(format!(
                    "snprintf({fmt:?}, {a},{b},{c}): fl=({:?},ret {}) glibc=({:?},ret {})",
                    f.0, f.1, g.0, g.1
                ));
            }
        }
    }
    if !div.is_empty() {
        eprintln!("PRINTF POSITIONAL/STAR DIVERGENCES ({}):", div.len());
        for d in div.iter().take(80) {
            eprintln!("  {d}");
        }
    }
    assert!(
        div.is_empty(),
        "{} printf positional/star divergences",
        div.len()
    );
}
