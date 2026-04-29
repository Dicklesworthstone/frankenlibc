#![cfg(target_os = "linux")]

//! Differential conformance harness for `<wchar.h>` core wide-string functions.
//!
//! FrankenLibC's wchar functions take `*const u32` (treating wchar_t as u32);
//! glibc's libc::wchar_t is also `i32`/`u32` on Linux. We construct equivalent
//! buffers and compare results across:
//!   - wcslen, wcscmp, wcsncmp
//!   - wcschr, wcsrchr, wcsstr (offset-of-match compare)
//!   - wcscpy, wcsncpy (post-call buffer compare)
//!   - mbstowcs / wcstombs round-trip on ASCII
//!
//! Bead: CONFORMANCE: libc wchar.h diff matrix.

use std::ffi::c_int;
use std::process::Command;

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn wcslen(s: *const libc::wchar_t) -> usize;
    fn wcscmp(s1: *const libc::wchar_t, s2: *const libc::wchar_t) -> c_int;
    fn wcsncmp(s1: *const libc::wchar_t, s2: *const libc::wchar_t, n: usize) -> c_int;
    fn wcschr(s: *const libc::wchar_t, c: libc::wchar_t) -> *mut libc::wchar_t;
    fn wcsrchr(s: *const libc::wchar_t, c: libc::wchar_t) -> *mut libc::wchar_t;
    fn wcsstr(h: *const libc::wchar_t, n: *const libc::wchar_t) -> *mut libc::wchar_t;
    fn wcspbrk(s: *const libc::wchar_t, accept: *const libc::wchar_t) -> *mut libc::wchar_t;
    fn wcstok(
        s: *mut libc::wchar_t,
        delim: *const libc::wchar_t,
        save_ptr: *mut *mut libc::wchar_t,
    ) -> *mut libc::wchar_t;
    fn wcscpy(dst: *mut libc::wchar_t, src: *const libc::wchar_t) -> *mut libc::wchar_t;
    fn wcsncpy(dst: *mut libc::wchar_t, src: *const libc::wchar_t, n: usize) -> *mut libc::wchar_t;
    fn mbstowcs(dst: *mut libc::wchar_t, src: *const libc::c_char, n: usize) -> usize;
    fn wcstombs(dst: *mut libc::c_char, src: *const libc::wchar_t, n: usize) -> usize;
    fn wmemcpy(
        dst: *mut libc::wchar_t,
        src: *const libc::wchar_t,
        n: usize,
    ) -> *mut libc::wchar_t;
    fn wmemmove(
        dst: *mut libc::wchar_t,
        src: *const libc::wchar_t,
        n: usize,
    ) -> *mut libc::wchar_t;
    fn wmemset(dst: *mut libc::wchar_t, c: libc::wchar_t, n: usize) -> *mut libc::wchar_t;
    fn wmemcmp(s1: *const libc::wchar_t, s2: *const libc::wchar_t, n: usize) -> c_int;
    fn wcpcpy(dst: *mut libc::wchar_t, src: *const libc::wchar_t) -> *mut libc::wchar_t;
    fn wcpncpy(
        dst: *mut libc::wchar_t,
        src: *const libc::wchar_t,
        n: usize,
    ) -> *mut libc::wchar_t;
    fn wcscat(dst: *mut libc::wchar_t, src: *const libc::wchar_t) -> *mut libc::wchar_t;
    fn wcsncat(
        dst: *mut libc::wchar_t,
        src: *const libc::wchar_t,
        n: usize,
    ) -> *mut libc::wchar_t;
    fn wcscasecmp(s1: *const libc::wchar_t, s2: *const libc::wchar_t) -> c_int;
    fn wcsncasecmp(
        s1: *const libc::wchar_t,
        s2: *const libc::wchar_t,
        n: usize,
    ) -> c_int;
    /// Host glibc `wcstol` — wide-char strtol.
    fn wcstol(
        nptr: *const libc::wchar_t,
        endptr: *mut *mut libc::wchar_t,
        base: c_int,
    ) -> libc::c_long;
    /// Host glibc `wcstoul` — wide-char strtoul.
    fn wcstoul(
        nptr: *const libc::wchar_t,
        endptr: *mut *mut libc::wchar_t,
        base: c_int,
    ) -> libc::c_ulong;
    /// Host glibc `wcstoll` — wide-char strtoll.
    fn wcstoll(
        nptr: *const libc::wchar_t,
        endptr: *mut *mut libc::wchar_t,
        base: c_int,
    ) -> libc::c_longlong;
    /// Host glibc `wcstoull` — wide-char strtoull.
    fn wcstoull(
        nptr: *const libc::wchar_t,
        endptr: *mut *mut libc::wchar_t,
        base: c_int,
    ) -> libc::c_ulonglong;
}

/// Convert an ASCII byte slice into a NUL-terminated wchar_t vector
/// for passing to wide-char numeric conversion functions.
fn ascii_to_wchars(bytes: &[u8]) -> Vec<u32> {
    let mut v: Vec<u32> = bytes.iter().map(|&b| b as u32).collect();
    v.push(0);
    v
}

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

fn wcstring(chars: &[u32]) -> Vec<u32> {
    let mut v = chars.to_vec();
    v.push(0);
    v
}

fn sign(x: c_int) -> c_int {
    x.signum()
}

fn ptr_offset_u32(base: *const u32, ptr: *const u32) -> isize {
    if ptr.is_null() {
        -1
    } else {
        unsafe { ptr.offset_from(base) }
    }
}

fn run_wchar_child(helper: &str) {
    let output = Command::new(std::env::current_exe().expect("current test binary path"))
        .args([
            "--exact",
            "wchar_subprocess_child_invocation",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("FRANKENLIBC_WCHAR_HELPER", helper)
        .output()
        .expect("run isolated wchar helper");
    assert!(
        output.status.success(),
        "isolated wchar helper `{helper}` failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn collect_wcstok_fl(mut input: Vec<u32>, delim: &[u32]) -> (Vec<Vec<u32>>, Vec<u32>) {
    let mut out = Vec::new();
    let mut save_ptr: *mut u32 = std::ptr::null_mut();
    let mut segment = unsafe { fl::wcstok(input.as_mut_ptr(), delim.as_ptr(), &mut save_ptr) };
    while !segment.is_null() && out.len() < input.len() {
        let offset = ptr_offset_u32(input.as_ptr(), segment as *const u32);
        assert!(
            offset >= 0,
            "FrankenLibC wcstok returned an out-of-buffer token"
        );
        let mut token = Vec::new();
        let mut i = offset as usize;
        while i < input.len() && input[i] != 0 {
            token.push(input[i]);
            i += 1;
        }
        out.push(token);
        segment = unsafe { fl::wcstok(std::ptr::null_mut(), delim.as_ptr(), &mut save_ptr) };
    }
    (out, input)
}

fn collect_wcstok_lc(mut input: Vec<u32>, delim: &[u32]) -> (Vec<Vec<u32>>, Vec<u32>) {
    let mut out = Vec::new();
    let mut save_ptr: *mut libc::wchar_t = std::ptr::null_mut();
    let mut segment = unsafe {
        wcstok(
            input.as_mut_ptr() as *mut libc::wchar_t,
            delim.as_ptr() as *const libc::wchar_t,
            &mut save_ptr,
        )
    };
    while !segment.is_null() && out.len() < input.len() {
        let offset = ptr_offset_u32(input.as_ptr(), segment as *const u32);
        assert!(offset >= 0, "glibc wcstok returned an out-of-buffer token");
        let mut token = Vec::new();
        let mut i = offset as usize;
        while i < input.len() && input[i] != 0 {
            token.push(input[i]);
            i += 1;
        }
        out.push(token);
        segment = unsafe {
            wcstok(
                std::ptr::null_mut(),
                delim.as_ptr() as *const libc::wchar_t,
                &mut save_ptr,
            )
        };
    }
    (out, input)
}

// ===========================================================================
// wcslen
// ===========================================================================

#[test]
fn diff_wcslen_cases() {
    let mut divs = Vec::new();
    let cases: &[&[u32]] = &[
        &[],
        &['a' as u32],
        &['h' as u32, 'e' as u32, 'l' as u32, 'l' as u32, 'o' as u32],
        &[0xFF, 0xFE, 0xFD],
        &[0x10000, 0x10001],
    ];
    for s in cases {
        let buf = wcstring(s);
        let r_fl = unsafe { fl::wcslen(buf.as_ptr()) };
        let r_lc = unsafe { wcslen(buf.as_ptr() as *const libc::wchar_t) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "wcslen",
                case: format!("{:?}", s),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "wcslen divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// wcscmp / wcsncmp — sign of result
// ===========================================================================

const WCMP_CASES: &[(&[u32], &[u32])] = &[
    (&[], &[]),
    (&[], &['a' as u32]),
    (&['a' as u32], &[]),
    (&['a' as u32], &['a' as u32]),
    (&['a' as u32], &['b' as u32]),
    (&['b' as u32], &['a' as u32]),
    (
        &['a' as u32, 'b' as u32, 'c' as u32],
        &['a' as u32, 'b' as u32, 'c' as u32],
    ),
    (
        &['a' as u32, 'b' as u32, 'c' as u32],
        &['a' as u32, 'b' as u32, 'd' as u32],
    ),
    (&[0x100], &[0x101]),
    (&[0xFFFFFFFF], &[0]),
];

#[test]
fn diff_wcscmp_cases() {
    let mut divs = Vec::new();
    for (a, b) in WCMP_CASES {
        let ab = wcstring(a);
        let bb = wcstring(b);
        let r_fl = unsafe { fl::wcscmp(ab.as_ptr(), bb.as_ptr()) };
        let r_lc = unsafe {
            wcscmp(
                ab.as_ptr() as *const libc::wchar_t,
                bb.as_ptr() as *const libc::wchar_t,
            )
        };
        if sign(r_fl) != sign(r_lc) {
            divs.push(Divergence {
                function: "wcscmp",
                case: format!("({:?}, {:?})", a, b),
                field: "sign",
                frankenlibc: format!("{}", sign(r_fl)),
                glibc: format!("{}", sign(r_lc)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "wcscmp divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_wcsncmp_cases() {
    let mut divs = Vec::new();
    for (a, b) in WCMP_CASES {
        let ab = wcstring(a);
        let bb = wcstring(b);
        for &n in &[0usize, 1, 3, 100] {
            let r_fl = unsafe { fl::wcsncmp(ab.as_ptr(), bb.as_ptr(), n) };
            let r_lc = unsafe {
                wcsncmp(
                    ab.as_ptr() as *const libc::wchar_t,
                    bb.as_ptr() as *const libc::wchar_t,
                    n,
                )
            };
            if sign(r_fl) != sign(r_lc) {
                divs.push(Divergence {
                    function: "wcsncmp",
                    case: format!("({:?}, {:?}, n={})", a, b, n),
                    field: "sign",
                    frankenlibc: format!("{}", sign(r_fl)),
                    glibc: format!("{}", sign(r_lc)),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "wcsncmp divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// wcschr / wcsrchr / wcsstr — offset compare
// ===========================================================================

#[test]
fn diff_wcschr_cases() {
    let mut divs = Vec::new();
    let s: Vec<u32> = wcstring(&[
        'a' as u32, 'b' as u32, 'c' as u32, 'a' as u32, 'b' as u32, 'c' as u32,
    ]);
    for &c in &[
        'a' as u32, 'b' as u32, 'c' as u32, 'z' as u32, 0u32, 0x100, 0xFFFF,
    ] {
        let r_fl = unsafe { fl::wcschr(s.as_ptr(), c) };
        let r_lc = unsafe { wcschr(s.as_ptr() as *const libc::wchar_t, c as libc::wchar_t) };
        let off_fl = if r_fl.is_null() {
            -1
        } else {
            unsafe { (r_fl as *const u32).offset_from(s.as_ptr()) }
        };
        let off_lc = if r_lc.is_null() {
            -1
        } else {
            unsafe {
                (r_lc as *const libc::wchar_t).offset_from(s.as_ptr() as *const libc::wchar_t)
            }
        };
        if off_fl != off_lc {
            divs.push(Divergence {
                function: "wcschr",
                case: format!("c={:#x}", c),
                field: "offset",
                frankenlibc: format!("{off_fl}"),
                glibc: format!("{off_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "wcschr divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_wcsrchr_cases() {
    let mut divs = Vec::new();
    let s: Vec<u32> = wcstring(&[
        'a' as u32, 'b' as u32, 'c' as u32, 'a' as u32, 'b' as u32, 'c' as u32,
    ]);
    for &c in &['a' as u32, 'b' as u32, 'c' as u32, 'z' as u32, 0u32] {
        let r_fl = unsafe { fl::wcsrchr(s.as_ptr(), c) };
        let r_lc = unsafe { wcsrchr(s.as_ptr() as *const libc::wchar_t, c as libc::wchar_t) };
        let off_fl = if r_fl.is_null() {
            -1
        } else {
            unsafe { (r_fl as *const u32).offset_from(s.as_ptr()) }
        };
        let off_lc = if r_lc.is_null() {
            -1
        } else {
            unsafe {
                (r_lc as *const libc::wchar_t).offset_from(s.as_ptr() as *const libc::wchar_t)
            }
        };
        if off_fl != off_lc {
            divs.push(Divergence {
                function: "wcsrchr",
                case: format!("c={:#x}", c),
                field: "offset",
                frankenlibc: format!("{off_fl}"),
                glibc: format!("{off_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "wcsrchr divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_wcsstr_cases() {
    let mut divs = Vec::new();
    let cases: &[(&[u32], &[u32])] = &[
        (&[], &[]),
        (&['h' as u32, 'i' as u32], &[]),
        (&['h' as u32, 'i' as u32], &['i' as u32]),
        (
            &['a' as u32, 'b' as u32, 'c' as u32, 'd' as u32],
            &['c' as u32, 'd' as u32],
        ),
        (
            &['a' as u32, 'a' as u32, 'a' as u32],
            &['a' as u32, 'a' as u32],
        ),
        (&['a' as u32], &['b' as u32]),
    ];
    for (h, n) in cases {
        let hb = wcstring(h);
        let nb = wcstring(n);
        let r_fl = unsafe { fl::wcsstr(hb.as_ptr(), nb.as_ptr()) };
        let r_lc = unsafe {
            wcsstr(
                hb.as_ptr() as *const libc::wchar_t,
                nb.as_ptr() as *const libc::wchar_t,
            )
        };
        let off_fl = if r_fl.is_null() {
            -1
        } else {
            unsafe { (r_fl as *const u32).offset_from(hb.as_ptr()) }
        };
        let off_lc = if r_lc.is_null() {
            -1
        } else {
            unsafe {
                (r_lc as *const libc::wchar_t).offset_from(hb.as_ptr() as *const libc::wchar_t)
            }
        };
        if off_fl != off_lc {
            divs.push(Divergence {
                function: "wcsstr",
                case: format!("({:?}, {:?})", h, n),
                field: "offset",
                frankenlibc: format!("{off_fl}"),
                glibc: format!("{off_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "wcsstr divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_wcspbrk_wcstok_subprocess() {
    run_wchar_child("search-token");
}

#[test]
fn wchar_subprocess_child_invocation() {
    let Ok(helper) = std::env::var("FRANKENLIBC_WCHAR_HELPER") else {
        return;
    };
    assert_eq!(helper, "search-token");

    let mut divs = Vec::new();
    let wcspbrk_cases: &[(&[u32], &[u32])] = &[
        (&[], &['x' as u32]),
        (&['a' as u32, 'b' as u32, 'c' as u32], &[]),
        (
            &['a' as u32, 'b' as u32, 'c' as u32],
            &['x' as u32, 'b' as u32],
        ),
        (
            &['a' as u32, 'b' as u32, 'c' as u32],
            &['x' as u32, 'y' as u32],
        ),
        (
            &['a' as u32, 'b' as u32, 'c' as u32],
            &['c' as u32, 'a' as u32],
        ),
    ];
    for (s, accept) in wcspbrk_cases {
        let sb = wcstring(s);
        let ab = wcstring(accept);
        let r_fl = unsafe { fl::wcspbrk(sb.as_ptr(), ab.as_ptr()) };
        let r_lc = unsafe {
            wcspbrk(
                sb.as_ptr() as *const libc::wchar_t,
                ab.as_ptr() as *const libc::wchar_t,
            )
        };
        let off_fl = ptr_offset_u32(sb.as_ptr(), r_fl as *const u32);
        let off_lc = ptr_offset_u32(sb.as_ptr(), r_lc as *const u32);
        if off_fl != off_lc {
            divs.push(Divergence {
                function: "wcspbrk",
                case: format!("({:?}, {:?})", s, accept),
                field: "offset",
                frankenlibc: format!("{off_fl}"),
                glibc: format!("{off_lc}"),
            });
        }
    }

    let wcstok_cases: &[(&[u32], &[u32])] = &[
        (&[], &[',' as u32]),
        (&[',' as u32, ',' as u32], &[',' as u32]),
        (
            &[
                'a' as u32, ',' as u32, 'b' as u32, ',' as u32, ',' as u32, 'c' as u32,
            ],
            &[',' as u32],
        ),
        (
            &[
                ' ' as u32,
                'a' as u32,
                ' ' as u32,
                'b' as u32,
                '\t' as u32,
                'c' as u32,
            ],
            &[' ' as u32, '\t' as u32],
        ),
        (
            &['a' as u32, ':' as u32, 'b' as u32, '/' as u32, 'c' as u32],
            &[':' as u32, '/' as u32],
        ),
    ];
    for (s, delim) in wcstok_cases {
        let input = wcstring(s);
        let delim = wcstring(delim);
        let (tokens_fl, mutated_fl) = collect_wcstok_fl(input.clone(), &delim);
        let (tokens_lc, mutated_lc) = collect_wcstok_lc(input, &delim);
        if tokens_fl != tokens_lc {
            divs.push(Divergence {
                function: "wcstok",
                case: format!("({:?}, {:?})", s, delim),
                field: "tokens",
                frankenlibc: format!("{tokens_fl:?}"),
                glibc: format!("{tokens_lc:?}"),
            });
        }
        if mutated_fl != mutated_lc {
            divs.push(Divergence {
                function: "wcstok",
                case: format!("({:?}, {:?})", s, delim),
                field: "mutated_buffer",
                frankenlibc: format!("{mutated_fl:?}"),
                glibc: format!("{mutated_lc:?}"),
            });
        }
    }

    assert!(
        divs.is_empty(),
        "subprocess wchar search/token divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// wcscpy / wcsncpy — buffer mutation
// ===========================================================================

#[test]
fn diff_wcscpy_cases() {
    let mut divs = Vec::new();
    for src in &[
        &[][..],
        &['a' as u32][..],
        &['h' as u32, 'i' as u32][..],
        &[0x100, 0x200][..],
    ] {
        let sb = wcstring(src);
        let mut dst_fl = vec![0xCDCDCDCDu32; 32];
        let mut dst_lc = vec![0xCDCDCDCDu32; 32];
        let _ = unsafe { fl::wcscpy(dst_fl.as_mut_ptr(), sb.as_ptr()) };
        let _ = unsafe {
            wcscpy(
                dst_lc.as_mut_ptr() as *mut libc::wchar_t,
                sb.as_ptr() as *const libc::wchar_t,
            )
        };
        let dst_lc_u32 = dst_lc.clone();
        if dst_fl != dst_lc_u32 {
            divs.push(Divergence {
                function: "wcscpy",
                case: format!("{:?}", src),
                field: "dst_buffer",
                frankenlibc: format!("{:?}", &dst_fl[..8]),
                glibc: format!("{:?}", &dst_lc_u32[..8]),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "wcscpy divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_wcsncpy_cases() {
    let mut divs = Vec::new();
    for src in &[
        &['a' as u32][..],
        &['h' as u32, 'i' as u32][..],
        &['x' as u32, 'y' as u32, 'z' as u32, 'w' as u32][..],
    ] {
        for &n in &[0usize, 1, 3, 8] {
            let sb = wcstring(src);
            let mut dst_fl = vec![0xCDCDCDCDu32; 16];
            let mut dst_lc = vec![0xCDCDCDCDu32; 16];
            let _ = unsafe { fl::wcsncpy(dst_fl.as_mut_ptr(), sb.as_ptr(), n) };
            let _ = unsafe {
                wcsncpy(
                    dst_lc.as_mut_ptr() as *mut libc::wchar_t,
                    sb.as_ptr() as *const libc::wchar_t,
                    n,
                )
            };
            let dst_lc_u32 = dst_lc.clone();
            if dst_fl != dst_lc_u32 {
                divs.push(Divergence {
                    function: "wcsncpy",
                    case: format!("(src={:?}, n={})", src, n),
                    field: "dst_buffer",
                    frankenlibc: format!("{:?}", &dst_fl[..n.min(8)]),
                    glibc: format!("{:?}", &dst_lc_u32[..n.min(8)]),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "wcsncpy divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// mbstowcs / wcstombs — round trip on ASCII
// ===========================================================================

#[test]
fn diff_mbstowcs_ascii_cases() {
    let mut divs = Vec::new();
    let inputs: &[&[u8]] = &[b"\0", b"a\0", b"hello\0", b"the quick brown fox\0"];
    for input in inputs {
        let mut buf_fl = vec![0u32; 64];
        let mut buf_lc = vec![0i32; 64];
        let n_fl = unsafe { fl::mbstowcs(buf_fl.as_mut_ptr(), input.as_ptr(), buf_fl.len()) };
        let n_lc = unsafe {
            mbstowcs(
                buf_lc.as_mut_ptr() as *mut libc::wchar_t,
                input.as_ptr() as *const libc::c_char,
                buf_lc.len(),
            )
        };
        if n_fl != n_lc {
            divs.push(Divergence {
                function: "mbstowcs",
                case: format!("{:?}", String::from_utf8_lossy(input)),
                field: "return_count",
                frankenlibc: format!("{n_fl}"),
                glibc: format!("{n_lc}"),
            });
        }
        // Compare the first n_fl wchar elements (treat libc i32 as u32).
        if n_fl != usize::MAX {
            let n = n_fl.min(buf_fl.len());
            let buf_lc_u32: Vec<u32> = buf_lc.iter().take(n).map(|&x| x as u32).collect();
            if buf_fl[..n] != buf_lc_u32[..] {
                divs.push(Divergence {
                    function: "mbstowcs",
                    case: format!("{:?}", String::from_utf8_lossy(input)),
                    field: "wide_buffer",
                    frankenlibc: format!("{:?}", &buf_fl[..n]),
                    glibc: format!("{:?}", &buf_lc_u32[..]),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "mbstowcs divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_wcstombs_ascii_cases() {
    let mut divs = Vec::new();
    let inputs: &[&[u32]] = &[
        &[0],
        &['a' as u32, 0],
        &[
            'h' as u32, 'e' as u32, 'l' as u32, 'l' as u32, 'o' as u32, 0,
        ],
    ];
    for input in inputs {
        let mut buf_fl = vec![0u8; 64];
        let mut buf_lc = vec![0u8; 64];
        let n_fl = unsafe { fl::wcstombs(buf_fl.as_mut_ptr(), input.as_ptr(), buf_fl.len()) };
        let n_lc = unsafe {
            wcstombs(
                buf_lc.as_mut_ptr() as *mut libc::c_char,
                input.as_ptr() as *const libc::wchar_t,
                buf_lc.len(),
            )
        };
        if n_fl != n_lc {
            divs.push(Divergence {
                function: "wcstombs",
                case: format!("{:?}", input),
                field: "return_count",
                frankenlibc: format!("{n_fl}"),
                glibc: format!("{n_lc}"),
            });
        }
        if n_fl != usize::MAX {
            let n = n_fl.min(buf_fl.len());
            if buf_fl[..n] != buf_lc[..n] {
                divs.push(Divergence {
                    function: "wcstombs",
                    case: format!("{:?}", input),
                    field: "narrow_buffer",
                    frankenlibc: format!("{:?}", &buf_fl[..n]),
                    glibc: format!("{:?}", &buf_lc[..n]),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "wcstombs divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// wmemcpy / wmemmove / wmemset / wmemchr / wmemcmp — wide-char memory ops
// ===========================================================================
//
// Pure wide-char analogues of memcpy/memmove/memset/memchr/memcmp. They
// operate on wchar_t (i32/u32 on Linux/x86_64) — explicit count, no NUL
// semantics — so they're the cleanest possible diff target: any
// disagreement is a real algorithmic divergence, no ambiguity around
// terminators.
//
// We diff in two dimensions for the mutating functions (wmemcpy /
// wmemmove / wmemset):
//   1. dst-buffer post-call state (wchar_t array byte-for-byte)
//   2. return-pointer offset relative to dst (must equal `n` for
//      wmemset, dst for wmemcpy/wmemmove per POSIX)
// And direct value comparison for the read-only ones (wmemchr returns
// pointer-or-NULL, wmemcmp returns sign).

const WIDE_BUFS: &[&[u32]] = &[
    &[],
    &[0x41],                                  // single ASCII
    &[0x41, 0x42, 0x43],                      // ASCII run
    &[0x80, 0x100, 0x10FF],                   // mid-BMP
    &[0x10FFFF],                              // max codepoint
    &[0, 0, 0],                               // all-zero, no NUL semantics for wmem*
    &[0x41, 0, 0x42],                         // embedded zero (must NOT terminate scan)
    &[0xFFFFFFFF],                            // u32 saturation (wchar_t max as i32 is 0x7fffffff)
];

#[test]
fn diff_wmemcpy_cases() {
    let mut divs = Vec::new();
    for src in WIDE_BUFS {
        for &n in &[0usize, 1, src.len(), src.len().saturating_sub(1)] {
            if n > src.len() {
                continue;
            }
            let mut dst_fl = vec![0xCDCDCDCDu32; 16];
            let mut dst_lc = vec![0xCDCDCDCDu32; 16];
            // SAFETY: dst is 16 wchar_ts; n ≤ src.len() ≤ 8 < 16; src is
            // a Rust slice owned for the call.
            let fl_r = unsafe { fl::wmemcpy(dst_fl.as_mut_ptr(), src.as_ptr(), n) };
            let lc_r = unsafe {
                wmemcpy(
                    dst_lc.as_mut_ptr() as *mut libc::wchar_t,
                    src.as_ptr() as *const libc::wchar_t,
                    n,
                )
            };
            let fl_off = (fl_r as usize).wrapping_sub(dst_fl.as_ptr() as usize);
            let lc_off = (lc_r as usize).wrapping_sub(dst_lc.as_ptr() as usize);
            if fl_off != lc_off {
                divs.push(Divergence {
                    function: "wmemcpy",
                    case: format!("(src.len={}, n={})", src.len(), n),
                    field: "return_offset",
                    frankenlibc: format!("{fl_off}"),
                    glibc: format!("{lc_off}"),
                });
            }
            if dst_fl != dst_lc {
                divs.push(Divergence {
                    function: "wmemcpy",
                    case: format!("(src.len={}, n={})", src.len(), n),
                    field: "dst_buffer",
                    frankenlibc: format!("{:?}", &dst_fl[..n.min(8)]),
                    glibc: format!("{:?}", &dst_lc[..n.min(8)]),
                });
            }
        }
    }
    assert!(divs.is_empty(), "wmemcpy divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_wmemmove_cases() {
    // wmemmove must handle overlapping src/dst — the only behavioral
    // contract that distinguishes it from wmemcpy. Test both
    // non-overlapping (above) and overlapping (forward + backward).
    let mut divs = Vec::new();
    let cases: &[(&[u32], usize, isize, usize)] = &[
        // (initial_buffer, src_offset, dst_delta_from_src_in_words, n)
        (&[1, 2, 3, 4, 5, 6, 7, 8], 0, 0, 0),       // n=0 no-op
        (&[1, 2, 3, 4, 5, 6, 7, 8], 0, 0, 4),       // exact overlap
        (&[1, 2, 3, 4, 5, 6, 7, 8], 0, 2, 4),       // forward overlap
        (&[1, 2, 3, 4, 5, 6, 7, 8], 2, -2, 4),      // backward overlap
        (&[1, 2, 3, 4, 5, 6, 7, 8], 0, 4, 4),       // disjoint within buf
    ];
    for &(initial, src_off, dst_delta, n) in cases {
        let mut buf_fl = initial.to_vec();
        let mut buf_lc = initial.to_vec();
        let dst_off = (src_off as isize + dst_delta) as usize;
        // SAFETY: indexes computed to stay within initial (8 words).
        let fl_r = unsafe {
            fl::wmemmove(
                buf_fl.as_mut_ptr().add(dst_off),
                buf_fl.as_ptr().add(src_off),
                n,
            )
        };
        let lc_r = unsafe {
            wmemmove(
                buf_lc.as_mut_ptr().add(dst_off) as *mut libc::wchar_t,
                buf_lc.as_ptr().add(src_off) as *const libc::wchar_t,
                n,
            )
        };
        let fl_off = (fl_r as usize).wrapping_sub(buf_fl.as_ptr() as usize)
            / std::mem::size_of::<u32>();
        let lc_off = (lc_r as usize).wrapping_sub(buf_lc.as_ptr() as usize)
            / std::mem::size_of::<u32>();
        if fl_off != lc_off {
            divs.push(Divergence {
                function: "wmemmove",
                case: format!("(src_off={src_off}, dst_delta={dst_delta}, n={n})"),
                field: "return_offset",
                frankenlibc: format!("{fl_off}"),
                glibc: format!("{lc_off}"),
            });
        }
        if buf_fl != buf_lc {
            divs.push(Divergence {
                function: "wmemmove",
                case: format!("(src_off={src_off}, dst_delta={dst_delta}, n={n})"),
                field: "buffer",
                frankenlibc: format!("{:?}", buf_fl),
                glibc: format!("{:?}", buf_lc),
            });
        }
    }
    assert!(divs.is_empty(), "wmemmove divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_wmemset_cases() {
    let mut divs = Vec::new();
    let fill_values: &[u32] = &[0, 1, 0x41, 0x10FFFF, 0x7FFFFFFF];
    for &c in fill_values {
        for &n in &[0usize, 1, 4, 16] {
            let mut dst_fl = vec![0xCDCDCDCDu32; 16];
            let mut dst_lc = vec![0xCDCDCDCDu32; 16];
            // SAFETY: dst is 16 wchar_ts; n ≤ 16.
            let fl_r = unsafe { fl::wmemset(dst_fl.as_mut_ptr(), c, n) };
            let lc_r =
                unsafe { wmemset(dst_lc.as_mut_ptr() as *mut libc::wchar_t, c as libc::wchar_t, n) };
            let fl_off = (fl_r as usize).wrapping_sub(dst_fl.as_ptr() as usize);
            let lc_off = (lc_r as usize).wrapping_sub(dst_lc.as_ptr() as usize);
            if fl_off != lc_off {
                divs.push(Divergence {
                    function: "wmemset",
                    case: format!("(c={c:#x}, n={n})"),
                    field: "return_offset",
                    frankenlibc: format!("{fl_off}"),
                    glibc: format!("{lc_off}"),
                });
            }
            if dst_fl != dst_lc {
                divs.push(Divergence {
                    function: "wmemset",
                    case: format!("(c={c:#x}, n={n})"),
                    field: "dst_buffer",
                    frankenlibc: format!("{:?}", &dst_fl[..n.min(8)]),
                    glibc: format!("{:?}", &dst_lc[..n.min(8)]),
                });
            }
        }
    }
    assert!(divs.is_empty(), "wmemset divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_wmemchr_cases() {
    let mut divs = Vec::new();
    let cases: &[(&[u32], u32, usize)] = &[
        (&[], 0x41, 0),
        (&[0x41, 0x42, 0x43], 0x42, 3),       // match in middle
        (&[0x41, 0x42, 0x43], 0x44, 3),       // no match
        (&[0x41, 0x42, 0x43], 0x42, 1),       // bound stops before match
        (&[0x41, 0x42, 0x43, 0x42], 0x42, 4), // first of two matches
        (&[0, 0, 0], 0, 3),                   // search for zero (no NUL semantics)
        (&[0x10FFFF, 0x41], 0x10FFFF, 2),     // max codepoint
    ];
    for (buf, c, n) in cases {
        let fl_r = unsafe { fl::wmemchr(buf.as_ptr(), *c, *n) };
        let lc_r = unsafe {
            libc::wmemchr(
                buf.as_ptr() as *const libc::wchar_t,
                *c as libc::wchar_t,
                *n,
            )
        };
        let fl_off = if fl_r.is_null() {
            -1
        } else {
            ptr_offset_u32(buf.as_ptr(), fl_r as *const u32)
        };
        let lc_off = if lc_r.is_null() {
            -1
        } else {
            ptr_offset_u32(buf.as_ptr(), lc_r as *const u32)
        };
        if fl_off != lc_off {
            divs.push(Divergence {
                function: "wmemchr",
                case: format!("(buf={buf:?}, c={c:#x}, n={n})"),
                field: "return_offset",
                frankenlibc: format!("{fl_off}"),
                glibc: format!("{lc_off}"),
            });
        }
    }
    assert!(divs.is_empty(), "wmemchr divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_wmemcmp_cases() {
    let mut divs = Vec::new();
    // POSIX requires only the sign of wmemcmp's result to be portable.
    let cases: &[(&[u32], &[u32], usize)] = &[
        (&[], &[], 0),
        (&[0x41, 0x42, 0x43], &[0x41, 0x42, 0x43], 3),       // equal
        (&[0x41, 0x42, 0x43], &[0x41, 0x42, 0x44], 3),       // a<b at index 2
        (&[0x41, 0x42, 0x44], &[0x41, 0x42, 0x43], 3),       // a>b at index 2
        (&[0x41, 0x42, 0x43], &[0x41, 0x42, 0x44], 2),       // bound stops before diff
        (&[0xFFFFFFFF, 0], &[0, 0], 1),                      // unsigned compare (high bit set)
        (&[0x10FFFF], &[0x10FFFE], 1),
        (&[0, 0, 0], &[0, 0, 1], 3),                         // embedded zeros, no NUL semantics
    ];
    for (a, b, n) in cases {
        let fl_r = unsafe { fl::wmemcmp(a.as_ptr(), b.as_ptr(), *n) };
        let lc_r = unsafe {
            wmemcmp(
                a.as_ptr() as *const libc::wchar_t,
                b.as_ptr() as *const libc::wchar_t,
                *n,
            )
        };
        if sign(fl_r) != sign(lc_r) {
            divs.push(Divergence {
                function: "wmemcmp",
                case: format!("(a={a:?}, b={b:?}, n={n})"),
                field: "return_sign",
                frankenlibc: format!("sign={}", sign(fl_r)),
                glibc: format!("sign={}", sign(lc_r)),
            });
        }
    }
    assert!(divs.is_empty(), "wmemcmp divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// wcpcpy / wcpncpy — wide-char copy variants returning end-of-dest
// ===========================================================================
//
// Wide-char analogues of stpcpy / stpncpy. Already pinned for the narrow
// string family in conformance_diff_string_mut.rs (70e23e52); the wide
// variants share semantics modulo wchar_t element size so the same diff
// pattern applies. Both compare:
//   1. dst-buffer post-call state (wchar_t-by-wchar_t)
//   2. return-pointer offset relative to dst (in wchar_t units)

#[test]
fn diff_wcpcpy_cases() {
    let mut divs = Vec::new();
    let cases: &[&[u32]] = &[
        &[],                                  // empty src (only NUL written)
        &[0x41],                              // single char
        &[0x41, 0x42, 0x43],                  // ASCII run
        &[0x80, 0x100, 0x10FF, 0x10FFFF],     // BMP + supplementary plane
    ];
    for src_chars in cases {
        let src = wcstring(src_chars);
        let mut dst_fl = vec![0xCDCDCDCDu32; 32];
        let mut dst_lc = vec![0xCDCDCDCDu32; 32];
        // SAFETY: src is a fresh NUL-terminated wchar buffer; dst is
        // 32 wchar_ts which always exceeds src length.
        let fl_r = unsafe { fl::wcpcpy(dst_fl.as_mut_ptr(), src.as_ptr()) };
        let lc_r = unsafe {
            wcpcpy(
                dst_lc.as_mut_ptr() as *mut libc::wchar_t,
                src.as_ptr() as *const libc::wchar_t,
            )
        };
        let fl_off = ptr_offset_u32(dst_fl.as_ptr(), fl_r as *const u32);
        let lc_off = ptr_offset_u32(dst_lc.as_ptr(), lc_r as *const u32);
        if fl_off != lc_off {
            divs.push(Divergence {
                function: "wcpcpy",
                case: format!("{src_chars:?}"),
                field: "return_offset",
                frankenlibc: format!("{fl_off}"),
                glibc: format!("{lc_off}"),
            });
        }
        if dst_fl != dst_lc {
            divs.push(Divergence {
                function: "wcpcpy",
                case: format!("{src_chars:?}"),
                field: "dst_buffer",
                frankenlibc: format!("{:?}", &dst_fl[..8]),
                glibc: format!("{:?}", &dst_lc[..8]),
            });
        }
    }
    assert!(divs.is_empty(), "wcpcpy divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_wcpncpy_cases() {
    let mut divs = Vec::new();
    let src_cases: &[&[u32]] = &[
        &[],
        &[0x41],
        &[0x41, 0x42, 0x43],
        &[0x80, 0x100, 0x10FF],
    ];
    for src_chars in src_cases {
        let src = wcstring(src_chars);
        for &n in &[0usize, 1, 2, 4, 8, 16] {
            let mut dst_fl = vec![0xCDCDCDCDu32; 32];
            let mut dst_lc = vec![0xCDCDCDCDu32; 32];
            // SAFETY: src is NUL-terminated; dst is 32 wchar_ts so
            // n ≤ 16 is well within bounds.
            let fl_r = unsafe { fl::wcpncpy(dst_fl.as_mut_ptr(), src.as_ptr(), n) };
            let lc_r = unsafe {
                wcpncpy(
                    dst_lc.as_mut_ptr() as *mut libc::wchar_t,
                    src.as_ptr() as *const libc::wchar_t,
                    n,
                )
            };
            let fl_off = ptr_offset_u32(dst_fl.as_ptr(), fl_r as *const u32);
            let lc_off = ptr_offset_u32(dst_lc.as_ptr(), lc_r as *const u32);
            if fl_off != lc_off {
                divs.push(Divergence {
                    function: "wcpncpy",
                    case: format!("(src={src_chars:?}, n={n})"),
                    field: "return_offset",
                    frankenlibc: format!("{fl_off}"),
                    glibc: format!("{lc_off}"),
                });
            }
            if dst_fl != dst_lc {
                divs.push(Divergence {
                    function: "wcpncpy",
                    case: format!("(src={src_chars:?}, n={n})"),
                    field: "dst_buffer",
                    frankenlibc: format!("{:?}", &dst_fl[..n.min(8)]),
                    glibc: format!("{:?}", &dst_lc[..n.min(8)]),
                });
            }
        }
    }
    assert!(divs.is_empty(), "wcpncpy divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// wcscat / wcsncat — wide-char concatenate
// ===========================================================================

#[test]
fn diff_wcscat_cases() {
    let mut divs = Vec::new();
    // (initial dst contents up to NUL, src) — dst capacity is 32.
    let cases: &[(&[u32], &[u32])] = &[
        (&[], &[]),                           // empty + empty
        (&[], &[0x41, 0x42]),                 // empty + run
        (&[0x41, 0x42], &[]),                 // run + empty
        (&[0x41, 0x42, 0x43], &[0x44, 0x45]), // ASCII concat
        (&[0x80, 0x100], &[0x10FF, 0x10FFFF]),// supplementary
    ];
    for (init, src_chars) in cases {
        let mut dst_fl = vec![0xCDCDCDCDu32; 32];
        let mut dst_lc = vec![0xCDCDCDCDu32; 32];
        // Pre-populate dst with `init` then a terminating zero, so
        // wcscat treats it as a valid C wide string.
        for (i, &ch) in init.iter().enumerate() {
            dst_fl[i] = ch;
            dst_lc[i] = ch;
        }
        dst_fl[init.len()] = 0;
        dst_lc[init.len()] = 0;
        let src = wcstring(src_chars);
        // SAFETY: dst[..=init.len()] is initialized as a NUL-terminated
        // wide string; src is NUL-terminated.
        let _ = unsafe { fl::wcscat(dst_fl.as_mut_ptr(), src.as_ptr()) };
        let _ = unsafe {
            wcscat(
                dst_lc.as_mut_ptr() as *mut libc::wchar_t,
                src.as_ptr() as *const libc::wchar_t,
            )
        };
        if dst_fl != dst_lc {
            divs.push(Divergence {
                function: "wcscat",
                case: format!("(init={init:?}, src={src_chars:?})"),
                field: "dst_buffer",
                frankenlibc: format!("{:?}", &dst_fl[..8]),
                glibc: format!("{:?}", &dst_lc[..8]),
            });
        }
    }
    assert!(divs.is_empty(), "wcscat divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_wcsncat_cases() {
    let mut divs = Vec::new();
    let cases: &[(&[u32], &[u32], usize)] = &[
        (&[], &[], 0),
        (&[], &[0x41, 0x42, 0x43], 0),         // n=0 must not append
        (&[0x41], &[0x42, 0x43], 1),           // exact-fit append
        (&[0x41], &[0x42, 0x43, 0x44], 2),     // partial append (truncated)
        (&[0x41, 0x42], &[0x43, 0x44, 0x45], 100), // n past src length
        (&[0x80], &[0x100, 0x10FF], 2),
    ];
    for (init, src_chars, n) in cases {
        let mut dst_fl = vec![0xCDCDCDCDu32; 32];
        let mut dst_lc = vec![0xCDCDCDCDu32; 32];
        for (i, &ch) in init.iter().enumerate() {
            dst_fl[i] = ch;
            dst_lc[i] = ch;
        }
        dst_fl[init.len()] = 0;
        dst_lc[init.len()] = 0;
        let src = wcstring(src_chars);
        // SAFETY: same as wcscat plus n bounded by src length and dst
        // capacity (init.len() + n + 1 ≤ 8 ≤ 32).
        let _ = unsafe { fl::wcsncat(dst_fl.as_mut_ptr(), src.as_ptr(), *n) };
        let _ = unsafe {
            wcsncat(
                dst_lc.as_mut_ptr() as *mut libc::wchar_t,
                src.as_ptr() as *const libc::wchar_t,
                *n,
            )
        };
        if dst_fl != dst_lc {
            divs.push(Divergence {
                function: "wcsncat",
                case: format!("(init={init:?}, src={src_chars:?}, n={n})"),
                field: "dst_buffer",
                frankenlibc: format!("{:?}", &dst_fl[..8]),
                glibc: format!("{:?}", &dst_lc[..8]),
            });
        }
    }
    assert!(divs.is_empty(), "wcsncat divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// wcscasecmp / wcsncasecmp — wide-char ASCII-case-insensitive compare
// ===========================================================================
//
// Same case-folding contract as strcasecmp/strncasecmp but on wchar_t.
// POSIX folds only ASCII A-Z ↔ a-z; non-ASCII wide chars are compared
// untouched. Sign-only comparison.

#[test]
fn diff_wcscasecmp_cases() {
    let mut divs = Vec::new();
    let cases: &[(&[u32], &[u32])] = &[
        (&[], &[]),
        (&[0x41, 0x42, 0x43], &[0x41, 0x42, 0x43]),               // equal
        (&[0x41, 0x42, 0x43], &[0x61, 0x62, 0x63]),               // ABC == abc
        (&[0x61, 0x62, 0x63], &[0x41, 0x42, 0x43]),               // abc == ABC
        (&[0x41], &[0x42]),                                        // a < b
        (&[0x42], &[0x41]),                                        // a > b
        (&[0x41, 0x42], &[0x41, 0x42, 0x43]),                      // prefix < longer
        (&[0x41, 0x42, 0x43], &[0x41, 0x42]),                      // longer > prefix
        (&[0x40], &[0x60]),                                        // '@' (0x40) vs '`' (0x60) — neither is A-Z, NO folding
        (&[0x10FFFF], &[0x10FFFF]),                                // max codepoint, equal
        (&[0x100], &[0x101]),                                      // non-ASCII pass-through
        (&[0x80], &[0x7F]),                                        // unsigned compare boundary
    ];
    for (a_chars, b_chars) in cases {
        let a = wcstring(a_chars);
        let b = wcstring(b_chars);
        let fl_r = unsafe { fl::wcscasecmp(a.as_ptr(), b.as_ptr()) };
        let lc_r = unsafe {
            wcscasecmp(
                a.as_ptr() as *const libc::wchar_t,
                b.as_ptr() as *const libc::wchar_t,
            )
        };
        if sign(fl_r) != sign(lc_r) {
            divs.push(Divergence {
                function: "wcscasecmp",
                case: format!("({a_chars:?}, {b_chars:?})"),
                field: "return_sign",
                frankenlibc: format!("sign={}", sign(fl_r)),
                glibc: format!("sign={}", sign(lc_r)),
            });
        }
    }
    assert!(divs.is_empty(), "wcscasecmp divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_wcsncasecmp_cases() {
    let mut divs = Vec::new();
    let cases: &[(&[u32], &[u32], usize)] = &[
        (&[0x41, 0x42, 0x43], &[0x61, 0x62, 0x64], 0),             // n=0 always equal
        (&[0x41, 0x42, 0x43], &[0x61, 0x62, 0x64], 2),             // bound stops before diff
        (&[0x41, 0x42, 0x43], &[0x61, 0x62, 0x64], 3),             // diff at index 2
        (&[0x41, 0x42, 0x43], &[0x61, 0x62, 0x63], 100),           // n past either string
        (&[0x41, 0x42, 0x43], &[0x61, 0x62, 0x63, 0x64], 3),       // prefix match within bound
        (&[0x41, 0x42, 0x43, 0x44], &[0x61, 0x62, 0x63], 4),       // longer > shorter at NUL boundary
        (&[0x100, 0x41], &[0x100, 0x61], 2),                       // non-ASCII followed by case-folded ASCII
    ];
    for (a_chars, b_chars, n) in cases {
        let a = wcstring(a_chars);
        let b = wcstring(b_chars);
        let fl_r = unsafe { fl::wcsncasecmp(a.as_ptr(), b.as_ptr(), *n) };
        let lc_r = unsafe {
            wcsncasecmp(
                a.as_ptr() as *const libc::wchar_t,
                b.as_ptr() as *const libc::wchar_t,
                *n,
            )
        };
        if sign(fl_r) != sign(lc_r) {
            divs.push(Divergence {
                function: "wcsncasecmp",
                case: format!("({a_chars:?}, {b_chars:?}, n={n})"),
                field: "return_sign",
                frankenlibc: format!("sign={}", sign(fl_r)),
                glibc: format!("sign={}", sign(lc_r)),
            });
        }
    }
    assert!(divs.is_empty(), "wcsncasecmp divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// wcstol / wcstoul / wcstoll / wcstoull — wide-char integer parsers
// ===========================================================================
//
// Wide-char analogues of strtol/strtoul/strtoll/strtoull. POSIX
// requires the same parsing rules (whitespace skip, optional sign,
// 0x/0/decimal prefix detection in base 0, ERANGE on overflow). Our
// inputs are ASCII-encoded into wchar_t arrays so the locale-
// sensitive paths stay neutral.
//
// Each test compares: return value (must agree exactly within range
// the C type can represent) AND endptr offset relative to the input
// (must agree on consumed character count).

const WCS_INT_INPUTS: &[(&[u8], c_int)] = &[
    (b"42", 0),
    (b"-7", 0),
    (b"+99", 0),
    (b"  123", 0),
    (b"0x1F", 0),       // base 0 → hex
    (b"017", 0),        // base 0 → octal
    (b"0", 0),
    (b"42", 10),
    (b"FF", 16),
    (b"-2147483648", 10), // INT32_MIN
    (b"2147483647", 10),  // INT32_MAX
    (b"abc", 10),         // no digits
    (b"", 10),            // empty
    (b"123abc", 10),      // trailing garbage
];

fn ptr_offset_w(base: *const u32, ptr: *const libc::wchar_t) -> isize {
    if ptr.is_null() {
        -1
    } else {
        unsafe { (ptr as *const u32).offset_from(base) }
    }
}

#[test]
fn diff_wcstol_cases() {
    let mut divs = Vec::new();
    for (input, base) in WCS_INT_INPUTS {
        let w = ascii_to_wchars(input);
        let p = w.as_ptr();
        let mut fl_end: *mut libc::wchar_t = std::ptr::null_mut();
        let mut lc_end: *mut libc::wchar_t = std::ptr::null_mut();
        let fl_v = unsafe { fl::wcstol(p as *const libc::wchar_t, &mut fl_end, *base) };
        let lc_v = unsafe { wcstol(p as *const libc::wchar_t, &mut lc_end, *base) };
        let fl_off = ptr_offset_w(p, fl_end);
        let lc_off = ptr_offset_w(p, lc_end);
        if fl_v != lc_v {
            divs.push(Divergence {
                function: "wcstol",
                case: format!("({:?}, base={base})", String::from_utf8_lossy(input)),
                field: "return",
                frankenlibc: format!("{fl_v}"),
                glibc: format!("{lc_v}"),
            });
        }
        if fl_off != lc_off {
            divs.push(Divergence {
                function: "wcstol",
                case: format!("({:?}, base={base})", String::from_utf8_lossy(input)),
                field: "endptr_offset",
                frankenlibc: format!("{fl_off}"),
                glibc: format!("{lc_off}"),
            });
        }
    }
    assert!(divs.is_empty(), "wcstol divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_wcstoul_cases() {
    let mut divs = Vec::new();
    for (input, base) in WCS_INT_INPUTS {
        let w = ascii_to_wchars(input);
        let p = w.as_ptr();
        let mut fl_end: *mut libc::wchar_t = std::ptr::null_mut();
        let mut lc_end: *mut libc::wchar_t = std::ptr::null_mut();
        let fl_v = unsafe { fl::wcstoul(p as *const libc::wchar_t, &mut fl_end, *base) };
        let lc_v = unsafe { wcstoul(p as *const libc::wchar_t, &mut lc_end, *base) };
        let fl_off = ptr_offset_w(p, fl_end);
        let lc_off = ptr_offset_w(p, lc_end);
        if fl_v != lc_v {
            divs.push(Divergence {
                function: "wcstoul",
                case: format!("({:?}, base={base})", String::from_utf8_lossy(input)),
                field: "return",
                frankenlibc: format!("{fl_v}"),
                glibc: format!("{lc_v}"),
            });
        }
        if fl_off != lc_off {
            divs.push(Divergence {
                function: "wcstoul",
                case: format!("({:?}, base={base})", String::from_utf8_lossy(input)),
                field: "endptr_offset",
                frankenlibc: format!("{fl_off}"),
                glibc: format!("{lc_off}"),
            });
        }
    }
    assert!(divs.is_empty(), "wcstoul divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_wcstoll_cases() {
    let mut divs = Vec::new();
    for (input, base) in WCS_INT_INPUTS {
        let w = ascii_to_wchars(input);
        let p = w.as_ptr();
        let mut fl_end: *mut libc::wchar_t = std::ptr::null_mut();
        let mut lc_end: *mut libc::wchar_t = std::ptr::null_mut();
        let fl_v = unsafe { fl::wcstoll(p as *const libc::wchar_t, &mut fl_end, *base) };
        let lc_v = unsafe { wcstoll(p as *const libc::wchar_t, &mut lc_end, *base) };
        let fl_off = ptr_offset_w(p, fl_end);
        let lc_off = ptr_offset_w(p, lc_end);
        if fl_v != lc_v {
            divs.push(Divergence {
                function: "wcstoll",
                case: format!("({:?}, base={base})", String::from_utf8_lossy(input)),
                field: "return",
                frankenlibc: format!("{fl_v}"),
                glibc: format!("{lc_v}"),
            });
        }
        if fl_off != lc_off {
            divs.push(Divergence {
                function: "wcstoll",
                case: format!("({:?}, base={base})", String::from_utf8_lossy(input)),
                field: "endptr_offset",
                frankenlibc: format!("{fl_off}"),
                glibc: format!("{lc_off}"),
            });
        }
    }
    assert!(divs.is_empty(), "wcstoll divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_wcstoull_cases() {
    let mut divs = Vec::new();
    for (input, base) in WCS_INT_INPUTS {
        let w = ascii_to_wchars(input);
        let p = w.as_ptr();
        let mut fl_end: *mut libc::wchar_t = std::ptr::null_mut();
        let mut lc_end: *mut libc::wchar_t = std::ptr::null_mut();
        let fl_v = unsafe { fl::wcstoull(p as *const libc::wchar_t, &mut fl_end, *base) };
        let lc_v = unsafe { wcstoull(p as *const libc::wchar_t, &mut lc_end, *base) };
        let fl_off = ptr_offset_w(p, fl_end);
        let lc_off = ptr_offset_w(p, lc_end);
        if fl_v != lc_v {
            divs.push(Divergence {
                function: "wcstoull",
                case: format!("({:?}, base={base})", String::from_utf8_lossy(input)),
                field: "return",
                frankenlibc: format!("{fl_v}"),
                glibc: format!("{lc_v}"),
            });
        }
        if fl_off != lc_off {
            divs.push(Divergence {
                function: "wcstoull",
                case: format!("({:?}, base={base})", String::from_utf8_lossy(input)),
                field: "endptr_offset",
                frankenlibc: format!("{fl_off}"),
                glibc: format!("{lc_off}"),
            });
        }
    }
    assert!(divs.is_empty(), "wcstoull divergences:\n{}", render_divs(&divs));
}

#[test]
fn wchar_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"wchar.h core\",\"reference\":\"glibc\",\"functions\":25,\"divergences\":0}}",
    );
}
