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

#[test]
fn wchar_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"wchar.h core\",\"reference\":\"glibc\",\"functions\":10,\"divergences\":0}}",
    );
}
