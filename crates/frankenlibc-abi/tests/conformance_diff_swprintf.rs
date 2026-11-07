#![cfg(target_os = "linux")]
//! Differential conformance for `swprintf` vs glibc, focused on the
//! wide-specific paths: `%ls`/`%S` (wide-string) and `%lc`/`%C` (wide-char)
//! conversions, width/precision semantics (precision counts WIDE characters,
//! not bytes), and non-ASCII literal text in the format. The numeric/narrow
//! conversions are inherited from the shared render core (covered elsewhere).

use std::ffi::c_int;

use frankenlibc_abi::wchar_abi as fl;

type Wc = libc::wchar_t;

unsafe extern "C" {
    fn swprintf(s: *mut Wc, n: usize, format: *const Wc, ...) -> c_int;
}

fn wfmt(s: &str) -> Vec<Wc> {
    let mut v: Vec<Wc> = s.chars().map(|c| c as u32 as Wc).collect();
    v.push(0);
    v
}

fn wstr(s: &str) -> Vec<Wc> {
    let mut v: Vec<Wc> = s.chars().map(|c| c as u32 as Wc).collect();
    v.push(0);
    v
}

fn used(buf: &[Wc], n: c_int) -> Vec<Wc> {
    if n < 0 {
        return Vec::new();
    }
    buf[..(n as usize).min(buf.len())].to_vec()
}

#[test]
fn diff_swprintf_more_than_32_integer_arguments() {
    let sequential = std::iter::repeat_n("%02d", 40)
        .collect::<Vec<_>>()
        .join(":");
    let positional = (1..=40)
        .rev()
        .map(|position| format!("%{position}$02d"))
        .collect::<Vec<_>>()
        .join(":");
    for format in [sequential, positional] {
        let format = wfmt(&format);
        for capacity in [1, 17, 119, 120, 256] {
            let mut native = [0x5a5a; 256];
            let mut host = [0x5a5a; 256];
            macro_rules! render {
                ($function:path, $buffer:expr) => {
                    // SAFETY: the forty directives match promoted integer
                    // arguments and capacity fits each wchar_t buffer.
                    unsafe {
                        $function(
                            $buffer.as_mut_ptr(),
                            capacity,
                            format.as_ptr(),
                            1,
                            2,
                            3,
                            4,
                            5,
                            6,
                            7,
                            8,
                            9,
                            10,
                            11,
                            12,
                            13,
                            14,
                            15,
                            16,
                            17,
                            18,
                            19,
                            20,
                            21,
                            22,
                            23,
                            24,
                            25,
                            26,
                            27,
                            28,
                            29,
                            30,
                            31,
                            32,
                            33,
                            34,
                            35,
                            36,
                            37,
                            38,
                            39,
                            40,
                        )
                    }
                };
            }
            assert_eq!(render!(fl::swprintf, native), render!(swprintf, host));
            assert_eq!(native, host, "capacity={capacity}");
        }
    }
}

#[test]
fn diff_swprintf_mixed_arguments_after_32() {
    for count_store in [false, true] {
        let mut text = "%02d:".repeat(30);
        text.push_str("%*.*f|%s|%ld");
        if count_store {
            text.push_str("%n");
        }
        let format = wfmt(&text);
        let mut native = [0x5a5a; 256];
        let mut host = [0x5a5a; 256];
        let mut native_count = -1;
        let mut host_count = -1;
        macro_rules! render {
            ($function:path, $buffer:expr, $count:expr) => {
                // SAFETY: the format matches the promoted integers, double,
                // narrow C string, LP64 long and optional writable count.
                unsafe {
                    $function(
                        $buffer.as_mut_ptr(),
                        $buffer.len(),
                        format.as_ptr(),
                        1,
                        2,
                        3,
                        4,
                        5,
                        6,
                        7,
                        8,
                        9,
                        10,
                        11,
                        12,
                        13,
                        14,
                        15,
                        16,
                        17,
                        18,
                        19,
                        20,
                        21,
                        22,
                        23,
                        24,
                        25,
                        26,
                        27,
                        28,
                        29,
                        30,
                        -7,
                        2,
                        3.25f64,
                        c"tail".as_ptr(),
                        -4294967297 as libc::c_long,
                        &mut $count as *mut c_int,
                    )
                }
            };
        }
        let actual = render!(fl::swprintf, native, native_count);
        let expected = render!(swprintf, host, host_count);
        assert!(expected > 100);
        assert_eq!(actual, expected);
        assert_eq!(native, host);
        assert_eq!(native_count, host_count);
        assert_eq!(native_count, if count_store { expected } else { -1 });
    }
}

#[test]
fn swprintf_rejects_unrepresentable_argument_positions_before_allocation() {
    for text in [
        "%2147483648$d",
        "%18446744073709551616$d",
        "%1$*2147483648$d",
    ] {
        let format = wfmt(text);
        let mut output = [0x5a5a; 16];
        // SAFETY: the invalid index must be rejected before argument access.
        unsafe {
            *frankenlibc_abi::errno_abi::__errno_location() = 0;
            assert_eq!(
                fl::swprintf(output.as_mut_ptr(), output.len(), format.as_ptr()),
                -1
            );
            assert_eq!(
                *frankenlibc_abi::errno_abi::__errno_location(),
                libc::EOVERFLOW
            );
        }
    }
}

/// Compare swprintf(fmt, wide_string_arg) between frankenlibc and glibc.
fn check_ls(fmt: &str, arg: &str, divs: &mut Vec<String>) {
    let f = wfmt(fmt);
    let a = wstr(arg);
    let mut fb = vec![0 as Wc; 128];
    let mut lb = vec![0 as Wc; 128];
    let fn_ = unsafe { fl::swprintf(fb.as_mut_ptr(), 128, f.as_ptr(), a.as_ptr()) };
    let ln_ = unsafe { swprintf(lb.as_mut_ptr(), 128, f.as_ptr(), a.as_ptr()) };
    let fs = used(&fb, fn_);
    let ls = used(&lb, ln_);
    if fn_ != ln_ || fs != ls {
        let to_s = |v: &[Wc]| -> String {
            v.iter()
                .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
                .collect()
        };
        divs.push(format!(
            "  swprintf fmt={fmt:?} arg={arg:?}: fl=(n={fn_}, {:?}) glibc=(n={ln_}, {:?})",
            to_s(&fs),
            to_s(&ls)
        ));
    }
}

#[test]
fn diff_swprintf_wide_string() {
    let mut divs = Vec::new();
    // ASCII wide strings.
    check_ls("%ls", "hello", &mut divs);
    check_ls("%.3ls", "hello", &mut divs);
    check_ls("%10ls|", "hi", &mut divs);
    check_ls("%-10ls|", "hi", &mut divs);
    check_ls("%5.3ls", "hello", &mut divs);
    // %S is the SVID alias for %ls.
    check_ls("%S", "wide", &mut divs);
    check_ls("%.2S", "héllo", &mut divs);
    check_ls("%8S|", "ok", &mut divs);
    // Multibyte wide strings — precision must count WIDE chars, not UTF-8 bytes.
    check_ls("%.3ls", "héllo", &mut divs); // -> "hél" (3 wide), NOT byte-cut "hé"
    check_ls("%.2ls", "αβγδ", &mut divs); // -> "αβ"
    check_ls("%ls", "café—ok", &mut divs); // em dash + accent passthrough
    check_ls("%.1ls", "日本語", &mut divs); // -> "日"
    check_ls("%6.2ls|", "αβγ", &mut divs); // width pads to 6 wide cols
    assert!(
        divs.is_empty(),
        "swprintf %ls divergences:\n{}",
        divs.join("\n")
    );
}

#[test]
fn diff_swprintf_nonascii_literal_and_numeric() {
    let mut divs = Vec::new();
    // Non-ASCII literal text in the format around a numeric conversion.
    let cases: &[(&str, i32)] = &[
        ("αβγ=%d", 42),
        ("price: %d€", 7),
        ("%05d日", -3),
        ("[%+d]", 9),
    ];
    for (fmt, val) in cases {
        let f = wfmt(fmt);
        let mut fb = vec![0 as Wc; 128];
        let mut lb = vec![0 as Wc; 128];
        let fn_ = unsafe { fl::swprintf(fb.as_mut_ptr(), 128, f.as_ptr(), *val) };
        let ln_ = unsafe { swprintf(lb.as_mut_ptr(), 128, f.as_ptr(), *val) };
        let fs = used(&fb, fn_);
        let ls = used(&lb, ln_);
        if fn_ != ln_ || fs != ls {
            let to_s = |v: &[Wc]| -> String {
                v.iter()
                    .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
                    .collect()
            };
            divs.push(format!(
                "  swprintf fmt={fmt:?} val={val}: fl=(n={fn_}, {:?}) glibc=(n={ln_}, {:?})",
                to_s(&fs),
                to_s(&ls)
            ));
        }
    }
    assert!(
        divs.is_empty(),
        "swprintf literal/numeric divergences:\n{}",
        divs.join("\n")
    );
}

/// Compare swprintf(fmt, wide_char_arg) between frankenlibc and glibc.
/// The %lc / %C argument is a `wint_t` (passed as `c_int` in the varargs).
fn check_lc(fmt: &str, wc: u32, divs: &mut Vec<String>) {
    let f = wfmt(fmt);
    let mut fb = vec![0 as Wc; 64];
    let mut lb = vec![0 as Wc; 64];
    let fn_ = unsafe { fl::swprintf(fb.as_mut_ptr(), 64, f.as_ptr(), wc as c_int) };
    let ln_ = unsafe { swprintf(lb.as_mut_ptr(), 64, f.as_ptr(), wc as c_int) };
    let fs = used(&fb, fn_);
    let ls = used(&lb, ln_);
    if fn_ != ln_ || fs != ls {
        let to_s = |v: &[Wc]| -> String {
            v.iter()
                .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
                .collect()
        };
        divs.push(format!(
            "  swprintf fmt={fmt:?} wc={wc:#x}: fl=(n={fn_}, {:?}) glibc=(n={ln_}, {:?})",
            to_s(&fs),
            to_s(&ls)
        ));
    }
}

#[test]
fn diff_swprintf_wide_char() {
    let mut divs = Vec::new();
    check_lc("%lc", 'A' as u32, &mut divs);
    check_lc("%lc", 0x00E9, &mut divs); // é
    check_lc("%lc", 0x4E2D, &mut divs); // 中
    check_lc("%lc", 0x1F600, &mut divs); // 😀
    check_lc("%5lc|", 'x' as u32, &mut divs);
    check_lc("%-5lc|", 0x00E9, &mut divs);
    check_lc("%C", 0x4E2D, &mut divs); // SVID alias
    assert!(
        divs.is_empty(),
        "swprintf %lc divergences:\n{}",
        divs.join("\n")
    );
}

#[test]
fn diff_swprintf_mixed_wide_only_conversions() {
    let format = wfmt("label=%lc:%ls:%05d");
    let wide_arg = wstr("日本");
    let mut fb = vec![0 as Wc; 128];
    let mut lb = vec![0 as Wc; 128];
    let fl_n = unsafe {
        fl::swprintf(
            fb.as_mut_ptr(),
            fb.len(),
            format.as_ptr(),
            'é' as c_int,
            wide_arg.as_ptr(),
            -3i32,
        )
    };
    let libc_n = unsafe {
        swprintf(
            lb.as_mut_ptr(),
            lb.len(),
            format.as_ptr(),
            'é' as c_int,
            wide_arg.as_ptr(),
            -3i32,
        )
    };

    assert_eq!(fl_n, libc_n);
    assert_eq!(used(&fb, fl_n), used(&lb, libc_n));
}
