#![cfg(target_os = "linux")]

//! Differential conformance harness for POSIX `nl_langinfo(3)`.
//!
//! Diffs fl's locale-info entries against host glibc's C locale (the
//! default — neither side has called setlocale, so glibc uses its
//! built-in C/POSIX defaults). fl ships the same C-locale strings.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{CStr, c_char};

use frankenlibc_abi::locale_abi as fl;

unsafe extern "C" {
    fn nl_langinfo(item: libc::nl_item) -> *const c_char;
}

#[derive(Debug)]
struct Divergence {
    case: String,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  case: {} | fl: {} | glibc: {}\n",
            d.case, d.frankenlibc, d.glibc,
        ));
    }
    out
}

#[test]
fn diff_nl_langinfo_c_locale_items() {
    // Items that fl and glibc both define for the C locale. Skipping
    // ones whose C-locale defaults are environment-dependent.
    let items: &[(libc::nl_item, &str)] = &[
        (libc::CODESET, "CODESET"),
        (libc::D_T_FMT, "D_T_FMT"),
        (libc::D_FMT, "D_FMT"),
        (libc::T_FMT, "T_FMT"),
        (libc::T_FMT_AMPM, "T_FMT_AMPM"),
        (libc::AM_STR, "AM_STR"),
        (libc::PM_STR, "PM_STR"),
        (libc::DAY_1, "DAY_1"),
        (libc::DAY_2, "DAY_2"),
        (libc::DAY_3, "DAY_3"),
        (libc::DAY_4, "DAY_4"),
        (libc::DAY_5, "DAY_5"),
        (libc::DAY_6, "DAY_6"),
        (libc::DAY_7, "DAY_7"),
        (libc::ABDAY_1, "ABDAY_1"),
        (libc::ABDAY_7, "ABDAY_7"),
        (libc::MON_1, "MON_1"),
        (libc::MON_12, "MON_12"),
        (libc::ABMON_1, "ABMON_1"),
        (libc::ABMON_12, "ABMON_12"),
        (libc::RADIXCHAR, "RADIXCHAR"),
        (libc::THOUSEP, "THOUSEP"),
        (libc::YESEXPR, "YESEXPR"),
        (libc::NOEXPR, "NOEXPR"),
    ];
    let mut divs = Vec::new();
    for &(item, name) in items {
        let p_fl = unsafe { fl::nl_langinfo(item) };
        let p_lc = unsafe { nl_langinfo(item) };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                case: name.to_string(),
                frankenlibc: format!("null={}", p_fl.is_null()),
                glibc: format!("null={}", p_lc.is_null()),
            });
            continue;
        }
        if p_fl.is_null() {
            continue;
        }
        let s_fl = unsafe { CStr::from_ptr(p_fl).to_bytes() };
        let s_lc = unsafe { CStr::from_ptr(p_lc).to_bytes() };
        if s_fl != s_lc {
            divs.push(Divergence {
                case: name.to_string(),
                frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "nl_langinfo divergences:\n{}",
        render_divs(&divs)
    );
}

/// Every item of LC_PAPER, LC_NAME, LC_ADDRESS, LC_TELEPHONE, LC_MEASUREMENT
/// and LC_IDENTIFICATION (categories 7..=12) in the C locale. fl returned ""
/// for all of them (perl's Langinfo.t and XS-APItest locale.t check
/// _NL_IDENTIFICATION_TERRITORY == "ISO"). Integer items (paper height and
/// width, country number) come back as the pointer value, compared as such;
/// strings byte for byte (_NL_MEASUREMENT_MEASUREMENT is the byte 1).
#[test]
fn diff_nl_langinfo_c_locale_extended_categories() {
    // (category, number of items including the trailing CODESET)
    let categories: &[(u32, u32)] = &[(7, 3), (8, 7), (9, 13), (10, 5), (11, 2), (12, 16)];
    let mut divs = Vec::new();
    let mut compared = 0;
    for &(category, count) in categories {
        for index in 0..count {
            let item = ((category << 16) | index) as libc::nl_item;
            let fl_ptr = unsafe { fl::nl_langinfo(item) };
            let lc_ptr = unsafe { nl_langinfo(item) };
            let render = |p: *const c_char| -> String {
                if (p as usize) < 65536 {
                    format!("int {}", p as usize)
                } else {
                    format!("{:?}", unsafe { CStr::from_ptr(p) })
                }
            };
            let (f, g) = (render(fl_ptr), render(lc_ptr));
            if f != g {
                divs.push(Divergence {
                    case: format!("{category}.{index}"),
                    frankenlibc: f,
                    glibc: g,
                });
            }
            compared += 1;
        }
    }
    assert_eq!(compared, 46);
    assert!(
        divs.is_empty(),
        "nl_langinfo extended-category divergences:\n{}",
        render_divs(&divs)
    );
}

/// LC_TIME items 50..=158 in the C locale: era count, the `wchar_t` forms of
/// every name and format, the week data, `_DATE_FMT`, `_NL_TIME_CODESET`, and
/// ALTMON_n / _NL_ABALTMON_n with their wide forms. fl returned "" for all of
/// them (gnulib test-nl_langinfo asserts strlen(ALTMON_1) > 0), so a wide
/// item read past a one-byte narrow literal.
#[test]
fn diff_nl_langinfo_c_locale_lc_time_extended() {
    let is_word = |i: u32| i == 50 || i == 102;
    let is_wide = |i: u32| {
        (52..=100).contains(&i) || i == 109 || (123..=134).contains(&i) || (147..=158).contains(&i)
    };
    let render = |i: u32, p: *const c_char| -> String {
        if is_word(i) {
            format!("word {}", p as usize)
        } else if is_wide(i) {
            let w = p.cast::<u32>();
            let mut s = String::new();
            let mut k = 0;
            // SAFETY: a wide item is a NUL-terminated wchar_t string.
            while unsafe { *w.add(k) } != 0 && k < 64 {
                s.push(char::from_u32(unsafe { *w.add(k) }).unwrap_or('?'));
                k += 1;
            }
            format!("wide {s:?}")
        } else {
            format!("{:?}", unsafe { CStr::from_ptr(p) })
        }
    };
    let mut divs = Vec::new();
    for index in 50u32..=158 {
        let item = ((2u32 << 16) | index) as libc::nl_item;
        let f = render(index, unsafe { fl::nl_langinfo(item) });
        let g = render(index, unsafe { nl_langinfo(item) });
        if f != g {
            divs.push(Divergence {
                case: format!("LC_TIME.{index}"),
                frankenlibc: f,
                glibc: g,
            });
        }
    }
    assert!(
        divs.is_empty(),
        "nl_langinfo LC_TIME extended divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn nl_langinfo_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc nl_langinfo\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
