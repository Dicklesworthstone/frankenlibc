#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strfmon_l oracle

//! Live GNU oracle for monetary layout, grouping, capacity and locale selection.
//! Each implementation owns its locale handles. Private LC_MONETARY fixtures
//! are compiled by localedef from self-contained character maps, so every sign
//! position and spacing rule runs even on a machine without installed locales.
//! The named matrix runs in isolated strict and hardened child processes.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::{Path, PathBuf};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

use frankenlibc_abi::{errno_abi, locale_abi as fll, string_abi, unistd_abi as flu};

type Strfmon = unsafe extern "C" fn(*mut c_char, usize, *const c_char, ...) -> isize;
type StrfmonL = unsafe extern "C" fn(*mut c_char, usize, *mut c_void, *const c_char, ...) -> isize;
type Newlocale = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> *mut c_void;
type Freelocale = unsafe extern "C" fn(*mut c_void);
type Uselocale = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type Setlocale = unsafe extern "C" fn(c_int, *const c_char) -> *const c_char;
type Errno = unsafe extern "C" fn() -> *mut c_int;

#[derive(Clone, Copy)]
struct Api {
    check_bounds: bool,
    plain: Strfmon,
    explicit: [StrfmonL; 2],
    newlocale: Newlocale,
    freelocale: Freelocale,
    uselocale: Uselocale,
    setlocale: Setlocale,
    errno: Errno,
}

fn native() -> Api {
    Api {
        check_bounds: true,
        plain: flu::strfmon,
        explicit: [flu::strfmon_l, string_abi::__strfmon_l],
        newlocale: fll::newlocale,
        freelocale: fll::freelocale,
        uselocale: fll::uselocale,
        setlocale: fll::setlocale,
        errno: errno_abi::__errno_location,
    }
}

fn host() -> Api {
    // Every oracle address is resolved independently and checked against the
    // corresponding native export; link-time aliases can otherwise self-compare.
    unsafe {
        use dlsym_oracle::host_fn;
        Api {
            check_bounds: false,
            plain: host_fn(c"strfmon", flu::strfmon as *const ()),
            explicit: [
                host_fn(c"strfmon_l", flu::strfmon_l as *const ()),
                host_fn(c"__strfmon_l", string_abi::__strfmon_l as *const ()),
            ],
            newlocale: host_fn(c"newlocale", fll::newlocale as *const ()),
            freelocale: host_fn(c"freelocale", fll::freelocale as *const ()),
            uselocale: host_fn(c"uselocale", fll::uselocale as *const ()),
            setlocale: host_fn(c"setlocale", fll::setlocale as *const ()),
            errno: host_fn(
                c"__errno_location",
                errno_abi::__errno_location as *const (),
            ),
        }
    }
}

fn new_locale(api: Api, mask: c_int, name: &CStr) -> *mut c_void {
    let locale = unsafe { (api.newlocale)(mask, name.as_ptr(), std::ptr::null_mut()) };
    assert!(
        !locale.is_null(),
        "newlocale({name:?}, {mask}): errno={}",
        unsafe { *(api.errno)() }
    );
    locale
}

/// Failure contents are unspecified. Successful results include their NUL,
/// and each native call checks the byte immediately past maxsize survived.
fn render(
    api: Api,
    explicit: Option<(usize, *mut c_void)>,
    fmt: &CStr,
    values: [f64; 2],
    maxsize: usize,
) -> (isize, c_int, Vec<u8>) {
    // GNU on the validation host writes spaces through offset 31 for C %18n
    // of 0.0 with maxsize 20, although it returns 18 with a correct terminator.
    // Give the independent oracle physical slack without changing its declared
    // capacity; preserve strict canary checks for every native call. This gate
    // compares GNU's monetary semantics, never reproduces its overwrite.
    let slack = if api.check_bounds { 1 } else { 4096 };
    let mut buffer = vec![0xa5; maxsize + slack];
    let (result, error) = unsafe {
        *(api.errno)() = 0;
        let pointer = buffer.as_mut_ptr().cast();
        let result = match explicit {
            Some((index, locale)) => {
                (api.explicit[index])(pointer, maxsize, locale, fmt.as_ptr(), values[0], values[1])
            }
            None => (api.plain)(pointer, maxsize, fmt.as_ptr(), values[0], values[1]),
        };
        (result, *(api.errno)())
    };
    if api.check_bounds {
        assert_eq!(buffer[maxsize], 0xa5, "{fmt:?}: wrote past {maxsize}");
    }
    if result < 0 {
        (result, error, Vec::new())
    } else {
        assert!(
            (result as usize) < maxsize,
            "{fmt:?}: missing terminator capacity"
        );
        assert_eq!(buffer[result as usize], 0, "{fmt:?}: missing terminator");
        (result, 0, buffer[..=result as usize].to_vec())
    }
}

fn run_glibc(fmt: &str, v: f64) -> (isize, Vec<u8>) {
    let cf = CString::new(fmt).unwrap();
    let api = host();
    unsafe {
        let loc = new_locale(api, libc::LC_ALL_MASK, c"C");
        let (n, _, bytes) = render(api, Some((0, loc)), &cf, [v, 0.0], 128);
        (api.freelocale)(loc);
        (n, bytes)
    }
}

fn run_fl(fmt: &str, v: f64) -> (isize, Vec<u8>) {
    let cf = CString::new(fmt).unwrap();
    let api = native();
    unsafe {
        let loc = new_locale(api, libc::LC_ALL_MASK, c"C");
        let (n, _, bytes) = render(api, Some((0, loc)), &cf, [v, 0.0], 128);
        (api.freelocale)(loc);
        (n, bytes)
    }
}

#[derive(Clone)]
struct Fixture {
    name: String,
    symbol: &'static str,
    international: &'static str,
    radix: &'static str,
    separator: &'static str,
    grouping: &'static str,
    positive: &'static str,
    negative: &'static str,
    frac: u8,
    int_frac: u8,
    // Currency-before, spacing, sign-position; national and international.
    layout: [[u8; 3]; 4],
}

fn fixtures() -> Vec<Fixture> {
    let base = Fixture {
        name: String::new(),
        symbol: "$",
        international: "XTS ",
        radix: ".",
        separator: ",",
        grouping: "3;3",
        positive: "",
        negative: "-",
        frac: 2,
        int_frac: 2,
        layout: [[1, 0, 1]; 4],
    };
    let mut result = Vec::new();
    for before in 0..=1 {
        for spacing in 0..=2 {
            for position in 0..=4 {
                result.push(Fixture {
                    name: format!("fl_money_{before}{spacing}{position}"),
                    layout: [[before, spacing, position]; 4],
                    ..base.clone()
                });
            }
        }
    }
    result.extend([
        Fixture {
            name: "fl_money_euro".into(),
            symbol: "<U20AC>",
            international: "EUR ",
            radix: ",",
            separator: "<U202F>",
            layout: [[0, 1, 1]; 4],
            ..base.clone()
        },
        Fixture {
            name: "fl_money_indian".into(),
            symbol: "<U20B9>",
            international: "INR ",
            grouping: "3;2",
            ..base.clone()
        },
        Fixture {
            name: "fl_money_yen".into(),
            symbol: "<UFFE5>",
            international: "JPY ",
            frac: 0,
            int_frac: 0,
            layout: [[1, 0, 4], [1, 0, 4], [1, 1, 4], [1, 1, 4]],
            ..base.clone()
        },
        Fixture {
            name: "fl_money_signed".into(),
            positive: "CR",
            negative: "DB",
            frac: 3,
            int_frac: 1,
            layout: [[0, 2, 3], [1, 2, 4], [1, 1, 2], [0, 1, 0]],
            ..base.clone()
        },
        Fixture {
            name: "fl_money_asymmetric".into(),
            symbol: "<U20AB>",
            international: "VND ",
            frac: 0,
            layout: [[0, 0, 1], [1, 0, 1], [0, 1, 2], [1, 1, 3]],
            ..base.clone()
        },
        Fixture {
            name: "fl_money_separator".into(),
            international: "USD_",
            positive: "CR",
            negative: "",
            layout: [[1, 2, 1], [1, 1, 4], [1, 2, 3], [0, 2, 4]],
            ..base.clone()
        },
        Fixture {
            name: "fl_money_stop".into(),
            grouping: "3;-1",
            ..base
        },
    ]);
    result
}

fn compile_fixtures() -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "frankenlibc-monetary-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    // No dependency on distribution locale sources or compressed charmaps.
    let mut charmap = String::from(
        "<code_set_name> UTF-8\n<escape_char> /\n<mb_cur_min> 1\n<mb_cur_max> 3\nCHARMAP\n",
    );
    for byte in 0..=127 {
        charmap.push_str(&format!("<U{byte:04X}> /x{byte:02x}\n"));
    }
    for scalar in ['\u{20ac}', '\u{202f}', '\u{20b9}', '\u{ffe5}', '\u{20ab}'] {
        let mut bytes = [0; 4];
        let encoded = scalar.encode_utf8(&mut bytes);
        charmap.push_str(&format!("<U{:04X}> ", scalar as u32));
        for byte in encoded.as_bytes() {
            charmap.push_str(&format!("/x{byte:02x}"));
        }
        charmap.push('\n');
    }
    charmap.push_str("END CHARMAP\n");
    let map = root.join("UTF-8.map");
    std::fs::write(&map, charmap).unwrap();
    for fixture in fixtures() {
        compile_fixture(&root, &map, &fixture);
    }
    root
}

fn compile_fixture(root: &Path, map: &Path, fixture: &Fixture) {
    let mut source = format!(
        "LC_MONETARY\nint_curr_symbol \"{}\"\ncurrency_symbol \"{}\"\n\
         mon_decimal_point \"{}\"\nmon_thousands_sep \"{}\"\nmon_grouping {}\n\
         positive_sign \"{}\"\nnegative_sign \"{}\"\nfrac_digits {}\nint_frac_digits {}\n",
        fixture.international,
        fixture.symbol,
        fixture.radix,
        fixture.separator,
        fixture.grouping,
        fixture.positive,
        fixture.negative,
        fixture.frac,
        fixture.int_frac,
    );
    for (prefix, fields) in ["p", "n", "int_p", "int_n"].into_iter().zip(fixture.layout) {
        for (field, value) in ["cs_precedes", "sep_by_space", "sign_posn"]
            .into_iter()
            .zip(fields)
        {
            source.push_str(&format!("{prefix}_{field} {value}\n"));
        }
    }
    source.push_str(
        "END LC_MONETARY\nLC_NUMERIC\ndecimal_point \",\"\nthousands_sep \".\"\n\
         grouping 3;3\nEND LC_NUMERIC\n",
    );
    let path = root.join(format!("{}.src", fixture.name));
    std::fs::write(&path, source).unwrap();
    let directory = root.join(&fixture.name);
    let output = std::process::Command::new("localedef")
        .args(["--no-archive", "-c", "-i"])
        .arg(path)
        .arg("-f")
        .arg(map)
        .arg(&directory)
        .output()
        .expect("monetary differential requires localedef");
    // localedef's warning status is expected for intentionally absent unrelated
    // categories. Both required categories must actually exist and later load
    // successfully through both implementations; a missing oracle never skips.
    assert!(
        matches!(output.status.code(), Some(0 | 1))
            && directory.join("LC_MONETARY").is_file()
            && directory.join("LC_NUMERIC").is_file(),
        "localedef {}: {}",
        fixture.name,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn strfmon_named_locales_match_glibc() {
    const CHILD: &str = "FRANKENLIBC_MONETARY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let root = compile_fixtures();
        for mode in ["strict", "hardened"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "strfmon_named_locales_match_glibc",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .env("FRANKENLIBC_MODE", mode)
                .env("LOCPATH", &root)
                .env("LC_ALL", "C")
                .env("LANG", "C")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{mode}:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "{mode}: monetary child executed no test"
            );
        }
        return;
    }
    let (gnu, fl) = (host(), native());
    let formats = [
        "%n",
        "%i",
        "%+n",
        "%^n",
        "%!n",
        "%!i",
        "%(n",
        "%(i",
        "%(!n",
        "%#6n",
        "%#6i",
        "%=*#6n",
        "%=*#6i",
        "%^#6n",
        "%!#6n",
        "%(!#6n",
        "%18n",
        "%-18i",
        "%=*18#6.4n",
        "%.0n",
        "%.4i",
        "%.1n",
        "cost: %n / %(i / 100%%",
        "%n%n",
        "%n %q",
        "%+(n",
        "%++n",
        "%#n",
    ];
    let values = [
        0.0,
        -0.0,
        12.34,
        -12.34,
        1234.567,
        -1234.567,
        1234567.89,
        0.005,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        -f64::NAN,
    ];
    let mut comparisons = 0;
    for fixture in fixtures() {
        let name = CString::new(fixture.name).unwrap();
        let gloc = new_locale(gnu, libc::LC_MONETARY_MASK, &name);
        let floc = new_locale(fl, libc::LC_MONETARY_MASK, &name);
        for format in formats {
            let format = CString::new(format).unwrap();
            for value in values {
                let pair = [value, -value];
                let expected = render(gnu, Some((0, gloc)), &format, pair, 512);
                for index in 0..2 {
                    let actual = render(fl, Some((index, floc)), &format, pair, 512);
                    assert_eq!(
                        actual, expected,
                        "{name:?}, alias={index}, {format:?}, {value:?}"
                    );
                    comparisons += 1;
                }
            }
        }
        // Buffer limits include every truncation point of a complete multibyte
        // symbol/separator sequence and two adjacent variadic conversions.
        for format in [c"%n", c"%i / %n", c"%=*18#6.4n"] {
            let pair = [-1234567.89, 12.34];
            let full = render(gnu, Some((0, gloc)), format, pair, 512).0;
            assert!(full > 0);
            for capacity in 0..=full as usize + 2 {
                let expected = render(gnu, Some((0, gloc)), format, pair, capacity);
                for index in 0..2 {
                    assert_eq!(
                        render(fl, Some((index, floc)), format, pair, capacity),
                        expected,
                        "{name:?}, alias={index}, {format:?}, capacity={capacity}"
                    );
                    comparisons += 1;
                }
            }
        }
        for format in [c"", c"%", c"%q", c"%%", c"x%q", c"%n %q"] {
            let expected = render(gnu, Some((0, gloc)), format, [1.0, 2.0], 0);
            for index in 0..2 {
                assert_eq!(
                    render(fl, Some((index, floc)), format, [1.0, 2.0], 0),
                    expected,
                    "{name:?}, alias={index}, zero capacity, {format:?}"
                );
                comparisons += 1;
            }
        }
        unsafe {
            (gnu.freelocale)(gloc);
            (fl.freelocale)(floc);
        }
    }
    assert!(comparisons > 20_000, "only {comparisons} comparisons ran");
    check_locale_selection(fl);
}

fn check_locale_selection(api: Api) {
    // These byte goldens were captured in an independent GNU-only process.
    // Keep global mutation native-only here: a dlsym host setlocale(LC_ALL)
    // still encounters interposed dependencies in an exported-ABI test binary.
    let c = new_locale(api, libc::LC_ALL_MASK, c"C");
    let dollar = new_locale(api, libc::LC_MONETARY_MASK, c"fl_money_101");
    let euro = new_locale(api, libc::LC_MONETARY_MASK, c"fl_money_euro");
    let numeric = new_locale(api, libc::LC_NUMERIC_MASK, c"fl_money_euro");
    let old = unsafe { (api.uselocale)(dollar) };
    assert!(!old.is_null());
    assert!(!unsafe { (api.setlocale)(libc::LC_MONETARY, c"fl_money_euro".as_ptr()) }.is_null());
    let mut rendered = Vec::new();
    rendered.push(render(api, None, c"%n", [1234.5, 0.0], 128));
    for locale in [euro, c, numeric] {
        for alias in 0..2 {
            rendered.push(render(
                api,
                Some((alias, locale)),
                c"%n",
                [1234.5, 0.0],
                128,
            ));
            assert_eq!(
                unsafe { (api.uselocale)(std::ptr::null_mut()) },
                dollar,
                "strfmon_l changed the caller's thread locale"
            );
        }
    }
    rendered.push(render(api, None, c"%n", [1234.5, 0.0], 128));
    unsafe {
        (api.uselocale)(usize::MAX as *mut c_void);
    }
    rendered.push(render(api, None, c"%n", [1234.5, 0.0], 128));
    assert_eq!(&rendered[0].2, b"$1,234.50\0");
    assert_eq!(&rendered[1].2, "1\u{202f}234,50 €\0".as_bytes());
    assert_eq!(&rendered[3].2, b"1234.50\0");
    assert_eq!(&rendered[5].2, b"1234,50\0");
    assert_eq!(rendered[0], rendered[7]);
    assert_eq!(rendered[1], rendered[8]);
    assert_eq!(rendered[1], rendered[2]);
    assert_eq!(rendered[3], rendered[4]);
    assert_eq!(rendered[5], rendered[6]);
    unsafe {
        // LC_MONETARY is the only process-global category this case
        // changes. Restore it directly; synthesizing a host LC_ALL name
        // while native symbols are interposed is unrelated to formatting.
        assert!(!(api.setlocale)(libc::LC_MONETARY, c"C".as_ptr()).is_null());
        (api.uselocale)(old);
        for locale in [c, dollar, euro, numeric] {
            (api.freelocale)(locale);
        }
    }
}

#[test]
fn strfmon_l_c_locale_matches_glibc() {
    let cases: &[(&str, f64)] = &[
        ("%n", 1234.567),
        ("%i", 1234.567),
        ("%n", -1234.567),
        ("%.2n", 9.999),
        ("%.0n", 12.5),
        ("%#6n", 5.0),
        ("%=*#6n", 12.34),
        ("%^n", 1000000.0),
        ("%(n", -42.0),
        ("%!n", 7.5),
        ("cost: %n done", 3.0),
    ];
    for &(fmt, v) in cases {
        let g = run_glibc(fmt, v);
        let f = run_fl(fmt, v);
        assert_eq!(
            f,
            g,
            "strfmon_l({fmt:?}, {v}): fl=({}, {:?}) glibc=({}, {:?})",
            f.0,
            String::from_utf8_lossy(&f.1),
            g.0,
            String::from_utf8_lossy(&g.1),
        );
    }
    let (gnu, fl) = (host(), native());
    let gloc = new_locale(gnu, libc::LC_ALL_MASK, c"C");
    let floc = new_locale(fl, libc::LC_ALL_MASK, c"C");
    for format in [c"", c"%n", c"%", c"%q", c"%%", c"x%q", c"%n %q"] {
        let expected = render(gnu, Some((0, gloc)), format, [1.0, 2.0], 0);
        for alias in 0..2 {
            assert_eq!(
                render(fl, Some((alias, floc)), format, [1.0, 2.0], 0),
                expected,
                "C locale zero capacity, alias={alias}, {format:?}"
            );
        }
    }
    unsafe {
        (gnu.freelocale)(gloc);
        (fl.freelocale)(floc);
    }
}

#[test]
fn strfmon_c_general_precision_and_bounds_match_glibc() {
    let (gnu, fl) = (host(), native());
    let gloc = new_locale(gnu, libc::LC_ALL_MASK, c"C");
    let floc = new_locale(fl, libc::LC_ALL_MASK, c"C");
    // Plain strfmon and both explicit aliases exercise the same generic path.
    let fold = unsafe { (fl.uselocale)(floc) };
    let calls = [None, Some((0, floc)), Some((1, floc))];

    // A legal precision beyond Rust's formatter limit used to abort through
    // the unbounded C fallback even with an adequately sized output buffer.
    let expected = render(gnu, Some((0, gloc)), c"%.100000n", [1.25, 0.0], 100003);
    assert_eq!(expected.0, 100002);
    assert_eq!(&expected.2[..4], b"1.25");
    assert!(expected.2[4..100002].iter().all(|&byte| byte == b'0'));
    for call in calls {
        assert_eq!(
            render(fl, call, c"%.100000n", [1.25, 0.0], 100003),
            expected
        );
    }

    // GNU's short-buffer handling can write outside its declared capacity;
    // never give its huge-precision formatter a small physical allocation.
    // The native path must reject these requests before allocating the field.
    for format in [c"%.100000n", c"%.1000000000n", c"%#1000000000n"] {
        for capacity in [0, 1, 16] {
            for call in calls {
                assert_eq!(
                    render(fl, call, format, [1.25, 0.0], capacity),
                    (-1, libc::E2BIG, Vec::new()),
                    "{format:?}, capacity={capacity}"
                );
            }
        }
    }
    for call in calls {
        assert_eq!(
            render(fl, call, c"%.100000n", [1.25, 0.0], 100002),
            (-1, libc::E2BIG, Vec::new()),
            "terminator must fit"
        );
    }

    for (format, values, capacity) in [
        (c"%.4n", [f64::INFINITY, 0.0], 64),
        (c"%.4n", [f64::NEG_INFINITY, 0.0], 64),
        (c"%#6.4n", [f64::NAN, 0.0], 64),
        (c"%#6.4n", [-f64::NAN, 0.0], 64),
        (c"%.4n", [-0.0, 0.0], 64),
        (c"%n %q", [-0.0, 0.0], 6),
        (c"%n %q", [-0.0, 0.0], 7),
        (c"%n %q", [0.0, 0.0], 6),
    ] {
        let expected = render(gnu, Some((0, gloc)), format, values, capacity);
        for call in calls {
            assert_eq!(
                render(fl, call, format, values, capacity),
                expected,
                "{format:?}, {values:?}, capacity={capacity}"
            );
        }
    }
    for capacity in 0..=48 {
        let format = c"%=*18#6.4n / %i";
        let values = [-1234.5, 2.5];
        let expected = render(gnu, Some((0, gloc)), format, values, capacity);
        for call in calls {
            assert_eq!(
                render(fl, call, format, values, capacity),
                expected,
                "multiple conversions, capacity={capacity}"
            );
        }
    }
    unsafe {
        (fl.uselocale)(fold);
        (gnu.freelocale)(gloc);
        (fl.freelocale)(floc);
    }
}
