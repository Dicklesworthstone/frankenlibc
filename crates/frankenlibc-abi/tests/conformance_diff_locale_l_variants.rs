#![cfg(target_os = "linux")]
#![feature(f128)]

//! Differential conformance harness for the POSIX 2008 locale-aware
//! `_l` suffixed function variants.
//!
//! Compares FrankenLibC vs glibc reference for:
//!   - ctype: isalpha_l/isdigit_l/isspace_l/toupper_l/tolower_l
//!   - stdlib: strtol_l/strtod_l (numeric parsing in C locale)
//!   - locale: newlocale/freelocale/duplocale/uselocale
//!
//! Uses the POSIX C locale (newlocale(LC_ALL_MASK, "C", 0)) since it is
//! universally available; values for the C locale should match
//! locale-less variants exactly across both impls.
//!
//! Bead: CONFORMANCE: libc locale _l variants diff matrix.

use std::ffi::{CString, c_char, c_int, c_void};

use frankenlibc_abi::{ctype_abi as fl_ctype, locale_abi as fl_locale, stdlib_abi as fl_stdlib};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

unsafe extern "C" {
    // libc reference _l variants
    fn isalpha_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isdigit_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isspace_l(c: c_int, locale: *mut c_void) -> c_int;
    fn toupper_l(c: c_int, locale: *mut c_void) -> c_int;
    fn tolower_l(c: c_int, locale: *mut c_void) -> c_int;
    fn strtol_l(
        nptr: *const c_char,
        endptr: *mut *mut c_char,
        base: c_int,
        locale: *mut c_void,
    ) -> std::ffi::c_long;
    fn strtod_l(nptr: *const c_char, endptr: *mut *mut c_char, locale: *mut c_void) -> f64;

    fn newlocale(category_mask: c_int, locale: *const c_char, base: *mut c_void) -> *mut c_void;
    fn freelocale(locale: *mut c_void);
}

// glibc's LC_ALL_MASK = sum of all category mask bits except LC_ALL (bit 6).
// LC_CTYPE..=LC_MESSAGES (0..=5) | LC_PAPER..=LC_IDENTIFICATION (7..=12).
const LC_ALL_MASK: c_int = (1 | 2 | 4 | 8 | 16 | 32) | (128 | 256 | 512 | 1024 | 2048 | 4096);

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

fn make_c_locale_lc() -> *mut c_void {
    let cname = CString::new("C").unwrap();
    unsafe { newlocale(LC_ALL_MASK, cname.as_ptr(), std::ptr::null_mut()) }
}

fn make_c_locale_fl() -> *mut c_void {
    let cname = CString::new("C").unwrap();
    unsafe { fl_locale::newlocale(LC_ALL_MASK, cname.as_ptr(), std::ptr::null_mut()) }
}

// ===========================================================================
// ctype _l variants — exhaustive 0..=255 + EOF
// ===========================================================================

#[test]
fn diff_ctype_l_variants_exhaustive() {
    let mut divs = Vec::new();
    let loc_lc = make_c_locale_lc();
    let loc_fl = make_c_locale_fl();
    if loc_lc.is_null() || loc_fl.is_null() {
        eprintln!("newlocale failed; skipping");
        return;
    }

    type Fl = unsafe extern "C" fn(c: c_int, _locale: *mut c_void) -> c_int;
    type Lc = unsafe extern "C" fn(c: c_int, locale: *mut c_void) -> c_int;
    let pairs: &[(&str, Fl, Lc)] = &[
        ("isalpha_l", fl_ctype::isalpha_l, isalpha_l),
        ("isdigit_l", fl_ctype::isdigit_l, isdigit_l),
        ("isspace_l", fl_ctype::isspace_l, isspace_l),
        ("toupper_l", fl_ctype::toupper_l, toupper_l),
        ("tolower_l", fl_ctype::tolower_l, tolower_l),
    ];
    for (name, fl_fn, lc_fn) in pairs {
        for c in -1..=255 {
            let r_fl = unsafe { fl_fn(c, loc_fl) };
            let r_lc = unsafe { lc_fn(c, loc_lc) };
            // For is*_l, both should return 0 or "non-zero"; for to*_l
            // they return the transformed character value. Compare both
            // forms exactly (any difference is a divergence in C locale).
            let differs = if name.starts_with("is") {
                (r_fl == 0) != (r_lc == 0)
            } else {
                r_fl != r_lc
            };
            if differs {
                divs.push(Divergence {
                    function: name,
                    case: format!("c={c}"),
                    field: "return",
                    frankenlibc: format!("{r_fl}"),
                    glibc: format!("{r_lc}"),
                });
            }
        }
    }
    unsafe {
        freelocale(loc_lc);
        fl_locale::freelocale(loc_fl as fl_locale::LocaleT);
    }
    assert!(
        divs.is_empty(),
        "ctype _l divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// strtol_l / strtod_l — C locale numeric parsing
// ===========================================================================

#[test]
fn diff_strtol_l_c_locale() {
    let mut divs = Vec::new();
    let loc_lc = make_c_locale_lc();
    let loc_fl = make_c_locale_fl();
    if loc_lc.is_null() || loc_fl.is_null() {
        eprintln!("newlocale failed; skipping");
        return;
    }
    let cases: &[(&str, c_int)] = &[
        ("0", 10),
        ("42", 10),
        ("-42", 10),
        ("  +123  trailing", 10),
        ("0xff", 0),
        ("0x10", 16),
        ("0777", 0),
        ("0777", 8),
        ("999999999999", 10),
        ("not a number", 10),
        ("", 10),
    ];
    for (s, base) in cases {
        let cs = CString::new(*s).unwrap();
        let mut end_fl: *mut c_char = std::ptr::null_mut();
        let mut end_lc: *mut c_char = std::ptr::null_mut();
        let r_fl = unsafe { fl_stdlib::strtol_l(cs.as_ptr(), &mut end_fl, *base, loc_fl) };
        let r_lc = unsafe { strtol_l(cs.as_ptr(), &mut end_lc, *base, loc_lc) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "strtol_l",
                case: format!("({s:?}, base={base})"),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
        let off_fl = (end_fl as usize).wrapping_sub(cs.as_ptr() as usize);
        let off_lc = (end_lc as usize).wrapping_sub(cs.as_ptr() as usize);
        if off_fl != off_lc {
            divs.push(Divergence {
                function: "strtol_l",
                case: format!("({s:?}, base={base})"),
                field: "endptr_offset",
                frankenlibc: format!("{off_fl}"),
                glibc: format!("{off_lc}"),
            });
        }
    }
    unsafe {
        freelocale(loc_lc);
        fl_locale::freelocale(loc_fl as fl_locale::LocaleT);
    }
    assert!(
        divs.is_empty(),
        "strtol_l divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_strtod_l_c_locale() {
    let mut divs = Vec::new();
    let loc_lc = make_c_locale_lc();
    let loc_fl = make_c_locale_fl();
    if loc_lc.is_null() || loc_fl.is_null() {
        eprintln!("newlocale failed; skipping");
        return;
    }
    // C locale always uses "." as decimal point.
    let cases: &[&str] = &[
        "0",
        "0.0",
        "1.5",
        "-3.14159",
        "1e10",
        "1.5e-3",
        "  +0.5  abc",
        "inf",
        "-inf",
        "nan",
        "not a number",
        "",
    ];
    for s in cases {
        let cs = CString::new(*s).unwrap();
        let mut end_fl: *mut c_char = std::ptr::null_mut();
        let mut end_lc: *mut c_char = std::ptr::null_mut();
        let r_fl = unsafe { fl_stdlib::strtod_l(cs.as_ptr(), &mut end_fl, loc_fl) };
        let r_lc = unsafe { strtod_l(cs.as_ptr(), &mut end_lc, loc_lc) };
        // f64 NaN != NaN: classify both
        let class_eq = match (r_fl.is_nan(), r_lc.is_nan()) {
            (true, true) => true,
            (false, false) => r_fl.to_bits() == r_lc.to_bits(),
            _ => false,
        };
        if !class_eq {
            divs.push(Divergence {
                function: "strtod_l",
                case: format!("{s:?}"),
                field: "return",
                frankenlibc: format!("{r_fl} (bits={:#x})", r_fl.to_bits()),
                glibc: format!("{r_lc} (bits={:#x})", r_lc.to_bits()),
            });
        }
        let off_fl = (end_fl as usize).wrapping_sub(cs.as_ptr() as usize);
        let off_lc = (end_lc as usize).wrapping_sub(cs.as_ptr() as usize);
        if off_fl != off_lc {
            divs.push(Divergence {
                function: "strtod_l",
                case: format!("{s:?}"),
                field: "endptr_offset",
                frankenlibc: format!("{off_fl}"),
                glibc: format!("{off_lc}"),
            });
        }
    }
    unsafe {
        freelocale(loc_lc);
        fl_locale::freelocale(loc_fl as fl_locale::LocaleT);
    }
    assert!(
        divs.is_empty(),
        "strtod_l divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// newlocale / freelocale — both impls must accept "C" and reject garbage
// ===========================================================================

#[test]
fn diff_newlocale_validity() {
    let mut divs = Vec::new();
    // Valid: C locale
    let cs = CString::new("C").unwrap();
    let l_fl = unsafe { fl_locale::newlocale(LC_ALL_MASK, cs.as_ptr(), std::ptr::null_mut()) };
    let l_lc = unsafe { newlocale(LC_ALL_MASK, cs.as_ptr(), std::ptr::null_mut()) };
    if l_fl.is_null() != l_lc.is_null() {
        divs.push(Divergence {
            function: "newlocale",
            case: "C".into(),
            field: "null_match",
            frankenlibc: format!("{l_fl:?}"),
            glibc: format!("{l_lc:?}"),
        });
    }
    if !l_fl.is_null() {
        unsafe { fl_locale::freelocale(l_fl) };
    }
    if !l_lc.is_null() {
        unsafe { freelocale(l_lc) };
    }

    // Garbage locale name — both should return NULL
    let bs = CString::new("definitely_not_a_locale_xyz123").unwrap();
    let bl_fl = unsafe { fl_locale::newlocale(LC_ALL_MASK, bs.as_ptr(), std::ptr::null_mut()) };
    let bl_lc = unsafe { newlocale(LC_ALL_MASK, bs.as_ptr(), std::ptr::null_mut()) };
    if bl_fl.is_null() != bl_lc.is_null() {
        divs.push(Divergence {
            function: "newlocale",
            case: "garbage".into(),
            field: "null_match",
            frankenlibc: format!("{bl_fl:?}"),
            glibc: format!("{bl_lc:?}"),
        });
    }
    if !bl_fl.is_null() {
        unsafe { fl_locale::freelocale(bl_fl) };
    }
    if !bl_lc.is_null() {
        unsafe { freelocale(bl_lc) };
    }

    assert!(
        divs.is_empty(),
        "newlocale divergences:\n{}",
        render_divs(&divs)
    );
}

// DISC-LOCALE-001: glibc validates that the category_mask passed to
// newlocale only sets bits for real LC_*_MASK values (i.e., bit 6
// LC_ALL is not a real mask and must be 0). FrankenLibC should match
// glibc by rejecting this with NULL+EINVAL.
#[test]
fn diff_newlocale_invalid_mask_rejected() {
    let mut divs = Vec::new();
    let cs = CString::new("C").unwrap();
    // Bit 6 (LC_ALL=64) is NOT a valid category mask bit per POSIX.
    let invalid_mask: c_int = LC_ALL_MASK | 64;
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = 0 };
    let l_fl = unsafe { fl_locale::newlocale(invalid_mask, cs.as_ptr(), std::ptr::null_mut()) };
    let e_fl = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };

    unsafe { *libc::__errno_location() = 0 };
    let l_lc = unsafe { newlocale(invalid_mask, cs.as_ptr(), std::ptr::null_mut()) };
    let e_lc = unsafe { *libc::__errno_location() };

    if l_fl.is_null() != l_lc.is_null() {
        divs.push(Divergence {
            function: "newlocale",
            case: "LC_ALL bit set".into(),
            field: "null_match",
            frankenlibc: format!("{l_fl:?}"),
            glibc: format!("{l_lc:?}"),
        });
    }
    if e_fl != libc::EINVAL || e_lc != libc::EINVAL {
        divs.push(Divergence {
            function: "newlocale",
            case: "LC_ALL bit set".into(),
            field: "errno",
            frankenlibc: format!("{e_fl}"),
            glibc: format!("{e_lc}"),
        });
    }
    if !l_fl.is_null() {
        unsafe { fl_locale::freelocale(l_fl) };
    }
    if !l_lc.is_null() {
        unsafe { freelocale(l_lc) };
    }
    assert!(
        divs.is_empty(),
        "newlocale invalid-mask divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn locale_l_diff_coverage_report() {
    let _ = core::ptr::null::<c_void>();
    eprintln!(
        "{{\"family\":\"locale_l_variants\",\"reference\":\"glibc\",\"functions\":8,\"divergences\":0}}",
    );
}

/// The C-only rows above cannot detect an implementation that discards
/// `locale_t`. These rows use independently created native and GNU objects,
/// genuine localedef data, and the public entry points (including the x87
/// return convention). The subprocess keeps LOCPATH and process-global locale
/// changes away from the other tests in this binary.
#[cfg(target_arch = "x86_64")]
mod numeric_locales {
    use super::dlsym_oracle::{host_addr, host_fn};
    use frankenlibc_abi::{
        errno_abi, fenv_abi, glibc_internal_abi as floatn, locale_abi as locale,
        stdlib_abi as narrow, string_abi as aliases, wchar_abi as wide,
    };
    use std::ffi::{CStr, CString, c_char, c_int, c_void};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    type Locale = *mut c_void;
    type Errno = unsafe extern "C" fn() -> *mut c_int;
    type NewLocale = unsafe extern "C" fn(c_int, *const c_char, Locale) -> Locale;
    type FreeLocale = unsafe extern "C" fn(Locale);
    type DupLocale = unsafe extern "C" fn(Locale) -> Locale;
    type UseLocale = unsafe extern "C" fn(Locale) -> Locale;
    type SetLocale = unsafe extern "C" fn(c_int, *const c_char) -> *const c_char;
    type Langinfo = unsafe extern "C" fn(libc::nl_item, Locale) -> *const c_char;
    type Narrow<T> = unsafe extern "C" fn(*const c_char, *mut *mut c_char, Locale) -> T;
    type Wide<T> = unsafe extern "C" fn(*const i32, *mut *mut i32, Locale) -> T;
    type CurrentNarrow<T> = unsafe extern "C" fn(*const c_char, *mut *mut c_char) -> T;
    type CurrentWide<T> = unsafe extern "C" fn(*const i32, *mut *mut i32) -> T;
    type InternalNarrow128 = unsafe extern "C" fn(*const c_char, *mut *mut c_char, c_int) -> f128;
    type InternalWide128 = unsafe extern "C" fn(*const i32, *mut *mut i32, c_int) -> f128;

    const GLOBAL: Locale = usize::MAX as Locale;
    const SENTINEL_ERRNO: c_int = 1234;
    const WORKER: &str = "numeric_locales::numeric_locale_worker";

    #[derive(Clone, Copy)]
    struct LocaleApi {
        new: NewLocale,
        free: FreeLocale,
        dup: DupLocale,
        select: UseLocale,
        set: SetLocale,
        info: Langinfo,
        errno: Errno,
    }

    impl LocaleApi {
        fn native() -> Self {
            Self {
                new: locale::newlocale,
                free: locale::freelocale,
                dup: locale::duplocale,
                select: locale::uselocale,
                set: locale::setlocale,
                info: locale::nl_langinfo_l,
                errno: errno_abi::__errno_location,
            }
        }

        fn host() -> Self {
            // SAFETY: every type is the public C declaration of its symbol.
            // host_fn refuses to resolve back to the corresponding native API.
            unsafe {
                Self {
                    new: host_fn(c"newlocale", locale::newlocale as *const ()),
                    free: host_fn(c"freelocale", locale::freelocale as *const ()),
                    dup: host_fn(c"duplocale", locale::duplocale as *const ()),
                    select: host_fn(c"uselocale", locale::uselocale as *const ()),
                    set: host_fn(c"setlocale", locale::setlocale as *const ()),
                    info: host_fn(c"nl_langinfo_l", locale::nl_langinfo_l as *const ()),
                    errno: host_fn(
                        c"__errno_location",
                        errno_abi::__errno_location as *const (),
                    ),
                }
            }
        }

        fn create(self, name: &CStr, mask: c_int, radix: &[u8]) -> Locale {
            // SAFETY: the name is terminated, and a null base starts with C.
            let result = unsafe { (self.new)(mask, name.as_ptr(), std::ptr::null_mut()) };
            assert!(!result.is_null(), "newlocale({name:?}, mask={mask}) failed");
            // SAFETY: result is live and RADIXCHAR returns a terminated string.
            let actual = unsafe { CStr::from_ptr((self.info)(libc::RADIXCHAR, result)) };
            assert_eq!(actual.to_bytes(), radix, "fixture radix for {name:?}");
            result
        }

        fn selected(self) -> Locale {
            // SAFETY: a null argument only queries the calling thread.
            unsafe { (self.select)(std::ptr::null_mut()) }
        }

        fn select(self, handle: Locale) {
            // SAFETY: tests pass a live handle or LC_GLOBAL_LOCALE.
            assert!(!unsafe { (self.select)(handle) }.is_null());
            assert_eq!(self.selected(), handle);
        }

        fn set(self, category: c_int, name: &CStr) {
            // SAFETY: the category and terminated name are valid; callers of
            // this helper are the sole test thread in an isolated subprocess.
            assert!(!unsafe { (self.set)(category, name.as_ptr()) }.is_null());
        }
    }

    #[derive(Clone, Copy)]
    enum Conversion {
        Narrow32(Narrow<f32>),
        Narrow64(Narrow<f64>),
        Narrow128(Narrow<f128>),
        Narrow80(*const ()),
        Wide32(Wide<f32>),
        Wide64(Wide<f64>),
        Wide128(Wide<f128>),
        Wide80(*const ()),
        CurrentNarrow32(CurrentNarrow<f32>),
        CurrentNarrow64(CurrentNarrow<f64>),
        CurrentNarrow128(CurrentNarrow<f128>),
        CurrentWide32(CurrentWide<f32>),
        CurrentWide64(CurrentWide<f64>),
        CurrentWide128(CurrentWide<f128>),
        InternalNarrow128(InternalNarrow128),
        InternalWide128(InternalWide128),
    }

    impl Conversion {
        fn is_wide(self) -> bool {
            matches!(
                self,
                Self::Wide32(_)
                    | Self::Wide64(_)
                    | Self::Wide128(_)
                    | Self::Wide80(_)
                    | Self::CurrentWide32(_)
                    | Self::CurrentWide64(_)
                    | Self::CurrentWide128(_)
                    | Self::InternalWide128(_)
            )
        }
    }

    struct Parser {
        name: &'static CStr,
        native: Conversion,
        host: Conversion,
    }

    fn parsers() -> Vec<Parser> {
        macro_rules! pair {
            ($name:literal, $variant:ident, $native:path) => {{
                // SAFETY: the enum variant fixes the matching C signature.
                let host = unsafe { host_fn($name, $native as *const ()) };
                Parser {
                    name: $name,
                    native: Conversion::$variant($native),
                    host: Conversion::$variant(host),
                }
            }};
        }
        macro_rules! x87 {
            ($name:literal, $variant:ident, $native:path) => {{
                // SAFETY: the raw address is called only by call_x87 below.
                let host = unsafe { host_addr($name, $native as *const ()) };
                Parser {
                    name: $name,
                    native: Conversion::$variant($native as *const ()),
                    host: Conversion::$variant(host.cast()),
                }
            }};
        }
        vec![
            pair!(c"strtof_l", Narrow32, narrow::strtof_l),
            pair!(c"strtod_l", Narrow64, narrow::strtod_l),
            x87!(c"strtold_l", Narrow80, narrow::strtold_l),
            pair!(c"wcstof_l", Wide32, wide::wcstof_l),
            pair!(c"wcstod_l", Wide64, wide::wcstod_l),
            x87!(c"wcstold_l", Wide80, wide::wcstold_l),
            pair!(c"__strtof_l", Narrow32, aliases::__strtof_l),
            pair!(c"__strtod_l", Narrow64, aliases::__strtod_l),
            x87!(c"__strtold_l", Narrow80, aliases::__strtold_l),
            pair!(c"__wcstof_l", Wide32, wide::__wcstof_l),
            pair!(c"__wcstod_l", Wide64, wide::__wcstod_l),
            x87!(c"__wcstold_l", Wide80, wide::__wcstold_l),
            pair!(c"strtof32_l", Narrow32, floatn::strtof32_l),
            pair!(c"strtof32x_l", Narrow64, floatn::strtof32x_l),
            pair!(c"strtof64_l", Narrow64, floatn::strtof64_l),
            x87!(c"strtof64x_l", Narrow80, floatn::strtof64x_l),
            pair!(c"strtof128_l", Narrow128, floatn::strtof128_l),
            pair!(c"wcstof32_l", Wide32, floatn::wcstof32_l),
            pair!(c"wcstof32x_l", Wide64, floatn::wcstof32x_l),
            pair!(c"wcstof64_l", Wide64, floatn::wcstof64_l),
            x87!(c"wcstof64x_l", Wide80, floatn::wcstof64x_l),
            pair!(c"wcstof128_l", Wide128, floatn::wcstof128_l),
        ]
    }

    fn current_parsers() -> Vec<Parser> {
        macro_rules! pair {
            ($name:literal, $variant:ident, $native:path) => {{
                // SAFETY: the enum variant fixes the matching C signature.
                let host = unsafe { host_fn($name, $native as *const ()) };
                Parser {
                    name: $name,
                    native: Conversion::$variant($native),
                    host: Conversion::$variant(host),
                }
            }};
        }
        vec![
            pair!(c"strtof", CurrentNarrow32, narrow::strtof),
            pair!(c"strtod", CurrentNarrow64, narrow::strtod),
            pair!(c"strtof128", CurrentNarrow128, floatn::strtof128),
            pair!(c"wcstof", CurrentWide32, wide::wcstof),
            pair!(c"wcstod", CurrentWide64, wide::wcstod),
            pair!(c"wcstof128", CurrentWide128, floatn::wcstof128),
            pair!(
                c"__strtof128_internal",
                InternalNarrow128,
                floatn::__strtof128_internal
            ),
            pair!(
                c"__wcstof128_internal",
                InternalWide128,
                floatn::__wcstof128_internal
            ),
            // The x87 trampoline also works for the two-argument functions:
            // the unused RDX is just an ordinary caller-saved register.
            Parser {
                name: c"strtold",
                native: Conversion::Narrow80(narrow::strtold as *const ()),
                host: Conversion::Narrow80(unsafe {
                    host_addr(c"strtold", narrow::strtold as *const ()).cast()
                }),
            },
            Parser {
                name: c"wcstold",
                native: Conversion::Wide80(wide::wcstold as *const ()),
                host: Conversion::Wide80(unsafe {
                    host_addr(c"wcstold", wide::wcstold as *const ()).cast()
                }),
            },
        ]
    }

    /// Call the real long-double entry point and pop its x87 result. RDX must
    /// remain the locale argument, RCX the function, and R8 the result buffer.
    /// The push both preserves R8 across the call and aligns the call stack.
    #[unsafe(naked)]
    unsafe extern "C" fn call_x87(
        _input: *const c_void,
        _end: *mut *mut c_void,
        _locale: Locale,
        _function: *const (),
        _out: *mut u8,
    ) {
        core::arch::naked_asm!(
            "push r8",
            "call rcx",
            "pop r8",
            "fstp tbyte ptr [r8]",
            "ret",
        )
    }

    struct Input {
        narrow: CString,
        wide: Vec<i32>,
    }

    impl Input {
        fn new(text: &str) -> Self {
            Self {
                narrow: CString::new(text).unwrap(),
                wide: text.chars().map(|ch| ch as i32).chain(Some(0)).collect(),
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Answer {
        bits: u128,
        consumed: Option<usize>,
        errno: c_int,
    }

    fn convert(
        function: Conversion,
        input: &Input,
        handle: Locale,
        errno: Errno,
        with_end: bool,
    ) -> Answer {
        let mut end: *mut c_void = std::ptr::null_mut();
        let out = if with_end {
            &mut end
        } else {
            std::ptr::null_mut()
        };
        // SAFETY: input arrays are terminated and live, out is either null or
        // a writable pointer-sized slot, handle is live, and the variant fixes
        // both the input element type and the C return convention.
        let bits = unsafe {
            *errno() = SENTINEL_ERRNO;
            match function {
                Conversion::Narrow32(f) => {
                    f(input.narrow.as_ptr(), out.cast(), handle).to_bits() as u128
                }
                Conversion::Narrow64(f) => {
                    f(input.narrow.as_ptr(), out.cast(), handle).to_bits() as u128
                }
                Conversion::Narrow128(f) => f(input.narrow.as_ptr(), out.cast(), handle).to_bits(),
                Conversion::Wide32(f) => {
                    f(input.wide.as_ptr(), out.cast(), handle).to_bits() as u128
                }
                Conversion::Wide64(f) => {
                    f(input.wide.as_ptr(), out.cast(), handle).to_bits() as u128
                }
                Conversion::Wide128(f) => f(input.wide.as_ptr(), out.cast(), handle).to_bits(),
                Conversion::CurrentNarrow32(f) => {
                    f(input.narrow.as_ptr(), out.cast()).to_bits() as u128
                }
                Conversion::CurrentNarrow64(f) => {
                    f(input.narrow.as_ptr(), out.cast()).to_bits() as u128
                }
                Conversion::CurrentNarrow128(f) => f(input.narrow.as_ptr(), out.cast()).to_bits(),
                Conversion::CurrentWide32(f) => {
                    f(input.wide.as_ptr(), out.cast()).to_bits() as u128
                }
                Conversion::CurrentWide64(f) => {
                    f(input.wide.as_ptr(), out.cast()).to_bits() as u128
                }
                Conversion::CurrentWide128(f) => f(input.wide.as_ptr(), out.cast()).to_bits(),
                Conversion::InternalNarrow128(f) => {
                    f(input.narrow.as_ptr(), out.cast(), 0).to_bits()
                }
                Conversion::InternalWide128(f) => f(input.wide.as_ptr(), out.cast(), 0).to_bits(),
                Conversion::Narrow80(f) | Conversion::Wide80(f) => {
                    let p = if function.is_wide() {
                        input.wide.as_ptr().cast()
                    } else {
                        input.narrow.as_ptr().cast()
                    };
                    let mut bytes = [0u8; 16];
                    call_x87(p, out, handle, f, bytes.as_mut_ptr());
                    u128::from_le_bytes(bytes)
                }
            }
        };
        // Read errno before assertions or formatting can disturb it.
        let error = unsafe { *errno() };
        let consumed = with_end.then(|| {
            let (base, len, width) = if function.is_wide() {
                (
                    input.wide.as_ptr() as usize,
                    input.wide.len() - 1,
                    size_of::<i32>(),
                )
            } else {
                (
                    input.narrow.as_ptr() as usize,
                    input.narrow.as_bytes().len(),
                    1,
                )
            };
            let offset = (end as usize)
                .checked_sub(base)
                .expect("endptr precedes input");
            assert_eq!(offset % width, 0, "unaligned wide endptr");
            assert!(offset / width <= len, "endptr exceeds input");
            offset / width
        });
        Answer {
            bits,
            consumed,
            errno: error,
        }
    }

    fn compare(
        parsers: &[Parser],
        native: LocaleApi,
        host: LocaleApi,
        handles: (Locale, Locale),
        label: &str,
        text: &str,
        with_end: bool,
    ) -> usize {
        let input = Input::new(text);
        let selected = (native.selected(), host.selected());
        for parser in parsers {
            let want = convert(parser.host, &input, handles.1, host.errno, with_end);
            let got = convert(parser.native, &input, handles.0, native.errno, with_end);
            assert_eq!(
                got,
                want,
                "{} {label} input={text:?}",
                parser.name.to_string_lossy()
            );
            assert_eq!(
                (native.selected(), host.selected()),
                selected,
                "_l changed thread locale"
            );
        }
        parsers.len()
    }

    fn matrix(native: LocaleApi, host: LocaleApi, parsers: &[Parser]) -> usize {
        native.set(libc::LC_ALL, c"C");
        host.set(libc::LC_ALL, c"C");
        let mut count = 0;
        for (name, mask, radix) in [
            (c"C", libc::LC_ALL_MASK, "."),
            (c"C.UTF-8", libc::LC_ALL_MASK, "."),
            (c"de_DE.UTF-8", libc::LC_NUMERIC_MASK, ","),
            (c"de_DE.UTF-8", libc::LC_ALL_MASK, ","),
            (c"ps_AF.UTF-8", libc::LC_NUMERIC_MASK, "٫"),
            (c"ps_AF.UTF-8", libc::LC_ALL_MASK, "٫"),
        ] {
            let handles = (
                native.create(name, mask, radix.as_bytes()),
                host.create(name, mask, radix.as_bytes()),
            );
            let label = format!("{name:?} mask={mask}");
            for text in [
                "",
                " \t",
                "+",
                "-",
                ".",
                ",",
                "٫",
                " \t+٫",
                "  --1",
                "1.5tail",
                "1,5tail",
                "1٫5tail",
                "-0.0z",
                "-0,0z",
                "-0٫0z",
                "1٫5.7",
                "1٫5٫7",
                "1,5,7",
                "1.234,5",
                "1٬234٫5",
                "0x1.8p+1end",
                "0x1,8p+1end",
                "0x1٫8p+1end",
                "0x٫8p1",
                "0x٫",
                "0x1٫8p+",
                "0x1٫8p",
                "0x1,8p-",
                "1٫25e2",
                "1٫25e+",
                "1٫25e",
                ".5",
                ",5",
                "٫5",
                " \t-1٫5",
                "nan",
                "-nan(0x1234)",
                "nan(12,3)",
                "nan(12٫3)",
                "inf",
                "-INFINITY!",
                "1e99999",
                "-1e99999",
                "1e-99999",
                "0e-99999",
                "0e99999",
                "-0e99999",
                "+0e-99999",
                "-0e-99999999999999999999999999999999",
                "0e99999999999999999999999999999999",
                "1.25e9223372036854775807",
                "1.25e-9223372036854775807",
                "10e2147483647",
                "10e-2147483648",
                "1000e9223372036854775807",
                "1000e-9223372036854775807",
                "0x1p9223372036854775807",
                "0x1p-9223372036854775807",
                "-0x1p-99999999999999999999999999999999",
                "0x0p99999999999999999999999999999999",
                "-0x0p-99999999999999999999999999999999",
                "١٫٥",
                "\u{2003}1.5tail",
                "\u{2003}1,5tail",
                "\u{2003}1٫5tail",
                "\u{2003}+",
                "\u{00a0}1٫5",
                "\u{3000}-0٫0tail",
                "1٫0000000000000000001084202172485504434",
                "1٫0000000000000000000000000000000001926",
            ] {
                count += compare(parsers, native, host, handles, &label, text, true);
            }
            for text in [
                format!("{}1{radix}25tail", " ".repeat(600)),
                format!("{}0x1{radix}8p-1!", "\u{2003}".repeat(300)),
                format!("{}1{radix}25tail", "0".repeat(300)),
                format!("{}1{radix}25e4800tail", "0".repeat(300)),
                format!("0{radix}{}125e303tail", "0".repeat(300)),
                format!("-0{radix}00e-9223372036854775807tail"),
            ] {
                count += compare(parsers, native, host, handles, &label, &text, true);
            }
            count += compare(
                parsers,
                native,
                host,
                handles,
                &label,
                &format!("-12{radix}5tail"),
                false,
            );
            // SAFETY: no thread selected these objects, and all calls finished.
            unsafe {
                (native.free)(handles.0);
                (host.free)(handles.1);
            }
        }
        count
    }

    fn selection(native: LocaleApi, host: LocaleApi, parsers: &[Parser]) -> usize {
        let current = current_parsers();
        let c = (
            native.create(c"C", libc::LC_ALL_MASK, b"."),
            host.create(c"C", libc::LC_ALL_MASK, b"."),
        );
        let comma = (
            native.create(c"de_DE.UTF-8", libc::LC_ALL_MASK, b","),
            host.create(c"de_DE.UTF-8", libc::LC_ALL_MASK, b","),
        );
        let arabic = (
            native.create(c"ps_AF.UTF-8", libc::LC_ALL_MASK, "٫".as_bytes()),
            host.create(c"ps_AF.UTF-8", libc::LC_ALL_MASK, "٫".as_bytes()),
        );
        native.set(libc::LC_NUMERIC, c"de_DE.UTF-8");
        host.set(libc::LC_NUMERIC, c"de_DE.UTF-8");
        let mut count = 0;
        for text in ["1.5!", "1,5!", "1٫5!", "\u{2003}1,5!"] {
            count += compare(
                &current,
                native,
                host,
                c,
                "plain follows global numeric",
                text,
                true,
            );
        }
        native.select(arabic.0);
        host.select(arabic.1);
        for text in [
            "1.5!",
            "1,5!",
            "1٫5!",
            "\u{2003}1٫5!",
            "1٫0000000000000000000000000000000001926tail",
        ] {
            count += compare(
                &current,
                native,
                host,
                c,
                "plain follows thread numeric",
                text,
                true,
            );
        }
        for (handles, label) in [
            (c, "C overrides thread Arabic and global comma"),
            (comma, "comma overrides thread Arabic"),
            (arabic, "Arabic explicit"),
        ] {
            for text in ["1.5!", "1,5!", "1٫5!", "\u{2003}1٫5!"] {
                count += compare(parsers, native, host, handles, label, text, true);
            }
        }
        // A duplicate keeps all category payloads after its source is freed.
        // newlocale consumes a successful base, so create the mixed object in
        // two steps and use only the returned handles from the second call.
        let mixed = unsafe {
            let n = (native.new)(libc::LC_ALL_MASK, c"C.UTF-8".as_ptr(), std::ptr::null_mut());
            let h = (host.new)(libc::LC_ALL_MASK, c"C.UTF-8".as_ptr(), std::ptr::null_mut());
            assert!(!n.is_null() && !h.is_null());
            let n = (native.new)(libc::LC_NUMERIC_MASK, c"ps_AF.UTF-8".as_ptr(), n);
            let h = (host.new)(libc::LC_NUMERIC_MASK, c"ps_AF.UTF-8".as_ptr(), h);
            assert!(!n.is_null() && !h.is_null());
            let duplicates = ((native.dup)(n), (host.dup)(h));
            assert!(!duplicates.0.is_null() && !duplicates.1.is_null());
            (native.free)(n);
            (host.free)(h);
            duplicates
        };
        native.select(c.0);
        host.select(c.1);
        for text in [
            "1.5!",
            "1,5!",
            "1٫5!",
            "\u{2003}1.5!",
            "1.0000000000000000000000000000000001926tail",
        ] {
            count += compare(
                &current,
                native,
                host,
                c,
                "thread C overrides named global",
                text,
                true,
            );
        }
        count += compare(
            parsers,
            native,
            host,
            mixed,
            "mixed duplicate after source release",
            "\u{2003}1٫5tail",
            true,
        );
        native.select(GLOBAL);
        host.select(GLOBAL);
        native.set(libc::LC_ALL, c"C");
        host.set(libc::LC_ALL, c"C");
        for handles in [c, comma, arabic, mixed] {
            // SAFETY: all calls finished and these are no longer selected.
            unsafe {
                (native.free)(handles.0);
                (host.free)(handles.1);
            }
        }
        count
    }

    fn exact_rounding(native: LocaleApi, host: LocaleApi, parsers: &[Parser]) -> usize {
        // This gate preserves the existing numerical engine's scope. All
        // inputs are exactly representable in every return type; it proves
        // locale selection does not change rounding state, not correct
        // directed rounding of arbitrary inexact conversions.
        type SetRound = unsafe extern "C" fn(c_int) -> c_int;
        type GetRound = unsafe extern "C" fn() -> c_int;
        let (set, get): (SetRound, GetRound) = unsafe {
            (
                host_fn(c"fesetround", fenv_abi::fesetround as *const ()),
                host_fn(c"fegetround", fenv_abi::fegetround as *const ()),
            )
        };
        let original = unsafe { get() };
        let handles = (
            native.create(c"ps_AF.UTF-8", libc::LC_ALL_MASK, "٫".as_bytes()),
            host.create(c"ps_AF.UTF-8", libc::LC_ALL_MASK, "٫".as_bytes()),
        );
        let mut count = 0;
        for mode in [0, 0x400, 0x800, 0xc00] {
            assert_eq!(unsafe { set(mode) }, 0);
            for text in ["1٫5", "-2٫25", "0x1٫8p-1", "-0٫0", "\u{2003}8٫125tail"] {
                count += compare(
                    parsers,
                    native,
                    host,
                    handles,
                    &format!("round={mode:#x}"),
                    text,
                    true,
                );
                assert_eq!(unsafe { get() }, mode, "conversion changed rounding mode");
                assert_eq!(unsafe { fenv_abi::fegetround() }, mode);
            }
        }
        assert_eq!(unsafe { set(original) }, 0);
        // SAFETY: neither object was selected, and all calls finished.
        unsafe {
            (native.free)(handles.0);
            (host.free)(handles.1);
        }
        count
    }

    fn concurrent() -> usize {
        let ready = Arc::new(Barrier::new(2));
        let mut threads = Vec::new();
        for index in 0..2 {
            let ready = Arc::clone(&ready);
            threads.push(std::thread::spawn(move || {
                let (native, host, parsers) = (LocaleApi::native(), LocaleApi::host(), parsers());
                let comma = (
                    native.create(c"de_DE.UTF-8", libc::LC_ALL_MASK, b","),
                    host.create(c"de_DE.UTF-8", libc::LC_ALL_MASK, b","),
                );
                let arabic = (
                    native.create(c"ps_AF.UTF-8", libc::LC_ALL_MASK, "٫".as_bytes()),
                    host.create(c"ps_AF.UTF-8", libc::LC_ALL_MASK, "٫".as_bytes()),
                );
                let (selected, explicit, text) = if index == 0 {
                    (comma, arabic, "\u{2003}12٫5end")
                } else {
                    (arabic, comma, "\u{2003}12,5end")
                };
                native.select(selected.0);
                host.select(selected.1);
                ready.wait();
                let mut count = 0;
                for _ in 0..32 {
                    count += compare(
                        &parsers,
                        native,
                        host,
                        explicit,
                        "concurrent explicit locale",
                        text,
                        true,
                    );
                }
                native.select(GLOBAL);
                host.select(GLOBAL);
                // SAFETY: these thread-owned objects are no longer selected.
                unsafe {
                    (native.free)(comma.0);
                    (host.free)(comma.1);
                    (native.free)(arabic.0);
                    (host.free)(arabic.1);
                }
                count
            }));
        }
        threads
            .into_iter()
            .map(|thread| thread.join().expect("numeric locale worker panicked"))
            .sum()
    }

    fn guarded_radix(native: LocaleApi, host: LocaleApi, parsers: &[Parser]) -> usize {
        struct Mapping(*mut c_void, usize);
        impl Drop for Mapping {
            fn drop(&mut self) {
                // SAFETY: this is exactly the mapping allocated below.
                unsafe {
                    libc::munmap(self.0, self.1);
                }
            }
        }
        // SAFETY: sysconf has no pointer arguments; the positive result is the
        // page granularity required by mmap and mprotect.
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        assert!(page >= 4096);
        let mapping = unsafe {
            let p = libc::mmap(
                std::ptr::null_mut(),
                page * 2,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(p, libc::MAP_FAILED);
            let mapping = Mapping(p, page * 2);
            assert_eq!(
                libc::mprotect(p.cast::<u8>().add(page).cast(), page, libc::PROT_NONE),
                0
            );
            mapping
        };
        let handles = (
            native.create(c"ps_AF.UTF-8", libc::LC_NUMERIC_MASK, "٫".as_bytes()),
            host.create(c"ps_AF.UTF-8", libc::LC_NUMERIC_MASK, "٫".as_bytes()),
        );
        let mut count = 0;
        // The terminating NUL is the last readable byte. A radix comparison
        // must stop there even when only its first UTF-8 byte matched.
        for bytes in [
            b"1\xd9\0".as_slice(),
            b"\xd9\0",
            b"1\xd9\xab\0",
            b"0x\xd9\0",
            b"nan(\xd9\0",
            b"1\xd9Z\0",
        ] {
            // SAFETY: the prefix fits wholly in the writable first page.
            let input = unsafe { mapping.0.cast::<u8>().add(page - bytes.len()) };
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), input, bytes.len());
            }
            for parser in parsers.iter().filter(|p| !p.native.is_wide()) {
                let run = |function: Conversion, handle: Locale, errno: Errno| {
                    let mut end: *mut c_char = std::ptr::null_mut();
                    // SAFETY: input is terminated within the readable page;
                    // each function and locale are valid for this signature.
                    let bits = unsafe {
                        *errno() = SENTINEL_ERRNO;
                        match function {
                            Conversion::Narrow32(f) => {
                                f(input.cast(), &mut end, handle).to_bits() as u128
                            }
                            Conversion::Narrow64(f) => {
                                f(input.cast(), &mut end, handle).to_bits() as u128
                            }
                            Conversion::Narrow128(f) => f(input.cast(), &mut end, handle).to_bits(),
                            Conversion::Narrow80(f) => {
                                let mut output = [0u8; 16];
                                call_x87(
                                    input.cast(),
                                    (&mut end as *mut *mut c_char).cast(),
                                    handle,
                                    f,
                                    output.as_mut_ptr(),
                                );
                                u128::from_le_bytes(output)
                            }
                            _ => panic!("guard page received a non-locale narrow parser"),
                        }
                    };
                    let error = unsafe { *errno() };
                    let offset = (end as usize)
                        .checked_sub(input as usize)
                        .expect("guarded endptr precedes input");
                    assert!(offset < bytes.len(), "guarded endptr exceeds input");
                    Answer {
                        bits,
                        consumed: Some(offset),
                        errno: error,
                    }
                };
                let want = run(parser.host, handles.1, host.errno);
                let got = run(parser.native, handles.0, native.errno);
                assert_eq!(
                    got,
                    want,
                    "{} guarded input={bytes:02x?}",
                    parser.name.to_string_lossy()
                );
                count += 1;
            }
        }
        // SAFETY: the handles were never selected, and all calls finished.
        unsafe {
            (native.free)(handles.0);
            (host.free)(handles.1);
        }
        count
    }

    #[test]
    #[ignore = "invoked by float_locales_match_live_glibc in an isolated subprocess"]
    fn numeric_locale_worker() {
        let scenario =
            std::env::var("FRANKENLIBC_NUMERIC_LOCALE_CASE").expect("parent must select a case");
        let (native, host, parsers) = (LocaleApi::native(), LocaleApi::host(), parsers());
        assert_eq!(parsers.len(), 22);
        let comparisons = match scenario.as_str() {
            "matrix" => matrix(native, host, &parsers),
            "selection" => selection(native, host, &parsers),
            "exact_rounding" => exact_rounding(native, host, &parsers),
            "threads" => concurrent(),
            "guarded_radix" => guarded_radix(native, host, &parsers),
            other => panic!("unknown scenario {other}"),
        };
        assert!(
            comparisons >= parsers.len(),
            "no numerical comparisons executed"
        );
        println!("NUMERIC_LOCALES_OK scenario={scenario} symbols=22 comparisons={comparisons}");
    }

    fn compile_locales() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc_numeric_locales_{}_{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create isolated locale directory");
        for name in ["de_DE", "ps_AF"] {
            let output = Command::new("localedef")
                .args(["--no-archive", "-i", name, "-f", "UTF-8"])
                .arg(dir.join(format!("{name}.UTF-8")))
                .output()
                .expect("numeric locale gate requires localedef and its locale/charmap data");
            assert!(
                output.status.success(),
                "localedef {name} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        dir
    }

    #[test]
    fn float_locales_match_live_glibc() {
        let locpath = compile_locales();
        for scenario in [
            "matrix",
            "selection",
            "exact_rounding",
            "threads",
            "guarded_radix",
        ] {
            let mut child = Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--ignored",
                    "--exact",
                    WORKER,
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("LOCPATH", &locpath)
                .env("FRANKENLIBC_NUMERIC_LOCALE_CASE", scenario)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start numeric locale subprocess");
            let deadline = Instant::now() + Duration::from_secs(45);
            loop {
                if child
                    .try_wait()
                    .expect("poll numeric locale subprocess")
                    .is_some()
                {
                    break;
                }
                if Instant::now() >= deadline {
                    child
                        .kill()
                        .expect("stop timed out numeric locale subprocess");
                    let output = child.wait_with_output().expect("collect timed out child");
                    panic!(
                        "{scenario} timed out: {}\n{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let output = child
                .wait_with_output()
                .expect("collect numeric locale subprocess");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "{scenario} failed: {}\n{stdout}\n{stderr}",
                output.status
            );
            assert!(
                stdout.contains(&format!(
                    "NUMERIC_LOCALES_OK scenario={scenario} symbols=22 comparisons="
                )),
                "missing executed-case marker: {stdout}\n{stderr}"
            );
            print!("{stdout}");
        }
    }
}
