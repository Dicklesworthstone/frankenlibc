#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcstoimax/wcstoumax oracle

//! Differential gate for wide intmax parsers wcstoimax/wcstoumax (bd-sc6pfb) —
//! previously uncovered (the wcstol-family fuzz covers wcstol/ll/ul/ull but not
//! these). For each wide input + base, fl must match host glibc on the value,
//! the endptr consumed-length (in wide chars), and errno (ERANGE on overflow).
//! No mocks.

use std::ffi::c_int;

use libc::wchar_t;

#[cfg(target_arch = "x86_64")]
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

#[test]
#[cfg(target_arch = "x86_64")]
fn wide_signed_integer_contract() {
    wide_integer_contract(false, false);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn wide_unsigned_integer_contract() {
    wide_integer_contract(true, false);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn wide_signed_scan_window_contract() {
    wide_integer_contract(false, true);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn wide_unsigned_scan_window_contract() {
    wide_integer_contract(true, true);
}

#[cfg(target_arch = "x86_64")]
fn wide_integer_contract(unsigned: bool, window: bool) {
    use frankenlibc_abi::{errno_abi as errno, isoc_abi as c23, locale_abi, wchar_abi as fl};
    use std::ffi::{CStr, c_char, c_void};

    type Signed = unsafe extern "C" fn(*const wchar_t, *mut *mut wchar_t, c_int) -> i64;
    type Unsigned = unsafe extern "C" fn(*const wchar_t, *mut *mut wchar_t, c_int) -> u64;
    type SignedL =
        unsafe extern "C" fn(*const wchar_t, *mut *mut wchar_t, c_int, *mut c_void) -> i64;
    type UnsignedL =
        unsafe extern "C" fn(*const wchar_t, *mut *mut wchar_t, c_int, *mut c_void) -> u64;
    type Error = unsafe extern "C" fn() -> *mut c_int;
    type NewLocale = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> *mut c_void;
    type FreeLocale = unsafe extern "C" fn(*mut c_void);
    struct Locale {
        pointer: *mut c_void,
        free: FreeLocale,
    }
    impl Drop for Locale {
        fn drop(&mut self) {
            if !self.pointer.is_null() {
                // SAFETY: each non-null locale is paired with its creating provider.
                unsafe { (self.free)(self.pointer) };
            }
        }
    }
    #[repr(C)]
    struct End {
        before: usize,
        pointer: *mut wchar_t,
        after: usize,
    }
    let entries: [(&CStr, *const (), bool); 10] = if unsigned {
        [
            (c"wcstoul", fl::wcstoul as *const (), false),
            (c"wcstoull", fl::wcstoull as *const (), false),
            (c"wcstoumax", fl::wcstoumax as *const (), false),
            (c"wcstoul_l", fl::wcstoul_l as *const (), true),
            (c"wcstoull_l", fl::wcstoull_l as *const (), true),
            (
                c"__isoc23_wcstoul",
                c23::__isoc23_wcstoul as *const (),
                false,
            ),
            (
                c"__isoc23_wcstoull",
                c23::__isoc23_wcstoull as *const (),
                false,
            ),
            (
                c"__isoc23_wcstoumax",
                c23::__isoc23_wcstoumax as *const (),
                false,
            ),
            (
                c"__isoc23_wcstoul_l",
                c23::__isoc23_wcstoul_l as *const (),
                true,
            ),
            (
                c"__isoc23_wcstoull_l",
                c23::__isoc23_wcstoull_l as *const (),
                true,
            ),
        ]
    } else {
        [
            (c"wcstol", fl::wcstol as *const (), false),
            (c"wcstoll", fl::wcstoll as *const (), false),
            (c"wcstoimax", fl::wcstoimax as *const (), false),
            (c"wcstol_l", fl::wcstol_l as *const (), true),
            (c"wcstoll_l", fl::wcstoll_l as *const (), true),
            (c"__isoc23_wcstol", c23::__isoc23_wcstol as *const (), false),
            (
                c"__isoc23_wcstoll",
                c23::__isoc23_wcstoll as *const (),
                false,
            ),
            (
                c"__isoc23_wcstoimax",
                c23::__isoc23_wcstoimax as *const (),
                false,
            ),
            (
                c"__isoc23_wcstol_l",
                c23::__isoc23_wcstol_l as *const (),
                true,
            ),
            (
                c"__isoc23_wcstoll_l",
                c23::__isoc23_wcstoll_l as *const (),
                true,
            ),
        ]
    };
    // SAFETY: GNU signatures match these declarations; the oracle rejects native addresses.
    let (host_errno, host_new, host_free): (Error, NewLocale, FreeLocale) = unsafe {
        (
            dlsym_oracle::host_fn(c"__errno_location", errno::__errno_location as *const ()),
            dlsym_oracle::host_fn(c"newlocale", locale_abi::newlocale as *const ()),
            dlsym_oracle::host_fn(c"freelocale", locale_abi::freelocale as *const ()),
        )
    };
    // SAFETY: C is a terminated locale name; both providers create fresh handles.
    let (native_locale, host_locale) = unsafe {
        (
            Locale {
                pointer: locale_abi::newlocale(
                    libc::LC_ALL_MASK,
                    c"C".as_ptr(),
                    std::ptr::null_mut(),
                ),
                free: locale_abi::freelocale,
            },
            Locale {
                pointer: host_new(libc::LC_ALL_MASK, c"C".as_ptr(), std::ptr::null_mut()),
                free: host_free,
            },
        )
    };
    assert!(!native_locale.pointer.is_null() && !host_locale.pointer.is_null());
    let mut cases: Vec<(Vec<wchar_t>, c_int)> = if window {
        let mut rows = Vec::new();
        for spaces in [509, 510, 511, 512, 513, 600] {
            for (sign, number, base) in [
                ("", "42!", 0),
                ("+", "42!", 2),
                ("-", "101!", 2),
                ("", "0b101!", 0),
                ("+", "0B101!", 2),
                ("-", "0x10!", 0),
            ] {
                let text = format!("{}{sign}{number}", " ".repeat(spaces));
                rows.push((text.chars().map(|c| c as wchar_t).collect(), base));
            }
        }
        rows
    } else {
        [
            ("", 0),
            (" \t\n\r\u{b}\u{c}", 0),
            ("+", 0),
            ("-", 0),
            ("0", 0),
            ("010", 0),
            ("08", 0),
            ("0x", 0),
            ("-0x", 16),
            ("0x1f!", 0),
            ("0b101!", 0),
            ("0B101!", 2),
            ("-0b101!", 0),
            ("+0B101z", 2),
            ("0b2", 0),
            ("0B", 2),
            ("0b101", 16),
            ("0b101", 36),
            ("9223372036854775807", 10),
            ("9223372036854775808", 10),
            ("-9223372036854775808", 10),
            ("-9223372036854775809", 10),
            ("18446744073709551615", 10),
            ("18446744073709551616", 10),
            ("-18446744073709551615", 10),
            ("-18446744073709551616", 10),
            ("\u{2003}42", 10),
            ("１２", 10),
            ("42", -1),
            ("42", 1),
            ("42", 37),
            ("", 1),
        ]
        .into_iter()
        .map(|(s, b)| (s.chars().map(|c| c as wchar_t).collect(), b))
        .collect()
    };
    if window {
        assert_eq!(cases.len(), 36);
    } else {
        assert_eq!(cases.len(), 32);
        for base in 2..=36 {
            cases.push((" +10z!".chars().map(|c| c as wchar_t).collect(), base));
        }
        let mut long = vec![b'9' as wchar_t; 5000];
        long.push(b'!' as wchar_t);
        cases.push((long, 10));
        assert_eq!(cases.len(), 68);
    }
    let mut compared = 0;
    for (name, native, locale) in entries {
        // SAFETY: each name has the corresponding standard wide integer C prototype.
        let host = unsafe { dlsym_oracle::host_addr(name, native) }
            .cast_const()
            .cast::<()>();
        for (text, base) in &cases {
            for with_end in [false, true] {
                let mut input = vec![0x1234; 8];
                input.extend_from_slice(text);
                input.push(0);
                input.extend_from_slice(&[0x5678; 8]);
                let before = input.clone();
                let mut records = Vec::new();
                for (address, error, loc) in [
                    (host, host_errno, host_locale.pointer),
                    (
                        native,
                        errno::__errno_location as Error,
                        native_locale.pointer,
                    ),
                ] {
                    // SAFETY: input+8 is terminated; end cell and guards remain live.
                    // Linux LP64 wide integer exports share these C signatures (the
                    // intmax Rust adapters use unsigned pointer pointees with identical ABI).
                    let record = unsafe {
                        let start = input.as_ptr().add(8);
                        let mut end = End {
                            before: 0x12345678,
                            pointer: start.add(text.len()).cast_mut(),
                            after: 0x87654321,
                        };
                        let output = if with_end {
                            &mut end.pointer
                        } else {
                            std::ptr::null_mut()
                        };
                        *error() = 1234;
                        let bits = match (unsigned, locale) {
                            (false, false) => std::mem::transmute::<*const (), Signed>(address)(
                                start, output, *base,
                            ) as u64,
                            (true, false) => std::mem::transmute::<*const (), Unsigned>(address)(
                                start, output, *base,
                            ),
                            (false, true) => std::mem::transmute::<*const (), SignedL>(address)(
                                start, output, *base, loc,
                            ) as u64,
                            (true, true) => std::mem::transmute::<*const (), UnsignedL>(address)(
                                start, output, *base, loc,
                            ),
                        };
                        let error = *error();
                        assert_eq!((end.before, end.after), (0x12345678, 0x87654321));
                        let offset = if with_end {
                            let bytes = (end.pointer as usize).wrapping_sub(start as usize);
                            let width = std::mem::size_of::<wchar_t>();
                            assert!(bytes <= text.len() * width);
                            assert_eq!(bytes % width, 0);
                            bytes as isize / width as isize
                        } else {
                            -1
                        };
                        (bits, offset, error)
                    };
                    assert_eq!(input, before, "{name:?}: input modified");
                    records.push(record);
                }
                assert_eq!(
                    records[0],
                    records[1],
                    "{name:?}, base={base}, end={with_end}, len={}, input prefix={:?}",
                    text.len(),
                    &text[..text.len().min(12)]
                );
                compared += 1;
            }
        }
    }
    assert_eq!(compared, 10 * cases.len() * 2);
    eprintln!(
        "wide unsigned={unsigned} window={window} parsers=10 cases={} comparisons={compared}",
        cases.len()
    );
}

/// The deployed C carrier resolves exact symbol names, avoiding header C23
/// redirection, and pins all twenty parser imports plus their errno accessor.
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)] // extracted by the retained remote release-validation command
const WIDE_INTEGER_PROBE: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <locale.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <wchar.h>
_Static_assert(sizeof(wchar_t)==4 && sizeof(long)==8 && sizeof(long long)==8,
               "Linux LP64 wide probe");

int main(void) {
    const char *const names[] = {"wcstol","wcstoul","wcstoll","wcstoull",
        "wcstoimax","wcstoumax","wcstol_l","wcstoul_l","wcstoll_l","wcstoull_l",
        "__isoc23_wcstol","__isoc23_wcstoul","__isoc23_wcstoll","__isoc23_wcstoull",
        "__isoc23_wcstoimax","__isoc23_wcstoumax","__isoc23_wcstol_l",
        "__isoc23_wcstoul_l","__isoc23_wcstoll_l","__isoc23_wcstoull_l","__errno_location"};
    void *functions[21]; struct stat want;
    const char *expected=getenv("FLC_WIDE_EXPECT_PROVIDER");
    if (!expected || syscall(SYS_newfstatat,AT_FDCWD,expected,&want,0)) return 42;
    for (unsigned i=0; i<21; i++) {
        Dl_info info; struct stat actual;
        functions[i]=dlsym(RTLD_DEFAULT,names[i]);
        if (!functions[i] || !dladdr(functions[i],&info) || !info.dli_fname ||
            syscall(SYS_newfstatat,AT_FDCWD,info.dli_fname,&actual,0) ||
            want.st_dev!=actual.st_dev || want.st_ino!=actual.st_ino) {
            fputs("wide provider mismatch\n",stderr); return 42;
        }
    }
    int *(*error)(void)=(int *(*)(void))functions[20];
    locale_t locale=newlocale(LC_ALL_MASK,"C",(locale_t)0);
    if (!locale) return 43;
    const struct sample { const wchar_t *text; int base; } cases[] = {
        {L"",0},{L" \t\n\r\v\f",0},{L"+",0},{L"-",0},{L"0",0},{L"010",0},
        {L"08",0},{L"0x",0},{L"-0x",16},{L"0x1f!",0},{L"0b101!",0},
        {L"0B101!",2},{L"-0b101!",0},{L"+0B101z",2},{L"0b2",0},{L"0B",2},
        {L"0b101",16},{L"0b101",36},{L"9223372036854775807",10},
        {L"9223372036854775808",10},{L"-9223372036854775808",10},
        {L"-9223372036854775809",10},{L"18446744073709551615",10},
        {L"18446744073709551616",10},{L"-18446744073709551615",10},
        {L"-18446744073709551616",10},{L"\u200342",10},{L"\uff11\uff12",10},
        {L"42",-1},{L"42",1},{L"42",37},{L"",1}
    };
    _Static_assert(sizeof(cases)/sizeof(cases[0])==32,"frozen ordinary corpus");
    const unsigned spaces[]={509,510,511,512,513,600};
    const wchar_t *const tails[]={L"42!",L"+42!",L"-101!",L"0b101!",L"+0B101!",L"-0x10!"};
    const int bases[]={0,2,2,0,2,0};
    unsigned records=0;
    for (unsigned i=0; i<20; i++) for (unsigned j=0; j<104; j++) {
        wchar_t input[6100], before[6100];
        for (unsigned k=0; k<6100; k++) input[k]=0x5678;
        for (unsigned k=0; k<8; k++) input[k]=0x1234;
        unsigned length=0; int base;
        const wchar_t *text;
        if (j<32) { text=cases[j].text; base=cases[j].base; }
        else if (j<67) { text=L" +10z!"; base=(int)j-30; }
        else if (j==67) {
            for (; length<5000; length++) input[8+length]=L'9';
            text=L"!"; base=10;
        } else {
            unsigned group=(j-68)/6, tail=(j-68)%6;
            for (; length<spaces[group]; length++) input[8+length]=L' ';
            text=tails[tail]; base=bases[tail];
        }
        for (unsigned k=0; text[k]; k++) input[8+length++]=text[k];
        input[8+length]=0;
        for (unsigned k=0; k<6100; k++) before[k]=input[k];
        for (int with_end=0; with_end<2; with_end++) {
            struct { uint64_t left; wchar_t *pointer; uint64_t right; } end =
                {UINT64_C(0x12345678),input+8+length,UINT64_C(0x87654321)};
            wchar_t **out=with_end ? &end.pointer : 0;
            uint64_t bits; *error()=1234;
            switch (i%10) {
                case 0: bits=(uint64_t)((long (*)(const wchar_t *,wchar_t **,int))functions[i])(input+8,out,base); break;
                case 1: bits=((unsigned long (*)(const wchar_t *,wchar_t **,int))functions[i])(input+8,out,base); break;
                case 2: bits=(uint64_t)((long long (*)(const wchar_t *,wchar_t **,int))functions[i])(input+8,out,base); break;
                case 3: bits=((unsigned long long (*)(const wchar_t *,wchar_t **,int))functions[i])(input+8,out,base); break;
                case 4: bits=(uint64_t)((intmax_t (*)(const wchar_t *,wchar_t **,int))functions[i])(input+8,out,base); break;
                case 5: bits=((uintmax_t (*)(const wchar_t *,wchar_t **,int))functions[i])(input+8,out,base); break;
                case 6: bits=(uint64_t)((long (*)(const wchar_t *,wchar_t **,int,locale_t))functions[i])(input+8,out,base,locale); break;
                case 7: bits=((unsigned long (*)(const wchar_t *,wchar_t **,int,locale_t))functions[i])(input+8,out,base,locale); break;
                case 8: bits=(uint64_t)((long long (*)(const wchar_t *,wchar_t **,int,locale_t))functions[i])(input+8,out,base,locale); break;
                default: bits=((unsigned long long (*)(const wchar_t *,wchar_t **,int,locale_t))functions[i])(input+8,out,base,locale); break;
            }
            int result_errno=*error();
            if (end.left!=UINT64_C(0x12345678) || end.right!=UINT64_C(0x87654321)) return 44;
            uintptr_t delta=(uintptr_t)end.pointer-(uintptr_t)(input+8);
            if (delta>length*sizeof(wchar_t) || delta%sizeof(wchar_t)) return 45;
            for (unsigned k=0; k<6100; k++) if (before[k]!=input[k]) return 46;
            ptrdiff_t consumed=with_end ? (ptrdiff_t)(delta/sizeof(wchar_t)) : -1;
            printf("%u %u %d %d %016" PRIx64 " %td %d\n",i,j,base,with_end,bits,consumed,result_errno);
            records++;
        }
    }
    freelocale(locale);
    printf("WIDE_RECORDS=%u\n",records);
    return records==4160 ? 0 : 47;
}
"#;

unsafe extern "C" {
    fn wcstoimax(nptr: *const wchar_t, endptr: *mut *mut wchar_t, base: c_int) -> i64;
    fn wcstoumax(nptr: *const wchar_t, endptr: *mut *mut wchar_t, base: c_int) -> u64;
    fn __errno_location() -> *mut c_int;
}

fn wide(s: &str) -> Vec<wchar_t> {
    let mut v: Vec<wchar_t> = s.chars().map(|c| c as wchar_t).collect();
    v.push(0);
    v
}

fn consumed(end: *mut wchar_t, base: *const wchar_t) -> isize {
    (end as isize - base as isize) / std::mem::size_of::<wchar_t>() as isize
}

#[test]
fn wcstoimax_matches_glibc() {
    let cases: &[(&str, c_int)] = &[
        ("123", 10),
        ("  -42xy", 10),
        ("0x1F", 16),
        ("777", 8),
        ("0", 0),
        ("abc", 10),
        ("9223372036854775808", 10),  // overflow -> ERANGE
        ("-9223372036854775809", 10), // underflow -> ERANGE
        ("+7", 10),
    ];
    for &(s, base) in cases {
        let w = wide(s);
        let mut ge: *mut wchar_t = std::ptr::null_mut();
        let mut fe: *mut wchar_t = std::ptr::null_mut();
        unsafe { *__errno_location() = 0 };
        let g = unsafe { wcstoimax(w.as_ptr(), &mut ge, base) };
        let gerr = unsafe { *__errno_location() };
        unsafe { *__errno_location() = 0 };
        let f = unsafe {
            frankenlibc_abi::wchar_abi::wcstoimax(
                w.as_ptr() as *const u32,
                &mut fe as *mut *mut wchar_t as *mut *mut u32,
                base,
            )
        };
        let ferr = unsafe { *__errno_location() };
        assert_eq!(f, g, "wcstoimax({s:?},{base}) value");
        assert_eq!(
            consumed(fe, w.as_ptr()),
            consumed(ge, w.as_ptr()),
            "wcstoimax({s:?}) endptr"
        );
        assert_eq!(ferr, gerr, "wcstoimax({s:?}) errno: fl={ferr} glibc={gerr}");
    }
}

#[test]
fn wcstoumax_matches_glibc() {
    let cases: &[(&str, c_int)] = &[
        ("123", 10),
        ("0xFFFFFFFFFFFFFFFF", 0),
        ("-1", 10),                   // wraparound
        ("18446744073709551616", 10), // overflow -> ERANGE
        ("zz", 36),
    ];
    for &(s, base) in cases {
        let w = wide(s);
        let mut ge: *mut wchar_t = std::ptr::null_mut();
        let mut fe: *mut wchar_t = std::ptr::null_mut();
        unsafe { *__errno_location() = 0 };
        let g = unsafe { wcstoumax(w.as_ptr(), &mut ge, base) };
        let gerr = unsafe { *__errno_location() };
        unsafe { *__errno_location() = 0 };
        let f = unsafe {
            frankenlibc_abi::wchar_abi::wcstoumax(
                w.as_ptr() as *const u32,
                &mut fe as *mut *mut wchar_t as *mut *mut u32,
                base,
            )
        };
        let ferr = unsafe { *__errno_location() };
        assert_eq!(f, g, "wcstoumax({s:?},{base}) value");
        assert_eq!(
            consumed(fe, w.as_ptr()),
            consumed(ge, w.as_ptr()),
            "wcstoumax({s:?}) endptr"
        );
        assert_eq!(ferr, gerr, "wcstoumax({s:?}) errno: fl={ferr} glibc={gerr}");
    }
}
