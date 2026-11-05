//! Conformance gate: the integer string-parse family (strtol/strtoul/strtoll/
//! strtoull/strtoimax/strtoumax + wide wcstol/wcstoul/wcstoll/wcstoull) matches
//! host glibc on the intricate edges — value clamping (LONG_MAX/MIN, ULONG_MAX),
//! endptr advancement (incl. past overflowing digits), base-0 prefix detection
//! (0x / leading-0 octal / invalid-octal-digit), sign + whitespace handling,
//! `strtoul("-1")` unsigned wraparound, and ERANGE / EINVAL errno.
//!
//! Expected values are GROUND TRUTH captured from a standalone gcc program
//! linked against this host's glibc (`-lm`), recorded inline. fl is called via
//! Rust paths and its errno read in-process (its own slot) — reliable for
//! string-argument functions (no const-folding, and the Rust-path call reaches
//! fl's body). long == long long == 64-bit on this target, so the *ll and
//! intmax variants share the golden values.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::errno_abi;
use frankenlibc_abi::stdlib_abi as sa;
use frankenlibc_abi::wchar_abi as wa;
use std::ffi::{CString, c_char, c_int};

#[cfg(target_arch = "x86_64")]
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

const ERANGE: c_int = 34;

fn clr() {
    unsafe { errno_abi::set_abi_errno(0) };
}
fn rd() -> c_int {
    unsafe { *errno_abi::__errno_location() }
}
fn wbuf(s: &str) -> Vec<i32> {
    let mut v: Vec<i32> = s.chars().map(|c| c as i32).collect();
    v.push(0);
    v
}

/// (input, base, want_value, want_endptr_offset, want_errno)
type SCase = (&'static str, c_int, i64, isize, c_int);
type UCase = (&'static str, c_int, u64, isize, c_int);

// Verified against gcc/glibc (see header). Shared by strtol/strtoll/strtoimax.
const SIGNED: &[SCase] = &[
    ("99999999999999999999999", 10, i64::MAX, 23, ERANGE),
    ("9223372036854775807", 10, 9223372036854775807, 19, 0),
    ("9223372036854775808", 10, i64::MAX, 19, ERANGE),
    ("-9223372036854775808", 10, i64::MIN, 20, 0),
    ("-9223372036854775809", 10, i64::MIN, 20, ERANGE),
    ("0x1F", 0, 31, 4, 0),
    ("010", 0, 8, 3, 0),
    ("08", 0, 0, 1, 0),
    ("0", 0, 0, 1, 0),
    ("0x", 0, 0, 1, 0),
    ("  +42", 10, 42, 5, 0),
    ("  -42", 10, -42, 5, 0),
    ("+", 10, 0, 0, 0),
    ("-", 10, 0, 0, 0),
    ("", 10, 0, 0, 0),
    ("z", 36, 35, 1, 0),
    ("Zz", 36, 1295, 2, 0),
    ("42abc", 10, 42, 2, 0),
    ("ffff", 16, 65535, 4, 0),
    ("0x7fffffffffffffff", 0, 9223372036854775807, 18, 0),
    ("-0x10", 0, -16, 5, 0),
    ("  0X1f", 0, 31, 6, 0),
    ("+0x1F", 16, 31, 5, 0),
    ("1010", 2, 10, 4, 0),
    ("777", 8, 511, 3, 0),
];

// Shared by strtoul/strtoull/strtoumax.
const UNSIGNED: &[UCase] = &[
    ("-1", 10, u64::MAX, 2, 0),
    ("18446744073709551615", 10, u64::MAX, 20, 0),
    ("18446744073709551616", 10, u64::MAX, 20, ERANGE),
    ("-0x1", 0, u64::MAX, 4, 0),
    ("0xFFFFFFFFFFFFFFFF", 0, u64::MAX, 18, 0),
    ("99999999999999999999999", 10, u64::MAX, 23, ERANGE),
    ("-18446744073709551615", 10, 1, 21, 0),
];

#[test]
fn strtol_family_matches_glibc() {
    let mut div: Vec<String> = Vec::new();

    macro_rules! run_signed {
        ($fn:path, $tag:literal) => {
            for &(s, base, wv, woff, we) in SIGNED {
                let c = CString::new(s).unwrap();
                let p = c.as_ptr();
                let mut e: *mut c_char = std::ptr::null_mut();
                clr();
                let v = unsafe { $fn(p, &mut e, base) } as i64;
                let off = (e as usize).wrapping_sub(p as usize) as isize;
                let er = rd();
                if v != wv || off != woff || er != we {
                    div.push(format!(
                        "{}({:?},{}): got (v={},end=+{},errno={}) want (v={},end=+{},errno={})",
                        $tag, s, base, v, off, er, wv, woff, we
                    ));
                }
            }
        };
    }
    macro_rules! run_unsigned {
        ($fn:path, $tag:literal) => {
            for &(s, base, wv, woff, we) in UNSIGNED {
                let c = CString::new(s).unwrap();
                let p = c.as_ptr();
                let mut e: *mut c_char = std::ptr::null_mut();
                clr();
                let v = unsafe { $fn(p, &mut e, base) } as u64;
                let off = (e as usize).wrapping_sub(p as usize) as isize;
                let er = rd();
                if v != wv || off != woff || er != we {
                    div.push(format!(
                        "{}({:?},{}): got (v={},end=+{},errno={}) want (v={},end=+{},errno={})",
                        $tag, s, base, v, off, er, wv, woff, we
                    ));
                }
            }
        };
    }

    run_signed!(sa::strtol, "strtol");
    run_signed!(sa::strtoll, "strtoll");
    run_signed!(sa::strtoimax, "strtoimax");
    run_unsigned!(sa::strtoul, "strtoul");
    run_unsigned!(sa::strtoull, "strtoull");
    run_unsigned!(sa::strtoumax, "strtoumax");

    // Wide variants share the same golden table.
    macro_rules! run_wsigned {
        ($fn:path, $tag:literal) => {
            for &(s, base, wv, woff, we) in SIGNED {
                let mut buf = wbuf(s);
                let p = buf.as_mut_ptr();
                let mut e: *mut i32 = std::ptr::null_mut();
                clr();
                let v = unsafe { $fn(p, &mut e, base) } as i64;
                let off = ((e as usize).wrapping_sub(p as usize) / 4) as isize;
                let er = rd();
                if v != wv || off != woff || er != we {
                    div.push(format!(
                        "{}({:?},{}): got (v={},end=+{},errno={}) want (v={},end=+{},errno={})",
                        $tag, s, base, v, off, er, wv, woff, we
                    ));
                }
            }
        };
    }
    macro_rules! run_wunsigned {
        ($fn:path, $tag:literal) => {
            for &(s, base, wv, woff, we) in UNSIGNED {
                let mut buf = wbuf(s);
                let p = buf.as_mut_ptr();
                let mut e: *mut i32 = std::ptr::null_mut();
                clr();
                let v = unsafe { $fn(p, &mut e, base) } as u64;
                let off = ((e as usize).wrapping_sub(p as usize) / 4) as isize;
                let er = rd();
                if v != wv || off != woff || er != we {
                    div.push(format!(
                        "{}({:?},{}): got (v={},end=+{},errno={}) want (v={},end=+{},errno={})",
                        $tag, s, base, v, off, er, wv, woff, we
                    ));
                }
            }
        };
    }
    run_wsigned!(wa::wcstol, "wcstol");
    run_wsigned!(wa::wcstoll, "wcstoll");
    run_wunsigned!(wa::wcstoul, "wcstoul");
    run_wunsigned!(wa::wcstoull, "wcstoull");

    assert!(
        div.is_empty(),
        "strtol-family divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}

#[test]
#[cfg(target_arch = "x86_64")]
fn native_integer_plt_protocol() {
    native_integer_protocol(false);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn native_integer_got_protocol() {
    native_integer_protocol(true);
}

#[cfg(target_arch = "x86_64")]
fn native_integer_protocol(got: bool) {
    use frankenlibc_abi::dlfcn_abi as dl;
    use frankenlibc_core::elf::ElfLoader;
    use std::ffi::{CStr, c_void};
    use std::os::unix::ffi::OsStrExt;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Record {
        bits: u64,
        offset: i64,
        error: c_int,
    }
    #[repr(C)]
    struct Guarded {
        before: u64,
        record: Record,
        after: u64,
    }
    type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
    type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
    type Sym = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
    type Selector = unsafe extern "C" fn(u32, u32) -> *mut c_void;
    type Probe = unsafe extern "C" fn(u32, *const c_char, u32, c_int, c_int, *mut Record);
    type Run = unsafe extern "C" fn() -> c_int;

    let root = std::env::temp_dir().join(format!(
        "frankenlibc-integer-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let source = root.join("integer.c");
    let library = root.join("integer.so");
    std::fs::write(&source, INTEGER_PLUGIN).unwrap();
    let output = Command::new("gcc")
        .args([
            "-shared",
            "-fPIC",
            "-nostdlib",
            "-O2",
            "-fno-builtin",
            "-fno-stack-protector",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wl,--hash-style=both",
            if got { "-fno-plt" } else { "-fplt" },
        ])
        .arg(&source)
        .arg("-o")
        .arg(&library)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let object = ElfLoader::new(0)
        .parse(&std::fs::read(&library).unwrap())
        .unwrap();
    assert!(object.needed_libraries.is_empty());
    let names = [
        c"atoi",
        c"atol",
        c"atoll",
        c"strtol",
        c"strtoul",
        c"strtoll",
        c"strtoull",
        c"strtoimax",
        c"strtoumax",
        c"__errno_location",
    ];
    let native = [
        sa::atoi as *mut c_void,
        sa::atol as *mut c_void,
        sa::atoll as *mut c_void,
        sa::strtol as *mut c_void,
        sa::strtoul as *mut c_void,
        sa::strtoll as *mut c_void,
        sa::strtoull as *mut c_void,
        sa::strtoimax as *mut c_void,
        sa::strtoumax as *mut c_void,
        errno_abi::__errno_location as *mut c_void,
    ];
    let host = std::array::from_fn::<_, 10, _>(|i| {
        // SAFETY: resolve the GNU definition and reject this native address.
        unsafe { dlsym_oracle::host_addr(names[i], native[i].cast_const().cast()) }
    });
    for name in names {
        let name = name.to_str().unwrap();
        assert!(
            object
                .undefined_symbols()
                .any(|(_, s)| object.symbol_name(s) == Some(name))
        );
        let wrapper = format!("integer_call_{name}");
        let output = Command::new("objdump")
            .args(["-dr", &format!("--disassemble={wrapper}")])
            .arg(&library)
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            if got {
                text.contains('*') && !text.contains("@plt>")
            } else {
                text.contains(&format!("<{name}@plt>"))
            },
            "{wrapper}: {text}"
        );
    }
    let mut corpus: Vec<(Vec<u8>, c_int)> = [
        (b"".as_slice(), 10),
        (b" \t\n\r\x0b\x0c", 10),
        (b"+", 10),
        (b"-", 10),
        (b" +", 10),
        (b"  -42tail", 10),
        (b"0", 0),
        (b"010", 0),
        (b"08", 0),
        (b"0x", 0),
        (b"-0x", 0),
        (b"+0Xg", 16),
        (b"0x10z", 0),
        (b"-0x10", 16),
        (b"9223372036854775807", 10),
        (b"9223372036854775808", 10),
        (b"-9223372036854775808", 10),
        (b"-9223372036854775809", 10),
        (b"18446744073709551615", 10),
        (b"18446744073709551616", 10),
        (b"-18446744073709551615", 10),
        (b"-18446744073709551616", 10),
        (b"\xff42", 10),
        (b"0b101!", 0),
        (b"0b101!", 2),
        (b"Zz!", 36),
        (b"  \t-0!", 10),
        (b"42", -7),
        (b"42", -1),
        (b"42", 1),
        (b"42", 37),
    ]
    .into_iter()
    .map(|(s, b)| (s.to_vec(), b))
    .collect();
    let mut huge = vec![b'9'; 5000];
    huge.extend_from_slice(b"!END");
    corpus.push((huge, 10));
    assert_eq!(corpus.len(), 32);
    for base in 2..=36 {
        corpus.push((b"+10z!".to_vec(), base));
    }
    assert_eq!(corpus.len(), 67);
    let ato: [&[u8]; 9] = [
        b"",
        b" \t",
        b"  42tail",
        b"-2147483648",
        b"2147483647",
        b"-1",
        b"+0",
        b"+17!",
        b"0x10",
    ];
    let mut reference = Vec::new();
    for (provider, expected) in [("GNU", host), ("native", native)] {
        let (open, close, symbol): (Open, Close, Sym) = if provider == "native" {
            (dl::dlopen, dl::dlclose, dl::dlsym)
        } else {
            // SAFETY: these GNU functions have the declared loader prototypes.
            unsafe {
                (
                    dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ()),
                    dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ()),
                    dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ()),
                )
            }
        };
        let path = CString::new(library.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is live/NUL-terminated. The DSO remains loaded below.
        let handle = unsafe { open(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        assert!(!handle.is_null(), "{provider}: integer plugin load failed");
        if provider == "native" {
            assert!(
                dl::native_dso_handle_for_tests(handle),
                "host fallback is not native"
            );
        }
        // SAFETY: each export is declared in INTEGER_PLUGIN with this signature.
        let (select, probe, lookup, smoke) = unsafe {
            let get = |s: &CStr| {
                let p = symbol(handle, s.as_ptr());
                assert!(!p.is_null());
                p
            };
            (
                std::mem::transmute::<*mut c_void, Selector>(get(c"integer_function")),
                std::mem::transmute::<*mut c_void, Probe>(get(c"integer_probe")),
                std::mem::transmute::<*mut c_void, Run>(get(c"integer_lookup")),
                std::mem::transmute::<*mut c_void, Run>(get(c"integer_smoke")),
            )
        };
        for (i, name) in names.iter().enumerate() {
            let wrapper = CString::new(format!("integer_call_{}", name.to_str().unwrap())).unwrap();
            // SAFETY: selector indices 0..10 match the plugin's two live tables.
            unsafe {
                assert_eq!(select(i as u32, 0), expected[i], "{provider}: {name:?}");
                let call = select(i as u32, 1);
                assert!(!call.is_null());
                assert_eq!(call, symbol(handle, wrapper.as_ptr()));
            }
        }
        // SAFETY: both are declared zero-argument C entrypoints in this DSO.
        assert_eq!(unsafe { lookup() }, 0, "{provider}: lookup");
        assert_eq!(unsafe { smoke() }, 0, "{provider}: 195-record smoke");
        let mut observed = Vec::new();
        for function in 0..9 {
            let inputs: Vec<(&[u8], c_int, c_int)> = if function < 3 {
                ato.iter().map(|s| (*s, 10, 0)).collect()
            } else {
                corpus
                    .iter()
                    .flat_map(|(s, b)| [(s.as_slice(), *b, 0), (s.as_slice(), *b, 1)])
                    .collect()
            };
            for (bytes, base, with_end) in inputs {
                let mut input = vec![b'L'; 8];
                input.extend_from_slice(bytes);
                input.push(0);
                input.extend_from_slice(&[b'R'; 8]);
                let before = input.clone();
                let mut output = Guarded {
                    before: 0x123456789abcdef0,
                    record: Record {
                        bits: 85,
                        offset: 85,
                        error: 85,
                    },
                    after: 0xfedcba9876543210,
                };
                // SAFETY: input+8 is NUL-terminated and surrounded by live guards;
                // Record matches the C layout and remains live through the call.
                unsafe {
                    probe(
                        function,
                        input.as_ptr().add(8).cast(),
                        bytes.len() as u32,
                        base,
                        with_end,
                        &mut output.record,
                    )
                };
                assert_eq!(input, before, "{provider}: input write function={function}");
                assert_eq!(
                    (output.before, output.after),
                    (0x123456789abcdef0, 0xfedcba9876543210)
                );
                let index = observed.len();
                if provider == "native" {
                    assert_eq!(
                        output.record, reference[index],
                        "function={function} base={base} end={with_end} input={bytes:?}"
                    );
                }
                observed.push(output.record);
            }
        }
        assert_eq!(observed.len(), 831);
        eprintln!("integer provider={provider} got={got} records=831 lookup=90 smoke=195");
        if provider == "GNU" {
            reference = observed;
        }
        // SAFETY: all calls have returned; no pointer into this DSO is reused.
        assert_eq!(unsafe { close(handle) }, 0);
    }
}

#[cfg(target_arch = "x86_64")]
const INTEGER_PLUGIN: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
/* Exact asm names prevent header atoi inlining and C23 strtol redirection.
   These are calls to the traditional exported C ABI, not C23 entrypoints. */
extern int import_atoi(const char *) __asm__("atoi");
extern long import_atol(const char *) __asm__("atol");
extern long long import_atoll(const char *) __asm__("atoll");
extern long import_strtol(const char *, char **, int) __asm__("strtol");
extern unsigned long import_strtoul(const char *, char **, int) __asm__("strtoul");
extern long long import_strtoll(const char *, char **, int) __asm__("strtoll");
extern unsigned long long import_strtoull(const char *, char **, int) __asm__("strtoull");
extern intmax_t import_strtoimax(const char *, char **, int) __asm__("strtoimax");
extern uintmax_t import_strtoumax(const char *, char **, int) __asm__("strtoumax");
_Static_assert(sizeof(long) == 8 && sizeof(intmax_t) == 8, "LP64 probe");

int integer_call_atoi(const char *s) { return import_atoi(s); }
long integer_call_atol(const char *s) { return import_atol(s); }
long long integer_call_atoll(const char *s) { return import_atoll(s); }
long integer_call_strtol(const char *s, char **e, int b) { return import_strtol(s,e,b); }
unsigned long integer_call_strtoul(const char *s, char **e, int b) { return import_strtoul(s,e,b); }
long long integer_call_strtoll(const char *s, char **e, int b) { return import_strtoll(s,e,b); }
unsigned long long integer_call_strtoull(const char *s, char **e, int b) { return import_strtoull(s,e,b); }
intmax_t integer_call_strtoimax(const char *s, char **e, int b) { return import_strtoimax(s,e,b); }
uintmax_t integer_call_strtoumax(const char *s, char **e, int b) { return import_strtoumax(s,e,b); }
int *integer_call___errno_location(void) { return __errno_location(); }

void *integer_function(unsigned i, unsigned wrappers) {
    void *const imports[] = {(void *)import_atoi,(void *)import_atol,(void *)import_atoll,
        (void *)import_strtol,(void *)import_strtoul,(void *)import_strtoll,
        (void *)import_strtoull,(void *)import_strtoimax,(void *)import_strtoumax,
        (void *)__errno_location};
    void *const calls[] = {(void *)integer_call_atoi,(void *)integer_call_atol,
        (void *)integer_call_atoll,(void *)integer_call_strtol,(void *)integer_call_strtoul,
        (void *)integer_call_strtoll,(void *)integer_call_strtoull,
        (void *)integer_call_strtoimax,(void *)integer_call_strtoumax,
        (void *)integer_call___errno_location};
    return i < 10 ? (wrappers ? calls[i] : imports[i]) : 0;
}

struct integer_result { uint64_t bits; int64_t offset; int error; };
void integer_probe(unsigned i, const char *s, unsigned length, int base, int with_end,
                   struct integer_result *out) {
    char *end = (char *)s + length;
    char **e = with_end ? &end : 0;
    int *slot = integer_call___errno_location(); *slot = 1234;
    switch (i) {
        case 0: out->bits = (uint64_t)(int64_t)integer_call_atoi(s); break;
        case 1: out->bits = (uint64_t)integer_call_atol(s); break;
        case 2: out->bits = (uint64_t)integer_call_atoll(s); break;
        case 3: out->bits = (uint64_t)integer_call_strtol(s,e,base); break;
        case 4: out->bits = integer_call_strtoul(s,e,base); break;
        case 5: out->bits = (uint64_t)integer_call_strtoll(s,e,base); break;
        case 6: out->bits = integer_call_strtoull(s,e,base); break;
        case 7: out->bits = (uint64_t)integer_call_strtoimax(s,e,base); break;
        case 8: out->bits = integer_call_strtoumax(s,e,base); break;
        default: out->bits = 85; break;
    }
    out->error = *slot;
    out->offset = with_end ? (int64_t)((uintptr_t)end - (uintptr_t)s) : -1;
}

int integer_lookup(void) {
    const char *const names[] = {"atoi","atol","atoll","strtol","strtoul","strtoll",
        "strtoull","strtoimax","strtoumax","__errno_location"};
    const char *const bad[] = {"GLIBC_2.17","GLIBC_2.25","GLIBC_2.34","GLIBC_2.36",
        "GLIBC_9.99","GLIBC_PRIVATE",""};
    for (unsigned i = 0; i < 10; i++) {
        void *want = integer_function(i,0); dlerror();
        if (dlsym(RTLD_DEFAULT,names[i]) != want || dlerror()) return 1;
        if (dlvsym(RTLD_DEFAULT,names[i],"GLIBC_2.2.5") != want || dlerror()) return 2;
        for (unsigned j = 0; j < 7; j++)
            if (dlvsym(RTLD_DEFAULT,names[i],bad[j]) || !dlerror() || dlerror()) return 3;
    }
    return 0;
}

int integer_smoke(void) {
    char huge[5005]; for (unsigned i = 0; i < 5000; i++) huge[i] = '9';
    huge[5000]='!'; huge[5001]=0;
    struct sample { const char *s; unsigned length; int base; uint64_t signed_bits, unsigned_bits;
                    int64_t end; int signed_errno, unsigned_errno; };
    const struct sample cases[] = {
        {"",0,10,0,0,0,1234,1234}, {"42",2,10,42,42,2,1234,1234},
        {"  -42tail",9,10,(uint64_t)-42,(uint64_t)-42,5,1234,1234},
        {"0x",2,0,0,0,1,1234,1234}, {"08",2,0,0,0,1,1234,1234},
        {"Zz!",3,36,1295,1295,2,1234,1234}, {"1010z",5,2,10,10,4,1234,1234},
        {"9223372036854775807",19,10,LONG_MAX,LONG_MAX,19,1234,1234},
        {"-9223372036854775808",20,10,(uint64_t)LONG_MIN,UINT64_C(9223372036854775808),20,1234,1234},
        {"9223372036854775808",19,10,LONG_MAX,UINT64_C(9223372036854775808),19,ERANGE,1234},
        {"18446744073709551615",20,10,LONG_MAX,UINT64_MAX,20,ERANGE,1234},
        {"18446744073709551616",20,10,LONG_MAX,UINT64_MAX,20,ERANGE,ERANGE},
        {"42",2,1,0,0,2,EINVAL,EINVAL}, {huge,5001,10,LONG_MAX,UINT64_MAX,5000,ERANGE,ERANGE}
    };
    for (unsigned i = 3; i < 9; i++) for (unsigned j = 0; j < 14; j++)
        for (int e = 0; e < 2; e++) {
            struct integer_result out; const struct sample *s = &cases[j];
            integer_probe(i,s->s,s->length,s->base,e,&out);
            int u = i==4 || i==6 || i==8;
            if (out.bits != (u ? s->unsigned_bits : s->signed_bits) ||
                out.error != (u ? s->unsigned_errno : s->signed_errno) ||
                out.offset != (e ? s->end : -1)) return __LINE__;
        }
    const char *const ato[] = {""," \t","  42tail","-2147483648","2147483647",
        "-1","+0","+17!","0x10"};
    const int64_t want[] = {0,0,42,INT_MIN,INT_MAX,-1,0,17,0};
    for (unsigned i = 0; i < 3; i++) for (unsigned j = 0; j < 9; j++) {
        struct integer_result out; integer_probe(i,ato[j],0,10,0,&out);
        if (out.bits != (uint64_t)want[j] || out.offset != -1 || out.error != 1234)
            return __LINE__;
    }
    return integer_lookup();
}
"#;

#[test]
#[cfg(target_arch = "x86_64")]
fn native_integer_extended_plt_protocol() {
    native_integer_extended_protocol(false);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn native_integer_extended_got_protocol() {
    native_integer_extended_protocol(true);
}

#[cfg(target_arch = "x86_64")]
fn native_integer_extended_protocol(got: bool) {
    use frankenlibc_abi::{dlfcn_abi as dl, isoc_abi as c23, locale_abi};
    use frankenlibc_core::elf::ElfLoader;
    use std::ffi::{CStr, c_void};
    use std::os::unix::ffi::OsStrExt;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Record {
        bits: u64,
        offset: i64,
        error: c_int,
    }
    #[repr(C)]
    struct Guarded {
        before: u64,
        record: Record,
        after: u64,
    }
    type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
    type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
    type Sym = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
    type NewLocale = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> *mut c_void;
    type FreeLocale = unsafe extern "C" fn(*mut c_void);
    type Selector = unsafe extern "C" fn(u32, u32) -> *mut c_void;
    type Case = unsafe extern "C" fn(u32, *mut i32, *mut c_char, *mut u32) -> c_int;
    type Probe = unsafe extern "C" fn(
        u32,
        *const c_void,
        u32,
        c_int,
        c_int,
        *mut c_void,
        *mut Record,
    ) -> c_int;
    type Run = unsafe extern "C" fn() -> c_int;
    struct Locale(*mut c_void, FreeLocale);
    impl Drop for Locale {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the handle is paired with its creating provider.
                unsafe { (self.1)(self.0) };
            }
        }
    }
    let root = std::env::temp_dir().join(format!(
        "frankenlibc-integer-extended-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let source = root.join("integer_extended.c");
    let library = root.join("integer_extended.so");
    std::fs::write(&source, INTEGER_EXTENDED_PLUGIN).unwrap();
    let output = Command::new("gcc")
        .args([
            "-shared",
            "-fPIC",
            "-nostdlib",
            "-O2",
            "-fno-builtin",
            "-fno-stack-protector",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wl,--hash-style=both",
            if got { "-fno-plt" } else { "-fplt" },
        ])
        .arg(&source)
        .arg("-o")
        .arg(&library)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let object = ElfLoader::new(0)
        .parse(&std::fs::read(&library).unwrap())
        .unwrap();
    assert!(object.needed_libraries.is_empty());
    let names = [
        c"strtol",
        c"strtoul",
        c"strtoll",
        c"strtoull",
        c"strtoimax",
        c"strtoumax",
        c"strtol_l",
        c"strtoul_l",
        c"strtoll_l",
        c"strtoull_l",
        c"__isoc23_strtol",
        c"__isoc23_strtoul",
        c"__isoc23_strtoll",
        c"__isoc23_strtoull",
        c"__isoc23_strtoimax",
        c"__isoc23_strtoumax",
        c"__isoc23_strtol_l",
        c"__isoc23_strtoul_l",
        c"__isoc23_strtoll_l",
        c"__isoc23_strtoull_l",
        c"wcstol",
        c"wcstoul",
        c"wcstoll",
        c"wcstoull",
        c"wcstoimax",
        c"wcstoumax",
        c"wcstol_l",
        c"wcstoul_l",
        c"wcstoll_l",
        c"wcstoull_l",
        c"__isoc23_wcstol",
        c"__isoc23_wcstoul",
        c"__isoc23_wcstoll",
        c"__isoc23_wcstoull",
        c"__isoc23_wcstoimax",
        c"__isoc23_wcstoumax",
        c"__isoc23_wcstol_l",
        c"__isoc23_wcstoul_l",
        c"__isoc23_wcstoll_l",
        c"__isoc23_wcstoull_l",
        c"__errno_location",
    ];
    let native = [
        sa::strtol as *mut c_void,
        sa::strtoul as *mut c_void,
        sa::strtoll as *mut c_void,
        sa::strtoull as *mut c_void,
        sa::strtoimax as *mut c_void,
        sa::strtoumax as *mut c_void,
        sa::strtol_l as *mut c_void,
        sa::strtoul_l as *mut c_void,
        sa::strtoll_l as *mut c_void,
        sa::strtoull_l as *mut c_void,
        c23::__isoc23_strtol as *mut c_void,
        c23::__isoc23_strtoul as *mut c_void,
        c23::__isoc23_strtoll as *mut c_void,
        c23::__isoc23_strtoull as *mut c_void,
        c23::__isoc23_strtoimax as *mut c_void,
        c23::__isoc23_strtoumax as *mut c_void,
        c23::__isoc23_strtol_l as *mut c_void,
        c23::__isoc23_strtoul_l as *mut c_void,
        c23::__isoc23_strtoll_l as *mut c_void,
        c23::__isoc23_strtoull_l as *mut c_void,
        wa::wcstol as *mut c_void,
        wa::wcstoul as *mut c_void,
        wa::wcstoll as *mut c_void,
        wa::wcstoull as *mut c_void,
        wa::wcstoimax as *mut c_void,
        wa::wcstoumax as *mut c_void,
        wa::wcstol_l as *mut c_void,
        wa::wcstoul_l as *mut c_void,
        wa::wcstoll_l as *mut c_void,
        wa::wcstoull_l as *mut c_void,
        c23::__isoc23_wcstol as *mut c_void,
        c23::__isoc23_wcstoul as *mut c_void,
        c23::__isoc23_wcstoll as *mut c_void,
        c23::__isoc23_wcstoull as *mut c_void,
        c23::__isoc23_wcstoimax as *mut c_void,
        c23::__isoc23_wcstoumax as *mut c_void,
        c23::__isoc23_wcstol_l as *mut c_void,
        c23::__isoc23_wcstoul_l as *mut c_void,
        c23::__isoc23_wcstoll_l as *mut c_void,
        c23::__isoc23_wcstoull_l as *mut c_void,
        errno_abi::__errno_location as *mut c_void,
    ];
    let host = std::array::from_fn::<_, 41, _>(|i| {
        // SAFETY: resolve the exact GNU export and reject the native address.
        unsafe { dlsym_oracle::host_addr(names[i], native[i].cast_const().cast()) }
    });
    for name in names {
        let name = name.to_str().unwrap();
        assert!(
            object
                .undefined_symbols()
                .any(|(_, s)| object.symbol_name(s) == Some(name))
        );
        let output = Command::new("objdump")
            .args(["-dr", &format!("--disassemble=integer_ext_call_{name}")])
            .arg(&library)
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            if got {
                text.contains('*') && !text.contains("@plt>")
            } else {
                text.contains(&format!("<{name}@plt>"))
            },
            "{name}: {text}"
        );
    }
    let mut reference = Vec::new();
    for (provider, expected) in [("GNU", host), ("native", native)] {
        let (open, close, symbol, new_locale, free_locale): (
            Open,
            Close,
            Sym,
            NewLocale,
            FreeLocale,
        ) = if provider == "native" {
            (
                dl::dlopen,
                dl::dlclose,
                dl::dlsym,
                locale_abi::newlocale,
                locale_abi::freelocale,
            )
        } else {
            // SAFETY: all GNU exports have their standard C prototypes.
            unsafe {
                (
                    dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ()),
                    dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ()),
                    dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ()),
                    dlsym_oracle::host_fn(c"newlocale", locale_abi::newlocale as *const ()),
                    dlsym_oracle::host_fn(c"freelocale", locale_abi::freelocale as *const ()),
                )
            }
        };
        // SAFETY: C is terminated and creates a fresh provider-owned locale.
        let locale = Locale(
            unsafe { new_locale(libc::LC_ALL_MASK, c"C".as_ptr(), std::ptr::null_mut()) },
            free_locale,
        );
        assert!(!locale.0.is_null(), "{provider}: C locale");
        let path = CString::new(library.as_os_str().as_bytes()).unwrap();
        // SAFETY: the live path is terminated; the handle stays loaded through all calls.
        let handle = unsafe { open(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        assert!(
            !handle.is_null(),
            "{provider}: extended integer plugin load failed"
        );
        if provider == "native" {
            assert!(
                dl::native_dso_handle_for_tests(handle),
                "host fallback is not native"
            );
        }
        // SAFETY: these exports have the exact prototypes in the C fixture.
        let (select, case, probe, lookup) = unsafe {
            let get = |name: &CStr| {
                let p = symbol(handle, name.as_ptr());
                assert!(!p.is_null());
                p
            };
            (
                std::mem::transmute::<*mut c_void, Selector>(get(c"integer_ext_function")),
                std::mem::transmute::<*mut c_void, Case>(get(c"integer_ext_case")),
                std::mem::transmute::<*mut c_void, Probe>(get(c"integer_ext_probe")),
                std::mem::transmute::<*mut c_void, Run>(get(c"integer_ext_lookup")),
            )
        };
        for (i, name) in names.iter().enumerate() {
            let wrapper =
                CString::new(format!("integer_ext_call_{}", name.to_str().unwrap())).unwrap();
            // SAFETY: all41indices select live imports/wrappers in this DSO.
            unsafe {
                assert_eq!(select(i as u32, 0), expected[i], "{provider}: {name:?}");
                assert_eq!(select(i as u32, 1), symbol(handle, wrapper.as_ptr()));
            }
        }
        // SAFETY: the zero-argument checker runs exactly451lookup outcomes.
        assert_eq!(unsafe { lookup() }, 0, "{provider}: versions");
        let mut observed = Vec::new();
        for function in 0..40 {
            for sample in 0..104 {
                let mut wide = vec![0x1234_i32; 6116];
                let mut narrow = vec![0x56_u8; 6116];
                let mut length = u32::MAX;
                // SAFETY: each live buffer has6100elements after its prefix guard;
                // the frozen corpus has at most5001characters plus its terminator.
                let base = unsafe {
                    case(
                        sample,
                        wide.as_mut_ptr().add(8),
                        narrow.as_mut_ptr().add(8).cast(),
                        &mut length,
                    )
                };
                assert!(length <= 5001);
                assert_eq!(&wide[..8], &[0x1234; 8]);
                assert_eq!(&narrow[..8], &[0x56; 8]);
                assert!(wide[9 + length as usize..].iter().all(|&x| x == 0x1234));
                assert!(narrow[9 + length as usize..].iter().all(|&x| x == 0x56));
                assert_eq!(wide[8 + length as usize], 0);
                assert_eq!(narrow[8 + length as usize], 0);
                let before_wide = wide.clone();
                let before_narrow = narrow.clone();
                for with_end in [0, 1] {
                    let mut out = Guarded {
                        before: 0x123456789abcdef0,
                        record: Record {
                            bits: 85,
                            offset: 85,
                            error: 85,
                        },
                        after: 0xfedcba9876543210,
                    };
                    // SAFETY: the selected terminated input and guarded output remain
                    // live; the locale belongs to this provider; the C probe checks endptr.
                    let rc = unsafe {
                        probe(
                            function,
                            if function < 20 {
                                narrow.as_ptr().add(8).cast()
                            } else {
                                wide.as_ptr().add(8).cast()
                            },
                            length,
                            base,
                            with_end,
                            locale.0,
                            &mut out.record,
                        )
                    };
                    assert_eq!(rc, 0, "{provider}: end guard/alignment");
                    assert_eq!(wide, before_wide, "{provider}: wide input modified");
                    assert_eq!(narrow, before_narrow, "{provider}: narrow input modified");
                    assert_eq!(
                        (out.before, out.after),
                        (0x123456789abcdef0, 0xfedcba9876543210)
                    );
                    if provider == "native" {
                        assert_eq!(
                            out.record,
                            reference[observed.len()],
                            "function={function} sample={sample} end={with_end}"
                        );
                    }
                    observed.push(out.record);
                }
            }
        }
        assert_eq!(observed.len(), 8320);
        eprintln!(
            "integer_extended provider={provider} got={got} imports=41 records=8320 lookup=451"
        );
        if provider == "GNU" {
            reference = observed;
        }
        // SAFETY: no DSO pointers are used after this close.
        assert_eq!(unsafe { close(handle) }, 0);
    }
}

#[cfg(target_arch = "x86_64")]
const INTEGER_EXTENDED_PLUGIN: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <locale.h>
#include <stddef.h>
#include <stdint.h>
#include <wchar.h>
_Static_assert(sizeof(long)==8 && sizeof(long long)==8 && sizeof(wchar_t)==4,"Linux LP64");
/* One list defines typed actual imports, wrappers and their index tables.
 * Exact asm names avoid header C23 redirection. Expected providers live in Rust. */
#define INTEGER_EXPORTS(F,L) \
 F(0,strtol,long,char) F(1,strtoul,unsigned long,char) \
 F(2,strtoll,long long,char) F(3,strtoull,unsigned long long,char) \
 F(4,strtoimax,intmax_t,char) F(5,strtoumax,uintmax_t,char) \
 L(6,strtol_l,long,char) L(7,strtoul_l,unsigned long,char) \
 L(8,strtoll_l,long long,char) L(9,strtoull_l,unsigned long long,char) \
 F(10,__isoc23_strtol,long,char) F(11,__isoc23_strtoul,unsigned long,char) \
 F(12,__isoc23_strtoll,long long,char) F(13,__isoc23_strtoull,unsigned long long,char) \
 F(14,__isoc23_strtoimax,intmax_t,char) F(15,__isoc23_strtoumax,uintmax_t,char) \
 L(16,__isoc23_strtol_l,long,char) L(17,__isoc23_strtoul_l,unsigned long,char) \
 L(18,__isoc23_strtoll_l,long long,char) L(19,__isoc23_strtoull_l,unsigned long long,char) \
 F(20,wcstol,long,wchar_t) F(21,wcstoul,unsigned long,wchar_t) \
 F(22,wcstoll,long long,wchar_t) F(23,wcstoull,unsigned long long,wchar_t) \
 F(24,wcstoimax,intmax_t,wchar_t) F(25,wcstoumax,uintmax_t,wchar_t) \
 L(26,wcstol_l,long,wchar_t) L(27,wcstoul_l,unsigned long,wchar_t) \
 L(28,wcstoll_l,long long,wchar_t) L(29,wcstoull_l,unsigned long long,wchar_t) \
 F(30,__isoc23_wcstol,long,wchar_t) F(31,__isoc23_wcstoul,unsigned long,wchar_t) \
 F(32,__isoc23_wcstoll,long long,wchar_t) F(33,__isoc23_wcstoull,unsigned long long,wchar_t) \
 F(34,__isoc23_wcstoimax,intmax_t,wchar_t) F(35,__isoc23_wcstoumax,uintmax_t,wchar_t) \
 L(36,__isoc23_wcstol_l,long,wchar_t) L(37,__isoc23_wcstoul_l,unsigned long,wchar_t) \
 L(38,__isoc23_wcstoll_l,long long,wchar_t) L(39,__isoc23_wcstoull_l,unsigned long long,wchar_t)
#define DECL(i,n,t,c) extern t ext_import_##n(const c *,c **,int) __asm__(#n); \
 t integer_ext_call_##n(const c *s,c **e,int b) { return ext_import_##n(s,e,b); }
#define DECL_L(i,n,t,c) extern t ext_import_##n(const c *,c **,int,locale_t) __asm__(#n); \
 t integer_ext_call_##n(const c *s,c **e,int b,locale_t l) { return ext_import_##n(s,e,b,l); }
INTEGER_EXPORTS(DECL,DECL_L)
int *integer_ext_call___errno_location(void) { return __errno_location(); }
void *integer_ext_function(unsigned i,unsigned wrappers) {
#define PTR(i,n,t,c) (void *)ext_import_##n,
#define WRAP(i,n,t,c) (void *)integer_ext_call_##n,
    void *const imports[]={INTEGER_EXPORTS(PTR,PTR) (void *)__errno_location};
    void *const calls[]={INTEGER_EXPORTS(WRAP,WRAP) (void *)integer_ext_call___errno_location};
    return i<41 ? (wrappers ? calls[i] : imports[i]) : 0;
}

struct integer_ext_result { uint64_t bits; int64_t offset; int error; };
int integer_ext_probe(unsigned i,const void *s,unsigned length,int base,int with_end,
                      locale_t locale,struct integer_ext_result *out) {
    int *slot=integer_ext_call___errno_location(); *slot=1234;
#define END_CELL(c) struct { volatile uint64_t left; c *pointer; volatile uint64_t right; } end = \
    {UINT64_C(0x12345678),(c *)s+length,UINT64_C(0x87654321)}; \
    c **e=with_end ? &end.pointer : 0;
#define CHECK_END(c) \
    if (end.left!=UINT64_C(0x12345678) || end.right!=UINT64_C(0x87654321)) return 2; \
    uintptr_t delta=(uintptr_t)end.pointer-(uintptr_t)s; \
    if (delta>length*sizeof(c) || delta%sizeof(c)) return 3; \
    out->offset=with_end ? (int64_t)(delta/sizeof(c)) : -1;
#define PARSE(i,n,t,c) case i: { END_CELL(c) \
    out->bits=(uint64_t)integer_ext_call_##n((const c *)s,e,base); \
    CHECK_END(c) break; }
#define PARSE_L(i,n,t,c) case i: { END_CELL(c) \
    out->bits=(uint64_t)integer_ext_call_##n((const c *)s,e,base,locale); \
    CHECK_END(c) break; }
    switch(i) { INTEGER_EXPORTS(PARSE,PARSE_L) default: return 1; }
    out->error=*slot;
    return 0;
}

/* 32 fixed cases +35 bases +one long overflow +36 scan-window cases.
 * Non-ASCII wide lookalikes become an invalid byte in the narrow C-locale case. */
int integer_ext_case(unsigned j,wchar_t *wide,char *narrow,unsigned *length) {
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
    _Static_assert(sizeof(cases)/sizeof(cases[0])==32,"frozen general corpus");
    const unsigned spaces[]={509,510,511,512,513,600};
    const wchar_t *const tails[]={L"42!",L"+42!",L"-101!",L"0b101!",L"+0B101!",L"-0x10!"};
    const int bases[]={0,2,2,0,2,0};
    unsigned size=0; int base; const wchar_t *text;
    if (j<32) { text=cases[j].text; base=cases[j].base; }
    else if (j<67) { text=L" +10z!"; base=(int)j-30; }
    else if (j==67) { for (;size<5000;size++) wide[size]=L'9'; text=L"!"; base=10; }
    else if (j<104) {
        unsigned group=(j-68)/6, tail=(j-68)%6;
        for (;size<spaces[group];size++) wide[size]=L' ';
        text=tails[tail]; base=bases[tail];
    } else { *length=0; wide[0]=0; narrow[0]=0; return 1; }
    for (unsigned k=0;text[k];k++) wide[size++]=text[k];
    wide[size]=0;
    for (unsigned k=0;k<=size;k++) narrow[k]=wide[k]<128 ? (char)wide[k] : (char)0xff;
    *length=size;
    return base;
}

int integer_ext_lookup(void) {
#define NAME(i,n,t,c) #n,
    const char *const names[]={INTEGER_EXPORTS(NAME,NAME) "__errno_location"};
    const char *const versions[]={"GLIBC_2.2.5","GLIBC_2.3","GLIBC_2.3.3","GLIBC_2.38"};
    const char *const bad[]={"GLIBC_2.17","GLIBC_2.25","GLIBC_2.34",
        "GLIBC_9.99","GLIBC_PRIVATE",""};
    for (unsigned i=0;i<41;i++) {
        unsigned family=i==40 ? 0 : ((i/10)%2 ? 3 :
            (i==8 || i==9 ? 2 : (i%10>=6 ? 1 : 0)));
        void *want=integer_ext_function(i,0); dlerror();
        if (dlsym(RTLD_DEFAULT,names[i])!=want || dlerror()) return 1;
        if (dlvsym(RTLD_DEFAULT,names[i],versions[family])!=want || dlerror()) return 2;
        for (unsigned v=0;v<4;v++) if (v!=family) {
            if (dlvsym(RTLD_DEFAULT,names[i],versions[v]) || !dlerror() || dlerror()) return 3;
        }
        for (unsigned b=0;b<6;b++) {
            if (dlvsym(RTLD_DEFAULT,names[i],bad[b]) || !dlerror() || dlerror()) return 4;
        }
    }
    return 0;
}
"#;
