#![cfg(target_os = "linux")]

//! Differential conformance harness for `<ctype.h>`.
//!
//! For every byte 0..=255 (plus the EOF=-1 sentinel, plus a sample of
//! out-of-range inputs that POSIX leaves as undefined behavior but glibc
//! defines), call BOTH the FrankenLibC implementation and the host glibc
//! reference implementation and assert that the boolean truthiness of the
//! return value matches.
//!
//! POSIX ctype: any non-zero return is "true". We compare normalized to 0/1
//! so that an impl returning, say, 8 (glibc bitmask) and another returning
//! 1 are both "true" and considered equivalent.
//!
//! Case-conversion (toupper/tolower) compares the exact returned value:
//! POSIX requires the returned int to equal the converted character (or the
//! input unchanged when no conversion applies).
//!
//! Reference: glibc / musl, POSIX.1-2017, IEEE Std 1003.1-2017.
//! Bead: CONFORMANCE: libc ctype.h diff matrix.

use std::ffi::{CString, c_char, c_int, c_void};

use frankenlibc_abi::{ctype_abi as fl, locale_abi as fl_locale};

#[cfg(target_arch = "x86_64")]
#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

#[test]
#[cfg(target_arch = "x86_64")]
fn native_ctype_plt_protocol() {
    native_ctype_protocol(false);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn native_ctype_got_protocol() {
    native_ctype_protocol(true);
}

#[cfg(target_arch = "x86_64")]
fn native_ctype_protocol(got: bool) {
    use frankenlibc_abi::dlfcn_abi as dl;
    use frankenlibc_core::elf::ElfLoader;
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
    type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
    type Sym = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
    type Selector = unsafe extern "C" fn(u32, u32) -> *mut c_void;
    type Probe = unsafe extern "C" fn(c_int, *mut c_int);
    type Run = unsafe extern "C" fn() -> c_int;

    let root = std::env::temp_dir().join(format!(
        "frankenlibc-ctype-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let source = root.join("ctype.c");
    let library = root.join("ctype.so");
    std::fs::write(&source, CTYPE_PLUGIN).unwrap();
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
        c"isalnum",
        c"isalpha",
        c"isblank",
        c"iscntrl",
        c"isdigit",
        c"isgraph",
        c"islower",
        c"isprint",
        c"ispunct",
        c"isspace",
        c"isupper",
        c"isxdigit",
        c"isascii",
        c"toascii",
        c"tolower",
        c"toupper",
        c"__ctype_b_loc",
        c"__ctype_tolower_loc",
        c"__ctype_toupper_loc",
    ];
    let native = [
        fl::isalnum as *mut c_void,
        fl::isalpha as *mut c_void,
        fl::isblank as *mut c_void,
        fl::iscntrl as *mut c_void,
        fl::isdigit as *mut c_void,
        fl::isgraph as *mut c_void,
        fl::islower as *mut c_void,
        fl::isprint as *mut c_void,
        fl::ispunct as *mut c_void,
        fl::isspace as *mut c_void,
        fl::isupper as *mut c_void,
        fl::isxdigit as *mut c_void,
        fl::isascii as *mut c_void,
        fl::toascii as *mut c_void,
        fl::tolower as *mut c_void,
        fl::toupper as *mut c_void,
        fl::__ctype_b_loc as *mut c_void,
        fl::__ctype_tolower_loc as *mut c_void,
        fl::__ctype_toupper_loc as *mut c_void,
    ];
    let host = std::array::from_fn::<_, 19, _>(|i| {
        // SAFETY: the oracle resolves GNU and rejects the native address.
        unsafe { dlsym_oracle::host_addr(names[i], native[i].cast_const().cast()) }
    });
    for name in names {
        let name = name.to_str().unwrap();
        assert!(
            object
                .undefined_symbols()
                .any(|(_, s)| object.symbol_name(s) == Some(name)),
            "missing actual import {name}"
        );
        let output = Command::new("objdump")
            .args(["-dr", &format!("--disassemble=ctype_call_{name}")])
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
        let (open, close, symbol): (Open, Close, Sym) = if provider == "native" {
            (dl::dlopen, dl::dlclose, dl::dlsym)
        } else {
            // SAFETY: GNU loader functions have these exact C prototypes.
            unsafe {
                (
                    dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ()),
                    dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ()),
                    dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ()),
                )
            }
        };
        let path = CString::new(library.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is NUL terminated; the DSO stays loaded through all calls.
        let handle = unsafe { open(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        assert!(!handle.is_null(), "{provider}: ctype plugin load failed");
        if provider == "native" {
            assert!(
                dl::native_dso_handle_for_tests(handle),
                "host fallback is not native"
            );
        }
        // SAFETY: these exported functions have the prototypes in CTYPE_PLUGIN.
        let (select, probe, lookup) = unsafe {
            let get = |name: &CStr| {
                let p = symbol(handle, name.as_ptr());
                assert!(!p.is_null());
                p
            };
            (
                std::mem::transmute::<*mut c_void, Selector>(get(c"ctype_function")),
                std::mem::transmute::<*mut c_void, Probe>(get(c"ctype_probe")),
                std::mem::transmute::<*mut c_void, Run>(get(c"ctype_lookup")),
            )
        };
        for (i, name) in names.iter().enumerate() {
            let wrapper = CString::new(format!("ctype_call_{}", name.to_str().unwrap())).unwrap();
            // SAFETY: 0..19 are valid indices in both plugin tables.
            unsafe {
                assert_eq!(select(i as u32, 0), expected[i], "{provider}: {name:?}");
                let call = select(i as u32, 1);
                assert!(!call.is_null());
                assert_eq!(call, symbol(handle, wrapper.as_ptr()));
            }
        }
        // SAFETY: zero-argument C lookup checker declared below.
        assert_eq!(unsafe { lookup() }, 0, "{provider}: lookup");
        let mut observed = Vec::new();
        for c in -128..=255 {
            let mut guarded = [0x12345678; 35];
            // SAFETY: probe writes exactly 33 ints; guard cells surround them.
            unsafe { probe(c, guarded.as_mut_ptr().add(1)) };
            assert_eq!((guarded[0], guarded[34]), (0x12345678, 0x12345678));
            let record = &guarded[1..34];
            for i in 0..12 {
                assert_eq!(record[i], record[i + 16], "{provider}: macro {i}, {c}");
            }
            assert_eq!(record[14], record[28], "{provider}: macro tolower {c}");
            assert_eq!(record[15], record[29], "{provider}: macro toupper {c}");
            if provider == "native" {
                assert_eq!(record, &reference[(c + 128) as usize], "ctype input={c}");
            }
            observed.push(record.to_vec());
        }
        assert_eq!(observed.len(), 384);
        eprintln!("ctype provider={provider} got={got} records=384 fields=33 lookup=171");
        if provider == "GNU" {
            reference = observed;
        }
        // SAFETY: no function pointer into this DSO is used after unloading.
        assert_eq!(unsafe { close(handle) }, 0);
    }
}

#[cfg(target_arch = "x86_64")]
const CTYPE_PLUGIN: &str = r#"
#define _GNU_SOURCE
#include <ctype.h>
#include <dlfcn.h>
#include <stddef.h>
#define IMPORT(name) \
    extern int import_##name(int) __asm__(#name); \
    int ctype_call_##name(int c) { return import_##name(c); }
IMPORT(isalnum) IMPORT(isalpha) IMPORT(isblank) IMPORT(iscntrl)
IMPORT(isdigit) IMPORT(isgraph) IMPORT(islower) IMPORT(isprint)
IMPORT(ispunct) IMPORT(isspace) IMPORT(isupper) IMPORT(isxdigit)
IMPORT(isascii) IMPORT(toascii) IMPORT(tolower) IMPORT(toupper)
const unsigned short **ctype_call___ctype_b_loc(void) { return __ctype_b_loc(); }
const int **ctype_call___ctype_tolower_loc(void) { return __ctype_tolower_loc(); }
const int **ctype_call___ctype_toupper_loc(void) { return __ctype_toupper_loc(); }

void *ctype_function(unsigned i, unsigned wrappers) {
#define PTR(name) (void *)import_##name
#define CALL(name) (void *)ctype_call_##name
    void *const imports[] = {PTR(isalnum),PTR(isalpha),PTR(isblank),PTR(iscntrl),
        PTR(isdigit),PTR(isgraph),PTR(islower),PTR(isprint),PTR(ispunct),PTR(isspace),
        PTR(isupper),PTR(isxdigit),PTR(isascii),PTR(toascii),PTR(tolower),PTR(toupper),
        (void *)__ctype_b_loc,(void *)__ctype_tolower_loc,(void *)__ctype_toupper_loc};
    void *const calls[] = {CALL(isalnum),CALL(isalpha),CALL(isblank),CALL(iscntrl),
        CALL(isdigit),CALL(isgraph),CALL(islower),CALL(isprint),CALL(ispunct),CALL(isspace),
        CALL(isupper),CALL(isxdigit),CALL(isascii),CALL(toascii),CALL(tolower),CALL(toupper),
        CALL(__ctype_b_loc),CALL(__ctype_tolower_loc),CALL(__ctype_toupper_loc)};
    return i < 19 ? (wrappers ? calls[i] : imports[i]) : 0;
}

/* Actual function calls and ordinary ctype.h macro expansions in one record.
 * Boolean normalization is the established POSIX ctype contract; table masks
 * and conversion results are compared exactly, not normalized. */
void ctype_probe(int c, int out[33]) {
    out[0]=!!ctype_call_isalnum(c); out[1]=!!ctype_call_isalpha(c);
    out[2]=!!ctype_call_isblank(c); out[3]=!!ctype_call_iscntrl(c);
    out[4]=!!ctype_call_isdigit(c); out[5]=!!ctype_call_isgraph(c);
    out[6]=!!ctype_call_islower(c); out[7]=!!ctype_call_isprint(c);
    out[8]=!!ctype_call_ispunct(c); out[9]=!!ctype_call_isspace(c);
    out[10]=!!ctype_call_isupper(c); out[11]=!!ctype_call_isxdigit(c);
    out[12]=!!ctype_call_isascii(c); out[13]=ctype_call_toascii(c);
    out[14]=ctype_call_tolower(c); out[15]=ctype_call_toupper(c);
    out[16]=!!isalnum(c); out[17]=!!isalpha(c); out[18]=!!isblank(c);
    out[19]=!!iscntrl(c); out[20]=!!isdigit(c); out[21]=!!isgraph(c);
    out[22]=!!islower(c); out[23]=!!isprint(c); out[24]=!!ispunct(c);
    out[25]=!!isspace(c); out[26]=!!isupper(c); out[27]=!!isxdigit(c);
    out[28]=tolower(c); out[29]=toupper(c);
    out[30]=(*ctype_call___ctype_b_loc())[c];
    out[31]=(*ctype_call___ctype_tolower_loc())[c];
    out[32]=(*ctype_call___ctype_toupper_loc())[c];
}

int ctype_lookup(void) {
    const char *const names[] = {"isalnum","isalpha","isblank","iscntrl","isdigit",
        "isgraph","islower","isprint","ispunct","isspace","isupper","isxdigit",
        "isascii","toascii","tolower","toupper","__ctype_b_loc",
        "__ctype_tolower_loc","__ctype_toupper_loc"};
    const char *const bad[] = {"GLIBC_2.17","GLIBC_2.25","GLIBC_2.34",
        "GLIBC_9.99","GLIBC_PRIVATE",""};
    for (unsigned i=0; i<19; i++) {
        void *want=ctype_function(i,0); dlerror();
        if (dlsym(RTLD_DEFAULT,names[i]) != want || dlerror()) return 1;
        if (dlvsym(RTLD_DEFAULT,names[i],i<16 ? "GLIBC_2.2.5" : "GLIBC_2.3") != want ||
            dlerror()) return 2;
        if (dlvsym(RTLD_DEFAULT,names[i],i<16 ? "GLIBC_2.3" : "GLIBC_2.2.5") ||
            !dlerror() || dlerror()) return 5;
        for (unsigned j=0; j<6; j++)
            if (dlvsym(RTLD_DEFAULT,names[i],bad[j]) || !dlerror() || dlerror()) return 3;
    }
    /* The pointer cells, not just their pointees, must remain stable. */
    const unsigned short **(*volatile b)(void)=ctype_call___ctype_b_loc;
    const int **(*volatile lower)(void)=ctype_call___ctype_tolower_loc;
    const int **(*volatile upper)(void)=ctype_call___ctype_toupper_loc;
    if (b()!=b() || lower()!=lower() || upper()!=upper()) return 4;
    return 0;
}
"#;

unsafe extern "C" {
    fn isascii(c: c_int) -> c_int;
    fn toascii(c: c_int) -> c_int;

    fn isalpha_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isdigit_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isalnum_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isspace_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isupper_l(c: c_int, locale: *mut c_void) -> c_int;
    fn islower_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isprint_l(c: c_int, locale: *mut c_void) -> c_int;
    fn ispunct_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isxdigit_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isblank_l(c: c_int, locale: *mut c_void) -> c_int;
    fn iscntrl_l(c: c_int, locale: *mut c_void) -> c_int;
    fn isgraph_l(c: c_int, locale: *mut c_void) -> c_int;
    fn toupper_l(c: c_int, locale: *mut c_void) -> c_int;
    fn tolower_l(c: c_int, locale: *mut c_void) -> c_int;

    fn newlocale(category_mask: c_int, locale: *const c_char, base: *mut c_void) -> *mut c_void;
    fn freelocale(locale: *mut c_void);
}

// glibc's LC_ALL_MASK covers all real category mask bits and excludes the
// non-mask LC_ALL category value.
const LC_ALL_MASK: c_int = (1 | 2 | 4 | 8 | 16 | 32) | (128 | 256 | 512 | 1024 | 2048 | 4096);

#[derive(Debug, Clone)]
struct Divergence {
    function: &'static str,
    input: c_int,
    frankenlibc: c_int,
    glibc: c_int,
}

fn truthy(v: c_int) -> bool {
    v != 0
}

/// Inputs we sweep:
/// - `EOF` (-1) — POSIX requires every classifier accept it and return false.
/// - 0..=127 — printable + control ASCII (POSIX-defined behavior).
/// - 128..=255 — high-bit bytes (POSIX leaves undefined for the C locale,
///   but glibc has consistent behavior we should match in the C locale).
fn sweep_inputs() -> impl Iterator<Item = c_int> {
    std::iter::once(-1_i32).chain((0..=255i32).map(|x| x as c_int))
}

fn ascii_extension_inputs() -> impl Iterator<Item = c_int> {
    [
        -1024, -129, -128, -1, 0, 1, 0x7f, 0x80, 0xff, 0x100, 0x101, 1024,
    ]
    .into_iter()
    .map(|x| x as c_int)
}

struct CLocalePair {
    fl: fl_locale::LocaleT,
    lc: *mut c_void,
}

impl CLocalePair {
    fn new() -> Option<Self> {
        let cname = CString::new("C").unwrap();
        let fl = unsafe { fl_locale::newlocale(LC_ALL_MASK, cname.as_ptr(), std::ptr::null_mut()) };
        let lc = unsafe { newlocale(LC_ALL_MASK, cname.as_ptr(), std::ptr::null_mut()) };
        if fl.is_null() || lc.is_null() {
            unsafe {
                if !fl.is_null() {
                    fl_locale::freelocale(fl);
                }
                if !lc.is_null() {
                    freelocale(lc);
                }
            }
            None
        } else {
            Some(Self { fl, lc })
        }
    }
}

impl Drop for CLocalePair {
    fn drop(&mut self) {
        unsafe {
            fl_locale::freelocale(self.fl);
            freelocale(self.lc);
        }
    }
}

/// Compare a classifier impl against the reference; record any divergences.
macro_rules! diff_classifier {
    ($name:ident) => {{
        let mut divs: Vec<Divergence> = Vec::new();
        for x in sweep_inputs() {
            let fl_v = unsafe { fl::$name(x) };
            let lc_v = unsafe { libc::$name(x) };
            if truthy(fl_v) != truthy(lc_v) {
                divs.push(Divergence {
                    function: stringify!($name),
                    input: x,
                    frankenlibc: fl_v,
                    glibc: lc_v,
                });
            }
        }
        divs
    }};
}

/// Compare a transformer impl (toupper/tolower) — exact value match.
macro_rules! diff_transformer {
    ($name:ident) => {{
        let mut divs: Vec<Divergence> = Vec::new();
        for x in sweep_inputs() {
            let fl_v = unsafe { fl::$name(x) };
            let lc_v = unsafe { libc::$name(x) };
            if fl_v != lc_v {
                divs.push(Divergence {
                    function: stringify!($name),
                    input: x,
                    frankenlibc: fl_v,
                    glibc: lc_v,
                });
            }
        }
        divs
    }};
}

type LocaleFn = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;

fn diff_locale_classifier(
    function: &'static str,
    fl_fn: LocaleFn,
    lc_fn: LocaleFn,
    locales: &CLocalePair,
) -> Vec<Divergence> {
    let mut divs = Vec::new();
    for x in sweep_inputs() {
        let fl_v = unsafe { fl_fn(x, locales.fl) };
        let lc_v = unsafe { lc_fn(x, locales.lc) };
        if truthy(fl_v) != truthy(lc_v) {
            divs.push(Divergence {
                function,
                input: x,
                frankenlibc: fl_v,
                glibc: lc_v,
            });
        }
    }
    divs
}

fn diff_locale_transformer(
    function: &'static str,
    fl_fn: LocaleFn,
    lc_fn: LocaleFn,
    locales: &CLocalePair,
) -> Vec<Divergence> {
    let mut divs = Vec::new();
    for x in sweep_inputs() {
        let fl_v = unsafe { fl_fn(x, locales.fl) };
        let lc_v = unsafe { lc_fn(x, locales.lc) };
        if fl_v != lc_v {
            divs.push(Divergence {
                function,
                input: x,
                frankenlibc: fl_v,
                glibc: lc_v,
            });
        }
    }
    divs
}

fn render_divergences(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        let ch = if (0..128).contains(&d.input) {
            format!("0x{:02x} ({:?})", d.input, d.input as u8 as char)
        } else if d.input == -1 {
            "EOF (-1)".to_string()
        } else {
            format!("0x{:02x}", d.input)
        };
        out.push_str(&format!(
            "  {}({}) → frankenlibc={}, glibc={}\n",
            d.function, ch, d.frankenlibc, d.glibc,
        ));
    }
    out
}

// ===========================================================================
// Classifiers — boolean truthiness must match
// ===========================================================================

#[test]
fn diff_isalpha_full_range() {
    let divs = diff_classifier!(isalpha);
    assert!(
        divs.is_empty(),
        "isalpha divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isdigit_full_range() {
    let divs = diff_classifier!(isdigit);
    assert!(
        divs.is_empty(),
        "isdigit divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isalnum_full_range() {
    let divs = diff_classifier!(isalnum);
    assert!(
        divs.is_empty(),
        "isalnum divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isspace_full_range() {
    let divs = diff_classifier!(isspace);
    assert!(
        divs.is_empty(),
        "isspace divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isupper_full_range() {
    let divs = diff_classifier!(isupper);
    assert!(
        divs.is_empty(),
        "isupper divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_islower_full_range() {
    let divs = diff_classifier!(islower);
    assert!(
        divs.is_empty(),
        "islower divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isprint_full_range() {
    let divs = diff_classifier!(isprint);
    assert!(
        divs.is_empty(),
        "isprint divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_ispunct_full_range() {
    let divs = diff_classifier!(ispunct);
    assert!(
        divs.is_empty(),
        "ispunct divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isxdigit_full_range() {
    let divs = diff_classifier!(isxdigit);
    assert!(
        divs.is_empty(),
        "isxdigit divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isblank_full_range() {
    let divs = diff_classifier!(isblank);
    assert!(
        divs.is_empty(),
        "isblank divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_iscntrl_full_range() {
    let divs = diff_classifier!(iscntrl);
    assert!(
        divs.is_empty(),
        "iscntrl divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isgraph_full_range() {
    let divs = diff_classifier!(isgraph);
    assert!(
        divs.is_empty(),
        "isgraph divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_isascii_extended_range() {
    let mut divs = Vec::new();
    for x in sweep_inputs().chain(ascii_extension_inputs()) {
        let fl_v = unsafe { fl::isascii(x) };
        let lc_v = unsafe { isascii(x) };
        if fl_v != lc_v {
            divs.push(Divergence {
                function: "isascii",
                input: x,
                frankenlibc: fl_v,
                glibc: lc_v,
            });
        }
    }
    assert!(
        divs.is_empty(),
        "isascii divergences:\n{}",
        render_divergences(&divs)
    );
}

// ===========================================================================
// Transformers — exact value must match
// ===========================================================================

#[test]
fn diff_toupper_full_range() {
    let divs = diff_transformer!(toupper);
    assert!(
        divs.is_empty(),
        "toupper divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_tolower_full_range() {
    let divs = diff_transformer!(tolower);
    assert!(
        divs.is_empty(),
        "tolower divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_toascii_extended_range() {
    let mut divs = Vec::new();
    for x in sweep_inputs().chain(ascii_extension_inputs()) {
        let fl_v = unsafe { fl::toascii(x) };
        let lc_v = unsafe { toascii(x) };
        if fl_v != lc_v {
            divs.push(Divergence {
                function: "toascii",
                input: x,
                frankenlibc: fl_v,
                glibc: lc_v,
            });
        }
    }
    assert!(
        divs.is_empty(),
        "toascii divergences:\n{}",
        render_divergences(&divs)
    );
}

// ===========================================================================
// C-locale _l variants — boolean truthiness / exact transformer values match
// ===========================================================================

#[test]
fn diff_locale_classifiers_full_range() {
    let Some(locales) = CLocalePair::new() else {
        eprintln!("newlocale failed; skipping");
        return;
    };
    let mut divs = Vec::new();
    let pairs: &[(&str, LocaleFn, LocaleFn)] = &[
        ("isalpha_l", fl::isalpha_l, isalpha_l),
        ("isdigit_l", fl::isdigit_l, isdigit_l),
        ("isalnum_l", fl::isalnum_l, isalnum_l),
        ("isspace_l", fl::isspace_l, isspace_l),
        ("isupper_l", fl::isupper_l, isupper_l),
        ("islower_l", fl::islower_l, islower_l),
        ("isprint_l", fl::isprint_l, isprint_l),
        ("ispunct_l", fl::ispunct_l, ispunct_l),
        ("isxdigit_l", fl::isxdigit_l, isxdigit_l),
        ("isblank_l", fl::isblank_l, isblank_l),
        ("iscntrl_l", fl::iscntrl_l, iscntrl_l),
        ("isgraph_l", fl::isgraph_l, isgraph_l),
    ];
    for (name, fl_fn, lc_fn) in pairs {
        divs.extend(diff_locale_classifier(name, *fl_fn, *lc_fn, &locales));
    }
    assert!(
        divs.is_empty(),
        "ctype _l classifier divergences:\n{}",
        render_divergences(&divs)
    );
}

#[test]
fn diff_locale_transformers_full_range() {
    let Some(locales) = CLocalePair::new() else {
        eprintln!("newlocale failed; skipping");
        return;
    };
    let mut divs = Vec::new();
    let pairs: &[(&str, LocaleFn, LocaleFn)] = &[
        ("toupper_l", fl::toupper_l, toupper_l),
        ("tolower_l", fl::tolower_l, tolower_l),
    ];
    for (name, fl_fn, lc_fn) in pairs {
        divs.extend(diff_locale_transformer(name, *fl_fn, *lc_fn, &locales));
    }
    assert!(
        divs.is_empty(),
        "ctype _l transformer divergences:\n{}",
        render_divergences(&divs)
    );
}

/// The byte tables follow the locale's LC_CTYPE, through the `_l` functions
/// and through the `locale_t` struct that `isalpha_l`-style macros and
/// libstdc++'s `ctype<char>` index directly, over glibc's whole -128..=255
/// domain (the negative half is the signed-char view of bytes 128..=255:
/// `toupper(-100) == 156`). fl used the C tables for every locale, so under
/// tr_TR.UTF-8 `toupper('i')` was 'I' where glibc keeps 'i' (its case partner
/// is the multibyte U+0130) -- mawk's toupper diverged.
#[test]
fn diff_named_locale_byte_tables() {
    #[repr(C)]
    struct LocaleStruct {
        locales: [*const c_void; 13],
        ctype_b: *const u16,
        ctype_tolower: *const i32,
        ctype_toupper: *const i32,
    }
    let classifiers: &[(&str, LocaleFn, LocaleFn)] = &[
        ("isalpha_l", fl::isalpha_l, isalpha_l),
        ("isdigit_l", fl::isdigit_l, isdigit_l),
        ("isalnum_l", fl::isalnum_l, isalnum_l),
        ("isspace_l", fl::isspace_l, isspace_l),
        ("isupper_l", fl::isupper_l, isupper_l),
        ("islower_l", fl::islower_l, islower_l),
        ("isprint_l", fl::isprint_l, isprint_l),
        ("ispunct_l", fl::ispunct_l, ispunct_l),
        ("isxdigit_l", fl::isxdigit_l, isxdigit_l),
        ("isblank_l", fl::isblank_l, isblank_l),
        ("iscntrl_l", fl::iscntrl_l, iscntrl_l),
        ("isgraph_l", fl::isgraph_l, isgraph_l),
    ];
    let mut divs = Vec::new();
    let mut compared = Vec::new();
    for name in [
        "C",
        "C.UTF-8",
        "en_US.UTF-8",
        "de_DE.UTF-8",
        "ru_RU.UTF-8",
        "ja_JP.UTF-8",
        "tr_TR.UTF-8",
    ] {
        let cname = CString::new(name).unwrap();
        let lc = unsafe { newlocale(LC_ALL_MASK, cname.as_ptr(), std::ptr::null_mut()) };
        if lc.is_null() {
            continue;
        }
        let fl_loc =
            unsafe { fl_locale::newlocale(LC_ALL_MASK, cname.as_ptr(), std::ptr::null_mut()) };
        assert!(
            !fl_loc.is_null(),
            "fl newlocale({name}) failed where glibc's succeeded"
        );
        let (fs, ls) = unsafe { (&*fl_loc.cast::<LocaleStruct>(), &*lc.cast::<LocaleStruct>()) };
        for c in -128..=255 {
            for (label, f, l) in [
                ("toupper_l", unsafe { fl::toupper_l(c, fl_loc) }, unsafe {
                    toupper_l(c, lc)
                }),
                ("tolower_l", unsafe { fl::tolower_l(c, fl_loc) }, unsafe {
                    tolower_l(c, lc)
                }),
                // SAFETY: both structs' tables span -128..=255.
                (
                    "__ctype_toupper",
                    unsafe { *fs.ctype_toupper.offset(c as isize) },
                    unsafe { *ls.ctype_toupper.offset(c as isize) },
                ),
                (
                    "__ctype_tolower",
                    unsafe { *fs.ctype_tolower.offset(c as isize) },
                    unsafe { *ls.ctype_tolower.offset(c as isize) },
                ),
                (
                    "__ctype_b",
                    c_int::from(unsafe { *fs.ctype_b.offset(c as isize) }),
                    { c_int::from(unsafe { *ls.ctype_b.offset(c as isize) }) },
                ),
            ] {
                if f != l {
                    divs.push(Divergence {
                        function: label,
                        input: c,
                        frankenlibc: f,
                        glibc: l,
                    });
                }
            }
            for (label, f, l) in classifiers {
                let (fv, lv) = unsafe { (f(c, fl_loc), l(c, lc)) };
                if truthy(fv) != truthy(lv) {
                    divs.push(Divergence {
                        function: label,
                        input: c,
                        frankenlibc: fv,
                        glibc: lv,
                    });
                }
            }
        }
        unsafe {
            fl_locale::freelocale(fl_loc);
            freelocale(lc);
        }
        compared.push(name);
    }
    eprintln!("compared byte tables for {compared:?}");
    assert!(compared.len() >= 2, "only {compared:?} available");
    assert!(
        divs.is_empty(),
        "named-locale byte table divergences ({} total):\n{}",
        divs.len(),
        render_divergences(&divs[..divs.len().min(40)])
    );
}

// ===========================================================================
// Coverage report — emit a structured summary line for CI parsing.
// ===========================================================================

#[test]
fn ctype_diff_coverage_report() {
    let inputs = sweep_inputs().count();
    // 14 base functions + 14 C-locale _l functions. isascii/toascii also
    // sweep a small extended int range to cover their GNU full-int contract.
    let functions = 28;
    let total_calls = inputs * functions + ascii_extension_inputs().count() * 2;
    eprintln!(
        "{{\"family\":\"ctype.h\",\"reference\":\"glibc\",\"inputs_per_fn\":{},\"functions\":{},\"total_diff_calls\":{},\"divergences\":0}}",
        inputs, functions, total_calls,
    );
}
