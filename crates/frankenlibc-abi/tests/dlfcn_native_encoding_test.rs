#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::{
    dlfcn_abi as dl, errno_abi as errno, glibc_internal_abi as internal, iconv_abi as iconv,
    locale_abi as locale, wchar_abi as wide,
};
use frankenlibc_core::elf::ElfLoader;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
type Sym = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type Run = unsafe extern "C" fn() -> c_int;
type Function = unsafe extern "C" fn(u32) -> *mut c_void;
type Dynamic = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type IconvOpen = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type Convert = unsafe extern "C" fn(
    *mut c_void,
    *mut *mut c_char,
    *mut usize,
    *mut *mut c_char,
    *mut usize,
) -> usize;

const SOURCE: &str = r#"#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <dlfcn.h>
#include <iconv.h>
#include <locale.h>
#include <wchar.h>
#include <uchar.h>

extern size_t __mbrlen(const char *, size_t, mbstate_t *);
extern size_t __mbrtowc(wchar_t *, const char *, size_t, mbstate_t *);

#define CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)
static const char text[] = "A\xE2\x82\xAC\xF0\x9F\x98\x80";
static const unsigned char utf16[] = {0x41, 0, 0xAC, 0x20, 0x3D, 0xD8, 0, 0xDE};

#ifdef LOCAL_CLOSE
int iconv_close(iconv_t descriptor) { (void)descriptor; return 23; }
#endif
int encoding_preemption_probe(void) { return iconv_close((iconv_t)0); }

/* Exercise caller-owned states and the locale object selected by this DSO. */
static int multibyte_body(locale_t plain, locale_t utf8) {
    mbstate_t state = {0};
    wchar_t wc = 0;
    CHECK(uselocale(plain) != (locale_t)0 && MB_CUR_MAX == 1);
    errno = 0;
    CHECK(mbrtowc(&wc, text + 1, 3, &state) == (size_t)-1 && errno == EILSEQ);
    memset(&state, 0, sizeof state);
    errno = 0;
    CHECK(__mbrtowc(&wc, text + 1, 3, &state) == (size_t)-1 && errno == EILSEQ);
    memset(&state, 0, sizeof state);
    errno = 0;
    CHECK(__mbrlen(text + 1, 3, &state) == (size_t)-1 && errno == EILSEQ);
    memset(&state, 0, sizeof state);
    CHECK(uselocale(utf8) != (locale_t)0 && MB_CUR_MAX == 6);
    CHECK(mbsinit(NULL) && mbsinit(&state));
    CHECK(mbrtowc(&wc, text + 1, 1, &state) == (size_t)-2 && !mbsinit(&state));
    CHECK(mbrtowc(&wc, text + 2, 2, &state) == 2 && wc == 0x20AC && mbsinit(&state));
    CHECK(mbrlen(text + 4, 2, &state) == (size_t)-2 && !mbsinit(&state));
    CHECK(mbrlen(text + 6, 2, &state) == 2 && mbsinit(&state));
    CHECK(__mbrtowc(&wc, text + 1, 1, &state) == (size_t)-2);
    CHECK(__mbrtowc(&wc, text + 2, 2, &state) == 2 && wc == 0x20AC);
    CHECK(__mbrlen(text + 1, 3, &state) == 3 && mbsinit(&state));

    char bytes[16];
    memset(bytes, 0x5A, sizeof bytes);
    CHECK(wcrtomb(bytes, 0x20AC, &state) == 3);
    CHECK(!memcmp(bytes, text + 1, 3) && bytes[3] == 0x5A);
    CHECK(btowc('A') == L'A' && wctob(L'A') == 'A');
    CHECK(btowc(255) == WEOF && wctob(0x20AC) == -1);

    wchar_t output[4] = {0};
    const char *source = text;
    mbstate_t before = state;
    CHECK(mbsrtowcs(NULL, &source, 0, &state) == 3 && source == text);
    CHECK(!memcmp(&state, &before, sizeof state));
    CHECK(mbsrtowcs(output, &source, 2, &state) == 2 && source == text + 4);
    CHECK(mbsrtowcs(output + 2, &source, 2, &state) == 1 && source == NULL);
    CHECK(output[0] == L'A' && output[1] == 0x20AC
          && output[2] == 0x1F600 && output[3] == 0);
    const wchar_t *wide_source = output;
    memset(bytes, 0x5A, sizeof bytes);
    CHECK(wcsrtombs(bytes, &wide_source, 4, &state) == 4 && wide_source == output + 2);
    CHECK(wcsrtombs(bytes + 4, &wide_source, 5, &state) == 4 && wide_source == NULL);
    CHECK(!memcmp(bytes, text, sizeof text) && bytes[sizeof text] == 0x5A);

    source = text;
    memset(output, 0, sizeof output);
    CHECK(mbsnrtowcs(output, &source, 2, 4, &state) == 1);
    CHECK(source == text + 2 && !mbsinit(&state));
    CHECK(mbsnrtowcs(output + 1, &source, sizeof text - 2, 3, &state) == 2);
    CHECK(source == NULL && mbsinit(&state));
    CHECK(output[1] == 0x20AC && output[2] == 0x1F600 && output[3] == 0);
    wide_source = output;
    memset(bytes, 0x5A, sizeof bytes);
    CHECK(wcsnrtombs(bytes, &wide_source, 2, 3, &state) == 1);
    CHECK(wide_source == output + 1 && bytes[1] == 0x5A);
    CHECK(wcsnrtombs(bytes + 1, &wide_source, 3, 8, &state) == 7 && wide_source == NULL);
    CHECK(!memcmp(bytes, text, sizeof text) && bytes[sizeof text] == 0x5A);

    CHECK(mblen(NULL, 0) == 0 && mblen(text + 1, 3) == 3);
    CHECK(mbtowc(&wc, text + 1, 3) == 3 && wc == 0x20AC);
    CHECK(wctomb(bytes, 0x20AC) == 3 && !memcmp(bytes, text + 1, 3));
    CHECK(mbstowcs(output, text, 4) == 3 && output[2] == 0x1F600);
    CHECK(wcstombs(bytes, output, sizeof bytes) == 8 && !memcmp(bytes, text, sizeof text));

    char16_t unit = 0;
    CHECK(mbrtoc16(&unit, text + 4, 4, &state) == 4 && unit == 0xD83D);
    CHECK(!mbsinit(&state));
    CHECK(mbrtoc16(&unit, "Q", 1, &state) == (size_t)-3 && unit == 0xDE00);
    CHECK(mbsinit(&state));
    CHECK(mbrtoc16(&unit, "Q", 1, &state) == 1 && unit == u'Q');
    memset(bytes, 0x5A, sizeof bytes);
    CHECK(c16rtomb(bytes, 0xD83D, &state) == 0 && bytes[0] == 0x5A);
    CHECK(!mbsinit(&state));
    CHECK(c16rtomb(bytes, 0xDE00, &state) == 4 && mbsinit(&state));
    CHECK(!memcmp(bytes, text + 4, 4) && bytes[4] == 0x5A);
    CHECK(c16rtomb(NULL, 0, &state) == 1 && mbsinit(&state));
    char32_t scalar = 0;
    CHECK(mbrtoc32(&scalar, text + 1, 3, &state) == 3 && scalar == 0x20AC);
    CHECK(c32rtomb(bytes, scalar, &state) == 3 && !memcmp(bytes, text + 1, 3));
    return 0;
}

/* Every failing conversion must publish only its completed prefix. */
static int iconv_body(iconv_t descriptor) {
    unsigned char storage[12];
    memset(storage, 0xA5, sizeof storage);
    char *input = (char *)text;
    char *output = (char *)storage + 1;
    size_t input_left = sizeof text - 1, output_left = 3;
    errno = 0;
    CHECK(iconv(descriptor, &input, &input_left, &output, &output_left) == (size_t)-1);
    CHECK(errno == E2BIG && input == text + 1 && input_left == 7);
    CHECK(output == (char *)storage + 3 && output_left == 1);
    CHECK(storage[0] == 0xA5 && storage[1] == 'A' && storage[2] == 0 && storage[3] == 0xA5);
    output_left = 6;
    CHECK(iconv(descriptor, &input, &input_left, &output, &output_left) == 0);
    CHECK(input == text + 8 && input_left == 0 && output_left == 0);
    CHECK(output == (char *)storage + 9 && storage[9] == 0xA5);
    CHECK(!memcmp(storage + 1, utf16, sizeof utf16));

    input = (char *)text + 1; input_left = 2;
    output = (char *)storage + 1; output_left = 10;
    errno = 0;
    CHECK(iconv(descriptor, &input, &input_left, &output, &output_left) == (size_t)-1);
    CHECK(errno == EINVAL && input == text + 1 && input_left == 2);
    CHECK(output == (char *)storage + 1 && output_left == 10);
    input_left = 3;
    CHECK(iconv(descriptor, &input, &input_left, &output, &output_left) == 0);
    CHECK(input_left == 0 && output_left == 8 && storage[1] == 0xAC && storage[2] == 0x20);

    char invalid[] = {(char)0xFF};
    input = invalid; input_left = sizeof invalid;
    output = (char *)storage + 1; output_left = 10;
    errno = 0;
    CHECK(iconv(descriptor, &input, &input_left, &output, &output_left) == (size_t)-1);
    CHECK(errno == EILSEQ && input == invalid && input_left == 1);
    CHECK(output == (char *)storage + 1 && output_left == 10);
    CHECK(iconv(descriptor, NULL, NULL, NULL, NULL) == 0);
    input = (char *)text; input_left = 1;
    errno = 1234;
    CHECK(iconv(descriptor, &input, &input_left, &output, &output_left) == 0);
    CHECK(errno == 1234 && input_left == 0 && output_left == 8);
    CHECK(storage[1] == 'A' && storage[2] == 0 && storage[0] == 0xA5 && storage[11] == 0xA5);
    return 0;
}

iconv_t encoding_create(void) { return iconv_open("UTF-16LE", "UTF-8"); }
int encoding_accept(iconv_t descriptor) { return iconv_body(descriptor); }

static int locale_body(locale_t plain, locale_t utf8) {
    int result = multibyte_body(plain, utf8);
    if (result) return result;
    /* An empty source codeset must consult the DSO-selected UTF-8 locale. */
    iconv_t descriptor = iconv_open("UTF-16LE", "");
    CHECK(descriptor != (iconv_t)-1);
    result = iconv_body(descriptor);
    if (iconv_close(descriptor) && !result) result = __LINE__;
    if (result) return result;
    errno = 0;
    CHECK(iconv_open("FRANKENLIBC_NO_SUCH_CODESET", "UTF-8") == (iconv_t)-1);
    CHECK(errno == EINVAL);
    return 0;
}

int encoding_run(void) {
    locale_t plain = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    CHECK(plain != (locale_t)0);
    locale_t utf8 = newlocale(LC_ALL_MASK, "C.UTF-8", (locale_t)0);
    if (!utf8) { freelocale(plain); return __LINE__; }
    locale_t previous = uselocale(plain);
    if (!previous) { freelocale(utf8); freelocale(plain); return __LINE__; }
    int result = locale_body(plain, utf8);
    if (!uselocale(previous) && !result) result = __LINE__;
    freelocale(utf8);
    freelocale(plain);
    return result;
}

void *encoding_function(unsigned index) {
    switch (index) {
        case 0: return (void *)iconv_open;
        case 1: return (void *)iconv;
        case 2: return (void *)iconv_close;
        case 3: return (void *)__ctype_get_mb_cur_max;
        case 4: return (void *)mbrlen;
        case 5: return (void *)mbrtowc;
        case 6: return (void *)mbsinit;
        case 7: return (void *)wcrtomb;
        case 8: return (void *)mbsrtowcs;
        case 9: return (void *)wcsrtombs;
        case 10: return (void *)mbsnrtowcs;
        case 11: return (void *)wcsnrtombs;
        case 12: return (void *)btowc;
        case 13: return (void *)wctob;
        case 14: return (void *)mblen;
        case 15: return (void *)mbtowc;
        case 16: return (void *)wctomb;
        case 17: return (void *)mbstowcs;
        case 18: return (void *)wcstombs;
        case 19: return (void *)__mbrlen;
        case 20: return (void *)__mbrtowc;
        case 21: return (void *)c16rtomb;
        case 22: return (void *)c32rtomb;
        case 23: return (void *)mbrtoc16;
        case 24: return (void *)mbrtoc32;
        default: return NULL;
    }
}
void *encoding_dynamic(const char *name, const char *version) {
    return version ? dlvsym(RTLD_DEFAULT, name, version) : dlsym(RTLD_DEFAULT, name);
}
int encoding_lookup_errors(void) {
    dlerror();
    CHECK(dlvsym(RTLD_DEFAULT, "mbrtoc16", "GLIBC_2.2.5") == NULL);
    CHECK(dlerror() != NULL && dlerror() == NULL);
    CHECK(dlvsym(RTLD_DEFAULT, "mbrtoc16", "GLIBC_2.16") != NULL);
    CHECK(dlerror() == NULL);
    return 0;
}

#ifdef LIFECYCLE
int encoding_init_result = -1;
static iconv_t lifetime_descriptor = (iconv_t)-1;
static void (*encoding_report)(int);
__attribute__((constructor)) static void init(void) {
    lifetime_descriptor = encoding_create();
    encoding_init_result = lifetime_descriptor == (iconv_t)-1 ? __LINE__ : 0;
}
void encoding_set_report(void (*report)(int)) { encoding_report = report; }
__attribute__((destructor)) static void fini(void) {
    int result = iconv_body(lifetime_descriptor);
    if (iconv_close(lifetime_descriptor) && !result) result = __LINE__;
    if (encoding_report) encoding_report(result);
}
#endif
"#;

fn symbols() -> [(&'static str, *const ()); 25] {
    [
        ("iconv_open", iconv::iconv_open as *const ()),
        ("iconv", iconv::iconv as *const ()),
        ("iconv_close", iconv::iconv_close as *const ()),
        (
            "__ctype_get_mb_cur_max",
            internal::__ctype_get_mb_cur_max as *const (),
        ),
        ("mbrlen", wide::mbrlen as *const ()),
        ("mbrtowc", wide::mbrtowc as *const ()),
        ("mbsinit", wide::mbsinit as *const ()),
        ("wcrtomb", wide::wcrtomb as *const ()),
        ("mbsrtowcs", wide::mbsrtowcs as *const ()),
        ("wcsrtombs", wide::wcsrtombs as *const ()),
        ("mbsnrtowcs", wide::mbsnrtowcs as *const ()),
        ("wcsnrtombs", wide::wcsnrtombs as *const ()),
        ("btowc", wide::btowc as *const ()),
        ("wctob", wide::wctob as *const ()),
        ("mblen", wide::mblen as *const ()),
        ("mbtowc", wide::mbtowc as *const ()),
        ("wctomb", wide::wctomb as *const ()),
        ("mbstowcs", wide::mbstowcs as *const ()),
        ("wcstombs", wide::wcstombs as *const ()),
        ("__mbrlen", wide::mbrlen as *const ()),
        ("__mbrtowc", wide::mbrtowc as *const ()),
        ("c16rtomb", wide::c16rtomb as *const ()),
        ("c32rtomb", wide::c32rtomb as *const ()),
        ("mbrtoc16", wide::mbrtoc16 as *const ()),
        ("mbrtoc32", wide::mbrtoc32 as *const ()),
    ]
}

#[derive(Clone, Copy)]
struct Api {
    open: Open,
    close: Close,
    sym: Sym,
    native: bool,
}

impl Api {
    fn new(native: bool) -> Self {
        if native {
            Self {
                open: dl::dlopen,
                close: dl::dlclose,
                sym: dl::dlsym,
                native,
            }
        } else {
            unsafe {
                Self {
                    open: dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ()),
                    close: dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ()),
                    sym: dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ()),
                    native,
                }
            }
        }
    }

    fn open(self, path: &Path, flags: c_int) -> *mut c_void {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(name.as_ptr(), flags | libc::RTLD_NOW) };
        assert!(!handle.is_null(), "open {path:?}");
        if self.native {
            assert!(dl::native_dso_handle_for_tests(handle), "host fallback");
        }
        handle
    }

    fn close(self, handle: *mut c_void) {
        assert_eq!(unsafe { (self.close)(handle) }, 0);
    }

    fn symbol(self, handle: *mut c_void, name: &CStr) -> *mut c_void {
        let address = unsafe { (self.sym)(handle, name.as_ptr()) };
        assert!(!address.is_null(), "symbol {name:?}");
        address
    }

    fn run(self, handle: *mut c_void, name: &CStr) -> c_int {
        let run: Run = unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { run() }
    }
}

struct Fixture {
    dir: PathBuf,
    path: PathBuf,
}

impl Fixture {
    fn new(flags: &[&str]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc-encoding-runtime-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("encoding.c");
        let path = dir.join("encoding.so");
        std::fs::write(&source, SOURCE).unwrap();
        compile(&source, &path, flags);
        let object = ElfLoader::new(0)
            .parse(&std::fs::read(&path).unwrap())
            .unwrap();
        assert!(
            object.needed_libraries.is_empty(),
            "fixture must not import a host runtime"
        );
        for (name, _) in symbols() {
            assert!(
                object
                    .dynsym
                    .iter()
                    .any(|symbol| object.symbol_name(symbol) == Some(name)),
                "missing import {name}"
            );
        }
        Self { dir, path }
    }
}

fn compile(source: &Path, output: &Path, flags: &[&str]) {
    let result = Command::new("gcc")
        .args([
            "-shared",
            "-fPIC",
            "-nostdlib",
            "-O2",
            "-fno-builtin",
            "-Wl,--hash-style=both",
        ])
        .args(flags)
        .arg(source)
        .arg("-o")
        .arg(output)
        .output()
        .expect("gcc is required");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn isolated(name: &str, native_only: bool, scenario: fn(Api)) {
    if let Ok(mode) = std::env::var("FRANKENLIBC_ENCODING_CHILD") {
        assert!(matches!(mode.as_str(), "host" | "native"));
        scenario(Api::new(mode == "native"));
        return;
    }
    let modes: &[&str] = if native_only {
        &["native"]
    } else {
        &["host", "native"]
    };
    for mode in modes {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FRANKENLIBC_ENCODING_CHILD", mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            if child.try_wait().unwrap().is_some() {
                let output = child.wait_with_output().unwrap();
                assert!(
                    output.status.success(),
                    "{name}: {mode}: {}\nstdout:\n{}\nstderr:\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                break;
            }
            if start.elapsed() > Duration::from_secs(40) {
                child.kill().unwrap();
                let _ = child.wait_with_output();
                panic!("{name}: {mode}: timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn assert_providers(api: Api, handle: *mut c_void) {
    let imported: Function =
        unsafe { std::mem::transmute(api.symbol(handle, c"encoding_function")) };
    for (index, (name, expected)) in symbols().into_iter().enumerate() {
        let actual = unsafe { imported(index as u32) };
        assert!(!actual.is_null(), "missing runtime {name}");
        if api.native {
            assert_eq!(actual as usize, expected as usize, "wrong provider: {name}");
        } else {
            let name = CString::new(name).unwrap();
            let host = unsafe { dlsym_oracle::host_addr(&name, expected) };
            assert_eq!(actual, host, "wrong provider: {name:?}");
        }
    }
}

#[test]
fn native_encoding_plt_and_got_execute_in_selected_locale() {
    isolated(
        "native_encoding_plt_and_got_execute_in_selected_locale",
        false,
        |api| {
            for flags in [&[][..], &["-fno-plt"][..]] {
                let fixture = Fixture::new(flags);
                let handle = api.open(&fixture.path, 0);
                assert_providers(api, handle);
                assert_eq!(api.run(handle, c"encoding_run"), 0);
                api.close(handle);
            }
        },
    );
}

#[test]
fn native_encoding_dynamic_lookup_keeps_versions_and_providers() {
    isolated(
        "native_encoding_dynamic_lookup_keeps_versions_and_providers",
        false,
        |api| {
            let fixture = Fixture::new(&[]);
            let handle = api.open(&fixture.path, 0);
            assert_providers(api, handle);
            let imported: Function =
                unsafe { std::mem::transmute(api.symbol(handle, c"encoding_function")) };
            let dynamic: Dynamic =
                unsafe { std::mem::transmute(api.symbol(handle, c"encoding_dynamic")) };
            for (index, (name, _)) in symbols().into_iter().enumerate() {
                let valid_version = match name {
                    "c16rtomb" | "c32rtomb" | "mbrtoc16" | "mbrtoc32" => c"GLIBC_2.16",
                    _ => c"GLIBC_2.2.5",
                };
                let wrong_version = if valid_version == c"GLIBC_2.16" {
                    c"GLIBC_2.2.5"
                } else {
                    c"GLIBC_2.16"
                };
                let name = CString::new(name).unwrap();
                let direct = unsafe { imported(index as u32) };
                for version in [std::ptr::null(), valid_version.as_ptr()] {
                    assert_eq!(
                        unsafe { dynamic(name.as_ptr(), version) },
                        direct,
                        "dynamic provider: {name:?}"
                    );
                }
                for version in [
                    wrong_version,
                    c"GLIBC_PRIVATE",
                    c"FRANKENLIBC_NO_SUCH_VERSION",
                ] {
                    assert!(
                        unsafe { dynamic(name.as_ptr(), version.as_ptr()) }.is_null(),
                        "unsupported version: {name:?}: {version:?}"
                    );
                }
            }
            assert_eq!(api.run(handle, c"encoding_lookup_errors"), 0);
            api.close(handle);
        },
    );
}

static FINAL_RESULT: AtomicI32 = AtomicI32::new(-100);

unsafe extern "C" fn final_report(result: c_int) {
    FINAL_RESULT.store(result, Ordering::Relaxed);
}

#[test]
fn native_encoding_descriptors_cross_dso_boundaries_and_finalize() {
    isolated(
        "native_encoding_descriptors_cross_dso_boundaries_and_finalize",
        false,
        |api| {
            let fixture = Fixture::new(&["-DLIFECYCLE"]);
            let handle = api.open(&fixture.path, 0);
            assert_providers(api, handle);
            assert_eq!(
                unsafe { *api.symbol(handle, c"encoding_init_result").cast::<c_int>() },
                0
            );
            let (open, convert, close): (IconvOpen, Convert, Close) = if api.native {
                (iconv::iconv_open, iconv::iconv, iconv::iconv_close)
            } else {
                unsafe {
                    (
                        dlsym_oracle::host_fn(c"iconv_open", iconv::iconv_open as *const ()),
                        dlsym_oracle::host_fn(c"iconv", iconv::iconv as *const ()),
                        dlsym_oracle::host_fn(c"iconv_close", iconv::iconv_close as *const ()),
                    )
                }
            };
            let caller_descriptor = unsafe { open(c"UTF-16LE".as_ptr(), c"UTF-8".as_ptr()) };
            assert_ne!(caller_descriptor as usize, usize::MAX);
            type Accept = unsafe extern "C" fn(*mut c_void) -> c_int;
            let accept: Accept =
                unsafe { std::mem::transmute(api.symbol(handle, c"encoding_accept")) };
            assert_eq!(unsafe { accept(caller_descriptor) }, 0);
            assert_eq!(unsafe { close(caller_descriptor) }, 0);

            type Create = unsafe extern "C" fn() -> *mut c_void;
            let create: Create =
                unsafe { std::mem::transmute(api.symbol(handle, c"encoding_create")) };
            let plugin_descriptor = unsafe { create() };
            assert_ne!(plugin_descriptor as usize, usize::MAX);
            type SetReport = unsafe extern "C" fn(unsafe extern "C" fn(c_int));
            let set_report: SetReport =
                unsafe { std::mem::transmute(api.symbol(handle, c"encoding_set_report")) };
            unsafe { set_report(final_report) };
            api.close(handle);
            assert_eq!(FINAL_RESULT.load(Ordering::Relaxed), 0);

            // The descriptor's state belongs to the runtime and outlives its
            // creating DSO. Use only caller-owned buffers after dlclose.
            let input = b"\xE2\x82\xAC";
            let mut source = input.as_ptr().cast::<c_char>().cast_mut();
            let mut input_left = input.len();
            let mut storage = [0xA5u8; 4];
            let mut output = storage.as_mut_ptr().cast::<c_char>();
            let mut output_left = 2;
            assert_eq!(
                unsafe {
                    convert(
                        plugin_descriptor,
                        &mut source,
                        &mut input_left,
                        &mut output,
                        &mut output_left,
                    )
                },
                0
            );
            assert_eq!(input_left, 0);
            assert_eq!(output_left, 0);
            assert_eq!(storage, [0xAC, 0x20, 0xA5, 0xA5]);
            assert_eq!(unsafe { close(plugin_descriptor) }, 0);
        },
    );
}

#[test]
fn native_encoding_scope_preempts_owned_fallback() {
    // Native GLOBAL/deep-binding policy intentionally precedes the fallback;
    // a custom version provided by a real DSO must not hit libc version checks.
    isolated(
        "native_encoding_scope_preempts_owned_fallback",
        true,
        |api| {
            let ordinary = Fixture::new(&["-DLOCAL_CLOSE"]);
            let source = ordinary.dir.join("provider.c");
            let provider = ordinary.dir.join("provider.so");
            let version_map = ordinary.dir.join("provider.map");
            std::fs::write(
                &source,
                "#include <iconv.h>\nint iconv_close(iconv_t cd) {(void)cd;return 37;}\n",
            )
            .unwrap();
            std::fs::write(
                &version_map,
                "ENCODING_CUSTOM { global: iconv_close; local: *; };\n",
            )
            .unwrap();
            let version_flag = format!("-Wl,--version-script={}", version_map.display());
            compile(&source, &provider, &[&version_flag]);
            let global = api.open(&provider, libc::RTLD_GLOBAL);
            let handle = api.open(&ordinary.path, 0);
            assert_eq!(api.run(handle, c"encoding_preemption_probe"), 37);
            let selected = api.symbol(global, c"iconv_close");
            let dynamic: Dynamic =
                unsafe { std::mem::transmute(api.symbol(handle, c"encoding_dynamic")) };
            for version in [std::ptr::null(), c"ENCODING_CUSTOM".as_ptr()] {
                assert_eq!(
                    unsafe { dynamic(c"iconv_close".as_ptr(), version) },
                    selected
                );
            }

            let deep = Fixture::new(&["-DLOCAL_CLOSE"]);
            let deep_handle = api.open(&deep.path, libc::RTLD_DEEPBIND);
            assert_eq!(api.run(deep_handle, c"encoding_preemption_probe"), 23);
            let own = api.symbol(deep_handle, c"iconv_close");
            let deep_dynamic: Dynamic =
                unsafe { std::mem::transmute(api.symbol(deep_handle, c"encoding_dynamic")) };
            assert_eq!(
                unsafe { deep_dynamic(c"iconv_close".as_ptr(), std::ptr::null()) },
                own
            );
            api.close(global);
            assert_eq!(api.run(handle, c"encoding_preemption_probe"), 37);
            api.close(handle);
            api.close(deep_handle);
        },
    );
}

#[test]
fn native_encoding_exported_aliases_preserve_restartable_locale_state() {
    isolated(
        "native_encoding_exported_aliases_preserve_restartable_locale_state",
        true,
        |_api| unsafe {
            let utf8 = locale::newlocale(
                libc::LC_CTYPE_MASK,
                c"C.UTF-8".as_ptr(),
                std::ptr::null_mut(),
            );
            let plain = locale::newlocale(libc::LC_CTYPE_MASK, c"C".as_ptr(), std::ptr::null_mut());
            assert!(!utf8.is_null() && !plain.is_null());
            let previous = locale::uselocale(utf8);
            assert!(!previous.is_null());
            let input = b"\xE2\x82\xAC";
            let source = input.as_ptr().cast::<c_char>();
            let mut state = [0u64; 1];
            let ps = state.as_mut_ptr().cast::<c_void>();
            let mut wc: libc::wchar_t = 0x5A;
            assert_eq!(internal::__mbrtowc(&mut wc, source, 0, ps), usize::MAX - 1);
            assert_eq!(wc, 0x5A);
            assert_ne!(wide::mbsinit(ps), 0);
            assert_eq!(internal::__mbrtowc(&mut wc, source, 1, ps), usize::MAX - 1);
            assert_eq!(wide::mbsinit(ps), 0);
            let pending = state;
            assert_eq!(
                internal::__mbrtowc(&mut wc, source.add(1), 0, ps),
                usize::MAX - 1
            );
            assert_eq!(state, pending, "zero input must retain the pending prefix");
            assert_eq!(internal::__mbrtowc(&mut wc, source.add(1), 2, ps), 2);
            assert_eq!(wc, 0x20AC);
            assert_ne!(wide::mbsinit(ps), 0);

            assert_eq!(internal::__mbrlen(source, 1, ps), usize::MAX - 1);
            assert_eq!(wide::mbsinit(ps), 0);
            assert_eq!(internal::__mbrlen(source.add(1), 2, ps), 2);
            assert_ne!(wide::mbsinit(ps), 0);
            *errno::__errno_location() = 0;
            assert_eq!(
                internal::__mbrtowc(&mut wc, b"\xFF".as_ptr().cast(), 1, ps),
                usize::MAX
            );
            assert_eq!(*errno::__errno_location(), libc::EILSEQ);

            assert!(!locale::uselocale(plain).is_null());
            state.fill(0);
            *errno::__errno_location() = 0;
            assert_eq!(internal::__mbrtowc(&mut wc, source, 3, ps), usize::MAX);
            assert_eq!(*errno::__errno_location(), libc::EILSEQ);
            state.fill(0);
            *errno::__errno_location() = 0;
            assert_eq!(internal::__mbrlen(source, 3, ps), usize::MAX);
            assert_eq!(*errno::__errno_location(), libc::EILSEQ);
            assert!(!locale::uselocale(previous).is_null());
            locale::freelocale(plain);
            locale::freelocale(utf8);
        },
    );
}
