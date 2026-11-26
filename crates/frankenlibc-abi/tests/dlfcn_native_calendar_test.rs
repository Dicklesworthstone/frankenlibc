#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::{
    dlfcn_abi as dl, glibc_internal_abi as internal, locale_abi as locale, stdlib_abi as stdlib,
    time_abi as time, unistd_abi as unistd,
};
use frankenlibc_core::elf::ElfLoader;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
type Sym = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type Run = unsafe extern "C" fn() -> c_int;
type Imported = unsafe extern "C" fn(u32) -> *mut c_void;
type Dynamic = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;

const SOURCE: &str = r#"#define _GNU_SOURCE
#include <time.h>
#include <locale.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>

#define CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)

struct guarded_tm {
    unsigned char before[16];
    struct tm value;
    unsigned char after[16];
};
struct guarded_text {
    unsigned char before[16];
    char value[128];
    unsigned char after[16];
};
struct guarded_asctime {
    unsigned char before[16];
    char value[26];
    unsigned char after[16];
};

static int guards(const unsigned char *before, const unsigned char *after) {
    for (size_t i = 0; i < 16; ++i)
        if (before[i] != 0xA5 || after[i] != 0xA5) return 0;
    return 1;
}
static int unchanged(const char *bytes, size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i)
        if ((unsigned char)bytes[i] != 0xA5) return 0;
    return 1;
}

int calendar_initial_timezone(void) {
    CHECK(tzname[0] != NULL && tzname[1] != NULL);
    CHECK(!strcmp(tzname[0], "GMT") && !strcmp(tzname[1], "GMT"));
    CHECK(timezone == 0 && daylight == 0);
    return 0;
}

int calendar_zone(const char *name) {
    CHECK(setenv("TZ", name, 1) == 0);
    tzset();
    return 0;
}
long calendar_offset(void) { return timezone; }
int calendar_daylight(void) { return daylight; }
const char *calendar_zone_name(unsigned index) { return index < 2 ? tzname[index] : NULL; }
struct tm *calendar_borrowed_tm(time_t stamp) { return localtime(&stamp); }
char *calendar_borrowed_text(time_t stamp) { return ctime(&stamp); }

int calendar_conversion(void) {
    CHECK(calendar_zone("UTC0") == 0);
    CHECK(timezone == 0 && daylight == 0);
    CHECK(!strcmp(tzname[0], "UTC") && !strcmp(tzname[1], "UTC"));
    time_t stamp = 1709210096;
    struct guarded_tm storage;
    memset(&storage, 0xA5, sizeof storage);
    CHECK(gmtime_r(&stamp, &storage.value) == &storage.value);
    struct tm *value = &storage.value;
    CHECK(value->tm_year == 124 && value->tm_mon == 1 && value->tm_mday == 29);
    CHECK(value->tm_hour == 12 && value->tm_min == 34 && value->tm_sec == 56);
    CHECK(value->tm_wday == 4 && value->tm_yday == 59 && value->tm_isdst == 0);
    CHECK(value->tm_gmtoff == 0 && !strcmp(value->tm_zone, "GMT"));
    CHECK(timegm(value) == stamp);
    CHECK(localtime_r(&stamp, value) == value);
    CHECK(value->tm_gmtoff == 0 && !strcmp(value->tm_zone, "UTC"));
    CHECK(mktime(value) == stamp && timelocal(value) == stamp);
    CHECK(difftime(stamp + 86401, stamp) == 86401.0);
    CHECK(difftime(stamp, stamp + 86401) == -86401.0);
    CHECK(gmtime(&stamp)->tm_mday == 29 && localtime(&stamp)->tm_hour == 12);

    stamp = -1;
    CHECK(gmtime_r(&stamp, value) == value);
    CHECK(value->tm_year == 69 && value->tm_mon == 11 && value->tm_mday == 31);
    CHECK(value->tm_hour == 23 && value->tm_min == 59 && value->tm_sec == 59);
    CHECK(timegm(value) == stamp);
    memset(value, 0, sizeof *value);
    value->tm_year = 124; value->tm_mon = 1; value->tm_mday = 30;
    CHECK(timegm(value) == 1709251200);
    CHECK(value->tm_mon == 2 && value->tm_mday == 1 && value->tm_wday == 5);
    stamp = INT64_MAX;
    errno = 0;
    CHECK(gmtime_r(&stamp, value) == NULL && errno == EOVERFLOW);
    CHECK(guards(storage.before, storage.after));

    CHECK(calendar_zone("EST5EDT,M3.2.0/2,M11.1.0/2") == 0);
    CHECK(timezone == 18000 && daylight == 1);
    CHECK(!strcmp(tzname[0], "EST") && !strcmp(tzname[1], "EDT"));
    static const struct {
        time_t stamp;
        int mon, day, hour, min, sec, dst;
        long offset;
        const char *zone;
    } cases[] = {
        {1705320000, 0, 15, 7, 0, 0, 0, -18000, "EST"},
        {1721044800, 6, 15, 8, 0, 0, 1, -14400, "EDT"},
        {1710053999, 2, 10, 1, 59, 59, 0, -18000, "EST"},
        {1710054000, 2, 10, 3, 0, 0, 1, -14400, "EDT"},
        {1730613599, 10, 3, 1, 59, 59, 1, -14400, "EDT"},
        {1730613600, 10, 3, 1, 0, 0, 0, -18000, "EST"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        stamp = cases[i].stamp;
        CHECK(localtime_r(&stamp, value) == value);
        CHECK(value->tm_year == 124 && value->tm_mon == cases[i].mon);
        CHECK(value->tm_mday == cases[i].day && value->tm_hour == cases[i].hour);
        CHECK(value->tm_min == cases[i].min && value->tm_sec == cases[i].sec);
        CHECK(value->tm_isdst == cases[i].dst && value->tm_gmtoff == cases[i].offset);
        CHECK(!strcmp(value->tm_zone, cases[i].zone));
        CHECK(mktime(value) == stamp && timelocal(value) == stamp);
    }
    CHECK(guards(storage.before, storage.after));
    return 0;
}

int calendar_format_and_parse(void) {
    CHECK(calendar_zone("UTC0") == 0);
    time_t stamp = 1709210096;
    struct guarded_tm storage;
    memset(&storage, 0xA5, sizeof storage);
    CHECK(localtime_r(&stamp, &storage.value) == &storage.value);
    struct guarded_asctime text;
    memset(&text, 0xA5, sizeof text);
    CHECK(asctime_r(&storage.value, text.value) == text.value);
    CHECK(!strcmp(text.value, "Thu Feb 29 12:34:56 2024\n"));
    CHECK(guards(text.before, text.after));
    memset(&text, 0xA5, sizeof text);
    CHECK(ctime_r(&stamp, text.value) == text.value);
    CHECK(!strcmp(text.value, "Thu Feb 29 12:34:56 2024\n"));
    CHECK(guards(text.before, text.after));
    CHECK(!strcmp(asctime(&storage.value), "Thu Feb 29 12:34:56 2024\n"));
    CHECK(!strcmp(ctime(&stamp), "Thu Feb 29 12:34:56 2024\n"));

    struct guarded_text formatted;
    memset(&formatted, 0xA5, sizeof formatted);
    const char *expected = "2024-02-29 12:34:56 +0000 UTC";
    size_t length = strlen(expected);
    CHECK(strftime(formatted.value, length + 1, "%F %T %z %Z", &storage.value) == length);
    CHECK(!strcmp(formatted.value, expected));
    CHECK(unchanged(formatted.value, length + 1, sizeof formatted.value));
    CHECK(guards(formatted.before, formatted.after));
    memset(&formatted, 0xA5, sizeof formatted);
    CHECK(strftime(formatted.value, 4, "%F %T", &storage.value) == 0);
    CHECK(unchanged(formatted.value, 4, sizeof formatted.value));
    CHECK(guards(formatted.before, formatted.after));
    memset(&formatted, 0xA5, sizeof formatted);
    CHECK(strftime(formatted.value, 0, "%Y", &storage.value) == 0);
    CHECK(unchanged(formatted.value, 0, sizeof formatted.value));
    CHECK(guards(formatted.before, formatted.after));

    const char input[] = "2024-02-29 12:34:56 tail";
    memset(&storage.value, 0, sizeof storage.value);
    char *end = strptime(input, "%F %T", &storage.value);
    CHECK(end == input + 19 && !strcmp(end, " tail"));
    CHECK(storage.value.tm_year == 124 && storage.value.tm_mon == 1);
    CHECK(storage.value.tm_mday == 29 && storage.value.tm_hour == 12);
    CHECK(storage.value.tm_min == 34 && storage.value.tm_sec == 56);
    CHECK(timegm(&storage.value) == stamp);
    CHECK(strptime("2024-13-29", "%F", &storage.value) == NULL);
    CHECK(guards(storage.before, storage.after));
    return 0;
}

size_t calendar_format_locale(locale_t selected, char *buffer, size_t capacity) {
    time_t stamp = 1709210096;
    struct tm value;
    if (!gmtime_r(&stamp, &value)) return 0;
    return strftime_l(buffer, capacity, "%A %B %p %Y", &value, selected);
}
locale_t calendar_newlocale(void) { return newlocale(LC_ALL_MASK, "C", NULL); }
void calendar_freelocale(locale_t selected) { freelocale(selected); }
int calendar_accept_locale(locale_t selected) {
    locale_t previous = uselocale(selected);
    CHECK(previous != NULL);
    CHECK(uselocale(previous) == selected);
    return 0;
}

void *calendar_import(unsigned index) {
    switch (index) {
        case 0: return (void *)gmtime;
        case 1: return (void *)gmtime_r;
        case 2: return (void *)localtime;
        case 3: return (void *)localtime_r;
        case 4: return (void *)mktime;
        case 5: return (void *)timegm;
        case 6: return (void *)timelocal;
        case 7: return (void *)difftime;
        case 8: return (void *)asctime;
        case 9: return (void *)asctime_r;
        case 10: return (void *)ctime;
        case 11: return (void *)ctime_r;
        case 12: return (void *)tzset;
        case 13: return (void *)strftime;
        case 14: return (void *)strftime_l;
        case 15: return (void *)strptime;
        case 16: return (void *)&tzname;
        case 17: return (void *)&timezone;
        case 18: return (void *)&daylight;
        default: return NULL;
    }
}
void *calendar_dynamic(const char *name, const char *version) {
    return version ? dlvsym(RTLD_DEFAULT, name, version) : dlsym(RTLD_DEFAULT, name);
}
"#;

fn symbols() -> [(&'static str, *const ()); 19] {
    [
        ("gmtime", time::gmtime as *const ()),
        ("gmtime_r", time::gmtime_r as *const ()),
        ("localtime", time::localtime as *const ()),
        ("localtime_r", time::localtime_r as *const ()),
        ("mktime", time::mktime as *const ()),
        ("timegm", time::timegm as *const ()),
        ("timelocal", unistd::timelocal as *const ()),
        ("difftime", time::difftime as *const ()),
        ("asctime", time::asctime as *const ()),
        ("asctime_r", time::asctime_r as *const ()),
        ("ctime", time::ctime as *const ()),
        ("ctime_r", time::ctime_r as *const ()),
        ("tzset", time::tzset as *const ()),
        ("strftime", time::strftime as *const ()),
        ("strftime_l", unistd::strftime_l as *const ()),
        ("strptime", time::strptime as *const ()),
        ("tzname", (&raw mut internal::tzname) as *const ()),
        ("timezone", (&raw mut internal::timezone) as *const ()),
        ("daylight", (&raw mut internal::daylight) as *const ()),
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

    fn open(self, path: &Path) -> *mut c_void {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(path.as_ptr(), libc::RTLD_NOW) };
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
        assert!(!address.is_null(), "missing {name:?}");
        address
    }

    fn run(self, handle: *mut c_void, name: &CStr) {
        let run: Run = unsafe { std::mem::transmute(self.symbol(handle, name)) };
        assert_eq!(unsafe { run() }, 0, "{name:?}: C fixture line");
    }
}

struct Fixture {
    dir: PathBuf,
    plt: PathBuf,
    got: PathBuf,
}

impl Fixture {
    fn at(dir: PathBuf) -> Self {
        Self {
            plt: dir.join("calendar.so"),
            got: dir.join("calendar-got.so"),
            dir,
        }
    }

    fn new() -> Self {
        let fixture = Self::at(std::env::temp_dir().join(format!(
            "frankenlibc-calendar-runtime-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        )));
        std::fs::create_dir(&fixture.dir).unwrap();
        let source = fixture.dir.join("calendar.c");
        std::fs::write(&source, SOURCE).unwrap();
        for (path, flags) in [(&fixture.plt, &[][..]), (&fixture.got, &["-fno-plt"][..])] {
            let output = Command::new("gcc")
                .args([
                    "-shared",
                    "-fPIC",
                    "-O2",
                    "-fno-builtin",
                    "-nostdlib",
                    "-Wl,--hash-style=both",
                ])
                .args(flags)
                .arg(&source)
                .arg("-o")
                .arg(path)
                .output()
                .expect("gcc is required");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let object = ElfLoader::new(0)
                .parse(&std::fs::read(path).unwrap())
                .unwrap();
            assert!(
                object.needed_libraries.is_empty(),
                "client imports a host runtime"
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
        }
        fixture
    }
}

fn isolated(name: &str, native_only: bool, scenario: fn(Api, &Fixture)) {
    if let Ok(provider) = std::env::var("FRANKENLIBC_CALENDAR_CHILD") {
        assert!(matches!(provider.as_str(), "host" | "native"));
        assert!(matches!(
            std::env::var("FRANKENLIBC_MODE").unwrap().as_str(),
            "strict" | "hardened"
        ));
        let fixture = Fixture::at(
            std::env::var_os("FRANKENLIBC_CALENDAR_FIXTURE")
                .unwrap()
                .into(),
        );
        scenario(Api::new(provider == "native"), &fixture);
        return;
    }
    let fixture = Fixture::new();
    let providers: &[&str] = if native_only {
        &["native"]
    } else {
        &["host", "native"]
    };
    for policy in ["strict", "hardened"] {
        for provider in providers {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture"])
                .env("FRANKENLIBC_CALENDAR_CHILD", provider)
                .env("FRANKENLIBC_CALENDAR_FIXTURE", &fixture.dir)
                .env("FRANKENLIBC_MODE", policy)
                .env("TZ", "UTC0")
                .env("LC_ALL", "C")
                .env_remove("LD_PRELOAD")
                .env_remove("LD_AUDIT")
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
                        "{name}: {provider}/{policy}: {}\nstdout:\n{}\nstderr:\n{}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    assert!(
                        String::from_utf8_lossy(&output.stdout)
                            .contains("test result: ok. 1 passed; 0 failed;"),
                        "{name}: {provider}/{policy}: child did not execute its scenario"
                    );
                    break;
                }
                if start.elapsed() > Duration::from_secs(40) {
                    child.kill().unwrap();
                    let _ = child.wait_with_output();
                    panic!("{name}: {provider}/{policy}: timeout");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn assert_providers(api: Api, handle: *mut c_void) {
    let imported: Imported = unsafe { std::mem::transmute(api.symbol(handle, c"calendar_import")) };
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
fn native_calendar_timezone_globals_start_like_gnu() {
    isolated(
        "native_calendar_timezone_globals_start_like_gnu",
        false,
        |api, fixture| {
            // Every provider/policy runs in a fresh process. The first DSO
            // entry reads the globals before any calendar operation or tzset,
            // even though the process already has TZ=UTC0 in its environment.
            for path in [&fixture.plt, &fixture.got] {
                let handle = api.open(path);
                api.run(handle, c"calendar_initial_timezone");
                assert_providers(api, handle);
                api.close(handle);
            }
        },
    );
}

#[test]
fn native_calendar_versions_and_providers_match_gnu() {
    isolated(
        "native_calendar_versions_and_providers_match_gnu",
        false,
        |api, fixture| {
            for path in [&fixture.plt, &fixture.got] {
                let handle = api.open(path);
                assert_providers(api, handle);
                let imported: Imported =
                    unsafe { std::mem::transmute(api.symbol(handle, c"calendar_import")) };
                let dynamic: Dynamic =
                    unsafe { std::mem::transmute(api.symbol(handle, c"calendar_dynamic")) };
                for (index, (name, _)) in symbols().into_iter().enumerate() {
                    let version = if name == "strftime_l" {
                        c"GLIBC_2.3"
                    } else {
                        c"GLIBC_2.2.5"
                    };
                    let wrong = if name == "strftime_l" {
                        c"GLIBC_2.2.5"
                    } else {
                        c"GLIBC_2.3"
                    };
                    let name = CString::new(name).unwrap();
                    let expected = unsafe { imported(index as u32) };
                    assert_eq!(
                        unsafe { dynamic(name.as_ptr(), std::ptr::null()) },
                        expected
                    );
                    assert_eq!(
                        unsafe { dynamic(name.as_ptr(), version.as_ptr()) },
                        expected
                    );
                    for version in [
                        wrong,
                        c"GLIBC_2.34",
                        c"GLIBC_PRIVATE",
                        c"FRANKENLIBC_NO_SUCH_VERSION",
                    ] {
                        assert!(
                            unsafe { dynamic(name.as_ptr(), version.as_ptr()) }.is_null(),
                            "unexpected {name:?}@{version:?}"
                        );
                    }
                }
                api.close(handle);
            }
        },
    );
}

#[test]
fn native_calendar_utc_dst_and_roundtrips_match_gnu() {
    isolated(
        "native_calendar_utc_dst_and_roundtrips_match_gnu",
        false,
        |api, fixture| {
            for path in [&fixture.plt, &fixture.got] {
                let handle = api.open(path);
                assert_providers(api, handle);
                api.run(handle, c"calendar_conversion");
                api.close(handle);
            }
        },
    );
}

#[test]
fn native_calendar_format_parse_and_bounds_match_gnu() {
    isolated(
        "native_calendar_format_parse_and_bounds_match_gnu",
        false,
        |api, fixture| {
            for path in [&fixture.plt, &fixture.got] {
                let handle = api.open(path);
                assert_providers(api, handle);
                api.run(handle, c"calendar_format_and_parse");
                api.close(handle);
            }
        },
    );
}

#[test]
fn native_calendar_timezone_and_borrowed_storage_are_shared() {
    isolated(
        "native_calendar_timezone_and_borrowed_storage_are_shared",
        true,
        |api, fixture| unsafe {
            type Zone = unsafe extern "C" fn(*const c_char) -> c_int;
            type Offset = unsafe extern "C" fn() -> libc::c_long;
            type Daylight = unsafe extern "C" fn() -> c_int;
            type Name = unsafe extern "C" fn(u32) -> *const c_char;
            type BorrowTm = unsafe extern "C" fn(i64) -> *mut libc::tm;
            type BorrowText = unsafe extern "C" fn(i64) -> *mut c_char;
            let first = api.open(&fixture.plt);
            let second = api.open(&fixture.got);
            assert_providers(api, first);
            assert_providers(api, second);
            let zone: Zone = std::mem::transmute(api.symbol(first, c"calendar_zone"));
            let offset: Offset = std::mem::transmute(api.symbol(second, c"calendar_offset"));
            let daylight: Daylight = std::mem::transmute(api.symbol(second, c"calendar_daylight"));
            let zone_name: Name = std::mem::transmute(api.symbol(second, c"calendar_zone_name"));
            assert_eq!(zone(c"EST5EDT,M3.2.0/2,M11.1.0/2".as_ptr()), 0);
            let summer = 1721044800_i64;
            let mut ordinary: libc::tm = std::mem::zeroed();
            assert_eq!(time::localtime_r(&summer, &mut ordinary), &raw mut ordinary);
            assert_eq!(
                (ordinary.tm_hour, ordinary.tm_isdst, ordinary.tm_gmtoff),
                (8, 1, -14400)
            );
            assert_eq!(offset(), (&raw const internal::timezone).read());
            assert_eq!(daylight(), (&raw const internal::daylight).read());
            assert_eq!(CStr::from_ptr(zone_name(1)), c"EDT");
            (&raw mut internal::timezone).write(1234);
            (&raw mut internal::daylight).write(7);
            assert_eq!(offset(), 1234);
            assert_eq!(daylight(), 7);
            assert_eq!(stdlib::setenv(c"TZ".as_ptr(), c"UTC0".as_ptr(), 1), 0);
            time::tzset();
            assert_eq!(offset(), 0);
            assert_eq!(daylight(), 0);
            assert_eq!(CStr::from_ptr(zone_name(0)), c"UTC");

            let borrow_first: BorrowTm =
                std::mem::transmute(api.symbol(first, c"calendar_borrowed_tm"));
            let borrow_second: BorrowTm =
                std::mem::transmute(api.symbol(second, c"calendar_borrowed_tm"));
            let borrow_text: BorrowText =
                std::mem::transmute(api.symbol(first, c"calendar_borrowed_text"));
            let borrowed = borrow_first(0);
            assert!(!borrowed.is_null());
            assert_eq!((*borrowed).tm_year, 70);
            let stamp = 1709210096_i64;
            assert_eq!(time::localtime(&stamp), borrowed);
            assert_eq!(borrow_second(stamp), borrowed);
            let text = borrow_text(stamp);
            assert!(!text.is_null());
            api.close(first);
            api.close(second);
            // Runtime-owned buffers and zone strings survive the importing DSOs.
            assert_eq!(
                ((*borrowed).tm_year, (*borrowed).tm_mon, (*borrowed).tm_mday),
                (124, 1, 29)
            );
            assert_eq!(CStr::from_ptr((*borrowed).tm_zone), c"UTC");
            assert_eq!(CStr::from_ptr(text), c"Thu Feb 29 12:34:56 2024\n");
        },
    );
}

#[test]
fn native_calendar_locale_objects_cross_dso_boundaries() {
    isolated(
        "native_calendar_locale_objects_cross_dso_boundaries",
        false,
        |api, fixture| unsafe {
            type NewLocale = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> *mut c_void;
            type FreeLocale = unsafe extern "C" fn(*mut c_void);
            type UseLocale = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
            type Format = unsafe extern "C" fn(
                *mut c_char,
                usize,
                *const c_char,
                *const c_void,
                *mut c_void,
            ) -> usize;
            type FormatInDso = unsafe extern "C" fn(*mut c_void, *mut c_char, usize) -> usize;
            type NewInDso = unsafe extern "C" fn() -> *mut c_void;
            type AcceptInDso = unsafe extern "C" fn(*mut c_void) -> c_int;
            let new: NewLocale = if api.native {
                locale::newlocale
            } else {
                dlsym_oracle::host_fn(c"newlocale", locale::newlocale as *const ())
            };
            let free: FreeLocale = if api.native {
                locale::freelocale
            } else {
                dlsym_oracle::host_fn(c"freelocale", locale::freelocale as *const ())
            };
            let current: UseLocale = if api.native {
                locale::uselocale
            } else {
                dlsym_oracle::host_fn(c"uselocale", locale::uselocale as *const ())
            };
            let format: Format = if api.native {
                unistd::strftime_l
            } else {
                dlsym_oracle::host_fn(c"strftime_l", unistd::strftime_l as *const ())
            };
            for path in [&fixture.plt, &fixture.got] {
                let handle = api.open(path);
                assert_providers(api, handle);
                let in_dso: FormatInDso =
                    std::mem::transmute(api.symbol(handle, c"calendar_format_locale"));
                let new_in_dso: NewInDso =
                    std::mem::transmute(api.symbol(handle, c"calendar_newlocale"));
                let free_in_dso: FreeLocale =
                    std::mem::transmute(api.symbol(handle, c"calendar_freelocale"));
                let accept_in_dso: AcceptInDso =
                    std::mem::transmute(api.symbol(handle, c"calendar_accept_locale"));
                let selected = new(libc::LC_ALL_MASK, c"C".as_ptr(), std::ptr::null_mut());
                assert!(!selected.is_null());
                let previous = current(std::ptr::null_mut());
                // C-locale text alone cannot prove a handle was accepted: an
                // invalid-handle fallback could format with the current C locale.
                assert_eq!(accept_in_dso(selected), 0, "DSO rejected ordinary locale");
                assert_eq!(current(std::ptr::null_mut()), previous);
                let mut output = [0xA5_u8; 80];
                let expected = c"Thursday February PM 2024";
                assert_eq!(
                    in_dso(selected, output.as_mut_ptr().add(16).cast(), 48),
                    expected.to_bytes().len()
                );
                assert_eq!(CStr::from_ptr(output.as_ptr().add(16).cast()), expected);
                assert!(
                    output[..16]
                        .iter()
                        .chain(&output[64..])
                        .all(|byte| *byte == 0xA5)
                );
                assert_eq!(current(std::ptr::null_mut()), previous);
                // Each direction consumes a locale obtained outside its caller.
                free_in_dso(selected);
                let selected = new_in_dso();
                assert!(!selected.is_null());
                let restored = current(selected);
                assert!(!restored.is_null(), "ordinary runtime rejected DSO locale");
                assert_eq!(restored, previous);
                assert_eq!(current(restored), selected);
                let mut value: libc::tm = std::mem::zeroed();
                value.tm_year = 124;
                value.tm_mon = 1;
                value.tm_mday = 29;
                value.tm_wday = 4;
                value.tm_hour = 12;
                assert_eq!(
                    format(
                        output.as_mut_ptr().add(16).cast(),
                        48,
                        c"%A %B %p %Y".as_ptr(),
                        (&raw const value).cast(),
                        selected
                    ),
                    expected.to_bytes().len()
                );
                assert_eq!(CStr::from_ptr(output.as_ptr().add(16).cast()), expected);
                assert_eq!(current(std::ptr::null_mut()), previous);
                free(selected);
                api.close(handle);
            }
        },
    );
}
