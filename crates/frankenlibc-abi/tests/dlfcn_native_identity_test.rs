#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::{
    dlfcn_abi as dl, glibc_internal_abi as internal, grp_abi as group, pwd_abi as passwd,
    unistd_abi as unistd,
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

const PASSWD: &str = "\
fl-native-alice:x:51001:52001:Native Alice:/srv/fl/alice:/bin/sh\n\
fl-native-bob:x:51002:52002:Native Bob:/srv/fl/bob:/bin/false\n\
fl-native-carol:x:51003:52003:Native Carol:/srv/fl/carol:/bin/sh\n";
const GROUP: &str = "\
fl-native-primary:x:52001:fl-native-alice\n\
fl-native-shared:x:52002:fl-native-alice,fl-native-bob\n\
fl-native-duplicate:x:52002:fl-native-alice\n\
fl-native-other:x:52003:fl-native-carol\n";

const SOURCE: &str = r#"#define _GNU_SOURCE
#include <pwd.h>
#include <grp.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>

#define CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)

struct guarded {
    unsigned char before[16];
    _Alignas(void *) char buffer[8192];
    unsigned char after[16];
};

static int guards(const struct guarded *storage) {
    for (size_t i = 0; i < 16; ++i)
        if (storage->before[i] != 0xA5 || storage->after[i] != 0xA5) return 0;
    return 1;
}

static int in_buffer(const void *pointer, const char *buffer, size_t size, size_t width) {
    uintptr_t p = (uintptr_t)pointer, start = (uintptr_t)buffer;
    return p >= start && p - start <= size && width <= size - (p - start);
}

static int buffered_string(const char *value, const char *buffer, size_t size,
                           const char *expected) {
    if (!in_buffer(value, buffer, size, 1)) return 0;
    size_t left = size - (size_t)((uintptr_t)value - (uintptr_t)buffer);
    return memchr(value, '\0', left) != NULL && !strcmp(value, expected);
}

static int passwd_record(const struct passwd *record, const char *buffer, size_t size) {
    return record->pw_uid == 51001 && record->pw_gid == 52001
        && buffered_string(record->pw_name, buffer, size, "fl-native-alice")
        && buffered_string(record->pw_passwd, buffer, size, "x")
        && buffered_string(record->pw_gecos, buffer, size, "Native Alice")
        && buffered_string(record->pw_dir, buffer, size, "/srv/fl/alice")
        && buffered_string(record->pw_shell, buffer, size, "/bin/sh");
}

static int group_record(const struct group *record, const char *buffer, size_t size) {
    return record->gr_gid == 52002
        && buffered_string(record->gr_name, buffer, size, "fl-native-shared")
        && buffered_string(record->gr_passwd, buffer, size, "x")
        && (uintptr_t)record->gr_mem % _Alignof(char *) == 0
        && in_buffer(record->gr_mem, buffer, size, 3 * sizeof(char *))
        && buffered_string(record->gr_mem[0], buffer, size, "fl-native-alice")
        && buffered_string(record->gr_mem[1], buffer, size, "fl-native-bob")
        && record->gr_mem[2] == NULL;
}

int identity_files(void) {
    struct passwd *pw = getpwnam("fl-native-alice");
    CHECK(pw && pw->pw_uid == 51001 && pw->pw_gid == 52001);
    CHECK(!strcmp(pw->pw_gecos, "Native Alice") && !strcmp(pw->pw_dir, "/srv/fl/alice"));
    pw = getpwuid(51002);
    CHECK(pw && !strcmp(pw->pw_name, "fl-native-bob"));
    CHECK(getpwnam("fl-native-absent") == NULL && getpwuid(UINT32_MAX) == NULL);
    struct group *gr = getgrnam("fl-native-shared");
    CHECK(gr && gr->gr_gid == 52002 && !strcmp(gr->gr_mem[0], "fl-native-alice"));
    CHECK(!strcmp(gr->gr_mem[1], "fl-native-bob") && gr->gr_mem[2] == NULL);
    gr = getgrgid(52003);
    CHECK(gr && !strcmp(gr->gr_name, "fl-native-other"));
    CHECK(getgrnam("fl-native-absent") == NULL && getgrgid(UINT32_MAX) == NULL);

    struct guarded storage;
    memset(&storage, 0xA5, sizeof storage);
    struct passwd record, *found = (struct passwd *)(uintptr_t)1;
    CHECK(getpwnam_r("fl-native-alice", &record, storage.buffer, 1, &found) == ERANGE);
    CHECK(found == NULL && (unsigned char)storage.buffer[1] == 0xA5 && guards(&storage));
    CHECK(getpwnam_r("fl-native-alice", &record, storage.buffer, sizeof storage.buffer, &found) == 0);
    CHECK(found == &record && passwd_record(&record, storage.buffer, sizeof storage.buffer));
    CHECK(getpwuid_r(51001, &record, storage.buffer, sizeof storage.buffer, &found) == 0);
    CHECK(found == &record && passwd_record(&record, storage.buffer, sizeof storage.buffer));
    found = (struct passwd *)(uintptr_t)1;
    CHECK(getpwnam_r("fl-native-absent", &record, storage.buffer, sizeof storage.buffer, &found) == 0);
    CHECK(found == NULL && guards(&storage));

    memset(&storage, 0xA5, sizeof storage);
    struct group group_record_out, *group_found = (struct group *)(uintptr_t)1;
    CHECK(getgrnam_r("fl-native-shared", &group_record_out, storage.buffer, 1, &group_found) == ERANGE);
    CHECK(group_found == NULL && (unsigned char)storage.buffer[1] == 0xA5 && guards(&storage));
    CHECK(getgrnam_r("fl-native-shared", &group_record_out, storage.buffer, sizeof storage.buffer, &group_found) == 0);
    CHECK(group_found == &group_record_out && group_record(&group_record_out, storage.buffer, sizeof storage.buffer));
    CHECK(getgrgid_r(52002, &group_record_out, storage.buffer, sizeof storage.buffer, &group_found) == 0);
    CHECK(group_found == &group_record_out && group_record(&group_record_out, storage.buffer, sizeof storage.buffer));
    group_found = (struct group *)(uintptr_t)1;
    CHECK(getgrgid_r(UINT32_MAX, &group_record_out, storage.buffer, sizeof storage.buffer, &group_found) == 0);
    CHECK(group_found == NULL && guards(&storage));

    /* An ERANGE enumeration retry must deliver the first record again. */
    setpwent();
    found = (struct passwd *)(uintptr_t)1;
    CHECK(getpwent_r(&record, storage.buffer, 1, &found) == ERANGE && found == NULL);
    const uid_t uids[] = {51001, 51002, 51003};
    for (size_t i = 0; i < 3; ++i) {
        CHECK(getpwent_r(&record, storage.buffer, sizeof storage.buffer, &found) == 0);
        CHECK(found == &record && record.pw_uid == uids[i]);
    }
    CHECK(getpwent_r(&record, storage.buffer, sizeof storage.buffer, &found) == ENOENT && found == NULL);
    endpwent();
    setgrent();
    group_found = (struct group *)(uintptr_t)1;
    CHECK(getgrent_r(&group_record_out, storage.buffer, 1, &group_found) == ERANGE && group_found == NULL);
    const gid_t gids[] = {52001, 52002, 52002, 52003};
    for (size_t i = 0; i < 4; ++i) {
        CHECK(getgrent_r(&group_record_out, storage.buffer, sizeof storage.buffer, &group_found) == 0);
        CHECK(group_found == &group_record_out && group_record_out.gr_gid == gids[i]);
    }
    CHECK(getgrent_r(&group_record_out, storage.buffer, sizeof storage.buffer, &group_found) == ENOENT && group_found == NULL);
    endgrent();
    CHECK(guards(&storage));

    /* Capacity failure copies only the permitted prefix and reports total size. */
    struct { gid_t before, ids[2], after; } membership = {
        0xA5A5A5A5u, {0xA5A5A5A5u, 0xA5A5A5A5u}, 0xA5A5A5A5u
    };
    int count = 0;
    CHECK(getgrouplist("fl-native-alice", 52001, NULL, &count) == -1 && count == 2);
    count = 1;
    CHECK(getgrouplist("fl-native-alice", 52001, membership.ids, &count) == -1 && count == 2);
    CHECK(membership.ids[0] == 52001 && membership.ids[1] == 0xA5A5A5A5u);
    count = 2;
    CHECK(getgrouplist("fl-native-alice", 52001, membership.ids, &count) == 2 && count == 2);
    CHECK(membership.ids[0] == 52001 && membership.ids[1] == 52002);
    CHECK(membership.before == 0xA5A5A5A5u && membership.after == 0xA5A5A5A5u);
    return 0;
}

void identity_reset(void) { setpwent(); setgrent(); }
void identity_end(void) { endpwent(); endgrent(); }
unsigned identity_next_passwd(void) {
    struct passwd *record = getpwent();
    return record ? record->pw_uid : UINT32_MAX;
}
unsigned identity_next_group(void) {
    struct group *record = getgrent();
    return record ? record->gr_gid : UINT32_MAX;
}
const char *identity_borrowed_name(void) {
    struct passwd *record = getpwnam("fl-native-alice");
    return record ? record->pw_name : NULL;
}

/* Both GNU and native callers select the same real third-party NSS module. */
int identity_module(void) {
    struct passwd *pw = getpwnam("fltest1");
    CHECK(pw && pw->pw_uid == 4201 && pw->pw_gid == 4301);
    CHECK(!strcmp(pw->pw_dir, "/home/fltest1"));
    pw = getpwuid(4202);
    CHECK(pw && !strcmp(pw->pw_name, "fltest2"));
    struct group *gr = getgrnam("fltestgrp");
    CHECK(gr && gr->gr_gid == 4301 && !strcmp(gr->gr_mem[1], "fltest2"));
    gr = getgrgid(4302);
    CHECK(gr && !strcmp(gr->gr_name, "fltestgrp2"));
    struct guarded storage;
    memset(&storage, 0xA5, sizeof storage);
    struct passwd out, *found = (struct passwd *)(uintptr_t)1;
    CHECK(getpwnam_r("fltest1", &out, storage.buffer, 1024, &found) == ERANGE && found == NULL);
    CHECK(getpwnam_r("fltest1", &out, storage.buffer, sizeof storage.buffer, &found) == 0);
    CHECK(found == &out && out.pw_uid == 4201);
    CHECK(buffered_string(out.pw_name, storage.buffer, sizeof storage.buffer, "fltest1"));
    struct group gout, *gfound = (struct group *)(uintptr_t)1;
    CHECK(getgrgid_r(4301, &gout, storage.buffer, 1024, &gfound) == ERANGE && gfound == NULL);
    CHECK(getgrgid_r(4301, &gout, storage.buffer, sizeof storage.buffer, &gfound) == 0);
    CHECK(gfound == &gout && gout.gr_gid == 4301);
    CHECK((uintptr_t)gout.gr_mem % _Alignof(char *) == 0);
    CHECK(in_buffer(gout.gr_mem, storage.buffer, sizeof storage.buffer, 3 * sizeof(char *)));
    CHECK(buffered_string(gout.gr_mem[0], storage.buffer, sizeof storage.buffer, "fltest1"));
    CHECK(buffered_string(gout.gr_mem[1], storage.buffer, sizeof storage.buffer, "fltest2"));
    CHECK(gout.gr_mem[2] == NULL && guards(&storage));
    setpwent();
    CHECK(getpwent_r(&out, storage.buffer, 1, &found) == ERANGE && found == NULL);
    CHECK(getpwent_r(&out, storage.buffer, sizeof storage.buffer, &found) == 0);
    CHECK(found == &out && out.pw_uid == 4201);
    endpwent();
    setgrent();
    CHECK(getgrent_r(&gout, storage.buffer, 1, &gfound) == ERANGE && gfound == NULL);
    CHECK(getgrent_r(&gout, storage.buffer, sizeof storage.buffer, &gfound) == 0);
    CHECK(gfound == &gout && gout.gr_gid == 4301);
    endgrent();
    return 0;
}

void *identity_function(unsigned index) {
    switch (index) {
        case 0: return (void *)getpwnam;
        case 1: return (void *)getpwuid;
        case 2: return (void *)getpwnam_r;
        case 3: return (void *)getpwuid_r;
        case 4: return (void *)setpwent;
        case 5: return (void *)getpwent;
        case 6: return (void *)getpwent_r;
        case 7: return (void *)endpwent;
        case 8: return (void *)getgrnam;
        case 9: return (void *)getgrgid;
        case 10: return (void *)getgrnam_r;
        case 11: return (void *)getgrgid_r;
        case 12: return (void *)setgrent;
        case 13: return (void *)getgrent;
        case 14: return (void *)getgrent_r;
        case 15: return (void *)endgrent;
        case 16: return (void *)getgrouplist;
        default: return NULL;
    }
}
void *identity_dynamic(const char *name, const char *version) {
    return version ? dlvsym(RTLD_DEFAULT, name, version) : dlsym(RTLD_DEFAULT, name);
}
"#;

fn symbols() -> [(&'static str, *const ()); 17] {
    [
        ("getpwnam", passwd::getpwnam as *const ()),
        ("getpwuid", passwd::getpwuid as *const ()),
        ("getpwnam_r", passwd::getpwnam_r as *const ()),
        ("getpwuid_r", passwd::getpwuid_r as *const ()),
        ("setpwent", passwd::setpwent as *const ()),
        ("getpwent", passwd::getpwent as *const ()),
        ("getpwent_r", passwd::getpwent_r as *const ()),
        ("endpwent", passwd::endpwent as *const ()),
        ("getgrnam", group::getgrnam as *const ()),
        ("getgrgid", group::getgrgid as *const ()),
        ("getgrnam_r", group::getgrnam_r as *const ()),
        ("getgrgid_r", group::getgrgid_r as *const ()),
        ("setgrent", group::setgrent as *const ()),
        ("getgrent", group::getgrent as *const ()),
        ("getgrent_r", group::getgrent_r as *const ()),
        ("endgrent", group::endgrent as *const ()),
        ("getgrouplist", unistd::getgrouplist as *const ()),
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
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(name.as_ptr(), libc::RTLD_NOW) };
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

    fn configure_accounts(self) {
        type Configure = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
        let configure: Configure = if self.native {
            internal::__nss_configure_lookup
        } else {
            unsafe {
                dlsym_oracle::host_fn(
                    c"__nss_configure_lookup",
                    internal::__nss_configure_lookup as *const (),
                )
            }
        };
        for database in [c"passwd", c"group"] {
            assert_eq!(
                unsafe { configure(database.as_ptr(), c"fltest".as_ptr()) },
                0
            );
        }
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
            plt: dir.join("identity.so"),
            got: dir.join("identity-got.so"),
            dir,
        }
    }

    fn new(module: bool) -> Self {
        let fixture = Self::at(std::env::temp_dir().join(format!(
            "frankenlibc-identity-runtime-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        )));
        std::fs::create_dir(&fixture.dir).unwrap();
        std::fs::write(fixture.dir.join("passwd"), PASSWD).unwrap();
        std::fs::write(fixture.dir.join("group"), GROUP).unwrap();
        std::fs::write(
            fixture.dir.join("nsswitch.conf"),
            "passwd: files\ngroup: files\ninitgroups: files\n",
        )
        .unwrap();
        let source = fixture.dir.join("identity.c");
        std::fs::write(&source, SOURCE).unwrap();
        for (path, flags) in [(&fixture.plt, &[][..]), (&fixture.got, &["-fno-plt"][..])] {
            compile(&source, path, flags, true);
            let object = ElfLoader::new(0)
                .parse(&std::fs::read(path).unwrap())
                .unwrap();
            assert!(
                object.needed_libraries.is_empty(),
                "client must not import a host runtime"
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
        if module {
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/integration/fixture_nss_module_lib.c");
            compile(
                &source,
                &fixture.dir.join("libnss_fltest.so.2"),
                &["-DSERVICE=fltest"],
                false,
            );
        }
        fixture
    }
}

fn compile(source: &Path, output: &Path, flags: &[&str], native_client: bool) {
    let mut command = Command::new("gcc");
    command.args([
        "-shared",
        "-fPIC",
        "-O2",
        "-fno-builtin",
        "-Wl,--hash-style=both",
    ]);
    if native_client {
        command.arg("-nostdlib");
    }
    let output = command
        .args(flags)
        .arg(source)
        .arg("-o")
        .arg(output)
        .output()
        .expect("gcc is required");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn isolated(name: &str, native_only: bool, module: bool, scenario: fn(Api, &Fixture)) {
    if let Ok(mode) = std::env::var("FRANKENLIBC_IDENTITY_CHILD") {
        assert!(matches!(mode.as_str(), "host" | "native"));
        let fixture = Fixture::at(
            std::env::var_os("FRANKENLIBC_IDENTITY_FIXTURE")
                .unwrap()
                .into(),
        );
        scenario(Api::new(mode == "native"), &fixture);
        return;
    }
    let fixture = Fixture::new(module);
    let modes: &[&str] = if native_only {
        &["native"]
    } else {
        &["host", "native"]
    };
    for mode in modes {
        let mut libraries = vec![fixture.dir.clone()];
        if let Some(previous) = std::env::var_os("LD_LIBRARY_PATH") {
            libraries.extend(std::env::split_paths(&previous));
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FRANKENLIBC_IDENTITY_CHILD", mode)
            .env("FRANKENLIBC_IDENTITY_FIXTURE", &fixture.dir)
            .env("FRANKENLIBC_PASSWD_PATH", fixture.dir.join("passwd"))
            .env("FRANKENLIBC_GROUP_PATH", fixture.dir.join("group"))
            .env(
                "FRANKENLIBC_NSSWITCH_CONF",
                fixture.dir.join("nsswitch.conf"),
            )
            .env("LD_LIBRARY_PATH", std::env::join_paths(libraries).unwrap())
            .env("FLTEST_STATUS", "")
            .env("FLTEST_ACCOUNT_ERRNO", "0")
            .env("FLTEST_ACCOUNT_SCRATCH", if module { "fltest" } else { "" })
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
                assert!(
                    String::from_utf8_lossy(&output.stdout)
                        .contains("test result: ok. 1 passed; 0 failed;"),
                    "{name}: {mode}: child did not execute its scenario:\n{}",
                    String::from_utf8_lossy(&output.stdout)
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
        unsafe { std::mem::transmute(api.symbol(handle, c"identity_function")) };
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
fn native_identity_files_plt_and_got_use_owned_sources() {
    isolated(
        "native_identity_files_plt_and_got_use_owned_sources",
        true,
        false,
        |api, fixture| {
            for path in [&fixture.plt, &fixture.got] {
                let handle = api.open(path);
                assert_providers(api, handle);
                assert_eq!(api.run(handle, c"identity_files"), 0);
                api.close(handle);
            }
        },
    );
}

#[test]
fn native_identity_versions_and_providers_match_gnu() {
    isolated(
        "native_identity_versions_and_providers_match_gnu",
        false,
        false,
        |api, fixture| {
            let handle = api.open(&fixture.plt);
            assert_providers(api, handle);
            let imported: Function =
                unsafe { std::mem::transmute(api.symbol(handle, c"identity_function")) };
            let dynamic: Dynamic =
                unsafe { std::mem::transmute(api.symbol(handle, c"identity_dynamic")) };
            for (index, (name, _)) in symbols().into_iter().enumerate() {
                let name = CString::new(name).unwrap();
                let expected = unsafe { imported(index as u32) };
                for version in [std::ptr::null(), c"GLIBC_2.2.5".as_ptr()] {
                    assert_eq!(unsafe { dynamic(name.as_ptr(), version) }, expected);
                }
                for version in [
                    c"GLIBC_2.34",
                    c"GLIBC_PRIVATE",
                    c"FRANKENLIBC_NO_SUCH_VERSION",
                ] {
                    assert!(
                        unsafe { dynamic(name.as_ptr(), version.as_ptr()) }.is_null(),
                        "unsupported version: {name:?}: {version:?}"
                    );
                }
            }
            api.close(handle);
        },
    );
}

#[test]
fn native_identity_enumeration_and_storage_cross_dso_boundaries() {
    isolated(
        "native_identity_enumeration_and_storage_cross_dso_boundaries",
        true,
        false,
        |api, fixture| unsafe {
            let first = api.open(&fixture.plt);
            let second = api.open(&fixture.got);
            assert_providers(api, first);
            assert_providers(api, second);
            type Void = unsafe extern "C" fn();
            type Next = unsafe extern "C" fn() -> u32;
            type Name = unsafe extern "C" fn() -> *const c_char;
            let reset: Void = std::mem::transmute(api.symbol(second, c"identity_reset"));
            let end: Void = std::mem::transmute(api.symbol(second, c"identity_end"));
            let first_pw: Next = std::mem::transmute(api.symbol(first, c"identity_next_passwd"));
            let second_pw: Next = std::mem::transmute(api.symbol(second, c"identity_next_passwd"));
            let first_gr: Next = std::mem::transmute(api.symbol(first, c"identity_next_group"));
            let second_gr: Next = std::mem::transmute(api.symbol(second, c"identity_next_group"));
            reset();
            let entry = passwd::getpwent();
            assert!(!entry.is_null());
            assert_eq!((*entry).pw_uid, 51001);
            assert_eq!(first_pw(), 51002);
            assert_eq!(second_pw(), 51003);
            assert_eq!(first_pw(), u32::MAX);
            let entry = group::getgrent();
            assert!(!entry.is_null());
            assert_eq!((*entry).gr_gid, 52001);
            assert_eq!(first_gr(), 52002);
            assert_eq!(second_gr(), 52002);
            let entry = group::getgrent();
            assert!(!entry.is_null());
            assert_eq!((*entry).gr_gid, 52003);
            assert_eq!(first_gr(), u32::MAX);
            reset();
            let entry = passwd::getpwent();
            assert!(!entry.is_null());
            assert_eq!((*entry).pw_uid, 51001);
            end();

            let borrowed: Name = std::mem::transmute(api.symbol(first, c"identity_borrowed_name"));
            let name = borrowed();
            assert!(!name.is_null());
            assert_eq!(CStr::from_ptr(name), c"fl-native-alice");
            api.close(first);
            // Ordinary runtime-owned result storage outlives the DSO that
            // obtained it. No subsequent account lookup invalidates the value.
            assert_eq!(CStr::from_ptr(name), c"fl-native-alice");
            api.close(second);
        },
    );
}

#[test]
fn native_identity_selected_nss_module_matches_gnu() {
    isolated(
        "native_identity_selected_nss_module_matches_gnu",
        false,
        true,
        |api, fixture| {
            api.configure_accounts();
            for path in [&fixture.plt, &fixture.got] {
                let handle = api.open(path);
                assert_providers(api, handle);
                assert_eq!(api.run(handle, c"identity_module"), 0);
                api.close(handle);
            }
        },
    );
}
