//! Execute the exact standalone NSS source against a real, provider-pinned
//! FrankenLibC loader/allocator DSO. This is component evidence: the DSO keeps
//! its ordinary build profile, and no standalone admission gate is bypassed.
//! Fixtures are first loaded by absolute path into its native registry; their
//! SONAMEs then exercise NSS's normal basename lookup and retained module cache.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[cfg(not(feature = "standalone"))]
compile_error!("compile the included NSS component with --cfg feature=\"standalone\"");

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use frankenlibc_core::addrinfo::hosts_policy::BackendResult;
use frankenlibc_core::nss::{Answer, Status};

#[allow(dead_code)]
#[path = "../../crates/frankenlibc-abi/src/nss_module.rs"]
mod nss_module;

struct Abi {
    dlopen: unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void,
    dlsym: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void,
    dladdr: unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int,
    dlerror: unsafe extern "C" fn() -> *mut c_char,
    snapshot: unsafe extern "C" fn(*mut c_void) -> c_int,
    malloc: unsafe extern "C" fn(usize) -> *mut c_void,
    realloc: usize,
    free: unsafe extern "C" fn(*mut c_void),
    errno: unsafe extern "C" fn() -> *mut c_int,
}

static ABI: OnceLock<Abi> = OnceLock::new();

// These adapters only forward to the requested DSO's real public functions.
// They do not implement loader, allocation, errno or NSS behavior themselves.
mod dlfcn_abi {
    use super::*;
    pub unsafe fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void {
        unsafe { (ABI.get().unwrap().dlopen)(path, flags) }
    }
    pub unsafe fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void {
        unsafe { (ABI.get().unwrap().dlsym)(handle, name) }
    }
}

mod errno_abi {
    use super::*;
    pub unsafe fn __errno_location() -> *mut c_int {
        unsafe { (ABI.get().unwrap().errno)() }
    }
}

pub mod malloc_abi {
    use super::*;
    pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
        unsafe { (ABI.get().unwrap().malloc)(size) }
    }
    pub unsafe extern "C" fn free(pointer: *mut c_void) {
        unsafe { (ABI.get().unwrap().free)(pointer) }
    }
}

fn cpath(path: &Path) -> CString {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).unwrap()
}

fn load_abi(path: &Path) {
    let path = std::fs::canonicalize(path).expect("candidate DSO exists");
    // The ordinary ABI DSO intentionally allows malloc-family preemption.
    // Bind its own allocator here to model the standalone namespace; otherwise
    // a native module's realloc could resolve to host libc while this source
    // component calls the explicitly selected candidate malloc export.
    let handle = unsafe {
        libc::dlopen(
            cpath(&path).as_ptr(),
            libc::RTLD_NOW | libc::RTLD_LOCAL | libc::RTLD_DEEPBIND,
        )
    };
    if handle.is_null() {
        let error = unsafe { libc::dlerror() };
        let message = if error.is_null() {
            "no host dlerror".into()
        } else {
            unsafe { CStr::from_ptr(error) }.to_string_lossy()
        };
        panic!("host cannot open candidate DSO: {message}");
    }
    let symbol = |name: &CStr| {
        let address = unsafe { libc::dlsym(handle, name.as_ptr()) };
        assert!(!address.is_null(), "candidate lacks {name:?}");
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::dladdr(address, &mut info) }, 1);
        let provider = unsafe { CStr::from_ptr(info.dli_fname) };
        assert_eq!(
            std::fs::canonicalize(Path::new(provider.to_str().unwrap())).unwrap(),
            path,
            "dependency export must not qualify as a candidate export"
        );
        address
    };
    macro_rules! bind {
        ($name:literal, $signature:ty) => {
            unsafe { std::mem::transmute::<*mut c_void, $signature>(symbol($name)) }
        };
    }
    // A deep-bound DSO has its own exported environment pointer. Supply the
    // process startup environment before its first operational call, just as
    // libc startup publishes envp. This also makes hardened mode and fixture
    // error injection visible to the real provider's getenv implementation.
    let owned_environment = symbol(c"__environ").cast::<*mut *mut c_char>();
    let host_environment = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__environ".as_ptr()) }
        .cast::<*mut *mut c_char>();
    assert!(!host_environment.is_null());
    assert_ne!(owned_environment, host_environment);
    unsafe { *owned_environment = *host_environment };
    let getenv = bind!(
        c"getenv",
        unsafe extern "C" fn(*const c_char) -> *mut c_char
    );
    for key in [c"FRANKENLIBC_MODE", c"FLTEST_STATUS", c"FLTEST_TRACE"] {
        let value = unsafe { getenv(key.as_ptr()) };
        assert!(!value.is_null(), "candidate environment lacks {key:?}");
        assert_eq!(
            unsafe { CStr::from_ptr(value) }.to_bytes(),
            std::env::var(key.to_str().unwrap()).unwrap().as_bytes()
        );
    }
    assert!(
        ABI.set(Abi {
            dlopen: bind!(
                c"dlopen",
                unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void
            ),
            dlsym: bind!(
                c"dlsym",
                unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void
            ),
            dladdr: bind!(
                c"dladdr",
                unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int
            ),
            dlerror: bind!(c"dlerror", unsafe extern "C" fn() -> *mut c_char),
            snapshot: bind!(
                c"__frankenlibc_runtime_decision_snapshot",
                unsafe extern "C" fn(*mut c_void) -> c_int
            ),
            malloc: bind!(c"malloc", unsafe extern "C" fn(usize) -> *mut c_void),
            realloc: symbol(c"realloc") as usize,
            free: bind!(c"free", unsafe extern "C" fn(*mut c_void)),
            errno: bind!(c"__errno_location", unsafe extern "C" fn() -> *mut c_int),
        })
        .is_ok()
    );
    // Keep the DSO loaded: its function pointers back all source-component calls.
}

fn loader_error() -> String {
    let error = unsafe { (ABI.get().unwrap().dlerror)() };
    if error.is_null() {
        "no dlerror".into()
    } else {
        unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned()
    }
}

fn native_module(directory: &Path, service: &str) -> *mut c_void {
    let path = directory.join(format!("libnss_{service}.so.2"));
    let handle = unsafe { dlfcn_abi::dlopen(cpath(&path).as_ptr(), libc::RTLD_NOW) };
    assert!(
        !handle.is_null(),
        "native module load failed: {}",
        loader_error()
    );
    assert_native_symbol(directory, service, handle, "getpwnam_r");
    handle
}

fn assert_native_symbol(
    directory: &Path,
    service: &str,
    handle: *mut c_void,
    function: &str,
) -> *mut c_void {
    let name = CString::new(format!("_nss_{service}_{function}")).unwrap();
    let address = unsafe { dlfcn_abi::dlsym(handle, name.as_ptr()) };
    assert!(
        !address.is_null(),
        "native symbol lookup failed: {}",
        loader_error()
    );
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { (ABI.get().unwrap().dladdr)(address, (&raw mut info).cast()) },
        1
    );
    assert_eq!(
        unsafe { CStr::from_ptr(info.dli_fname) },
        cpath(&directory.join(format!("libnss_{service}.so.2"))).as_c_str()
    );
    // The host must not own these callbacks, even though it owns the test process.
    assert_eq!(
        unsafe { libc::dladdr(address, &mut info) },
        0,
        "callback escaped into the host loader"
    );
    let basename = CString::new(format!("libnss_{service}.so.2")).unwrap();
    assert!(
        unsafe { libc::dlopen(basename.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) }.is_null(),
        "the host unexpectedly loaded the module"
    );
    let again = unsafe { dlfcn_abi::dlopen(basename.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
    assert_eq!(
        again, handle,
        "NSS basename must refer to the retained native object"
    );
    address
}

fn found<T: std::fmt::Debug>(answer: Answer<T>) -> T {
    match answer {
        Answer::Found(value) => value,
        other => panic!("expected NSS success, got {other:?}"),
    }
}

fn host_found<T>(answer: BackendResult<T, c_int>) -> T {
    match answer {
        BackendResult::Success(value) => value,
        _ => panic!("expected hosts module success"),
    }
}

unsafe extern "C" fn service_reentry() -> c_int {
    // Report failure instead of unwinding through a C callback.
    match nss_module::getpwnam(b"flowned", b"fltest1") {
        Answer::Found(entry) if entry.pw_uid == 4201 => 0,
        _ => 1,
    }
}

fn check_success(directory: &Path, handle: *mut c_void) {
    let service = b"flowned";
    for _ in 0..3 {
        let user = found(nss_module::getpwnam(service, b"fltest1"));
        assert_eq!((user.pw_uid, user.pw_gid), (4201, 4301));
        assert_eq!(user.pw_dir, b"/home/fltest1");
        assert_eq!(
            found(nss_module::getpwuid(service, 4202)).pw_name,
            b"fltest2"
        );
        let group = found(nss_module::getgrnam(service, b"fltestmany"));
        assert_eq!(group.gr_gid, 4303);
        assert_eq!(
            group.gr_mem,
            [b"fltest2".to_vec(), b"nobody".to_vec(), b"fltest1".to_vec()]
        );
        assert_eq!(
            found(nss_module::getgrgid(service, 4302)).gr_name,
            b"fltestgrp2"
        );
        assert!(matches!(
            nss_module::getpwnam(service, b"no_such_fixture_user"),
            Answer::NotFound
        ));
        for family in [libc::AF_INET, libc::AF_INET6] {
            let host = host_found(nss_module::gethostbyname(service, b"fltest-large", family));
            assert_eq!(host.name, b"fltest-host.example");
            assert_eq!(host.aliases[2], vec![b'a'; 3072]);
            let expected: Vec<std::net::IpAddr> = if family == libc::AF_INET {
                vec!["192.0.2.41".parse().unwrap(), "192.0.2.42".parse().unwrap()]
            } else {
                vec![
                    "2001:db8::41".parse().unwrap(),
                    "2001:db8::42".parse().unwrap(),
                ]
            };
            assert_eq!(host.addresses, expected);
            let reverse = host_found(nss_module::gethostbyaddr(service, expected[1]));
            assert_eq!(reverse.name, b"fltest-host.example");
            assert_eq!(reverse.aliases[2].len(), 3072);
        }
    }
    let canonical = host_found(nss_module::gethostbyname(
        service,
        b"fltest-canonical",
        libc::AF_INET,
    ));
    assert_eq!(
        canonical.canonical_name,
        Some(b"fltest-official.example".to_vec())
    );
    assert!(nss_module::gethostbyname4(service, b"fltest-host").is_none());
    let allocator = assert_native_symbol(directory, "flowned", handle, "allocator_address");
    let allocator: unsafe extern "C" fn(u32) -> usize = unsafe { std::mem::transmute(allocator) };
    let abi = ABI.get().unwrap();
    for (which, expected) in [
        abi.malloc as *const () as usize,
        abi.realloc,
        abi.free as *const () as usize,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            unsafe { allocator(which as u32) },
            expected,
            "module and NSS must use the same allocator provider (entry {which})"
        );
    }
    let (status, groups) = nss_module::initgroups_segment(service, b"fltest1", 4301, &[4301], -1);
    assert_eq!(status, Status::Success);
    assert_eq!(groups, [4302, 4303, 0]);
    let count = assert_native_symbol(directory, "flowned", handle, "initgroups_reallocations");
    let count: unsafe extern "C" fn() -> u32 = unsafe { std::mem::transmute(count) };
    assert_eq!(
        unsafe { count() },
        1,
        "fixture must resize the owned caller allocation"
    );
    let setter = assert_native_symbol(directory, "flowned", handle, "set_service_reentry");
    let setter: unsafe extern "C" fn(unsafe extern "C" fn() -> c_int) =
        unsafe { std::mem::transmute(setter) };
    unsafe { setter(service_reentry) };
    let entry = found(nss_module::service_entry(
        service,
        nss_module::ServiceKey::Name(b"fltest-reentry"),
        Some(b"tcp"),
    ));
    assert_eq!(entry.port, 4347);
    assert_eq!(entry.aliases[2], vec![b's'; 3072]);
    for symbol in [
        "getpwnam_r",
        "getgrnam_r",
        "gethostbyname3_r",
        "gethostbyaddr2_r",
        "initgroups_dyn",
    ] {
        assert_native_symbol(directory, "flowned", handle, symbol);
    }
}

fn check_legacy_and_tuples(directory: &Path) {
    let legacy = native_module(directory, "flownedlegacy");
    let host = host_found(nss_module::gethostbyname(
        b"flownedlegacy",
        b"fltest-large",
        libc::AF_INET,
    ));
    assert_eq!(host.name, b"fltest-host.example");
    assert!(matches!(
        nss_module::gethostbyname(b"flownedlegacy", b"fltest-host", libc::AF_INET6),
        BackendResult::Unavailable(_)
    ));
    assert_native_symbol(directory, "flownedlegacy", legacy, "gethostbyname_r");
    let tuple = native_module(directory, "flownedtuple");
    for _ in 0..2 {
        let answer =
            host_found(nss_module::gethostbyname4(b"flownedtuple", b"fltest-tuple-large").unwrap());
        assert_eq!(
            answer.canonical_name,
            Some(b"fltest-tuple.example".to_vec())
        );
        assert_eq!(
            answer.addresses,
            [
                ("192.0.2.41".parse().unwrap(), 0),
                ("2001:db8::41".parse().unwrap(), 0),
                ("fe80::41".parse().unwrap(), 7),
                ("fe80::41".parse().unwrap(), 9),
            ]
        );
    }
    assert_native_symbol(directory, "flownedtuple", tuple, "gethostbyname4_r");
    let (status, groups) =
        nss_module::initgroups_segment(b"flownedlegacy", b"fltest1", 4301, &[4301], -1);
    assert_eq!((status, groups), (Status::Success, vec![4302, 4303, 0]));
    assert!(matches!(
        nss_module::getpwnam(b"flownedmissing", b"fltest1"),
        Answer::Unavailable(_)
    ));
    assert!(matches!(
        nss_module::getpwnam(b"../flowned", b"fltest1"),
        Answer::Unavailable(_)
    ));
}

#[test]
fn owned_nss_source_executes_native_modules() {
    if let Ok(scenario) = std::env::var("FRANKENLIBC_NSS_COMPONENT_CHILD") {
        let directory =
            PathBuf::from(std::env::var_os("FRANKENLIBC_NSS_COMPONENT_FIXTURES").unwrap());
        load_abi(Path::new(
            &std::env::var_os("FRANKENLIBC_NSS_COMPONENT_CANDIDATE").unwrap(),
        ));
        let handle = native_module(&directory, "flowned");
        // The loader calls above record decisions only in hardened mode. This
        // read-only 32-byte ABI snapshot neither selects a mode nor creates a
        // record, so it also detects strict cached prematurely during dlopen.
        let mut snapshot = [0u64; 4];
        let recorded = unsafe { (ABI.get().unwrap().snapshot)(snapshot.as_mut_ptr().cast()) };
        assert_eq!(
            recorded,
            c_int::from(std::env::var("FRANKENLIBC_MODE").unwrap() == "hardened"),
            "provider's recorded runtime mode must match the requested mode"
        );
        match scenario.as_str() {
            "success" => {
                check_success(&directory, handle);
                check_legacy_and_tuples(&directory);
            }
            "notfound" => {
                assert!(matches!(
                    nss_module::getpwnam(b"flowned", b"fltest1"),
                    Answer::NotFound
                ));
                assert!(matches!(
                    nss_module::gethostbyname(b"flowned", b"fltest-host", libc::AF_INET),
                    BackendResult::NotFound(_)
                ));
            }
            "tryagain" => {
                assert_eq!(
                    nss_module::getpwnam(b"flowned", b"fltest1"),
                    Answer::TryAgain(libc::EAGAIN)
                );
                assert!(matches!(
                    nss_module::gethostbyname(b"flowned", b"fltest-host", libc::AF_INET),
                    BackendResult::TryAgain(libc::EAI_AGAIN)
                ));
            }
            "unavail" => {
                assert_eq!(
                    nss_module::getpwnam(b"flowned", b"fltest1"),
                    Answer::Unavailable(libc::ENOENT)
                );
                assert!(matches!(
                    nss_module::gethostbyname(b"flowned", b"fltest-host", libc::AF_INET),
                    BackendResult::Unavailable(_)
                ));
            }
            _ => panic!("unknown component scenario"),
        }
        return;
    }
    let directory = PathBuf::from(
        std::env::var_os("FRANKENLIBC_NSS_COMPONENT_FIXTURES")
            .expect("runner supplies compiled native fixtures"),
    );
    for mode in ["strict", "hardened"] {
        for scenario in ["success", "notfound", "tryagain", "unavail"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "owned_nss_source_executes_native_modules",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("FRANKENLIBC_NSS_COMPONENT_CHILD", scenario)
                .env("FRANKENLIBC_MODE", mode)
                .env("LD_LIBRARY_PATH", &directory)
                .env(
                    "FLTEST_STATUS",
                    if scenario == "success" { "" } else { scenario },
                )
                .env("FLTEST_TRACE", "1")
                .env("FLTEST_REQUIRE_TUPLE_HEAD_RESET", "1")
                .env_remove("FLTEST_SERVICE_REENTER")
                .env_remove("FLTEST_TUPLE_SHAPE")
                .output()
                .expect("execute NSS source component child");
            assert!(
                output.status.success(),
                "{mode}/{scenario} failed ({}):\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "child must run its test"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("flowned:getpwnam_r(fltest1)"),
                "module callback must actually execute"
            );
            println!("PASS owned NSS component {mode}/{scenario}");
        }
    }
}
