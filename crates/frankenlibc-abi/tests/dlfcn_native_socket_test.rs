//! Native socket imports, protocol behavior, provider identity and version parity.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::{dlfcn_abi as dl, socket_abi as socket, unistd_abi as unistd};
use frankenlibc_core::elf::ElfLoader;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

const SOURCE: &str = include_str!("fixtures/native_socket_runtime.c");
const CHILD: &str = "FRANKENLIBC_SOCKET_RUNTIME_CHILD";
type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
type Sym = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type Function = unsafe extern "C" fn(u32) -> *mut c_void;
type Dynamic = unsafe extern "C" fn(*const c_char, *const c_char, *mut c_int) -> *mut c_void;

fn symbols() -> [(&'static str, &'static str, *const ()); 20] {
    [
        ("socket", "GLIBC_2.2.5", socket::socket as *const ()),
        ("socketpair", "GLIBC_2.2.5", socket::socketpair as *const ()),
        ("bind", "GLIBC_2.2.5", socket::bind as *const ()),
        ("listen", "GLIBC_2.2.5", socket::listen as *const ()),
        ("connect", "GLIBC_2.2.5", socket::connect as *const ()),
        ("accept", "GLIBC_2.2.5", socket::accept as *const ()),
        ("accept4", "GLIBC_2.10", socket::accept4 as *const ()),
        ("shutdown", "GLIBC_2.2.5", socket::shutdown as *const ()),
        ("getsockname", "GLIBC_2.2.5", socket::getsockname as *const ()),
        ("getpeername", "GLIBC_2.2.5", socket::getpeername as *const ()),
        ("getsockopt", "GLIBC_2.2.5", socket::getsockopt as *const ()),
        ("setsockopt", "GLIBC_2.2.5", socket::setsockopt as *const ()),
        ("send", "GLIBC_2.2.5", socket::send as *const ()),
        ("recv", "GLIBC_2.2.5", socket::recv as *const ()),
        ("sendto", "GLIBC_2.2.5", socket::sendto as *const ()),
        ("recvfrom", "GLIBC_2.2.5", socket::recvfrom as *const ()),
        ("sendmsg", "GLIBC_2.2.5", socket::sendmsg as *const ()),
        ("recvmsg", "GLIBC_2.2.5", socket::recvmsg as *const ()),
        ("sendmmsg", "GLIBC_2.14", unistd::sendmmsg as *const ()),
        ("recvmmsg", "GLIBC_2.12", unistd::recvmmsg as *const ()),
    ]
}

struct Api {
    open: Open,
    close: Close,
    sym: Sym,
    native: bool,
}

impl Api {
    fn new(native: bool) -> Self {
        if native {
            Self { open: dl::dlopen, close: dl::dlclose, sym: dl::dlsym, native }
        } else {
            // SAFETY: the oracle rejects our interposed entry points and
            // returns host functions with these exact declared signatures.
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

    fn open(&self, path: &Path) -> *mut c_void {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(name.as_ptr(), libc::RTLD_NOW) };
        assert!(!handle.is_null(), "open {path:?}");
        if self.native {
            assert!(dl::native_dso_handle_for_tests(handle), "host fallback: {path:?}");
        }
        handle
    }

    fn symbol(&self, handle: *mut c_void, name: &CStr) -> *mut c_void {
        let address = unsafe { (self.sym)(handle, name.as_ptr()) };
        assert!(!address.is_null(), "missing {name:?}");
        address
    }
}

struct Fixture {
    path: PathBuf,
    nonce: u64,
}

impl Fixture {
    fn new(got: bool) -> Self {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc-native-socket-{}-{stamp}", std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("fixture.c");
        let path = dir.join("fixture.so");
        std::fs::write(&source, SOURCE).unwrap();
        let mut command = Command::new("gcc");
        command.args([
            "-shared", "-fPIC", "-nostdlib", "-O2", "-fno-builtin",
            "-Wall", "-Wextra", "-Werror", "-Wl,--hash-style=both",
        ]);
        if got {
            command.arg("-fno-plt");
        }
        let output = command.arg(&source).arg("-o").arg(&path).output().expect("gcc is required");
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let bytes = std::fs::read(&path).unwrap();
        let object = ElfLoader::new(0).parse(&bytes).unwrap();
        assert!(object.needed_libraries.is_empty(), "host dependencies would mask missing bindings");
        for (name, _, _) in symbols() {
            assert!(
                object.undefined_symbols().any(|(_, symbol)| object.symbol_name(symbol) == Some(name)),
                "fixture did not import {name}"
            );
        }
        Self { path, nonce: stamp as u64 ^ (u64::from(std::process::id()) << 32) }
    }
}

fn exercise(native: bool) {
    let api = Api::new(native);
    for got in [false, true] {
        let fixture = Fixture::new(got);
        let handle = api.open(&fixture.path);
        let direct: Function = unsafe { std::mem::transmute(api.symbol(handle, c"socket_function")) };
        let dynamic: Dynamic = unsafe { std::mem::transmute(api.symbol(handle, c"socket_dynamic")) };
        for (index, (name, version, expected)) in symbols().into_iter().enumerate() {
            let actual = unsafe { direct(index as u32) };
            let name = CString::new(name).unwrap();
            let version = CString::new(version).unwrap();
            let expected = if native {
                expected as *mut c_void
            } else {
                unsafe { dlsym_oracle::host_addr(&name, expected) }
            };
            assert_eq!(actual, expected, "wrong provider for {name:?}");
            for required in [std::ptr::null(), version.as_ptr()] {
                let mut error = -1;
                assert_eq!(unsafe { dynamic(name.as_ptr(), required, &mut error) }, actual);
                assert_eq!(error, 0);
            }
            for rejected in [c"GLIBC_2.34", c"FRANKENLIBC_SOCKET_MISSING_VERSION"] {
                let mut error = -1;
                assert!(unsafe { dynamic(name.as_ptr(), rejected.as_ptr(), &mut error) }.is_null());
                assert_eq!(error, 1, "version rejection must set dlerror");
            }
        }
        type Run = unsafe extern "C" fn() -> c_int;
        for name in [c"socket_stream_protocol", c"socket_datagram_protocol"] {
            let run: Run = unsafe { std::mem::transmute(api.symbol(handle, name)) };
            assert_eq!(unsafe { run() }, 0, "{name:?}: failing C protocol line");
        }
        type Listen = unsafe extern "C" fn(u64) -> c_int;
        let listen: Listen = unsafe { std::mem::transmute(api.symbol(handle, c"socket_listener_protocol")) };
        assert_eq!(unsafe { listen(fixture.nonce) }, 0, "listener: failing C protocol line");
        assert_eq!(unsafe { (api.close)(handle) }, 0);
    }
}

#[test]
fn native_socket_runtime_protocols_and_versions() {
    if let Ok(provider) = std::env::var(CHILD) {
        assert!(matches!(provider.as_str(), "host" | "native"));
        exercise(provider == "native");
        return;
    }
    // A fresh process owns each runtime policy and loader namespace. A host
    // fallback cannot count as a successful native test, even in interpose mode.
    for (provider, mode) in [("host", "strict"), ("native", "strict"), ("native", "hardened")] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_socket_runtime_protocols_and_versions", "--nocapture"])
            .env(CHILD, provider)
            .env("FRANKENLIBC_MODE", mode)
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{provider}/{mode}: {status}");
                break;
            }
            if start.elapsed() > Duration::from_secs(40) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{provider}/{mode}: timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
