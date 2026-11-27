//! Real native mappings must be discoverable throughout their public lifetime.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::{dlfcn_abi as dl, glibc_internal_abi as ext};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

const SOURCE: &str = include_str!("../../../tests/integration/fixture_native_find_object.c");
const MARKER: u64 = 0xa5a5_a5a5_a5a5_a5a5;
static FINALIZER: AtomicI32 = AtomicI32::new(0);

// Independent declaration of the GNU ELF64 ABI, including all reserved words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
struct FindObject {
    flags: u64,
    start: usize,
    end: usize,
    link_map: usize,
    eh_frame: usize,
    reserved: [u64; 7],
}

impl FindObject {
    fn sentinel() -> Self {
        Self {
            flags: MARKER,
            start: MARKER as usize,
            end: MARKER as usize,
            link_map: MARKER as usize,
            eh_frame: MARKER as usize,
            reserved: [MARKER; 7],
        }
    }
}

#[repr(C)]
struct Guarded {
    before: u64,
    value: FindObject,
    after: u64,
}

type Query = unsafe extern "C" fn(*mut c_void, *mut FindObject) -> c_int;
type Indirect = unsafe extern "C" fn(*mut c_void, *mut FindObject, *const c_char) -> c_int;

unsafe extern "C" fn query(address: *mut c_void, result: *mut FindObject) -> c_int {
    unsafe { ext::_dl_find_object(address, result.cast()) }
}

unsafe extern "C" fn report_finalizer(result: c_int) {
    FINALIZER.store(result, Ordering::SeqCst);
}

fn directory() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("franken-find-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn compile(dir: &Path, eh: bool) -> PathBuf {
    let input = dir.join(format!("find_{eh}.c"));
    let output = dir.join(format!("libfind_{eh}.so"));
    std::fs::write(&input, SOURCE).unwrap();
    let mut command = Command::new("cc");
    command.args([
        "-shared",
        "-fPIC",
        "-nostdlib",
        "-fno-builtin",
        "-fno-stack-protector",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wl,--hash-style=both",
        "-Wl,--build-id=none",
    ]);
    if eh {
        command.args(["-funwind-tables", "-Wl,--eh-frame-hdr"]);
    } else {
        command.args([
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-Wl,--no-eh-frame-hdr",
        ]);
    }
    let result = command.arg(&input).arg("-o").arg(&output).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    output
}

fn open(path: &Path) -> *mut c_void {
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    let handle = unsafe { dl::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(
        dl::native_dso_handle_for_tests(handle),
        "not a native load: {path:?}"
    );
    handle
}

fn symbol(handle: *mut c_void, name: &CStr) -> *mut c_void {
    let address = unsafe { dl::dlsym(handle, name.as_ptr()) };
    assert!(!address.is_null(), "missing {name:?}");
    address
}

fn expected(path: &Path, handle: *mut c_void) -> FindObject {
    let mut link_map = std::ptr::null_mut::<c_void>();
    assert_eq!(
        unsafe { ext::dlinfo(handle, 2, (&raw mut link_map).cast()) },
        0
    );
    assert!(!link_map.is_null());
    // The first public link_map word is l_addr, the load bias.
    let bias = unsafe { *link_map.cast::<usize>() };
    // Decode the ELF file independently of the implementation's ELF parser.
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(&bytes[..6], b"\x7fELF\x02\x01");
    let word = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) as usize;
    let short = |offset| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
    let table = word(32);
    assert_eq!(short(54), 56);
    let mut result = FindObject {
        flags: 0,
        start: usize::MAX,
        end: 0,
        link_map: link_map as usize,
        eh_frame: 0,
        reserved: [0; 7],
    };
    for index in 0..short(56) {
        let at = table + index * 56;
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let address = bias + word(at + 16);
        let memory_size = word(at + 40);
        if kind == 1 && memory_size != 0 {
            result.start = result.start.min(address);
            result.end = result.end.max(address + memory_size);
        } else if kind == 0x6474_e550 {
            result.eh_frame = address;
        }
    }
    result
}

fn assert_query(function: Query, address: *mut c_void, expected: FindObject) {
    let mut result = Guarded {
        before: MARKER,
        value: FindObject::sentinel(),
        after: MARKER,
    };
    assert_eq!(unsafe { function(address, &raw mut result.value) }, 0);
    assert_eq!(result.value, expected);
    assert_eq!((result.before, result.after), (MARKER, MARKER));
}

#[test]
fn native_find_object_lifecycle() {
    // A regression that takes the loader lock from a constructor or destructor
    // must fail within a bound instead of hanging the entire integration suite.
    if std::env::var_os("FL_FIND_OBJECT_CHILD").is_none() {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_find_object_lifecycle", "--nocapture"])
            .env("FL_FIND_OBJECT_CHILD", "1")
            .spawn()
            .unwrap();
        let started = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "native find-object child failed: {status}"
                );
                return;
            }
            if started.elapsed() > Duration::from_secs(40) {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("native find-object lifecycle deadlocked");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert_eq!(std::mem::size_of::<FindObject>(), 96);
    let dir = directory();
    let paths = [compile(&dir, true), compile(&dir, false)];
    let host: Query =
        unsafe { dlsym_oracle::host_fn(c"_dl_find_object", ext::_dl_find_object as *const ()) };
    for (index, path) in paths.iter().enumerate() {
        let handle = open(path);
        let data = symbol(handle, c"find_data");
        let code = symbol(handle, c"find_answer");
        let expected = expected(path, handle);
        assert_eq!(expected.eh_frame != 0, index == 0);
        assert_eq!(
            unsafe { *symbol(handle, c"find_constructor_result").cast::<c_int>() },
            1
        );
        // GNU's link map cannot see these mappings. Accepting host dlopen as a
        // fallback would make the test pass without exercising the new index.
        let mut missing = FindObject::sentinel();
        assert_eq!(unsafe { host(data, &raw mut missing) }, -1);
        assert_eq!(missing, FindObject::sentinel());
        let direct: Query = unsafe { std::mem::transmute(symbol(handle, c"find_direct")) };
        for address in [
            data,
            code,
            expected.start as *mut c_void,
            (expected.end - 1) as *mut c_void,
        ] {
            assert_query(query, address, expected);
            assert_query(direct, address, expected);
        }
        let indirect: Indirect = unsafe { std::mem::transmute(symbol(handle, c"find_indirect")) };
        for version in [std::ptr::null(), c"GLIBC_2.35".as_ptr()] {
            let mut info = FindObject::sentinel();
            assert_eq!(unsafe { indirect(code, &raw mut info, version) }, 0);
            assert_eq!(info, expected);
        }
        assert_eq!(
            unsafe { indirect(code, &raw mut missing, c"GLIBC_999.0".as_ptr()) },
            -2
        );
        assert_eq!(missing, FindObject::sentinel());
        // Keep one object live while the other slot is repeatedly retired and
        // reused. Its link_map identity and all lookup fields must stay stable.
        for _ in 0..16 {
            let other = open(&paths[1 - index]);
            assert_query(query, data, expected);
            assert_eq!(unsafe { dl::dlclose(other) }, 0);
            assert_query(query, code, expected);
        }
        let set_report: unsafe extern "C" fn(unsafe extern "C" fn(c_int)) =
            unsafe { std::mem::transmute(symbol(handle, c"find_set_finalizer_report")) };
        FINALIZER.store(0, Ordering::SeqCst);
        unsafe { set_report(report_finalizer) };
        assert_eq!(unsafe { dl::dlclose(handle) }, 0);
        assert_eq!(FINALIZER.load(Ordering::SeqCst), 1);
        // The stale PC is only compared numerically; it must never be read.
        assert_eq!(unsafe { query(data, &raw mut missing) }, -1);
        assert_eq!(missing, FindObject::sentinel());
    }
}
