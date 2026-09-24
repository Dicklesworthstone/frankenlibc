//! Gates must exercise ABI-owned anonymous mappings, not compare glibc to itself.
#![cfg(all(target_os = "linux", target_arch = "x86_64", not(feature = "standalone")))]

use std::ffi::{CStr, CString, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use frankenlibc_abi::dlfcn_abi as fl;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Dso {
    handle: *mut c_void,
    path: PathBuf,
}

impl Dso {
    fn new() -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "frankenlibc-inspection-{}-{stamp}-{sequence}", std::process::id(),
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("libinspection.so");
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/integration/fixture_native_inspection_dso.c");
        let output = Command::new("cc")
            .args(["-shared", "-fPIC", "-nostdlib", "-fexceptions",
                   "-Wl,--hash-style=gnu", "-Wl,--eh-frame-hdr", "-o"])
            .arg(&path).arg(source).output().expect("run C fixture compiler");
        assert!(output.status.success(), "fixture compile: {}",
                String::from_utf8_lossy(&output.stderr));
        let filename = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { fl::dlopen(filename.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        assert!(!handle.is_null(), "native fixture dlopen failed");
        assert!(fl::native_dso_handle_for_tests(handle), "host fallback would mask the defect");
        Self { handle, path }
    }

    fn symbol(&self, name: &CStr) -> *mut c_void {
        let address = unsafe { fl::dlsym(self.handle, name.as_ptr()) };
        assert!(!address.is_null(), "missing fixture symbol {name:?}");
        address
    }

    fn close(&mut self) {
        assert_eq!(unsafe { fl::dlclose(self.handle) }, 0);
        self.handle = std::ptr::null_mut();
    }
}

impl Drop for Dso {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let _ = unsafe { fl::dlclose(self.handle) };
        }
    }
}

fn address_info(address: *const c_void) -> (i32, libc::Dl_info) {
    // SAFETY: all-zero is a valid initial value for a pointer-only C struct.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let result = unsafe { fl::dladdr(address, (&raw mut info).cast()) };
    (result, info)
}

#[test]
fn native_address_lookup_reports_resident_path_and_symbol_bounds() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let mut dso = Dso::new();
    let data = dso.symbol(c"inspection_data");
    let (found, info) = address_info(data);
    assert_ne!(found, 0);
    assert_eq!(unsafe { CStr::from_ptr(info.dli_fname) }.to_bytes(),
               dso.path.as_os_str().as_bytes());
    assert_eq!(unsafe { CStr::from_ptr(info.dli_sname) }, c"inspection_data");
    assert_eq!(info.dli_saddr, data);
    assert!(!info.dli_fbase.is_null());
    let (found, interior) = address_info((data as usize + 7) as *const c_void);
    assert_ne!(found, 0);
    assert_eq!(interior.dli_saddr, data);
    let (found, past) = address_info((data as usize + 16) as *const c_void);
    assert_ne!(found, 0);
    assert!(past.dli_sname.is_null() && past.dli_saddr.is_null());
    let (found, header) = address_info(info.dli_fbase);
    assert_ne!(found, 0);
    assert!(header.dli_sname.is_null() && header.dli_saddr.is_null());
    // A second lookup must not overwrite temporary storage behind the first.
    let function = dso.symbol(c"inspection_function");
    let (found, function_info) = address_info(function);
    assert_ne!(found, 0);
    assert_eq!(unsafe { CStr::from_ptr(function_info.dli_sname) }, c"inspection_function");
    assert_eq!(unsafe { CStr::from_ptr(info.dli_sname) }, c"inspection_data");
    dso.close();
    // Do not dereference returned strings after the object has been unloaded.
    assert_eq!(address_info(data).0, 0);
}

#[test]
fn native_zero_sized_symbol_matches_only_its_exact_address() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let dso = Dso::new();
    let zero = dso.symbol(c"inspection_zero");
    let (found, exact) = address_info(zero);
    assert_ne!(found, 0);
    assert_eq!(unsafe { CStr::from_ptr(exact.dli_sname) }, c"inspection_zero");
    let (found, interior) = address_info((zero as usize + 1) as *const c_void);
    assert_ne!(found, 0);
    assert!(interior.dli_sname.is_null() && interior.dli_saddr.is_null());
    assert_eq!(address_info(1usize as *const c_void).0, 0);
}
