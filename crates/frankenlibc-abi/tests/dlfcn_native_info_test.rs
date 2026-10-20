#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::{dlfcn_abi as dl, glibc_internal_abi as ext};
use frankenlibc_core::elf::ElfLoader;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
type Sym = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type Error = unsafe extern "C" fn() -> *const c_char;
type Info = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void) -> c_int;
type Address = unsafe extern "C" fn(*const c_void, *mut c_void, *mut *mut c_void, c_int) -> c_int;

const SOURCE: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
int info_data = 19;
int info_function(void) { return 73; }
int info_ifunc_calls;
static int selected_function(void) { return 81; }
static void *select_function(void) { ++info_ifunc_calls; return selected_function; }
int info_indirect_function(void) __attribute__((ifunc("select_function")));
int info_address(const void *address, Dl_info *output, void **extra, int flags) {
    return dladdr1(address, output, extra, flags);
}
int info_indirect_query(void *handle, int request, void *output, const char *version) {
    int (*function)(void *, int, void *) = version
        ? dlvsym(RTLD_DEFAULT, "dlinfo", version) : dlsym(RTLD_DEFAULT, "dlinfo");
    return function ? function(handle, request, output) : -2;
}
int info_indirect_address(const void *address, Dl_info *output, void **extra, int flags,
                          const char *version) {
    int (*function)(const void *, Dl_info *, void **, int) = version
        ? dlvsym(RTLD_DEFAULT, "dladdr1", version) : dlsym(RTLD_DEFAULT, "dladdr1");
    return function ? function(address, output, extra, flags) : -2;
}
#ifdef HAS_TLS
struct info_block_type { int prefix[8]; int value; };
__thread struct info_block_type info_block = {{7}, 41};
void *info_value_address(void) { return &info_block.value; }
#else
void *info_value_address(void) { return &info_data; }
#endif
int info_query(void *handle, int request, void *output) {
    return dlinfo(handle, request, output);
}
#ifdef LIFECYCLE
static void *self_handle;
static void (*report)(int, int);
int info_constructor_result = -10;
__attribute__((constructor)) static void initialize(void) {
    void *handle = dlopen("$ORIGIN/libinfo.so", RTLD_NOW | RTLD_NOLOAD);
    if (!handle) { info_constructor_result = -11; return; }
    self_handle = handle;
    Lmid_t ns = -1;
    void *tls = (void *)1;
    int a = dlinfo(handle, RTLD_DI_LMID, &ns);
    int b = dlinfo(handle, RTLD_DI_TLS_DATA, &tls);
    info_constructor_result = a == 0 && b == 0 && ns == 0 && tls == 0 ? 1 : -12;
    dlclose(handle);
}
void info_set_report(void (*callback)(int, int)) { report = callback; }
__attribute__((destructor)) static void finalize(void) {
    Lmid_t ns = -1;
    int result = dlinfo(self_handle, RTLD_DI_LMID, &ns);
    if (report) report(result, (int)ns);
}
#endif
"#;

#[repr(C)]
struct LinkMap {
    base: usize,
    name: *const c_char,
    dynamic: *const c_void,
    next: *const LinkMap,
    previous: *const LinkMap,
}

#[derive(Clone, Copy)]
struct Api {
    open: Open,
    close: Close,
    sym: Sym,
    error: Error,
    info: Info,
    address: Address,
    native: bool,
}
impl Api {
    fn new(native: bool) -> Self {
        if native {
            // Enter through a real C DSO's imports, not a test-only Rust hook.
            // Its single LOCAL reference is intentionally kept for this isolated
            // child's lifetime so both returned function pointers remain valid.
            // The older directly linked compatibility exports are a separate
            // integration surface and are not credited by this plugin suite.
            let bridge = Fixture::new(false, false);
            let name = CString::new(bridge.library.as_os_str().as_bytes()).unwrap();
            let h = unsafe { dl::dlopen(name.as_ptr(), libc::RTLD_NOW) };
            assert!(!h.is_null() && dl::native_dso_handle_for_tests(h));
            let info = unsafe { dl::dlsym(h, c"info_query".as_ptr()) };
            let address = unsafe { dl::dlsym(h, c"info_address".as_ptr()) };
            assert!(!info.is_null() && !address.is_null());
            Self {
                open: dl::dlopen,
                close: dl::dlclose,
                sym: dl::dlsym,
                error: dl::dlerror,
                info: unsafe { std::mem::transmute::<*mut c_void, Info>(info) },
                address: unsafe { std::mem::transmute::<*mut c_void, Address>(address) },
                native,
            }
        } else {
            unsafe {
                Self {
                    open: dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ()),
                    close: dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ()),
                    sym: dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ()),
                    error: dlsym_oracle::host_fn(c"dlerror", dl::dlerror as *const ()),
                    info: dlsym_oracle::host_fn(c"dlinfo", ext::dlinfo as *const ()),
                    address: dlsym_oracle::host_fn(c"dladdr1", ext::dladdr1 as *const ()),
                    native,
                }
            }
        }
    }
    fn open_path(self, path: &Path, flags: c_int) -> *mut c_void {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(name.as_ptr(), flags | libc::RTLD_NOW) };
        assert!(!handle.is_null(), "dlopen {path:?}");
        if self.native {
            assert!(dl::native_dso_handle_for_tests(handle), "host fallback");
        }
        handle
    }
    fn close(self, handle: *mut c_void) {
        assert_eq!(unsafe { (self.close)(handle) }, 0);
    }
    fn symbol(self, handle: *mut c_void, name: &CStr) -> *mut c_void {
        let result = unsafe { (self.sym)(handle, name.as_ptr()) };
        assert!(!result.is_null(), "dlsym {name:?}");
        result
    }
    fn query<T: Copy>(self, handle: *mut c_void, request: i32, initial: T) -> (i32, T) {
        let mut result = initial;
        let code = unsafe { (self.info)(handle, request, (&raw mut result).cast()) };
        (code, result)
    }
    fn map(self, handle: *mut c_void) -> *const LinkMap {
        let (code, map) = self.query(handle, 2, std::ptr::null::<LinkMap>());
        assert_eq!(code, 0);
        assert!(!map.is_null());
        map
    }
}

struct Fixture {
    dir: PathBuf,
    library: PathBuf,
}
impl Fixture {
    fn new(tls: bool, lifecycle: bool) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc-info-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("info.c");
        let library = dir.join("libinfo.so");
        std::fs::write(&source, SOURCE).unwrap();
        let mut command = Command::new("gcc");
        command
            .args([
                "-shared",
                "-fPIC",
                "-nostdlib",
                "-O2",
                "-Wl,--hash-style=both",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&library);
        if tls {
            command.arg("-DHAS_TLS");
        }
        if lifecycle {
            command.arg("-DLIFECYCLE");
        }
        let output = command.output().expect("gcc is required");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let object = ElfLoader::new(0)
            .parse(&std::fs::read(&library).unwrap())
            .unwrap();
        assert!(
            object.needed_libraries.is_empty(),
            "no host runtime dependencies allowed"
        );
        assert_eq!(object.tls_segment.is_some(), tls);
        for name in ["dlinfo", "dladdr1", "dlsym", "dlvsym"] {
            assert!(
                object
                    .undefined_symbols()
                    .any(|(_, symbol)| object.symbol_name(symbol) == Some(name))
            );
        }
        Self { dir, library }
    }
}

fn isolated(name: &str, native_only: bool, scenario: fn(Api)) {
    if let Ok(mode) = std::env::var("FRANKENLIBC_INFO_CHILD") {
        assert!(mode == "host" || mode == "native");
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
            .env("FRANKENLIBC_INFO_CHILD", mode)
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{name}: {mode}: {status}");
                break;
            }
            if start.elapsed() > Duration::from_secs(40) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{name}: {mode}: timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn info_reports_owned_map_origin_headers_and_absent_tls() {
    isolated(
        "info_reports_owned_map_origin_headers_and_absent_tls",
        false,
        |api| {
            let f = Fixture::new(false, false);
            let h = api.open_path(&f.library, 0);
            assert_eq!(api.query(h, 1, -1 as c_long), (0, 0));
            assert_eq!(api.query(h, 9, usize::MAX), (0, 0));
            assert_eq!(api.query(h, 10, 1usize), (0, 0));
            let map = api.map(h);
            assert_eq!(
                unsafe { CStr::from_ptr((*map).name) }.to_bytes(),
                f.library.as_os_str().as_bytes()
            );
            let (count, headers) = api.query(h, 11, std::ptr::null::<libc::Elf64_Phdr>());
            assert!(count > 0 && !headers.is_null());
            let headers = unsafe { std::slice::from_raw_parts(headers, count as usize) };
            let dynamic = headers.iter().find(|header| header.p_type == 2).unwrap();
            assert_eq!(
                unsafe { (*map).dynamic } as usize,
                unsafe { (*map).base } + dynamic.p_vaddr as usize
            );
            let mut origin = vec![0xa5u8; f.dir.as_os_str().as_bytes().len() + 33];
            assert_eq!(unsafe { (api.info)(h, 6, origin.as_mut_ptr().cast()) }, 0);
            let expected = f.dir.as_os_str().as_bytes();
            assert_eq!(&origin[..expected.len()], expected);
            assert_eq!(origin[expected.len()], 0);
            assert!(
                origin[expected.len() + 1..]
                    .iter()
                    .all(|byte| *byte == 0xa5)
            );
            // Live link-map pointers are accepted for introspection too, without
            // dereferencing an arbitrary incoming handle inside the native route.
            assert_eq!(api.query(map.cast_mut().cast(), 1, -1 as c_long), (0, 0));
            let own_query: Info = unsafe { std::mem::transmute(api.symbol(h, c"info_query")) };
            let mut ns: c_long = -1;
            assert_eq!(unsafe { own_query(h, 1, (&raw mut ns).cast()) }, 0);
            assert_eq!(ns, 0);
            api.close(h);
        },
    );
}

#[test]
fn info_pointers_survive_registry_growth_and_links_skip_unloaded_objects() {
    isolated(
        "info_pointers_survive_registry_growth_and_links_skip_unloaded_objects",
        false,
        |api| {
            let f = Fixture::new(false, false);
            let h = api.open_path(&f.library, 0);
            let map = api.map(h);
            let name = unsafe { (*map).name };
            let phdr = api.query(h, 11, 0usize);
            let mut objects = Vec::new();
            for i in 0..48 {
                let path = f.dir.join(format!("copy{i}.so"));
                std::fs::copy(&f.library, &path).unwrap();
                let handle = api.open_path(&path, 0);
                objects.push((handle, api.map(handle)));
            }
            assert_eq!(api.map(h), map);
            assert_eq!(unsafe { (*map).name }, name);
            assert_eq!(api.query(h, 11, 0usize), phdr);
            for (i, &(handle, _)) in objects.iter().enumerate() {
                if i % 2 == 1 {
                    api.close(handle);
                }
            }
            let mut previous = map;
            for (i, &(handle, current)) in objects.iter().enumerate() {
                if i % 2 == 1 {
                    continue;
                }
                assert_eq!(unsafe { (*previous).next }, current);
                assert_eq!(unsafe { (*current).previous }, previous);
                assert_eq!(api.map(handle), current);
                previous = current;
            }
            assert!(unsafe { (*previous).next }.is_null());
            for (i, &(handle, _)) in objects.iter().enumerate() {
                if i % 2 == 0 {
                    api.close(handle);
                }
            }
            assert!(unsafe { (*map).next }.is_null());
            api.close(h);
        },
    );
}

#[test]
fn info_tls_soft_lookup_is_thread_local_and_does_not_allocate() {
    isolated(
        "info_tls_soft_lookup_is_thread_local_and_does_not_allocate",
        false,
        |api| {
            let f = Fixture::new(true, false);
            let h = api.open_path(&f.library, 0);
            let (code, module) = api.query(h, 9, 0usize);
            assert_eq!(code, 0);
            assert!(module > 0);
            for _ in 0..5 {
                assert_eq!(api.query(h, 10, 1usize), (0, 0));
            }
            let value: unsafe extern "C" fn() -> *mut i32 =
                unsafe { std::mem::transmute(api.symbol(h, c"info_value_address")) };
            let main_value = unsafe { value() };
            assert_eq!(unsafe { *main_value }, 41);
            let (_, main_base) = api.query(h, 10, 0usize);
            assert_ne!(main_base, 0);
            assert_eq!(
                main_value as usize,
                main_base + 8 * std::mem::size_of::<i32>()
            );
            unsafe {
                *main_value = 99;
            }
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
            let mut threads = Vec::new();
            for i in 0..2 {
                let barrier = barrier.clone();
                let handle = h as usize;
                threads.push(std::thread::spawn(move || {
                    let h = handle as *mut c_void;
                    assert_eq!(api.query(h, 9, 0usize), (0, module));
                    assert_eq!(api.query(h, 10, 1usize), (0, 0));
                    let current = unsafe { value() };
                    assert_eq!(unsafe { *current }, 41);
                    unsafe {
                        *current = 120 + i;
                    }
                    let (code, base) = api.query(h, 10, 0usize);
                    assert_eq!(code, 0);
                    assert_ne!(base, 0);
                    assert_eq!(current as usize, base + 32);
                    assert_ne!(base, main_base);
                    barrier.wait();
                    barrier.wait();
                    assert_eq!(unsafe { *current }, 120 + i);
                    base
                }));
            }
            barrier.wait();
            assert_eq!(unsafe { *main_value }, 99);
            barrier.wait();
            let first = threads.remove(0).join().unwrap();
            let second = threads.remove(0).join().unwrap();
            assert_ne!(first, second);
            api.close(h);
        },
    );
}

#[test]
fn info_origin_is_retained_after_backing_path_is_renamed() {
    isolated(
        "info_origin_is_retained_after_backing_path_is_renamed",
        false,
        |api| {
            let f = Fixture::new(false, false);
            let h = api.open_path(&f.library, 0);
            let map = api.map(h);
            std::fs::rename(&f.library, f.dir.join("renamed.so")).unwrap();
            let mut output = vec![0u8; f.dir.as_os_str().as_bytes().len() + 1];
            assert_eq!(unsafe { (api.info)(h, 6, output.as_mut_ptr().cast()) }, 0);
            assert_eq!(&output[..output.len() - 1], f.dir.as_os_str().as_bytes());
            assert_eq!(
                unsafe { CStr::from_ptr((*map).name) }.to_bytes(),
                f.library.as_os_str().as_bytes()
            );
            api.close(h);
        },
    );
}

#[test]
fn info_errors_do_not_write_outputs_and_success_clears_error() {
    isolated(
        "info_errors_do_not_write_outputs_and_success_clears_error",
        false,
        |api| {
            let f = Fixture::new(false, false);
            let h = api.open_path(&f.library, 0);
            assert_eq!(
                api.query(h, 9876, 0xa5a5a5a5a5a5a5a5u64),
                (-1, 0xa5a5a5a5a5a5a5a5)
            );
            assert!(!unsafe { (api.error)() }.is_null());
            assert!(unsafe { (api.error)() }.is_null());
            assert_eq!(api.query(h, 9876, 12usize), (-1, 12));
            assert_eq!(api.query(h, 1, -1 as c_long), (0, 0));
            assert!(unsafe { (api.error)() }.is_null());
            api.close(h);
        },
    );
}

static FINAL_RESULT: AtomicI32 = AtomicI32::new(-100);
unsafe extern "C" fn final_report(rc: c_int, ns: c_int) {
    FINAL_RESULT.store(if rc == 0 && ns == 0 { 1 } else { -1 }, Ordering::Relaxed);
}

#[test]
fn info_is_available_to_native_constructors_and_finalizers() {
    isolated(
        "info_is_available_to_native_constructors_and_finalizers",
        false,
        |api| {
            let f = Fixture::new(true, true);
            let h = api.open_path(&f.library, 0);
            assert_eq!(
                unsafe { *api.symbol(h, c"info_constructor_result").cast::<c_int>() },
                1
            );
            type Set = unsafe extern "C" fn(unsafe extern "C" fn(c_int, c_int));
            let set: Set = unsafe { std::mem::transmute(api.symbol(h, c"info_set_report")) };
            unsafe { set(final_report) };
            api.close(h);
            assert_eq!(FINAL_RESULT.load(Ordering::Relaxed), 1);
        },
    );
}

#[test]
fn info_main_and_foreign_host_handles_use_real_host_metadata() {
    isolated(
        "info_main_and_foreign_host_handles_use_real_host_metadata",
        false,
        |api| {
            let main = unsafe { (api.open)(std::ptr::null(), libc::RTLD_NOW) };
            assert!(!main.is_null());
            assert_eq!(api.query(main, 1, -1 as c_long), (0, 0));
            assert!(!api.map(main).is_null());
            assert!(api.query(main, 11, 0usize).0 > 0);
            api.close(main);
            let foreign = unsafe { (api.open)(c"libm.so.6".as_ptr(), libc::RTLD_NOW) };
            assert!(!foreign.is_null());
            if api.native {
                assert!(!dl::native_dso_handle_for_tests(foreign));
            }
            let host = Api::new(false);
            assert_eq!(api.map(foreign), host.map(foreign));
            assert_eq!(
                api.query(foreign, 11, 0usize),
                host.query(foreign, 11, 0usize)
            );
            api.close(foreign);
        },
    );
}

#[test]
fn info_stale_native_ids_and_null_outputs_are_never_host_handles() {
    isolated(
        "info_stale_native_ids_and_null_outputs_are_never_host_handles",
        true,
        |api| {
            let f = Fixture::new(false, false);
            let h = api.open_path(&f.library, 0);
            assert_eq!(unsafe { (api.info)(h, 1, std::ptr::null_mut()) }, -1);
            assert!(!unsafe { (api.error)() }.is_null());
            api.close(h);
            assert!(!dl::native_dso_handle_for_tests(h));
            assert_eq!(api.query(h, 9, 77usize), (-1, 77));
            assert!(!unsafe { (api.error)() }.is_null());
            assert!(unsafe { (api.error)() }.is_null());
            assert_eq!(api.query(std::ptr::null_mut(), 1, 77usize), (-1, 77));
            assert_eq!(api.query(libc::RTLD_NEXT, 1, 77usize), (-1, 77));
        },
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
struct ElfSymbol {
    name: u32,
    info: u8,
    other: u8,
    section: u16,
    value: u64,
    size: u64,
}

fn file_symbol(path: &Path, name: &str) -> (usize, ElfSymbol) {
    let bytes = std::fs::read(path).unwrap();
    let object = ElfLoader::new(0).parse(&bytes).unwrap();
    let (index, symbol) = object
        .dynsym
        .iter()
        .enumerate()
        .find(|(_, symbol)| object.symbol_name(symbol) == Some(name))
        .unwrap();
    let dynamic = object
        .program_headers
        .iter()
        .find(|header| header.p_type == frankenlibc_core::elf::ProgramType::Dynamic)
        .unwrap();
    let entries = &bytes[dynamic.p_offset as usize..(dynamic.p_offset + dynamic.p_filesz) as usize];
    let table = entries
        .as_chunks::<16>()
        .0
        .iter()
        .take_while(|entry| entry[..8] != [0; 8])
        .find(|entry| i64::from_le_bytes(entry[..8].try_into().unwrap()) == 6)
        .unwrap();
    let offset = u64::from_le_bytes(table[8..16].try_into().unwrap()) as usize + index * 24;
    (
        offset,
        ElfSymbol {
            name: symbol.st_name,
            info: symbol.st_info,
            other: symbol.st_other,
            section: symbol.st_shndx,
            value: symbol.st_value,
            size: symbol.st_size,
        },
    )
}

fn address_query(
    function: Address,
    address: *const c_void,
    flag: i32,
) -> (libc::Dl_info, *mut c_void) {
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let mut extra = std::ptr::without_provenance_mut(1);
    assert_eq!(
        unsafe { function(address, (&raw mut info).cast(), &mut extra, flag) },
        1
    );
    (info, extra)
}

#[test]
fn info_dladdr1_exposes_mapped_symbols_and_the_same_link_map() {
    isolated(
        "info_dladdr1_exposes_mapped_symbols_and_the_same_link_map",
        false,
        |api| {
            let f = Fixture::new(false, false);
            let h = api.open_path(&f.library, 0);
            let map = api.map(h);
            let base = unsafe { (*map).base };
            let imported: Address = unsafe { std::mem::transmute(api.symbol(h, c"info_address")) };
            for name in ["info_function", "info_data"] {
                let name_c = CString::new(name).unwrap();
                let address = api.symbol(h, &name_c);
                let (table_offset, expected) = file_symbol(&f.library, name);
                for function in [api.address, imported] {
                    let (info, extra) = address_query(function, address, 1);
                    assert_eq!(info.dli_fbase as usize, base);
                    assert_eq!(info.dli_saddr, address);
                    assert_eq!(
                        unsafe { CStr::from_ptr(info.dli_sname) }.to_bytes(),
                        name.as_bytes()
                    );
                    assert_eq!(extra as usize, base + table_offset);
                    assert_eq!(
                        unsafe { extra.cast::<ElfSymbol>().read_unaligned() },
                        expected
                    );
                    let (_, extra_map) = address_query(function, address, 2);
                    assert_eq!(extra_map.cast::<LinkMap>(), map.cast_mut());
                    let (_, untouched) = address_query(function, address, 9876);
                    assert_eq!(untouched as usize, 1);
                }
            }
            // The ELF header belongs to the DSO but not to an exported symbol.
            let (info, extra) = address_query(api.address, base as *const c_void, 1);
            assert!(info.dli_sname.is_null() && info.dli_saddr.is_null() && extra.is_null());
            let (_, extra) = address_query(api.address, base as *const c_void, 2);
            assert_eq!(extra.cast::<LinkMap>(), map.cast_mut());
            // Inspection of an IFUNC resolver address is metadata, not resolution.
            let (_, resolver) = file_symbol(&f.library, "info_indirect_function");
            let counter = api.symbol(h, c"info_ifunc_calls").cast::<i32>();
            assert_eq!(unsafe { *counter }, 0);
            let (info, extra) = address_query(
                api.address,
                (base + resolver.value as usize) as *const c_void,
                1,
            );
            assert_eq!(
                unsafe { CStr::from_ptr(info.dli_sname) }.to_bytes(),
                b"info_indirect_function"
            );
            assert_eq!(unsafe { (*extra.cast::<ElfSymbol>()).info } & 15, 10);
            assert_eq!(unsafe { *counter }, 0);
            api.close(h);
        },
    );
}

#[test]
fn info_dynamic_introspection_functions_preserve_native_handle_ownership() {
    isolated(
        "info_dynamic_introspection_functions_preserve_native_handle_ownership",
        false,
        |api| {
            let f = Fixture::new(false, false);
            let h = api.open_path(&f.library, 0);
            type IndirectInfo =
                unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, *const c_char) -> c_int;
            type IndirectAddress = unsafe extern "C" fn(
                *const c_void,
                *mut c_void,
                *mut *mut c_void,
                c_int,
                *const c_char,
            ) -> c_int;
            let query: IndirectInfo =
                unsafe { std::mem::transmute(api.symbol(h, c"info_indirect_query")) };
            let address_query: IndirectAddress =
                unsafe { std::mem::transmute(api.symbol(h, c"info_indirect_address")) };
            let address = api.symbol(h, c"info_function");
            let map = api.map(h);
            for version in [
                std::ptr::null(),
                c"GLIBC_2.3.3".as_ptr(),
                c"GLIBC_2.34".as_ptr(),
            ] {
                let mut ns: c_long = -1;
                assert_eq!(unsafe { query(h, 1, (&raw mut ns).cast(), version) }, 0);
                assert_eq!(ns, 0);
                let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
                let mut extra = std::ptr::null_mut();
                assert_eq!(
                    unsafe {
                        address_query(address, (&raw mut info).cast(), &mut extra, 2, version)
                    },
                    1
                );
                assert_eq!(extra.cast::<LinkMap>(), map.cast_mut());
                assert_eq!(info.dli_saddr, address);
            }
            let mut ns: c_long = 77;
            assert_eq!(
                unsafe { query(h, 1, (&raw mut ns).cast(), c"NO_SUCH_VERSION".as_ptr()) },
                -2
            );
            assert_eq!(ns, 77);
            api.close(h);
        },
    );
}

#[test]
fn info_dladdr1_works_without_section_headers_and_retains_symbol_pointers() {
    isolated(
        "info_dladdr1_works_without_section_headers_and_retains_symbol_pointers",
        false,
        |api| {
            let f = Fixture::new(false, false);
            let stripped = f.dir.join("no-sections.so");
            let mut bytes = std::fs::read(&f.library).unwrap();
            bytes[40..48].fill(0);
            bytes[58..64].fill(0);
            std::fs::write(&stripped, &bytes).unwrap();
            let object = ElfLoader::new(0).parse(&bytes).unwrap();
            assert!(!object.dynsym.is_empty());
            let h = api.open_path(&stripped, 0);
            let map = api.map(h);
            let address = api.symbol(h, c"info_data");
            let (offset, expected) = file_symbol(&stripped, "info_data");
            let (info, extra) = address_query(api.address, address, 1);
            assert_eq!(extra as usize, unsafe { (*map).base } + offset);
            let other = api.open_path(&f.library, 0);
            let reopen = api.open_path(&stripped, 0);
            assert_eq!(address_query(api.address, address, 1).1, extra);
            api.close(other);
            api.close(reopen);
            assert_eq!(
                unsafe { extra.cast::<ElfSymbol>().read_unaligned() },
                expected
            );
            assert_eq!(
                unsafe { CStr::from_ptr(info.dli_sname) }.to_bytes(),
                b"info_data"
            );
            api.close(h);
        },
    );
}
