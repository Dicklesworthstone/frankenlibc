//! Execute real mmap-backed DSOs through the public inspection ABI.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi::{
    dl_iterate_phdr, dladdr, dlclose, dlopen, dlsym, native_dso_handle_for_tests,
};

static GUARD: Mutex<()> = Mutex::new(());
const PROBE: &str = include_str!("../../../tests/integration/fixture_native_phdr.c");

fn directory() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("franken-phdr-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn compile(dir: &Path, name: &str, source: &str, dependency: Option<&Path>) -> PathBuf {
    let input = dir.join(format!("{name}.c"));
    let output = dir.join(format!("lib{name}.so"));
    std::fs::write(&input, source).unwrap();
    let mut command = Command::new("cc");
    command
        .args([
            "-shared",
            "-fPIC",
            "-nostdlib",
            "-fno-builtin",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wl,--build-id=none",
            "-Wl,--eh-frame-hdr",
            "-Wl,--no-as-needed",
            "-Wl,-rpath,$ORIGIN",
        ])
        .arg("-Xlinker")
        .arg("-soname")
        .arg("-Xlinker")
        .arg(output.file_name().unwrap())
        .arg("-o")
        .arg(&output)
        .arg(&input);
    if let Some(dependency) = dependency {
        command.arg(dependency);
    }
    let result = command
        .output()
        .expect("C compiler required; no silent skip");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    output
}

fn group(dir: &Path) -> (PathBuf, PathBuf) {
    let leaf = compile(dir, "phdr_leaf", "int phdr_leaf(void) { return 40; }", None);
    let root = compile(
        dir,
        "phdr_root",
        "extern int phdr_leaf(void); int phdr_answer(void) { return phdr_leaf() + 2; }",
        Some(&leaf),
    );
    (root, leaf)
}

fn open(path: &Path) -> *mut c_void {
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    let handle = unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW) };
    assert!(
        native_dso_handle_for_tests(handle),
        "not a native load: {path:?}"
    );
    handle
}

fn symbol(handle: *mut c_void, name: &CStr) -> *mut c_void {
    let address = unsafe { dlsym(handle, name.as_ptr()) };
    assert!(!address.is_null(), "missing {name:?}");
    address
}

fn call(address: usize) -> c_int {
    // SAFETY: all call sites retain the fixture's handle or an active snapshot.
    let function: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(address) };
    unsafe { function() }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Header {
    kind: u32,
    flags: u32,
    values: [u64; 6],
}

impl Header {
    fn from_abi(p: &libc::Elf64_Phdr) -> Self {
        Self {
            kind: p.p_type,
            flags: p.p_flags,
            values: [
                p.p_offset, p.p_vaddr, p.p_paddr, p.p_filesz, p.p_memsz, p.p_align,
            ],
        }
    }
}

fn file_headers(path: &Path) -> Vec<Header> {
    // Independent byte decoding: do not ask the implementation under test
    // to manufacture its own expected program-header values.
    let bytes = std::fs::read(path).unwrap();
    let u16_at = |i| u16::from_le_bytes(bytes[i..i + 2].try_into().unwrap()) as usize;
    let offset = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let stride = u16_at(54);
    assert_eq!(stride, 56);
    (0..u16_at(56))
        .map(|i| {
            let entry = &bytes[offset + i * stride..offset + (i + 1) * stride];
            Header {
                kind: u32::from_le_bytes(entry[..4].try_into().unwrap()),
                flags: u32::from_le_bytes(entry[4..8].try_into().unwrap()),
                values: std::array::from_fn(|j| {
                    u64::from_le_bytes(entry[8 + j * 8..16 + j * 8].try_into().unwrap())
                }),
            }
        })
        .collect()
}

#[derive(Clone, Debug)]
struct Record {
    name: Vec<u8>,
    base: usize,
    name_pointer: usize,
    header_pointer: usize,
    headers: Vec<Header>,
    adds: u64,
    subs: u64,
    module: usize,
    tls: usize,
}

unsafe extern "C-unwind" fn capture(
    info: *mut libc::dl_phdr_info,
    size: usize,
    data: *mut c_void,
) -> c_int {
    assert!(size >= std::mem::size_of::<libc::dl_phdr_info>());
    let info = unsafe { &*info };
    let records = unsafe { &mut *data.cast::<Vec<Record>>() };
    let name = unsafe { CStr::from_ptr(info.dlpi_name) }
        .to_bytes()
        .to_vec();
    let headers = unsafe { std::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize) }
        .iter()
        .map(Header::from_abi)
        .collect();
    records.push(Record {
        name,
        base: info.dlpi_addr as usize,
        name_pointer: info.dlpi_name as usize,
        header_pointer: info.dlpi_phdr as usize,
        headers,
        adds: info.dlpi_adds,
        subs: info.dlpi_subs,
        module: info.dlpi_tls_modid,
        tls: info.dlpi_tls_data as usize,
    });
    0
}

fn records() -> Vec<Record> {
    let mut result = Vec::new();
    assert_eq!(
        unsafe { dl_iterate_phdr(Some(capture), (&raw mut result).cast()) },
        0
    );
    result
}

fn at<'a>(records: &'a [Record], path: &Path) -> &'a Record {
    let found = records
        .iter()
        .filter(|r| r.name == path.as_os_str().as_bytes())
        .collect::<Vec<_>>();
    assert_eq!(found.len(), 1, "missing or duplicate {path:?}: {records:?}");
    found[0]
}

fn absent(path: &Path) {
    assert!(
        !records()
            .iter()
            .any(|r| r.name == path.as_os_str().as_bytes()),
        "leaked {path:?}"
    );
}

#[test]
fn native_phdr_metadata_survives_replacement_and_unload() {
    let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let dir = directory();
    let (root, leaf) = group(&dir);
    let expected = file_headers(&root);
    let before = records();
    let handle = open(&root);
    let address = symbol(handle, c"phdr_answer") as usize;
    let first = records();
    let initial = at(&first, &root);
    assert_eq!(initial.headers, expected);
    assert!(
        initial.headers.iter().any(|p| p.kind == 0x6474_e550),
        "missing unwind header"
    );
    assert!(initial.headers.iter().any(|p| p.kind == 1
        && p.flags & 1 != 0
        && address >= initial.base + p.values[1] as usize
        && address < initial.base + (p.values[1] + p.values[4]) as usize));
    let dependency = at(&first, &leaf);
    assert_eq!(
        (initial.adds, initial.subs),
        (dependency.adds, dependency.subs)
    );
    if let Some(before) = before.first() {
        assert_eq!(initial.adds, before.adds + 2);
        assert_eq!(initial.subs, before.subs);
    }
    // A missing-file lookup must not increment the published-object count.
    let missing = CString::new(dir.join("missing.so").as_os_str().as_bytes()).unwrap();
    assert!(unsafe { dlopen(missing.as_ptr(), libc::RTLD_NOW) }.is_null());
    // Rename instead of destroying fixtures. Replace the pathname with a
    // different ELF image; iteration must continue describing the mapped one.
    std::fs::rename(&root, dir.join("retained-original.so")).unwrap();
    compile(
        &dir,
        "phdr_root",
        "char replacement[65536]; int unrelated(void) { return 9; }",
        None,
    );
    std::fs::rename(&leaf, dir.join("retained-leaf.so")).unwrap();
    let second = records();
    let current = at(&second, &root);
    assert_eq!(current.headers, expected);
    assert_eq!(
        (current.name_pointer, current.header_pointer),
        (initial.name_pointer, initial.header_pointer)
    );
    assert_eq!((current.adds, current.subs), (initial.adds, initial.subs));
    assert_eq!(call(address), 42);
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { dladdr(address as *const c_void, (&raw mut info).cast()) },
        1
    );
    assert_eq!(info.dli_fbase as usize, current.base);
    assert_eq!(
        unsafe { CStr::from_ptr(info.dli_fname) }.to_bytes(),
        root.as_os_str().as_bytes()
    );
    assert_eq!(unsafe { dlclose(handle) }, 0);
    absent(&root);
    absent(&leaf);
    if let Some(after) = records().first() {
        assert_eq!(after.adds, initial.adds);
        assert_eq!(after.subs, initial.subs + 2);
    }
}

#[test]
fn native_phdr_tls_is_lazy_and_per_thread() {
    let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let dir = directory();
    let path = compile(&dir, "phdr_tls", "__thread int phdr_value = 7;", None);
    let handle = open(&path);
    let initial = at(&records(), &path).clone();
    assert_ne!(initial.module, 0);
    assert_eq!(initial.tls, 0);
    assert_eq!(at(&records(), &path).tls, 0, "inspection allocated TLS");
    let main = symbol(handle, c"phdr_value") as *mut c_int;
    assert_eq!(unsafe { *main }, 7);
    unsafe {
        *main = 31;
    }
    assert_eq!(at(&records(), &path).tls, main as usize);
    let thread_path = path.clone();
    let thread_handle = handle as usize;
    let worker = std::thread::spawn(move || {
        let before = at(&records(), &thread_path).clone();
        assert_eq!(before.module, initial.module);
        assert_eq!(before.tls, 0);
        let address = symbol(thread_handle as *mut c_void, c"phdr_value") as *mut c_int;
        assert_eq!(unsafe { *address }, 7);
        unsafe {
            *address = 19;
        }
        assert_eq!(at(&records(), &thread_path).tls, address as usize);
        address as usize
    })
    .join()
    .unwrap();
    assert_ne!(worker, main as usize);
    assert_eq!(unsafe { *main }, 31);
    assert_eq!(unsafe { dlclose(handle) }, 0);
    absent(&path);
}

struct Reentry {
    root: PathBuf,
    leaf: PathBuf,
    new_path: PathBuf,
    handle: usize,
    address: usize,
    action: u8,
    visited: usize,
    new_handle: usize,
}

unsafe extern "C-unwind" fn reenter(
    info: *mut libc::dl_phdr_info,
    _: usize,
    data: *mut c_void,
) -> c_int {
    let info = unsafe { &*info };
    let state = unsafe { &mut *data.cast::<Reentry>() };
    let name = unsafe { CStr::from_ptr(info.dlpi_name) }.to_bytes();
    assert_ne!(
        name,
        state.new_path.as_os_str().as_bytes(),
        "new load entered an old snapshot"
    );
    if name == state.leaf.as_os_str().as_bytes() {
        state.visited += 1;
    }
    if name != state.root.as_os_str().as_bytes() {
        return 0;
    }
    state.visited += 1;
    if state.action == 0 {
        let handle = state.handle;
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            send.send(unsafe { dlclose(handle as *mut c_void) })
                .unwrap();
        });
        assert_eq!(
            receive
                .recv_timeout(Duration::from_secs(10))
                .expect("iterator held a loader lock across callback"),
            0
        );
        worker.join().unwrap();
    } else {
        assert_eq!(unsafe { dlclose(state.handle as *mut c_void) }, 0);
    }
    // The last public reference is gone, but BOTH snapshot mappings remain
    // callable and visible through a recursive public enumeration.
    assert_eq!(call(state.address), 42);
    let nested = records();
    at(&nested, &state.root);
    at(&nested, &state.leaf);
    assert!(native_dso_handle_for_tests(state.handle as *mut c_void));
    state.new_handle = open(&state.new_path) as usize;
    at(&records(), &state.new_path);
    if state.action == 2 {
        panic!("intentional native callback unwind");
    }
    if state.action == 1 { 37 } else { 0 }
}

#[test]
fn native_phdr_snapshot_reentry_early_stop_and_unwind() {
    let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(unsafe { dl_iterate_phdr(None, std::ptr::null_mut()) }, 0);
    for action in 0..3 {
        let dir = directory();
        let (root, leaf) = group(&dir);
        let new_path = compile(&dir, "phdr_later", "int later(void) { return 8; }", None);
        let handle = open(&root);
        let mut state = Reentry {
            root,
            leaf,
            new_path,
            handle: handle as usize,
            address: symbol(handle, c"phdr_answer") as usize,
            action,
            visited: 0,
            new_handle: 0,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            dl_iterate_phdr(Some(reenter), (&raw mut state).cast())
        }));
        if action == 2 {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), if action == 1 { 37 } else { 0 });
        }
        assert_eq!(state.visited, if action == 0 { 2 } else { 1 });
        assert!(!native_dso_handle_for_tests(handle), "snapshot pin leaked");
        absent(&state.root);
        absent(&state.leaf);
        assert_ne!(state.new_handle, 0);
        assert_eq!(unsafe { dlclose(state.new_handle as *mut c_void) }, 0);
        absent(&state.new_path);
    }
}

#[test]
fn native_phdr_runtime_calls_from_native_code() {
    let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let dir = directory();
    let path = compile(&dir, "phdr_runtime", PROBE, None);
    let handle = open(&path);
    assert_eq!(
        call(symbol(handle, c"native_phdr_runtime_probe") as usize),
        42
    );
    // Prefix short-circuit must never proceed to the native entry, and must
    // release the unvisited snapshot's pins before a subsequent final close.
    unsafe extern "C-unwind" fn stop(
        _: *mut libc::dl_phdr_info,
        _: usize,
        data: *mut c_void,
    ) -> c_int {
        unsafe {
            *data.cast::<usize>() += 1;
        }
        -29
    }
    let mut calls = 0usize;
    assert_eq!(
        unsafe { dl_iterate_phdr(Some(stop), (&raw mut calls).cast()) },
        -29
    );
    assert_eq!(calls, 1);
    assert_eq!(unsafe { dlclose(handle) }, 0);
    absent(&path);
}

#[cfg(feature = "standalone")]
mod standalone_prefix {
    use super::*;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::FileExt;

    // These host-created fixtures populate the process's initial-map prefix,
    // not the already-correct owned registry. Inspection always calls the
    // standalone implementation imported by the enclosing module.
    struct ForeignImage(*mut c_void);

    impl ForeignImage {
        fn open(path: &Path, namespace: bool) -> Self {
            let name = CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: live terminated pathname; the fixture has no dependencies.
            let handle = unsafe {
                if namespace {
                    libc::dlmopen(libc::LM_ID_NEWLM, name.as_ptr(), libc::RTLD_NOW)
                } else {
                    libc::dlopen(name.as_ptr(), libc::RTLD_NOW)
                }
            };
            assert!(!handle.is_null(), "host fixture load failed: {path:?}");
            assert!(!native_dso_handle_for_tests(handle));
            Self(handle)
        }

        fn address(&self) -> usize {
            // SAFETY: this retained host handle exports the fixed fixture ABI.
            let address = unsafe { libc::dlsym(self.0, c"prefix_answer".as_ptr()) };
            assert!(!address.is_null());
            address as usize
        }
    }

    impl Drop for ForeignImage {
        fn drop(&mut self) {
            // SAFETY: this object owns the single matching host load reference.
            assert_eq!(unsafe { libc::dlclose(self.0) }, 0);
        }
    }

    fn fixture(dir: &Path, name: &str) -> PathBuf {
        compile(dir, name, "int prefix_answer(void) { return 42; }", None)
    }

    fn image_for(records: &[Record], address: usize) -> &Record {
        let matching = records
            .iter()
            .filter(|record| {
                record.headers.iter().any(|header| {
                    header.kind == libc::PT_LOAD
                        && record
                            .base
                            .checked_add(header.values[1] as usize)
                            .zip(
                                record
                                    .base
                                    .checked_add((header.values[1] + header.values[4]) as usize),
                            )
                            .is_some_and(|(start, end)| start <= address && address < end)
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            1,
            "missing or duplicate image for {address:#x}"
        );
        matching[0]
    }

    #[test]
    fn standalone_prefix_reports_auxv_main_and_vdso() {
        let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let all = records();
        let main = all.first().expect("missing executable");
        assert!(
            main.name.is_empty(),
            "the executable must be first with an empty name"
        );
        assert_eq!(
            main.headers,
            file_headers(&std::env::current_exe().unwrap()),
        );
        assert_eq!(
            image_for(
                &all,
                standalone_prefix_reports_auxv_main_and_vdso as *const () as usize
            )
            .base,
            main.base,
        );
        // SAFETY: getauxval has no pointer arguments. This Linux fixture
        // requires the real kernel vDSO rather than silently skipping it.
        let vdso = unsafe { libc::getauxval(libc::AT_SYSINFO_EHDR) } as usize;
        assert_ne!(vdso, 0, "kernel vDSO required for this regression");
        let object = image_for(&all, vdso);
        assert_eq!(object.name, b"linux-vdso.so.1");
        assert_eq!(object.base, vdso);
        assert!(object.headers.iter().any(|p| p.kind == libc::PT_DYNAMIC));
    }

    #[test]
    fn standalone_prefix_uses_live_headers_after_backing_file_changes() {
        let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = directory();
        let path = fixture(&dir, "prefix_live");
        let expected = file_headers(&path);
        let image = ForeignImage::open(&path, false);
        let address = image.address();
        let initial = image_for(&records(), address).clone();
        assert_eq!(initial.headers, expected);

        // Make only the header page private before changing its on-disk
        // counterpart. An identical volatile write triggers COW without
        // changing any mapped metadata or executable instruction.
        let header = initial
            .headers
            .iter()
            .find(|p| p.kind == libc::PT_LOAD && p.values[0] == 0)
            .unwrap();
        let header_address = initial.base + header.values[1] as usize;
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert!(page.is_power_of_two());
        assert!(header_address.is_multiple_of(page));
        let mut protection = 0;
        if header.flags & libc::PF_R != 0 {
            protection |= libc::PROT_READ;
        }
        if header.flags & libc::PF_W != 0 {
            protection |= libc::PROT_WRITE;
        }
        if header.flags & libc::PF_X != 0 {
            protection |= libc::PROT_EXEC;
        }
        // SAFETY: this page belongs to the retained fixture, and the byte is
        // ELF identification padding. Restore its original protection before
        // doing any inspection or entering fixture code.
        unsafe {
            assert_eq!(
                libc::mprotect(
                    header_address as *mut c_void,
                    page,
                    protection | libc::PROT_WRITE,
                ),
                0
            );
            let byte = (header_address + 15) as *mut u8;
            byte.write_volatile(byte.read_volatile());
            assert_eq!(
                libc::mprotect(header_address as *mut c_void, page, protection),
                0
            );
        }
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        // Zero e_phnum in the file only. No file is unlinked or truncated.
        file.write_all_at(&[0, 0], 56).unwrap();
        let current = image_for(&records(), address).clone();
        assert_eq!(current.headers, expected);
        assert_eq!(current.base, initial.base);
        assert_eq!(call(address), 42);
        file.write_all_at(&(expected.len() as u16).to_le_bytes(), 56)
            .unwrap();

        // Preserve the original file while replacing its former pathname.
        std::fs::rename(&path, dir.join("retained-prefix-live.so")).unwrap();
        compile(
            &dir,
            "prefix_live",
            "char replacement[65536]; int unrelated(void) { return 9; }",
            None,
        );
        assert_ne!(file_headers(&path), expected);
        assert_eq!(image_for(&records(), address).headers, expected);
        assert_eq!(call(address), 42);
    }

    #[test]
    fn standalone_prefix_enumerates_deleted_memfd_images() {
        let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = directory();
        let path = fixture(&dir, "prefix_memfd");
        let expected = file_headers(&path);
        // SAFETY: the name is terminated and the successful descriptor is
        // immediately transferred to File ownership. A memfd has no directory
        // entry to delete and appears as a deleted mapping from creation.
        let fd = unsafe { libc::memfd_create(c"franken-phdr-prefix".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(&std::fs::read(&path).unwrap()).unwrap();
        let image = ForeignImage::open(
            Path::new(&format!("/proc/self/fd/{}", file.as_raw_fd())),
            false,
        );
        let address = image.address();
        drop(file);
        assert!(
            std::fs::read_to_string("/proc/self/maps")
                .unwrap()
                .lines()
                .any(|line| line.contains("franken-phdr-prefix") && line.contains(" (deleted)"))
        );
        let current = image_for(&records(), address).clone();
        assert_eq!(current.headers, expected);
        assert!(
            current.headers.iter().any(|p| p.kind == 0x6474_e550),
            "the deleted image's unwind metadata must remain discoverable"
        );
        assert_eq!(call(address), 42);
    }

    #[test]
    fn standalone_prefix_keeps_distinct_instances_of_the_same_file() {
        let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = directory();
        let path = fixture(&dir, "prefix_instances");
        let expected = file_headers(&path);
        let first = ForeignImage::open(&path, false);
        let second = ForeignImage::open(&path, true);
        let all = records();
        let one = image_for(&all, first.address());
        let two = image_for(&all, second.address());
        assert_ne!(one.base, two.base);
        assert_eq!(one.headers, expected);
        assert_eq!(two.headers, expected);
        assert_eq!(call(first.address()), 42);
        assert_eq!(call(second.address()), 42);
    }

    #[test]
    fn standalone_prefix_rejects_a_plain_elf_file_mapping() {
        let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = directory();
        let path = fixture(&dir, "prefix_data_only");
        let file = std::fs::File::open(&path).unwrap();
        let length = file.metadata().unwrap().len() as usize;
        // SAFETY: valid retained descriptor, no fixed address; the mapping is
        // ordinary read-only file data, not an executable PT_LOAD layout.
        let memory = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(memory, libc::MAP_FAILED);
        let all = records();
        // Release VM storage only; the fixture files remain available.
        assert_eq!(unsafe { libc::munmap(memory, length) }, 0);
        assert!(
            !all.iter()
                .any(|record| record.name == path.as_os_str().as_bytes()),
            "an mmap of ELF file bytes is not a loaded shared object"
        );
    }

    #[test]
    fn standalone_prefix_finds_phdrs_in_a_separate_load_segment() {
        let _guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        // This image deliberately has no contiguous file-to-virtual mapping:
        // file page 2 (the PHDR table) lives at virtual page 5.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert!(page.is_power_of_two());
        let mut bytes = vec![0u8; 4 * page];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&(2 * page as u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&3u16.to_le_bytes());
        let expected = [
            (0, 0, libc::PF_R),
            (2, 5, libc::PF_R),
            (3, 6, libc::PF_R | libc::PF_X),
        ]
        .into_iter()
        .map(|(offset, address, flags)| Header {
            kind: libc::PT_LOAD,
            flags,
            values: [
                offset * page as u64,
                address * page as u64,
                0,
                page as u64,
                page as u64,
                page as u64,
            ],
        })
        .collect::<Vec<_>>();
        for (index, header) in expected.iter().enumerate() {
            let record = &mut bytes[2 * page + index * 56..2 * page + (index + 1) * 56];
            record[..4].copy_from_slice(&header.kind.to_le_bytes());
            record[4..8].copy_from_slice(&header.flags.to_le_bytes());
            for (field, value) in header.values.iter().enumerate() {
                record[8 + field * 8..16 + field * 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        // SAFETY: valid terminated name, owned descriptor, no filesystem entry.
        let fd = unsafe { libc::memfd_create(c"franken-split-phdr".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(&bytes).unwrap();
        struct Mapping(*mut c_void, usize);
        impl Drop for Mapping {
            fn drop(&mut self) {
                // SAFETY: the entire reserved range remains privately owned.
                assert_eq!(unsafe { libc::munmap(self.0, self.1) }, 0);
            }
        }
        // SAFETY: reserve a fresh private range; fixed mappings below replace
        // only pages inside that reservation, never another object's memory.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                8 * page,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED);
        let mapping = Mapping(base, 8 * page);
        for header in &expected {
            let address = (base as usize + header.values[1] as usize) as *mut c_void;
            let protection = libc::PROT_READ
                | if header.flags & libc::PF_X != 0 {
                    libc::PROT_EXEC
                } else {
                    0
                };
            // SAFETY: page-aligned file offset and address lie inside our
            // reserved mapping. The file remains open throughout all mappings.
            assert_eq!(
                unsafe {
                    libc::mmap(
                        address,
                        page,
                        protection,
                        libc::MAP_PRIVATE | libc::MAP_FIXED,
                        file.as_raw_fd(),
                        header.values[0] as libc::off_t,
                    )
                },
                address
            );
        }
        let all = records();
        let image = image_for(&all, base as usize + 6 * page);
        assert_eq!(image.base, base as usize);
        assert_eq!(image.headers, expected);
        drop(mapping);
    }
}
