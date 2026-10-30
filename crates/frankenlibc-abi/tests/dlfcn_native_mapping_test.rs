#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::dlfcn_abi as dl;
use frankenlibc_core::elf::{ElfLoader, LoadedObject, ProgramType};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
#[path = "../src/dlfcn_map_layout.rs"]
mod map_layout;

const SOURCE: &str = include_str!("fixtures/native_mapping.c");
type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
type Sym = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;

#[derive(Clone, Copy)]
struct Api { open: Open, close: Close, sym: Sym, native: bool }
impl Api {
    fn new(native: bool) -> Self {
        if native {
            Self { open: dl::dlopen, close: dl::dlclose, sym: dl::dlsym, native }
        } else { unsafe { Self {
            open: dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ()),
            close: dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ()),
            sym: dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ()), native,
        } } }
    }
    fn try_open(self, path: &Path, flags: c_int) -> *mut c_void {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(path.as_ptr(), flags | libc::RTLD_NOW) };
        if self.native && !handle.is_null() {
            assert!(dl::native_dso_handle_for_tests(handle), "host fallback cannot pass this test");
        }
        handle
    }
    fn open(self, path: &Path) -> *mut c_void {
        let handle = self.try_open(path, 0);
        assert!(!handle.is_null(), "open failed: {path:?}");
        handle
    }
    fn close(self, handle: *mut c_void) {
        assert_eq!(unsafe { (self.close)(handle) }, 0);
    }
    fn symbol(self, handle: *mut c_void, name: &CStr) -> usize {
        let pointer = unsafe { (self.sym)(handle, name.as_ptr()) };
        assert!(!pointer.is_null(), "symbol {name:?}");
        pointer as usize
    }
}

fn isolated(name: &str, scenario: fn(Api)) {
    if let Ok(mode) = std::env::var("FRANKENLIBC_MAPPING_CHILD") {
        assert!(mode == "host" || mode == "native");
        scenario(Api::new(mode == "native"));
        return;
    }
    for mode in ["host", "native"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FRANKENLIBC_MAPPING_CHILD", mode).spawn().unwrap();
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "{name}: {mode}: {status}");
                break;
            }
            if start.elapsed() > Duration::from_secs(40) {
                child.kill().unwrap(); child.wait().unwrap();
                panic!("{name}: {mode}: timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

struct Fixture { dir: PathBuf, library: PathBuf }
impl Fixture {
    fn new(alignment: usize, max_page: bool) -> Self {
        let dir = std::env::temp_dir().join(format!("frankenlibc-mapping-{}-{}",
            std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&dir).unwrap();
        let library = dir.join("libmapping.so");
        let source = dir.join("mapping.c");
        std::fs::write(&source, SOURCE).unwrap();
        let mut command = Command::new("gcc");
        command.args(["-shared", "-fPIC", "-nostdlib", "-O2", "-fno-builtin",
            "-Wl,--hash-style=both,-z,relro,-z,now", "-Wl,-soname,libmapping.so"])
            .arg(format!("-DALIGNMENT={alignment}"))
            .arg(&source).arg("-o").arg(&library);
        if max_page { command.arg("-Wl,-z,max-page-size=0x200000"); }
        compile(&mut command);
        let object = parse(&library);
        assert!(object.needed_libraries.is_empty());
        assert!(object.undefined_symbols().all(|(_, symbol)| symbol.is_weak()));
        assert_eq!(object.program_headers.iter().filter(|header| header.is_load())
            .map(|header| header.p_align).max().unwrap(),
            if max_page { 0x20_0000 } else { alignment as u64 });
        Self { dir, library }
    }
    fn consumer(&self, missing: bool) -> PathBuf {
        let source = self.dir.join("consumer.c");
        let library = self.dir.join("libconsumer.so");
        std::fs::write(&source, if missing {
            "extern int mapping_probe(void); extern int mapping_absent_strong(void);\nint consumer(void) { return mapping_probe() + mapping_absent_strong(); }\n"
        } else {
            "extern int mapping_probe(void); int consumer(void) { return mapping_probe(); }\n"
        }).unwrap();
        compile(Command::new("gcc").args(["-shared", "-fPIC", "-nostdlib", "-O2"])
            .arg(&source).arg("-o").arg(&library)
            .arg(format!("-L{}", self.dir.display()))
            .args(["-Wl,--no-as-needed", "-lmapping", "-Wl,-rpath,$ORIGIN"]));
        assert_eq!(parse(&library).needed_libraries, vec!["libmapping.so".to_owned()]);
        library
    }
}

fn compile(command: &mut Command) {
    let output = command.output().expect("gcc is required, not a skipped test");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}
fn parse(path: &Path) -> LoadedObject {
    ElfLoader::new(0).parse(&std::fs::read(path).unwrap()).unwrap()
}
fn permissions(address: usize) -> String {
    for line in std::fs::read_to_string("/proc/self/maps").unwrap().lines() {
        let mut fields = line.split_whitespace();
        let (start, end) = fields.next().unwrap().split_once('-').unwrap();
        let start = usize::from_str_radix(start, 16).unwrap();
        let end = usize::from_str_radix(end, 16).unwrap();
        if start <= address && address < end { return fields.next().unwrap().to_owned(); }
    }
    panic!("address is not mapped: {address:#x}");
}
fn inspect(api: Api, handle: *mut c_void, object: &LoadedObject, alignment: usize, relro: bool) {
    let data = api.symbol(handle, c"mapping_data");
    let bss = api.symbol(handle, c"mapping_bss");
    let locked = api.symbol(handle, c"mapping_locked");
    let probe = api.symbol(handle, c"mapping_probe");
    let symbol = object.dynsym.iter().find(|symbol| symbol.is_defined()
        && object.symbol_name(symbol) == Some("mapping_data")).unwrap();
    let base = data.checked_sub(symbol.st_value as usize).unwrap();
    for header in object.program_headers.iter().filter(|header| header.is_load()) {
        if header.p_align > 1 {
            assert_eq!(base % header.p_align as usize, 0, "load bias violates PT_LOAD p_align");
        }
    }
    assert_eq!(data % alignment, 0); assert_eq!(bss % alignment, 0);
    assert!(permissions(data).starts_with("rw-"));
    assert!(permissions(bss).starts_with("rw-"));
    assert!(permissions(probe).starts_with("r-x"));
    assert_eq!(!permissions(locked).contains('w'), relro);
    let call: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(probe) };
    // Constructor, file bytes, zero-filled BSS, data relocation, writable tail.
    assert_eq!(unsafe { call() }, 1);
    if api.native {
        let mut ranges = object.program_headers.iter().filter(|h| h.is_load() && h.p_memsz != 0)
            .map(|h| (h.p_vaddr as usize & !4095,
                (h.p_vaddr as usize + h.p_memsz as usize + 4095) & !4095))
            .collect::<Vec<_>>();
        ranges.sort_unstable();
        for pair in ranges.windows(2) {
            if pair[0].1 < pair[1].0 {
                assert!(permissions(base + pair[0].1).starts_with("---"), "image hole accessible");
            }
        }
    }
}
fn aligned(api: Api, alignment: usize, max_page: bool, stripped: bool) {
    let fixture = Fixture::new(alignment, max_page);
    if stripped {
        let mut bytes = std::fs::read(&fixture.library).unwrap();
        bytes[40..48].fill(0); // e_shoff
        bytes[58..64].fill(0); // e_shentsize/e_shnum/e_shstrndx
        std::fs::write(&fixture.library, bytes).unwrap();
    }
    let object = parse(&fixture.library);
    if stripped { assert!(object.section_headers.is_empty()); }
    let mut handles = Vec::new();
    for i in 0..8 {
        let copy = fixture.dir.join(format!("copy-{i}.so"));
        std::fs::copy(&fixture.library, &copy).unwrap();
        let handle = api.open(&copy);
        inspect(api, handle, &object, alignment, true);
        handles.push(handle);
    }
    // Every mapping remains live while subsequent ones are placed.
    for handle in handles.into_iter().rev() { api.close(handle); }
    let reopened = api.open(&fixture.library);
    inspect(api, reopened, &object, alignment, true);
    api.close(reopened);
}

#[test]
fn mapping_preserves_baseline_page_layout() {
    isolated("mapping_preserves_baseline_page_layout", |api| aligned(api, 4096, false, false));
}
#[test]
fn mapping_honors_64k_data_and_bss_alignment() {
    isolated("mapping_honors_64k_data_and_bss_alignment", |api| aligned(api, 65536, false, false));
}
#[test]
fn mapping_honors_2m_data_and_bss_alignment() {
    isolated("mapping_honors_2m_data_and_bss_alignment", |api| aligned(api, 2097152, false, false));
}
#[test]
fn mapping_honors_linker_max_page_size() {
    isolated("mapping_honors_linker_max_page_size", |api| aligned(api, 4096, true, false));
}
#[test]
fn mapping_alignment_does_not_require_section_headers() {
    isolated("mapping_alignment_does_not_require_section_headers", |api| aligned(api, 65536, false, true));
}
#[test]
fn mapping_aligns_transitive_dependencies() {
    isolated("mapping_aligns_transitive_dependencies", |api| {
        let fixture = Fixture::new(2097152, false);
        let consumer = fixture.consumer(false);
        let handle = api.open(&consumer);
        inspect(api, handle, &parse(&fixture.library), 2097152, true);
        let call: unsafe extern "C" fn() -> c_int = unsafe {
            std::mem::transmute(api.symbol(handle, c"consumer"))
        };
        assert_eq!(unsafe { call() }, 1);
        api.close(handle);
        assert!(api.try_open(&fixture.library, libc::RTLD_NOLOAD).is_null());
    });
}
#[test]
fn mapping_failed_relocations_do_not_publish_aligned_dependencies() {
    isolated("mapping_failed_relocations_do_not_publish_aligned_dependencies", |api| {
        let fixture = Fixture::new(65536, false);
        let consumer = fixture.consumer(true);
        assert!(api.try_open(&consumer, 0).is_null());
        assert!(api.try_open(&fixture.library, libc::RTLD_NOLOAD).is_null());
        let handle = api.open(&fixture.library);
        inspect(api, handle, &parse(&fixture.library), 65536, true);
        api.close(handle);
    });
}

fn change_relro(path: &Path, partial_tail: bool) {
    let mut bytes = std::fs::read(path).unwrap();
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let size = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    assert_eq!(size, 56);
    let offset = (0..count).map(|i| phoff + i * size).find(|&offset| {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) == 0x6474_e552
    }).unwrap();
    let start = u64::from_le_bytes(bytes[offset + 16..offset + 24].try_into().unwrap());
    let len = u64::from_le_bytes(bytes[offset + 40..offset + 48].try_into().unwrap());
    assert_eq!((start + len) % 4096, 0);
    let length = if partial_tail { len + 32 } else { 16 };
    bytes[offset + 32..offset + 40].copy_from_slice(&length.to_le_bytes());
    bytes[offset + 40..offset + 48].copy_from_slice(&length.to_le_bytes());
    std::fs::write(path, bytes).unwrap();
    let object = parse(path);
    let header = object.program_headers.iter().find(|h| h.p_type == ProgramType::GnuRelro).unwrap();
    assert_eq!(header.p_memsz, length);
    assert_ne!((header.p_vaddr + length) % 4096, 0);
    assert!(object.program_headers.iter().any(|h| h.is_load()
        && h.p_vaddr <= start && start + length <= h.p_vaddr + h.p_memsz));
}
#[test]
fn mapping_relro_partial_tail_keeps_adjacent_data_writable() {
    isolated("mapping_relro_partial_tail_keeps_adjacent_data_writable", |api| {
        let fixture = Fixture::new(4096, false);
        change_relro(&fixture.library, true);
        let handle = api.open(&fixture.library);
        inspect(api, handle, &parse(&fixture.library), 4096, true);
        api.close(handle);
    });
}
#[test]
fn mapping_relro_subpage_interval_does_not_protect_the_whole_page() {
    isolated("mapping_relro_subpage_interval_does_not_protect_the_whole_page", |api| {
        let fixture = Fixture::new(4096, false);
        change_relro(&fixture.library, false);
        let handle = api.open(&fixture.library);
        inspect(api, handle, &parse(&fixture.library), 4096, false);
        api.close(handle);
    });
}

#[test]
fn reservation_partitions_every_page_offset_without_overlapping_live_memory() {
    for alignment in [4096usize, 8192, 65536, 2097152] {
        for length in [4096, 12288, alignment + 4096] {
            let layout = map_layout::Reservation::new(length,
                [(0, 0, 4096), (alignment as u64, 0, alignment as u64)]).unwrap();
            for offset in (0..alignment).step_by(4096) {
                let base = 0x1_0000_0000usize + offset;
                let placement = layout.place(base).unwrap();
                assert_eq!(placement.base % alignment, 0);
                assert_eq!(placement.prefix + length + placement.suffix, layout.reserve_len);
                assert_eq!(base + placement.prefix, placement.base);
                assert_eq!(placement.prefix % 4096, 0);
                assert_eq!(placement.suffix % 4096, 0);
                assert!(placement.prefix < alignment);
            }
        }
    }
}
#[test]
fn reservation_rejects_invalid_sizes_congruence_alignment_and_overflow() {
    use map_layout::Reservation as R;
    for alignment in [0u64, 1, 4096, 65536] {
        assert!(R::new(4096, [(0, 0, alignment)]).is_some());
    }
    assert!(R::new(4096, []).is_none());
    for size in [0usize, 1, 4095, 4097, usize::MAX] {
        assert!(R::new(size, [(0, 0, 4096)]).is_none());
    }
    for alignment in [3u64, 4097, 12288, 1u64 << 63, u64::MAX] {
        assert!(R::new(4096, [(0, 0, alignment)]).is_none());
    }
    assert!(R::new(4096, [(4096, 0, 65536)]).is_none());
    assert!(R::new(4096, [(1, 0, 0)]).is_none());
    let layout = R::new(4096, [(0, 0, 65536)]).unwrap();
    assert!(layout.place(1).is_none());
    assert!(layout.place(usize::MAX & !4095).is_none());
}
#[test]
fn relro_rounding_excludes_partial_tail_and_validates_before_rounding() {
    use map_layout::relro_pages;
    assert_eq!(relro_pages(&(0x1234..0x2345), 0x3000), Some(0x1000..0x2000));
    assert_eq!(relro_pages(&(0x1234..0x2000), 0x3000), Some(0x1000..0x2000));
    assert_eq!(relro_pages(&(0x1234..0x1240), 0x3000), Some(0x1000..0x1000));
    assert_eq!(relro_pages(&(0x1234..0x1234), 0x3000), Some(0x1000..0x1000));
    assert!(relro_pages(&(0x1000..0x3001), 0x3000).is_none());
    // This is a malformed address interval, not a reverse iteration request.
    let reversed = std::ops::Range {
        start: 0x2000,
        end: 0x1000,
    };
    assert!(relro_pages(&reversed, 0x3000).is_none());
}
