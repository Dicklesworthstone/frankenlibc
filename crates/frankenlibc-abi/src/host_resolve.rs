//! Raw host symbol resolution — bypasses ALL dynamic linker interposition.
//!
//! Resolves symbols in the host glibc by parsing the in-memory ELF image
//! using only raw syscalls and pointer math. Zero libc calls, zero recursion.
#![allow(dead_code)]

use std::ffi::CStr;
use std::ffi::{c_char, c_int, c_void};
use std::mem::MaybeUninit;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

static HOST_PTHREAD_CREATE: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_JOIN: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_DETACH: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_EXIT: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_CANCEL: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_SETCANCELSTATE: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_SETCANCELTYPE: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_TESTCANCEL: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_KILL: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_GETCPUCLOCKID: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_GETAFFINITY_NP: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_SETAFFINITY_NP: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_GETTID_NP: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_SETNAME_NP: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_GETNAME_NP: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_SIGQUEUE: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_SELF: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_EQUAL: AtomicUsize = AtomicUsize::new(0);
static HOST_MALLOC: AtomicUsize = AtomicUsize::new(0);
static HOST_CALLOC: AtomicUsize = AtomicUsize::new(0);
static HOST_REALLOC: AtomicUsize = AtomicUsize::new(0);
static HOST_FREE: AtomicUsize = AtomicUsize::new(0);
static HOST_ERRNO_LOCATION: AtomicUsize = AtomicUsize::new(0);
static HOST_DLVSYM: AtomicUsize = AtomicUsize::new(0);
static HOST_DL_ITERATE_PHDR: AtomicUsize = AtomicUsize::new(0);
static HOST_DLADDR: AtomicUsize = AtomicUsize::new(0);
static RESOLVED: AtomicUsize = AtomicUsize::new(0);
static HOST_IMAGE: OnceLock<LoadedGlibcImage> = OnceLock::new();

#[inline]
pub(crate) unsafe fn host_dlvsym_next_raw(
    symbol: *const c_char,
    version: *const c_char,
) -> *mut c_void {
    // Use the ELF-resolved host dlvsym to avoid calling our interposed dlvsym,
    // which during bootstrap passthrough resolves from our export table instead
    // of delegating to the real host dynamic linker.
    let addr = HOST_DLVSYM.load(Ordering::Acquire);
    if addr != 0 {
        type DlvsymFn =
            unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut c_void;
        let host_dlvsym: DlvsymFn = unsafe { core::mem::transmute(addr) };
        return unsafe { host_dlvsym(libc::RTLD_NEXT, symbol, version) };
    }
    // Fallback: try libc::dlvsym (may recurse into our interposed dlvsym)
    unsafe { libc::dlvsym(libc::RTLD_NEXT, symbol, version) }
}

unsafe fn raw_read(fd: i32, buf: *mut u8, count: usize) -> isize {
    unsafe { libc::syscall(libc::SYS_read, fd, buf, count) as isize }
}
unsafe fn raw_open(path: *const u8) -> i32 {
    unsafe { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, path, libc::O_RDONLY, 0) as i32 }
}
unsafe fn raw_close(fd: i32) {
    unsafe { libc::syscall(libc::SYS_close, fd) };
}
unsafe fn raw_fstat(fd: i32, stat: *mut libc::stat) -> i32 {
    unsafe { libc::syscall(libc::SYS_fstat, fd, stat) as i32 }
}

#[repr(C)]
struct DlIterateTarget {
    base: usize,
    path: [u8; 512],
}

unsafe extern "C" fn find_glibc_base_cb(
    info: *mut libc::dl_phdr_info,
    _size: usize,
    data: *mut c_void,
) -> libc::c_int {
    if info.is_null() || data.is_null() {
        return 0;
    }
    // SAFETY: callback arguments come from libc::dl_iterate_phdr for the life of the call.
    let info = unsafe { &*info };
    if info.dlpi_name.is_null() {
        return 0;
    }
    // SAFETY: dlpi_name is a valid NUL-terminated C string for this callback invocation.
    let Ok(name) = unsafe { CStr::from_ptr(info.dlpi_name) }.to_str() else {
        return 0;
    };
    if !name.contains("libc.so") {
        return 0;
    }
    // SAFETY: data points to our stack-owned DlIterateTarget for the duration of dl_iterate_phdr.
    let target = unsafe { &mut *(data as *mut DlIterateTarget) };
    target.base = info.dlpi_addr as usize;
    let bytes = name.as_bytes();
    let len = bytes.len().min(target.path.len().saturating_sub(1));
    target.path[..len].copy_from_slice(&bytes[..len]);
    target.path[len] = 0;
    1
}

fn find_glibc_image_via_phdr() -> Option<(usize, [u8; 512])> {
    let mut target = DlIterateTarget {
        base: 0,
        path: [0; 512],
    };
    let host_dl_iterate = host_dl_iterate_phdr_cached()?;
    type DlIteratePhdrFn = unsafe extern "C" fn(
        Option<unsafe extern "C" fn(*mut libc::dl_phdr_info, usize, *mut c_void) -> libc::c_int>,
        *mut c_void,
    ) -> libc::c_int;
    let host_dl_iterate: DlIteratePhdrFn = unsafe { core::mem::transmute(host_dl_iterate) };
    // SAFETY: callback and out-pointer remain valid for the synchronous iteration.
    unsafe {
        host_dl_iterate(
            Some(find_glibc_base_cb),
            (&mut target as *mut DlIterateTarget).cast(),
        );
    }
    if target.base == 0 || target.path[0] == 0 {
        return None;
    }
    Some((target.base, target.path))
}

fn find_glibc_image_via_maps() -> Option<(usize, [u8; 512])> {
    let fd = unsafe { raw_open(c"/proc/self/maps".as_ptr().cast()) };
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 262144];
    let mut total = 0usize;
    loop {
        let n = unsafe { raw_read(fd, buf.as_mut_ptr().add(total), buf.len() - total) };
        if n <= 0 {
            break;
        }
        total += n as usize;
        if total >= buf.len() {
            break;
        }
    }
    unsafe { raw_close(fd) };
    let text = core::str::from_utf8(&buf[..total]).ok()?;
    for line in text.lines() {
        if !line.contains("libc.so") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        if parts[1].starts_with("r--p") && parts[2] == "00000000" {
            let dash = parts[0].find('-')?;
            let base = usize::from_str_radix(&parts[0][..dash], 16).ok()?;
            let mut path = [0u8; 512];
            let bytes = parts[5].as_bytes();
            let len = bytes.len().min(path.len().saturating_sub(1));
            path[..len].copy_from_slice(&bytes[..len]);
            path[len] = 0;
            return Some((base, path));
        }
    }
    None
}

fn loaded_glibc_image() -> Option<(usize, [u8; 512])> {
    // Prefer the raw `/proc/self/maps` scan during bootstrap. Calling
    // `dl_iterate_phdr` before we have already cached the host implementation
    // can recurse back through our own interposed loader ABI.
    find_glibc_image_via_maps().or_else(find_glibc_image_via_phdr)
}

struct LoadedGlibcImage {
    base: usize,
    mapped: usize,
    len: usize,
}

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const SHT_DYNSYM: u32 = 11;

#[repr(C)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
struct Elf64Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

#[repr(C)]
struct Elf64Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

fn symbol_name_matches(strtab: &[u8], name_offset: u32, symbol: &[u8]) -> bool {
    let start = name_offset as usize;
    if start >= strtab.len() {
        return false;
    }
    let rest = &strtab[start..];
    let Some(end) = rest.iter().position(|byte| *byte == 0) else {
        return false;
    };
    &rest[..end] == symbol
}

fn resolve_symbol_from_data(base: usize, data: &[u8], symbol: &str) -> Option<usize> {
    let ehdr = data.get(..std::mem::size_of::<Elf64Ehdr>())?;
    // SAFETY: slice length checked above and ELF header is plain-old-data.
    let ehdr = unsafe { &*(ehdr.as_ptr().cast::<Elf64Ehdr>()) };
    if ehdr.e_ident[..4] != ELF_MAGIC {
        return None;
    }
    let shoff = ehdr.e_shoff as usize;
    let shentsize = ehdr.e_shentsize as usize;
    let shnum = ehdr.e_shnum as usize;
    if shentsize < std::mem::size_of::<Elf64Shdr>() || shnum == 0 {
        return None;
    }

    let mut dynsym: Option<&Elf64Shdr> = None;
    let mut dynstr: Option<&Elf64Shdr> = None;
    for idx in 0..shnum {
        let off = shoff.checked_add(idx.checked_mul(shentsize)?)?;
        let end = off.checked_add(std::mem::size_of::<Elf64Shdr>())?;
        let shdr_bytes = data.get(off..end)?;
        // SAFETY: bounded by the mmap slice and section headers are POD.
        let shdr = unsafe { &*(shdr_bytes.as_ptr().cast::<Elf64Shdr>()) };
        if shdr.sh_type == SHT_DYNSYM {
            dynsym = Some(shdr);
            let linked = shdr.sh_link as usize;
            if linked >= shnum {
                return None;
            }
            let linked_off = shoff.checked_add(linked.checked_mul(shentsize)?)?;
            let linked_end = linked_off.checked_add(std::mem::size_of::<Elf64Shdr>())?;
            let linked_bytes = data.get(linked_off..linked_end)?;
            // SAFETY: bounded by the mmap slice and section headers are POD.
            dynstr = Some(unsafe { &*(linked_bytes.as_ptr().cast::<Elf64Shdr>()) });
            break;
        }
    }

    let dynsym = dynsym?;
    let dynstr = dynstr?;
    let str_start = dynstr.sh_offset as usize;
    let str_end = str_start.checked_add(dynstr.sh_size as usize)?;
    let strtab = data.get(str_start..str_end)?;
    let sym_start = dynsym.sh_offset as usize;
    let sym_size = dynsym.sh_size as usize;
    let sym_entsize = (dynsym.sh_entsize as usize).max(std::mem::size_of::<Elf64Sym>());
    let sym_end = sym_start.checked_add(sym_size)?;
    let sym_bytes = data.get(sym_start..sym_end)?;
    let wanted = symbol.as_bytes();
    let mut offset = 0usize;
    while offset.checked_add(std::mem::size_of::<Elf64Sym>())? <= sym_bytes.len() {
        let entry = &sym_bytes[offset..offset + std::mem::size_of::<Elf64Sym>()];
        // SAFETY: bounded by the mmap slice and symbol entries are POD.
        let sym = unsafe { &*(entry.as_ptr().cast::<Elf64Sym>()) };
        if sym.st_shndx != 0
            && sym.st_value != 0
            && symbol_name_matches(strtab, sym.st_name, wanted)
        {
            let addr = base.saturating_add(sym.st_value as usize);
            // STT_GNU_IFUNC (type 10): st_value points to a resolver function
            // that returns the actual implementation address. Call it.
            let sym_type = sym.st_info & 0xf;
            if sym_type == 10 {
                // SAFETY: resolver is a function at `addr` with signature () -> *mut ().
                type IfuncResolver = unsafe extern "C" fn() -> usize;
                let resolver: IfuncResolver = unsafe { core::mem::transmute(addr) };
                let resolved = unsafe { resolver() };
                return Some(resolved);
            }
            return Some(addr);
        }
        offset = offset.checked_add(sym_entsize)?;
    }
    None
}

fn load_glibc_image() -> Option<&'static LoadedGlibcImage> {
    if let Some(image) = HOST_IMAGE.get() {
        return Some(image);
    }
    let (base, path) = loaded_glibc_image()?;
    let fd = unsafe { raw_open(path.as_ptr()) };
    if fd < 0 {
        return None;
    }
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let stat_ok = unsafe { raw_fstat(fd, stat.as_mut_ptr()) } == 0;
    if !stat_ok {
        unsafe { raw_close(fd) };
        return None;
    }
    // SAFETY: raw_fstat succeeded and fully initialized the struct.
    let stat = unsafe { stat.assume_init() };
    if stat.st_size <= 0 {
        unsafe { raw_close(fd) };
        return None;
    }
    let len = stat.st_size as usize;
    // SAFETY: read-only private file mapping for ELF parsing.
    // Use raw SYS_mmap syscall to avoid going through our interposed mmap.
    let mapped = unsafe {
        libc::syscall(
            libc::SYS_mmap,
            std::ptr::null::<c_void>(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd,
            0i64,
        ) as *mut c_void
    };
    unsafe { raw_close(fd) };
    if std::ptr::eq(mapped, libc::MAP_FAILED) || (mapped as isize) < 0 {
        return None;
    }
    let image = LoadedGlibcImage {
        base,
        mapped: mapped as usize,
        len,
    };
    let _ = HOST_IMAGE.set(image);
    HOST_IMAGE.get()
}

/// Early-resolve the host dlvsym so that subsequent host_dlvsym_next_raw calls
/// bypass our interposed dlvsym. Must be called before delegate_to_host_libc_start_main.
pub(crate) fn ensure_host_dlvsym() {
    if HOST_DLVSYM.load(Ordering::Acquire) != 0 {
        return;
    }
    if let Some(addr) = resolve_host_symbol_raw("dlvsym") {
        HOST_DLVSYM.store(addr, Ordering::Release);
    }
}

pub(crate) fn bootstrap_host_symbols() {
    let mut unresolved = 0usize;
    for (symbol, cache) in [
        ("pthread_create", &HOST_PTHREAD_CREATE),
        ("pthread_join", &HOST_PTHREAD_JOIN),
        ("pthread_detach", &HOST_PTHREAD_DETACH),
        ("pthread_exit", &HOST_PTHREAD_EXIT),
        ("pthread_cancel", &HOST_PTHREAD_CANCEL),
        ("pthread_setcancelstate", &HOST_PTHREAD_SETCANCELSTATE),
        ("pthread_setcanceltype", &HOST_PTHREAD_SETCANCELTYPE),
        ("pthread_testcancel", &HOST_PTHREAD_TESTCANCEL),
        ("pthread_kill", &HOST_PTHREAD_KILL),
        ("pthread_getcpuclockid", &HOST_PTHREAD_GETCPUCLOCKID),
        ("pthread_getaffinity_np", &HOST_PTHREAD_GETAFFINITY_NP),
        ("pthread_setaffinity_np", &HOST_PTHREAD_SETAFFINITY_NP),
        ("pthread_gettid_np", &HOST_PTHREAD_GETTID_NP),
        ("pthread_setname_np", &HOST_PTHREAD_SETNAME_NP),
        ("pthread_getname_np", &HOST_PTHREAD_GETNAME_NP),
        ("pthread_sigqueue", &HOST_PTHREAD_SIGQUEUE),
        ("pthread_self", &HOST_PTHREAD_SELF),
        ("pthread_equal", &HOST_PTHREAD_EQUAL),
        ("malloc", &HOST_MALLOC),
        ("calloc", &HOST_CALLOC),
        ("realloc", &HOST_REALLOC),
        ("free", &HOST_FREE),
        ("__errno_location", &HOST_ERRNO_LOCATION),
        ("dlvsym", &HOST_DLVSYM),
        ("dl_iterate_phdr", &HOST_DL_ITERATE_PHDR),
        ("dladdr", &HOST_DLADDR),
    ] {
        if cache.load(Ordering::Acquire) == 0 {
            let a = resolve_host_symbol_raw(symbol).unwrap_or(0);
            if a != 0 {
                cache.store(a, Ordering::Release);
            } else {
                unresolved += 1;
            }
        }
    }
    RESOLVED.store((unresolved == 0) as usize, Ordering::Release);
}

pub(crate) fn resolve_host_symbol_raw(symbol: &str) -> Option<usize> {
    let image = load_glibc_image()?;
    // SAFETY: cached mapping is process-lifetime read-only storage for libc ELF bytes.
    let data = unsafe { core::slice::from_raw_parts(image.mapped as *const u8, image.len) };
    resolve_symbol_from_data(image.base, data, symbol)
}

pub(crate) fn resolve_host_symbol_cached(
    slot: &OnceLock<usize>,
    symbol: &'static str,
) -> Option<usize> {
    let ptr = *slot.get_or_init(|| resolve_host_symbol_raw(symbol).unwrap_or(0));
    (ptr != 0).then_some(ptr)
}

#[inline]
fn load_host_symbol(cache: &AtomicUsize) -> Option<usize> {
    bootstrap_host_symbols();
    let addr = cache.load(Ordering::Acquire);
    (addr != 0).then_some(addr)
}

pub(crate) fn host_pthread_create_raw() -> Option<
    unsafe extern "C" fn(
        *mut libc::pthread_t,
        *const libc::pthread_attr_t,
        Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>,
        *mut c_void,
    ) -> i32,
> {
    load_host_symbol(&HOST_PTHREAD_CREATE).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_join_raw()
-> Option<unsafe extern "C" fn(libc::pthread_t, *mut *mut c_void) -> i32> {
    load_host_symbol(&HOST_PTHREAD_JOIN).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_detach_raw() -> Option<unsafe extern "C" fn(libc::pthread_t) -> i32> {
    load_host_symbol(&HOST_PTHREAD_DETACH).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_exit_raw() -> Option<unsafe extern "C" fn(*mut c_void) -> !> {
    load_host_symbol(&HOST_PTHREAD_EXIT).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_cancel_raw() -> Option<unsafe extern "C" fn(libc::pthread_t) -> i32> {
    load_host_symbol(&HOST_PTHREAD_CANCEL).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_setcancelstate_raw()
-> Option<unsafe extern "C" fn(c_int, *mut c_int) -> i32> {
    load_host_symbol(&HOST_PTHREAD_SETCANCELSTATE).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_setcanceltype_raw()
-> Option<unsafe extern "C" fn(c_int, *mut c_int) -> i32> {
    load_host_symbol(&HOST_PTHREAD_SETCANCELTYPE).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_testcancel_raw() -> Option<unsafe extern "C" fn()> {
    load_host_symbol(&HOST_PTHREAD_TESTCANCEL).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_kill_raw() -> Option<unsafe extern "C" fn(libc::pthread_t, c_int) -> i32>
{
    load_host_symbol(&HOST_PTHREAD_KILL).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_getcpuclockid_raw()
-> Option<unsafe extern "C" fn(libc::pthread_t, *mut libc::clockid_t) -> i32> {
    load_host_symbol(&HOST_PTHREAD_GETCPUCLOCKID).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_getaffinity_np_raw()
-> Option<unsafe extern "C" fn(libc::pthread_t, usize, *mut libc::cpu_set_t) -> i32> {
    load_host_symbol(&HOST_PTHREAD_GETAFFINITY_NP).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_setaffinity_np_raw()
-> Option<unsafe extern "C" fn(libc::pthread_t, usize, *const libc::cpu_set_t) -> i32> {
    load_host_symbol(&HOST_PTHREAD_SETAFFINITY_NP).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_gettid_np_raw()
-> Option<unsafe extern "C" fn(libc::pthread_t) -> libc::pid_t> {
    load_host_symbol(&HOST_PTHREAD_GETTID_NP).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_setname_np_raw()
-> Option<unsafe extern "C" fn(libc::pthread_t, *const c_char) -> i32> {
    load_host_symbol(&HOST_PTHREAD_SETNAME_NP).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_getname_np_raw()
-> Option<unsafe extern "C" fn(libc::pthread_t, *mut c_char, usize) -> i32> {
    load_host_symbol(&HOST_PTHREAD_GETNAME_NP).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_sigqueue_raw()
-> Option<unsafe extern "C" fn(libc::pthread_t, c_int, libc::sigval) -> i32> {
    load_host_symbol(&HOST_PTHREAD_SIGQUEUE).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_self_raw() -> Option<unsafe extern "C" fn() -> libc::pthread_t> {
    load_host_symbol(&HOST_PTHREAD_SELF).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_equal_raw()
-> Option<unsafe extern "C" fn(libc::pthread_t, libc::pthread_t) -> i32> {
    load_host_symbol(&HOST_PTHREAD_EQUAL).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_malloc_raw() -> Option<unsafe extern "C" fn(usize) -> *mut c_void> {
    load_host_symbol(&HOST_MALLOC).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_calloc_raw() -> Option<unsafe extern "C" fn(usize, usize) -> *mut c_void> {
    load_host_symbol(&HOST_CALLOC).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_realloc_raw() -> Option<unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void>
{
    load_host_symbol(&HOST_REALLOC).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_free_raw() -> Option<unsafe extern "C" fn(*mut c_void)> {
    load_host_symbol(&HOST_FREE).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_errno_location_raw() -> Option<unsafe extern "C" fn() -> *mut c_int> {
    load_host_symbol(&HOST_ERRNO_LOCATION).map(|addr| unsafe { core::mem::transmute(addr) })
}

/// Get the cached host `dl_iterate_phdr` address (non-blocking, no recursion).
#[inline]
pub(crate) fn host_dl_iterate_phdr_cached() -> Option<usize> {
    let addr = HOST_DL_ITERATE_PHDR.load(Ordering::Acquire);
    (addr != 0).then_some(addr)
}

/// Get the cached host `dladdr` address (non-blocking, no recursion).
#[inline]
pub(crate) fn host_dladdr_cached() -> Option<usize> {
    let addr = HOST_DLADDR.load(Ordering::Acquire);
    (addr != 0).then_some(addr)
}

#[inline]
pub(crate) fn host_errno(default_errno: c_int) -> c_int {
    let Some(host_errno_location) = host_errno_location_raw() else {
        return default_errno;
    };
    // SAFETY: host `__errno_location` returns a valid thread-local errno pointer.
    let ptr = unsafe { host_errno_location() };
    if ptr.is_null() {
        default_errno
    } else {
        // SAFETY: non-null pointer returned by host `__errno_location` is readable.
        unsafe { *ptr }
    }
}
