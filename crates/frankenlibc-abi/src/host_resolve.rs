//! Raw host symbol resolution — bypasses ALL dynamic linker interposition.
//!
//! Resolves symbols in the host glibc by parsing the in-memory ELF image
//! using only raw syscalls and pointer math. Zero libc calls, zero recursion.
#![allow(dead_code)]

use std::ffi::{c_char, c_int, c_void};
use std::mem::MaybeUninit;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use frankenlibc_core::syscall as raw_syscall;

static HOST_PTHREAD_CREATE: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_CANCEL: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_SETCANCELSTATE: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_SETCANCELTYPE: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_TESTCANCEL: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_REGISTER_CANCEL: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_UNREGISTER_CANCEL: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_REGISTER_CANCEL_DEFER: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_UNREGISTER_CANCEL_RESTORE: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_UNWIND_NEXT: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_JOIN: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_DETACH: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_EXIT: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_SELF: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_TRYJOIN_NP: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_TIMEDJOIN_NP: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_CLOCKJOIN_NP: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_CONDATTR_GETCLOCK: AtomicUsize = AtomicUsize::new(0);
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
static HOST_LOADER_IMAGE: OnceLock<LoadedGlibcImage> = OnceLock::new();
const DLPI_NAME_SCAN_LIMIT: usize = 512;

#[inline]
pub(crate) unsafe fn host_dlvsym_next_raw(
    symbol: *const c_char,
    version: *const c_char,
) -> *mut c_void {
    if HOST_DLVSYM.load(Ordering::Acquire) == 0 {
        ensure_host_dlvsym();
    }
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
    match unsafe { raw_syscall::sys_read(fd, buf, count) } {
        Ok(n) => n as isize,
        Err(e) => -(e as isize),
    }
}
unsafe fn raw_open(path: *const u8) -> i32 {
    unsafe { raw_syscall::sys_openat(libc::AT_FDCWD, path, libc::O_RDONLY, 0) }.unwrap_or(-1)
}
unsafe fn raw_close(fd: i32) {
    let _ = raw_syscall::sys_close(fd);
}
unsafe fn raw_fstat(fd: i32, stat: *mut libc::stat) -> i32 {
    unsafe { raw_syscall::sys_fstat(fd, stat as *mut u8) }
        .map(|_| 0)
        .unwrap_or(-1)
}

unsafe fn bounded_c_string_len(ptr: *const c_char, limit: usize) -> Option<usize> {
    if ptr.is_null() {
        return None;
    }
    (0..limit).find(|&len| unsafe { *ptr.add(len) } == 0)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
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
    // SAFETY: dlpi_name is provided by dl_iterate_phdr for this callback invocation.
    let Some(name_len) = (unsafe { bounded_c_string_len(info.dlpi_name, DLPI_NAME_SCAN_LIMIT) })
    else {
        return 0;
    };
    let name_bytes = unsafe { std::slice::from_raw_parts(info.dlpi_name.cast::<u8>(), name_len) };
    if !contains_bytes(name_bytes, b"libc.so") {
        return 0;
    }
    // SAFETY: data points to our stack-owned DlIterateTarget for the duration of dl_iterate_phdr.
    let target = unsafe { &mut *(data as *mut DlIterateTarget) };
    target.base = info.dlpi_addr as usize;
    let len = name_bytes.len().min(target.path.len().saturating_sub(1));
    target.path[..len].copy_from_slice(&name_bytes[..len]);
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

fn find_image_via_maps(needle: &str) -> Option<(usize, [u8; 512])> {
    let fd = unsafe { raw_open(c"/proc/self/maps".as_ptr().cast()) };
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 4096];
    let mut line_buf = [0u8; 1024];
    let mut line_len = 0usize;
    loop {
        let n = unsafe { raw_read(fd, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }
        for &byte in &buf[..n as usize] {
            if byte == b'\n' {
                if let Ok(line) = core::str::from_utf8(&line_buf[..line_len])
                    && let Some(image) = parse_maps_line_for_image(line, needle)
                {
                    unsafe { raw_close(fd) };
                    return Some(image);
                }
                line_len = 0;
                continue;
            }
            if line_len < line_buf.len() {
                line_buf[line_len] = byte;
                line_len += 1;
            } else {
                // Discard overlong lines until the next newline.
                line_len = line_buf.len();
            }
        }
    }
    unsafe { raw_close(fd) };
    if let Ok(line) = core::str::from_utf8(&line_buf[..line_len]) {
        return parse_maps_line_for_image(line, needle);
    }
    None
}

fn find_glibc_image_via_maps() -> Option<(usize, [u8; 512])> {
    find_image_via_maps("libc.so")
}

/// The prefix of glibc's `struct link_map` that the loader documents in
/// `<link.h>`.
#[repr(C)]
struct LinkMapHead {
    l_addr: usize,
    l_name: *const c_char,
    l_ld: *const c_void,
    l_next: *const LinkMapHead,
    l_prev: *const LinkMapHead,
}

/// The prefix of `struct r_debug` (`<link.h>`).
#[repr(C)]
struct RDebugHead {
    r_version: libc::c_int,
    r_map: *const LinkMapHead,
}

#[cfg(not(feature = "standalone"))]
unsafe extern "C" {
    /// The dynamic loader's debugger interface, exported by ld.so.
    static _r_debug: RDebugHead;
}

/// Find a loaded object whose path contains `needle` by walking the loader's
/// link map. Plain memory reads: the `/proc/self/maps` scan it replaces made
/// the kernel format every mapping of the process, ~4% of a preloaded
/// process's startup cycles (bd-rc0923-epic-eeuy4f.25). The link map is
/// complete before any constructor or first call reaches this code.
#[cfg(not(feature = "standalone"))]
fn find_image_via_link_map(needle: &[u8]) -> Option<(usize, [u8; 512])> {
    find_object_via_link_map(needle).map(|(base, path, _dynamic)| (base, path))
}

/// `find_image_via_link_map` plus the object's dynamic section (`l_ld`).
#[cfg(not(feature = "standalone"))]
fn find_object_via_link_map(needle: &[u8]) -> Option<(usize, [u8; 512], usize)> {
    // SAFETY: `_r_debug` is ld.so's statically allocated debugger interface;
    // r_map and every l_next/l_name it reaches stay valid while their objects
    // are loaded (all of the initial objects, for the process lifetime).
    let mut node = unsafe { (*core::ptr::addr_of!(_r_debug)).r_map };
    for _ in 0..4096 {
        if node.is_null() {
            return None;
        }
        // SAFETY: as above.
        let entry = unsafe { &*node };
        if !entry.l_name.is_null()
            && let Some(len) = unsafe { bounded_c_string_len(entry.l_name, 512) }
        {
            // SAFETY: bounded_c_string_len found a terminator within `len + 1`.
            let name = unsafe { std::slice::from_raw_parts(entry.l_name.cast::<u8>(), len) };
            if entry.l_addr != 0 && contains_bytes(name, needle) {
                let mut path = [0u8; 512];
                path[..len.min(511)].copy_from_slice(&name[..len.min(511)]);
                return Some((entry.l_addr, path, entry.l_ld as usize));
            }
        }
        node = entry.l_next;
    }
    None
}

#[cfg(feature = "standalone")]
fn find_image_via_link_map(_needle: &[u8]) -> Option<(usize, [u8; 512])> {
    None
}

#[cfg(feature = "standalone")]
fn find_object_via_link_map(_needle: &[u8]) -> Option<(usize, [u8; 512], usize)> {
    None
}

fn find_loader_image_via_maps() -> Option<(usize, [u8; 512])> {
    find_image_via_maps("ld-linux")
}

fn parse_maps_line(line: &str) -> Option<(usize, [u8; 512])> {
    parse_maps_line_for_image(line, "libc.so")
}

fn parse_maps_line_for_image(line: &str, needle: &str) -> Option<(usize, [u8; 512])> {
    if !line.contains(needle) {
        return None;
    }
    let entry = frankenlibc_core::proc_maps::parse_maps_line(line)?;
    if !entry.perms.starts_with("r--p") || entry.offset != 0 {
        return None;
    }
    let path_part = entry.path?;
    let mut path = [0u8; 512];
    let bytes = path_part.as_bytes();
    let len = bytes.len().min(path.len().saturating_sub(1));
    path[..len].copy_from_slice(&bytes[..len]);
    path[len] = 0;
    Some((entry.start, path))
}

fn loaded_glibc_image() -> Option<(usize, [u8; 512])> {
    // Prefer the raw `/proc/self/maps` scan during bootstrap. Calling
    // `dl_iterate_phdr` before we have already cached the host implementation
    // can recurse back through our own interposed loader ABI.
    find_image_via_link_map(b"libc.so")
        .or_else(find_glibc_image_via_maps)
        .or_else(find_glibc_image_via_phdr)
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

const SHT_GNU_HASH: u32 = 0x6fff_fff6;

/// Compares only `symbol.len() + 1` bytes: scanning every candidate name to its
/// NUL first made each lookup read the whole string table.
fn symbol_name_matches(strtab: &[u8], name_offset: u32, symbol: &[u8]) -> bool {
    let start = name_offset as usize;
    let Some(end) = start.checked_add(symbol.len()) else {
        return false;
    };
    strtab.get(start..end) == Some(symbol) && strtab.get(end) == Some(&0)
}

fn gnu_hash(name: &[u8]) -> u32 {
    name.iter().fold(5381u32, |h, byte| {
        h.wrapping_mul(33).wrapping_add(u32::from(*byte))
    })
}

/// Walks the image's `.gnu.hash` chain (the loader's own lookup structure)
/// for `wanted`, yielding symbol indices whose hash matches. Every defined
/// symbol of that name lies in one chain, kept in `.dynsym` order, so the first
/// acceptable candidate is the one the linear scan finds. Allocation-free: this
/// runs while host malloc itself is being resolved.
struct GnuHashChain<'a> {
    table: &'a [u8],
    chain_at: usize,
    symoffset: usize,
    hash: u32,
    next_index: Option<usize>,
}

impl<'a> GnuHashChain<'a> {
    /// `None` when the table is malformed; the caller then scans linearly.
    fn new(table: &'a [u8], wanted: &[u8]) -> Option<Self> {
        let nbuckets = gnu_hash_word(table, 0)? as usize;
        let symoffset = gnu_hash_word(table, 1)? as usize;
        let bloom_words = gnu_hash_word(table, 2)? as usize;
        if nbuckets == 0 {
            return None;
        }
        // ELFCLASS64 bloom words are 8 bytes, i.e. two u32 slots each.
        let buckets_at = 4usize.checked_add(bloom_words.checked_mul(2)?)?;
        let chain_at = buckets_at.checked_add(nbuckets)?;
        let hash = gnu_hash(wanted);
        let first = gnu_hash_word(table, buckets_at + hash as usize % nbuckets)? as usize;
        if first != 0 && first < symoffset {
            return None;
        }
        Some(Self {
            table,
            chain_at,
            symoffset,
            hash,
            next_index: (first != 0).then_some(first),
        })
    }
}

impl Iterator for GnuHashChain<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        loop {
            let index = self.next_index.take()?;
            let chain_hash = gnu_hash_word(
                self.table,
                self.chain_at.checked_add(index - self.symoffset)?,
            )?;
            if chain_hash & 1 == 0 {
                self.next_index = index.checked_add(1);
            }
            if chain_hash | 1 == self.hash | 1 {
                return Some(index);
            }
        }
    }
}

fn gnu_hash_word(table: &[u8], index: usize) -> Option<u32> {
    let at = index.checked_mul(4)?;
    let bytes = table.get(at..at.checked_add(4)?)?;
    Some(u32::from_ne_bytes(bytes.try_into().ok()?))
}

/// An image's `.dynsym` with its string table and, when present and linked to
/// it, its `.gnu.hash` table.
struct DynamicSymbols<'a> {
    strtab: &'a [u8],
    sym_bytes: &'a [u8],
    sym_entsize: usize,
    gnu_hash: Option<&'a [u8]>,
}

impl<'a> DynamicSymbols<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
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
        let section = |idx: usize| -> Option<&'a Elf64Shdr> {
            let off = shoff.checked_add(idx.checked_mul(shentsize)?)?;
            let end = off.checked_add(std::mem::size_of::<Elf64Shdr>())?;
            let shdr_bytes = data.get(off..end)?;
            // SAFETY: bounded by the mmap slice and section headers are POD.
            Some(unsafe { &*(shdr_bytes.as_ptr().cast::<Elf64Shdr>()) })
        };
        let contents = |shdr: &Elf64Shdr| -> Option<&'a [u8]> {
            let start = shdr.sh_offset as usize;
            data.get(start..start.checked_add(shdr.sh_size as usize)?)
        };

        let mut dynsym: Option<(usize, &Elf64Shdr)> = None;
        let mut gnu_hash: Option<&Elf64Shdr> = None;
        for idx in 0..shnum {
            let shdr = section(idx)?;
            if shdr.sh_type == SHT_DYNSYM && dynsym.is_none() {
                dynsym = Some((idx, shdr));
            } else if shdr.sh_type == SHT_GNU_HASH && gnu_hash.is_none() {
                gnu_hash = Some(shdr);
            }
        }
        let (dynsym_index, dynsym) = dynsym?;
        let linked = dynsym.sh_link as usize;
        if linked >= shnum {
            return None;
        }
        Some(Self {
            strtab: contents(section(linked)?)?,
            sym_bytes: contents(dynsym)?,
            sym_entsize: (dynsym.sh_entsize as usize).max(std::mem::size_of::<Elf64Sym>()),
            gnu_hash: gnu_hash
                .filter(|shdr| shdr.sh_link as usize == dynsym_index)
                .and_then(contents),
        })
    }

    /// The symbol tables of an object as the loader mapped them, from its
    /// dynamic section. Finding host symbols in the on-disk file meant
    /// opening libc and ld.so, mapping them whole and faulting in their
    /// .dynsym/.dynstr/.gnu.hash pages in every preloaded process, although
    /// the loaded images already carry the same tables
    /// (bd-rc0923-epic-eeuy4f.25). Requires DT_GNU_HASH (glibc always has it).
    ///
    /// `known_count` is the object's symbol count if a previous call already
    /// derived it (zero if not); the second value returned is that count.
    ///
    /// # Safety
    /// `dynamic` must be the `l_ld` of an object loaded at `base` that stays
    /// loaded for the process lifetime.
    unsafe fn from_loaded(
        base: usize,
        dynamic: usize,
        known_count: usize,
    ) -> Option<(DynamicSymbols<'static>, usize)> {
        const DT_NULL: i64 = 0;
        const DT_STRTAB: i64 = 5;
        const DT_SYMTAB: i64 = 6;
        const DT_STRSZ: i64 = 10;
        const DT_SYMENT: i64 = 11;
        const DT_GNU_HASH: i64 = 0x6fff_fef5;
        if dynamic == 0 {
            return None;
        }
        // glibc relocates these d_ptr entries in place; accept an offset
        // that was not (below the load base) as well.
        let address = |value: usize| if value < base { base + value } else { value };
        let (mut strtab, mut symtab, mut strsz, mut syment, mut gnu_hash) = (0, 0, 0, 0, 0);
        let mut entry = dynamic as *const [i64; 2];
        for _ in 0..4096 {
            // SAFETY: the dynamic section is a DT_NULL-terminated array of
            // (tag, value) pairs inside the loaded object.
            let [tag, value] = unsafe { entry.read() };
            match tag {
                DT_NULL => break,
                DT_STRTAB => strtab = address(value as usize),
                DT_SYMTAB => symtab = address(value as usize),
                DT_STRSZ => strsz = value as usize,
                DT_SYMENT => syment = value as usize,
                DT_GNU_HASH => gnu_hash = address(value as usize),
                _ => {}
            }
            // SAFETY: not past DT_NULL yet.
            entry = unsafe { entry.add(1) };
        }
        if strtab == 0 || symtab == 0 || gnu_hash == 0 || strsz == 0 {
            return None;
        }
        let syment = syment.max(std::mem::size_of::<Elf64Sym>());
        // The symbol count is one past the end of the chain of the highest
        // non-empty bucket.
        let word = |index: usize| -> u32 {
            // SAFETY: indices below stay within the GNU hash table, whose
            // extent the header words describe.
            unsafe { (gnu_hash as *const u32).add(index).read_unaligned() }
        };
        let (nbuckets, symoffset, bloom_words) =
            (word(0) as usize, word(1) as usize, word(2) as usize);
        let buckets_at = 4 + bloom_words * 2;
        let chains_at = buckets_at + nbuckets;
        // Deriving the count reads every bucket and a chain (libc: ~1000
        // words), which is why callers cache it: it was paid again on each
        // of the ~30 host symbols resolved at startup.
        let count = if known_count != 0 {
            known_count
        } else {
            let max_bucket = (0..nbuckets).map(|i| word(buckets_at + i) as usize).max()?;
            let mut count = symoffset;
            if max_bucket >= symoffset {
                count = max_bucket;
                while word(chains_at + count - symoffset) & 1 == 0 {
                    count += 1;
                }
                count += 1;
            }
            count
        };
        // SAFETY: each extent was derived from the object's own dynamic
        // section and hash table, and the object is never unloaded.
        unsafe {
            Some((
                DynamicSymbols {
                    strtab: std::slice::from_raw_parts(strtab as *const u8, strsz),
                    sym_bytes: std::slice::from_raw_parts(symtab as *const u8, count * syment),
                    sym_entsize: syment,
                    gnu_hash: Some(std::slice::from_raw_parts(
                        gnu_hash as *const u8,
                        (chains_at + count - symoffset) * 4,
                    )),
                },
                count,
            ))
        }
    }

    fn count(&self) -> usize {
        self.sym_bytes.len() / self.sym_entsize
    }

    fn symbol(&self, index: usize) -> Option<&'a Elf64Sym> {
        let offset = index.checked_mul(self.sym_entsize)?;
        let entry = self
            .sym_bytes
            .get(offset..offset.checked_add(std::mem::size_of::<Elf64Sym>())?)?;
        // SAFETY: bounded by the mmap slice and symbol entries are POD.
        Some(unsafe { &*(entry.as_ptr().cast::<Elf64Sym>()) })
    }

    /// First defined symbol named `wanted` in `.dynsym` order.
    fn find_defined(&self, wanted: &[u8], use_gnu_hash: bool) -> Option<&'a Elf64Sym> {
        let mut hashed = self
            .gnu_hash
            .filter(|_| use_gnu_hash)
            .and_then(|table| GnuHashChain::new(table, wanted));
        let mut linear = 0..self.count();
        loop {
            let index = match hashed.as_mut() {
                Some(chain) => chain.next(),
                None => linear.next(),
            }?;
            let sym = self.symbol(index)?;
            if sym.st_shndx != 0
                && sym.st_value != 0
                && symbol_name_matches(self.strtab, sym.st_name, wanted)
            {
                return Some(sym);
            }
        }
    }
}

fn resolve_symbol_from_data(base: usize, data: &[u8], symbol: &str) -> Option<usize> {
    resolve_in(base, &DynamicSymbols::parse(data)?, symbol)
}

fn resolve_in(base: usize, table: &DynamicSymbols<'_>, symbol: &str) -> Option<usize> {
    let sym = table.find_defined(symbol.as_bytes(), true)?;
    let addr = base.saturating_add(sym.st_value as usize);
    // STT_GNU_IFUNC (type 10): st_value points to a resolver function
    // that returns the actual implementation address. Call it.
    if sym.st_info & 0xf == 10 {
        // SAFETY: resolver is a function at `addr` with signature () -> *mut ().
        type IfuncResolver = unsafe extern "C" fn() -> usize;
        let resolver: IfuncResolver = unsafe { core::mem::transmute(addr) };
        return Some(unsafe { resolver() });
    }
    Some(addr)
}

#[allow(unreachable_code)]
fn load_glibc_image() -> Option<&'static LoadedGlibcImage> {
    // Standalone mode: no host glibc to load
    #[cfg(feature = "standalone")]
    {
        return None;
    }
    #[cfg(not(feature = "standalone"))]
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
    // Use raw syscall to avoid going through our interposed mmap.
    let mapped = match unsafe {
        raw_syscall::sys_mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd,
            0,
        )
    } {
        Ok(ptr) => ptr as *mut c_void,
        Err(_) => {
            unsafe { raw_close(fd) };
            return None;
        }
    };
    unsafe { raw_close(fd) };
    let image = LoadedGlibcImage {
        base,
        mapped: mapped as usize,
        len,
    };
    let _ = HOST_IMAGE.set(image);
    HOST_IMAGE.get()
}

fn load_loader_image() -> Option<&'static LoadedGlibcImage> {
    if let Some(image) = HOST_LOADER_IMAGE.get() {
        return Some(image);
    }
    let (base, path) = find_image_via_link_map(b"ld-linux").or_else(find_loader_image_via_maps)?;
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
    // Use raw syscall to avoid going through our interposed mmap.
    let mapped = match unsafe {
        raw_syscall::sys_mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd,
            0,
        )
    } {
        Ok(ptr) => ptr as *mut c_void,
        Err(_) => {
            unsafe { raw_close(fd) };
            return None;
        }
    };
    unsafe { raw_close(fd) };
    let image = LoadedGlibcImage {
        base,
        mapped: mapped as usize,
        len,
    };
    let _ = HOST_LOADER_IMAGE.set(image);
    HOST_LOADER_IMAGE.get()
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

/// Counts entries into [`bootstrap_host_symbols`] so the rescan can back off.
/// Separate from `RESOLVED`, which records that every symbol has been found.
static BOOTSTRAP_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn bootstrap_host_symbols() {
    // EARLY-OUT ON FULL RESOLUTION. `RESOLVED` was written at the end of this
    // function and never read anywhere, so the table below was walked on EVERY
    // call — and every symbol still at 0 was re-resolved, which means a full ELF
    // symbol-table scan with string comparison per call. Measured with callgrind
    // on a malloc/free loop, `symbol_name_matches` was 5.42% of fl's entire
    // instruction budget and `resolve_symbol_from_data` a further 2.31%, i.e.
    // 7.7% of malloc+free spent looking up host symbols. bd-dcrhgl.
    if RESOLVED.load(Ordering::Acquire) != 0 {
        return;
    }

    // BACKOFF, because a plain one-shot latch would be wrong. Some of these
    // resolve only once the loader image is mapped (`dlvsym`,
    // `dl_iterate_phdr`), so an early call can legitimately fail and a later one
    // succeed; latching after the first pass would lose them permanently.
    // Retrying on attempts 0, 1, 2 and then only on powers of two keeps the
    // late-resolution path working while making the steady state — a symbol
    // that is genuinely absent — cost one atomic increment and a branch instead
    // of a symbol-table walk.
    let attempt = BOOTSTRAP_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    if attempt > 2 && !attempt.is_power_of_two() {
        return;
    }

    let mut unresolved = 0usize;
    for (symbol, cache) in [
        ("pthread_create", &HOST_PTHREAD_CREATE),
        ("pthread_cancel", &HOST_PTHREAD_CANCEL),
        ("pthread_setcancelstate", &HOST_PTHREAD_SETCANCELSTATE),
        ("pthread_setcanceltype", &HOST_PTHREAD_SETCANCELTYPE),
        ("pthread_testcancel", &HOST_PTHREAD_TESTCANCEL),
        ("__pthread_register_cancel", &HOST_PTHREAD_REGISTER_CANCEL),
        (
            "__pthread_unregister_cancel",
            &HOST_PTHREAD_UNREGISTER_CANCEL,
        ),
        (
            "__pthread_register_cancel_defer",
            &HOST_PTHREAD_REGISTER_CANCEL_DEFER,
        ),
        (
            "__pthread_unregister_cancel_restore",
            &HOST_PTHREAD_UNREGISTER_CANCEL_RESTORE,
        ),
        ("__pthread_unwind_next", &HOST_PTHREAD_UNWIND_NEXT),
        ("pthread_join", &HOST_PTHREAD_JOIN),
        ("pthread_detach", &HOST_PTHREAD_DETACH),
        ("pthread_exit", &HOST_PTHREAD_EXIT),
        ("pthread_self", &HOST_PTHREAD_SELF),
        ("pthread_tryjoin_np", &HOST_PTHREAD_TRYJOIN_NP),
        ("pthread_timedjoin_np", &HOST_PTHREAD_TIMEDJOIN_NP),
        ("pthread_clockjoin_np", &HOST_PTHREAD_CLOCKJOIN_NP),
        ("pthread_condattr_getclock", &HOST_PTHREAD_CONDATTR_GETCLOCK),
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

/// The loaded libc (`needle` "libc.so") or ld.so ("ld-linux") symbol
/// tables, found once via the link map; `None` falls back to the file.
fn loaded_tables(
    needle: &[u8],
    cache: &'static LoadedTablesCache,
) -> Option<(usize, DynamicSymbols<'static>)> {
    #[cfg(feature = "standalone")]
    {
        let _ = (needle, cache);
        return None;
    }
    #[cfg(not(feature = "standalone"))]
    {
        let mut base = cache.base.load(Ordering::Acquire);
        let mut dynamic = cache.dynamic.load(Ordering::Acquire);
        if base == 0 {
            let (found_base, _path, found_dynamic) = find_object_via_link_map(needle)?;
            (base, dynamic) = (found_base, found_dynamic);
            cache.dynamic.store(dynamic, Ordering::Release);
            cache.base.store(base, Ordering::Release);
        }
        // SAFETY: link-map objects found at startup stay loaded.
        let (tables, count) = unsafe {
            DynamicSymbols::from_loaded(base, dynamic, cache.count.load(Ordering::Acquire))
        }?;
        cache.count.store(count, Ordering::Release);
        Some((base, tables))
    }
}

struct LoadedTablesCache {
    base: AtomicUsize,
    dynamic: AtomicUsize,
    /// Symbol count derived from the GNU hash table; zero until derived.
    count: AtomicUsize,
}

static LOADED_LIBC_TABLES: LoadedTablesCache = LoadedTablesCache {
    base: AtomicUsize::new(0),
    dynamic: AtomicUsize::new(0),
    count: AtomicUsize::new(0),
};
static LOADED_LOADER_TABLES: LoadedTablesCache = LoadedTablesCache {
    base: AtomicUsize::new(0),
    dynamic: AtomicUsize::new(0),
    count: AtomicUsize::new(0),
};

pub(crate) fn resolve_host_symbol_raw(symbol: &str) -> Option<usize> {
    if let Some((base, tables)) = loaded_tables(b"libc.so", &LOADED_LIBC_TABLES) {
        return resolve_in(base, &tables, symbol);
    }
    let image = load_glibc_image()?;
    // SAFETY: cached mapping is process-lifetime read-only storage for libc ELF bytes.
    let data = unsafe { core::slice::from_raw_parts(image.mapped as *const u8, image.len) };
    resolve_symbol_from_data(image.base, data, symbol)
}

pub(crate) fn resolve_loader_symbol_raw(symbol: &str) -> Option<usize> {
    if let Some((base, tables)) = loaded_tables(b"ld-linux", &LOADED_LOADER_TABLES) {
        return resolve_in(base, &tables, symbol);
    }
    let image = load_loader_image()?;
    // SAFETY: cached mapping is process-lifetime read-only storage for ld-linux ELF bytes.
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

pub(crate) fn host_pthread_cancel_raw() -> Option<unsafe extern "C" fn(libc::pthread_t) -> i32> {
    load_host_symbol(&HOST_PTHREAD_CANCEL).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_setcancelstate_raw()
-> Option<unsafe extern "C-unwind" fn(c_int, *mut c_int) -> i32> {
    load_host_symbol(&HOST_PTHREAD_SETCANCELSTATE).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_setcanceltype_raw()
-> Option<unsafe extern "C-unwind" fn(c_int, *mut c_int) -> i32> {
    load_host_symbol(&HOST_PTHREAD_SETCANCELTYPE).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_testcancel_raw() -> Option<unsafe extern "C-unwind" fn()> {
    load_host_symbol(&HOST_PTHREAD_TESTCANCEL).map(|addr| unsafe { core::mem::transmute(addr) })
}

/// glibc's C cleanup-handler registration (`pthread_cleanup_push` without
/// `-fexceptions`). `__pthread_unwind_next` continues a cancellation unwind.
pub(crate) fn host_pthread_register_cancel_raw() -> Option<unsafe extern "C-unwind" fn(*mut c_void)>
{
    load_host_symbol(&HOST_PTHREAD_REGISTER_CANCEL)
        .map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_unregister_cancel_raw()
-> Option<unsafe extern "C-unwind" fn(*mut c_void)> {
    load_host_symbol(&HOST_PTHREAD_UNREGISTER_CANCEL)
        .map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_register_cancel_defer_raw()
-> Option<unsafe extern "C-unwind" fn(*mut c_void)> {
    load_host_symbol(&HOST_PTHREAD_REGISTER_CANCEL_DEFER)
        .map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_unregister_cancel_restore_raw()
-> Option<unsafe extern "C-unwind" fn(*mut c_void)> {
    load_host_symbol(&HOST_PTHREAD_UNREGISTER_CANCEL_RESTORE)
        .map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_unwind_next_raw() -> Option<unsafe extern "C-unwind" fn(*mut c_void) -> !>
{
    load_host_symbol(&HOST_PTHREAD_UNWIND_NEXT).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_join_raw()
-> Option<unsafe extern "C-unwind" fn(libc::pthread_t, *mut *mut c_void) -> i32> {
    load_host_symbol(&HOST_PTHREAD_JOIN).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_detach_raw() -> Option<unsafe extern "C" fn(libc::pthread_t) -> i32> {
    load_host_symbol(&HOST_PTHREAD_DETACH).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_exit_raw() -> Option<unsafe extern "C-unwind" fn(*mut c_void) -> !> {
    load_host_symbol(&HOST_PTHREAD_EXIT).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_self_raw() -> Option<unsafe extern "C" fn() -> libc::pthread_t> {
    load_host_symbol(&HOST_PTHREAD_SELF).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_tryjoin_np_raw()
-> Option<unsafe extern "C" fn(libc::pthread_t, *mut *mut c_void) -> i32> {
    load_host_symbol(&HOST_PTHREAD_TRYJOIN_NP).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_timedjoin_np_raw()
-> Option<unsafe extern "C" fn(libc::pthread_t, *mut *mut c_void, *const libc::timespec) -> i32> {
    load_host_symbol(&HOST_PTHREAD_TIMEDJOIN_NP).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_clockjoin_np_raw() -> Option<
    unsafe extern "C" fn(libc::pthread_t, *mut *mut c_void, c_int, *const libc::timespec) -> i32,
> {
    load_host_symbol(&HOST_PTHREAD_CLOCKJOIN_NP).map(|addr| unsafe { core::mem::transmute(addr) })
}

pub(crate) fn host_pthread_condattr_getclock_raw()
-> Option<unsafe extern "C" fn(*const libc::pthread_condattr_t, *mut libc::clockid_t) -> i32> {
    load_host_symbol(&HOST_PTHREAD_CONDATTR_GETCLOCK)
        .map(|addr| unsafe { core::mem::transmute(addr) })
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

/// Attempts spent resolving the host `__errno_location` SPECIFICALLY.
///
/// bd-7dq39e. `bootstrap_host_symbols` backs off on ONE counter shared by every
/// caller of every symbol, and while `RESOLVED` is still 0 that counter is
/// advanced overwhelmingly by malloc/free — so the few attempts the backoff does
/// allow get spent on somebody else's call and this symbol stays cold. Its own
/// budget cannot be starved that way.
static ERRNO_RESOLVE_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

/// The host `__errno_location`, resolved on its own budget.
///
/// THE SILENT NO-OP THIS EXISTS TO KILL. When this returns `None`,
/// [`write_host_errno_if_available`] returns having written nothing — while the
/// caller has already produced its error return. The ABI then reports a failure
/// with whatever was in the slot before, which for a test that seeds it is
/// `errno == 0`. Measured: five stdio error-path gates failing together, e.g.
/// `fdopen(-1) should set EBADF: left: 0, right: 9`, 3 runs in 14 (21%) against
/// HEAD on worker hz4.
///
/// The backoff SHAPE is kept — bd-dcrhgl measured symbol lookup at 7.7% of
/// malloc+free, so a per-call ELF scan is not affordable — but the budget is
/// this symbol's own, so a cold cache always gets its first three attempts.
/// Once resolved this is one load and a branch, as before.
pub(crate) fn host_errno_location_raw() -> Option<unsafe extern "C" fn() -> *mut c_int> {
    if let Some(addr) = load_host_symbol(&HOST_ERRNO_LOCATION) {
        // SAFETY: the cached address is the host `__errno_location`.
        return Some(unsafe {
            core::mem::transmute::<usize, unsafe extern "C" fn() -> *mut c_int>(addr)
        });
    }

    // Cold: the shared bootstrap skipped us. Spend one of THIS symbol's own
    // attempts. `resolve_host_symbol_raw` reaches the ELF image through raw
    // syscalls (`raw_open`/`raw_fstat`/raw `mmap`), never through fl's own
    // interposed entry points, so this cannot re-enter the errno path.
    let attempt = ERRNO_RESOLVE_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    if attempt > 2 && !attempt.is_power_of_two() {
        return None;
    }
    let addr = resolve_host_symbol_raw("__errno_location").unwrap_or(0);
    if addr == 0 {
        return None;
    }
    HOST_ERRNO_LOCATION.store(addr, Ordering::Release);
    // SAFETY: resolved from the host image's symbol table under that name.
    Some(unsafe { core::mem::transmute::<usize, unsafe extern "C" fn() -> *mut c_int>(addr) })
}

#[inline]
pub(crate) unsafe fn write_host_errno_if_available(val: c_int) {
    let Some(host_errno_location) = host_errno_location_raw() else {
        return;
    };
    // SAFETY: host `__errno_location` returns the thread-local errno pointer when available.
    let ptr = unsafe { host_errno_location() };
    if !ptr.is_null() {
        // SAFETY: non-null pointer returned by host `__errno_location` is writable.
        unsafe { std::ptr::write_volatile(ptr, val) };
    }
}

/// The host `__errno_location` ONLY if it is already cached — never resolves.
///
/// For callers that must not do work: [`crate::runtime_policy::observe`]'s errno
/// guard runs on every adverse call and may not perform an ELF scan, take the
/// image `OnceLock`, or re-enter anything (bd-q1mkwh). A cold cache here is not
/// a problem to solve — if the symbol is not resolved then `set_abi_errno` could
/// not have written the host slot either, so there is nothing to preserve.
#[inline]
pub(crate) fn host_errno_location_cached() -> Option<unsafe extern "C" fn() -> *mut c_int> {
    let addr = HOST_ERRNO_LOCATION.load(Ordering::Acquire);
    (addr != 0).then(|| {
        // SAFETY: a non-zero cache entry is the resolved host `__errno_location`.
        unsafe { core::mem::transmute::<usize, unsafe extern "C" fn() -> *mut c_int>(addr) }
    })
}

/// Get the cached host `dl_iterate_phdr` address (non-blocking, no recursion).
#[inline]
pub(crate) fn host_dl_iterate_phdr_cached() -> Option<usize> {
    let addr = HOST_DL_ITERATE_PHDR.load(Ordering::Acquire);
    (addr != 0).then_some(addr)
}

/// Get the cached host `dladdr` address, lazily bootstrapping the
/// host-symbol cache on first use so callers that run before startup
/// (notably conformance / test harnesses) still resolve correctly.
///
/// bd-oraci: without the bootstrap the cache stays empty, our dladdr
/// always falls through to the "unavailable" branch, and every
/// fixture case comparing against host glibc fails with
/// impl_output="0" vs host_output="nonzero".
#[inline]
pub(crate) fn host_dladdr_cached() -> Option<usize> {
    load_host_symbol(&HOST_DLADDR)
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

#[cfg(test)]
mod tests {
    use std::ffi::c_char;

    use super::{DynamicSymbols, bounded_c_string_len, contains_bytes, find_object_via_link_map};

    #[test]
    fn bounded_c_string_len_accepts_terminated_input() {
        let input = b"/lib/x86_64-linux-gnu/libc.so.6\0ignored";

        let len = unsafe { bounded_c_string_len(input.as_ptr().cast::<c_char>(), input.len()) };

        assert_eq!(len, Some(b"/lib/x86_64-linux-gnu/libc.so.6".len()));
    }

    #[test]
    fn bounded_c_string_len_rejects_unterminated_input() {
        let input = b"/lib/libc.so.6";

        let len = unsafe { bounded_c_string_len(input.as_ptr().cast::<c_char>(), input.len()) };

        assert_eq!(len, None);
    }

    /// The `.gnu.hash` lookup must pick exactly the symbol the linear scan
    /// picks, for every defined name of the real host libc and loader
    /// (including multiply-versioned names such as `memcpy`).
    #[test]
    fn gnu_hash_lookup_matches_linear_scan_for_every_host_symbol() {
        let mut images = 0usize;
        for path in [
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/lib64/ld-linux-x86-64.so.2",
        ] {
            let Ok(data) = std::fs::read(path) else {
                continue;
            };
            let table = DynamicSymbols::parse(&data).expect("parse .dynsym");
            assert!(table.gnu_hash.is_some(), "{path} has no .gnu.hash");
            let mut checked = 0usize;
            for index in 0..table.count() {
                let sym = table.symbol(index).expect("symbol");
                if sym.st_shndx == 0 || sym.st_value == 0 {
                    continue;
                }
                let start = sym.st_name as usize;
                let len = table.strtab[start..]
                    .iter()
                    .position(|byte| *byte == 0)
                    .expect("terminated name");
                let name = &table.strtab[start..start + len];
                let hashed = table.find_defined(name, true).map(|s| s as *const _);
                let linear = table.find_defined(name, false).map(|s| s as *const _);
                assert!(hashed.is_some(), "{path}: {:?} not found via hash", name);
                assert_eq!(
                    hashed,
                    linear,
                    "{path}: {:?}",
                    String::from_utf8_lossy(name)
                );
                checked += 1;
            }
            assert!(checked > 20, "{path}: only {checked} symbols checked");
            assert!(
                table
                    .find_defined(b"no_such_symbol_frankenlibc", true)
                    .is_none()
            );
            assert!(table.find_defined(b"", true).is_none());
            images += 1;
        }
        assert!(images > 0, "no host libc/loader image found to check");
    }

    /// The loaded libc's in-memory tables (found via the link map) resolve
    /// every defined symbol to the same st_value as the on-disk file's.
    #[test]
    fn loaded_tables_match_the_file_for_every_libc_symbol() {
        let (base, path, dynamic) =
            find_object_via_link_map(b"libc.so").expect("libc in this process's link map");
        let path_len = path.iter().position(|&b| b == 0).unwrap();
        let path = std::str::from_utf8(&path[..path_len]).unwrap();
        let data = std::fs::read(path).expect("read libc");
        let file = DynamicSymbols::parse(&data).expect("parse file");
        // SAFETY: libc stays loaded for the life of the test process.
        let (loaded, count) =
            unsafe { DynamicSymbols::from_loaded(base, dynamic, 0) }.expect("loaded tables");
        // A cached count yields the same tables.
        let (cached, cached_count) =
            unsafe { DynamicSymbols::from_loaded(base, dynamic, count) }.expect("cached tables");
        assert_eq!(cached_count, count);
        assert_eq!(cached.count(), loaded.count());
        let mut checked = 0usize;
        for index in 0..file.count() {
            let sym = file.symbol(index).unwrap();
            if sym.st_shndx == 0 || sym.st_value == 0 {
                continue;
            }
            let start = sym.st_name as usize;
            let len = file.strtab[start..].iter().position(|&b| b == 0).unwrap();
            let name = &file.strtab[start..start + len];
            let from_file = file.find_defined(name, true).map(|s| s.st_value);
            let from_memory = loaded.find_defined(name, true).map(|s| s.st_value);
            assert_eq!(
                from_memory,
                from_file,
                "{:?}",
                String::from_utf8_lossy(name)
            );
            checked += 1;
        }
        assert!(checked > 1000, "only {checked} libc symbols checked");
    }

    #[test]
    fn contains_bytes_finds_libc_marker_without_utf8() {
        assert!(contains_bytes(b"/tmp/\xfflibc.so.6", b"libc.so"));
        assert!(!contains_bytes(b"/tmp/libpthread.so.0", b"libc.so"));
    }
}
