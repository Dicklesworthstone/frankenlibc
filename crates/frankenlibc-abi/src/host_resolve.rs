//! Raw host symbol resolution — bypasses ALL dynamic linker interposition.
//!
//! This module resolves symbols in the host glibc by:
//! 1. Reading `/proc/self/maps` via raw `SYS_read` to find glibc's base address
//! 2. Parsing the in-memory ELF headers to find the `.dynsym`/`.dynstr` tables
//! 3. Looking up symbol names and computing absolute addresses
//!
//! Zero libc calls. Zero interposition. Zero recursion. Pure syscalls + pointer math.

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

// Cached host function pointers — resolved once, used forever.
static HOST_PTHREAD_CREATE: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_JOIN: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_DETACH: AtomicUsize = AtomicUsize::new(0);
static HOST_DLOPEN: AtomicUsize = AtomicUsize::new(0);
static HOST_DLSYM: AtomicUsize = AtomicUsize::new(0);
static HOST_DLVSYM: AtomicUsize = AtomicUsize::new(0);
static HOST_DLCLOSE: AtomicUsize = AtomicUsize::new(0);
static RESOLVED: AtomicUsize = AtomicUsize::new(0);

/// Raw read from fd using SYS_read. No libc involvement.
unsafe fn raw_read(fd: i32, buf: *mut u8, count: usize) -> isize {
    unsafe { libc::syscall(libc::SYS_read, fd, buf, count) as isize }
}

/// Raw open using SYS_openat. No libc involvement.
unsafe fn raw_open(path: *const u8) -> i32 {
    unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            path,
            libc::O_RDONLY,
            0,
        ) as i32
    }
}

/// Raw close using SYS_close.
unsafe fn raw_close(fd: i32) {
    unsafe { libc::syscall(libc::SYS_close, fd) };
}

/// Find glibc's base address and file path by parsing /proc/self/maps.
/// Returns (base_addr, r-xp_base) or None.
fn find_glibc_base() -> Option<(usize, usize)> {
    let fd = unsafe { raw_open(b"/proc/self/maps\0".as_ptr()) };
    if fd < 0 {
        return None;
    }

    let mut buf = [0u8; 8192];
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

    // Find the r--p (ELF headers) and r-xp (executable) mappings of libc.so.6
    let mut elf_base = None;
    let mut exec_base = None;

    for line in text.lines() {
        if !line.contains("libc") || !line.contains(".so") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        let addr_range = parts[0];
        let perms = parts[1];
        let offset = parts[2];

        let dash = addr_range.find('-')?;
        let start = usize::from_str_radix(&addr_range[..dash], 16).ok()?;

        if perms.starts_with("r--p") && offset == "00000000" && elf_base.is_none() {
            elf_base = Some(start);
        }
        if perms.starts_with("r-xp") && exec_base.is_none() {
            exec_base = Some(start);
        }

        if elf_base.is_some() && exec_base.is_some() {
            break;
        }
    }

    Some((elf_base?, exec_base?))
}

// ELF64 structures (minimal, for symbol lookup only)
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const SHT_DYNSYM: u32 = 11;
const SHT_STRTAB: u32 = 3;

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

/// Resolve a symbol from the in-memory glibc ELF image.
/// `elf_base` is the address where the ELF headers are mapped (r--p region).
/// Returns the absolute address of the symbol, or 0 if not found.
unsafe fn resolve_elf_symbol(elf_base: usize, symbol_name: &[u8]) -> usize {
    let ehdr = &*(elf_base as *const Elf64Ehdr);

    // Verify ELF magic
    if ehdr.e_ident[..4] != ELF_MAGIC {
        return 0;
    }

    let shdr_base = elf_base + ehdr.e_shoff as usize;
    let shdr_count = ehdr.e_shnum as usize;
    let shdr_size = ehdr.e_shentsize as usize;

    // Find .dynsym and its linked .dynstr
    let mut dynsym_shdr: Option<&Elf64Shdr> = None;
    let mut dynstr_shdr: Option<&Elf64Shdr> = None;

    for i in 0..shdr_count {
        let shdr = &*((shdr_base + i * shdr_size) as *const Elf64Shdr);
        if shdr.sh_type == SHT_DYNSYM && dynsym_shdr.is_none() {
            dynsym_shdr = Some(shdr);
            // The linked section (sh_link) is the string table
            if (shdr.sh_link as usize) < shdr_count {
                let strtab =
                    &*((shdr_base + shdr.sh_link as usize * shdr_size) as *const Elf64Shdr);
                if strtab.sh_type == SHT_STRTAB {
                    dynstr_shdr = Some(strtab);
                }
            }
        }
    }

    let Some(dynsym) = dynsym_shdr else { return 0 };
    let Some(dynstr) = dynstr_shdr else { return 0 };

    // The section addresses (sh_addr) are relative to the ELF base.
    // Since glibc is mapped with headers at elf_base, we use elf_base + sh_addr.
    let sym_table = elf_base + dynsym.sh_addr as usize;
    let str_table = elf_base + dynstr.sh_addr as usize;
    let sym_count = dynsym.sh_size as usize / core::mem::size_of::<Elf64Sym>();

    for i in 0..sym_count {
        let sym = &*((sym_table + i * core::mem::size_of::<Elf64Sym>()) as *const Elf64Sym);

        // Skip undefined symbols
        if sym.st_shndx == 0 || sym.st_value == 0 {
            continue;
        }

        // Get symbol name
        let name_ptr = (str_table + sym.st_name as usize) as *const u8;
        let mut name_len = 0usize;
        while *name_ptr.add(name_len) != 0 && name_len < 256 {
            name_len += 1;
        }
        let name = core::slice::from_raw_parts(name_ptr, name_len);

        if name == symbol_name {
            // Symbol value is relative to ELF base
            return elf_base + sym.st_value as usize;
        }
    }

    0
}

/// Bootstrap: resolve all critical host symbols from the in-memory glibc ELF.
/// Called once during early startup. Uses ONLY raw syscalls and pointer math.
pub(crate) fn bootstrap_host_symbols() {
    if RESOLVED.load(Ordering::Relaxed) != 0 {
        return;
    }

    let Some((elf_base, _exec_base)) = find_glibc_base() else {
        return;
    };

    // Resolve critical symbols
    let symbols: &[(&[u8], &AtomicUsize)] = &[
        (b"pthread_create", &HOST_PTHREAD_CREATE),
        (b"pthread_join", &HOST_PTHREAD_JOIN),
        (b"pthread_detach", &HOST_PTHREAD_DETACH),
        (b"dlopen", &HOST_DLOPEN),
        (b"dlsym", &HOST_DLSYM),
        (b"dlvsym", &HOST_DLVSYM),
        (b"dlclose", &HOST_DLCLOSE),
    ];

    for (name, cache) in symbols {
        let addr = unsafe { resolve_elf_symbol(elf_base, name) };
        if addr != 0 {
            cache.store(addr, Ordering::Release);
        }
    }

    RESOLVED.store(1, Ordering::Release);
}

/// Get the host glibc's pthread_create function pointer.
pub(crate) fn host_pthread_create_raw() -> Option<
    unsafe extern "C" fn(
        *mut libc::pthread_t,
        *const libc::pthread_attr_t,
        Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>,
        *mut c_void,
    ) -> i32,
> {
    bootstrap_host_symbols();
    let addr = HOST_PTHREAD_CREATE.load(Ordering::Acquire);
    if addr != 0 {
        Some(unsafe { core::mem::transmute(addr) })
    } else {
        None
    }
}

/// Get the host glibc's pthread_join function pointer.
pub(crate) fn host_pthread_join_raw(
) -> Option<unsafe extern "C" fn(libc::pthread_t, *mut *mut c_void) -> i32> {
    bootstrap_host_symbols();
    let addr = HOST_PTHREAD_JOIN.load(Ordering::Acquire);
    if addr != 0 {
        Some(unsafe { core::mem::transmute(addr) })
    } else {
        None
    }
}

/// Get the host glibc's pthread_detach function pointer.
pub(crate) fn host_pthread_detach_raw() -> Option<unsafe extern "C" fn(libc::pthread_t) -> i32> {
    bootstrap_host_symbols();
    let addr = HOST_PTHREAD_DETACH.load(Ordering::Acquire);
    if addr != 0 {
        Some(unsafe { core::mem::transmute(addr) })
    } else {
        None
    }
}

/// Get the host glibc's dlopen function pointer.
pub(crate) fn host_dlopen_raw(
) -> Option<unsafe extern "C" fn(*const i8, i32) -> *mut c_void> {
    bootstrap_host_symbols();
    let addr = HOST_DLOPEN.load(Ordering::Acquire);
    if addr != 0 {
        Some(unsafe { core::mem::transmute(addr) })
    } else {
        None
    }
}

/// Get the host glibc's dlsym function pointer.
pub(crate) fn host_dlsym_raw(
) -> Option<unsafe extern "C" fn(*mut c_void, *const i8) -> *mut c_void> {
    bootstrap_host_symbols();
    let addr = HOST_DLSYM.load(Ordering::Acquire);
    if addr != 0 {
        Some(unsafe { core::mem::transmute(addr) })
    } else {
        None
    }
}
