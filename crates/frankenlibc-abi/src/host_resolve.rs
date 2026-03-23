//! Raw host symbol resolution — bypasses ALL dynamic linker interposition.
//!
//! Resolves symbols in the host glibc by parsing the in-memory ELF image
//! using only raw syscalls and pointer math. Zero libc calls, zero recursion.

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

static HOST_PTHREAD_CREATE: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_JOIN: AtomicUsize = AtomicUsize::new(0);
static HOST_PTHREAD_DETACH: AtomicUsize = AtomicUsize::new(0);
static RESOLVED: AtomicUsize = AtomicUsize::new(0);

unsafe fn raw_read(fd: i32, buf: *mut u8, count: usize) -> isize {
    unsafe { libc::syscall(libc::SYS_read, fd, buf, count) as isize }
}
unsafe fn raw_open(path: *const u8) -> i32 {
    unsafe { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, path, libc::O_RDONLY, 0) as i32 }
}
unsafe fn raw_close(fd: i32) { unsafe { libc::syscall(libc::SYS_close, fd) }; }

fn find_glibc_base() -> Option<usize> {
    let fd = unsafe { raw_open(b"/proc/self/maps\0".as_ptr()) };
    if fd < 0 { return None; }
    let mut buf = [0u8; 32768];
    let mut total = 0usize;
    loop {
        let n = unsafe { raw_read(fd, buf.as_mut_ptr().add(total), buf.len() - total) };
        if n <= 0 { break; }
        total += n as usize;
        if total >= buf.len() { break; }
    }
    unsafe { raw_close(fd) };
    let text = core::str::from_utf8(&buf[..total]).ok()?;
    for line in text.lines() {
        if !line.contains("libc") || !line.contains(".so") { continue; }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 { continue; }
        if parts[1].starts_with("r--p") && parts[2] == "00000000" {
            let dash = parts[0].find('-')?;
            return usize::from_str_radix(&parts[0][..dash], 16).ok();
        }
    }
    None
}

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_SYMENT: i64 = 11;

#[repr(C)] struct Ehdr { e_ident: [u8; 16], _pad: [u8; 24], e_phoff: u64, _e_shoff: u64, _e_flags: u32, _e_ehsize: u16, e_phentsize: u16, e_phnum: u16, _tail: [u8; 6] }
#[repr(C)] struct Phdr { p_type: u32, _p_flags: u32, _p_offset: u64, p_vaddr: u64, _rest: [u8; 32] }
#[repr(C)] struct Dyn { d_tag: i64, d_val: u64 }
#[repr(C)] struct Sym { st_name: u32, _st_info: u8, _st_other: u8, st_shndx: u16, st_value: u64, _st_size: u64 }

unsafe fn resolve_elf_symbol(base: usize, name: &[u8]) -> usize {
    let ehdr = &*(base as *const Ehdr);
    if ehdr.e_ident[..4] != ELF_MAGIC { return 0; }
    let mut dyn_addr = 0usize;
    for i in 0..ehdr.e_phnum as usize {
        let ph = &*((base + ehdr.e_phoff as usize + i * ehdr.e_phentsize as usize) as *const Phdr);
        if ph.p_type == PT_DYNAMIC { dyn_addr = base + ph.p_vaddr as usize; break; }
    }
    if dyn_addr == 0 { return 0; }
    let (mut symtab, mut strtab, mut syment) = (0usize, 0usize, 24usize);
    let mut dp = dyn_addr;
    loop {
        let d = &*(dp as *const Dyn);
        match d.d_tag { DT_NULL => break, DT_SYMTAB => symtab = d.d_val as usize, DT_STRTAB => strtab = d.d_val as usize, DT_SYMENT => syment = d.d_val as usize, _ => {} }
        dp += 16;
    }
    if symtab == 0 || strtab == 0 { return 0; }
    let max = if strtab > symtab { (strtab - symtab) / syment } else { 10000 };
    for i in 0..max {
        let s = &*((symtab + i * syment) as *const Sym);
        if s.st_shndx == 0 || s.st_value == 0 { continue; }
        let np = (strtab + s.st_name as usize) as *const u8;
        let mut nl = 0; while *np.add(nl) != 0 && nl < 256 { nl += 1; }
        if core::slice::from_raw_parts(np, nl) == name {
            return base + s.st_value as usize;
        }
    }
    0
}

pub(crate) fn bootstrap_host_symbols() {
    if RESOLVED.load(Ordering::Relaxed) != 0 { return; }
    let Some(base) = find_glibc_base() else { return; };
    for (name, cache) in [
        (&b"pthread_create"[..], &HOST_PTHREAD_CREATE),
        (b"pthread_join", &HOST_PTHREAD_JOIN),
        (b"pthread_detach", &HOST_PTHREAD_DETACH),
    ] {
        let a = unsafe { resolve_elf_symbol(base, name) };
        if a != 0 { cache.store(a, Ordering::Release); }
    }
    RESOLVED.store(1, Ordering::Release);
}

pub(crate) fn host_pthread_create_raw() -> Option<
    unsafe extern "C" fn(*mut libc::pthread_t, *const libc::pthread_attr_t,
        Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>, *mut c_void) -> i32>
{
    bootstrap_host_symbols();
    let a = HOST_PTHREAD_CREATE.load(Ordering::Acquire);
    (a != 0).then(|| unsafe { core::mem::transmute(a) })
}
