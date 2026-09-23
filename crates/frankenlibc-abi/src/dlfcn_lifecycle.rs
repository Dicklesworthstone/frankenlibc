//! Native ELF DT_INIT/DT_FINI and relocated init/fini arrays.
//!
//! Dynamic tags, not section names, are authoritative. Validate every callback
//! in the entire transaction before executing any user code. ELF gABI 8.6:
//! INIT precedes INIT_ARRAY; FINI_ARRAY runs backwards, then FINI.

use std::ffi::{c_char, c_int};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use frankenlibc_core::elf::{LoadedObject, ProgramType};

use super::NativeDso;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Layout {
    init: Option<u64>,
    fini: Option<u64>,
    init_array: Option<u64>,
    init_size: Option<u64>,
    fini_array: Option<u64>,
    fini_size: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct Callbacks {
    pub(super) init: Vec<usize>,
    pub(super) fini: Vec<usize>,
}

// On GNU/Linux the ELF initializer receives the real process argument vectors.
// Store only integers during startup: no allocation, locks, or libc calls. In
// debug integration tests this initializer belongs to the test executable; in
// the deployed cdylib it runs when the surrounding loader initializes us.
static ARGC: AtomicI32 = AtomicI32::new(0);
static ARGV: AtomicUsize = AtomicUsize::new(0);
static ENVP: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn capture_arguments(
    argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char,
) {
    ARGC.store(argc, Ordering::Relaxed);
    ENVP.store(envp as usize, Ordering::Relaxed);
    ARGV.store(argv as usize, Ordering::Release);
}

#[used]
#[unsafe(link_section = ".init_array")]
static CAPTURE_ARGUMENTS: unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) =
    capture_arguments;

pub(super) unsafe fn call_init(address: usize) {
    let argv = ARGV.load(Ordering::Acquire) as *mut *mut c_char;
    let argc = ARGC.load(Ordering::Relaxed);
    let envp = ENVP.load(Ordering::Relaxed) as *mut *mut c_char;
    // SAFETY: the caller validated an executable native ELF address and pins
    // its mapping plus dependencies for the full invocation. GNU/Linux init
    // callbacks accept these arguments; ordinary void constructors ignore them.
    let callback: unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) =
        unsafe { std::mem::transmute(address) };
    unsafe { callback(argc, argv, envp) };
}

pub(super) unsafe fn call_fini(address: usize) {
    // SAFETY: same executable-address and mapping-lifetime contract as call_init.
    let callback: unsafe extern "C" fn() = unsafe { std::mem::transmute(address) };
    unsafe { callback() };
}

fn set_once(slot: &mut Option<u64>, value: u64) -> Option<()> {
    if slot.is_some_and(|old| old != value) { return None; }
    *slot = Some(value);
    Some(())
}

impl Layout {
    pub(super) fn parse(bytes: &[u8], object: &LoadedObject) -> Option<Self> {
        let mut result = Self::default();
        for header in &object.program_headers {
            if header.p_type != ProgramType::Dynamic { continue; }
            let start = usize::try_from(header.p_offset).ok()?;
            let size = usize::try_from(header.p_filesz).ok()?;
            let entries = bytes.get(start..start.checked_add(size)?)?;
            if entries.len() % 16 != 0 { return None; }
            let mut terminated = false;
            for entry in entries.chunks_exact(16) {
                let tag = i64::from_le_bytes(entry[..8].try_into().ok()?);
                let value = u64::from_le_bytes(entry[8..].try_into().ok()?);
                match tag {
                    0 => { terminated = true; break; }
                    12 => set_once(&mut result.init, value)?,
                    13 => set_once(&mut result.fini, value)?,
                    25 => set_once(&mut result.init_array, value)?,
                    26 => set_once(&mut result.fini_array, value)?,
                    27 => set_once(&mut result.init_size, value)?,
                    28 => set_once(&mut result.fini_size, value)?,
                    // PREINIT_ARRAY is not permitted in a shared object.
                    32 | 33 if value != 0 => return None,
                    _ => {}
                }
            }
            if !terminated { return None; }
        }
        validate_array(result.init_array, result.init_size)?;
        validate_array(result.fini_array, result.fini_size)?;
        Some(result)
    }

    pub(super) fn resolve(&self, dso: &NativeDso) -> Option<Callbacks> {
        let mut init = Vec::new();
        let mut fini = read_array(dso, self.fini_array, self.fini_size)?;
        fini.reverse();
        if let Some(offset) = self.init.filter(|offset| *offset != 0) {
            init.push(dso.mapping.base.checked_add(usize::try_from(offset).ok()?)?);
        }
        init.extend(read_array(dso, self.init_array, self.init_size)?);
        if let Some(offset) = self.fini.filter(|offset| *offset != 0) {
            fini.push(dso.mapping.base.checked_add(usize::try_from(offset).ok()?)?);
        }
        Some(Callbacks { init, fini })
    }
}

fn validate_array(address: Option<u64>, size: Option<u64>) -> Option<()> {
    match (address, size) {
        (None, None | Some(0)) => Some(()),
        (Some(_), Some(size)) if size % 8 == 0 && size <= 8 * 65536 => Some(()),
        _ => None,
    }
}

fn read_array(dso: &NativeDso, address: Option<u64>, size: Option<u64>) -> Option<Vec<usize>> {
    validate_array(address, size)?;
    let size = usize::try_from(size.unwrap_or(0)).ok()?;
    if size == 0 { return Some(Vec::new()); }
    let offset = usize::try_from(address?).ok()?;
    let end = offset.checked_add(size)?;
    if end > dso.mapping.len || !dso.object.program_headers.iter().any(|header| {
        header.is_load() && header.p_flags.0 & 4 != 0
            && header.p_vaddr <= offset as u64
            && header.p_vaddr.checked_add(header.p_memsz).is_some_and(|limit| end as u64 <= limit)
    }) { return None; }
    let start = dso.mapping.base.checked_add(offset)?;
    let mut callbacks = Vec::with_capacity(size / 8);
    for offset in (0..size).step_by(8) {
        // SAFETY: checked readable PT_LOAD range of this unpublished mapping.
        // Read after relocation, never from the original file's array values.
        let address = unsafe { std::ptr::read_unaligned((start + offset) as *const usize) };
        if address != 0 && address != usize::MAX { callbacks.push(address); }
    }
    Some(callbacks)
}

pub(super) fn executable_address(dso: &NativeDso, address: usize) -> bool {
    let Some(offset) = address.checked_sub(dso.mapping.base) else { return false; };
    offset < dso.mapping.len && dso.object.program_headers.iter().any(|header| {
        header.is_load() && header.p_flags.0 & 1 != 0 && header.p_vaddr <= offset as u64
            && header.p_vaddr.checked_add(header.p_memsz).is_some_and(|end| (offset as u64) < end)
    })
}
