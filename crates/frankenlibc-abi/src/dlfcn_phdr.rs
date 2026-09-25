//! Program-header iteration over the owned link map.
//!
//! Snapshot membership and pin every mapping before entering a foreign
//! iterator or callback. Neither native loader lock crosses those calls.
//! Names and C-layout headers belong to the DSO, not the snapshot, so their
//! addresses remain stable until unload. Native TLS IDs name the private
//! native resolver's modules, never entries in the host DTV.

use std::ffi::{c_char, c_int, c_void};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_core::elf::{LoadedObject, ProgramType};

use super::{NATIVE_DSOS, OPERATIONS, ResidentPin, tls};

pub(crate) type Callback =
    unsafe extern "C-unwind" fn(*mut libc::dl_phdr_info, usize, *mut c_void) -> c_int;
pub(crate) type IteratorFn =
    unsafe extern "C-unwind" fn(Option<Callback>, *mut c_void) -> c_int;

// Updated only at publication/retirement, under OPERATIONS and the registry
// mutex. Failed transactions and RTLD_NOLOAD do not invent load events.
static ADDS: AtomicU64 = AtomicU64::new(0);
static SUBS: AtomicU64 = AtomicU64::new(0);

pub(super) fn published(count: usize) {
    let _ = ADDS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(count as u64))
    });
}

pub(super) fn retired(count: usize) {
    let _ = SUBS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(count as u64))
    });
}

pub(super) struct Headers {
    entries: Vec<libc::Elf64_Phdr>,
}

impl std::fmt::Debug for Headers {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Headers").field("count", &self.entries.len()).finish()
    }
}

impl Headers {
    pub(super) fn new(object: &LoadedObject) -> Option<Self> {
        let count = object.program_headers.len();
        if count == 0 || count > u16::MAX as usize { return None; }
        let mut entries = Vec::new();
        entries.try_reserve_exact(count).ok()?;
        for header in &object.program_headers {
            let p_type = match header.p_type {
                ProgramType::Null => 0,
                ProgramType::Load => 1,
                ProgramType::Dynamic => 2,
                ProgramType::Interp => 3,
                ProgramType::Note => 4,
                ProgramType::Shlib => 5,
                ProgramType::Phdr => 6,
                ProgramType::Tls => 7,
                ProgramType::GnuEhFrame => 0x6474_e550,
                ProgramType::GnuStack => 0x6474_e551,
                ProgramType::GnuRelro => 0x6474_e552,
                ProgramType::GnuProperty => 0x6474_e553,
                ProgramType::Unknown(raw) => raw,
            };
            entries.push(libc::Elf64_Phdr {
                p_type, p_flags: header.p_flags.0,
                p_offset: header.p_offset, p_vaddr: header.p_vaddr,
                p_paddr: header.p_paddr, p_filesz: header.p_filesz,
                p_memsz: header.p_memsz, p_align: header.p_align,
            });
        }
        Some(Self { entries })
    }
}

struct Object {
    id: usize,
    base: u64,
    name: *const c_char,
    headers: *const libc::Elf64_Phdr,
    count: u16,
    tls: Option<Arc<tls::Module>>,
}

struct Snapshot {
    objects: Vec<Object>,
    adds: u64,
    subs: u64,
    // Drop after the object metadata. These are lifetime pins, NOT extra
    // dlopen references that a callback can consume by closing a handle.
    _pins: Vec<ResidentPin>,
}

impl Snapshot {
    fn acquire() -> Option<Self> {
        let mut snapshot = Self {
            objects: Vec::new(), _pins: Vec::new(), adds: 0, subs: 0,
        };
        let Some(registry) = NATIVE_DSOS.get() else { return Some(snapshot); };
        let _operation = OPERATIONS.lock();
        let mut dsos = registry.lock().ok()?;
        snapshot.objects.try_reserve_exact(dsos.len()).ok()?;
        snapshot._pins.try_reserve_exact(dsos.len()).ok()?;
        // Complete every fallible operation before constructing a pin: its
        // destructor takes these locks and must never run while we hold them.
        if dsos.iter().any(|dso| dso.load_pins == usize::MAX) { return None; }
        for dso in dsos.iter_mut() {
            snapshot.objects.push(Object {
                id: dso.id, base: dso.object.base, name: dso.name.as_ptr(),
                headers: dso.phdrs.entries.as_ptr(), count: dso.phdrs.entries.len() as u16,
                tls: dso.tls.clone(),
            });
            dso.load_pins += 1;
            snapshot._pins.push(ResidentPin { id: dso.id });
        }
        snapshot.adds = ADDS.load(Ordering::Relaxed);
        snapshot.subs = SUBS.load(Ordering::Relaxed);
        Some(snapshot)
    }
}

struct Prefix {
    callback: Callback,
    data: *mut c_void,
    native_adds: u64,
    native_subs: u64,
    host_adds: u64,
    host_subs: u64,
}

unsafe extern "C-unwind" fn forward_prefix(
    info: *mut libc::dl_phdr_info, size: usize, data: *mut c_void,
) -> c_int {
    // SAFETY: iterate supplies this private stack context for the synchronous
    // prefix iterator. The caller's callback receives only its original data.
    let context = unsafe { &mut *data.cast::<Prefix>() };
    if info.is_null() { return -1; }
    let size = size.min(std::mem::size_of::<libc::dl_phdr_info>());
    // Copy only fields the prefix actually supplies. Never read beyond an
    // older ABI struct or advertise unknown future fields in our local copy.
    let mut copy: libc::dl_phdr_info = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(info.cast::<u8>(), (&raw mut copy).cast::<u8>(), size);
    }
    if size >= std::mem::offset_of!(libc::dl_phdr_info, dlpi_adds) + 8 {
        context.host_adds = copy.dlpi_adds;
        copy.dlpi_adds = copy.dlpi_adds.saturating_add(context.native_adds);
    }
    if size >= std::mem::offset_of!(libc::dl_phdr_info, dlpi_subs) + 8 {
        context.host_subs = copy.dlpi_subs;
        copy.dlpi_subs = copy.dlpi_subs.saturating_add(context.native_subs);
    }
    // SAFETY: valid callback/data supplied to the public ABI; metadata backing
    // the prefix's pointer fields remains owned by that synchronous iterator.
    unsafe { (context.callback)(&mut copy, size, context.data) }
}

/// Visit the existing host/startup prefix, then native objects in load order.
/// A nonzero callback result stops BOTH parts. RAII releases all pins on normal
/// return, early termination and C-unwind, after the prefix's locks unwind.
///
/// # Safety
/// Callback and data obey dl_iterate_phdr's ABI. The optional prefix is a
/// trusted synchronous iterator with that same callback contract.
pub(crate) unsafe fn iterate(
    callback: Option<Callback>, data: *mut c_void, prefix: Option<IteratorFn>,
) -> c_int {
    let Some(callback) = callback else { return 0; };
    let Some(snapshot) = Snapshot::acquire() else { return -1; };
    let mut context = Prefix {
        callback, data, native_adds: snapshot.adds, native_subs: snapshot.subs,
        host_adds: 0, host_subs: 0,
    };
    if let Some(prefix) = prefix {
        // No operation/registry lock is held while entering the host loader.
        let result = unsafe { prefix(Some(forward_prefix), (&raw mut context).cast()) };
        if result != 0 { return result; }
    }
    for object in &snapshot.objects {
        let (module, tls_data) = match &object.tls {
            Some(module) => (object.id, tls::allocated_address(module)),
            None => (0, std::ptr::null_mut()),
        };
        let mut info = libc::dl_phdr_info {
            dlpi_addr: object.base, dlpi_name: object.name,
            dlpi_phdr: object.headers, dlpi_phnum: object.count,
            dlpi_adds: context.host_adds.saturating_add(snapshot.adds),
            dlpi_subs: context.host_subs.saturating_add(snapshot.subs),
            dlpi_tls_modid: module, dlpi_tls_data: tls_data,
        };
        // All snapshot mappings stay pinned, including objects not visited
        // yet. A nested/concurrent close cannot invalidate these pointers.
        let result = unsafe { callback(&mut info, std::mem::size_of::<libc::dl_phdr_info>(), data) };
        if result != 0 { return result; }
    }
    0
}
