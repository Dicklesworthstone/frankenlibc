//! Caller-relative native dlopen, using the existing search and group loader.
//!
//! Snapshot immutable search metadata at first load. No reread of a replaced
//! backing file can change the calling object's RPATH/RUNPATH or ORIGIN.
//! A temporary pin retains the caller while file I/O runs without either lock.

use std::ffi::{c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use super::super as abi;
use super::{
    NativeReopen, OPERATIONS, PreparedDso, ResidentPin, SearchContext, SearchPaths, absolute_path,
    dlfcn_core, ifunc, initialize, lookup, native_dso_id_from_handle, open_file, prepare_file,
    prepare_group, process_exit, publish_group, registry, reopen, reopen_native_soname,
};
use crate::runtime_policy;

#[derive(Clone)]
pub(super) struct Metadata {
    origin: PathBuf,
    search: Arc<SearchPaths>,
    // Empty in the resident metadata; filled from live loader ancestry only
    // in the per-call snapshot. A retired parent's path cannot remain active.
    inherited: Vec<PathBuf>,
}

impl std::fmt::Debug for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenMetadata")
            .field("origin", &self.origin)
            .field("inherited", &self.inherited)
            .finish_non_exhaustive()
    }
}

impl Metadata {
    pub(super) fn new(prepared: &PreparedDso) -> Option<Self> {
        Some(Self {
            origin: prepared.path.parent()?.to_owned(),
            search: Arc::clone(&prepared.search),
            inherited: Vec::new(),
        })
    }

    fn snapshot(dsos: &[super::NativeDso], caller: usize) -> Option<Self> {
        let dso = dsos.iter().find(|dso| dso.id == caller)?;
        let mut metadata = dso.open_metadata.clone();
        let mut parent = dso.loader;
        let mut ancestors = Vec::new();
        while let Some(id) = parent {
            let Some(dso) = dsos.iter().find(|dso| dso.id == id) else {
                break;
            };
            if ancestors.contains(&id) || id == caller {
                return None;
            }
            ancestors.push(id);
            parent = dso.loader;
        }
        // Nearest surviving loader's RPATH precedes more distant ancestors.
        // RUNPATH is never inherited. Reopens do not invent a new ancestry.
        for id in ancestors.into_iter().rev() {
            let ancestor = dsos.iter().find(|dso| dso.id == id)?;
            metadata.inherited = ancestor
                .open_metadata
                .search
                .child_rpaths(&metadata.inherited);
        }
        Some(metadata)
    }
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn native_dlopen(_name: *const c_char, _flags: c_int) -> *mut c_void {
    std::arch::naked_asm!("mov rdx, [rsp]", "jmp {entry}", entry = sym entry);
}

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn native_dlopen(_name: *const c_char, _flags: c_int) -> *mut c_void {
    std::arch::naked_asm!("mov x2, x30", "b {entry}", entry = sym entry);
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe extern "C" fn native_dlopen(name: *const c_char, flags: c_int) -> *mut c_void {
    unsafe { entry(name, flags, 0) }
}

pub(super) fn resolver_address() -> u64 {
    native_dlopen as *const () as usize as u64
}

unsafe extern "C" fn entry(name: *const c_char, flags: c_int, caller_pc: usize) -> *mut c_void {
    // SAFETY: the shared bridge preserves the caller's public dlopen arguments.
    unsafe { dispatch(name, flags, caller_pc, None) }
}

pub(super) unsafe extern "C" fn bound_entry(
    name: *const c_char,
    flags: c_int,
    caller_pc: usize,
    origin: usize,
) -> *mut c_void {
    // SAFETY: a per-object bridge supplies immutable origin, with no new frame.
    unsafe { dispatch(name, flags, caller_pc, Some(origin)) }
}

unsafe fn dispatch(
    name: *const c_char,
    flags: c_int,
    caller_pc: usize,
    origin: Option<usize>,
) -> *mut c_void {
    // Pending IFUNC code is not yet in the registry. Reject before caller
    // classification rather than forwarding its unknown PC into host dlopen.
    if ifunc::active() || process_exit::unloading() {
        abi::set_dlerror(dlfcn_core::ERR_NOT_FOUND);
        return std::ptr::null_mut();
    }
    let snapshot = {
        let _operation = OPERATIONS.lock();
        let Ok(mut dsos) = registry().lock() else {
            abi::set_dlerror(dlfcn_core::ERR_NOT_FOUND);
            return std::ptr::null_mut();
        };
        let id = lookup::caller_id(&dsos, caller_pc)
            .or_else(|| origin.filter(|id| dsos.iter().any(|dso| dso.id == *id)));
        match id {
            Some(id) => {
                let Some(metadata) = Metadata::snapshot(&dsos, id) else {
                    abi::set_dlerror(dlfcn_core::ERR_NOT_FOUND);
                    return std::ptr::null_mut();
                };
                let Some(dso) = dsos.iter_mut().find(|dso| dso.id == id) else {
                    abi::set_dlerror(dlfcn_core::ERR_NOT_FOUND);
                    return std::ptr::null_mut();
                };
                let Some(pins) = dso.load_pins.checked_add(1) else {
                    abi::set_dlerror(dlfcn_core::ERR_NOT_FOUND);
                    return std::ptr::null_mut();
                };
                dso.load_pins = pins;
                Some((ResidentPin { id }, metadata))
            }
            None => None,
        }
    };
    let Some((_caller_pin, metadata)) = snapshot else {
        // Missing bound provenance is not permission to search relative to
        // the executable or let a host loader reinterpret a native request.
        if origin.is_some() {
            abi::set_dlerror(dlfcn_core::ERR_NOT_FOUND);
            return std::ptr::null_mut();
        }
        return unsafe { abi::dlopen(name, flags) };
    };
    if !dlfcn_core::valid_flags(flags) {
        abi::set_dlerror(dlfcn_core::ERR_INVALID_FLAGS);
        return std::ptr::null_mut();
    }
    // NULL/empty names keep the public main-program-handle contract.
    if name.is_null() {
        return unsafe { abi::dlopen(name, flags) };
    }
    let Some(name_bytes) = (unsafe { abi::bounded_cstr_bytes(name) }) else {
        abi::set_dlerror(dlfcn_core::ERR_NOT_FOUND);
        return std::ptr::null_mut();
    };
    if name_bytes.is_empty() {
        return unsafe { abi::dlopen(name, flags) };
    }
    let (_, decision) = runtime_policy::decide(ApiFamily::Loader, name as usize, 0, false, true, 0);
    let mut declined = None;
    let result = if matches!(decision.action, MembraneAction::Deny) {
        None
    } else {
        load(name_bytes, flags, Some(&metadata), &mut declined)
    };
    let result = match result {
        Some(handle) => {
            abi::clear_dlerror();
            handle
        }
        None => {
            abi::set_dlerror(dlfcn_core::ERR_NOT_FOUND);
            // Preserve the interpose policy for a selected host-coupled file.
            // Never repeat native relocation/IFUNC execution or ask the host
            // to reinterpret a bare name relative to this Rust wrapper.
            #[cfg(not(feature = "standalone"))]
            if let Some(declined) = declined
                && let Some(path) = declined.host_path()
            {
                abi::NATIVE_PATHNAME_FALLBACKS
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let handle = unsafe { abi::host_dlopen_with_error(path.as_ptr(), flags) };
                runtime_policy::observe(
                    ApiFamily::Loader,
                    decision.profile,
                    12,
                    handle.is_null(),
                );
                return handle;
            }
            std::ptr::null_mut()
        }
    };
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 12, result.is_null());
    result
}

/// Retain the exact selected regular file for fallback classification. The
/// native preparation consumes a cloned descriptor with a shared offset, so
/// classification rewinds only after the failed native transaction has ended.
pub(super) struct Declined {
    #[cfg(not(feature = "standalone"))]
    path: PathBuf,
    #[cfg(not(feature = "standalone"))]
    file: std::fs::File,
    #[cfg(not(feature = "standalone"))]
    device: u64,
    #[cfg(not(feature = "standalone"))]
    inode: u64,
}

#[cfg(not(feature = "standalone"))]
impl Declined {
    fn host_path(mut self) -> Option<std::ffi::CString> {
        use std::io::{Read, Seek, SeekFrom};
        use std::os::unix::ffi::OsStrExt;
        if ifunc::active() || process_exit::unloading() {
            return None;
        }
        // A replaced pathname must not bypass a rejected native image or turn
        // the classification read into a blocking FIFO/device read. The host
        // loader still owns its own final pathname open and error handling.
        let (_, device, inode) = open_file(&self.path)?;
        if (device, inode) != (self.device, self.inode) {
            return None;
        }
        self.file.seek(SeekFrom::Start(0)).ok()?;
        let mut bytes = Vec::new();
        self.file.read_to_end(&mut bytes).ok()?;
        let object = frankenlibc_core::elf::ElfLoader::new(0)
            .parse(&bytes)
            .ok()?;
        if !super::host_may_load_parsed_object(&object) {
            return None;
        }
        std::ffi::CString::new(self.path.as_os_str().as_bytes()).ok()
    }
}

/// Shared native loading path for public and caller-relative entry points.
/// `declined` is populated only for a previously unowned, selected pathname;
/// resident reopen rejection never permits a second host-owned copy. Only the
/// private caller path returns Some(NULL), for an error-free NOLOAD absence.
pub(super) fn load(
    name: &[u8],
    flags: c_int,
    caller: Option<&Metadata>,
    declined: &mut Option<Declined>,
) -> Option<*mut c_void> {
    *declined = None;
    if ifunc::active() || process_exit::unloading() || name.is_empty() || name.contains(&0) {
        return None;
    }
    if !name.contains(&b'/') {
        match reopen_native_soname(name, flags) {
            NativeReopen::Opened(handle) => return Some(handle),
            NativeReopen::Rejected => return None,
            NativeReopen::Missing => {}
        }
    }
    let context = SearchContext::process();
    let candidates = if let Some(caller) = caller {
        caller
            .search
            .candidates(name, &caller.origin, &caller.inherited, &context)?
    } else {
        let executable = std::fs::read_link("/proc/self/exe").ok();
        let origin = executable.as_deref().and_then(Path::parent);
        if origin.is_none() && SearchPaths::requires_origin(name) {
            return None;
        }
        SearchPaths::default().candidates(name, origin.unwrap_or(Path::new("/")), &[], &context)?
    };
    let (path, file, device, inode) = candidates.into_iter().find_map(|candidate| {
        let path = absolute_path(&candidate)?;
        open_file(&path).map(|(file, device, inode)| (path, file, device, inode))
    })?;
    {
        let _operation = OPERATIONS.lock();
        if process_exit::unloading() {
            return None;
        }
        let mut dsos = registry().lock().ok()?;
        if let Some(index) = dsos
            .iter()
            .position(|dso| dso.device == device && dso.inode == inode)
        {
            let handle = reopen(&mut dsos, index, flags)?;
            let id = dsos[index].id;
            drop(dsos);
            initialize(id)?;
            return Some(handle);
        }
    }
    // Public opens retain their existing fallback path. Only the private
    // caller-relative entry needs this exact selected pathname and descriptor.
    #[cfg(not(feature = "standalone"))]
    if caller.is_some() {
        *declined = file.try_clone().ok().map(|file| Declined {
            path: path.clone(),
            file,
            device,
            inode,
        });
    }
    if caller.is_none() && flags & dlfcn_core::RTLD_NOLOAD != 0 {
        return None;
    }
    let root = prepare_file(file, device, inode, &path, &context)?;
    if flags & dlfcn_core::RTLD_NOLOAD != 0 {
        // A valid but absent native object is an error-free NULL result. A
        // host-coupled object must still consult host NOLOAD; it may already
        // be resident in that separate namespace. Never map either here.
        #[cfg(not(feature = "standalone"))]
        if super::host_may_load_parsed_object(&root.object) {
            return None;
        }
        *declined = None;
        return Some(std::ptr::null_mut());
    }
    // dlopen creates an independent load group. Caller RPATH locates its root
    // but must NOT leak into that new root's transitive dependency search.
    // The new object's own RPATH/RUNPATH still govern ordinary DT_NEEDED.
    let group = prepare_group(root, &context)?;
    let _operation = OPERATIONS.lock();
    if process_exit::unloading() {
        return None;
    }
    process_exit::install()?;
    {
        let dsos = registry().lock().ok()?;
        if dsos
            .iter()
            .any(|dso| dso.device == device && dso.inode == inode)
        {
            // Another transaction may have published while file I/O ran.
            // Even if its reopen is rejected, it remains the sole owner.
            *declined = None;
        }
    }
    let result = publish_group(&group, flags)?;
    // Publication has selected the sole native owner. Any later failure must
    // not be rescued by publishing a second copy through the host loader.
    *declined = None;
    initialize(native_dso_id_from_handle(result)?)?;
    Some(result)
}
