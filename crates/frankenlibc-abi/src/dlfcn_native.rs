//! Native mmap-backed DSO groups. File I/O happens before the registry lock;
//! mappings and relocation edges are published only after the whole group binds.
//!
//! Constructors, destructors, TLS and IFUNC execution are deliberately not
//! admitted by this loader yet. No dependency is delegated to the host loader.

use std::cell::RefCell;
use std::ffi::{OsStr, c_int, c_void};
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use frankenlibc_core::dlfcn as dlfcn_core;
use frankenlibc_core::elf::{
    ElfLoader, LoadImage, LoadedObject, PltBindingPolicy, RelocationResult, SymbolLookup,
};
use frankenlibc_core::syscall as raw_syscall;

const HANDLE_TAG: usize = 0x4d;
const HANDLE_MASK: usize = 0xff;
const MAX_GROUP_OBJECTS: usize = 256;

#[derive(Debug)]
struct Mapping {
    base: usize,
    len: usize,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this guard exclusively owns this complete anonymous mapping.
        // It is dropped on rollback or after the last reachable loader root
        // disappears. As with dlclose generally, callers must stop executing
        // code from an object before releasing their last handle to it.
        let _ = unsafe { raw_syscall::sys_munmap(self.base as *mut u8, self.len) };
    }
}

#[derive(Debug)]
struct NativeDso {
    id: usize,
    device: u64,
    inode: u64,
    // Keep the opened inode alive even after unlink/replacement of the path.
    _file: File,
    references: usize,
    nodelete: bool,
    global: bool,
    // DT_NEEDED order is the lookup scope; relocation-only providers are
    // lifetime edges, not additional members of a handle's lookup scope.
    needed: Vec<usize>,
    dependencies: Vec<usize>,
    mapping: Mapping,
    object: LoadedObject,
}

struct PreparedDso {
    file: File,
    device: u64,
    inode: u64,
    bytes: Vec<u8>,
    object: LoadedObject,
    image: LoadImage,
    needed: Vec<usize>,
}

static NATIVE_DSOS: OnceLock<Mutex<Vec<NativeDso>>> = OnceLock::new();
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

fn registry() -> &'static Mutex<Vec<NativeDso>> {
    NATIVE_DSOS.get_or_init(|| Mutex::new(Vec::new()))
}

fn handle(id: usize) -> *mut c_void {
    ((id << 8) | HANDLE_TAG) as *mut c_void
}

pub(super) fn native_dso_id_from_handle(handle: *mut c_void) -> Option<usize> {
    let value = handle as usize;
    (value & HANDLE_MASK == HANDLE_TAG).then_some(value >> 8)
}

#[doc(hidden)]
pub fn native_dso_handle_for_tests(handle: *mut c_void) -> bool {
    let Some(id) = native_dso_id_from_handle(handle) else {
        return false;
    };
    registry()
        .lock()
        .map(|dsos| dsos.iter().any(|dso| dso.id == id))
        .unwrap_or(false)
}

fn next_id() -> Option<usize> {
    NEXT_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
            (id <= (usize::MAX >> 8)).then(|| id + 1)
        })
        .ok()
}

fn open_file(path: &Path) -> Option<(File, u64, u64)> {
    // A FIFO must not block before its type can be checked. Never perform this
    // open, or the subsequent read/parse, while holding the loader registry.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    metadata.is_file().then_some((file, metadata.dev(), metadata.ino()))
}

fn prepare_file(mut file: File, device: u64, inode: u64) -> Option<PreparedDso> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    let loader = ElfLoader::new(0);
    let object = loader.parse(&bytes).ok()?;
    // ET_EXEC cannot be safely relocated as an ordinary shared library.
    if bytes.get(16..18)? != [3, 0].as_slice()
        || object.tls_segment.is_some()
        || object.legacy_init.is_some()
        || object.legacy_fini.is_some()
        || !object.init_array.is_empty()
        || !object.fini_array.is_empty()
        || object.dynsym.iter().any(|symbol| symbol.st_info & 0xf == 10)
        || object.has_unsupported_relocations()
    {
        return None;
    }
    let image = loader.materialize_load_image(&bytes, &object).ok()?;
    if image.low_vaddr != 0 || image.memory.is_empty() {
        return None;
    }
    Some(PreparedDso {
        file, device, inode, bytes, object, image, needed: Vec::new(),
    })
}

fn prepare_group(root: PreparedDso) -> Option<Vec<PreparedDso>> {
    let mut group = vec![root];
    let mut cursor = 0;
    while cursor < group.len() {
        let names = group[cursor].object.needed_libraries.clone();
        let mut needed = Vec::new();
        for name in names {
            // Path-bearing DT_NEEDED entries use the process working directory,
            // not the referring object's directory. SONAME search is separate.
            if !name.as_bytes().contains(&b'/') {
                return None;
            }
            let path = PathBuf::from(name);
            let (file, device, inode) = open_file(&path)?;
            let index = if let Some(index) = group.iter().position(|dso| {
                dso.device == device && dso.inode == inode
            }) {
                index
            } else {
                if group.len() == MAX_GROUP_OBJECTS {
                    return None;
                }
                let dso = prepare_file(file, device, inode)?;
                group.push(dso);
                group.len() - 1
            };
            if !needed.contains(&index) {
                needed.push(index);
            }
        }
        group[cursor].needed = needed;
        cursor += 1;
    }
    Some(group)
}

fn find<'a>(resident: &'a [NativeDso], pending: &'a [NativeDso], id: usize) -> Option<&'a NativeDso> {
    resident.iter().chain(pending).find(|dso| dso.id == id)
}

fn lookup_order(resident: &[NativeDso], pending: &[NativeDso], root: usize) -> Vec<usize> {
    // dlsym(handle) searches breadth-first, not depth-first. Mark on insertion
    // so diamonds and dependency cycles neither duplicate nor reorder entries.
    let mut order = vec![root];
    let mut cursor = 0;
    while cursor < order.len() {
        if let Some(dso) = find(resident, pending, order[cursor]) {
            for &dependency in &dso.needed {
                if !order.contains(&dependency) {
                    order.push(dependency);
                }
            }
        }
        cursor += 1;
    }
    order
}

fn promote_global(dsos: &mut [NativeDso], root: usize) {
    for id in lookup_order(dsos, &[], root) {
        if let Some(dso) = dsos.iter_mut().find(|dso| dso.id == id) {
            dso.global = true;
        }
    }
}

fn reopen(dsos: &mut [NativeDso], index: usize, flags: c_int) -> Option<*mut c_void> {
    let references = dsos[index].references.checked_add(1)?;
    let id = dsos[index].id;
    dsos[index].references = references;
    dsos[index].nodelete |= flags & dlfcn_core::RTLD_NODELETE != 0;
    if flags & dlfcn_core::RTLD_GLOBAL != 0 {
        promote_global(dsos, id);
    }
    Some(handle(id))
}

fn map_object(prepared: &PreparedDso, id: usize, needed: Vec<usize>) -> Option<NativeDso> {
    let file = prepared.file.try_clone().ok()?;
    let len = prepared.image.memory.len();
    // SAFETY: independent anonymous mapping, writable only while relocating.
    let base = unsafe {
        raw_syscall::sys_mmap(
            std::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0,
        )
    }.ok()?;
    let mapping = Mapping { base: base as usize, len };
    // SAFETY: the fresh mapping has exactly len writable bytes and is disjoint
    // from the immutable source Vec. The guard unmaps it on every error path.
    unsafe { core::slice::from_raw_parts_mut(base, len) }
        .copy_from_slice(&prepared.image.memory);
    let object = ElfLoader::new(base as u64).parse(&prepared.bytes).ok()?;
    Some(NativeDso {
        id,
        device: prepared.device,
        inode: prepared.inode,
        _file: file,
        references: 0,
        nodelete: false,
        global: false,
        dependencies: needed.clone(),
        needed,
        mapping,
        object,
    })
}

fn protect_object(dso: &NativeDso, image: &LoadImage) -> Option<()> {
    for segment in &image.segments {
        let offset = usize::try_from(segment.map_addr).ok()?;
        let len = usize::try_from(segment.map_size).ok()?;
        if offset.checked_add(len)? > dso.mapping.len {
            return None;
        }
        let address = dso.mapping.base.checked_add(offset)? as *mut u8;
        // SAFETY: checked range inside this mapping; page alignment and flags
        // come from the validated materialized PT_LOAD image.
        unsafe { raw_syscall::sys_mprotect(address, len, segment.prot) }.ok()?;
    }
    if let Some(range) = &image.relro_range {
        let start = range.start & !0xfff;
        let end = range.end.checked_add(0xfff)? & !0xfff;
        if end > dso.mapping.len {
            return None;
        }
        if end > start {
            let address = dso.mapping.base.checked_add(start)? as *mut u8;
            // SAFETY: page-rounded RELRO range checked against this mapping.
            unsafe { raw_syscall::sys_mprotect(address, end - start, libc::PROT_READ) }.ok()?;
        }
    }
    Some(())
}

struct Resolver<'a> {
    scope: Vec<&'a NativeDso>,
    providers: RefCell<Vec<usize>>,
}

impl SymbolLookup for Resolver<'_> {
    fn lookup(&self, name: &str) -> Option<u64> {
        self.lookup_versioned(name, None)
    }

    fn lookup_versioned(&self, name: &str, version: Option<&str>) -> Option<u64> {
        for dso in &self.scope {
            if let Some(symbol) = dso.object.lookup_symbol_versioned(name, version) {
                let address = symbol.definition_address(dso.object.base)?;
                let mut providers = self.providers.borrow_mut();
                if !providers.contains(&dso.id) {
                    providers.push(dso.id);
                }
                return Some(address);
            }
        }
        if version.is_some_and(|name| !super::version_supported(name.as_bytes())) {
            return None;
        }
        let address = super::resolve_exported_symbol(name.as_bytes());
        (!address.is_null()).then_some(address as u64)
    }
}

fn publish_group(group: &[PreparedDso], flags: c_int) -> Option<*mut c_void> {
    let mut dsos = registry().lock().ok()?;
    // Another opener may have completed while this transaction read its files.
    if let Some(index) = dsos.iter().position(|dso| {
        dso.device == group[0].device && dso.inode == group[0].inode
    }) {
        return reopen(&mut dsos, index, flags);
    }

    // Reuse resident identities, and do not restage the dependencies of an
    // already-loaded object (its original image, not today's file, owns them).
    let mut ids = vec![None; group.len()];
    let mut visit = vec![0];
    let mut new_indexes = Vec::new();
    let mut cursor = 0;
    while cursor < visit.len() {
        let index = visit[cursor];
        if ids[index].is_none() {
            let prepared = &group[index];
            if let Some(dso) = dsos.iter().find(|dso| {
                dso.device == prepared.device && dso.inode == prepared.inode
            }) {
                ids[index] = Some(dso.id);
            } else {
                ids[index] = Some(next_id()?);
                new_indexes.push(index);
                visit.extend(&prepared.needed);
            }
        }
        cursor += 1;
    }

    let root = ids[0]?;
    let mut pending = Vec::new();
    for &index in &new_indexes {
        let needed = group[index].needed.iter()
            .map(|&dependency| ids[dependency])
            .collect::<Option<Vec<_>>>()?;
        pending.push(map_object(&group[index], ids[index]?, needed)?);
    }
    // Every member is mapped before the first relocation. Forward references,
    // siblings and cycles therefore resolve without publishing partial DSOs.
    let local_scope = lookup_order(&dsos, &pending, root);
    let mut edges = Vec::new();
    for dso in &pending {
        let mut scope = dsos.iter().filter(|dso| dso.global).collect::<Vec<_>>();
        for &id in &local_scope {
            if !scope.iter().any(|dso| dso.id == id) {
                scope.push(find(&dsos, &pending, id)?);
            }
        }
        let resolver = Resolver { scope, providers: RefCell::new(Vec::new()) };
        // SAFETY: all pending mappings remain uniquely owned by this
        // transaction, are disjoint and writable, and no callback is invoked.
        let memory = unsafe {
            core::slice::from_raw_parts_mut(dso.mapping.base as *mut u8, dso.mapping.len)
        };
        let report = ElfLoader::new(dso.object.base).apply_relocations_with_policy(
            &dso.object, memory, &resolver, PltBindingPolicy::Eager,
        );
        if !report.events.iter().all(|event| {
            matches!(event.result, RelocationResult::Applied | RelocationResult::Skipped)
        }) {
            return None;
        }
        edges.push(resolver.providers.into_inner());
    }
    for ((dso, providers), &index) in pending.iter_mut().zip(edges).zip(&new_indexes) {
        for provider in providers {
            if provider != dso.id && !dso.dependencies.contains(&provider) {
                dso.dependencies.push(provider);
            }
        }
        protect_object(dso, &group[index].image)?;
    }
    // No resident state has changed before this point. Dropping pending on any
    // failure above rolls back mappings and descriptors, but never providers.
    let root_dso = pending.iter_mut().find(|dso| dso.id == root)?;
    root_dso.references = 1;
    root_dso.nodelete = flags & dlfcn_core::RTLD_NODELETE != 0;
    dsos.extend(pending);
    if flags & dlfcn_core::RTLD_GLOBAL != 0 {
        promote_global(&mut dsos, root);
    }
    Some(handle(root))
}

pub(super) fn load_native_dso(name: &[u8], flags: c_int) -> Option<*mut c_void> {
    let path = Path::new(OsStr::from_bytes(name));
    let (file, device, inode) = open_file(path)?;
    {
        let mut dsos = registry().lock().ok()?;
        if let Some(index) = dsos.iter().position(|dso| dso.device == device && dso.inode == inode) {
            return reopen(&mut dsos, index, flags);
        }
    }
    if flags & dlfcn_core::RTLD_NOLOAD != 0 {
        return None;
    }
    let root = prepare_file(file, device, inode)?;
    let group = prepare_group(root)?;
    publish_group(&group, flags)
}

pub(super) fn resolve_native_dso_symbol(
    handle: *mut c_void,
    symbol_name: &[u8],
    version_name: Option<&[u8]>,
) -> Option<Option<*mut c_void>> {
    let id = native_dso_id_from_handle(handle)?;
    let symbol = std::str::from_utf8(symbol_name).ok()?;
    let version = match version_name {
        Some(bytes) => Some(std::str::from_utf8(bytes).ok()?),
        None => None,
    };
    let dsos = registry().lock().ok()?;
    dsos.iter().find(|dso| dso.id == id)?;
    for candidate in lookup_order(&dsos, &[], id) {
        let dso = dsos.iter().find(|dso| dso.id == candidate)?;
        if let Some(address) = dso.object.lookup_symbol_versioned(symbol, version)
            .and_then(|symbol| symbol.definition_address(dso.object.base))
        {
            return Some(Some(address as *mut c_void));
        }
    }
    Some(None)
}

pub(super) fn close_native_dso(handle: *mut c_void) -> Option<c_int> {
    let id = native_dso_id_from_handle(handle)?;
    let mut dsos = registry().lock().ok()?;
    let dso = dsos.iter_mut().find(|dso| dso.id == id)?;
    if dso.references == 0 {
        return Some(-1);
    }
    dso.references -= 1;
    // Reachability, rather than incoming-edge counts, permits an otherwise
    // unreferenced cycle to unload. NODELETE is a root and pins its closure.
    let mut live = dsos.iter().filter(|dso| dso.references != 0 || dso.nodelete)
        .map(|dso| dso.id).collect::<Vec<_>>();
    let mut cursor = 0;
    while cursor < live.len() {
        if let Some(dso) = dsos.iter().find(|dso| dso.id == live[cursor]) {
            for &dependency in &dso.dependencies {
                if !live.contains(&dependency) {
                    live.push(dependency);
                }
            }
        }
        cursor += 1;
    }
    // retain preserves the remaining global lookup order. The mapping guards
    // perform unmap only after the complete liveness set has been computed.
    dsos.retain(|dso| live.contains(&dso.id));
    Some(0)
}
