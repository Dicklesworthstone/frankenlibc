//! Native mmap-backed DSO groups. File I/O happens before the registry lock;
//! mappings and relocation edges are published only after the whole group binds.
//!
//! Native constructors/destructors run outside the registry mutex, under a
//! reentrant operation lock. General-/local-dynamic TLS, GNU2 TLSDESC and eager
//! IFUNC are owned here; initial-exec TLS remains unsupported.
//! No dependency is delegated to the host loader.

use std::cell::RefCell;
use std::ffi::{CString, OsStr, c_int, c_void};
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use frankenlibc_core::dlfcn as dlfcn_core;
use frankenlibc_core::elf::{
    Elf64Rela, ElfLoader, LoadImage, LoadedObject, PltBindingPolicy, ProgramType,
    RelocationResult, SymbolLookup,
};
use frankenlibc_core::syscall as raw_syscall;

#[path = "dlfcn_search.rs"]
mod search;
use search::{SearchContext, SearchPaths};

#[path = "dlfcn_lifecycle.rs"]
mod lifecycle;

#[path = "dlfcn_tls.rs"]
mod tls;

#[path = "dlfcn_thread_exit.rs"]
mod thread_exit;

#[path = "dlfcn_ifunc.rs"]
mod ifunc;

#[path = "dlfcn_binding.rs"]
mod binding;

#[path = "dlfcn_versions.rs"]
mod versions;

#[path = "dlfcn_cxa.rs"]
mod cxa;

#[path = "dlfcn_process_exit.rs"]
mod process_exit;

#[path = "dlfcn_inspection.rs"]
mod inspection;
pub(super) use inspection::address_info as native_address_info;

// Lock order: operation lock -> registry. The operation lock is recursive for
// same-thread constructor/finalizer reentry; other threads cannot observe a
// partially initialized object. No registry guard crosses a user callback.
static OPERATIONS: parking_lot::ReentrantMutex<()> = parking_lot::ReentrantMutex::new(());

// All accesses occur under OPERATIONS. Nested dlclose calls update reference
// counts, but only the outer collector runs finalizers and retires mappings.
static COLLECTING: AtomicBool = AtomicBool::new(false);
struct CollectionGuard;
impl Drop for CollectionGuard {
    fn drop(&mut self) { COLLECTING.store(false, Ordering::Relaxed); }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitState { Pending, Running, Live }


const HANDLE_TAG: usize = 0x4d;
const HANDLE_MASK: usize = 0xff;
const MAX_GROUP_OBJECTS: usize = 256;
const DF_1_NODELETE: u64 = 0x8;
const DF_1_NOOPEN: u64 = 0x40;
const DF_1_PIE: u64 = 0x0800_0000;

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
    // dladdr strings must outlive a lookup and retain the requested pathname.
    name: CString,
    references: usize,
    // In-flight dependency staging retains mappings without inventing public
    // dlopen references that a concurrent dlclose could consume.
    load_pins: usize,
    nodelete: bool,
    global: bool,
    // Global visibility is ordered by promotion, not original mapping time.
    global_rank: usize,
    symbolic: bool,
    // DT_NEEDED order is the lookup scope; relocation-only providers are
    // lifetime edges, not additional members of a handle's lookup scope.
    needed: Vec<usize>,
    needed_by_name: Vec<(String, usize)>,
    dependencies: Vec<usize>,
    mapping: Mapping,
    object: LoadedObject,
    versions: versions::Table,
    callbacks: lifecycle::Callbacks,
    tls: Option<Arc<tls::Module>>,
    tls_relocations: Vec<Elf64Rela>,
    tls_descriptors: tls::Descriptors,
    thread_exit_pins: usize,
    state: InitState,
    initialized_at: usize,
    retiring: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dependency {
    Prepared(usize),
    Resident(usize),
}

// A prepared transaction owns these guards until publication or rollback.
// Releasing the last staging pin must collect a provider whose final public
// handle was closed during file I/O, including after a failed consumer load.
struct ResidentPin {
    id: usize,
}

impl Drop for ResidentPin {
    fn drop(&mut self) {
        let _operation = OPERATIONS.lock();
        let Ok(mut dsos) = registry().lock() else { return; };
        if let Some(dso) = dsos.iter_mut().find(|dso| dso.id == self.id) {
            let Some(pins) = dso.load_pins.checked_sub(1) else { return; };
            dso.load_pins = pins;
        }
        drop(dsos);
        // Process teardown owns its own finalization order. Otherwise this
        // may invoke callbacks, so neither registry nor file I/O is held.
        if !process_exit::unloading() {
            let _ = collect_unreachable();
        }
    }
}

struct PreparedDso {
    file: File,
    device: u64,
    inode: u64,
    bytes: Vec<u8>,
    object: LoadedObject,
    image: LoadImage,
    flags: u64,
    needed: Vec<Dependency>,
    needed_by_name: Vec<(String, Dependency)>,
    resident_pins: Vec<ResidentPin>,
    path: PathBuf,
    search: SearchPaths,
    inherited_rpaths: Vec<PathBuf>,
    lifecycle: lifecycle::Layout,
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

fn absolute_path(path: &Path) -> Option<PathBuf> {
    if path.is_absolute() { Some(path.to_owned()) }
    else { Some(std::env::current_dir().ok()?.join(path)) }
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

// Read runtime metadata rather than section headers: stripped objects retain
// their load restrictions. Reject ambiguous/truncated dynamic segments before
// mapping, TLS allocation, IFUNC execution, or constructor side effects.
fn dynamic_flags(bytes: &[u8], object: &LoadedObject) -> Option<u64> {
    let mut headers = object.program_headers.iter()
        .filter(|header| header.p_type == ProgramType::Dynamic);
    let Some(header) = headers.next() else { return Some(0); };
    if headers.next().is_some() || header.p_filesz > header.p_memsz { return None; }
    if !object.program_headers.iter().any(|load| {
        if !load.is_load() { return false; }
        let Some(delta) = header.p_vaddr.checked_sub(load.p_vaddr) else { return false; };
        load.p_offset.checked_add(delta) == Some(header.p_offset)
            && delta.checked_add(header.p_filesz).is_some_and(|end| end <= load.p_filesz)
    }) { return None; }
    let offset = usize::try_from(header.p_offset).ok()?;
    let size = usize::try_from(header.p_filesz).ok()?;
    if size % 16 != 0 { return None; }
    let mut flags = None;
    for entry in bytes.get(offset..offset.checked_add(size)?)?.chunks_exact(16) {
        let tag = i64::from_le_bytes(entry[..8].try_into().ok()?);
        let value = u64::from_le_bytes(entry[8..].try_into().ok()?);
        if tag == 0 { return Some(flags.unwrap_or(0)); }
        if tag == 0x6fff_fffb {
            if flags.is_some_and(|old| old != value) { return None; }
            flags = Some(value);
        }
    }
    None
}

fn prepare_file(mut file: File, device: u64, inode: u64, requested_path: &Path, context: &SearchContext) -> Option<PreparedDso> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    let loader = ElfLoader::new(0);
    let object = loader.parse(&bytes).ok()?;
    // ET_EXEC cannot be safely relocated as an ordinary shared library.
    if bytes.get(16..18)? != [3, 0].as_slice()
        || tls::validate(&object, &bytes).is_none()
    {
        return None;
    }
    let flags = dynamic_flags(&bytes, &object)?;
    // PIE also has ET_DYN, but is not a dlopen-able shared library. NOOPEN
    // applies to dependencies as well as the explicitly requested root.
    if flags & (DF_1_NOOPEN | DF_1_PIE) != 0 { return None; }
    let lifecycle = lifecycle::Layout::parse(&bytes, &object)?;
    let image = loader.materialize_load_image(&bytes, &object).ok()?;
    if image.low_vaddr != 0 || image.memory.is_empty() {
        return None;
    }
    // $ORIGIN follows the name used to load this object, not the symlink
    // target. Identity still comes from the retained descriptor. Callers make
    // the requested pathname absolute before opening, so a later chdir cannot
    // rebase its relative directory while parsing or staging dependencies.
    let path = requested_path.to_owned();
    let search = SearchPaths::parse(&bytes, &object, path.parent()?, context.secure)?;
    Some(PreparedDso {
        file, device, inode, bytes, object, image, flags, needed: Vec::new(),
        needed_by_name: Vec::new(), resident_pins: Vec::new(),
        path, search, inherited_rpaths: Vec::new(), lifecycle,
    })
}

// Match the resident link map BEFORE filesystem search. A loaded SONAME (or
// an established DT_NEEDED alias) remains usable after rename/unlink or package
// replacement. For path aliases, an opened inode can identify the same image.
// Some(None) means absent; None means the transaction cannot safely continue.
fn pin_resident_dependency(name: &str, identity: Option<(u64, u64)>) -> Option<Option<ResidentPin>> {
    let _operation = OPERATIONS.lock();
    if process_exit::unloading() { return None; }
    let mut dsos = registry().lock().ok()?;
    let index = dsos.iter().position(|dso| {
        if dso.retiring { return false; }
        if let Some((device, inode)) = identity {
            return dso.device == device && dso.inode == inode;
        }
        dso.object.soname.as_deref() == Some(name)
            || dsos.iter().any(|consumer| {
                !consumer.retiring && consumer.needed_by_name.iter()
                    .any(|(alias, id)| alias == name && *id == dso.id)
            })
    });
    let Some(index) = index else { return Some(None); };
    let dso = &mut dsos[index];
    dso.load_pins = dso.load_pins.checked_add(1)?;
    Some(Some(ResidentPin { id: dso.id }))
}

fn prepare_group(root: PreparedDso, context: &SearchContext) -> Option<Vec<PreparedDso>> {
    let mut group = vec![root];
    let mut cursor = 0;
    while cursor < group.len() {
        let names = group[cursor].object.needed_libraries.clone();
        let mut needed = Vec::new();
        let mut needed_by_name = Vec::new();
        for name in names {
            if !name.as_bytes().contains(&b'/') {
                if let Some(pin) = pin_resident_dependency(&name, None)? {
                    let dependency = Dependency::Resident(pin.id);
                    group[cursor].resident_pins.push(pin);
                    if !needed.contains(&dependency) { needed.push(dependency); }
                    needed_by_name.push((name, dependency));
                    continue;
                }
                if let Some(index) = group.iter().position(|dso| dso.object.soname.as_deref() == Some(name.as_str())) {
                    let dependency = Dependency::Prepared(index);
                    if !needed.contains(&dependency) { needed.push(dependency); }
                    needed_by_name.push((name, dependency));
                    continue;
                }
            }
            let parent = &group[cursor];
            let candidates = parent.search.candidates(name.as_bytes(), parent.path.parent()?, &parent.inherited_rpaths, context)?;
            let inherited = parent.search.child_rpaths(&parent.inherited_rpaths);
            let (path, file, device, inode) = candidates.into_iter().find_map(|path| {
                let path = absolute_path(&path)?;
                open_file(&path).map(|(file, device, inode)| (path, file, device, inode))
            })?;
            if let Some(pin) = pin_resident_dependency(&name, Some((device, inode)))? {
                let dependency = Dependency::Resident(pin.id);
                group[cursor].resident_pins.push(pin);
                if !needed.contains(&dependency) { needed.push(dependency); }
                needed_by_name.push((name, dependency));
                continue;
            }
            let index = if let Some(index) = group.iter().position(|dso| {
                dso.device == device && dso.inode == inode
            }) {
                index
            } else {
                if group.len() == MAX_GROUP_OBJECTS {
                    return None;
                }
                let mut dso = prepare_file(file, device, inode, &path, context)?;
                dso.inherited_rpaths = inherited;
                group.push(dso);
                group.len() - 1
            };
            let dependency = Dependency::Prepared(index);
            if !needed.contains(&dependency) {
                needed.push(dependency);
            }
            needed_by_name.push((name, dependency));
        }
        group[cursor].needed = needed;
        group[cursor].needed_by_name = needed_by_name;
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

// Must be called with the registry locked. No additional lock or callback
// is involved, so relocation, TLS and IFUNC see one consistent global order.
fn global_scope_order(dsos: &[NativeDso]) -> Vec<usize> {
    let mut globals = dsos.iter().filter(|dso| dso.global && !dso.retiring)
        .map(|dso| (dso.global_rank, dso.id)).collect::<Vec<_>>();
    globals.sort_unstable();
    globals.into_iter().map(|(_, id)| id).collect()
}

fn promote_global(dsos: &mut [NativeDso], root: usize) {
    // A LOCAL object can predate every GLOBAL object. Promoting it appends
    // its BFS dependency closure; it must not jump ahead of existing globals.
    let mut order = global_scope_order(dsos);
    for id in lookup_order(dsos, &[], root) {
        if !order.contains(&id) { order.push(id); }
    }
    // Compact ranks after unload. Ranks are bounded by resident count, so
    // repeated opens cannot overflow a process-lifetime sequence counter.
    for (rank, id) in order.into_iter().enumerate() {
        if let Some(dso) = dsos.iter_mut().find(|dso| dso.id == id && !dso.retiring) {
            dso.global = true;
            dso.global_rank = rank;
        }
    }
}

fn reopen(dsos: &mut [NativeDso], index: usize, flags: c_int) -> Option<*mut c_void> {
    // Resurrection during a finalization batch is deliberately rejected. Its
    // dependency closure is pinned for callbacks, but is no longer admissible
    // for new consumers. Never return a soon-to-be-unmapped successful handle.
    if dsos[index].retiring { return None; }
    let references = dsos[index].references.checked_add(1)?;
    let id = dsos[index].id;
    dsos[index].references = references;
    dsos[index].nodelete |= flags & dlfcn_core::RTLD_NODELETE != 0;
    if flags & dlfcn_core::RTLD_GLOBAL != 0 {
        promote_global(dsos, id);
    }
    Some(handle(id))
}

fn map_object(
    prepared: &PreparedDso, id: usize, needed: Vec<usize>,
    needed_by_name: Vec<(String, usize)>,
) -> Option<NativeDso> {
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
    let mut object = ElfLoader::new(base as u64).parse(&prepared.bytes).ok()?;
    let symbolic = binding::symbolic(&prepared.bytes, &object)?;
    let versions = versions::Table::parse(&prepared.bytes, &object)?;
    let tls_relocations = tls::take_relocations(&mut object);
    Some(NativeDso {
        id,
        device: prepared.device,
        inode: prepared.inode,
        _file: file,
        name: CString::new(prepared.path.as_os_str().as_bytes()).ok()?,
        references: 0,
        load_pins: 0,
        nodelete: prepared.flags & DF_1_NODELETE != 0,
        global: false,
        global_rank: 0,
        symbolic,
        dependencies: needed.clone(),
        needed,
        needed_by_name,
        mapping,
        object,
        versions,
        callbacks: lifecycle::Callbacks::default(),
        tls: None,
        tls_relocations,
        tls_descriptors: tls::Descriptors::default(),
        thread_exit_pins: 0,
        state: InitState::Pending,
        initialized_at: 0,
        retiring: false,
    })
}

fn protect_object(dso: &NativeDso, image: &LoadImage, apply_relro: bool) -> Option<()> {
    // Anonymous gaps between PT_LOAD segments must not remain writable.
    // SAFETY: this guard owns the entire page-aligned anonymous mapping.
    unsafe { raw_syscall::sys_mprotect(dso.mapping.base as *mut u8, dso.mapping.len, libc::PROT_NONE) }.ok()?;
    for segment in &image.segments {
        let offset = usize::try_from(segment.map_addr).ok()?;
        let len = usize::try_from(segment.map_size).ok()?;
        if offset.checked_add(len)? > dso.mapping.len {
            return None;
        }
        if !apply_relro && segment.prot & (libc::PROT_WRITE | libc::PROT_EXEC)
            == (libc::PROT_WRITE | libc::PROT_EXEC)
        { return None; }
        let address = dso.mapping.base.checked_add(offset)? as *mut u8;
        // SAFETY: checked range inside this mapping; page alignment and flags
        // come from the validated materialized PT_LOAD image.
        unsafe { raw_syscall::sys_mprotect(address, len, segment.prot) }.ok()?;
    }
    if apply_relro && let Some(range) = &image.relro_range {
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
        if name == "__tls_get_addr" { return tls::resolver_address(version); }
        if name == "__cxa_thread_atexit_impl" { return thread_exit::resolver_address(version); }
        if matches!(name, "__cxa_atexit" | "__cxa_finalize") { return cxa::resolver_address(name, version); }
        if matches!(name, "exit" | "_Exit" | "_exit" | "quick_exit") { return process_exit::resolver_address(name, version); }
        for dso in &self.scope {
            if let Some(symbol) = dso.versions.lookup(
                &dso.object, name, version, versions::Lookup::Relocation { hidden: false },
            ) {
                // All IFUNC references belong to the explicit late pass.
                if symbol.is_tls() || symbol.is_ifunc() { return None; }
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
                if dso.retiring { return None; }
                ids[index] = Some(dso.id);
            } else {
                if let Some(id) = next_id() {
                    ids[index] = Some(id);
                } else {
                    return None;
                }
                new_indexes.push(index);
                visit.extend(prepared.needed.iter().filter_map(|dependency| {
                    match dependency {
                        Dependency::Prepared(index) => Some(*index),
                        Dependency::Resident(_) => None,
                    }
                }));
            }
        }
        cursor += 1;
    }

    // Prepared edges address this transaction; resident edges address the
    // original link map and are kept alive by the group's staging guards.
    let dependency_id = |dependency: Dependency| -> Option<usize> {
        match dependency {
            Dependency::Prepared(index) => ids.get(index).copied().flatten(),
            Dependency::Resident(id) => dsos.iter()
                .find(|dso| dso.id == id && !dso.retiring).map(|dso| dso.id),
        }
    };
    let root = ids[0]?;
    let mut pending = Vec::new();
    for &index in &new_indexes {
        let needed = group[index].needed.iter()
            .map(|&dependency| dependency_id(dependency))
            .collect::<Option<Vec<_>>>()?;
        let needed_by_name = group[index].needed_by_name.iter()
            .map(|(name, dependency)| Some((name.clone(), dependency_id(*dependency)?)))
            .collect::<Option<Vec<_>>>()?;
        pending.push(map_object(&group[index], ids[index]?, needed, needed_by_name)?);
    }
    // Version requirements are a dependency contract, not merely a filter on
    // symbols that happen to be relocated. Validate against the named direct
    // provider's ORIGINAL image before any resolver, initializer or publication.
    for dso in &pending {
        for requirement in &dso.versions.requirements {
            let provider_id = dso.needed_by_name.iter()
                .find(|(name, _)| name == &requirement.library)
                .map(|(_, id)| *id)
                .or_else(|| dso.needed.iter().copied().find(|&id| {
                    find(&dsos, &pending, id).is_some_and(|provider| {
                        provider.object.soname.as_deref() == Some(requirement.library.as_str())
                    })
                }))?;
            if !find(&dsos, &pending, provider_id)?.versions.satisfies(requirement) {
                return None;
            }
        }
    }
    let direct = binding::prepare(&dsos, &mut pending, root, flags)?;
    let indirect = ifunc::prepare(&dsos, &mut pending, root, flags)?;
    // Every member is mapped before the first relocation. Forward references,
    // siblings and cycles therefore resolve without publishing partial DSOs.
    let mut edges = Vec::new();
    for (dso, plan) in pending.iter().zip(&direct) {
        let scope = binding::scope(&dsos, &pending, root, dso, flags)?;
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
        binding::apply(plan, memory, &resolver)?;
        tls::relocate(dso, memory, &resolver)?;
        edges.push(resolver.providers.into_inner());
    }
    for (dso, providers) in pending.iter_mut().zip(edges) {
        for provider in providers {
            if provider != dso.id && !dso.dependencies.contains(&provider) {
                dso.dependencies.push(provider);
            }
        }
        dso.tls = tls::Module::capture(dso)?;
    }
    if indirect.iter().any(|plan| !plan.is_empty()) {
        for (dso, &index) in pending.iter().zip(&new_indexes) {
            protect_object(dso, &group[index].image, false)?;
        }
        let order = ifunc::execution_order(&dsos, &pending, root);
        let context = ifunc::Context::new(&dsos, &pending);
        // OPERATIONS stays held. Recursive load/lookup/close is rejected while
        // resolving, so residents cannot disappear while their addresses are
        // in use. The pending transaction is never exposed as a live handle.
        drop(dsos);
        let edges = ifunc::execute(context, &indirect, &order)?;
        dsos = registry().lock().ok()?;
        for (dso, providers) in pending.iter_mut().zip(edges) {
            for provider in providers {
                if provider != dso.id && !dso.dependencies.contains(&provider) {
                    dso.dependencies.push(provider);
                }
            }
        }
    }
    // Resolve every array from relocated memory before running constructors.
    // Also retain providers of callback addresses, even when no symbol
    // relocation was required to materialize that address.
    let mut lifecycle_data = Vec::new();
    for (dso, &index) in pending.iter().zip(&new_indexes) {
        let callbacks = group[index].lifecycle.resolve(dso)?;
        let mut providers = Vec::new();
        for &address in callbacks.init.iter().chain(&callbacks.fini) {
            let provider = dsos.iter().chain(&pending).find(|provider| {
                !provider.retiring && lifecycle::executable_address(provider, address)
            })?;
            if provider.id != dso.id && !providers.contains(&provider.id) {
                providers.push(provider.id);
            }
        }
        lifecycle_data.push((callbacks, providers));
    }
    for (dso, (callbacks, providers)) in pending.iter_mut().zip(lifecycle_data) {
        dso.callbacks = callbacks;
        for provider in providers {
            if !dso.dependencies.contains(&provider) { dso.dependencies.push(provider); }
        }
    }
    for (dso, &index) in pending.iter().zip(&new_indexes) {
        protect_object(dso, &group[index].image, true)?;
    }
    // Resident staging pins are temporary. No published reference, scope or
    // lifetime edge changes before this point. Dropping pending on failure
    // rolls back mappings; releasing the group's pins then permits collection.
    // Resolver side effects, like arbitrary constructor effects, are not undoable.
    let root_dso = pending.iter_mut().find(|dso| dso.id == root)?;
    root_dso.references = 1;
    root_dso.nodelete |= flags & dlfcn_core::RTLD_NODELETE != 0;
    dsos.extend(pending);
    if flags & dlfcn_core::RTLD_GLOBAL != 0 {
        promote_global(&mut dsos, root);
    }
    Some(handle(root))
}

pub(super) fn load_native_dso(name: &[u8], flags: c_int) -> Option<*mut c_void> {
    if ifunc::active() || process_exit::unloading() { return None; }
    if name.is_empty() || name.contains(&0) {
        return None;
    }
    // A loaded SONAME names its original image, even if its backing file has
    // since been renamed, unlinked, or replaced. Do not reopen the filesystem
    // before this lookup, and do not let RTLD_NOLOAD create a new object.
    if !name.contains(&b'/') {
        let _operation = OPERATIONS.lock();
        if process_exit::unloading() {
            return None;
        }
        let mut dsos = registry().lock().ok()?;
        if let Some(index) = dsos.iter().position(|dso| {
            dso.object.soname.as_deref().is_some_and(|soname| soname.as_bytes() == name)
        }) {
            let handle = reopen(&mut dsos, index, flags)?;
            let id = dsos[index].id;
            drop(dsos);
            initialize(id)?;
            return Some(handle);
        }
    }
    let context = SearchContext::process();
    let executable = std::fs::read_link("/proc/self/exe").ok();
    let origin = executable.as_deref().and_then(Path::parent);
    // Do not fabricate an ORIGIN when /proc cannot identify the executable.
    if name.contains(&b'$') && origin.is_none() {
        return None;
    }
    let candidates = SearchPaths::default().candidates(
        name, origin.unwrap_or(Path::new("/")), &[], &context,
    )?;
    // Explicit pathnames stay exact. Bare names use the immutable initial
    // environment, native cache and default directories, not an implicit cwd.
    // The context also suppresses environment/ORIGIN use in secure execution.
    let (path, file, device, inode) = candidates.into_iter().find_map(|candidate| {
        let path = absolute_path(&candidate)?;
        open_file(&path).map(|(file, device, inode)| (path, file, device, inode))
    })?;
    {
        let _operation = OPERATIONS.lock();
        if process_exit::unloading() { return None; }
        let mut dsos = registry().lock().ok()?;
        if let Some(index) = dsos.iter().position(|dso| dso.device == device && dso.inode == inode) {
            let handle = reopen(&mut dsos, index, flags)?;
            let id = dsos[index].id;
            drop(dsos);
            initialize(id)?;
            return Some(handle);
        }
    }
    if flags & dlfcn_core::RTLD_NOLOAD != 0 {
        return None;
    }
    let root = prepare_file(file, device, inode, &path, &context)?;
    let group = prepare_group(root, &context)?;
    // Slow file reads and dependency staging hold neither loader lock. Recheck
    // resident identities atomically once the complete group is prepared.
    let _operation = OPERATIONS.lock();
    if process_exit::unloading() { return None; }
    process_exit::install()?;
    let result = publish_group(&group, flags)?;
    initialize(native_dso_id_from_handle(result)?)?;
    Some(result)
}

/// Libraries owned by the host dynamic linker in an interpose (L0/L1)
/// process. An object that links against any of them cannot be isolated from
/// the host link map, so the native loader is not the right owner for it.
const HOST_RUNTIME_SONAMES: &[&str] = &[
    "libc.so.6",
    "libm.so.6",
    "libpthread.so.0",
    "libdl.so.2",
    "librt.so.1",
    "libutil.so.1",
    "libresolv.so.2",
    "libgcc_s.so.1",
    "libstdc++.so.6",
    "ld-linux-x86-64.so.2",
    "ld-linux-aarch64.so.1",
];

/// Whether a pathname `dlopen` the native loader declined may be served by
/// the host loader instead (interpose builds only; bd-rc0923-epic-eeuy4f.3).
///
/// Only ordinary host-coupled objects qualify: those whose DT_NEEDED list
/// names a host runtime library (every normal glibc-linked DSO, including all
/// Python extension modules). Self-contained objects keep the native loader's
/// fail-closed verdict — a bad IFUNC resolver or TLSDESC pair must not be
/// "rescued" by the host — and nothing falls back while an IFUNC resolver is
/// running (recursive loads must fail).
pub(super) fn host_may_load_declined_object(name: &[u8]) -> bool {
    if ifunc::active() {
        return false;
    }
    let Ok(bytes) = std::fs::read(OsStr::from_bytes(name)) else {
        return false;
    };
    let Ok(object) = ElfLoader::new(0).parse(&bytes) else {
        return false;
    };
    object
        .needed_libraries
        .iter()
        .any(|needed| HOST_RUNTIME_SONAMES.contains(&needed.as_str()))
}

pub(super) fn resolve_native_dso_symbol(
    handle: *mut c_void,
    symbol_name: &[u8],
    version_name: Option<&[u8]>,
) -> Option<Option<*mut c_void>> {
    // Only the standalone main-program handle owns this native global scope.
    // RTLD_DEFAULT/RTLD_NEXT need caller-relative scope and lifetime handling;
    // never silently interpret either pseudo-handle as this explicit handle.
    let id = if cfg!(feature = "standalone") && super::is_main_program_handle(handle) {
        None
    } else {
        Some(native_dso_id_from_handle(handle)?)
    };
    if ifunc::active() { return Some(None); }
    let symbol = std::str::from_utf8(symbol_name).ok()?;
    let version = match version_name {
        Some(bytes) => Some(std::str::from_utf8(bytes).ok()?),
        None => None,
    };
    let _operation = OPERATIONS.lock();
    let dsos = registry().lock().ok()?;
    let order = if let Some(id) = id {
        dsos.iter().find(|dso| dso.id == id)?;
        lookup_order(&dsos, &[], id)
    } else {
        global_scope_order(&dsos)
    };
    for candidate in order {
        let dso = dsos.iter().find(|dso| dso.id == candidate)?;
        if let Some(symbol) = dso.versions.lookup(&dso.object, symbol, version, versions::Lookup::Public) {
            if symbol.is_tls() {
                let module = dso.tls.clone()?;
                let offset = usize::try_from(symbol.st_value).ok()?;
                drop(dsos);
                return Some(tls::address(&module, offset));
            }
            if symbol.is_ifunc() {
                let address = usize::try_from(symbol.definition_address(dso.object.base)?).ok()?;
                drop(dsos);
                // A main-handle lookup has no owning DSO. Retain an indirect
                // implementation through the selected provider, not a fake ID.
                return Some(ifunc::resolve_symbol(id.unwrap_or(candidate), address)
                    .map(|address| address as *mut c_void));
            }
            return Some(symbol.definition_address(dso.object.base).map(|address| address as *mut c_void));
        }
    }
    Some(None)
}

// Initialize a dependency before its consumer. Mark on traversal so cycles
// execute each initializer once; mark Running before releasing the mutex so a
// constructor reopening itself cannot recursively initialize itself again.
fn initialize(root: usize) -> Option<()> {
    let mut stack = vec![(root, false)];
    let mut seen = Vec::new();
    while let Some((id, ready)) = stack.pop() {
        let mut dsos = registry().lock().ok()?;
        let dso = dsos.iter_mut().find(|dso| dso.id == id)?;
        if dso.state != InitState::Pending { continue; }
        if !ready {
            if seen.contains(&id) { continue; }
            seen.push(id);
            stack.push((id, true));
            stack.extend(dso.needed.iter().rev().map(|&id| (id, false)));
            continue;
        }
        dso.state = InitState::Running;
        let callbacks = dso.callbacks.init.clone();
        drop(dsos);
        for address in callbacks {
            // SAFETY: validated before publication; Pending/Running are roots
            // for nested close, retaining every mapping until init returns.
            unsafe { lifecycle::call_init(address) };
        }
        let mut dsos = registry().lock().ok()?;
        let sequence = dsos.iter().map(|dso| dso.initialized_at).max().unwrap_or(0).checked_add(1)?;
        let dso = dsos.iter_mut().find(|dso| dso.id == id)?;
        dso.initialized_at = sequence;
        dso.state = InitState::Live;
    }
    Some(())
}

fn live_ids(dsos: &[NativeDso]) -> Vec<usize> {
    // Active initialization and finalization batches pin their entire closure
    // during reentrant operations, independent of explicit open counts.
    let mut live = dsos.iter().filter(|dso| {
        dso.references != 0 || dso.load_pins != 0 || dso.thread_exit_pins != 0 || dso.nodelete
            || dso.state != InitState::Live || dso.retiring
    }).map(|dso| dso.id).collect::<Vec<_>>();
    let mut cursor = 0;
    while cursor < live.len() {
        if let Some(dso) = dsos.iter().find(|dso| dso.id == live[cursor]) {
            for &dependency in &dso.dependencies {
                if !live.contains(&dependency) { live.push(dependency); }
            }
        }
        cursor += 1;
    }
    live
}

fn collect_unreachable() -> Option<()> {
    if COLLECTING.swap(true, Ordering::Relaxed) { return Some(()); }
    let _collection = CollectionGuard;
    loop {
        let mut dsos = registry().lock().ok()?;
        let live = live_ids(&dsos);
        let mut retiring = dsos.iter().filter(|dso| !live.contains(&dso.id))
            .map(|dso| (dso.initialized_at, dso.id)).collect::<Vec<_>>();
        if retiring.is_empty() { return Some(()); }
        retiring.sort_unstable_by(|left, right| right.cmp(left));
        let ids = retiring.iter().map(|entry| entry.1).collect::<Vec<_>>();
        let mut callbacks = Vec::new();
        for &id in &ids {
            let dso = dsos.iter_mut().find(|dso| dso.id == id)?;
            dso.retiring = true;
            callbacks.push((id, dso.callbacks.fini.clone()));
        }
        // Pin the WHOLE batch, not just the currently executing finalizer: a
        // dependency in a cycle may still call back into an earlier member.
        drop(dsos);
        for (id, callbacks) in callbacks {
            for address in callbacks {
                // SAFETY: all validated callback mappings remain pinned above.
                unsafe { lifecycle::call_fini(address) };
            }
            cxa::finalize_owners(&[id])?;
        }
        // A later finalizer may register onto an earlier member of a cycle.
        // Drain those entries too before dropping any mapping in this batch.
        cxa::finalize_owners(&ids)?;
        let mut dsos = registry().lock().ok()?;
        dsos.retain(|dso| !ids.contains(&dso.id));
        // Nested closes can make an external provider unreachable. Recompute
        // after dropping this batch's edges instead of leaking that provider.
    }
}

pub(super) fn close_native_dso(handle: *mut c_void) -> Option<c_int> {
    let id = native_dso_id_from_handle(handle)?;
    if ifunc::active() { return Some(-1); }
    let _operation = OPERATIONS.lock();
    let mut dsos = registry().lock().ok()?;
    let dso = dsos.iter_mut().find(|dso| dso.id == id)?;
    if dso.references == 0 { return Some(-1); }
    dso.references -= 1;
    drop(dsos);
    collect_unreachable()?;
    Some(0)
}
