//! Caller-relative lookup for native plugins, separate from the host namespace.
//!
//! A native import of dlsym/dlvsym enters a private, return-address-preserving
//! bridge. Passing a native caller to the host's RTLD_DEFAULT would silently
//! lose its LOCAL group. The public interpose exports remain unchanged.
//! Scope membership holds IDs, never pointers or lifetime references; a
//! successful DEFAULT lookup separately retains the selected native provider.
//! NEXT uses only the tail of the caller's original load group. It neither
//! searches unrelated globals nor creates an ordinary provider lifetime edge.

use std::ffi::{CStr, c_char, c_void};

use frankenlibc_core::dlfcn as core;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use super::super as abi;
use super::{
    NativeDso, OPERATIONS, ResidentPin, global_scope_order, ifunc, lifecycle, lookup_order,
    registry, tls, unique, versions,
};
use crate::runtime_policy;

#[path = "dlfcn_memory.rs"]
mod memory;

#[path = "dlfcn_lookup_bridge.rs"]
mod bridge;
pub(super) use bridge::BoundCalls;

#[derive(Clone, Copy, Debug)]
pub(super) struct LocalScope {
    pub(super) root: usize,
    deepbind: bool,
}

/// Called with the operation and registry locks, only after publication or a
/// successful reopen. Reused dependencies keep their older scopes first.
/// Vec allocation follows the surrounding loader's abort-on-OOM contract.
pub(super) fn attach_scope(dsos: &mut [NativeDso], root: usize, deepbind: bool) {
    let members = lookup_order(dsos, &[], root);
    // First discovery assigns the actual DT_NEEDED parent, not just the
    // outer group root. An inner ancestor can survive after that root retires.
    // Determine parents before taking mutable borrows; cycles never assign
    // a parent to the root or revisit a node already discovered by BFS.
    let parents = members
        .iter()
        .enumerate()
        .map(|(index, &id)| {
            let parent = members[..index].iter().copied().find(|parent| {
                dsos.iter()
                    .any(|dso| dso.id == *parent && dso.needed.contains(&id))
            });
            (id, parent)
        })
        .collect::<Vec<_>>();
    for dso in dsos.iter_mut().filter(|dso| members.contains(&dso.id)) {
        if dso.state == super::InitState::Pending && dso.lookup_scopes.is_empty() {
            dso.loader = parents
                .iter()
                .find(|(id, _)| *id == dso.id)
                .and_then(|(_, parent)| *parent);
        }
        if !dso.lookup_scopes.iter().any(|scope| scope.root == root) {
            dso.lookup_scopes.push(LocalScope { root, deepbind });
        }
    }
}

// A C call enters with its real return PC: at [rsp] on x86_64, or in lr (x30)
// on aarch64. The naked tail bridge adds that PC as the last argument without
// creating a frame or disturbing stack alignment. Reading it in an ordinary Rust
// function is not reliable: optimizers, frame-pointer settings and debug/release
// prologues differ.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn native_dlsym(_handle: *mut c_void, _name: *const c_char) -> *mut c_void {
    std::arch::naked_asm!("mov rdx, [rsp]", "jmp {entry}", entry = sym dlsym_entry);
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn native_dlvsym(
    _handle: *mut c_void,
    _name: *const c_char,
    _version: *const c_char,
) -> *mut c_void {
    std::arch::naked_asm!("mov rcx, [rsp]", "jmp {entry}", entry = sym dlvsym_entry);
}

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn native_dlsym(_handle: *mut c_void, _name: *const c_char) -> *mut c_void {
    std::arch::naked_asm!("mov x2, x30", "b {entry}", entry = sym dlsym_entry);
}

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn native_dlvsym(
    _handle: *mut c_void,
    _name: *const c_char,
    _version: *const c_char,
) -> *mut c_void {
    std::arch::naked_asm!("mov x3, x30", "b {entry}", entry = sym dlvsym_entry);
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe extern "C" fn native_dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void {
    unsafe { dlsym_entry(handle, name, 0) }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe extern "C" fn native_dlvsym(
    handle: *mut c_void,
    name: *const c_char,
    version: *const c_char,
) -> *mut c_void {
    unsafe { dlvsym_entry(handle, name, version, 0) }
}

/// Distinguish an unknown runtime name from an unsupported version of a
/// known name. The latter must never escape into the generic builtin table
/// or host lookup: that can mix incompatible allocator/FILE ownership domains.
/// Native scoped definitions are searched before applying this fallback.
pub(super) fn runtime_export(name: &str, version: Option<&str>) -> Option<Option<u64>> {
    memory::address(name, None)?;
    Some(memory::address(name, version))
}

/// Only native relocation fallback binds these bridges; a DSO-provided
/// ordinary definition still wins the existing preemption/scope search.
pub(super) fn resolver_address(name: &str, version: Option<&str>) -> Option<u64> {
    // The same allocation/string frontends serve native relocations and
    // dynamically obtained pointers; do not mix an owned allocator with host free.
    if let Some(address) = runtime_export(name, version) {
        return address;
    }
    // Dynamically obtained introspection functions must understand native
    // handles. Host dlinfo cannot interpret our tagged IDs as link-map pointers.
    // Its compatibility versions are independent of dlsym's version set.
    if matches!(name, "dlinfo" | "dladdr1") {
        return super::introspection::resolver_address(name, version);
    }
    let baseline = if cfg!(target_arch = "aarch64") {
        "GLIBC_2.17"
    } else {
        "GLIBC_2.2.5"
    };
    if version.is_some_and(|version| version != baseline && version != "GLIBC_2.34") {
        return None;
    }
    match name {
        "dlopen" => Some(super::open::resolver_address()),
        "dlsym" => Some(native_dlsym as *const () as usize as u64),
        "dlvsym" => Some(native_dlvsym as *const () as usize as u64),
        _ => None,
    }
}

unsafe extern "C" fn dlsym_entry(
    handle: *mut c_void,
    name: *const c_char,
    caller: usize,
) -> *mut c_void {
    unsafe { dispatch(handle, name, None, caller, None) }
}

unsafe extern "C" fn dlvsym_entry(
    handle: *mut c_void,
    name: *const c_char,
    version: *const c_char,
    caller: usize,
) -> *mut c_void {
    unsafe { dispatch(handle, name, Some(version), caller, None) }
}

// The generated entries add immutable provenance without changing any C argument.
unsafe extern "C" fn bound_dlsym_entry(
    handle: *mut c_void,
    name: *const c_char,
    caller: usize,
    origin: usize,
) -> *mut c_void {
    // SAFETY: forwarded arguments retain the public dlsym contract.
    unsafe { dispatch(handle, name, None, caller, Some(origin)) }
}

unsafe extern "C" fn bound_dlvsym_entry(
    handle: *mut c_void,
    name: *const c_char,
    version: *const c_char,
    caller: usize,
    origin: usize,
) -> *mut c_void {
    // SAFETY: forwarded arguments retain the public dlvsym contract.
    unsafe { dispatch(handle, name, Some(version), caller, Some(origin)) }
}

pub(super) fn bound_resolver_address(
    dso: &NativeDso,
    name: &str,
    version: Option<&str>,
) -> Option<Option<u64>> {
    dso.lookup_bridges.address(name, version)
}

pub(super) fn caller_id(dsos: &[NativeDso], return_pc: usize) -> Option<usize> {
    // The return PC can be exactly at the end of an executable segment. Its
    // preceding call instruction still belongs to that segment.
    let call_pc = return_pc.checked_sub(1)?;
    dsos.iter()
        .find(|dso| lifecycle::executable_address(dso, call_pc))
        .map(|dso| dso.id)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Request {
    Default,
    Next,
}

unsafe fn dispatch(
    handle: *mut c_void,
    name: *const c_char,
    version: Option<*const c_char>,
    caller: usize,
    origin: Option<usize>,
) -> *mut c_void {
    // Explicit handles retain their existing validation and ownership path.
    let request = match handle as usize {
        core::RTLD_DEFAULT => Request::Default,
        core::RTLD_NEXT => Request::Next,
        _ => return unsafe { forward(handle, name, version) },
    };
    // A pending IFUNC's caller has not been published yet. Check reentry
    // BEFORE caller identification, or that absence would send a native PC to
    // the host loader. Recursive lookup remains unsupported during IFUNC.
    if ifunc::active() {
        abi::set_dlerror(core::ERR_SYMBOL_NOT_FOUND);
        return std::ptr::null_mut();
    }
    let operation = OPERATIONS.lock();
    let id = registry().lock().ok().and_then(|dsos| {
        caller_id(&dsos, caller)
            .or_else(|| origin.filter(|id| dsos.iter().any(|dso| dso.id == *id)))
    });
    let Some(id) = id else {
        drop(operation);
        // Bound entries never turn a stale native origin into a host lookup.
        if origin.is_some() {
            abi::set_dlerror(core::ERR_SYMBOL_NOT_FOUND);
            return std::ptr::null_mut();
        }
        return unsafe { forward(handle, name, version) };
    };
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Loader, handle as usize, 0, false, true, 0);
    let result = if matches!(decision.action, MembraneAction::Deny) || ifunc::active() {
        None
    } else {
        unsafe { validated_lookup(id, name, version, request) }
    };
    // None is failure; Some(NULL) is a successful zero-valued symbol/IFUNC.
    // Once a caller is recognized, a native miss never falls through to a
    // host RTLD_NEXT/DEFAULT call with an unrelated caller address.
    let adverse = result.is_none();
    if adverse {
        abi::set_dlerror(core::ERR_SYMBOL_NOT_FOUND);
    } else {
        abi::clear_dlerror();
    }
    runtime_policy::observe(ApiFamily::Loader, decision.profile, 8, adverse);
    result.unwrap_or(std::ptr::null_mut())
}

unsafe fn forward(
    handle: *mut c_void,
    name: *const c_char,
    version: Option<*const c_char>,
) -> *mut c_void {
    match version {
        Some(version) => unsafe { abi::dlvsym(handle, name, version) },
        None => unsafe { abi::dlsym(handle, name) },
    }
}

unsafe fn bounded_name<'a>(pointer: *const c_char) -> Option<&'a CStr> {
    if pointer.is_null() {
        return None;
    }
    let (len, terminated) = unsafe {
        crate::util::scan_c_string(
            pointer,
            crate::malloc_abi::known_remaining(pointer as usize),
        )
    };
    if !terminated {
        return None;
    }
    let size = len.checked_add(1)?;
    // SAFETY: the same bounded scan used by the public ABI found the NUL.
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), size) };
    CStr::from_bytes_with_nul(bytes).ok()
}

struct Search {
    before_host: Vec<usize>,
    after_host: Vec<usize>,
}

fn search_order(dsos: &[NativeDso], caller: usize) -> Option<Search> {
    let dso = dsos.iter().find(|dso| dso.id == caller)?;
    let mut local = Vec::new();
    for scope in &dso.lookup_scopes {
        for id in lookup_order(dsos, &[], scope.root) {
            if !local.contains(&id) {
                local.push(id);
            }
        }
    }
    // A surviving independently retained dependency may outlive every former
    // group root. Its own dependency closure remains a valid local scope.
    if local.is_empty() {
        local = lookup_order(dsos, &[], caller);
    }
    let deepbind = dso
        .lookup_scopes
        .first()
        .is_some_and(|scope| scope.deepbind);
    let mut global = global_scope_order(dsos);
    let mut before = if dso.symbolic {
        vec![caller]
    } else {
        Vec::new()
    };
    if deepbind {
        for id in local {
            if !before.contains(&id) {
                before.push(id);
            }
        }
        global.retain(|id| !before.contains(id));
        Some(Search {
            before_host: before,
            after_host: global,
        })
    } else {
        for id in local {
            if !global.contains(&id) {
                global.push(id);
            }
        }
        global.retain(|id| !before.contains(id));
        Some(Search {
            before_host: before,
            after_host: global,
        })
    }
}

/// NEXT is not DEFAULT with one definition omitted. Walk the original
/// DT_NEEDED loader ancestry, then skip through the caller in that ancestor's
/// breadth-first scope. Reopen/new-group memberships never reparent a DSO.
/// Missing ancestors terminate the walk at the last surviving inner loader;
/// scope pruning and successful DEFAULT lifetime edges are independent of it.
fn next_order(dsos: &[NativeDso], caller: usize) -> Option<Vec<usize>> {
    let mut root = caller;
    let mut depth = 0;
    loop {
        let dso = dsos.iter().find(|dso| dso.id == root)?;
        let Some(parent) = dso.loader else {
            break;
        };
        if !dsos.iter().any(|dso| dso.id == parent) {
            break;
        }
        depth += 1;
        if depth >= dsos.len() {
            return None;
        }
        root = parent;
    }
    let mut order = lookup_order(dsos, &[], root);
    let skip = order.iter().position(|id| *id == caller)?.checked_add(1)?;
    drop(order.drain(..skip));
    Some(order)
}

/// Keep a mapping alive across TLS allocation or arbitrary host IFUNC code,
/// without retaining it permanently if lookup fails. Drop outside the registry.
fn pin(id: usize) -> Option<ResidentPin> {
    let mut dsos = registry().lock().ok()?;
    let dso = dsos.iter_mut().find(|dso| dso.id == id)?;
    dso.load_pins = dso.load_pins.checked_add(1)?;
    Some(ResidentPin { id })
}

unsafe fn validated_lookup(
    caller: usize,
    name: *const c_char,
    version: Option<*const c_char>,
    request: Request,
) -> Option<*mut c_void> {
    let name = unsafe { bounded_name(name)? };
    let version = match version {
        Some(pointer) => Some(unsafe { bounded_name(pointer)? }),
        None => None,
    };
    let symbol_name = name.to_str().ok()?;
    let version_name = version.map(CStr::to_str).transpose().ok()?;
    let _caller_pin = pin(caller)?;
    if request == Request::Next {
        let order = {
            let dsos = registry().lock().ok()?;
            next_order(&dsos, caller)?
        };
        // A local-tail miss is final. In particular, libc builtins, the host
        // global scope and a later RTLD_GLOBAL plugin are NOT NEXT fallbacks.
        return native_search(caller, &order, symbol_name, version_name, request).flatten();
    }
    let search = {
        let dsos = registry().lock().ok()?;
        search_order(&dsos, caller)?
    };
    if let Some(result) = native_search(
        caller,
        &search.before_host,
        symbol_name,
        version_name,
        request,
    ) {
        return result;
    }
    if let Some(address) = runtime_export(symbol_name, version_name) {
        // Scoped definitions can supply their own versions, even one the
        // runtime does not implement. Search them before finalizing refusal.
        // A rejected runtime version is NOT a host lookup opportunity.
        if let Some(result) = native_search(
            caller,
            &search.after_host,
            symbol_name,
            version_name,
            request,
        ) {
            return result;
        }
        return address.map(|address| address as *mut c_void);
    }
    let bound = {
        let dsos = registry().lock().ok()?;
        bound_resolver_address(
            dsos.iter().find(|dso| dso.id == caller)?,
            symbol_name,
            version_name,
        )
    };
    if let Some(address) = bound {
        // A custom native definition still preempts the runtime entry.
        if let Some(result) = native_search(
            caller,
            &search.after_host,
            symbol_name,
            version_name,
            request,
        ) {
            return result;
        }
        return address.map(|address| address as *mut c_void);
    }
    // The host global prefix already contains the interposed libc in L0/L1.
    // This never loads another object or imports a host module ID into TLS.
    // Rebind lookup itself to the same caller-preserving bridge.
    if let Some(address) = resolver_address(symbol_name, version_name) {
        return Some(address as *mut c_void);
    }
    if let Some(address) = unsafe { host_symbol(name, version) } {
        return Some(address);
    }
    if let Some(result) = native_search(
        caller,
        &search.after_host,
        symbol_name,
        version_name,
        request,
    ) {
        return result;
    }
    if version_name.is_some_and(|version| !abi::version_supported(version.as_bytes())) {
        return None;
    }
    let address = abi::resolve_exported_symbol(name.to_bytes());
    (!address.is_null()).then_some(address)
}

#[cfg(not(feature = "standalone"))]
unsafe fn host_symbol(name: &CStr, version: Option<&CStr>) -> Option<*mut c_void> {
    // Resolve both host entry points before clearing the host error state.
    // A helper resolution must not contaminate the result of the real lookup.
    type Error = unsafe extern "C" fn() -> *const c_char;
    type Lookup = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
    type Versioned = unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut c_void;
    let error = crate::host_resolve::resolve_host_symbol_raw("dlerror")?;
    let lookup = crate::host_resolve::resolve_host_symbol_raw(if version.is_some() {
        "dlvsym"
    } else {
        "dlsym"
    })?;
    // SAFETY: resolved host addresses have exactly these libc signatures.
    let error: Error = unsafe { std::mem::transmute(error) };
    unsafe { error() };
    // No native registry/index guard crosses host IFUNC or other user code.
    let address = match version {
        Some(version) => {
            let lookup: Versioned = unsafe { std::mem::transmute(lookup) };
            unsafe { lookup(libc::RTLD_DEFAULT, name.as_ptr(), version.as_ptr()) }
        }
        None => {
            let lookup: Lookup = unsafe { std::mem::transmute(lookup) };
            unsafe { lookup(libc::RTLD_DEFAULT, name.as_ptr()) }
        }
    };
    unsafe { error() }.is_null().then_some(address)
}

#[cfg(feature = "standalone")]
unsafe fn host_symbol(_name: &CStr, _version: Option<&CStr>) -> Option<*mut c_void> {
    None
}

/// Outer None is a scope miss. Some(None) is a selected definition that could
/// not be materialized; never hide that failure by choosing a later provider.
fn native_search(
    caller: usize,
    order: &[usize],
    name: &str,
    version: Option<&str>,
    request: Request,
) -> Option<Option<*mut c_void>> {
    let unique = unique::Transaction::new();
    let definition = {
        let dsos = registry().lock().ok()?;
        let caller_retiring = dsos.iter().find(|dso| dso.id == caller)?.retiring;
        let mut selected = None;
        for id in order {
            let Some(dso) = dsos.iter().find(|dso| dso.id == *id) else {
                continue;
            };
            // FINI may use its still-mapped batch, but a live caller must not
            // acquire a pointer into a batch that is irreversibly retiring.
            if dso.retiring && !caller_retiring {
                continue;
            }
            if let Some(symbol) =
                dso.versions
                    .lookup(&dso.object, name, version, versions::Lookup::Public)
            {
                let Some(definition) = unique.select(dso, symbol) else {
                    return Some(None);
                };
                selected = Some(definition);
                break;
            }
        }
        selected?
    };
    Some(materialize(caller, definition, unique, request))
}

fn materialize(
    caller: usize,
    definition: unique::Selection,
    unique: unique::Transaction,
    request: Request,
) -> Option<*mut c_void> {
    let _provider_pin = pin(definition.provider)?;
    let address = if definition.symbol.is_tls() {
        let module = {
            let dsos = registry().lock().ok()?;
            dsos.iter()
                .find(|dso| dso.id == definition.provider)?
                .tls
                .clone()?
        };
        tls::address(&module, usize::try_from(definition.tls_offset(0)?).ok()?)?
    } else {
        let address = usize::try_from(definition.address()?).ok()?;
        if definition.symbol.is_ifunc() {
            // An indirect implementation may have a different provider. For
            // NEXT, attach that safety edge to the selected resolver's DSO,
            // not to the caller: lookup itself must not keep that DSO alive.
            let owner = if request == Request::Default {
                caller
            } else {
                definition.provider
            };
            ifunc::resolve_symbol(owner, address)? as *mut c_void
        } else {
            address as *mut c_void
        }
    };
    let mut dsos = registry().lock().ok()?;
    let requester = dsos.iter_mut().find(|dso| dso.id == caller)?;
    let retain = request == Request::Default
        && definition.provider != caller
        && !requester.dependencies.contains(&definition.provider);
    if retain {
        requester.dependencies.try_reserve(1).ok()?;
    }
    // Address materialization and capacity checks precede every permanent
    // ownership mutation. Failure does not reserve UNIQUE or pin a provider.
    unique.commit(&mut dsos, &mut [])?;
    if retain {
        dsos.iter_mut()
            .find(|dso| dso.id == caller)?
            .dependencies
            .push(definition.provider);
    }
    Some(address)
}
