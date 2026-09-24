//! Owned C++ static-object termination for native DSO groups.
//!
//! This queue is separate from the host C++ runtime: native __dso_handle
//! values must never enter the host termination list. Entries are removed
//! BEFORE invoking user code, including for recursive __cxa_finalize calls.

use std::ffi::{c_int, c_void};
use std::sync::Mutex;

use super::{NativeDso, OPERATIONS, ifunc, lifecycle, registry};

type Destructor = unsafe extern "C" fn(*mut c_void);

struct Entry {
    destructor: Destructor,
    argument: usize,
    token: usize,
    owner: Option<usize>,
    provider: usize,
}

static ENTRIES: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

fn contains(dso: &NativeDso, address: usize) -> bool {
    let Some(offset) = (address as u64).checked_sub(dso.object.base) else { return false; };
    dso.object.program_headers.iter().any(|segment| {
        segment.is_load() && segment.p_vaddr <= offset
            && segment.p_vaddr.checked_add(segment.p_memsz).is_some_and(|end| offset < end)
    })
}

fn register(destructor: Destructor, argument: *mut c_void, token: *mut c_void) -> Option<()> {
    if ifunc::active() { return None; }
    let _operation = OPERATIONS.lock();
    let mut entries = ENTRIES.lock().ok()?;
    entries.try_reserve(1).ok()?;
    let mut dsos = registry().lock().ok()?;
    let provider = dsos.iter().find(|dso| {
        lifecycle::executable_address(dso, destructor as *const () as usize)
    })?.id;
    let owner = if token.is_null() { None } else {
        Some(dsos.iter().find(|dso| contains(dso, token as usize))?.id)
    };
    // A retiring provider cannot be resurrected by registering a callback
    // onto a still-live owner (or the process list). Registrations within the
    // retiring batch are drained before any of that batch is unmapped.
    if dsos.iter().find(|dso| dso.id == provider)?.retiring
        && !owner.is_some_and(|id| dsos.iter().any(|dso| dso.id == id && dso.retiring))
    { return None; }
    if let Some(owner) = owner {
        let dso = dsos.iter_mut().find(|dso| dso.id == owner)?;
        if provider != owner && !dso.dependencies.contains(&provider) {
            // Not a root: the registering DSO can still be dlclosed. Its
            // callback provider stays reachable until that DSO is retired.
            dso.dependencies.try_reserve(1).ok()?;
            dso.dependencies.push(provider);
        }
    } else {
        // A NULL-token callback belongs to process termination rather than a
        // DSO's FINI list. Retain its executable code until it actually runs.
        let dso = dsos.iter_mut().find(|dso| dso.id == provider)?;
        dso.thread_exit_pins = dso.thread_exit_pins.checked_add(1)?;
    }
    entries.push(Entry { destructor, argument: argument as usize, token: token as usize, owner, provider });
    Some(())
}

struct CallPins(Vec<usize>);
impl CallPins {
    fn acquire(entry: &Entry) -> Option<Self> {
        let mut owners = vec![entry.provider];
        if let Some(owner) = entry.owner && owner != entry.provider { owners.push(owner); }
        let mut dsos = registry().lock().ok()?;
        for id in &owners {
            dsos.iter().find(|dso| dso.id == *id)?.thread_exit_pins.checked_add(1)?;
        }
        for dso in dsos.iter_mut().filter(|dso| owners.contains(&dso.id)) {
            dso.thread_exit_pins += 1;
        }
        if entry.owner.is_none() {
            // Transfer the queued NULL-token pin to the in-flight callback.
            dsos.iter_mut().find(|dso| dso.id == entry.provider)?.thread_exit_pins -= 1;
        }
        Some(Self(owners))
    }
}
impl Drop for CallPins {
    fn drop(&mut self) {
        if let Ok(mut dsos) = registry().lock() {
            for dso in dsos.iter_mut().filter(|dso| self.0.contains(&dso.id)) {
                dso.thread_exit_pins -= 1;
            }
        }
        // A nested dlclose may have removed the last ordinary reference. As
        // with TLS pins, let the next loader collection retire that object;
        // never unmap code underneath a returning __cxa_finalize caller.
    }
}

fn drain(mut matches: impl FnMut(&Entry) -> bool) -> Option<()> {
    if ifunc::active() { return None; }
    let _operation = OPERATIONS.lock();
    loop {
        let mut entries = ENTRIES.lock().ok()?;
        let Some(index) = entries.iter().rposition(&mut matches) else { return Some(()); };
        let pins = CallPins::acquire(&entries[index])?;
        let entry = entries.remove(index);
        drop(entries);
        // SAFETY: registration validated native executable code; the owned
        // argument remains the caller's responsibility. Both owner and code
        // provider are pinned. No queue/registry mutex crosses this callback.
        unsafe { (entry.destructor)(entry.argument as *mut c_void) };
        drop(pins);
        // Re-search from the newest entry. Registrations made by a callback
        // take priority over older entries; recursion cannot call it twice.
    }
}

pub(super) fn finalize_owners(owners: &[usize]) -> Option<()> {
    // Also drains registrations left by custom CRTs with no __cxa_finalize
    // FINI hook. Never leave a callable entry pointing into unmapped code.
    drain(|entry| entry.owner.is_some_and(|owner| owners.contains(&owner)))
}

unsafe extern "C" fn register_impl(
    destructor: Option<Destructor>, argument: *mut c_void, token: *mut c_void,
) -> c_int {
    let Some(destructor) = destructor else { return -1; };
    if register(destructor, argument, token).is_some() { 0 } else { -1 }
}

unsafe extern "C" fn finalize_impl(token: *mut c_void) {
    let _ = drain(|entry| token.is_null() || entry.token == token as usize);
}

pub(super) fn resolver_address(name: &str, version: Option<&str>) -> Option<u64> {
    if version.is_some_and(|version| version != "GLIBC_2.2.5") { return None; }
    match name {
        "__cxa_atexit" => Some(register_impl as *const () as usize as u64),
        "__cxa_finalize" => Some(finalize_impl as *const () as usize as u64),
        _ => None,
    }
}
