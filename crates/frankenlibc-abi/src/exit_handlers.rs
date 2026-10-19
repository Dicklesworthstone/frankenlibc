//! Exactly-once exit registrations shared with host-internal termination.
//! The native registry remains authoritative. Host on_exit stores only stable
//! integer tickets; early DSO finalization consumes entries before code unload.

use super::{CxaEntry, ExitHandler, c_int, c_void, ptr, set_abi_errno};

// Stable tickets let host-internal exit and owned exit share exactly-once
// ownership without giving glibc pointers to movable registry entries. Cleared
// tickets remain harmless when a DSO was explicitly finalized before exit.
static EXIT_HANDLERS: std::sync::Mutex<Vec<(usize, ExitHandler)>> =
    std::sync::Mutex::new(Vec::new());
static NEXT_EXIT_TICKET: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(1);

fn invoke_exit_handler(handler: ExitHandler, status: c_int) {
    match handler {
        ExitHandler::Atexit(func) => func(),
        ExitHandler::OnExit(entry) => unsafe { (entry.func)(status, entry.arg) },
        ExitHandler::Cxa(entry) => unsafe { (entry.func)(entry.arg) },
    }
}

#[cfg(all(not(debug_assertions), not(feature = "standalone")))]
unsafe extern "C" fn host_exit_ticket(status: c_int, ticket: *mut c_void) {
    let handler = {
        let mut handlers = EXIT_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
        handlers.iter().position(|(id, _)| *id == ticket as usize)
            .map(|index| handlers.remove(index).1)
    };
    if let Some(handler) = handler {
        invoke_exit_handler(handler, status);
        // Host exit only knows host FILEs. Flush output produced by an owned
        // handler too; no registry lock is held across callbacks or stdio.
        unsafe { crate::stdio_abi::fflush(ptr::null_mut()) };
    }
}

pub(super) fn register_exit_handler(handler: ExitHandler) -> c_int {
    use std::sync::atomic::Ordering;
    let Ok(ticket) = NEXT_EXIT_TICKET.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
                                                  |id| id.checked_add(1)) else {
        unsafe { set_abi_errno(libc::ENOMEM) };
        return -1;
    };
    // Resolve outside the registry lock. In an interposed release glibc can
    // exit internally (notably from its makecontext return trampoline), so
    // each owned registration needs a corresponding host completion ticket.
    // Debug tests and standalone builds retain their wholly owned lifecycle.
    #[cfg(all(not(debug_assertions), not(feature = "standalone")))]
    let host = crate::host_resolve::resolve_host_symbol_raw("on_exit");
    {
        let mut handlers = EXIT_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
        if handlers.try_reserve(1).is_err() {
            unsafe { set_abi_errno(libc::ENOMEM) };
            return -1;
        }
        handlers.push((ticket, handler));
    }
    #[cfg(all(not(debug_assertions), not(feature = "standalone")))]
    if let Some(host) = host {
        type OnExit = unsafe extern "C" fn(
            unsafe extern "C" fn(c_int, *mut c_void), *mut c_void,
        ) -> c_int;
        // SAFETY: raw lookup resolves glibc, never our interposed on_exit;
        // the ticket is an opaque integer and is never dereferenced.
        let register: OnExit = unsafe { std::mem::transmute(host) };
        if unsafe { register(host_exit_ticket, ticket as *mut c_void) } != 0 {
            let mut handlers = EXIT_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(index) = handlers.iter().position(|(id, _)| *id == ticket) {
                handlers.remove(index);
            }
            unsafe { set_abi_errno(libc::ENOMEM) };
            return -1;
        }
    }
    0
}

/// `__cxa_atexit`: an entry in the shared exit-function list.
pub(crate) fn register_cxa_exit_handler(
    func: unsafe extern "C" fn(*mut c_void),
    arg: *mut c_void,
    dso: *mut c_void,
) -> c_int {
    register_exit_handler(ExitHandler::Cxa(CxaEntry { func, arg, dso }))
}

/// Claim one matching entry at a time, before invoking it without the lock.
/// Reentrant registration/finalization sees all other unclaimed entries; a
/// nested exit cannot lose callbacks hidden in an outer extracted batch.
pub(crate) fn finalize_cxa_handlers(dso: *mut c_void) {
    loop {
        let handler = {
            let mut handlers = EXIT_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
            handlers.iter().rposition(|(_, handler)| matches!(handler,
                ExitHandler::Cxa(entry) if dso.is_null() || entry.dso == dso))
                .map(|index| handlers.remove(index).1)
        };
        let Some(handler) = handler else { break };
        invoke_exit_handler(handler, 0);
    }
}

pub(super) fn run_exit_handlers(status: c_int) {
    loop {
        let handler = EXIT_HANDLERS.lock().unwrap_or_else(|e| e.into_inner()).pop();
        let Some((_, handler)) = handler else { break };
        // Pop before the call, but do not extract the whole list: callbacks
        // registered reentrantly must precede older entries in LIFO order.
        invoke_exit_handler(handler, status);
    }
}

