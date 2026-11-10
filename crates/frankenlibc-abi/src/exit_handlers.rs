//! Exactly-once exit registrations shared with host-internal termination.
//! The native registry owns callbacks; the host stores only opaque tickets.
//! C++ tickets retain their DSO association so either finalizer consumes them.

use std::mem::MaybeUninit;

use super::{CxaEntry, ExitHandler, c_int, c_void, set_abi_errno};

const INLINE_EXIT_HANDLERS: usize = 64;

struct ExitHandlerRegistry {
    inline: [MaybeUninit<(usize, ExitHandler)>; INLINE_EXIT_HANDLERS],
    inline_len: usize,
    spill: Vec<(usize, ExitHandler)>,
}

impl ExitHandlerRegistry {
    const fn new() -> Self {
        Self {
            inline: [const { MaybeUninit::uninit() }; INLINE_EXIT_HANDLERS],
            inline_len: 0,
            spill: Vec::new(),
        }
    }

    fn try_push(&mut self, entry: (usize, ExitHandler)) -> Result<(), ()> {
        if self.spill.is_empty() && self.inline_len < INLINE_EXIT_HANDLERS {
            self.inline[self.inline_len].write(entry);
            self.inline_len += 1;
            return Ok(());
        }
        self.spill.try_reserve(1).map_err(|_| ())?;
        self.spill.push(entry);
        Ok(())
    }

    fn pop(&mut self) -> Option<(usize, ExitHandler)> {
        if let Some(entry) = self.spill.pop() {
            return Some(entry);
        }
        if self.inline_len == 0 {
            return None;
        }
        self.inline_len -= 1;
        // SAFETY: `0..inline_len` slots are initialized.
        Some(unsafe { self.inline[self.inline_len].assume_init_read() })
    }

    fn remove_inline_at(&mut self, index: usize) -> (usize, ExitHandler) {
        // SAFETY: `index < self.inline_len` and all `0..self.inline_len` slots are initialized.
        let removed = unsafe { self.inline[index].assume_init_read() };
        for i in index..self.inline_len - 1 {
            let next = unsafe { self.inline[i + 1].assume_init_read() };
            self.inline[i].write(next);
        }
        self.inline_len -= 1;
        removed
    }

    fn remove_by_ticket(&mut self, ticket: usize) -> Option<ExitHandler> {
        for idx in 0..self.inline_len {
            // SAFETY: `idx < self.inline_len`.
            let (id, _) = unsafe { self.inline[idx].assume_init_ref() };
            if *id == ticket {
                return Some(self.remove_inline_at(idx).1);
            }
        }
        self.spill
            .iter()
            .position(|(id, _)| *id == ticket)
            .map(|idx| self.spill.remove(idx).1)
    }

    fn rremove_matching(
        &mut self,
        mut predicate: impl FnMut(&ExitHandler) -> bool,
    ) -> Option<ExitHandler> {
        if let Some(idx) = self.spill.iter().rposition(|(_, h)| predicate(h)) {
            return Some(self.spill.remove(idx).1);
        }
        for idx in (0..self.inline_len).rev() {
            // SAFETY: `idx < self.inline_len`.
            let (_, handler) = unsafe { self.inline[idx].assume_init_ref() };
            if predicate(handler) {
                return Some(self.remove_inline_at(idx).1);
            }
        }
        None
    }
}

static EXIT_HANDLERS: std::sync::Mutex<ExitHandlerRegistry> =
    std::sync::Mutex::new(ExitHandlerRegistry::new());
static NEXT_EXIT_TICKET: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

fn invoke_exit_handler(handler: ExitHandler, status: c_int) {
    match handler {
        ExitHandler::Atexit(func) => func(),
        ExitHandler::OnExit(entry) => unsafe { (entry.func)(status, entry.arg) },
        ExitHandler::Cxa(entry) => unsafe { (entry.func)(entry.arg) },
    }
}

// Debug tests and standalone builds retain a wholly owned lifecycle. In an
// interposed release, glibc can terminate internally, without calling our exit.
#[cfg(all(not(debug_assertions), not(feature = "standalone")))]
mod host {
    use super::*;
    type OnExit =
        unsafe extern "C" fn(unsafe extern "C" fn(c_int, *mut c_void), *mut c_void) -> c_int;
    type CxaAtExit =
        unsafe extern "C" fn(unsafe extern "C" fn(*mut c_void), *mut c_void, *mut c_void) -> c_int;

    pub(super) enum Registration {
        OnExit(OnExit),
        Cxa(CxaAtExit, *mut c_void),
    }

    // Registered before the first ticket, so output from exit callbacks is
    // flushed AFTER those callbacks, never as a side effect of ordinary dlclose.
    // Registration failure remains retryable; no registry lock is held here.
    static FLUSH_REGISTERED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    static HOST_ON_EXIT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static HOST_CXA_ATEXIT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static HOST_CXA_FINALIZE: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    #[inline]
    fn cached_host_symbol(
        slot: &std::sync::atomic::AtomicUsize,
        name: &'static str,
    ) -> Option<usize> {
        use std::sync::atomic::Ordering;
        let cached = slot.load(Ordering::Acquire);
        if cached != 0 {
            return Some(cached);
        }
        let resolved = crate::host_resolve::resolve_host_symbol_raw(name)?;
        slot.store(resolved, Ordering::Release);
        Some(resolved)
    }

    unsafe extern "C" fn flush_owned_streams(_status: c_int, _arg: *mut c_void) {
        unsafe { crate::stdio_abi::fflush(std::ptr::null_mut()) };
    }

    fn claim(ticket: *mut c_void) -> Option<ExitHandler> {
        let mut handlers = EXIT_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
        handlers.remove_by_ticket(ticket as usize)
    }

    unsafe extern "C" fn on_exit_ticket(status: c_int, ticket: *mut c_void) {
        if let Some(handler) = claim(ticket) {
            invoke_exit_handler(handler, status);
        }
    }

    unsafe extern "C" fn cxa_ticket(ticket: *mut c_void) {
        if let Some(handler) = claim(ticket) {
            // This slot contains only Cxa or Atexit, neither takes exit status.
            invoke_exit_handler(handler, 0);
        }
    }

    pub(super) fn prepare(handler: &ExitHandler) -> Result<Option<Registration>, ()> {
        use std::sync::atomic::Ordering;
        let Some(address) = cached_host_symbol(&HOST_ON_EXIT, "on_exit") else {
            return Ok(None);
        };
        // SAFETY: raw lookup excludes this interposer and resolves the host ABI.
        let on_exit: OnExit = unsafe { std::mem::transmute(address) };
        if !FLUSH_REGISTERED.load(Ordering::Acquire) {
            if unsafe { on_exit(flush_owned_streams, std::ptr::null_mut()) } != 0 {
                return Err(());
            }
            FLUSH_REGISTERED.store(true, Ordering::Release);
        }
        if !matches!(handler, ExitHandler::OnExit(_))
            && let Some(address) = cached_host_symbol(&HOST_CXA_ATEXIT, "__cxa_atexit")
        {
            // SAFETY: __cxa_atexit takes callback, opaque operand and DSO tag.
            let register: CxaAtExit = unsafe { std::mem::transmute(address) };
            let dso = match handler {
                ExitHandler::Cxa(entry) => entry.dso,
                _ => std::ptr::null_mut(),
            };
            return Ok(Some(Registration::Cxa(register, dso)));
        }
        Ok(Some(Registration::OnExit(on_exit)))
    }

    impl Registration {
        pub(super) fn attach(self, ticket: usize) -> c_int {
            // SAFETY: the native registry owns the callback before publication;
            // these opaque integer operands are never dereferenced by either side.
            unsafe {
                match self {
                    Self::OnExit(register) => register(on_exit_ticket, ticket as *mut c_void),
                    Self::Cxa(register, dso) => register(cxa_ticket, ticket as *mut c_void, dso),
                }
            }
        }
    }

    pub(super) fn finalize(dso: *mut c_void) {
        if let Some(address) = cached_host_symbol(&HOST_CXA_FINALIZE, "__cxa_finalize") {
            // Host and bridged registrations share the host's ordering. Its
            // callback claims our entry; no native lock crosses foreign code.
            let finalize: unsafe extern "C" fn(*mut c_void) =
                unsafe { std::mem::transmute(address) };
            unsafe { finalize(dso) };
        }
    }
}

pub(super) fn register_exit_handler(handler: ExitHandler) -> c_int {
    use std::sync::atomic::Ordering;
    let Ok(ticket) =
        NEXT_EXIT_TICKET.try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
    else {
        unsafe { set_abi_errno(libc::ENOMEM) };
        return -1;
    };
    #[cfg(all(not(debug_assertions), not(feature = "standalone")))]
    let bridge = match host::prepare(&handler) {
        Ok(bridge) => bridge,
        Err(()) => {
            unsafe { set_abi_errno(libc::ENOMEM) };
            return -1;
        }
    };
    {
        let mut handlers = EXIT_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
        if handlers.try_push((ticket, handler)).is_err() {
            unsafe { set_abi_errno(libc::ENOMEM) };
            return -1;
        }
    }
    #[cfg(all(not(debug_assertions), not(feature = "standalone")))]
    if let Some(bridge) = bridge
        && bridge.attach(ticket) != 0
    {
        let mut handlers = EXIT_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
        let _ = handlers.remove_by_ticket(ticket);
        unsafe { set_abi_errno(libc::ENOMEM) };
        return -1;
    }
    0
}

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
    #[cfg(all(not(debug_assertions), not(feature = "standalone")))]
    host::finalize(dso);
    loop {
        let handler = {
            let mut handlers = EXIT_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
            handlers.rremove_matching(|handler| match handler {
                ExitHandler::Cxa(entry) => dso.is_null() || entry.dso == dso,
                // The C++ ABI specifies plain atexit as a null-DSO registration.
                ExitHandler::Atexit(_) => dso.is_null(),
                ExitHandler::OnExit(_) => false,
            })
        };
        let Some(handler) = handler else { break };
        invoke_exit_handler(handler, 0);
    }
    // Destructors can fork or register another callback for this DSO. Keep
    // its handlers until the destructor pass finishes, then withdraw all of
    // them before the loader can unmap the object. NULL preserves process
    // registrations, matching GNU __cxa_finalize's lifecycle contract.
    crate::pthread_abi::unregister_atfork(dso);
}

/// Normal process termination destroys the calling thread's C++ TLS objects
/// before process callbacks. The two registries below mirror registration in
/// startup_abi::__cxa_thread_atexit_impl: the host owns its TLS/DSO pinning when
/// interposing, while standalone and recursive-lookup fallbacks are owned here.
/// Do not put this in finalize_cxa_handlers: dlclose is not thread termination.
fn run_exiting_thread_dtors() {
    #[cfg(all(not(debug_assertions), not(feature = "standalone")))]
    if let Some(address) = crate::host_resolve::resolve_host_symbol_raw("__call_tls_dtors") {
        // SAFETY: lookup excludes our export and returns the host's no-argument
        // destructor driver. It removes each entry before invoking user code,
        // so recursive exit and newly registered TLS destructors remain valid.
        let drain: unsafe extern "C" fn() = unsafe { std::mem::transmute(address) };
        unsafe { drain() };
    }
    // This is also needed for fallback registrations made during host lookup.
    // invoke_tls_dtors drops the TLS borrow before entering each destructor.
    crate::startup_abi::invoke_tls_dtors();
}

pub(super) fn run_exit_handlers(status: c_int) {
    // No registry lock or extracted callback batch may cross TLS destruction.
    // A TLS destructor can register process callbacks or recursively call exit.
    run_exiting_thread_dtors();
    loop {
        let handler = EXIT_HANDLERS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop();
        let Some((_, handler)) = handler else { break };
        // Claim before invocation. Reentrant registrations precede older ones.
        invoke_exit_handler(handler, status);
    }
}
