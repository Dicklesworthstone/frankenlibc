//! Normal process termination for the native DSO namespace.
//!
//! Host and owned-libc exit paths schedule the same permanent Rust trampoline;
//! native tokens never enter a host C++ termination list. Native callbacks run
//! before native ELF FINI, with the exiting thread's TLS still addressable.
//! This is not a merged host/native atexit ordering implementation.

use std::ffi::{c_int, c_void};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::{InitState, OPERATIONS, cxa, ifunc, lifecycle, registry, thread_exit};

// OPERATIONS serializes transitions; atomics also permit checking reentry
// without holding a second mutex across user code. 0=idle, 1=TLS/C++, 2=FINI,
// 3=complete. Recursive exit resumes the queue instead of repeating callbacks.
static PHASE: AtomicUsize = AtomicUsize::new(0);
#[cfg(not(feature = "standalone"))]
static HOST_INSTALLED: AtomicBool = AtomicBool::new(false);
static OWNED_INSTALLED: AtomicBool = AtomicBool::new(false);

enum Work { Fini(usize), Owner(usize), All }
static WORK: Mutex<Vec<Work>> = Mutex::new(Vec::new());

pub(super) fn unloading() -> bool { PHASE.load(Ordering::Relaxed) >= 2 }

pub(super) fn install() -> Option<()> {
    let _operation = OPERATIONS.lock();
    // A standalone process has no host on_exit. Requiring that symbol
    // would reject every otherwise valid native DSO before publication.
    #[cfg(not(feature = "standalone"))]
    if !HOST_INSTALLED.load(Ordering::Relaxed) {
        let address = crate::host_resolve::resolve_host_symbol_raw("on_exit")?;
        type OnExit = unsafe extern "C" fn(
            Option<unsafe extern "C" fn(c_int, *mut c_void)>, *mut c_void,
        ) -> c_int;
        // SAFETY: host symbol resolution selects on_exit with this exact ABI.
        // The registered callback is permanent Rust code, not unloadable DSO
        // code, and its argument contains no native loader handle or pointer.
        let register: OnExit = unsafe { std::mem::transmute(address) };
        if unsafe { register(Some(hook), std::ptr::null_mut()) } != 0 { return None; }
        HOST_INSTALLED.store(true, Ordering::Relaxed);
    }
    if !OWNED_INSTALLED.load(Ordering::Relaxed) {
        if unsafe { crate::stdlib_abi::on_exit(Some(hook), std::ptr::null_mut()) } != 0 { return None; }
        OWNED_INSTALLED.store(true, Ordering::Relaxed);
    }
    Some(())
}

fn finish() -> Option<()> {
    if ifunc::active() { return None; }
    let _operation = OPERATIONS.lock();
    if PHASE.load(Ordering::Relaxed) == 3 { return Some(()); }
    if PHASE.load(Ordering::Relaxed) < 2 {
        PHASE.store(1, Ordering::Relaxed);
        // Removing each entry before calling it also makes recursive exit
        // from a TLS or C++ destructor continue with older pending entries.
        thread_exit::prepare_process_exit();
        cxa::finalize_all()?;
        if PHASE.load(Ordering::Relaxed) < 2 {
            let mut dsos = registry().lock().ok()?;
            let mut order = dsos.iter().filter(|dso| {
                !dso.retiring && dso.state != InitState::Pending
            }).map(|dso| (dso.initialized_at, dso.id)).collect::<Vec<_>>();
            order.sort_unstable_by(|left, right| right.cmp(left));
            let mut work = Vec::new();
            for (_, id) in order {
                let dso = dsos.iter_mut().find(|dso| dso.id == id)?;
                // Pin every mapping for the entire shutdown, including
                // NODELETE and objects still owned by other live threads.
                dso.retiring = true;
                work.extend(dso.callbacks.fini.iter().copied().map(Work::Fini));
                work.push(Work::Owner(id));
            }
            work.push(Work::All);
            work.reverse();
            *WORK.lock().ok()? = work;
            cxa::begin_process_fini();
            PHASE.store(2, Ordering::Relaxed);
        }
    }
    loop {
        let next = WORK.lock().ok()?.pop();
        match next {
            Some(Work::Fini(address)) => {
                // SAFETY: validated native executable address. All shutdown
                // mappings remain pinned, and no registry/queue guard is held.
                unsafe { lifecycle::call_fini(address) };
            }
            Some(Work::Owner(id)) => cxa::finalize_owners(&[id])?,
            Some(Work::All) => cxa::finalize_all()?,
            None => { PHASE.store(3, Ordering::Relaxed); return Some(()); }
        }
    }
    // Intentionally no munmap or destruction of loader/TLS state. Finalizers
    // and other exit callbacks can still refer to it; the kernel reclaims it.
}

unsafe extern "C" fn hook(_status: c_int, _argument: *mut c_void) {
    let _ = finish();
}

unsafe extern "C" fn exit_impl(status: c_int) -> ! {
    thread_exit::prepare_process_exit();
    // The owned hook normally runs from libc's normal exit handler chain.
    // On reentry that hook has already been consumed, so resume explicitly.
    if PHASE.load(Ordering::Relaxed) != 0 { let _ = finish(); }
    unsafe { crate::stdlib_abi::exit(status) }
}

unsafe extern "C" fn immediate_exit(status: c_int) -> ! {
    frankenlibc_core::syscall::sys_exit_group(status)
}

pub(super) fn resolver_address(name: &str, version: Option<&str>) -> Option<u64> {
    let (address, versions): (*const (), &[&str]) = match name {
        "exit" => (exit_impl as *const (), &["GLIBC_2.2.5"]),
        "_Exit" | "_exit" => (immediate_exit as *const (), &["GLIBC_2.2.5"]),
        "quick_exit" => (crate::stdlib_abi::quick_exit as *const (), &["GLIBC_2.10", "GLIBC_2.24"]),
        _ => return None,
    };
    if version.is_some_and(|version| !versions.contains(&version)) { return None; }
    Some(address as usize as u64)
}
