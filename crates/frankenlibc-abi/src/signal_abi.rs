//! ABI layer for `<signal.h>` functions.
//!
//! Validates via `frankenlibc_core::signal` helpers, then calls `libc` for
//! actual signal delivery.

use std::cell::RefCell;
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use frankenlibc_core::errno;
use frankenlibc_core::signal as signal_core;
use frankenlibc_core::syscall;
use frankenlibc_membrane::hji_reachability::{HjiReachabilityController, ReachState};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::runtime_policy;

#[inline]
fn last_host_errno(default_errno: c_int) -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(default_errno)
}

const MAX_TRACKED_SIGNAL: usize = 128;
const HJI_WARMUP_OBSERVATIONS: usize = 64;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SA_RESTORER_FLAG: c_int = 0x04000000;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelSigaction {
    sa_handler: usize,
    sa_flags: usize,
    sa_restorer: usize,
    sa_mask: libc::c_ulong,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl KernelSigaction {
    const fn zeroed() -> Self {
        Self {
            sa_handler: 0,
            sa_flags: 0,
            sa_restorer: 0,
            sa_mask: 0,
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[unsafe(naked)]
unsafe extern "C" fn signal_restorer_trampoline() {
    // SAFETY: this is the x86_64 Linux signal restorer sequence. The kernel
    // enters here after a user handler returns and expects a bare rt_sigreturn
    // syscall with no Rust prologue/epilogue.
    std::arch::naked_asm!("mov rax, 15", "syscall", "ud2",);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn signal_restorer_trampoline_addr() -> usize {
    signal_restorer_trampoline as *const () as usize
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn sigset_first_word(set: &libc::sigset_t) -> libc::c_ulong {
    // SAFETY: x86_64 rt_sigaction consumes only the first kernel-sized word.
    unsafe { *(set as *const libc::sigset_t).cast::<libc::c_ulong>() }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_sigset_first_word(set: &mut libc::sigset_t, value: libc::c_ulong) {
    // SAFETY: the caller zero-initializes the rest of the sigset_t storage.
    unsafe {
        *(set as *mut libc::sigset_t).cast::<libc::c_ulong>() = value;
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn user_to_kernel_sigaction(act: &libc::sigaction) -> KernelSigaction {
    KernelSigaction {
        sa_handler: act.sa_sigaction,
        sa_flags: act.sa_flags as usize,
        sa_restorer: act.sa_restorer.map_or(0usize, |restorer| restorer as usize),
        sa_mask: sigset_first_word(&act.sa_mask),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn kernel_to_user_sigaction(act: &KernelSigaction) -> libc::sigaction {
    let mut user = unsafe { std::mem::zeroed::<libc::sigaction>() };
    user.sa_sigaction = act.sa_handler;
    user.sa_flags = act.sa_flags as c_int;
    if act.sa_restorer != 0 {
        // SAFETY: kernel-provided restorer address is surfaced verbatim.
        user.sa_restorer =
            unsafe { std::mem::transmute::<usize, Option<extern "C" fn()>>(act.sa_restorer) };
    }
    write_sigset_first_word(&mut user.sa_mask, act.sa_mask);
    user
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignalSafetyClassification {
    Safe = 0,
    DeferSignal = 1,
    MaskRequired = 2,
}

impl SignalSafetyClassification {
    const fn as_u8(self) -> u8 {
        self as u8
    }

    const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Safe,
            1 => Self::DeferSignal,
            _ => Self::MaskRequired,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum SignalCriticalSectionKind {
    MallocArenaLockAcquire = 0,
    MallocFastbinMutation = 1,
    MallocLargebinLink = 2,
    PtrValidatorTlsCache = 3,
    PtrValidatorArenaLookup = 4,
    PtrValidatorFingerprint = 5,
    PtrValidatorCanaryCheck = 6,
    RuntimePolicyDecision = 7,
    SetjmpContextTransfer = 8,
    StdioRegistryFlush = 9,
}

impl SignalCriticalSectionKind {
    const fn risk_ppm(self) -> u32 {
        match self {
            Self::MallocArenaLockAcquire => 820_000,
            Self::MallocFastbinMutation => 780_000,
            Self::MallocLargebinLink => 860_000,
            Self::PtrValidatorTlsCache => 180_000,
            Self::PtrValidatorArenaLookup => 420_000,
            Self::PtrValidatorFingerprint => 510_000,
            Self::PtrValidatorCanaryCheck => 560_000,
            Self::RuntimePolicyDecision => 320_000,
            Self::SetjmpContextTransfer => 900_000,
            Self::StdioRegistryFlush => 470_000,
        }
    }

    const fn latency_ns(self) -> u64 {
        match self {
            Self::MallocArenaLockAcquire => 90_000,
            Self::MallocFastbinMutation => 70_000,
            Self::MallocLargebinLink => 120_000,
            Self::PtrValidatorTlsCache => 400,
            Self::PtrValidatorArenaLookup => 5_000,
            Self::PtrValidatorFingerprint => 12_000,
            Self::PtrValidatorCanaryCheck => 18_000,
            Self::RuntimePolicyDecision => 2_000,
            Self::SetjmpContextTransfer => 140_000,
            Self::StdioRegistryFlush => 35_000,
        }
    }

    const fn symbol(self) -> &'static str {
        match self {
            Self::MallocArenaLockAcquire => "malloc",
            Self::MallocFastbinMutation => "free",
            Self::MallocLargebinLink => "realloc",
            Self::PtrValidatorTlsCache => "ptr_validator_tls",
            Self::PtrValidatorArenaLookup => "ptr_validator_arena",
            Self::PtrValidatorFingerprint => "ptr_validator_fingerprint",
            Self::PtrValidatorCanaryCheck => "ptr_validator_canary",
            Self::RuntimePolicyDecision => "runtime_policy",
            Self::SetjmpContextTransfer => "siglongjmp",
            Self::StdioRegistryFlush => "fflush",
        }
    }

    const fn range_label(self) -> &'static str {
        match self {
            Self::MallocArenaLockAcquire => "malloc.arena_lock_acquire",
            Self::MallocFastbinMutation => "malloc.fastbin_mutation",
            Self::MallocLargebinLink => "malloc.largebin_link",
            Self::PtrValidatorTlsCache => "membrane.tls_cache",
            Self::PtrValidatorArenaLookup => "membrane.arena_lookup",
            Self::PtrValidatorFingerprint => "membrane.fingerprint",
            Self::PtrValidatorCanaryCheck => "membrane.canary_check",
            Self::RuntimePolicyDecision => "runtime_policy.decide",
            Self::SetjmpContextTransfer => "setjmp.context_transfer",
            Self::StdioRegistryFlush => "stdio.registry_flush",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalSafetyRange {
    pub symbol: &'static str,
    pub range_label: &'static str,
    pub classification: SignalSafetyClassification,
}

pub const SIGNAL_SAFETY_MAP: [SignalSafetyRange; 10] = [
    SignalSafetyRange {
        symbol: SignalCriticalSectionKind::MallocArenaLockAcquire.symbol(),
        range_label: SignalCriticalSectionKind::MallocArenaLockAcquire.range_label(),
        classification: SignalSafetyClassification::MaskRequired,
    },
    SignalSafetyRange {
        symbol: SignalCriticalSectionKind::MallocFastbinMutation.symbol(),
        range_label: SignalCriticalSectionKind::MallocFastbinMutation.range_label(),
        classification: SignalSafetyClassification::DeferSignal,
    },
    SignalSafetyRange {
        symbol: SignalCriticalSectionKind::MallocLargebinLink.symbol(),
        range_label: SignalCriticalSectionKind::MallocLargebinLink.range_label(),
        classification: SignalSafetyClassification::MaskRequired,
    },
    SignalSafetyRange {
        symbol: SignalCriticalSectionKind::PtrValidatorTlsCache.symbol(),
        range_label: SignalCriticalSectionKind::PtrValidatorTlsCache.range_label(),
        classification: SignalSafetyClassification::Safe,
    },
    SignalSafetyRange {
        symbol: SignalCriticalSectionKind::PtrValidatorArenaLookup.symbol(),
        range_label: SignalCriticalSectionKind::PtrValidatorArenaLookup.range_label(),
        classification: SignalSafetyClassification::DeferSignal,
    },
    SignalSafetyRange {
        symbol: SignalCriticalSectionKind::PtrValidatorFingerprint.symbol(),
        range_label: SignalCriticalSectionKind::PtrValidatorFingerprint.range_label(),
        classification: SignalSafetyClassification::DeferSignal,
    },
    SignalSafetyRange {
        symbol: SignalCriticalSectionKind::PtrValidatorCanaryCheck.symbol(),
        range_label: SignalCriticalSectionKind::PtrValidatorCanaryCheck.range_label(),
        classification: SignalSafetyClassification::DeferSignal,
    },
    SignalSafetyRange {
        symbol: SignalCriticalSectionKind::RuntimePolicyDecision.symbol(),
        range_label: SignalCriticalSectionKind::RuntimePolicyDecision.range_label(),
        classification: SignalSafetyClassification::Safe,
    },
    SignalSafetyRange {
        symbol: SignalCriticalSectionKind::SetjmpContextTransfer.symbol(),
        range_label: SignalCriticalSectionKind::SetjmpContextTransfer.range_label(),
        classification: SignalSafetyClassification::MaskRequired,
    },
    SignalSafetyRange {
        symbol: SignalCriticalSectionKind::StdioRegistryFlush.symbol(),
        range_label: SignalCriticalSectionKind::StdioRegistryFlush.range_label(),
        classification: SignalSafetyClassification::DeferSignal,
    },
];

struct SignalHandlerSlot {
    handler: AtomicUsize,
    flags: AtomicUsize,
}

impl SignalHandlerSlot {
    const fn new() -> Self {
        Self {
            handler: AtomicUsize::new(0),
            flags: AtomicUsize::new(0),
        }
    }
}

static SIGNAL_HANDLER_SLOTS: [SignalHandlerSlot; MAX_TRACKED_SIGNAL + 1] =
    [const { SignalHandlerSlot::new() }; MAX_TRACKED_SIGNAL + 1];

thread_local! {
    static SIGNAL_CRITICAL_DEPTH: AtomicU32 = const { AtomicU32::new(0) };
    static SIGNAL_CLASSIFICATION: AtomicU8 =
        const { AtomicU8::new(SignalSafetyClassification::Safe as u8) };
    static DEFERRED_SIGNALS: [AtomicU32; MAX_TRACKED_SIGNAL + 1] =
        const { [const { AtomicU32::new(0) }; MAX_TRACKED_SIGNAL + 1] };
    static SIGNAL_HJI_CONTROLLER: RefCell<HjiReachabilityController> =
        RefCell::new(HjiReachabilityController::new());
}

static SIGNAL_DEFERRED_DELIVERIES: AtomicU64 = AtomicU64::new(0);
static SIGNAL_FLUSHED_DELIVERIES: AtomicU64 = AtomicU64::new(0);
static SIGNAL_IMMEDIATE_DELIVERIES: AtomicU64 = AtomicU64::new(0);

fn signal_slot(signum: c_int) -> Option<&'static SignalHandlerSlot> {
    if (1..=MAX_TRACKED_SIGNAL as c_int).contains(&signum) {
        Some(&SIGNAL_HANDLER_SLOTS[signum as usize])
    } else {
        None
    }
}

fn is_default_or_ignore_handler(handler: usize) -> bool {
    handler == libc::SIG_DFL || handler == libc::SIG_IGN
}

fn signal_handler_trampoline_addr() -> usize {
    signal_handler_trampoline as *const () as usize
}

fn signal_siginfo_trampoline_addr() -> usize {
    signal_siginfo_trampoline as *const () as usize
}

fn is_signal_trampoline(handler: usize) -> bool {
    handler == signal_handler_trampoline_addr() || handler == signal_siginfo_trampoline_addr()
}

fn handler_dispatch_classification(kind: SignalCriticalSectionKind) -> SignalSafetyClassification {
    let depth = SIGNAL_CRITICAL_DEPTH.with(|value| value.load(Ordering::Relaxed));
    let adverse = depth > 1;
    let hji_state = SIGNAL_HJI_CONTROLLER.with(|controller| {
        let mut controller = controller.borrow_mut();
        for _ in 0..HJI_WARMUP_OBSERVATIONS {
            controller.observe(kind.risk_ppm(), kind.latency_ns(), adverse);
        }
        controller.state()
    });
    match hji_state {
        ReachState::Safe => SignalSafetyClassification::Safe,
        ReachState::Approaching | ReachState::Calibrating => {
            SignalSafetyClassification::DeferSignal
        }
        ReachState::Breached => SignalSafetyClassification::MaskRequired,
    }
}

fn queue_deferred_signal(signum: c_int) {
    if !(1..=MAX_TRACKED_SIGNAL as c_int).contains(&signum) {
        return;
    }
    DEFERRED_SIGNALS.with(|pending| {
        pending[signum as usize].fetch_add(1, Ordering::Relaxed);
    });
    SIGNAL_DEFERRED_DELIVERIES.fetch_add(1, Ordering::Relaxed);
}

fn take_deferred_signals() -> Vec<(c_int, u32)> {
    DEFERRED_SIGNALS.with(|pending| {
        let mut out = Vec::new();
        for signum in 1..=MAX_TRACKED_SIGNAL as c_int {
            let count = pending[signum as usize].swap(0, Ordering::Relaxed);
            if count != 0 {
                out.push((signum, count));
            }
        }
        out
    })
}

unsafe fn dispatch_registered_handler(
    signum: c_int,
    info: *mut libc::siginfo_t,
    context: *mut c_void,
) {
    let Some(slot) = signal_slot(signum) else {
        return;
    };
    let handler = slot.handler.load(Ordering::Relaxed);
    if handler == 0 || is_default_or_ignore_handler(handler) {
        return;
    }
    let flags = slot.flags.load(Ordering::Relaxed) as c_int;
    if flags & libc::SA_SIGINFO != 0 {
        // SAFETY: the handler pointer was installed by the caller via sigaction with SA_SIGINFO.
        let handler: extern "C" fn(c_int, *mut libc::siginfo_t, *mut c_void) =
            unsafe { std::mem::transmute(handler) };
        handler(signum, info, context);
    } else {
        // SAFETY: the handler pointer was installed by the caller via signal/sigaction.
        let handler: extern "C" fn(c_int) = unsafe { std::mem::transmute(handler) };
        handler(signum);
    }
}

unsafe extern "C" fn signal_handler_trampoline(signum: c_int) {
    let classification = SIGNAL_CLASSIFICATION
        .with(|value| SignalSafetyClassification::from_u8(value.load(Ordering::Relaxed)));
    if SIGNAL_CRITICAL_DEPTH.with(|value| value.load(Ordering::Relaxed)) > 0
        && !matches!(classification, SignalSafetyClassification::Safe)
    {
        queue_deferred_signal(signum);
        return;
    }
    SIGNAL_IMMEDIATE_DELIVERIES.fetch_add(1, Ordering::Relaxed);
    // SAFETY: dispatch uses the stored user handler for this signal number.
    unsafe { dispatch_registered_handler(signum, std::ptr::null_mut(), std::ptr::null_mut()) };
}

unsafe extern "C" fn signal_siginfo_trampoline(
    signum: c_int,
    info: *mut libc::siginfo_t,
    context: *mut c_void,
) {
    let classification = SIGNAL_CLASSIFICATION
        .with(|value| SignalSafetyClassification::from_u8(value.load(Ordering::Relaxed)));
    if SIGNAL_CRITICAL_DEPTH.with(|value| value.load(Ordering::Relaxed)) > 0
        && !matches!(classification, SignalSafetyClassification::Safe)
    {
        queue_deferred_signal(signum);
        return;
    }
    SIGNAL_IMMEDIATE_DELIVERIES.fetch_add(1, Ordering::Relaxed);
    // SAFETY: dispatch uses the stored user handler for this signal number.
    unsafe { dispatch_registered_handler(signum, info, context) };
}

fn rewrite_old_sigaction(oldact_ref: &mut libc::sigaction, prev_handler: usize, prev_flags: usize) {
    if is_signal_trampoline(oldact_ref.sa_sigaction) && prev_handler != 0 {
        let kernel_flags = oldact_ref.sa_flags;
        oldact_ref.sa_sigaction = prev_handler;
        oldact_ref.sa_flags = (prev_flags as c_int) | (kernel_flags & SA_RESTORER_FLAG);
    }
}

pub struct SignalCriticalSectionGuard {
    active: bool,
}

impl Drop for SignalCriticalSectionGuard {
    fn drop(&mut self) {
        if self.active {
            exit_signal_critical_section();
            self.active = false;
        }
    }
}

#[must_use]
pub fn enter_signal_critical_section(
    kind: SignalCriticalSectionKind,
) -> SignalCriticalSectionGuard {
    SIGNAL_CRITICAL_DEPTH.with(|depth| {
        depth.fetch_add(1, Ordering::Relaxed);
    });
    let classification = handler_dispatch_classification(kind);
    SIGNAL_CLASSIFICATION.with(|value| value.store(classification.as_u8(), Ordering::Relaxed));
    SignalCriticalSectionGuard { active: true }
}

pub fn exit_signal_critical_section() {
    let should_flush = SIGNAL_CRITICAL_DEPTH.with(|depth| {
        let current = depth.load(Ordering::Relaxed);
        if current == 0 {
            return false;
        }
        let next = current - 1;
        depth.store(next, Ordering::Relaxed);
        next == 0
    });
    if !should_flush {
        return;
    }
    SIGNAL_CLASSIFICATION
        .with(|value| value.store(SignalSafetyClassification::Safe.as_u8(), Ordering::Relaxed));
    for (signum, count) in take_deferred_signals() {
        for _ in 0..count {
            SIGNAL_FLUSHED_DELIVERIES.fetch_add(1, Ordering::Relaxed);
            // SAFETY: deferred delivery replays the previously registered handler on the same thread.
            unsafe {
                dispatch_registered_handler(signum, std::ptr::null_mut(), std::ptr::null_mut())
            };
        }
    }
}

#[doc(hidden)]
pub fn current_signal_classification_for_test() -> SignalSafetyClassification {
    SIGNAL_CLASSIFICATION
        .with(|value| SignalSafetyClassification::from_u8(value.load(Ordering::Relaxed)))
}

#[doc(hidden)]
pub unsafe fn invoke_signal_handler_for_test(signum: c_int) {
    let flags = signal_slot(signum)
        .map(|slot| slot.flags.load(Ordering::Relaxed) as c_int)
        .unwrap_or(0);
    if flags & libc::SA_SIGINFO != 0 {
        // SAFETY: this test hook exercises the same trampoline path used by the kernel.
        unsafe { signal_siginfo_trampoline(signum, std::ptr::null_mut(), std::ptr::null_mut()) };
    } else {
        // SAFETY: this test hook exercises the same trampoline path used by the kernel.
        unsafe { signal_handler_trampoline(signum) };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalDeliveryMetrics {
    pub deferred: u64,
    pub flushed: u64,
    pub immediate: u64,
}

#[doc(hidden)]
pub fn reset_signal_delivery_metrics_for_test() {
    SIGNAL_DEFERRED_DELIVERIES.store(0, Ordering::Relaxed);
    SIGNAL_FLUSHED_DELIVERIES.store(0, Ordering::Relaxed);
    SIGNAL_IMMEDIATE_DELIVERIES.store(0, Ordering::Relaxed);
}

#[doc(hidden)]
pub fn signal_delivery_metrics_for_test() -> SignalDeliveryMetrics {
    SignalDeliveryMetrics {
        deferred: SIGNAL_DEFERRED_DELIVERIES.load(Ordering::Relaxed),
        flushed: SIGNAL_FLUSHED_DELIVERIES.load(Ordering::Relaxed),
        immediate: SIGNAL_IMMEDIATE_DELIVERIES.load(Ordering::Relaxed),
    }
}

// ---------------------------------------------------------------------------
// signal
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn signal(signum: c_int, handler: libc::sighandler_t) -> libc::sighandler_t {
    let sig_err = libc::SIG_ERR;

    let (_mode, decision) =
        runtime_policy::decide(ApiFamily::Signal, signum as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return sig_err;
    }

    if !signal_core::catchable_signal(signum) {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return sig_err;
    }

    let mut act = unsafe { std::mem::zeroed::<libc::sigaction>() };
    act.sa_sigaction = handler as libc::sighandler_t;
    let mut oldact = unsafe { std::mem::zeroed::<libc::sigaction>() };
    let rc = unsafe { sigaction(signum, &act as *const libc::sigaction, &mut oldact) };
    let adverse = rc != 0;
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, adverse);
    if adverse {
        sig_err
    } else {
        oldact.sa_sigaction
    }
}

// ---------------------------------------------------------------------------
// raise
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn raise(signum: c_int) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Signal, signum as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    if !signal_core::valid_signal(signum) {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    let pid = syscall::sys_getpid();
    let rc = unsafe { libc::syscall(libc::SYS_kill, pid, signum) as c_int };
    let adverse = rc != 0;
    if adverse {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EINVAL),
            )
        };
    }
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// kill
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn kill(pid: libc::pid_t, signum: c_int) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Signal, signum as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    if !signal_core::valid_signal(signum) && signum != 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_kill, pid, signum) as c_int };
    let adverse = rc != 0;
    if adverse {
        unsafe { set_abi_errno(last_host_errno(errno::ESRCH)) };
    }
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// killpg
// ---------------------------------------------------------------------------

/// Send a signal to a process group.
///
/// Equivalent to `kill(-pgrp, sig)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn killpg(pgrp: libc::pid_t, signum: c_int) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Signal, signum as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    if pgrp < 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    if !signal_core::valid_signal(signum) && signum != 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    // killpg(pgrp, sig) == kill(-pgrp, sig); for pgrp==0 means own process group.
    let target = if pgrp == 0 { 0 } else { -pgrp };
    let rc = unsafe { libc::syscall(libc::SYS_kill, target, signum) as c_int };
    let adverse = rc != 0;
    if adverse {
        unsafe { set_abi_errno(last_host_errno(errno::ESRCH)) };
    }
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// sigprocmask
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigprocmask(
    how: c_int,
    set: *const libc::sigset_t,
    oldset: *mut libc::sigset_t,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Signal, how as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    let kernel_sigset_size = std::mem::size_of::<libc::c_ulong>();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            how,
            set,
            oldset,
            kernel_sigset_size,
        ) as c_int
    };
    let adverse = rc != 0;
    if adverse {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
    }
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 8, adverse);
    rc
}

// ---------------------------------------------------------------------------
// pthread_sigmask (identical to sigprocmask on Linux)
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_sigmask(
    how: c_int,
    set: *const libc::sigset_t,
    oldset: *mut libc::sigset_t,
) -> c_int {
    // On Linux, pthread_sigmask is identical to sigprocmask — both operate on
    // the calling thread's signal mask via rt_sigprocmask.
    unsafe { sigprocmask(how, set, oldset) }
}

// ---------------------------------------------------------------------------
// sigemptyset
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigemptyset(set: *mut libc::sigset_t) -> c_int {
    if set.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    // Zero the entire sigset_t structure.
    unsafe {
        std::ptr::write_bytes(set as *mut u8, 0, std::mem::size_of::<libc::sigset_t>());
    }
    0
}

// ---------------------------------------------------------------------------
// sigfillset
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigfillset(set: *mut libc::sigset_t) -> c_int {
    if set.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    // Set all bits in the sigset_t structure.
    unsafe {
        std::ptr::write_bytes(set as *mut u8, 0xFF, std::mem::size_of::<libc::sigset_t>());
    }
    0
}

// ---------------------------------------------------------------------------
// sigaddset
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigaddset(set: *mut libc::sigset_t, signum: c_int) -> c_int {
    if set.is_null() || !signal_core::valid_signal(signum) {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    // sigset_t is an array of unsigned longs. Signal N maps to:
    //   word = (N-1) / bits_per_word, bit = (N-1) % bits_per_word
    let idx = (signum - 1) as usize;
    let bits_per_word = std::mem::size_of::<libc::c_ulong>() * 8;
    let word = idx / bits_per_word;
    let bit = idx % bits_per_word;
    let words = set as *mut libc::c_ulong;
    unsafe { *words.add(word) |= 1usize.wrapping_shl(bit as u32) as libc::c_ulong };
    0
}

// ---------------------------------------------------------------------------
// sigdelset
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigdelset(set: *mut libc::sigset_t, signum: c_int) -> c_int {
    if set.is_null() || !signal_core::valid_signal(signum) {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let idx = (signum - 1) as usize;
    let bits_per_word = std::mem::size_of::<libc::c_ulong>() * 8;
    let word = idx / bits_per_word;
    let bit = idx % bits_per_word;
    let words = set as *mut libc::c_ulong;
    unsafe { *words.add(word) &= !(1usize.wrapping_shl(bit as u32) as libc::c_ulong) };
    0
}

// ---------------------------------------------------------------------------
// sigismember
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigismember(set: *const libc::sigset_t, signum: c_int) -> c_int {
    if set.is_null() || !signal_core::valid_signal(signum) {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let idx = (signum - 1) as usize;
    let bits_per_word = std::mem::size_of::<libc::c_ulong>() * 8;
    let word = idx / bits_per_word;
    let bit = idx % bits_per_word;
    let words = set as *const libc::c_ulong;
    let val = unsafe { *words.add(word) };
    if (val & (1usize.wrapping_shl(bit as u32) as libc::c_ulong)) != 0 {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// pause
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pause() -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Signal, 0, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_pause) as c_int };
    // pause always returns -1 with EINTR when interrupted.
    unsafe { set_abi_errno(last_host_errno(errno::EINTR)) };
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, true);
    rc
}

// ---------------------------------------------------------------------------
// sigsuspend
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigsuspend(mask: *const libc::sigset_t) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Signal, mask as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    if mask.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    let kernel_sigset_size = std::mem::size_of::<libc::c_ulong>();
    let rc = unsafe { libc::syscall(libc::SYS_rt_sigsuspend, mask, kernel_sigset_size) as c_int };
    // sigsuspend always returns -1 with EINTR.
    unsafe { set_abi_errno(last_host_errno(errno::EINTR)) };
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, true);
    rc
}

// ---------------------------------------------------------------------------
// sigaltstack
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigaltstack(
    ss: *const libc::stack_t,
    old_ss: *mut libc::stack_t,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Signal, ss as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_sigaltstack, ss, old_ss) as c_int };
    let adverse = rc != 0;
    if adverse {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
    }
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// sigaction
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigaction(
    signum: c_int,
    act: *const libc::sigaction,
    oldact: *mut libc::sigaction,
) -> c_int {
    let mode = runtime_policy::mode();
    let decision = if mode.heals_enabled() {
        let (_, decision) =
            runtime_policy::decide(ApiFamily::Signal, signum as usize, 0, false, true, 0);
        if matches!(decision.action, MembraneAction::Deny) {
            unsafe { set_abi_errno(errno::EINVAL) };
            runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
            return -1;
        }
        Some(decision)
    } else {
        None
    };

    if !signal_core::catchable_signal(signum) {
        unsafe { set_abi_errno(errno::EINVAL) };
        if let Some(decision) = decision {
            runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        }
        return -1;
    }

    // Linux `rt_sigaction` expects the kernel sigset size (`sizeof(unsigned long)`),
    // not libc's userspace `sigset_t` size.
    let kernel_sigset_size = std::mem::size_of::<libc::c_ulong>();
    let mut kernel_act = KernelSigaction::zeroed();
    let mut kernel_oldact = KernelSigaction::zeroed();
    let kernel_act_ptr = if act.is_null() {
        std::ptr::null()
    } else {
        // SAFETY: act was supplied by the caller for this syscall wrapper.
        kernel_act = user_to_kernel_sigaction(unsafe { &*act });
        let user_handler = kernel_act.sa_handler;
        if !is_default_or_ignore_handler(user_handler) {
            if kernel_act.sa_flags & libc::SA_SIGINFO as usize != 0 {
                kernel_act.sa_handler = signal_siginfo_trampoline_addr();
            } else {
                kernel_act.sa_handler = signal_handler_trampoline_addr();
            }
            if kernel_act.sa_flags & SA_RESTORER_FLAG as usize == 0 || kernel_act.sa_restorer == 0 {
                kernel_act.sa_flags |= SA_RESTORER_FLAG as usize;
                kernel_act.sa_restorer = signal_restorer_trampoline_addr();
            }
        }
        &kernel_act as *const KernelSigaction
    };
    let kernel_oldact_ptr = if oldact.is_null() {
        std::ptr::null_mut()
    } else {
        &mut kernel_oldact as *mut KernelSigaction
    };
    let (prev_handler, prev_flags) = signal_slot(signum)
        .map(|slot| {
            (
                slot.handler.load(Ordering::Relaxed),
                slot.flags.load(Ordering::Relaxed),
            )
        })
        .unwrap_or((0, 0));
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigaction,
            signum,
            kernel_act_ptr,
            kernel_oldact_ptr,
            kernel_sigset_size,
        ) as c_int
    };
    let adverse = rc != 0;
    if adverse {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
    } else {
        if !oldact.is_null() {
            let mut user_oldact = kernel_to_user_sigaction(&kernel_oldact);
            rewrite_old_sigaction(&mut user_oldact, prev_handler, prev_flags);
            // SAFETY: oldact is caller-provided writable storage.
            unsafe { *oldact = user_oldact };
        }
        if !act.is_null() {
            let user_handler = kernel_act.sa_handler;
            if let Some(slot) = signal_slot(signum) {
                if is_default_or_ignore_handler(user_handler) {
                    slot.handler.store(user_handler, Ordering::Relaxed);
                    slot.flags.store(kernel_act.sa_flags, Ordering::Relaxed);
                } else {
                    // SAFETY: act is non-null in this branch.
                    let user_act = unsafe { &*act };
                    slot.handler.store(user_act.sa_sigaction, Ordering::Relaxed);
                    slot.flags
                        .store(user_act.sa_flags as usize, Ordering::Relaxed);
                }
            }
        }
    }
    if let Some(decision) = decision {
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, adverse);
    }
    rc
}

// ---------------------------------------------------------------------------
// Additional signal functions — native raw-syscall implementation
// ---------------------------------------------------------------------------

/// `sigpending` — get pending signals via `rt_sigpending` syscall.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigpending(set: *mut libc::sigset_t) -> c_int {
    if set.is_null() {
        unsafe { set_abi_errno(libc::EFAULT as c_int) };
        return -1;
    }
    let kernel_sigset_size = std::mem::size_of::<libc::c_ulong>();
    // SAFETY: rt_sigpending writes to the provided set pointer.
    let rc = unsafe { libc::syscall(libc::SYS_rt_sigpending, set, kernel_sigset_size) as c_int };
    if rc != 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EFAULT)) };
    }
    rc
}

/// `sigwait` — wait for a signal from `set` via `rt_sigtimedwait` syscall.
/// Returns 0 on success with the signal number stored in `*sig`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigwait(set: *const libc::sigset_t, sig: *mut c_int) -> c_int {
    if set.is_null() || sig.is_null() {
        return libc::EINVAL;
    }
    let kernel_sigset_size = std::mem::size_of::<libc::c_ulong>();
    // SAFETY: rt_sigtimedwait blocks until a signal from `set` is pending.
    // With null timeout, it blocks indefinitely. Returns the signal number.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigtimedwait,
            set,
            std::ptr::null::<libc::siginfo_t>(),
            std::ptr::null::<libc::timespec>(),
            kernel_sigset_size,
        ) as c_int
    };
    if rc > 0 {
        // SAFETY: sig is non-null; we checked above.
        unsafe { *sig = rc };
        0
    } else {
        // On error, return the errno value per POSIX sigwait semantics.
        last_host_errno(libc::EINTR)
    }
}

// ---------------------------------------------------------------------------
// Legacy/obsolete signal functions — implemented natively
// ---------------------------------------------------------------------------

/// `siginterrupt` — allow signals to interrupt system calls (obsolete).
/// Implemented natively via sigaction.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn siginterrupt(sig: c_int, flag: c_int) -> c_int {
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: get current action for the signal.
    if unsafe {
        libc::syscall(
            libc::SYS_rt_sigaction,
            sig,
            std::ptr::null::<libc::sigaction>(),
            &mut sa as *mut libc::sigaction,
            std::mem::size_of::<libc::c_ulong>(),
        )
    } != 0
    {
        return -1;
    }
    if flag != 0 {
        sa.sa_flags &= !libc::SA_RESTART;
    } else {
        sa.sa_flags |= libc::SA_RESTART;
    }
    // SAFETY: set the modified action.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigaction,
            sig,
            &sa as *const libc::sigaction,
            std::ptr::null::<libc::sigaction>(),
            std::mem::size_of::<libc::c_ulong>(),
        ) as c_int
    };
    if rc != 0 { -1 } else { 0 }
}

/// `sighold` — add signal to process signal mask (XSI obsolete).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sighold(sig: c_int) -> c_int {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    unsafe { libc::sigaddset(&mut set, sig) };
    let kernel_sigset_size = std::mem::size_of::<libc::c_ulong>();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_BLOCK,
            &set as *const libc::sigset_t,
            std::ptr::null::<libc::sigset_t>(),
            kernel_sigset_size,
        ) as c_int
    };
    if rc != 0 { -1 } else { 0 }
}

/// `sigrelse` — remove signal from process signal mask (XSI obsolete).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigrelse(sig: c_int) -> c_int {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    unsafe { libc::sigaddset(&mut set, sig) };
    let kernel_sigset_size = std::mem::size_of::<libc::c_ulong>();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_UNBLOCK,
            &set as *const libc::sigset_t,
            std::ptr::null::<libc::sigset_t>(),
            kernel_sigset_size,
        ) as c_int
    };
    if rc != 0 { -1 } else { 0 }
}

/// `sigignore` — set signal disposition to SIG_IGN (XSI obsolete).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigignore(sig: c_int) -> c_int {
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = libc::SIG_IGN;
    sa.sa_flags = 0;
    unsafe { libc::sigemptyset(&mut sa.sa_mask) };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigaction,
            sig,
            &sa as *const libc::sigaction,
            std::ptr::null::<libc::sigaction>(),
            std::mem::size_of::<libc::c_ulong>(),
        ) as c_int
    };
    if rc != 0 { -1 } else { 0 }
}

/// `psiginfo` — print signal info to stderr.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn psiginfo(info: *const libc::siginfo_t, msg: *const std::ffi::c_char) {
    if info.is_null() {
        return;
    }
    let sig = unsafe { (*info).si_signo };
    let abbrev = unsafe { sigabbrev_np(sig) };
    let desc = if abbrev.is_null() {
        "Unknown signal"
    } else {
        unsafe { std::ffi::CStr::from_ptr(abbrev) }
            .to_str()
            .unwrap_or("Unknown signal")
    };
    if !msg.is_null() {
        let c_msg = unsafe { std::ffi::CStr::from_ptr(msg) };
        if let Ok(s) = c_msg.to_str() {
            let out = format!("{s}: SIG{desc}\n");
            unsafe {
                crate::unistd_abi::sys_write_fd(libc::STDERR_FILENO, out.as_ptr().cast(), out.len())
            };
            return;
        }
    }
    let out = format!("SIG{desc}\n");
    unsafe { crate::unistd_abi::sys_write_fd(libc::STDERR_FILENO, out.as_ptr().cast(), out.len()) };
}

/// `sigabbrev_np` — return abbreviated signal name (GNU extension).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigabbrev_np(sig: c_int) -> *const std::ffi::c_char {
    // Return signal abbreviation without "SIG" prefix
    static NAMES: &[&[u8]] = &[
        b"0\0",      // 0
        b"HUP\0",    // 1
        b"INT\0",    // 2
        b"QUIT\0",   // 3
        b"ILL\0",    // 4
        b"TRAP\0",   // 5
        b"ABRT\0",   // 6
        b"BUS\0",    // 7
        b"FPE\0",    // 8
        b"KILL\0",   // 9
        b"USR1\0",   // 10
        b"SEGV\0",   // 11
        b"USR2\0",   // 12
        b"PIPE\0",   // 13
        b"ALRM\0",   // 14
        b"TERM\0",   // 15
        b"STKFLT\0", // 16
        b"CHLD\0",   // 17
        b"CONT\0",   // 18
        b"STOP\0",   // 19
        b"TSTP\0",   // 20
        b"TTIN\0",   // 21
        b"TTOU\0",   // 22
        b"URG\0",    // 23
        b"XCPU\0",   // 24
        b"XFSZ\0",   // 25
        b"VTALRM\0", // 26
        b"PROF\0",   // 27
        b"WINCH\0",  // 28
        b"IO\0",     // 29
        b"PWR\0",    // 30
        b"SYS\0",    // 31
    ];
    if sig < 0 || sig as usize >= NAMES.len() {
        return std::ptr::null();
    }
    NAMES[sig as usize].as_ptr().cast()
}

/// `sigdescr_np` — return signal description string (GNU extension).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigdescr_np(sig: c_int) -> *const std::ffi::c_char {
    static DESCS: &[&[u8]] = &[
        b"Unknown signal 0\0",         // 0
        b"Hangup\0",                   // 1
        b"Interrupt\0",                // 2
        b"Quit\0",                     // 3
        b"Illegal instruction\0",      // 4
        b"Trace/breakpoint trap\0",    // 5
        b"Aborted\0",                  // 6
        b"Bus error\0",                // 7
        b"Floating point exception\0", // 8
        b"Killed\0",                   // 9
        b"User defined signal 1\0",    // 10
        b"Segmentation fault\0",       // 11
        b"User defined signal 2\0",    // 12
        b"Broken pipe\0",              // 13
        b"Alarm clock\0",              // 14
        b"Terminated\0",               // 15
        b"Stack fault\0",              // 16
        b"Child exited\0",             // 17
        b"Continued\0",                // 18
        b"Stopped (signal)\0",         // 19
        b"Stopped\0",                  // 20
        b"Stopped (tty input)\0",      // 21
        b"Stopped (tty output)\0",     // 22
        b"Urgent I/O condition\0",     // 23
        b"CPU time limit exceeded\0",  // 24
        b"File size limit exceeded\0", // 25
        b"Virtual timer expired\0",    // 26
        b"Profiling timer expired\0",  // 27
        b"Window changed\0",           // 28
        b"I/O possible\0",             // 29
        b"Power failure\0",            // 30
        b"Bad system call\0",          // 31
    ];
    if sig < 0 || sig as usize >= DESCS.len() {
        return std::ptr::null();
    }
    DESCS[sig as usize].as_ptr().cast()
}

/// `sigandset` — compute intersection of two signal sets (GNU).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigandset(
    dest: *mut libc::sigset_t,
    left: *const libc::sigset_t,
    right: *const libc::sigset_t,
) -> c_int {
    if dest.is_null() || left.is_null() || right.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    // SAFETY: sigset_t on Linux is an array of unsigned longs.
    unsafe {
        let d = dest as *mut u64;
        let l = left as *const u64;
        let r = right as *const u64;
        let n = std::mem::size_of::<libc::sigset_t>() / 8;
        for i in 0..n {
            *d.add(i) = *l.add(i) & *r.add(i);
        }
    }
    0
}

/// `sigorset` — compute union of two signal sets (GNU).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigorset(
    dest: *mut libc::sigset_t,
    left: *const libc::sigset_t,
    right: *const libc::sigset_t,
) -> c_int {
    if dest.is_null() || left.is_null() || right.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    // SAFETY: sigset_t on Linux is an array of unsigned longs.
    unsafe {
        let d = dest as *mut u64;
        let l = left as *const u64;
        let r = right as *const u64;
        let n = std::mem::size_of::<libc::sigset_t>() / 8;
        for i in 0..n {
            *d.add(i) = *l.add(i) | *r.add(i);
        }
    }
    0
}

/// `sigisemptyset` — test if signal set is empty (GNU).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigisemptyset(set: *const libc::sigset_t) -> c_int {
    if set.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    // SAFETY: sigset_t on Linux is an array of unsigned longs.
    unsafe {
        let s = set as *const u64;
        let n = std::mem::size_of::<libc::sigset_t>() / 8;
        for i in 0..n {
            if *s.add(i) != 0 {
                return 0; // Not empty
            }
        }
    }
    1 // Empty
}

/// `__libc_current_sigrtmin` — return minimum real-time signal number.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_current_sigrtmin() -> c_int {
    // Linux reserves SIGRTMIN+0..+2 for NPTL; usable range starts at SIGRTMIN+3 = 35.
    35
}

/// `__libc_current_sigrtmax` — return maximum real-time signal number.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_current_sigrtmax() -> c_int {
    // SIGRTMAX on Linux x86_64 = 64.
    64
}
