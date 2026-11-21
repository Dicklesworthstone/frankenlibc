//! Raw Linux syscall primitives for supported architectures.
//!
//! Each function issues a single trap instruction (`syscall` on x86_64,
//! `svc 0` on aarch64) with the specified number of arguments.
//! The return value is the raw kernel return register value.

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicUsize, Ordering};

const CANCEL_SYSCALL_SLOTS: usize = 1024;
const CANCEL_SLOT_EMPTY: i32 = 0;
const CANCEL_SLOT_TOMBSTONE: i32 = -1;

/// Encode a positive `tid` (`>= 1`) into a transient negative claiming sentinel
/// (`<= -3`) so an asynchronous signal handler interrupting the same thread mid-CAS
/// detects self-reentry immediately instead of spinning forever.
#[inline]
const fn cancel_slot_claiming_for_tid(tid: i32) -> i32 {
    if tid >= i32::MAX - 1 {
        i32::MIN
    } else if tid <= 1 {
        -3
    } else {
        -(tid + 2)
    }
}

#[inline]
const fn is_cancel_slot_claiming(stored: i32) -> bool {
    stored <= -2
}

#[repr(C)]
struct CancelSyscallArgs {
    nr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
}

#[cfg(target_arch = "x86_64")]
global_asm!(
    ".pushsection .text.__fl_syscall_cancel_arch,\"ax\",@progbits",
    ".p2align 4",
    ".globl __fl_syscall_cancel_arch",
    ".hidden __fl_syscall_cancel_arch",
    ".type __fl_syscall_cancel_arch,@function",
    "__fl_syscall_cancel_arch:",
    ".cfi_startproc",
    ".globl __fl_syscall_cancel_begin",
    ".hidden __fl_syscall_cancel_begin",
    "__fl_syscall_cancel_begin:",
    "mov eax, dword ptr [rdi]",
    "test al, 1",
    "jnz __fl_syscall_cancel_abort",
    "mov r11, rsi",
    "mov rax, qword ptr [r11 + 0]",
    "mov rdi, qword ptr [r11 + 8]",
    "mov rsi, qword ptr [r11 + 16]",
    "mov rdx, qword ptr [r11 + 24]",
    "mov r10, qword ptr [r11 + 32]",
    "mov r8,  qword ptr [r11 + 40]",
    "mov r9,  qword ptr [r11 + 48]",
    ".globl __fl_syscall_cancel_insn",
    ".hidden __fl_syscall_cancel_insn",
    "__fl_syscall_cancel_insn:",
    "syscall",
    ".globl __fl_syscall_cancel_end",
    ".hidden __fl_syscall_cancel_end",
    "__fl_syscall_cancel_end:",
    "ret",
    ".globl __fl_syscall_cancel_abort",
    ".hidden __fl_syscall_cancel_abort",
    "__fl_syscall_cancel_abort:",
    "mov rax, -4",
    "ret",
    ".cfi_endproc",
    ".size __fl_syscall_cancel_arch, . - __fl_syscall_cancel_arch",
    ".popsection",
);

#[cfg(target_arch = "aarch64")]
global_asm!(
    ".pushsection .text.__fl_syscall_cancel_arch,\"ax\",@progbits",
    ".p2align 2",
    ".globl __fl_syscall_cancel_arch",
    ".hidden __fl_syscall_cancel_arch",
    ".type __fl_syscall_cancel_arch,@function",
    "__fl_syscall_cancel_arch:",
    ".cfi_startproc",
    ".globl __fl_syscall_cancel_begin",
    ".hidden __fl_syscall_cancel_begin",
    "__fl_syscall_cancel_begin:",
    "ldr w9, [x0]",
    "tbnz w9, #0, __fl_syscall_cancel_abort",
    "mov x10, x1",
    "ldr x8, [x10, #0]",
    "ldr x0, [x10, #8]",
    "ldr x1, [x10, #16]",
    "ldr x2, [x10, #24]",
    "ldr x3, [x10, #32]",
    "ldr x4, [x10, #40]",
    "ldr x5, [x10, #48]",
    ".globl __fl_syscall_cancel_insn",
    ".hidden __fl_syscall_cancel_insn",
    "__fl_syscall_cancel_insn:",
    "svc #0",
    ".globl __fl_syscall_cancel_end",
    ".hidden __fl_syscall_cancel_end",
    "__fl_syscall_cancel_end:",
    "ret",
    ".globl __fl_syscall_cancel_abort",
    ".hidden __fl_syscall_cancel_abort",
    "__fl_syscall_cancel_abort:",
    "mov x0, #-4",
    "ret",
    ".cfi_endproc",
    ".size __fl_syscall_cancel_arch, . - __fl_syscall_cancel_arch",
    ".popsection",
);

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe extern "C" {
    fn __fl_syscall_cancel_arch(cancel_word: *const u32, args: *const CancelSyscallArgs) -> usize;
    fn __fl_syscall_cancel_begin();
    fn __fl_syscall_cancel_insn();
    fn __fl_syscall_cancel_abort();
}

/// Return `(begin, insn, abort)` instruction addresses for `__fl_syscall_cancel_arch`.
///
/// If `NATIVE_SIGCANCEL` interrupts a thread while its PC is in `begin..insn`,
/// redirecting its PC to `abort` prevents a pre-syscall lost wakeup without
/// unwinding out of the signal frame.
#[inline]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn native_cancel_syscall_pc_range() -> (usize, usize, usize) {
    (
        __fl_syscall_cancel_begin as *const () as usize,
        __fl_syscall_cancel_insn as *const () as usize,
        __fl_syscall_cancel_abort as *const () as usize,
    )
}

static NATIVE_CANCEL_WINDOW_DEPTH: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_CANCEL_TIDS: [AtomicI32; CANCEL_SYSCALL_SLOTS] =
    [const { AtomicI32::new(CANCEL_SLOT_EMPTY) }; CANCEL_SYSCALL_SLOTS];
static ACTIVE_CANCEL_WORDS: [AtomicUsize; CANCEL_SYSCALL_SLOTS] =
    [const { AtomicUsize::new(0) }; CANCEL_SYSCALL_SLOTS];
static ACTIVE_CANCEL_RSPS: [AtomicUsize; CANCEL_SYSCALL_SLOTS] =
    [const { AtomicUsize::new(0) }; CANCEL_SYSCALL_SLOTS];
static ACTIVE_CANCEL_STATE: [AtomicU8; CANCEL_SYSCALL_SLOTS] =
    [const { AtomicU8::new(0) }; CANCEL_SYSCALL_SLOTS];
static ACTIVE_SIGNAL_DEPTH: [AtomicUsize; CANCEL_SYSCALL_SLOTS] =
    [const { AtomicUsize::new(0) }; CANCEL_SYSCALL_SLOTS];

const CANCEL_STATE_CONSUMED: u8 = 1;
const CANCEL_STATE_INTERRUPTED: u8 = 2;

#[inline(always)]
#[cfg(target_arch = "x86_64")]
fn current_stack_pointer() -> usize {
    let sp: usize;
    // SAFETY: Reading RSP has no side effects.
    unsafe {
        asm!("mov {}, rsp", out(reg) sp, options(nostack, nomem, preserves_flags));
    }
    sp
}

#[inline(always)]
#[cfg(target_arch = "aarch64")]
fn current_stack_pointer() -> usize {
    let sp: usize;
    // SAFETY: Reading SP has no side effects.
    unsafe {
        asm!("mov {}, sp", out(reg) sp, options(nostack, nomem, preserves_flags));
    }
    sp
}

/// Allocation-free, TLS-free raw `SYS_gettid` for signal handlers and cancel windows.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub fn raw_gettid_nocancel() -> i32 {
    let ret: usize;
    // SAFETY: SYS_gettid (186 on x86_64) takes no arguments and never fails.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") 186usize => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret as i32
}

/// Allocation-free, TLS-free raw `SYS_gettid` for signal handlers and cancel windows.
#[inline(always)]
#[cfg(target_arch = "aarch64")]
pub fn raw_gettid_nocancel() -> i32 {
    let ret: usize;
    // SAFETY: SYS_gettid (178 on aarch64) takes no arguments and never fails.
    unsafe {
        asm!(
            "svc 0",
            in("x8") 178usize,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret as i32
}

/// Whether at least one native thread is currently inside a cancellable syscall window.
#[inline(always)]
pub fn native_cancel_syscall_any_active() -> bool {
    NATIVE_CANCEL_WINDOW_DEPTH.load(Ordering::Relaxed) != 0
}

static CANCEL_SYSCALL_EVER_USED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Token returned by [`arm_native_cancel_syscall`] and passed back to
/// [`disarm_native_cancel_syscall`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeCancelWindowToken {
    /// No trap slot could be claimed (e.g. invalid TID or table saturation).
    None,
    /// Fresh trap slot claimed for this thread; disarming frees the slot.
    Fresh,
    /// Nested trap inside a signal handler that interrupted an outer window on
    /// the same thread; disarming restores the outer window's saved fields.
    Nested {
        idx: usize,
        prev_state: u8,
        prev_signal_depth: usize,
        prev_rsp: usize,
        prev_word: usize,
    },
}

/// Arm the interruptible native cancellation syscall trap for `tid`.
///
/// If an outer cancellation window on the same `tid` already owns an armed slot
/// (e.g., an application signal handler invoking a nested blocking cancellation
/// point), saves the outer slot's state and re-arms the slot for the inner
/// window; [`disarm_native_cancel_syscall`] restores the outer slot verbatim.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn arm_native_cancel_syscall(
    tid: i32,
    cancel_word: *const u32,
    window_rsp: usize,
) -> NativeCancelWindowToken {
    if tid <= 0 || cancel_word.is_null() {
        return NativeCancelWindowToken::None;
    }
    let self_claiming = cancel_slot_claiming_for_tid(tid);
    CANCEL_SYSCALL_EVER_USED.store(true, Ordering::Release);
    let start = (tid as u32 as usize) % CANCEL_SYSCALL_SLOTS;
    'retry: for _ in 0..16 {
        let mut first_tombstone: Option<usize> = None;
        for i in 0..CANCEL_SYSCALL_SLOTS {
            let idx = (start + i) % CANCEL_SYSCALL_SLOTS;
            let mut stored = ACTIVE_CANCEL_TIDS[idx].load(Ordering::Acquire);
            while is_cancel_slot_claiming(stored) {
                if stored == self_claiming {
                    return NativeCancelWindowToken::None;
                }
                core::hint::spin_loop();
                stored = ACTIVE_CANCEL_TIDS[idx].load(Ordering::Acquire);
            }
            if stored == tid {
                // Swap `RSPS`/`WORDS` BEFORE clearing `ACTIVE_SIGNAL_DEPTH` so a
                // `SIGCANCEL` arriving mid-transition while `signal_depth > 0`
                // ignores the slot rather than seeing mismatched outer/inner RSPs.
                let prev_rsp = ACTIVE_CANCEL_RSPS[idx].swap(window_rsp, Ordering::AcqRel);
                let prev_word =
                    ACTIVE_CANCEL_WORDS[idx].swap(cancel_word as usize, Ordering::AcqRel);
                let prev_state = ACTIVE_CANCEL_STATE[idx].swap(0, Ordering::AcqRel);
                let prev_signal_depth = ACTIVE_SIGNAL_DEPTH[idx].swap(0, Ordering::AcqRel);
                return NativeCancelWindowToken::Nested {
                    idx,
                    prev_state,
                    prev_signal_depth,
                    prev_rsp,
                    prev_word,
                };
            }
            if stored == CANCEL_SLOT_TOMBSTONE {
                if first_tombstone.is_none() {
                    first_tombstone = Some(idx);
                }
                continue;
            }
            if stored == CANCEL_SLOT_EMPTY {
                let (target, expected) = match first_tombstone {
                    Some(tomb) => (tomb, CANCEL_SLOT_TOMBSTONE),
                    None => (idx, CANCEL_SLOT_EMPTY),
                };
                if ACTIVE_CANCEL_TIDS[target]
                    .compare_exchange(expected, self_claiming, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    ACTIVE_CANCEL_STATE[target].store(0, Ordering::Relaxed);
                    ACTIVE_SIGNAL_DEPTH[target].store(0, Ordering::Relaxed);
                    ACTIVE_CANCEL_RSPS[target].store(window_rsp, Ordering::Relaxed);
                    ACTIVE_CANCEL_WORDS[target].store(cancel_word as usize, Ordering::Relaxed);
                    NATIVE_CANCEL_WINDOW_DEPTH.fetch_add(1, Ordering::AcqRel);
                    ACTIVE_CANCEL_TIDS[target].store(tid, Ordering::Release);
                    return NativeCancelWindowToken::Fresh;
                }
                continue 'retry;
            }
        }
        if let Some(tomb) = first_tombstone {
            if ACTIVE_CANCEL_TIDS[tomb]
                .compare_exchange(
                    CANCEL_SLOT_TOMBSTONE,
                    self_claiming,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                ACTIVE_CANCEL_STATE[tomb].store(0, Ordering::Relaxed);
                ACTIVE_SIGNAL_DEPTH[tomb].store(0, Ordering::Relaxed);
                ACTIVE_CANCEL_RSPS[tomb].store(window_rsp, Ordering::Relaxed);
                ACTIVE_CANCEL_WORDS[tomb].store(cancel_word as usize, Ordering::Relaxed);
                NATIVE_CANCEL_WINDOW_DEPTH.fetch_add(1, Ordering::AcqRel);
                ACTIVE_CANCEL_TIDS[tomb].store(tid, Ordering::Release);
                return NativeCancelWindowToken::Fresh;
            }
            continue 'retry;
        }
        return NativeCancelWindowToken::None;
    }
    NativeCancelWindowToken::None
}

/// Disarm the interruptible native cancellation syscall trap for `tid`.
/// Returns `true` if the trap was aborted before kernel entry or returned `-EINTR`.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn disarm_native_cancel_syscall(tid: i32, token: NativeCancelWindowToken) -> bool {
    match token {
        NativeCancelWindowToken::None => false,
        NativeCancelWindowToken::Nested {
            idx,
            prev_state,
            prev_signal_depth,
            prev_rsp,
            prev_word,
        } => {
            if tid <= 0 || ACTIVE_CANCEL_TIDS[idx].load(Ordering::Acquire) != tid {
                return false;
            }
            // Restore `ACTIVE_SIGNAL_DEPTH` FIRST so a `SIGCANCEL` arriving while
            // restoring the outer `WORDS`/`RSPS`/`STATE` observes the outer signal depth.
            ACTIVE_SIGNAL_DEPTH[idx].store(prev_signal_depth, Ordering::Release);
            ACTIVE_CANCEL_WORDS[idx].store(prev_word, Ordering::Release);
            ACTIVE_CANCEL_RSPS[idx].store(prev_rsp, Ordering::Release);
            let inner_state = ACTIVE_CANCEL_STATE[idx].swap(prev_state, Ordering::AcqRel);
            inner_state & CANCEL_STATE_INTERRUPTED != 0
        }
        NativeCancelWindowToken::Fresh => {
            if tid <= 0 || !native_cancel_syscall_any_active() {
                return false;
            }
            let start = (tid as u32 as usize) % CANCEL_SYSCALL_SLOTS;
            for i in 0..CANCEL_SYSCALL_SLOTS {
                let idx = (start + i) % CANCEL_SYSCALL_SLOTS;
                let stored = ACTIVE_CANCEL_TIDS[idx].load(Ordering::Acquire);
                if stored == tid {
                    ACTIVE_CANCEL_WORDS[idx].store(0, Ordering::Release);
                    ACTIVE_CANCEL_RSPS[idx].store(0, Ordering::Release);
                    ACTIVE_SIGNAL_DEPTH[idx].store(0, Ordering::Release);
                    let state = ACTIVE_CANCEL_STATE[idx].swap(0, Ordering::AcqRel);
                    ACTIVE_CANCEL_TIDS[idx].store(CANCEL_SLOT_TOMBSTONE, Ordering::Release);
                    let _ = NATIVE_CANCEL_WINDOW_DEPTH.try_update(
                        Ordering::AcqRel,
                        Ordering::Acquire,
                        |d| Some(d.saturating_sub(1)),
                    );
                    return state & CANCEL_STATE_INTERRUPTED != 0;
                }
                if stored == CANCEL_SLOT_EMPTY {
                    break;
                }
            }
            false
        }
    }
}

/// Mark entry/exit of an application signal handler on the current thread so a
/// handler invoked before the blocking syscall reaches `try_cancelable_syscall`
/// never consumes the enclosing cancellation window's trap slot.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn note_signal_handler_for_cancel_window(entering: bool) {
    if !native_cancel_syscall_any_active() {
        return;
    }
    let tid = raw_gettid_nocancel();
    if tid <= 0 {
        return;
    }
    let start = (tid as u32 as usize) % CANCEL_SYSCALL_SLOTS;
    for i in 0..CANCEL_SYSCALL_SLOTS {
        let idx = (start + i) % CANCEL_SYSCALL_SLOTS;
        let stored = ACTIVE_CANCEL_TIDS[idx].load(Ordering::Acquire);
        if stored == tid {
            if entering {
                ACTIVE_SIGNAL_DEPTH[idx].fetch_add(1, Ordering::AcqRel);
            } else {
                let _ =
                    ACTIVE_SIGNAL_DEPTH[idx].try_update(Ordering::AcqRel, Ordering::Acquire, |d| {
                        Some(d.saturating_sub(1))
                    });
            }
            return;
        }
        if stored == CANCEL_SLOT_EMPTY {
            break;
        }
    }
}

/// Clear all inherited active cancel-syscall slots in a fork child.
pub fn reset_native_cancel_syscalls_after_fork() {
    NATIVE_CANCEL_WINDOW_DEPTH.store(0, Ordering::Release);
    if !CANCEL_SYSCALL_EVER_USED.swap(false, Ordering::AcqRel) {
        return;
    }
    for i in 0..CANCEL_SYSCALL_SLOTS {
        ACTIVE_CANCEL_WORDS[i].store(0, Ordering::Release);
        ACTIVE_CANCEL_RSPS[i].store(0, Ordering::Release);
        ACTIVE_CANCEL_STATE[i].store(0, Ordering::Release);
        ACTIVE_SIGNAL_DEPTH[i].store(0, Ordering::Release);
        ACTIVE_CANCEL_TIDS[i].store(CANCEL_SLOT_EMPTY, Ordering::Release);
    }
}

#[cold]
#[inline(never)]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe fn try_cancelable_syscall(args: &CancelSyscallArgs) -> Option<usize> {
    let sp = current_stack_pointer();
    let tid = raw_gettid_nocancel();
    if tid <= 0 {
        return None;
    }
    let start = (tid as u32 as usize) % CANCEL_SYSCALL_SLOTS;
    for i in 0..CANCEL_SYSCALL_SLOTS {
        let idx = (start + i) % CANCEL_SYSCALL_SLOTS;
        let stored = ACTIVE_CANCEL_TIDS[idx].load(Ordering::Acquire);
        if stored == tid {
            if ACTIVE_SIGNAL_DEPTH[idx].load(Ordering::Acquire) != 0 {
                return None;
            }
            let word = ACTIVE_CANCEL_WORDS[idx].load(Ordering::Acquire);
            let window_rsp = ACTIVE_CANCEL_RSPS[idx].load(Ordering::Acquire);
            if word == 0 || window_rsp.wrapping_sub(sp) >= 16384 {
                return None;
            }
            if ACTIVE_CANCEL_STATE[idx]
                .compare_exchange(
                    0,
                    CANCEL_STATE_CONSUMED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return None;
            }
            // SAFETY: `word` is a static 32-bit atomic cancellation word and `args`
            // holds the caller's validated syscall register image.
            let ret = unsafe { __fl_syscall_cancel_arch(word as *const u32, args) };
            if ret as isize == -(crate::errno::EINTR as isize) {
                ACTIVE_CANCEL_STATE[idx].fetch_or(CANCEL_STATE_INTERRUPTED, Ordering::Release);
            }
            return Some(ret);
        }
        if stored == CANCEL_SLOT_EMPTY {
            break;
        }
    }
    None
}

/// Fill a Rust-owned slice with kernel entropy, returning the actual count.
///
/// Unlike the pointer-based veneer, this boundary is safe for core callers:
/// the exclusive slice proves the writable extent for the whole syscall.
/// Flags and partial/error results retain the Linux getrandom contract. No
/// host libc call, descriptor, allocation, or fallback generator is involved.
#[inline]
pub fn sys_getrandom_slice(buffer: &mut [u8], flags: u32) -> Result<usize, i32> {
    // SAFETY: buffer is exclusively borrowed and writable for buffer.len()
    // bytes. The kernel does not retain its address after the syscall returns.
    let count = unsafe { super::sys_getrandom(buffer.as_mut_ptr(), buffer.len(), flags) }?;
    usize::try_from(count)
        .ok()
        .filter(|&count| count <= buffer.len())
        .ok_or(crate::errno::EIO)
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
const fn current_clone_tail_args(
    parent_tid: usize,
    child_tid: usize,
    tls: usize,
) -> (usize, usize, usize) {
    (parent_tid, child_tid, tls)
}

#[inline(always)]
#[cfg(target_arch = "aarch64")]
const fn current_clone_tail_args(
    parent_tid: usize,
    child_tid: usize,
    tls: usize,
) -> (usize, usize, usize) {
    (parent_tid, tls, child_tid)
}

/// Issue a syscall with 0 arguments.
///
/// # Safety
///
/// The caller must supply a valid syscall number and accept the kernel's
/// return value semantics.
#[inline]
#[cfg(target_arch = "x86_64")]
pub unsafe fn syscall0(nr: usize) -> usize {
    if native_cancel_syscall_any_active()
        && let Some(ret) = unsafe {
            try_cancelable_syscall(&CancelSyscallArgs {
                nr,
                a1: 0,
                a2: 0,
                a3: 0,
                a4: 0,
                a5: 0,
                a6: 0,
            })
        }
    {
        return ret;
    }
    let ret: usize;
    // SAFETY: Inline asm issues syscall instruction. Caller guarantees nr is valid.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 0 arguments.
///
/// # Safety
///
/// The caller must supply a valid syscall number and accept the kernel's
/// return value semantics.
#[inline]
#[cfg(target_arch = "aarch64")]
pub unsafe fn syscall0(nr: usize) -> usize {
    if native_cancel_syscall_any_active()
        && let Some(ret) = unsafe {
            try_cancelable_syscall(&CancelSyscallArgs {
                nr,
                a1: 0,
                a2: 0,
                a3: 0,
                a4: 0,
                a5: 0,
                a6: 0,
            })
        }
    {
        return ret;
    }
    let ret: usize;
    // SAFETY: Inline asm issues `svc 0`. Caller guarantees nr is valid.
    unsafe {
        asm!(
            "svc 0",
            in("x8") nr,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
}

/// Issue a syscall with 1 argument.
///
/// # Safety
///
/// The caller must supply valid syscall number and argument.
#[inline]
#[cfg(target_arch = "x86_64")]
pub unsafe fn syscall1(nr: usize, a1: usize) -> usize {
    if native_cancel_syscall_any_active()
        && let Some(ret) = unsafe {
            try_cancelable_syscall(&CancelSyscallArgs {
                nr,
                a1,
                a2: 0,
                a3: 0,
                a4: 0,
                a5: 0,
                a6: 0,
            })
        }
    {
        return ret;
    }
    let ret: usize;
    // SAFETY: Inline asm issues syscall instruction. Caller guarantees validity.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 1 argument.
///
/// # Safety
///
/// The caller must supply valid syscall number and argument.
#[inline]
#[cfg(target_arch = "aarch64")]
pub unsafe fn syscall1(nr: usize, a1: usize) -> usize {
    if native_cancel_syscall_any_active()
        && let Some(ret) = unsafe {
            try_cancelable_syscall(&CancelSyscallArgs {
                nr,
                a1,
                a2: 0,
                a3: 0,
                a4: 0,
                a5: 0,
                a6: 0,
            })
        }
    {
        return ret;
    }
    let ret: usize;
    // SAFETY: Inline asm issues `svc 0`. Caller guarantees validity.
    unsafe {
        asm!(
            "svc 0",
            in("x8") nr,
            inlateout("x0") a1 => ret,
            options(nostack),
        );
    }
    ret
}

/// Issue a syscall with 2 arguments.
///
/// # Safety
///
/// The caller must supply valid syscall number and arguments.
#[inline]
#[cfg(target_arch = "x86_64")]
pub unsafe fn syscall2(nr: usize, a1: usize, a2: usize) -> usize {
    if native_cancel_syscall_any_active()
        && let Some(ret) = unsafe {
            try_cancelable_syscall(&CancelSyscallArgs {
                nr,
                a1,
                a2,
                a3: 0,
                a4: 0,
                a5: 0,
                a6: 0,
            })
        }
    {
        return ret;
    }
    let ret: usize;
    // SAFETY: Inline asm issues syscall instruction. Caller guarantees validity.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 2 arguments.
///
/// # Safety
///
/// The caller must supply valid syscall number and arguments.
#[inline]
#[cfg(target_arch = "aarch64")]
pub unsafe fn syscall2(nr: usize, a1: usize, a2: usize) -> usize {
    if native_cancel_syscall_any_active()
        && let Some(ret) = unsafe {
            try_cancelable_syscall(&CancelSyscallArgs {
                nr,
                a1,
                a2,
                a3: 0,
                a4: 0,
                a5: 0,
                a6: 0,
            })
        }
    {
        return ret;
    }
    let ret: usize;
    // SAFETY: Inline asm issues `svc 0`. Caller guarantees validity.
    unsafe {
        asm!(
            "svc 0",
            in("x8") nr,
            inlateout("x0") a1 => ret,
            in("x1") a2,
            options(nostack),
        );
    }
    ret
}

/// Issue a syscall with 3 arguments.
///
/// # Safety
///
/// The caller must supply valid syscall number and arguments.
#[inline]
#[cfg(target_arch = "x86_64")]
pub unsafe fn syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> usize {
    if native_cancel_syscall_any_active()
        && let Some(ret) = unsafe {
            try_cancelable_syscall(&CancelSyscallArgs {
                nr,
                a1,
                a2,
                a3,
                a4: 0,
                a5: 0,
                a6: 0,
            })
        }
    {
        return ret;
    }
    let ret: usize;
    // SAFETY: Inline asm issues syscall instruction. Caller guarantees validity.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 3 arguments.
///
/// # Safety
///
/// The caller must supply valid syscall number and arguments.
#[inline]
#[cfg(target_arch = "aarch64")]
pub unsafe fn syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> usize {
    if native_cancel_syscall_any_active()
        && let Some(ret) = unsafe {
            try_cancelable_syscall(&CancelSyscallArgs {
                nr,
                a1,
                a2,
                a3,
                a4: 0,
                a5: 0,
                a6: 0,
            })
        }
    {
        return ret;
    }
    let ret: usize;
    // SAFETY: Inline asm issues `svc 0`. Caller guarantees validity.
    unsafe {
        asm!(
            "svc 0",
            in("x8") nr,
            inlateout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            options(nostack),
        );
    }
    ret
}

/// Issue a syscall with 4 arguments.
///
/// # Safety
///
/// The caller must supply valid syscall number and arguments.
#[inline]
#[cfg(target_arch = "x86_64")]
pub unsafe fn syscall4(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
    if native_cancel_syscall_any_active()
        && let Some(ret) = unsafe {
            try_cancelable_syscall(&CancelSyscallArgs {
                nr,
                a1,
                a2,
                a3,
                a4,
                a5: 0,
                a6: 0,
            })
        }
    {
        return ret;
    }
    let ret: usize;
    // SAFETY: Inline asm issues syscall instruction. Caller guarantees validity.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 4 arguments.
///
/// # Safety
///
/// The caller must supply valid syscall number and arguments.
#[inline]
#[cfg(target_arch = "aarch64")]
pub unsafe fn syscall4(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
    if native_cancel_syscall_any_active()
        && let Some(ret) = unsafe {
            try_cancelable_syscall(&CancelSyscallArgs {
                nr,
                a1,
                a2,
                a3,
                a4,
                a5: 0,
                a6: 0,
            })
        }
    {
        return ret;
    }
    let ret: usize;
    // SAFETY: Inline asm issues `svc 0`. Caller guarantees validity.
    unsafe {
        asm!(
            "svc 0",
            in("x8") nr,
            inlateout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            options(nostack),
        );
    }
    ret
}

/// Issue a syscall with 5 arguments.
///
/// # Safety
///
/// The caller must supply valid syscall number and arguments.
#[inline]
#[cfg(target_arch = "x86_64")]
pub unsafe fn syscall5(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> usize {
    if native_cancel_syscall_any_active()
        && let Some(ret) = unsafe {
            try_cancelable_syscall(&CancelSyscallArgs {
                nr,
                a1,
                a2,
                a3,
                a4,
                a5,
                a6: 0,
            })
        }
    {
        return ret;
    }
    let ret: usize;
    // SAFETY: Inline asm issues syscall instruction. Caller guarantees validity.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 5 arguments.
///
/// # Safety
///
/// The caller must supply valid syscall number and arguments.
#[inline]
#[cfg(target_arch = "aarch64")]
pub unsafe fn syscall5(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> usize {
    if native_cancel_syscall_any_active()
        && let Some(ret) = unsafe {
            try_cancelable_syscall(&CancelSyscallArgs {
                nr,
                a1,
                a2,
                a3,
                a4,
                a5,
                a6: 0,
            })
        }
    {
        return ret;
    }
    let ret: usize;
    // SAFETY: Inline asm issues `svc 0`. Caller guarantees validity.
    unsafe {
        asm!(
            "svc 0",
            in("x8") nr,
            inlateout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            in("x4") a5,
            options(nostack),
        );
    }
    ret
}

/// Execute `clone` syscall with a child trampoline.
///
/// The child stack at `child_sp` must contain:
/// - `[child_sp + 0]`: function pointer (8 bytes)
/// - `[child_sp + 8]`: argument value (8 bytes)
///
/// After clone, the child thread:
/// 1. Pops the function pointer into `rax`
/// 2. Pops the argument into `rdi` (first C ABI parameter)
/// 3. Aligns the stack to 16 bytes
/// 4. Calls the function via `call rax`
/// 5. On return, exits the thread via `SYS_exit` with the return value
///
/// The parent receives the child TID in `rax` (positive) or `-errno` (negative).
///
/// # Safety
///
/// - `child_sp` must point to a valid, writable stack with fn_ptr and arg placed.
/// - The function pointer must be valid and callable.
/// - `parent_tid` and `child_tid` must be valid if corresponding flags are set.
#[inline]
#[cfg(target_arch = "x86_64")]
pub unsafe fn clone_thread_asm(
    flags: usize,
    child_sp: usize,
    parent_tid: usize,
    child_tid: usize,
    tls: usize,
) -> usize {
    let ret: usize;
    let (raw_parent_tid, raw_fourth_arg, raw_fifth_arg) =
        current_clone_tail_args(parent_tid, child_tid, tls);
    // SAFETY: The caller guarantees that child_sp points to a valid stack with
    // fn_ptr at [sp] and arg at [sp+8]. The clone syscall creates a new thread
    // that starts executing at the instruction after `syscall`. The child path
    // (rax==0) pops fn_ptr and arg from its stack and calls the function. The
    // parent path (rax>0) falls through to label 2.
    unsafe {
        asm!(
            // SYS_clone = 56
            "mov eax, 56",
            "syscall",
            // Check: parent (rax > 0) or child (rax == 0)?
            "test rax, rax",
            "jnz 2f",
            // ===== Child path (rax == 0) =====
            // Clear frame pointer for clean backtraces
            "xor ebp, ebp",
            // Pop fn_ptr and arg from child stack
            "pop rax",            // fn_ptr -> rax
            "pop rdi",            // arg -> rdi (first C ABI argument)
            // Align stack to 16 bytes before call (defensive)
            "and rsp, -16",
            // Call fn_ptr(arg)
            "call rax",
            // fn_ptr returned — exit the thread with its return value
            "mov edi, eax",       // return value -> exit status
            "mov eax, 60",        // SYS_exit (thread exit, not exit_group)
            "syscall",
            "ud2",                // unreachable
            // ===== Parent path =====
            "2:",
            // rax = child TID (positive) or -errno (negative)
            in("rdi") flags,
            in("rsi") child_sp,
            in("rdx") raw_parent_tid,
            in("r10") raw_fourth_arg,
            in("r8") raw_fifth_arg,
            lateout("rax") ret,
            lateout("rcx") _,     // clobbered by syscall
            lateout("r11") _,     // clobbered by syscall
            options(nostack),
        );
    }
    ret
}

/// Execute `clone` syscall with a child trampoline on aarch64.
///
/// The child stack at `child_sp` must contain:
/// - `[child_sp + 0]`: function pointer (8 bytes)
/// - `[child_sp + 8]`: argument value (8 bytes)
///
/// After clone, the child thread:
/// 1. Pops the function pointer into `x9`
/// 2. Pops the argument into `x0` (first C ABI parameter)
/// 3. Aligns the stack to 16 bytes
/// 4. Calls the function via `blr x9`
/// 5. On return, exits the thread via `SYS_exit` with the return value
///
/// The parent receives the child TID in `x0` (positive) or `-errno` (negative).
///
/// # Safety
///
/// - `child_sp` must point to a valid, writable stack with fn_ptr and arg placed.
/// - The function pointer must be valid and callable.
/// - `parent_tid` and `child_tid` must be valid if corresponding flags are set.
#[inline]
#[cfg(target_arch = "aarch64")]
pub unsafe fn clone_thread_asm(
    flags: usize,
    child_sp: usize,
    parent_tid: usize,
    child_tid: usize,
    tls: usize,
) -> usize {
    let ret: usize;
    let (raw_parent_tid, raw_fourth_arg, raw_fifth_arg) =
        current_clone_tail_args(parent_tid, child_tid, tls);
    // SAFETY: caller guarantees child_sp points to a valid child stack with
    // fn_ptr and arg words at the top. Parent receives child tid; child runs
    // trampoline and exits through SYS_exit.
    //
    // The raw aarch64 clone ABI uses:
    //   clone(flags, stack, parent_tid, tls, child_tid)
    // rather than the x86_64 order:
    //   clone(flags, stack, parent_tid, child_tid, tls)
    // so the final two arguments must be swapped before binding x3/x4.
    unsafe {
        asm!(
            "mov x8, {clone_nr}",
            "svc 0",
            "cbnz x0, 2f",
            "mov x29, xzr",
            "ldr x9, [sp], #8",
            "ldr x0, [sp], #8",
            "mov x10, sp",
            "bic x10, x10, #0xf",
            "mov sp, x10",
            "blr x9",
            "mov x8, {exit_nr}",
            "svc 0",
            "brk #0",
            "2:",
            clone_nr = const 220usize,
            exit_nr = const 93usize,
            in("x0") flags,
            in("x1") child_sp,
            in("x2") raw_parent_tid,
            in("x3") raw_fourth_arg,
            in("x4") raw_fifth_arg,
            lateout("x0") ret,
            lateout("x8") _,
            lateout("x9") _,
            lateout("x10") _,
            options(nostack),
        );
    }
    ret
}

/// Issue a syscall with 6 arguments.
///
/// # Safety
///
/// The caller must supply valid syscall number and arguments.
#[inline]
#[cfg(target_arch = "x86_64")]
pub unsafe fn syscall6(
    nr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> usize {
    if native_cancel_syscall_any_active()
        && let Some(ret) = unsafe {
            try_cancelable_syscall(&CancelSyscallArgs {
                nr,
                a1,
                a2,
                a3,
                a4,
                a5,
                a6,
            })
        }
    {
        return ret;
    }
    let ret: usize;
    // SAFETY: Inline asm issues syscall instruction. Caller guarantees validity.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            in("r9") a6,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::current_clone_tail_args;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RawCloneTailAbi {
        ParentChildTidTls,
        ParentTlsChildTid,
    }

    const fn map_clone_tail_args(
        abi: RawCloneTailAbi,
        parent_tid: usize,
        child_tid: usize,
        tls: usize,
    ) -> (usize, usize, usize) {
        match abi {
            RawCloneTailAbi::ParentChildTidTls => (parent_tid, child_tid, tls),
            RawCloneTailAbi::ParentTlsChildTid => (parent_tid, tls, child_tid),
        }
    }

    #[test]
    fn raw_clone_tail_arg_mapping_matches_documented_arch_abis() {
        assert_eq!(
            map_clone_tail_args(RawCloneTailAbi::ParentChildTidTls, 11, 22, 33),
            (11, 22, 33)
        );
        assert_eq!(
            map_clone_tail_args(RawCloneTailAbi::ParentTlsChildTid, 11, 22, 33),
            (11, 33, 22)
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn current_raw_clone_tail_abi_matches_x86_64_layout() {
        assert_eq!(current_clone_tail_args(1, 2, 3), (1, 2, 3));
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn current_raw_clone_tail_abi_matches_aarch64_layout() {
        assert_eq!(current_clone_tail_args(1, 2, 3), (1, 3, 2));
    }

    #[test]
    fn kernel_entropy_syscall_writes_only_the_supplied_slice() {
        let mut storage = [0xa5; 258];
        assert_eq!(super::sys_getrandom_slice(&mut storage[1..257], 1), Ok(256));
        assert_eq!(storage[0], 0xa5);
        assert_eq!(storage[257], 0xa5);
    }

    #[test]
    fn kernel_entropy_syscall_preserves_invalid_flag_errors() {
        assert_eq!(
            super::sys_getrandom_slice(&mut [], u32::MAX),
            Err(crate::errno::EINVAL)
        );
    }
}

/// Issue a syscall with 6 arguments.
///
/// # Safety
///
/// The caller must supply valid syscall number and arguments.
#[inline]
#[cfg(target_arch = "aarch64")]
pub unsafe fn syscall6(
    nr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> usize {
    if native_cancel_syscall_any_active()
        && let Some(ret) = unsafe {
            try_cancelable_syscall(&CancelSyscallArgs {
                nr,
                a1,
                a2,
                a3,
                a4,
                a5,
                a6,
            })
        }
    {
        return ret;
    }
    let ret: usize;
    // SAFETY: Inline asm issues `svc 0`. Caller guarantees validity.
    unsafe {
        asm!(
            "svc 0",
            in("x8") nr,
            inlateout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            in("x4") a5,
            in("x5") a6,
            options(nostack),
        );
    }
    ret
}
