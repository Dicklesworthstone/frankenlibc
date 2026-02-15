//! Raw Linux syscall primitives for supported architectures.
//!
//! Each function issues a single trap instruction (`syscall` on x86_64,
//! `svc 0` on aarch64) with the specified number of arguments.
//! The return value is the raw kernel return register value.

use core::arch::asm;

/// Issue a syscall with 0 arguments.
///
/// # Safety
///
/// The caller must supply a valid syscall number and accept the kernel's
/// return value semantics.
#[inline]
#[cfg(target_arch = "x86_64")]
pub unsafe fn syscall0(nr: usize) -> usize {
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
    // SAFETY: The caller guarantees that child_sp points to a valid stack with
    // fn_ptr at [sp] and arg at [sp+8]. The clone syscall creates a new thread
    // that starts executing at the instruction after `syscall`. The child path
    // (rax==0) pops fn_ptr and arg from its stack and calls the function. The
    // parent path (rax>0) falls through to label 2.
    unsafe {
        asm!(
            // Move child_tid and tls into the registers clone expects
            "mov r10, {ctid}",
            "mov r8, {tls}",
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
            ctid = in(reg) child_tid,
            tls = in(reg) tls,
            in("rdi") flags,
            in("rsi") child_sp,
            in("rdx") parent_tid,
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
    // SAFETY: caller guarantees child_sp points to a valid child stack with
    // fn_ptr and arg words at the top. Parent receives child tid; child runs
    // trampoline and exits through SYS_exit.
    unsafe {
        asm!(
            "mov x8, {clone_nr}",
            "svc 0",
            "cbnz x0, 2f",
            "mov x29, xzr",
            "ldr x9, [sp], #8",
            "ldr x0, [sp], #8",
            "and sp, sp, #-16",
            "blr x9",
            "mov x8, {exit_nr}",
            "svc 0",
            "brk #0",
            "2:",
            clone_nr = const 220usize,
            exit_nr = const 93usize,
            in("x0") flags,
            in("x1") child_sp,
            in("x2") parent_tid,
            in("x3") child_tid,
            in("x4") tls,
            lateout("x0") ret,
            lateout("x8") _,
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
