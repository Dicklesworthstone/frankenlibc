#![feature(c_variadic)]
#![feature(f128)]
#![feature(portable_simd)]
#![cfg_attr(target_arch = "x86_64", feature(rtm_target_feature))]
#![cfg_attr(target_arch = "x86_64", feature(stdarch_x86_rtm))]
#![feature(thread_local)]
// `core::intrinsics::return_address`: a cancellation point opens its
// asynchronous-cancel window only when it was called from outside this
// object (pthread_abi::at_cancellation_point).
#![feature(core_intrinsics)]
#![allow(internal_features)]
#![allow(unused_features)]
// All extern "C" ABI exports accept raw pointers from C callers; the membrane
// validates at runtime, so per-function safety docs would be redundant boilerplate.
#![allow(clippy::missing_safety_doc)]
#![allow(invalid_runtime_symbol_definitions)]
//! # frankenlibc-abi
//!
//! ABI-compatible extern "C" boundary layer for frankenlibc.
//!
//! This crate produces a `cdylib` (`libc.so`) that exposes POSIX/C standard library
//! functions via `extern "C"` symbols. Each function passes through the membrane
//! validation pipeline before delegating to the safe implementations in `frankenlibc-core`.
//!
//! # Architecture
//!
//! ```text
//! C caller -> ABI entry (this crate) -> Membrane validation -> Core impl -> return
//! ```
//!
//! In **strict** mode, the membrane validates but does not silently rewrite operations.
//! Invalid operations produce POSIX-correct error returns.
//!
//! In **hardened** mode, the membrane validates AND applies deterministic healing
//! (clamp, truncate, quarantine, safe-default) for unsafe patterns.

// Architecture support matrix (bd-10pq). The ABI has inline asm
// (setjmp_abi.rs global_asm!), x86-specific intrinsics (RTM in
// htm_fast_path), and raw-syscall sequences that assume a
// specific ABI register layout. Until each ISA has its own
// validated code-path, fail at compile time with a clear
// message rather than silently producing a broken .so.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "frankenlibc-abi currently supports only target_arch = \"x86_64\" \
    (primary) and \"aarch64\" (active bring-up). RISC-V and other \
    ISAs are tracked under bd-10pq — they need per-ISA inline asm \
    (setjmp_abi), intrinsic replacements (htm_fast_path), and \
    raw-syscall sequences before this crate can build on them."
);

#[cfg(all(feature = "owned-unwind-stub", not(feature = "standalone")))]
compile_error!("owned-unwind-stub is only valid for opt-in standalone experiments");

#[macro_use]
mod macros;

pub(crate) mod host_resolve;
#[doc(hidden)]
pub mod htm_fast_path;
mod membrane_state;
#[cfg(feature = "owned-tls-cache")]
mod owned_tls_cache;
mod runtime_policy;
/// Address-derived slab ownership test (bd-e0y02p).
///
/// `pub` rather than `pub(crate)` because the design's first measurement has to
/// come from an integration test or bench: this crate gates its inline
/// `#[cfg(test)]` modules behind `cfg(not(test))`, so a unit test written here
/// would never compile (bd-0z7a1y). Not yet reachable from `malloc`/`free` --
/// the ownership test is measured before the allocator is rewired.
pub mod slab_region;

#[cfg(feature = "conformance-testing")]
pub use runtime_policy::conformance_testing;

// Bootstrap ABI modules (Phase 1 - implemented)
// Gated behind cfg(not(test)) because these modules export #[no_mangle] symbols
// (malloc, free, memcpy, strlen, ...) that would shadow the system allocator and
// libc in the test binary, causing infinite recursion or deadlock.
#[cfg(not(test))]
pub mod malloc_abi;
#[cfg(all(not(test), feature = "standalone", feature = "owned-unwind-stub"))]
pub mod owned_unwind_abi;
#[cfg(not(test))]
pub mod stdlib_abi;
#[cfg(not(test))]
pub mod string_abi;
#[cfg(not(test))]
pub mod wchar_abi;

// Phase 2 ABI modules — pure Rust delegates (safe in test mode)
pub mod ctype_abi;
mod erf_tables;
pub mod errno_abi;
mod expl_table;
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    not(debug_assertions),
    not(test),
    not(feature = "standalone")
))]
mod fromfp_abi;
#[path = "math_abi.rs"]
mod legacy_math_abi;
pub mod locale_abi;
mod locale_catalog;
#[path = "math_exports.rs"]
pub mod math_abi;
pub mod startup_helpers;
pub mod stdbit_abi;
mod trig_tables;

/// The default build is baseline x86-64 and runs on every x86_64 CPU; its
/// AVX2/FMA kernels are chosen at run time (bd-rc0923-epic-eeuy4f.13). A build
/// compiled for more -- the labelled `release-x86-64-v3` profile, or any
/// `-Ctarget-cpu`/`-Ctarget-feature` override -- executes those instructions
/// from the first memcpy on, before main and even before this library's
/// constructors (libselinux's constructor calls our `sysconf` first), so on a
/// CPU without them every process died of SIGILL. Such a build refuses to run
/// instead, naming the extensions it was compiled for.
///
/// The check runs as the resolver of a hidden IFUNC that a `#[used]` static
/// points at: the loader resolves that IRELATIVE relocation while relocating
/// this object, before any constructor anywhere. The resolver is hand-written
/// assembly, because Rust compiled for this build may itself use the very
/// instructions it checks for (BMI in a bit test, a VEX move for a buffer).
#[cfg(all(
    not(test),
    target_os = "linux",
    target_arch = "x86_64",
    any(
        target_feature = "sse3",
        target_feature = "ssse3",
        target_feature = "sse4.1",
        target_feature = "sse4.2",
        target_feature = "popcnt",
        target_feature = "cmpxchg16b",
        target_feature = "lahfsahf",
        target_feature = "movbe",
        target_feature = "xsave",
        target_feature = "avx",
        target_feature = "avx2",
        target_feature = "fma",
        target_feature = "f16c",
        target_feature = "bmi1",
        target_feature = "bmi2",
        target_feature = "lzcnt",
        target_feature = "avx512f"
    )
))]
mod cpu_guard {
    /// Every extension a build can be compiled to require, as
    /// (compiled in, CPUID word, bit, name). Words: 0 = leaf 1 ECX,
    /// 1 = leaf 7 EBX, 2 = leaf 0x8000_0001 ECX.
    const FEATURES: [(bool, u32, u32, &[u8]); 21] = [
        (cfg!(target_feature = "sse3"), 0, 0, b"sse3"),
        (cfg!(target_feature = "ssse3"), 0, 9, b"ssse3"),
        (cfg!(target_feature = "fma"), 0, 12, b"fma"),
        (cfg!(target_feature = "cmpxchg16b"), 0, 13, b"cmpxchg16b"),
        (cfg!(target_feature = "sse4.1"), 0, 19, b"sse4.1"),
        (cfg!(target_feature = "sse4.2"), 0, 20, b"sse4.2"),
        (cfg!(target_feature = "movbe"), 0, 22, b"movbe"),
        (cfg!(target_feature = "popcnt"), 0, 23, b"popcnt"),
        (cfg!(target_feature = "xsave"), 0, 26, b"xsave"),
        (cfg!(target_feature = "avx"), 0, 28, b"avx"),
        (cfg!(target_feature = "f16c"), 0, 29, b"f16c"),
        (cfg!(target_feature = "bmi1"), 1, 3, b"bmi1"),
        (cfg!(target_feature = "avx2"), 1, 5, b"avx2"),
        (cfg!(target_feature = "bmi2"), 1, 8, b"bmi2"),
        (cfg!(target_feature = "avx512f"), 1, 16, b"avx512f"),
        (cfg!(target_feature = "avx512dq"), 1, 17, b"avx512dq"),
        (cfg!(target_feature = "avx512cd"), 1, 28, b"avx512cd"),
        (cfg!(target_feature = "avx512bw"), 1, 30, b"avx512bw"),
        (cfg!(target_feature = "avx512vl"), 1, 31, b"avx512vl"),
        (cfg!(target_feature = "lahfsahf"), 2, 0, b"lahfsahf"),
        (cfg!(target_feature = "lzcnt"), 2, 5, b"lzcnt"),
    ];

    const fn required(word: u32) -> u32 {
        let mut mask = 0;
        let mut i = 0;
        while i < FEATURES.len() {
            if FEATURES[i].0 && FEATURES[i].1 == word {
                mask |= 1 << FEATURES[i].2;
            }
            i += 1;
        }
        mask
    }

    const LEAF1_ECX: u32 = required(0);
    const LEAF7_EBX: u32 = required(1);
    const EXT_ECX: u32 = required(2);
    /// Register state the OS must save (XCR0) before VEX/EVEX code may run:
    /// SSE+AVX, plus opmask and ZMM for AVX-512. BMI and LZCNT are VEX- or
    /// legacy-encoded integer instructions and need none.
    const XCR0: u32 = if cfg!(target_feature = "avx512f") {
        0xe6
    } else if cfg!(target_feature = "avx") {
        0x6
    } else {
        0
    };

    const PREFIX: &[u8] =
        b"frankenlibc: this libfrankenlibc_abi.so was compiled for x86-64 extensions this CPU \
or OS does not provide (needs:";
    const SUFFIX: &[u8] = b"); use the default baseline x86-64 build \
(cargo build -p frankenlibc-abi --release)\n";

    const fn message_len() -> usize {
        let mut len = PREFIX.len() + SUFFIX.len();
        let mut i = 0;
        while i < FEATURES.len() {
            if FEATURES[i].0 {
                len += 1 + FEATURES[i].3.len();
            }
            i += 1;
        }
        len
    }

    const MESSAGE_LEN: usize = message_len();

    const fn message() -> [u8; MESSAGE_LEN] {
        let mut out = [0u8; MESSAGE_LEN];
        let mut at = 0;
        let mut j = 0;
        while j < PREFIX.len() {
            out[at] = PREFIX[j];
            at += 1;
            j += 1;
        }
        let mut i = 0;
        while i < FEATURES.len() {
            if FEATURES[i].0 {
                out[at] = b' ';
                at += 1;
                let name = FEATURES[i].3;
                let mut k = 0;
                while k < name.len() {
                    out[at] = name[k];
                    at += 1;
                    k += 1;
                }
            }
            i += 1;
        }
        let mut j = 0;
        while j < SUFFIX.len() {
            out[at] = SUFFIX[j];
            at += 1;
            j += 1;
        }
        out
    }

    /// Plain bytes, no pointers: nothing here needs a relocation, so the
    /// resolver may read it before this object's relocations are done.
    static MESSAGE: [u8; MESSAGE_LEN] = message();

    // Callee-saved rbx is clobbered by cpuid; r8-r11 are scratch. Absent
    // CPUID leaves read as zero. Numeric labels avoid 0 and 1, which LLVM's
    // Intel-syntax parser can take for binary literals.
    core::arch::global_asm!(
        ".pushsection .text.__frankenlibc_cpu_guard_resolve,\"ax\",@progbits",
        ".p2align 4",
        ".type __frankenlibc_cpu_guard_resolve, @function",
        "__frankenlibc_cpu_guard_resolve:",
        "push rbx",
        "xor eax, eax",
        "xor ecx, ecx",
        "cpuid",
        "mov r8d, eax",
        "mov eax, 1",
        "xor ecx, ecx",
        "cpuid",
        "mov r9d, ecx",
        "xor r10d, r10d",
        "cmp r8d, 7",
        "jb 2f",
        "mov eax, 7",
        "xor ecx, ecx",
        "cpuid",
        "mov r10d, ebx",
        "2:",
        "mov eax, 0x80000000",
        "xor ecx, ecx",
        "cpuid",
        "mov r8d, eax",
        "xor r11d, r11d",
        "cmp r8d, 0x80000001",
        "jb 3f",
        "mov eax, 0x80000001",
        "xor ecx, ecx",
        "cpuid",
        "mov r11d, ecx",
        "3:",
        "pop rbx",
        "and r9d, {leaf1}",
        "cmp r9d, {leaf1}",
        "jne 5f",
        "and r10d, {leaf7}",
        "cmp r10d, {leaf7}",
        "jne 5f",
        "and r11d, {ext}",
        "cmp r11d, {ext}",
        "jne 5f",
        "mov edx, {xcr0}",
        "test edx, edx",
        "jz 4f",
        // xgetbv faults unless the OS enabled XSAVE (CPUID.1:ECX.OSXSAVE).
        "mov eax, 1",
        "xor ecx, ecx",
        "push rbx",
        "cpuid",
        "pop rbx",
        "bt ecx, 27",
        "jnc 5f",
        "xor ecx, ecx",
        "xgetbv",
        "and eax, {xcr0}",
        "cmp eax, {xcr0}",
        "jne 5f",
        "4:",
        "lea rax, [rip + {noop}]",
        "ret",
        "5:",
        "mov eax, 1",
        "mov edi, 2",
        "lea rsi, [rip + {message}]",
        "mov edx, {len}",
        "syscall",
        "mov eax, 231",
        "mov edi, 127",
        "syscall",
        "ud2",
        ".size __frankenlibc_cpu_guard_resolve, . - __frankenlibc_cpu_guard_resolve",
        ".popsection",
        ".globl __frankenlibc_cpu_guard",
        ".hidden __frankenlibc_cpu_guard",
        ".type __frankenlibc_cpu_guard, @gnu_indirect_function",
        ".set __frankenlibc_cpu_guard, __frankenlibc_cpu_guard_resolve",
        leaf1 = const LEAF1_ECX,
        leaf7 = const LEAF7_EBX,
        ext = const EXT_ECX,
        xcr0 = const XCR0,
        len = const MESSAGE_LEN,
        message = sym MESSAGE,
        noop = sym noop,
    );

    unsafe extern "C" {
        fn __frankenlibc_cpu_guard();
    }

    #[used]
    static FORCE_IRELATIVE: unsafe extern "C" fn() = __frankenlibc_cpu_guard;

    extern "C" fn noop() {}
}

#[cfg(all(not(test), target_os = "linux"))]
#[used]
#[unsafe(link_section = ".init_array")]
static FRANKENLIBC_ABI_INIT_ARRAY: extern "C" fn() = frankenlibc_abi_stdio_init_entry;

#[cfg(all(not(test), target_os = "linux"))]
#[inline(never)]
extern "C" fn frankenlibc_abi_stdio_init_entry() {
    // SAFETY: this runs during process initialization before user code and
    // publishes the stdio globals/aliases onto stable NativeFile storage while
    // patching host libio exit handling for the exported _IO symbols.
    stdio_abi::init_host_stdio_streams();
    // aarch64: seed the pointer guard the native setjmp/longjmp asm reads (and
    // the stack canary) from AT_RANDOM here. The loader runs this constructor
    // before main whichever startup path runs, and owned startup does not seed
    // them, so this randomizes the guard before main captures any jmp_buf.
    // x86_64 needs no seeding: its asm reads glibc's TCB guard at %fs:0x30.
    #[cfg(target_arch = "aarch64")]
    unistd_abi::init_stack_canary();
    runtime_policy::signal_runtime_ready();
    // Hardened mode: build the ~79 KB validation pipeline now, on the main
    // thread's stack, instead of lazily inside whichever thread first
    // validates — which may be a 32 KiB-stack worker (bd-rc0923-epic-eeuy4f.9).
    if runtime_policy::mode().heals_enabled() {
        let _ = membrane_state::try_global_pipeline();
    }
}

// Phase 2+ ABI modules — call libc syscalls, gated to prevent symbol recursion in tests
#[cfg(not(test))]
pub mod c11threads_abi;
#[cfg(not(test))]
pub mod dirent_abi;
#[cfg(not(test))]
pub mod dlfcn_abi;
#[cfg(not(test))]
pub mod efun_abi;
#[cfg(not(test))]
pub mod err_abi;
#[cfg(not(test))]
pub mod fenv_abi;
#[cfg(not(test))]
pub mod fortify_abi;
#[cfg(not(test))]
pub mod grp_abi;
#[cfg(not(test))]
pub mod iconv_abi;
#[cfg(not(test))]
pub mod inet_abi;
#[cfg(not(test))]
pub mod io_abi;
#[cfg(not(test))]
pub mod isoc_abi;
#[cfg(not(test))]
pub mod mmap_abi;
#[cfg(not(test))]
pub mod nlist_abi;
#[cfg(not(test))]
pub mod poll_abi;
#[cfg(not(test))]
pub mod process_abi;
#[cfg(not(test))]
pub mod pthread_abi;
#[cfg(not(test))]
pub mod pwd_abi;
#[cfg(not(test))]
pub mod resolv_abi;
#[cfg(not(test))]
pub mod resolv_state;
#[cfg(not(test))]
pub mod resource_abi;
#[cfg(not(test))]
pub mod search_abi;
pub mod setjmp_abi;
#[cfg(not(test))]
pub mod signal_abi;
#[cfg(not(test))]
pub mod socket_abi;
#[cfg(not(test))]
pub mod startup_abi;
#[cfg(not(test))]
pub mod stdio_abi;
#[cfg(not(test))]
pub mod termios_abi;
#[cfg(not(test))]
pub mod time_abi;
#[cfg(not(test))]
pub mod unistd_abi;

// Massive glibc internal symbol coverage
#[cfg(not(test))]
pub mod glibc_internal_abi;
#[cfg(not(test))]
pub mod io_internal_abi;
#[cfg(not(test))]
pub mod rpc_abi;
// NSS service modules (libnss_<service>.so.2) for the passwd/group/shadow
// and initgroups databases.
#[cfg(not(test))]
pub(crate) mod nss_module;

pub mod util;
