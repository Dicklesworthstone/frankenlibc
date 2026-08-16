//! Instruction-count driver for `malloc`+`free`: fl against live host glibc.
//!
//! WHY THIS EXISTS. Wall-clock ablation has been exhausted on this vein. Two
//! attempts to price a component by removing it both came back SLOWER, for two
//! different reasons — the fallback-table insert is a lookup accelerator `free`
//! depends on, and the membrane `decide`/`observe` pair gates the fast path it
//! sits on. The per-call components are mutually load-bearing, so ablation can
//! only price a component that is inert with respect to control flow, and in
//! this allocator most are not. The remaining ~27 ns per pair is therefore
//! UNATTRIBUTED by wall clock.
//!
//! A counted mechanism does not have that problem: instructions retired is
//! additive, attributable per function, and immune to the load on a 64-thread
//! box that makes small wall-clock deltas unreadable here.
//!
//! `perf` is unavailable (`perf_event_paranoid=4` on this host and on every rch
//! worker), so this is built to run under callgrind, which counts in software:
//!
//!     valgrind --tool=callgrind --callgrind-out-file=OUT \
//!         ./target/release/examples/malloc_icount fl
//!     callgrind_annotate OUT | head -40
//!
//! Run once per arm and compare. The arm is chosen by argv so the two runs
//! differ ONLY in which allocator the loop calls — same binary, same loop, same
//! instruction stream around it, which is what makes the difference readable as
//! the allocator's own cost rather than the harness's.
//!
//! NOTE ON WHAT THIS DOES *NOT* DO. It reports no ratio and no timing, and it
//! must not be used to claim a speedup: callgrind's instruction counts are not
//! cycles, and a memory-bound path can retire few instructions slowly. It
//! answers "where do fl's instructions go", which is the question wall clock
//! could not answer here.

use std::ffi::c_void;

type MallocFn = unsafe extern "C" fn(usize) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void);

fn dl<T: Copy>(handle: *mut c_void, name: &[u8]) -> T {
    // SAFETY: handle came from dlmopen; name is a NUL-terminated byte string.
    let p = unsafe { libc::dlsym(handle, name.as_ptr().cast()) };
    assert!(!p.is_null(), "dlsym {:?}", std::str::from_utf8(name));
    // SAFETY: the resolved symbol has the C signature named by `T`.
    unsafe { std::mem::transmute_copy::<usize, T>(&(p as usize)) }
}

/// Pairs per size class. Deliberately modest: callgrind runs ~50x slower than
/// native, and instruction counts are exact rather than statistical, so there is
/// nothing to gain from a large N and a lot of wall time to lose.
const PAIRS: usize = 20_000;
const SIZES: [usize; 4] = [16, 64, 256, 1024];

fn main() {
    let arm = std::env::args().nth(1).unwrap_or_else(|| "fl".to_string());

    let (malloc_fn, free_fn): (MallocFn, FreeFn) = match arm.as_str() {
        "fl" => (
            frankenlibc_abi::malloc_abi::malloc,
            frankenlibc_abi::malloc_abi::free,
        ),
        "glibc" => {
            // A NEW link map, exactly as malloc_st_probe does it: this gives a
            // private glibc whose allocator is untouched by fl's interposition,
            // so the incumbent arm really is the incumbent.
            // SAFETY: LM_ID_NEWLM with a NUL-terminated soname.
            let handle = unsafe {
                libc::dlmopen(
                    libc::LM_ID_NEWLM,
                    c"libc.so.6".as_ptr(),
                    libc::RTLD_NOW | libc::RTLD_LOCAL,
                )
            };
            assert!(!handle.is_null(), "dlmopen libc.so.6");
            (dl(handle, b"malloc\0"), dl(handle, b"free\0"))
        }
        other => panic!("unknown arm {other:?}; expected 'fl' or 'glibc'"),
    };

    // Checksum-accumulate the pointers so the loop cannot be optimised away and
    // so a miscompiled arm shows up as a different checksum rather than as a
    // suspiciously cheap run.
    let mut checksum = 0u64;
    for size in SIZES {
        for _ in 0..PAIRS {
            // SAFETY: `size` is non-zero; every pointer returned is freed once
            // through the same arm's `free`.
            unsafe {
                let p = malloc_fn(std::hint::black_box(size));
                checksum ^= p as u64;
                free_fn(std::hint::black_box(p));
            }
        }
    }

    println!(
        "MALLOC_ICOUNT arm={arm} pairs_per_size={PAIRS} sizes={SIZES:?} checksum=0x{checksum:x}"
    );
}
