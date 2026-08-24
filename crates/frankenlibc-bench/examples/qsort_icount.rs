//! Instruction-count driver for `qsort`: fl against live host glibc.
//!
//! WHY THIS EXISTS. `qsort` is the one libc primitive where fl has a structural
//! advantage rather than a structural tax. glibc's `qsort` is a GENERIC sort
//! over a function pointer: every comparison is an indirect call, and the
//! element moves are `memcpy`s of a runtime `size`. fl can instead recognise the
//! common case — a natural-order sort of machine integers — sort the raw values
//! with the MONOMORPHISED standard-library sort, and then verify the candidate
//! against the caller's comparator on adjacent pairs, committing only if it is
//! genuinely ordered and restoring the original otherwise.
//!
//! That verify-and-commit shape is what makes the lane sound for the ubiquitous
//! `return *(int*)a - *(int*)b` comparator, whose subtraction can overflow: the
//! check uses the real comparator on the real data, so a disagreement anywhere
//! makes the lane decline rather than commit a wrong order.
//!
//! The width-8 lane was deleted by `51c39dec3` and restored under bd-nas5rt;
//! this driver exists so the claim can be measured rather than asserted.
//!
//! `perf` is unavailable (`perf_event_paranoid=4` on this host and on every rch
//! worker), so this is built to run under callgrind, which counts in software:
//!
//!     valgrind --tool=callgrind --callgrind-out-file=OUT \
//!         ./target/release/examples/qsort_icount fl
//!
//! Run once per arm and compare. The arm is chosen by argv so the two runs
//! differ ONLY in which `qsort` the loop calls.
//!
//! NOTE ON WHAT THIS DOES *NOT* DO. It reports no ratio and no timing.
//! Instruction counts are not cycles. It answers "how much work does each
//! implementation do for the same sort", which is the question a shared, loaded
//! host can still answer honestly.

use std::ffi::c_void;

// fl declares the comparator as `Option<fn>` (C's nullable pointer); glibc's
// symbol has the same ABI. `Option<fn>` is null-optimised, so the two types are
// layout-identical and the `transmute` below is the ABI-correct spelling.
type ComparFn = unsafe extern "C" fn(*const c_void, *const c_void) -> i32;
type QsortFn = unsafe extern "C" fn(*mut c_void, usize, usize, Option<ComparFn>);

/// The comparator every C program writes, overflow and all. Using the textbook
/// form rather than a correct one is deliberate: it is what the fast lane has to
/// cope with, and a driver that used `a < b ? -1 : ...` would measure a case the
/// real world does not send.
unsafe extern "C" fn cmp_i64(a: *const c_void, b: *const c_void) -> i32 {
    // SAFETY: the loop below only ever passes pointers to 8-byte elements of its
    // own buffer.
    let (av, bv) = unsafe { (*(a as *const i64), *(b as *const i64)) };
    if av < bv {
        -1
    } else if av > bv {
        1
    } else {
        0
    }
}

/// Element counts. 512 sits inside the `[64, 2048]` lane window; 4096 sits
/// ABOVE it, so it is served by `pdqsort` in both arms and acts as a control —
/// if the fl/glibc gap moved only at 512 the difference really is the lane.
const SIZES: [usize; 2] = [512, 4096];

/// Element counts for this run, overridable so the lane window can be isolated.
///
/// This is not a convenience. The lane serves `[64, 2048]` only, so a run that
/// mixes 512 with 4096 measures the two regimes TOGETHER and the larger one
/// dominates by its element count — an aggregate that hides whichever way the
/// lane went. Reporting only the mixed figure would be the same mistake as
/// reading 64 KiB calloc as "malloc is at parity" because a zero-fill drowned
/// the wrapper.
fn sizes() -> Vec<usize> {
    match std::env::var("QSORT_SIZES") {
        Ok(v) => v
            .split(',')
            .filter_map(|t| t.trim().parse::<usize>().ok())
            .filter(|n| *n > 1)
            .collect::<Vec<_>>(),
        Err(_) => SIZES.to_vec(),
    }
}

fn rounds() -> usize {
    std::env::var("QSORT_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200)
}

/// Deterministic scrambled input. A sorted or reverse-sorted array would be
/// served by the monotonic-detect lane in one pass and would measure that lane
/// instead of the one under test.
fn scrambled(n: usize) -> Vec<i64> {
    let mut v: Vec<i64> = (0..n as i64).collect();
    let mut x: u64 = 0x243F_6A88_85A3_08D3;
    for i in (1..n).rev() {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        v.swap(i, (x.wrapping_mul(0x2545_F491_4F6C_DD1D) as usize) % (i + 1));
    }
    v
}

fn main() {
    let arm = std::env::args().nth(1).unwrap_or_else(|| "fl".to_string());

    let qsort_fn: QsortFn = match arm.as_str() {
        "fl" => frankenlibc_abi::stdlib_abi::qsort as QsortFn,
        "glibc" => {
            // A NEW link map, so the incumbent is untouched by fl's interposition.
            // SAFETY: LM_ID_NEWLM with a NUL-terminated soname.
            let handle = unsafe {
                libc::dlmopen(
                    libc::LM_ID_NEWLM,
                    c"libc.so.6".as_ptr(),
                    libc::RTLD_NOW | libc::RTLD_LOCAL,
                )
            };
            assert!(!handle.is_null(), "dlmopen libc.so.6");
            // SAFETY: dlsym on a NUL-terminated name in a handle we just opened.
            let sym = unsafe { libc::dlsym(handle, c"qsort".as_ptr()) };
            assert!(!sym.is_null(), "dlsym qsort");
            let fl = frankenlibc_abi::stdlib_abi::qsort as *const () as usize;
            assert_ne!(
                sym as usize, fl,
                "the resolved qsort IS fl's own — this driver would compare fl \
                 against itself"
            );
            // SAFETY: the address is glibc's qsort, whose C signature is QsortFn.
            unsafe { std::mem::transmute::<*mut c_void, QsortFn>(sym) }
        }
        other => panic!("unknown arm {other:?}; expected 'fl' or 'glibc'"),
    };

    let rounds = rounds();
    let mut checksum = 0u64;

    let sizes = sizes();
    for size in sizes.iter().copied() {
        let source = scrambled(size);
        for _ in 0..rounds {
            // Re-scramble from the same source each round so every round sorts
            // the SAME unsorted input. Sorting an already-sorted array would
            // measure the monotonic lane from round two onward.
            let mut buf = source.clone();
            // SAFETY: `buf` holds `size` 8-byte elements and `cmp_i64` only
            // dereferences 8 bytes at each pointer it is given.
            unsafe {
                qsort_fn(
                    buf.as_mut_ptr().cast::<c_void>(),
                    std::hint::black_box(size),
                    8,
                    Some(cmp_i64),
                );
            }
            // Order-sensitive fold, NOT an XOR: an XOR over a permutation of
            // 0..n is the same for every ordering, so it would be identical
            // whether or not the sort ran.
            checksum = checksum
                .wrapping_mul(0x100_0000_01b3)
                .wrapping_add(buf[0] as u64)
                .wrapping_add((buf[size / 2] as u64) << 1)
                .wrapping_add((buf[size - 1] as u64) << 2);
            debug_assert!(buf.windows(2).all(|w| w[0] <= w[1]));
        }
    }

    println!("QSORT_ICOUNT arm={arm} rounds={rounds} sizes={sizes:?} checksum=0x{checksum:x}");
}
