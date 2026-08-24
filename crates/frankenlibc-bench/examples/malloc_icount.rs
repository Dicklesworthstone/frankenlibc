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
type CallocFn = unsafe extern "C" fn(usize, usize) -> *mut c_void;

fn dl<T: Copy>(handle: *mut c_void, name: &[u8]) -> T {
    // SAFETY: handle came from dlmopen; name is a NUL-terminated byte string.
    let p = unsafe { libc::dlsym(handle, name.as_ptr().cast()) };
    assert!(!p.is_null(), "dlsym {:?}", std::str::from_utf8(name));
    // SAFETY: the resolved symbol has the C signature named by `T`.
    unsafe { std::mem::transmute_copy::<usize, T>(&(p as usize)) }
}

/// Fold one returned pointer into a running checksum, order-sensitively.
///
/// NOT an XOR. The pair loop frees each block immediately, so every iteration
/// gets the SAME address back, and an XOR of an even number of equal values is
/// exactly zero — which is byte-for-byte what a loop the optimiser had deleted
/// would print. The default `malloc` mode really did print `checksum=0x0` for
/// both arms, so the one line that exists to prove the loop ran was proving
/// nothing. The churn and growth modes below had already been converted to this
/// mix for that reason; this is the third caller they were meant to share.
///
/// The multiply makes the fold non-commutative, so it also separates "N
/// allocations happened" from "the same allocation happened N times in a
/// different order", which a sum would not.
#[inline]
fn mix(accumulator: u64, ptr: *mut c_void) -> u64 {
    accumulator
        .wrapping_mul(0x100_0000_01b3)
        .wrapping_add(ptr as u64)
}

/// Pairs per size class. Deliberately modest: callgrind runs ~50x slower than
/// native, and instruction counts are exact rather than statistical, so there is
/// nothing to gain from a large N and a lot of wall time to lose.
const PAIRS_DEFAULT: usize = 20_000;

/// Overridable so a run can be repeated at two loop counts.
///
/// That is not a convenience: it is the control that distinguishes a PER-CALL
/// cost from one-time startup. A function whose instruction count is identical
/// at 1,000 and 20,000 pairs is not in the hot path however large its share of
/// the total looks, and a share-of-total reading alone cannot tell the two
/// apart.
fn pairs() -> usize {
    std::env::var("ICOUNT_PAIRS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(PAIRS_DEFAULT)
}
const SIZES: [usize; 4] = [16, 64, 256, 1024];

/// The size list for a run: [`SIZES`] unless trailing numeric arguments override it.
///
/// Split out of the churn arm and given to the malloc arm too, because the two
/// halves of this allocator answer DIFFERENT questions above
/// `MAX_SMALL_SIZE` (32 KiB) and only one of them could be asked. Below the
/// ceiling every request is segment-served; above it `strict_small_or_host_allocate`
/// declines and the request goes to `native_libc_malloc` plus the fallback size
/// table. That fallback path is the target of bd-dcrhgl's inline size header,
/// and with only the four default sizes compiled in there was no way to point
/// this instrument at it.
///
/// Churn mode already had this and calloc's zero-fill dominates it: at 64 KiB a
/// pair retires ~66,000 instructions, of which the wrapper is ~600, so the ratio
/// reads 1.009x and says nothing about the wrapper. `malloc` does not fill, so
/// the same size through the malloc arm is where the fallback table is visible.
///
/// Non-numeric and zero arguments are ignored rather than rejected: the caller
/// may be passing a mode word ("churn"/"growth") in the same position.
fn sizes_from_args(skip: usize) -> Vec<usize> {
    sizes_from(std::env::args(), skip)
}

/// [`sizes_from_args`] over an explicit argument sequence, so it is testable.
fn sizes_from(args: impl Iterator<Item = String>, skip: usize) -> Vec<usize> {
    let overrides: Vec<usize> = args
        .skip(skip)
        .filter_map(|a| a.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .collect();
    if overrides.is_empty() {
        SIZES.to_vec()
    } else {
        overrides
    }
}

/// Resolve `calloc` for an arm, mirroring how `main` resolves malloc/free.
///
/// The glibc arm comes from a NEW link map so the incumbent allocator is
/// untouched by fl's interposition -- the same reason `main` uses `dlmopen`.
fn calloc_for_arm(arm: &str) -> CallocFn {
    match arm {
        "fl" => frankenlibc_abi::malloc_abi::calloc,
        "glibc" => {
            // SAFETY: LM_ID_NEWLM with a NUL-terminated soname.
            let handle = unsafe {
                libc::dlmopen(
                    libc::LM_ID_NEWLM,
                    c"libc.so.6".as_ptr(),
                    libc::RTLD_NOW | libc::RTLD_LOCAL,
                )
            };
            assert!(!handle.is_null(), "dlmopen libc.so.6");
            dl(handle, b"calloc\0")
        }
        other => panic!("unknown arm {other:?}; expected 'fl' or 'glibc'"),
    }
}

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

    // CHURN MODE (`malloc_icount <arm> churn [size ...]`): calloc one block and
    // free it immediately, repeatedly.
    //
    // This is the shape the fresh-slot zero-fill elision does NOT help: every
    // iteration after the first recycles the same slot, so the fill still runs.
    // It is measured separately for exactly that reason -- quoting the growth
    // number for a churning caller would be quoting a case they never hit.
    // Optional trailing arguments override the size list, which is how the
    // above-MAX_SMALL_SIZE host path gets exercised without a rebuild.
    if std::env::args().nth(2).as_deref() == Some("churn") {
        let calloc_fn: CallocFn = calloc_for_arm(&arm);
        let iters = pairs();
        let sizes: Vec<usize> = sizes_from_args(3);
        let mut checksum = 0u64;
        for &size in &sizes {
            for _ in 0..iters {
                // SAFETY: one element of `size` bytes, freed once immediately.
                let p = unsafe { calloc_fn(1, std::hint::black_box(size)) };
                assert!(!p.is_null(), "calloc(1, {size}) returned NULL");
                // Reading the first byte keeps the zero-fill observable: a fill
                // that silently stopped happening would change this sum.
                // SAFETY: `p` is live and at least one byte wide.
                checksum = mix(checksum, p).wrapping_add(unsafe { *p.cast::<u8>() } as u64);
                // SAFETY: allocated by this arm above, freed exactly once.
                unsafe { free_fn(std::hint::black_box(p)) };
            }
        }
        println!(
            "CALLOC_ICOUNT arm={arm} mode=churn iters_per_size={iters} sizes={sizes:?} \
             checksum=0x{checksum:x}"
        );
        return;
    }

    // GROWTH MODE (`malloc_icount <arm> growth`): calloc a run of blocks and
    // free them only at the END, instead of churning one block at a time.
    //
    // WHY IT IS A SEPARATE MODE. fl's `calloc` skips the zero-fill for a segment
    // slot that has never been handed out, because those pages are still the
    // MAP_ANONYMOUS zeros the arena was mapped with. A churn loop frees each
    // block immediately, so the next call recycles the same slot and the skip
    // NEVER fires -- measuring churn would report "no effect" for a change that
    // only applies to growth, which is the shape real calloc callers have.
    if std::env::args().nth(2).as_deref() == Some("growth") {
        let calloc_fn: CallocFn = calloc_for_arm(&arm);
        let live = pairs();
        let mut checksum = 0u64;
        let mut held: Vec<*mut core::ffi::c_void> = Vec::with_capacity(live);
        for size in SIZES {
            for _ in 0..live {
                // SAFETY: one element of `size` bytes; every pointer is freed
                // once below through the same arm.
                let p = unsafe { calloc_fn(1, std::hint::black_box(size)) };
                // Touch the first byte so a zero-fill that did not happen would
                // show up as a wrong checksum rather than as free speed. The
                // fold itself is `mix`, which is order-sensitive for the reason
                // documented there.
                // SAFETY: `p` is live and at least one byte wide.
                checksum = mix(checksum, p).wrapping_add(unsafe { *p.cast::<u8>() } as u64);
                held.push(p);
            }
            for p in held.drain(..) {
                // SAFETY: allocated by this arm just above, freed exactly once.
                unsafe { free_fn(std::hint::black_box(p)) };
            }
        }
        println!(
            "CALLOC_ICOUNT arm={arm} mode=growth live_per_size={live} sizes={SIZES:?} \
             checksum=0x{checksum:x}"
        );
        return;
    }

    // Checksum-accumulate the pointers so a miscompiled arm shows up as a
    // different checksum rather than as a suspiciously cheap run.
    //
    // The checksum does NOT keep the loop alive -- `black_box` on the size and
    // on the freed pointer does that, and it has to, because fl's entry point
    // is named `malloc` with the C ABI and LLVM treats it as the builtin. What
    // the checksum adds is evidence that the pointers differed, which is why it
    // must not be an XOR: see `mix`.
    let mut checksum = 0u64;
    let pairs = pairs();
    // Trailing numeric arguments select the sizes; see `sizes_from_args`. The
    // mode word is at index 2 and is not numeric, so a plain
    // `malloc_icount fl 65536` is unambiguous.
    let sizes = sizes_from_args(2);
    for size in sizes.iter().copied() {
        for _ in 0..pairs {
            // SAFETY: `size` is non-zero; every pointer returned is freed once
            // through the same arm's `free`.
            unsafe {
                let p = malloc_fn(std::hint::black_box(size));
                assert!(!p.is_null(), "malloc({size}) returned NULL");
                checksum = mix(checksum, p);
                free_fn(std::hint::black_box(p));
            }
        }
    }

    println!(
        "MALLOC_ICOUNT arm={arm} pairs_per_size={pairs} sizes={sizes:?} checksum=0x{checksum:x}"
    );
}

#[cfg(test)]
mod tests {
    use super::{SIZES, mix, sizes_from};
    use std::ffi::c_void;

    fn args(list: &[&str]) -> std::vec::IntoIter<String> {
        list.iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// The malloc arm must be able to reach ABOVE `MAX_SMALL_SIZE`.
    ///
    /// This is the whole point of the parameter: below 32 KiB every request is
    /// segment-served and the fallback size table is never consulted, so an
    /// instrument fixed at 16/64/256/1024 cannot measure the path bd-dcrhgl's
    /// inline size header would replace.
    #[test]
    fn trailing_numeric_arguments_select_the_sizes() {
        assert_eq!(sizes_from(args(&["prog", "fl", "65536"]), 2), vec![65536]);
        assert_eq!(
            sizes_from(args(&["prog", "fl", "65536", "131072"]), 2),
            vec![65536, 131072]
        );
        // churn/growth pass their mode word at index 2 and sizes from 3.
        assert_eq!(
            sizes_from(args(&["prog", "fl", "churn", "65536"]), 3),
            vec![65536]
        );
    }

    /// With no override the default list is used, and a mode word must not be
    /// mistaken for a size.
    #[test]
    fn a_mode_word_is_not_a_size() {
        assert_eq!(sizes_from(args(&["prog", "fl"]), 2), SIZES.to_vec());
        // `churn` parsed at skip=2 would be an override if the filter were
        // wrong; it is not numeric, so the defaults must survive.
        assert_eq!(sizes_from(args(&["prog", "fl", "churn"]), 2), SIZES.to_vec());
        assert_eq!(
            sizes_from(args(&["prog", "fl", "growth"]), 2),
            SIZES.to_vec()
        );
    }

    /// A zero size would make `calloc(1, 0)`/`malloc(0)` the thing measured,
    /// which is a different question and returns a pointer that cannot be
    /// dereferenced for the checksum. It is dropped, not accepted.
    #[test]
    fn zero_and_garbage_sizes_are_dropped() {
        assert_eq!(sizes_from(args(&["prog", "fl", "0"]), 2), SIZES.to_vec());
        assert_eq!(sizes_from(args(&["prog", "fl", "-8"]), 2), SIZES.to_vec());
        assert_eq!(sizes_from(args(&["prog", "fl", "abc"]), 2), SIZES.to_vec());
        // A valid size alongside garbage still selects the valid one.
        assert_eq!(
            sizes_from(args(&["prog", "fl", "abc", "4096", "0"]), 2),
            vec![4096]
        );
    }

    fn ptr(addr: usize) -> *mut c_void {
        addr as *mut c_void
    }

    /// THE DEFECT, pinned. The pair loop frees each block immediately, so it
    /// gets the same address back every time; the old `checksum ^= p as u64`
    /// therefore cancelled to exactly zero on any even iteration count, and both
    /// arms printed `checksum=0x0`.
    ///
    /// Zero is the value an ELIDED loop prints, so the one line that exists to
    /// say the loop ran said nothing. Anything that reintroduces a self-cancelling
    /// fold fails here.
    #[test]
    fn a_repeated_address_does_not_cancel_to_zero() {
        let repeated = ptr(0x7f00_0000_1000);
        for count in [2usize, 4, 8, 1024, 12_000] {
            let mut acc = 0u64;
            for _ in 0..count {
                acc = mix(acc, repeated);
            }
            assert_ne!(
                acc, 0,
                "{count} folds of one address cancelled to zero — that is exactly \
                 what an optimised-away loop prints"
            );
        }

        // The property the old code lacked, stated directly: XOR does cancel.
        let mut xored = 0u64;
        for _ in 0..12_000 {
            xored ^= repeated as u64;
        }
        assert_eq!(xored, 0, "the control must reproduce the original defect");
    }

    /// A sum would also survive the test above while still failing to
    /// distinguish "N allocations" from "the same N addresses in another order".
    /// The multiply is what makes the fold non-commutative.
    #[test]
    fn the_fold_is_order_sensitive() {
        let a = ptr(0x1000);
        let b = ptr(0x2000);
        assert_ne!(
            mix(mix(0, a), b),
            mix(mix(0, b), a),
            "the fold is commutative, so a reordered allocation stream is invisible"
        );
    }

    /// A run of DISTINCT addresses — the growth-mode shape — must not land on
    /// zero either, and consecutive prefixes must differ, so a loop that stopped
    /// early is visible rather than absorbed.
    #[test]
    fn distinct_addresses_produce_distinct_running_values() {
        let mut acc = 0u64;
        let mut seen = Vec::new();
        for i in 0..256usize {
            acc = mix(acc, ptr(0x7f00_0000_0000 + i * 64));
            assert_ne!(acc, 0, "prefix of length {} folded to zero", i + 1);
            seen.push(acc);
        }
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "two different prefixes folded to the same value");
    }
}
