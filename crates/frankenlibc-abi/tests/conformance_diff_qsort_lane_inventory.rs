//! Lane INVENTORY for the deployed `qsort`, by comparator call count (bd-nas5rt).
//!
//! ## Why this file exists
//!
//! `crates/frankenlibc-abi/tests/` already holds four `qsort` gates —
//! `conformance_diff_qsort_i64_fastlane`, `_radix`, `_radix16` and `_count8`.
//! Every one of them compares SORTED OUTPUT against live glibc, and pdqsort
//! sorts correctly too, so **all four pass whether or not the lane they name
//! exists**. That is the hollow shape bd-nas5rt records: 51c39dec3 deleted lanes
//! and no gate went red.
//!
//! Three of those four are worse than hollow at HEAD — they name a lane that is
//! **not in the dispatch at all**. `frankenlibc_core::stdlib::sort::qsort` has
//! exactly two fast lanes (width 4 and width 8, both `I*_FAST_LANE_MIN..=MAX`)
//! and then `pdqsort_recurse`. There is no large-N radix lane, no 2-byte radix
//! lane and no 1-byte counting-sort lane, yet `_radix`, `_radix16` and `_count8`
//! assert in their own doc comments that those lanes are being exercised, and
//! they are green.
//!
//! ## What this gate does instead
//!
//! It counts the caller's comparator invocations, which separates the two paths
//! without any counter in production code: a fast lane sorts the raw integers
//! with the standard-library sort and then verifies the candidate against the
//! caller's comparator on ADJACENT PAIRS ONLY, so it spends about `n` calls per
//! ordering it attempts. Any comparison sort needs O(n log n) — for n = 4096
//! that is tens of thousands. The classifier below is `calls <= 4 * n`, a bound
//! no comparison sort can meet and every lane meets comfortably.
//!
//! Each row also checks fl's bytes against live glibc under the SAME comparator,
//! so this file is a superset of what the hollow gates check rather than a
//! replacement for their parity claim.
//!
//! ## What it measured, first run, n = 4096, scrambled distinct keys
//!
//! ```text
//!   width 1   fl 39914 calls   glibc 43975   -> NoLane   (_count8 names a lane here)
//!   width 2   fl 53078 calls   glibc 42835   -> NoLane   (_radix16 names a lane here)
//!   width 4   fl  4095 calls   glibc 42835   -> Lane
//!   width 8   fl  4095 calls   glibc 42835   -> Lane
//!   width 16  fl 53078 calls   glibc 42835   -> NoLane   (none claimed)
//! ```
//!
//! 4095 is exactly `n - 1`: the lane's verify pass, one comparison per adjacent
//! pair, and nothing else. The separation from the fallback is a factor of ten,
//! so the classifier is not a close call at this size.
//!
//! **The absent-lane rows are asserted as ABSENT on purpose.** They are the
//! tripwire in the honest direction: they state HEAD's real inventory in code,
//! so restoring a lane turns this file red and forces the restorer to move the
//! row from `NoLane` to `Lane` deliberately, rather than a lane appearing or
//! vanishing with nothing to notice it.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc qsort oracle + C-ABI comparators

use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Comparator invocations since the last `reset`. A `static` is required
/// because a C comparator is a bare `extern "C" fn` with no context argument —
/// which is precisely the indirect, contextless call the fast lanes exist to
/// avoid paying `O(n log n)` times.
static CALLS: AtomicUsize = AtomicUsize::new(0);

fn reset() {
    CALLS.store(0, Ordering::Relaxed);
}
fn calls() -> usize {
    CALLS.load(Ordering::Relaxed)
}

macro_rules! counting_cmp {
    ($name:ident, $ty:ty) => {
        /// Natural ascending comparator for `$ty`, written the way C callers
        /// write it (subtraction, not `Ord::cmp`), counting its own calls.
        extern "C" fn $name(a: *const c_void, b: *const c_void) -> c_int {
            CALLS.fetch_add(1, Ordering::Relaxed);
            // SAFETY: qsort hands back element pointers into the caller's own
            // array, each at least `size_of::<$ty>()` bytes wide.
            let (x, y) = unsafe { (*(a as *const $ty), *(b as *const $ty)) };
            if x < y {
                -1
            } else if x > y {
                1
            } else {
                0
            }
        }
    };
}

counting_cmp!(cmp_i8, i8);
counting_cmp!(cmp_i16, i16);
counting_cmp!(cmp_i32, i32);
counting_cmp!(cmp_i64, i64);

/// A 16-byte element with no integer interpretation, to show the lanes are
/// keyed on WIDTH and not merely on "the data happens to be sortable".
#[repr(C)]
#[derive(Clone, Copy)]
struct Wide16 {
    key: i64,
    _pad: i64,
}
extern "C" fn cmp_wide16(a: *const c_void, b: *const c_void) -> c_int {
    CALLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: both pointers address 16-byte elements of the caller's array.
    let (x, y) = unsafe { (*(a as *const Wide16), *(b as *const Wide16)) };
    if x.key < y.key {
        -1
    } else if x.key > y.key {
        1
    } else {
        0
    }
}

fn mix(seed: u64, i: usize) -> u64 {
    let mut z = seed.wrapping_add((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// What the dispatch is expected to do for a (width, n) pair at HEAD.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Expect {
    /// A fast lane commits: comparator calls are linear in `n`.
    Lane,
    /// No lane exists for this shape; pdqsort pays the comparator O(n log n)
    /// times. Asserted, not tolerated — see the module comment.
    NoLane,
}

/// Sort `bytes` with fl's DEPLOYED ABI entry point and with live glibc under
/// the same comparator; return (fl comparator calls, glibc comparator calls).
/// Both arms are counted, because glibc's count is the reference for "what a
/// comparison sort costs on this exact input" — a hard-coded O(n log n)
/// estimate would be an assumption where a measurement is available.
fn both(bytes: &[u8], width: usize, n: usize, cmp: extern "C" fn(*const c_void, *const c_void) -> c_int) -> (usize, usize) {
    let mut fl_buf = bytes.to_vec();
    reset();
    // SAFETY: `fl_buf` is exactly `n * width` writable bytes and `cmp` reads
    // only `width` bytes per element.
    unsafe {
        frankenlibc_abi::stdlib_abi::qsort(
            fl_buf.as_mut_ptr() as *mut c_void,
            n,
            width,
            Some(cmp),
        );
    }
    let fl_calls = calls();

    let mut gl_buf = bytes.to_vec();
    reset();
    // SAFETY: same shape, glibc's own entry point.
    unsafe {
        libc::qsort(gl_buf.as_mut_ptr() as *mut c_void, n, width, Some(cmp));
    }
    let gl_calls = calls();

    assert_eq!(
        fl_buf, gl_buf,
        "width {width} n {n}: fl qsort bytes diverge from live glibc"
    );
    (fl_calls, gl_calls)
}

fn scrambled(width: usize, n: usize) -> Vec<u8> {
    // Distinct keys in scrambled order. Distinctness matters: with heavy
    // duplicates pdqsort's equal-element partition can finish in far fewer
    // calls, which would blur the classifier this whole file rests on.
    let mut out = vec![0u8; n * width];
    for i in 0..n {
        let key = (mix(0x51C3_9DEC, i) % (n as u64)) as i64 - (n as i64 / 2) + i as i64;
        let le = key.to_le_bytes();
        // Little-endian, so the low `take` bytes ARE the key at the narrow
        // widths; anything above 8 bytes stays the zero padding the `vec!`
        // already put there (Wide16's `_pad`).
        let take = width.min(8);
        out[i * width..i * width + take].copy_from_slice(&le[..take]);
    }
    out
}

#[test]
fn the_deployed_qsort_lane_inventory_is_what_head_actually_has() {
    const N: usize = 4096;
    // (label, width, expectation, comparator, the gate that names this lane)
    let rows: &[(&str, usize, Expect, extern "C" fn(*const c_void, *const c_void) -> c_int, &str)] = &[
        (
            "width1 (1-byte keys)",
            1,
            Expect::NoLane,
            cmp_i8,
            "conformance_diff_qsort_count8 claims a counting-sort lane here",
        ),
        (
            "width2 (2-byte keys)",
            2,
            Expect::NoLane,
            cmp_i16,
            "conformance_diff_qsort_radix16 claims a 2-byte radix lane here",
        ),
        (
            "width4 (i32)",
            4,
            Expect::Lane,
            cmp_i32,
            "the surviving I32 lane, I32_FAST_LANE_MIN..=I32_FAST_LANE_MAX",
        ),
        (
            "width8 (i64)",
            8,
            Expect::Lane,
            cmp_i64,
            "the I64 lane restored under bd-nas5rt in 187b85580",
        ),
        (
            "width16 (struct)",
            16,
            Expect::NoLane,
            cmp_wide16,
            "no lane is claimed or expected at this width",
        ),
    ];

    // width1 cannot hold 4096 distinct keys, so its own count is what it is;
    // the classifier is a per-row bound on `n`, not a cross-row comparison.
    for &(label, width, expect, cmp, note) in rows {
        let bytes = scrambled(width, N);
        let (fl_calls, gl_calls) = both(&bytes, width, N, cmp);
        let linear_bound = 4 * N;
        let observed = if fl_calls <= linear_bound {
            Expect::Lane
        } else {
            Expect::NoLane
        };
        eprintln!(
            "QSORT_LANE_INVENTORY {label}: fl_calls={fl_calls} glibc_calls={gl_calls} \
             linear_bound={linear_bound} observed={observed:?} expected={expect:?} -- {note}"
        );
        assert_eq!(
            observed, expect,
            "{label}: fl made {fl_calls} comparator calls for n={N} (linear bound {linear_bound}, \
             live glibc made {gl_calls} on the same input). {note}. \
             If a lane was just added or removed here, this row is the thing that is supposed to \
             notice — update it deliberately."
        );
    }
}

/// The i64 lane's window has a FLOOR as well as a ceiling, and no gate checks
/// it. `I64_FAST_LANE_MIN` is 64, so n=32 must fall through to the comparison
/// sort — and if someone lowers the floor, this goes red rather than silently
/// changing the cost of every tiny sort in the process.
///
/// The bound here is `2 * n`, not the `4 * n` the main inventory uses, and the
/// difference is deliberate rather than sloppy. At n=32 pdqsort is effectively
/// an insertion sort, so the separation is far tighter than at n=4096: measured
/// on this input, fl made 137 calls and live glibc 108, against 31 for a lane
/// that commits on its first ordering. `4 * 32 = 128` sits nine calls under
/// fl's real count and would be a coin flip; `2 * 32 = 64` cannot be reached by
/// any comparison sort over 32 distinct keys.
#[test]
fn below_the_lane_floor_there_is_no_lane() {
    const N: usize = 32;
    let bytes = scrambled(8, N);
    let (fl_calls, gl_calls) = both(&bytes, 8, N, cmp_i64);
    eprintln!(
        "QSORT_LANE_INVENTORY below_floor width8 n={N}: fl_calls={fl_calls} glibc_calls={gl_calls}"
    );
    assert!(
        fl_calls > 2 * N,
        "n={N} is below I64_FAST_LANE_MIN (64) yet fl made only {fl_calls} comparator calls \
         (live glibc made {gl_calls} on the same input), which is lane-shaped: the floor moved \
         and nothing else would have said so"
    );
}
