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
unsafe extern "C" fn cmp_i32(a: *const c_void, b: *const c_void) -> i32 {
    // SAFETY: the driver only passes pointers to 4-byte elements of its own
    // buffer when it selects this comparator.
    let (av, bv) = unsafe { (*(a as *const i32), *(b as *const i32)) };
    if av < bv {
        -1
    } else if av > bv {
        1
    } else {
        0
    }
}

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

/// SHA-256 of the running binary, read from `/proc/self/exe`.
///
/// Self-reported rather than taken from the shell that launched it: a hash
/// computed outside the process can describe a DIFFERENT file if the target
/// directory was rewritten between build and run, which is exactly how a stale
/// artifact gets certified. This one cannot be wrong about which bytes are
/// executing.
fn self_elf_sha256() -> String {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read("/proc/self/exe").expect("read /proc/self/exe");
    let mut h = Sha256::new();
    h.update(&bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Live thread count from `/proc/self/status`, reported rather than assumed.
///
/// A second runnable thread would make the arms share a core and is the first
/// thing to suspect in an anomalous row, so the count belongs in the output
/// beside the numbers rather than in an assumption.
fn thread_count() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Threads:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|n| n.parse().ok()))
        })
        .unwrap_or(0)
}

fn resolve(arm: &str) -> QsortFn {
    match arm {
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
    }
}

/// Sort `rounds` copies of `source` through `qsort_fn`, at `width` bytes per
/// element.
///
/// `width` selects which lane the call is eligible for: 4 is the i32 lane, 8 the
/// i64 lane, and 16 is wider than any lane so it is served by `pdqsort` in fl and
/// by the generic sort in glibc — a control that isolates how much of the gap is
/// the lane rather than the surrounding machinery.
fn drive(qsort_fn: QsortFn, source: &[i64], width: usize, rounds: usize) -> u64 {
    let size = source.len();
    let mut checksum = 0u64;
    for _ in 0..rounds {
        // Rebuild from the same source each round, so every round sorts the SAME
        // unsorted input. Re-sorting an already-sorted array would measure the
        // monotonic-detect lane from round two onward.
        // Write exactly `width` bytes per element. Writing eight at a
        // FOUR-byte stride runs the last element past the end of the buffer,
        // which aborted every width-4 case of the first sweep — a defect in this
        // driver, not in either sort.
        let mut buf = vec![0u8; size * width];
        let compar = if width == 4 {
            for (i, v) in source.iter().enumerate() {
                buf[i * 4..i * 4 + 4].copy_from_slice(&(*v as i32).to_ne_bytes());
            }
            cmp_i32 as ComparFn
        } else {
            for (i, v) in source.iter().enumerate() {
                buf[i * width..i * width + 8].copy_from_slice(&v.to_ne_bytes());
            }
            cmp_i64 as ComparFn
        };
        // SAFETY: `buf` holds `size` elements of `width` bytes and the comparator
        // reads only the leading 4 or 8 bytes of each pointer it is given.
        unsafe {
            qsort_fn(
                buf.as_mut_ptr().cast::<c_void>(),
                std::hint::black_box(size),
                width,
                Some(compar),
            );
        }
        // Order-sensitive fold, NOT an XOR: an XOR over a permutation of 0..n is
        // the same for every ordering, so it would be identical whether or not
        // the sort ran.
        let read = |off: usize| -> i64 {
            if width == 4 {
                i32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as i64
            } else {
                i64::from_ne_bytes(buf[off..off + 8].try_into().unwrap())
            }
        };
        let first = read(0);
        let last = read((size - 1) * width);
        checksum = checksum
            .wrapping_mul(0x100_0000_01b3)
            .wrapping_add(first as u64)
            .wrapping_add((last as u64) << 2);
    }
    checksum
}

fn main() {
    // Both arms run in ONE process, so callgrind attributes each to its own
    // function and the comparison is same-invocation rather than
    // across-process. `--separate-callers` is not needed: fl's `qsort` and
    // glibc's sort are distinct symbols in distinct objects.
    let rounds = rounds();
    let sizes = sizes();
    let width: usize = std::env::var("QSORT_WIDTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);

    let fl = resolve("fl");
    let glibc = resolve("glibc");

    println!(
        "QSORT_PROVENANCE elf_sha256={} threads={} width={width} rounds={rounds} sizes={sizes:?}",
        self_elf_sha256(),
        thread_count()
    );

    for size in sizes.iter().copied() {
        let source = scrambled(size);
        // ABBA: each arm runs twice, interleaved, so a drift in machine state
        // over the run cannot be mistaken for a difference between the arms.
        let a1 = drive(fl, &source, width, rounds);
        let b1 = drive(glibc, &source, width, rounds);
        let b2 = drive(glibc, &source, width, rounds);
        let a2 = drive(fl, &source, width, rounds);
        // Every arm sorts identical input, so all four checksums must agree.
        // A mismatch means the two implementations disagree on the OUTPUT and no
        // instruction count from this run is worth reading.
        assert_eq!(a1, b1, "fl and glibc produced different orders at n={size}");
        assert_eq!(a1, a2, "fl disagreed with itself at n={size}");
        assert_eq!(b1, b2, "glibc disagreed with itself at n={size}");
        println!("QSORT_CASE size={size} width={width} checksum=0x{a1:x} arms=ABBA");
    }
}
