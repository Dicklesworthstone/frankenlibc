//! Instruction-count driver for the fused multi-conversion `snprintf` shapes.
//!
//! WHY THIS EXISTS. The fused family is the second-worst entry on the frontier at
//! 2.64-3.92x, and the open question on it is narrow: one commit added a float
//! probe to all six printf entry points, and the fused shapes traverse that entry
//! sequence without containing a single float conversion. Answering "did that
//! probe move the fused cost" by wall clock has failed twice, blocked by the quiet
//! gate at loadavg 20 and 33.
//!
//! It should not need a quiet host. This session established that instruction and
//! branch counts settle questions wall clock cannot: a 2-instruction edit that
//! looked like a win cost 30-40 cycles in mispredicts, and a "4.6% regression"
//! turned out to be two binaries with byte-identical allocator code. Both were
//! resolved by counting, in minutes, under load. This driver brings the same tool
//! to printf.
//!
//!     valgrind --tool=callgrind --branch-sim=yes \
//!         --callgrind-out-file=OUT ./target/release/examples/snprintf_icount fl
//!
//! Run once per arm and compare. The arm is chosen by argv so the two runs differ
//! ONLY in which `snprintf` the loop calls.
//!
//! NOTE ON WHAT THIS DOES NOT DO. It reports no ratio and no timing, and must not
//! be used to claim a speedup: instructions retired are not cycles. It answers
//! "how much work does each implementation do, and how predictable is it" — which
//! is what the layout-floor result says wall clock cannot answer below ~5% here.

use std::ffi::{c_char, c_int, c_void};

type SnprintfFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, ...) -> c_int;

union SnprintfSym {
    raw: *mut c_void,
    function: SnprintfFn,
}

/// Reps per shape. Modest on purpose: callgrind runs ~50x slower than native and
/// its counts are exact rather than statistical, so a large N buys nothing.
const REPS_DEFAULT: usize = 20_000;

/// Overridable so a run can be repeated at two loop counts.
///
/// That is the control that separates PER-CALL cost from one-time startup: a
/// function whose count is identical at 1,000 and 20,000 reps is not in the hot
/// path however large its share of the total looks.
fn reps() -> usize {
    std::env::var("SNPRINTF_ICOUNT_REPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(REPS_DEFAULT)
}

fn snprintf_for_arm(arm: &str) -> SnprintfFn {
    match arm {
        "fl" => frankenlibc_abi::stdio_abi::snprintf,
        "glibc" => {
            // A NEW link map, so the incumbent is untouched by fl's interposition
            // — the same reason the coverage harness uses dlmopen.
            // SAFETY: LM_ID_NEWLM with a NUL-terminated soname.
            let handle = unsafe {
                libc::dlmopen(
                    libc::LM_ID_NEWLM,
                    c"libc.so.6".as_ptr(),
                    libc::RTLD_NOW | libc::RTLD_LOCAL,
                )
            };
            assert!(!handle.is_null(), "dlmopen libc.so.6");
            // SAFETY: the handle came from dlmopen; the name is NUL-terminated.
            let raw = unsafe { libc::dlsym(handle, c"snprintf".as_ptr()) };
            assert!(!raw.is_null(), "dlsym snprintf");
            assert_ne!(
                raw as usize,
                frankenlibc_abi::stdio_abi::snprintf as usize,
                "the glibc arm resolved to fl's own snprintf — this would compare \
                 fl against itself"
            );
            // SAFETY: the resolved symbol has C's documented snprintf signature.
            unsafe { SnprintfSym { raw }.function }
        }
        other => panic!("unknown arm {other:?}; expected 'fl' or 'glibc'"),
    }
}

fn main() {
    let arm = std::env::args().nth(1).unwrap_or_else(|| "fl".to_string());
    let f = snprintf_for_arm(&arm);
    let n = reps();

    let mut buf = [0u8; 256];
    let dst = buf.as_mut_ptr().cast::<c_char>();
    let a = c"alpha";
    let b = c"bravo";
    let c = c"charlie";
    let d = c"delta";

    // Checksum-accumulate the return values so no call can be optimised away and
    // a miscompiled arm shows up as a different checksum rather than as a
    // suspiciously cheap run.
    let mut sum: u64 = 0;

    // The conversion ladder, type held constant, which is the shape that
    // regressed the fused penalty to ~75% per-conversion (bd-ntb9fq).
    for _ in 0..n {
        // SAFETY: `dst` has 256 bytes; every format names exactly its arguments.
        unsafe {
            sum ^= f(dst, 256, c"%s %s".as_ptr(), a.as_ptr(), b.as_ptr()) as u64;
            sum ^= f(dst, 256, c"%s %s %s".as_ptr(), a.as_ptr(), b.as_ptr(), c.as_ptr()) as u64;
            sum ^= f(
                dst,
                256,
                c"%s %s %s %s".as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                c.as_ptr(),
                d.as_ptr(),
            ) as u64;
            // Real-world shapes: access-log and structured key/value.
            sum ^= f(
                dst,
                256,
                c"%s %s %d %lu".as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                42i32,
                7u64,
            ) as u64;
            sum ^= f(
                dst,
                256,
                c"%s=%s %s=%s".as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                c.as_ptr(),
                d.as_ptr(),
            ) as u64;
        }
        sum = sum.wrapping_mul(0x0000_0100_0000_01b3);
    }

    println!("SNPRINTF_ICOUNT arm={arm} reps={n} shapes=5 checksum=0x{sum:x}");
}
