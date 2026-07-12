// qsort unsigned fast-lane head-to-head. Before this change, u32/u64 keys in the
// comparison fast-lane window [64, 2048] failed the signed verify and dropped to
// the generic stdlib byte sort, which drives the caller's FFI comparator on every
// O(n log n) comparison. The new unsigned attempt sorts native u32/u64 keys with
// NO per-comparison callback + one O(n) verify — the same mechanism the signed
// (i32/i64) lane already uses.
//
// Three arms per width, all on FULL-RANGE unsigned keys (top bit set, so signed
// order diverges and the NEW unsigned path is the one exercised):
//   old  = stdlib in-place byte sort driven by the u-comparator (the pre-change
//          fallback for unsigned keys),
//   new  = frankenlibc_core::stdlib::qsort (takes the new unsigned lane),
//   glibc = libc::qsort with a C comparator.
// Each timed loop resets the buffer from a pristine copy first; a reset-only
// baseline is measured and subtracted so only the sort is counted. Output is
// asserted byte-identical to a reference sort before timing.
use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_core::stdlib::qsort as fl_qsort;

fn lcg(s: &mut u64) -> u64 {
    *s = s
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *s >> 1
}

// fl-style byte comparators (unsigned interpretation).
fn fl_cmp_u64(a: &[u8], b: &[u8]) -> i32 {
    u64::from_ne_bytes(a.try_into().unwrap())
        .cmp(&u64::from_ne_bytes(b.try_into().unwrap())) as i32
}
fn fl_cmp_u32(a: &[u8], b: &[u8]) -> i32 {
    u32::from_ne_bytes(a.try_into().unwrap())
        .cmp(&u32::from_ne_bytes(b.try_into().unwrap())) as i32
}

extern "C" fn gl_cmp_u64(a: *const c_void, b: *const c_void) -> i32 {
    let x = unsafe { *(a as *const u64) };
    let y = unsafe { *(b as *const u64) };
    x.cmp(&y) as i32
}
extern "C" fn gl_cmp_u32(a: *const c_void, b: *const c_void) -> i32 {
    let x = unsafe { *(a as *const u32) };
    let y = unsafe { *(b as *const u32) };
    x.cmp(&y) as i32
}

// The pre-change generic fallback for a fixed-width key: the stdlib unstable sort
// driven by the caller's comparator on every comparison (what `qsort` did for
// unsigned keys once the signed lane verify-failed).
fn old_generic_sort(buf: &mut [u8], width: usize, cmp: fn(&[u8], &[u8]) -> i32) {
    match width {
        8 => {
            let (chunks, _) = buf.as_chunks_mut::<8>();
            chunks.sort_unstable_by(|a, b| cmp(&a[..], &b[..]).cmp(&0));
        }
        4 => {
            let (chunks, _) = buf.as_chunks_mut::<4>();
            chunks.sort_unstable_by(|a, b| cmp(&a[..], &b[..]).cmp(&0));
        }
        _ => unreachable!(),
    }
}

fn reference_sorted(pristine: &[u8], width: usize, cmp: fn(&[u8], &[u8]) -> i32) -> Vec<u8> {
    let mut v = pristine.to_vec();
    old_generic_sort(&mut v, width, cmp);
    v
}

fn bench_width(
    label: &str,
    width: usize,
    n: usize,
    fl_cmp: fn(&[u8], &[u8]) -> i32,
    gl_cmp: extern "C" fn(*const c_void, *const c_void) -> i32,
) {
    let mut seed = 0xC0FFEE ^ (n as u64) ^ ((width as u64) << 32);
    let mut pristine = vec![0u8; n * width];
    for chunk in pristine.chunks_exact_mut(width) {
        let v = lcg(&mut seed);
        // Force the top bit set on ~half the keys so signed/unsigned order truly
        // diverges (this is the case that previously missed the fast lane).
        let key = v | ((v & 1) << 63);
        chunk.copy_from_slice(&key.to_ne_bytes()[..width]);
    }

    let want = reference_sorted(&pristine, width, fl_cmp);

    // Correctness: fl qsort (new lane) must match the reference sort byte-for-byte.
    {
        let mut b = pristine.clone();
        fl_qsort(&mut b, width, fl_cmp);
        assert_eq!(b, want, "{label}: fl new-lane output != reference sort");

        let mut g = pristine.clone();
        unsafe {
            libc::qsort(g.as_mut_ptr() as *mut c_void, n, width, Some(gl_cmp));
        }
        assert_eq!(g, want, "{label}: glibc output != reference sort");
    }

    let iters = (30_000_000usize / (n * width)).max(3000);
    let mut buf = pristine.clone();

    // Reset-only baseline (subtracted from each arm).
    let t = Instant::now();
    for _ in 0..iters {
        buf.copy_from_slice(&pristine);
        black_box(&buf);
    }
    let reset = t.elapsed().as_nanos() as f64 / iters as f64;

    let t = Instant::now();
    for _ in 0..iters {
        buf.copy_from_slice(&pristine);
        old_generic_sort(black_box(&mut buf), width, fl_cmp);
        black_box(&buf);
    }
    let old = (t.elapsed().as_nanos() as f64 / iters as f64 - reset).max(0.0);

    let t = Instant::now();
    for _ in 0..iters {
        buf.copy_from_slice(&pristine);
        fl_qsort(black_box(&mut buf), width, fl_cmp);
        black_box(&buf);
    }
    let new = (t.elapsed().as_nanos() as f64 / iters as f64 - reset).max(0.0);

    let t = Instant::now();
    for _ in 0..iters {
        buf.copy_from_slice(&pristine);
        unsafe { libc::qsort(black_box(buf.as_mut_ptr()) as *mut c_void, n, width, Some(gl_cmp)) };
        black_box(&buf);
    }
    let gl = (t.elapsed().as_nanos() as f64 / iters as f64 - reset).max(0.0);

    println!(
        "QSORT-U {label} n={n} old={old:.0}ns new={new:.0}ns glibc={gl:.0}ns  \
         old/new={:.2}x  glibc/new(Score)={:.2}x  glibc/old={:.2}x",
        old / new,
        gl / new,
        gl / old,
    );
}

fn main() {
    for &n in &[128usize, 512, 1024, 2048] {
        bench_width("u64", 8, n, fl_cmp_u64, gl_cmp_u64);
    }
    for &n in &[128usize, 512, 1024, 2048] {
        bench_width("u32", 4, n, fl_cmp_u32, gl_cmp_u32);
    }
}
